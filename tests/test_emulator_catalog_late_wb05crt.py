"""Exact-source WB05C(RT)V2.03 UDP behavior; raw payloads are synthetic, not physics."""

import asyncio
import base64
from copy import deepcopy
import json
import math
from pathlib import Path
from types import SimpleNamespace

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.profiles import catalog_late_wb05crt as family
from gree_emulator.server import EmulatorServer
from gree_emulator.wire import InvalidPacket, decode_outer, encode_reply


FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-late-wb05crt-v203_research.json").read_text())
MAC = "020000000001"
HOST_MAC = "0200000000a5"
KEY = bytes.fromhex(FIXTURE["key_slots"]["synthetic_test_device_key_hex"])
GENERIC = bytes.fromhex(FIXTURE["key_slots"]["generic_key_hex"])
ADDR = ("192.0.2.10", 5001)


def controller(mac=MAC, mid="10001"):
    profile = next(profile for profile in family.PROFILES if profile.id == FIXTURE["profile_id"])
    return SimpleNamespace(
        id="crt-root", children=[], mac=mac, mid=mid, name="Synthetic WB05C(RT)",
        key=KEY, profile=profile, state=deepcopy(dict(profile.initial_state)), last_step=0,
    )


def request_bytes(inner, *, selector=0, uid=42, tcid="unmatched-target"):
    outer = {"t": "pack", "i": selector, "uid": uid, "cid": "synthetic-host", "tcid": tcid}
    if selector == 2:
        outer["pack"] = inner
    else:
        plaintext = json.dumps(inner, separators=(",", ":")).encode("utf-8") + b"\n"
        key = KEY if selector == 0 else GENERIC
        ciphertext = AES.new(key, AES.MODE_ECB).encrypt(pad(plaintext, AES.block_size))
        outer["pack"] = base64.b64encode(ciphertext).decode("ascii")
    return json.dumps(outer, separators=(",", ":")).encode("utf-8")


def send(device, inner, *, selector=0, uid=42, addr=ADDR):
    outer = decode_outer(request_bytes(inner, selector=selector, uid=uid))
    return device.profile.handler.handle_from(device, outer, addr)


def wire_response(encoded, *, expect_uid=True):
    assert not encoded.endswith(b"\n") and b"\n" not in encoded and b"\r" not in encoded
    outer = json.loads(encoded)
    expected_fields = {"t", "i", "msgId", "cid", "tcid", "pack"}
    if expect_uid:
        expected_fields.add("uid")
    assert set(outer) == expected_fields
    assert outer["t"] == "pack"
    assert type(outer["i"]) is int and type(outer["msgId"]) is int
    if expect_uid:
        assert type(outer["uid"]) is int
    key = KEY if outer["i"] == 0 else GENERIC
    ciphertext = base64.b64decode(outer["pack"], validate=True)
    plaintext = unpad(AES.new(key, AES.MODE_ECB).decrypt(ciphertext), AES.block_size)
    assert plaintext.endswith(b"\n") and plaintext.count(b"\n") == 1
    assert b"\r" not in plaintext
    return outer, json.loads(plaintext[:-1])


def response(reply, *, expect_uid=True):
    assert reply.destination_port == FIXTURE["transport"]["reply_destination_port"]
    return wire_response(encode_reply(reply), expect_uid=expect_uid)


def expected_raw_status(payload, raw_clock_hex):
    vector = FIXTURE["raw_binary"]["bin_status"]
    encoded_payload = base64.b64encode(payload)
    metadata = bytearray(
        base64.b64decode(vector["wrapper"]["header"], validate=True)
    )
    clock = bytes.fromhex(raw_clock_hex)
    clock_offset = vector["metadata_clock_offset"]
    assert len(metadata) == vector["metadata_length_bytes"]
    assert len(clock) == vector["metadata_clock_length"]
    metadata[3] = len(encoded_payload) & 255
    metadata[clock_offset:clock_offset + len(clock)] = clock
    return {
        "t": "binStatus", "mac": MAC,
        "binStatus": encoded_payload.decode("ascii"),
        "header": base64.b64encode(metadata).decode("ascii"),
    }
def decoded_tick(device, now):
    decoded = []
    for reply, destination in device.profile.handler.tick(device, now):
        outer, inner = response(reply, expect_uid="uid" in reply.outer)
        decoded.append((outer, inner, destination))
    return decoded

def assert_ubindok_proactive(replies, *, utm_msg_id=0, login_msg_id=1, cur_gnet_id=0, host_mac=HOST_MAC):
    assert len(replies) == 2
    utm_outer, utm_inner = response(replies[0], expect_uid=False)
    login_outer, login_inner = response(replies[1], expect_uid=False)
    for outer in (utm_outer, login_outer):
        assert outer["i"] == 0
        assert outer["cid"] == MAC and outer["tcid"] == host_mac
        assert "uid" not in outer
    assert utm_outer["msgId"] == utm_msg_id
    assert utm_inner == {"t": "Utm"}
    assert login_outer["msgId"] == login_msg_id
    assert type(login_inner["curGnetID"]) is int
    assert login_inner == {
        "t": "getLoginInfo", "loginInfo": ["GnetID"], "curGnetID": cur_gnet_id,
    }


def test_udp_registration_is_exact_and_general_cloud_only_callbacks_are_not_udp():
    root = controller()
    source = FIXTURE["transport"]
    registered = [(item["name"], item["slot"]) for item in source["udp_table"]]
    assert registered == [
        ("scan", 1), ("UBindok", 0), ("ret", 0), ("binCmd", 0), ("reset", 0),
        ("hbok", 1), ("Utm", 0), ("loginInfoRes", 0), ("statusCheck", 0),
    ]
    before = deepcopy(root.state)
    for operation in source["general_cloud_only"]:
        slot = operation["slot"]
        assert send(root, {"t": operation["name"]}, selector=slot) == []
        assert root.state == before
    assert send(root, {"t": "cmd", "opt": ["ReportClientID"], "p": ["report-host"]}) == []
    assert root.state == before
    assert send(root, {"t": "hbok"}, selector=3) == []
    assert root.state == before
    assert root.profile.handler.advertise(root, {"t": "scan"}) == []


def test_all_nine_udp_callbacks_match_the_source_output_contract():
    cases = [
        ("scan", 1, {"t": "scan"}, "scan"),
        ("UBindok", 0, {"t": "UBindok", "host": HOST_MAC, "hostManaged": 1, "roomId": 2}, "UBindok"),
        ("ret", 0, {"t": "ret", "r": 200}, None),
        ("binCmd", 0, {"t": "binCmd"}, "binCmd"),
        ("reset", 0, {"t": "reset", "mac": MAC}, "reset"),
        ("hbok", 1, {"t": "hbok"}, None),
        ("Utm", 0, {"t": "Utm", "time": "2026-01-02 03:04:05"}, None),
        ("loginInfoRes", 0, {"t": "loginInfoRes", "r": 200, "result": {"platform": 3}}, None),
        ("statusCheck", 0, {"t": "statusCheck"}, None),
    ]
    for operation, selector, payload, reply_kind in cases:
        root = controller()
        replies = send(root, payload, selector=selector, uid=0xFFFFFFFF)
        if reply_kind == "UBindok":
            assert_ubindok_proactive(replies)
            assert root.state["_runtime"]["msg_id"] == 2
            continue
        if reply_kind is None:
            assert replies == [], operation
            continue
        reply, = replies
        outer, inner = response(reply)
        assert outer == {
            "t": "pack", "i": selector, "uid": 0xFFFFFFFF, "msgId": 0,
            "cid": MAC, "tcid": "", "pack": outer["pack"],
        }
        if reply_kind == "scan":
            assert inner == {
                "t": "UBind", "scene": inner["scene"], "mid": "10001", "ver": "V3.5.M",
                "lock": 0, "devkey": KEY.decode("ascii"), "hid": FIXTURE["hid"],
            }
            assert type(inner["scene"]) is int
            assert inner["scene"] in FIXTURE["transport"]["scan"]["scene_numeric_values"]
        elif reply_kind == "binCmd":
            assert inner == {"t": "res", "r": 200, "mac": MAC}
        else:
            assert inner == {"t": "ret", "r": 200, "mac": MAC}


def test_source_key_slots_and_lf_framing_are_not_gree_lan_framing():
    root = controller()
    assert GENERIC == b"en (otClceakve r" and GENERIC != KEY

    request = request_bytes({"t": "scan"}, selector=1, uid=42)
    assert not request.endswith(b"\n")
    outer = decode_outer(request)
    plaintext = unpad(
        AES.new(GENERIC, AES.MODE_ECB).decrypt(base64.b64decode(outer["pack"], validate=True)),
        AES.block_size,
    )
    assert plaintext == b'{"t":"scan"}\n'
    reply, = send(root, {"t": "scan"}, selector=1)
    encoded = encode_reply(reply)
    outer_reply = json.loads(encoded)
    assert not encoded.endswith(b"\n")
    reply_plaintext = unpad(
        AES.new(GENERIC, AES.MODE_ECB).decrypt(base64.b64decode(outer_reply["pack"], validate=True)),
        AES.block_size,
    )
    assert reply_plaintext.endswith(b"\n")
    assert json.loads(reply_plaintext[:-1])["t"] == "UBind"
    wrapped_selector, _ = response(send(root, {"t": "scan"}, selector=257)[0])
    assert wrapped_selector["i"] == 1


def test_emulator_server_routes_udp5001_to_fixed_reply_port5000_without_tcid_filter():
    root = controller()
    counter = FIXTURE["transport"]["scan"]["synthetic_scan_then_ubindok_counter_vector"]

    async def scenario():
        server = EmulatorServer([root])
        sent = []
        server.transport = SimpleNamespace(
            sendto=lambda data, addr: sent.append((data, addr)),
            close=lambda: server.connection_lost(None),
        )
        packet = request_bytes({"t": "scan"}, selector=1, uid=12, tcid="not-the-module")
        assert root.state["_runtime"]["msg_id"] == counter["initial_msg_id"]
        server.datagram_received(packet, ("127.0.0.1", 5001))
        assert len(sent) == 1
        data, destination = sent[0]
        assert destination == ("127.0.0.1", 5000)
        outer, inner = wire_response(data)
        assert inner["t"] == "UBind"
        assert outer["cid"] == MAC and outer["tcid"] == ""
        assert outer["msgId"] == counter["scan_reply_msg_id"]
        assert root.state["_runtime"]["msg_id"] == counter["counter_after_scan"]

        managed = request_bytes(
            {"t": "UBindok", "host": HOST_MAC, "hostManaged": 1, "roomId": 2},
            uid=0xFFFFFFFF,
        )
        server.datagram_received(managed, ("127.0.0.1", 5001))
        assert len(sent) == 3
        proactive = []
        for data, destination in sent[1:]:
            assert destination == ("127.0.0.1", 5000)
            proactive.append(wire_response(data, expect_uid=False))
        assert [inner for _, inner in proactive] == [
            {"t": "Utm"},
            {"t": "getLoginInfo", "loginInfo": ["GnetID"], "curGnetID": 0},
        ]
        assert [outer["msgId"] for outer, _ in proactive] == [
            counter["ubindok_utm_msg_id"], counter["ubindok_login_msg_id"],
        ]
        assert all(outer["cid"] == MAC and outer["tcid"] == HOST_MAC for outer, _ in proactive)
        assert root.state["_runtime"]["msg_id"] == counter["counter_after_ubindok"]

        server.datagram_received(packet, ("127.0.0.1", 5000))
        oversized = json.dumps({
            "t": "pack", "i": 1, "uid": 12, "cid": "host", "tcid": "x" * 1600,
            "pack": "AAAA",
        }, separators=(",", ":")).encode()
        server.datagram_received(oversized, ("127.0.0.1", 5001))
        assert len(sent) == 3
        server.close()

    asyncio.run(scenario())


def test_managed_host_room_uid_counters_and_source_proactive_lifecycle():
    root = controller()
    host_addr = ("192.0.2.99", 5001)
    replies = send(
        root, {"t": "UBindok", "host": HOST_MAC, "hostManaged": 1, "roomId": 258, "lock": 0},
        addr=host_addr,
    )
    assert_ubindok_proactive(replies)
    runtime = root.state["_runtime"]
    assert runtime["host_managed"] == 1
    assert runtime["lock"] == 1
    assert runtime["host_mac"] == HOST_MAC != root.mac
    assert runtime["host_addr"] == host_addr
    assert runtime["room_id"] == 2
    assert runtime["msg_id"] == 2

    assert send(root, {"t": "scan"}, selector=1) == []
    bound_scan, = send(root, {"t": "scan", "i": 1}, selector=1)
    bound_outer, bound_inner = response(bound_scan)
    assert bound_inner["t"] == "UBind"
    assert type(bound_inner["scene"]) is int
    assert bound_inner["scene"] in FIXTURE["transport"]["scan"]["scene_numeric_values"]

    assert send(root, {"t": "UBindok", "host": "", "hostManaged": 0, "roomId": 258}, addr=host_addr) == []
    runtime = root.state["_runtime"]
    assert runtime["host_managed"] == 0 and runtime["host_mac"] == ""
    assert runtime["host_addr"] is None
    assert runtime["room_id"] == 2

def test_ubindok_missing_host_managed_enters_native_managed_branch_and_ignores_lock():
    root = controller()
    replies = send(root, {"t": "UBindok", "host": HOST_MAC, "lock": 0})
    assert_ubindok_proactive(replies)
    runtime = root.state["_runtime"]
    assert runtime["host_managed"] == 1
    assert runtime["host_mac"] == HOST_MAC and runtime["host_addr"] == ADDR
    assert runtime["lock"] == 1 and runtime["msg_id"] == 2
    assert runtime["heartbeat_watchdog_due"] is not None


def test_unmanaged_ubind_retries_use_virtual_source_countdowns():
    retry = FIXTURE["lifecycle"]["ubind_retry"]
    root = controller()
    runtime = root.state["_runtime"]
    runtime.update(retry["synthetic_test_initial_state"])
    expected = retry["synthetic_test_outbound"]

    def assert_ubind_send(now):
        (reply, addr), = root.profile.handler.tick(root, now)
        assert addr == (expected["destination_host"], expected["destination_port"])
        outer, inner = response(reply, expect_uid=False)
        assert outer["i"] == expected["selector"] and outer["msgId"] == expected["msgId"]
        assert outer["cid"] == MAC and outer["tcid"] == expected["tcid"]
        assert inner == expected["inner"]

    assert_ubind_send(0.0)
    assert runtime["ubind_retry_count"] == 1 and runtime["ubind_flag"] == 0x43
    assert root.profile.handler.tick(root, 0.299) == []
    assert_ubind_send(0.301)
    assert runtime["ubind_retry_count"] == 2 and runtime["ubind_flag"] == 0x43
    assert root.profile.handler.tick(root, 0.599) == []
    assert_ubind_send(0.601)

    assert runtime["ubind_retry_count"] == -1
    assert runtime["ubind_flag"] == 0 and runtime["ubind_timer"] == 0x401E
    assert runtime["msg_id"] == expected["msgId"]
    assert root.profile.handler.tick(root, 0.699) == []
    assert runtime["ubind_timer"] == 0x401E

    calls_to_next_update = 10 - runtime["countdown_calls"]
    calls_to_expiry = calls_to_next_update + 29 * 10
    expiry = runtime["countdown_next_at"] + (calls_to_expiry - 1) * 0.1
    assert root.profile.handler.tick(root, expiry - 0.001) == []
    assert runtime["ubind_timer"] == 0x4001
    assert root.profile.handler.tick(root, expiry + 0.001) == []
    assert runtime["ubind_retry_count"] == 0 and runtime["ubind_timer"] == 0

    runtime.update(retry["synthetic_test_alternate_gate"])
    assert_ubind_send(expiry + 0.102)
    assert runtime["ubind_retry_count"] == 1
    runtime["ubind_gate_4e5"] = 0
    assert root.profile.handler.tick(root, expiry + 0.102) == []
    assert runtime["ubind_retry_count"] == 0
    assert runtime["ubind_flag"] == 0 and runtime["ubind_timer"] == 0


def test_managed_worker_login_info_uses_the_1500ms_source_countdown():
    root = controller()
    host_addr = ("192.0.2.99", 5001)
    cur_gnet_id = FIXTURE["lifecycle"]["ubindok"]["proactive_packets"]["getLoginInfo"][
        "synthetic_test_curGnetID_u8"
    ]
    root.state["_runtime"]["controller_id_available"] = cur_gnet_id
    proactive = send(
        root, {"t": "UBindok", "host": HOST_MAC, "hostManaged": 1}, addr=host_addr,
    )
    assert_ubindok_proactive(proactive, cur_gnet_id=cur_gnet_id)

    runtime = root.state["_runtime"]
    first_due = runtime["countdown_next_at"]
    assert runtime["source_state_7"] == 0x4F
    assert root.profile.handler.tick(root, first_due + 1.399) == []
    assert runtime["source_state_7"] == 0x41
    scheduled = root.profile.handler.tick(root, first_due + 1.401)
    (reply, addr), = scheduled
    assert addr == (host_addr[0], 5000)
    outer, inner = response(reply, expect_uid=False)
    assert outer["i"] == 0 and outer["msgId"] == 3
    assert outer["cid"] == MAC and outer["tcid"] == HOST_MAC
    assert inner == {"t": "getLoginInfo", "loginInfo": ["GnetID"], "curGnetID": cur_gnet_id}
    assert runtime["source_state_7"] == 0x4F
    assert runtime["msg_id"] == 3


def test_managed_ubindok_starts_60s_heartbeat_and_61s_watchdog():
    root = controller()
    host_addr = ("192.0.2.99", 5001)
    replies = send(
        root, {"t": "UBindok", "host": HOST_MAC, "hostManaged": 1}, addr=host_addr,
    )
    assert_ubindok_proactive(replies)
    runtime = root.state["_runtime"]
    assert runtime["heartbeat_period_ms"] == 60000
    assert runtime["heartbeat_period_due"] is not None
    assert runtime["heartbeat_timer_active"] is True
    assert runtime["heartbeat_timer_ms"] == 61000
    assert runtime["heartbeat_watchdog_due"] is not None
    assert runtime["msg_id"] == 2

    assert send(root, {"t": "hbok"}, selector=1) == []
    runtime = root.state["_runtime"]
    assert runtime["heartbeat_timer_active"] is True
    assert runtime["heartbeat_timer_ms"] == 61000
    assert runtime["heartbeat_watchdog_due"] is not None
    assert runtime["heartbeat_watchdog_due"] > runtime["heartbeat_period_due"]
    assert runtime["msg_id"] == 3



@pytest.mark.parametrize(("initial_msg_id", "expected_msg_id"), [(41, 41), (65535, 65535), (65536, 0)])
def test_heartbeat_period_emits_exact_generic_hb_without_incrementing_msg_id(
    initial_msg_id, expected_msg_id,
):
    root = controller()
    heartbeat = FIXTURE["lifecycle"]["heartbeat"]
    host_addr = ("192.0.2.99", 5001)
    runtime = root.state["_runtime"]
    runtime.update({
        "host_managed": 1, "host_mac": HOST_MAC, "host_addr": host_addr,
        "msg_id": initial_msg_id, "rssi": heartbeat["synthetic_test_rssi_u32"],
        "source_state_7": 0, "heartbeat_timer_active": True,
        "heartbeat_period_due": 1000.0, "heartbeat_period_ms": 60000,
        "heartbeat_watchdog_due": 1061.0,
    })
    assert root.profile.handler.tick(root, 999.999) == []
    (reply, addr), = root.profile.handler.tick(root, 1000.001)
    assert addr == (host_addr[0], 5000)
    outer, inner = response(reply)
    assert outer["i"] == 1 and outer["uid"] == 0
    assert outer["msgId"] == expected_msg_id
    assert outer["cid"] == MAC and outer["tcid"] == HOST_MAC
    assert inner == {"t": "hb", "cid": MAC, "RSSI": heartbeat["synthetic_test_rssi_u32"]}
    assert runtime["msg_id"] == expected_msg_id
    assert runtime["heartbeat_period_ms"] == 60000


def test_watchdog_virtual_jitter_schedules_a_distinct_one_second_heartbeat():
    root = controller()
    runtime = root.state["_runtime"]
    host_addr = ("192.0.2.99", 5001)
    runtime.update({
        "virtual_boot_time": 0.0, "host_managed": 1, "host_mac": HOST_MAC,
        "host_addr": host_addr, "source_state_7": 0, "heartbeat_timer_active": True,
        "heartbeat_watchdog_due": 61.0, "heartbeat_period_due": None,
    })
    watchdog_now = 61.001
    assert root.profile.handler.tick(root, watchdog_now) == []
    assert runtime["heartbeat_watchdog_due"] == pytest.approx(watchdog_now + 61)
    seed = int(watchdog_now * 1000) & 0xFFFFFFFF
    lcg_state = (seed * 0x5851F42D4C957F2D + 1) & 0xFFFFFFFFFFFFFFFF
    jitter_ms = (((lcg_state >> 32) & 0x7FFFFFFF) % 10) * 300
    expected_due = watchdog_now + 1 + jitter_ms / 1000
    assert runtime["heartbeat_period_ms"] == 1000
    assert runtime["heartbeat_period_due"] == pytest.approx(expected_due)
    assert root.profile.handler.tick(root, expected_due - 0.001) == []
    (reply, addr), = root.profile.handler.tick(root, expected_due + 0.001)
    assert addr == (host_addr[0], 5000)
    outer, inner = response(reply)
    assert outer["i"] == 1 and outer["uid"] == 0
    assert inner["t"] == "hb"
    assert runtime["heartbeat_miss_count"] == 1
    assert runtime["heartbeat_period_ms"] == 60000

def test_three_unanswered_watchdog_heartbeats_clear_binding_but_preserve_retry_gate(
    monkeypatch,
):
    root = controller()
    clock = [10.0]
    monkeypatch.setattr(family, "monotonic", lambda: clock[0])
    retry_contract = FIXTURE["lifecycle"]["ubind_retry"]
    retry = retry_contract["synthetic_test_outbound"]
    retry_gate = retry_contract["synthetic_test_alternate_gate"]
    host_addr = ("192.0.2.99", 5001)
    root.state["_runtime"]["virtual_boot_time"] = 0.0
    root.state["_runtime"].update(retry_gate)
    replies = send(
        root, {"t": "UBindok", "host": HOST_MAC, "hostManaged": 1}, addr=host_addr,
    )
    assert_ubindok_proactive(replies)
    runtime = root.state["_runtime"]
    assert runtime["ubind_gate_4ed"] == retry_gate["ubind_gate_4ed"]
    assert runtime["ubind_gate_4e5"] == retry_gate["ubind_gate_4e5"]
    assert runtime["report_ready"] == 0
    assert runtime["heartbeat_watchdog_due"] is not None
    assert send(root, {"t": "hbok"}, selector=1) == []
    runtime = root.state["_runtime"]
    assert runtime["msg_id"] == 3
    assert send(
        root, {"t": "loginInfoRes", "r": 200, "result": {"platform": 3}}
    ) == []
    runtime = root.state["_runtime"]
    assert runtime["source_state_7"] == 0

    def decode_replies(replies):
        decoded = []
        for reply, addr in replies:
            assert addr in ((host_addr[0], 5000), ("255.255.255.255", 5000))
            outer, inner = response(reply, expect_uid="uid" in reply.outer)
            decoded.append((addr, outer, inner))
        return decoded

    def tick_until(deadline):
        replies = []
        while True:
            current_runtime = root.state["_runtime"]
            callback_at = current_runtime["countdown_next_at"]
            if callback_at is None or callback_at > deadline:
                break
            clock[0] = callback_at
            replies.extend(root.profile.handler.tick(root, callback_at))
        clock[0] = deadline
        replies.extend(root.profile.handler.tick(root, deadline))
        return decode_replies(replies)

    first_due = runtime["heartbeat_period_due"]
    initial = tick_until(first_due + 0.001)
    initial_heartbeats = [item for item in initial if item[2]["t"] == "hb"]
    assert len(initial_heartbeats) == 1
    initial_heartbeat, = initial_heartbeats
    assert initial_heartbeat[1]["i"] == 1 and initial_heartbeat[1]["uid"] == 0
    assert initial_heartbeat[1]["msgId"] == 3
    assert runtime["heartbeat_miss_count"] == 0
    for expected_misses in (1, 2, 3):
        watchdog_due = runtime["heartbeat_watchdog_due"]
        assert watchdog_due is not None
        watchdog_events = tick_until(watchdog_due + 0.001)
        assert not any(item[2]["t"] == "hb" for item in watchdog_events)
        followup_due = runtime["heartbeat_period_due"]
        assert runtime["heartbeat_period_ms"] == 1000
        decoded = tick_until(followup_due + 0.001)
        heartbeats = [item for item in decoded if item[2]["t"] == "hb"]
        assert len(heartbeats) == 1
        assert heartbeats[0][1]["i"] == 1 and heartbeats[0][1]["uid"] == 0
        assert heartbeats[0][1]["msgId"] == 3
        if expected_misses < 3:
            assert runtime["heartbeat_miss_count"] == expected_misses
            assert runtime["host_managed"] == 1
        else:
            if not any(item[2]["t"] == "UBind" for item in decoded):
                decoded.extend(tick_until(followup_due + 0.102))
            ubinds = [item for item in decoded if item[2]["t"] == "UBind"]
            assert len(ubinds) == 1
            _, outer, inner = ubinds[0]
            assert outer["i"] == retry["selector"]
            # Disconnect invokes HBOK's counter increment before UBind retries.
            assert outer["msgId"] == 4
            assert "uid" not in outer and outer["tcid"] == ""
            assert inner == retry["inner"]
            assert runtime["heartbeat_miss_count"] == 0
            assert runtime["host_managed"] == 0 and runtime["lock"] == 0
            assert runtime["host_addr"] == host_addr and runtime["host_mac"] == HOST_MAC
            assert runtime["ubind_gate_4ed"] == retry_gate["ubind_gate_4ed"]
            assert runtime["ubind_gate_4e5"] == retry_gate["ubind_gate_4e5"]
            assert runtime["report_ready"] == 0
            assert runtime["heartbeat_timer_active"] is False
            assert runtime["heartbeat_watchdog_due"] is None


def test_source_byte_countdown_0x4a_expires_after_ten_100ms_callbacks():
    root = controller()
    runtime = root.state["_runtime"]
    runtime["countdown_next_at"] = 1000.1
    runtime["countdown_bytes"][6] = int(
        FIXTURE["lifecycle"]["udp_worker"]["byte_timer_countdown_values"]["1000ms"], 16
    )
    assert root.profile.handler.tick(root, 1000.999) == []
    assert runtime["countdown_bytes"][6] == 0x41
    assert root.profile.handler.tick(root, 1001.001) == []
    assert runtime["countdown_bytes"][6] == 0x80


def test_countdown_active_markers_and_ten_callback_phase_match_source(monkeypatch):
    root = controller()
    clock = [999.9]
    monkeypatch.setattr(family, "monotonic", lambda: clock[0])
    assert root.profile.handler.tick(root, clock[0]) == []

    runtime = root.state["_runtime"]
    timer = FIXTURE["lifecycle"]["udp_worker"]
    markers = timer["countdown_marker_vectors"]
    byte_marker, byte_three = markers[:2]
    halfword_marker, halfword_one = markers[2:]
    runtime["countdown_bytes"][0] = int(byte_marker["initial"], 16)
    runtime["countdown_bytes"][1] = int(byte_three["initial"], 16)
    runtime["countdown_halfwords"][0] = int(halfword_marker["initial"], 16)
    runtime["countdown_halfwords"][1] = int(halfword_one["initial"], 16)

    clock[0] = 1000.001
    assert root.profile.handler.tick(root, clock[0]) == []
    runtime = root.state["_runtime"]
    assert runtime["countdown_bytes"][0] == int(byte_marker["after_one_callback"], 16)
    assert runtime["countdown_bytes"][1] == int(byte_three["after_one_callback"], 16)
    assert runtime["countdown_halfwords"][0] == int(halfword_marker["initial"], 16)

    clock[0] = 1000.901
    assert root.profile.handler.tick(root, clock[0]) == []
    runtime = root.state["_runtime"]
    assert runtime["countdown_bytes"][1] == int(byte_three["after_three_callbacks"], 16)
    assert runtime["countdown_halfwords"][0] == int(
        halfword_marker["after_one_table_update"], 16
    )
    assert runtime["countdown_halfwords"][1] == int(
        halfword_one["after_one_table_update"], 16
    )
    assert runtime["countdown_calls"] == 0


def test_huge_elapsed_countdown_gap_is_bounded_and_preserves_source_phase(monkeypatch):
    vector = FIXTURE["lifecycle"]["udp_worker"]["synthetic_large_elapsed_gap_vector"]
    callbacks = vector["callbacks_due"]
    slow_updates, calls_after = divmod(
        vector["initial_countdown_calls"] + callbacks, 10
    )
    assert slow_updates == vector["slow_table_updates_due"]
    assert calls_after == vector["countdown_calls_after"]
    assert vector["first_countdown_deadline_s"] + callbacks / 10 == pytest.approx(
        vector["next_countdown_deadline_s"]
    )

    actual_count_down = family._count_down
    count_down_calls = 0

    def count_down(*args, **kwargs):
        nonlocal count_down_calls
        count_down_calls += 1
        assert count_down_calls <= vector["maximum_local_model_count_down_helper_calls_per_tick"]
        return actual_count_down(*args, **kwargs)

    monkeypatch.setattr(family, "_count_down", count_down)
    root = controller()
    clock = [vector["initial_monotonic_s"]]
    monkeypatch.setattr(family, "monotonic", lambda: clock[0])
    assert root.profile.handler.tick(root, clock[0]) == []
    runtime = root.state["_runtime"]
    assert runtime["countdown_next_at"] == pytest.approx(vector["first_countdown_deadline_s"])
    runtime["countdown_calls"] = vector["initial_countdown_calls"]
    runtime["countdown_bytes"][0] = int(vector["byte_input"], 16)
    runtime["countdown_halfwords"][0] = int(vector["halfword_input"], 16)
    runtime["countdown_extra_byte"] = int(vector["extra_byte_input"], 16)

    clock[0] = vector["target_monotonic_s"]
    assert root.profile.handler.tick(root, clock[0]) == []
    assert count_down_calls == vector["expected_count_down_helper_calls"]
    runtime = root.state["_runtime"]
    assert runtime["countdown_bytes"][0] == int(vector["byte_output"], 16)
    assert runtime["countdown_halfwords"][0] == int(vector["halfword_output"], 16)
    assert runtime["countdown_extra_byte"] == int(vector["extra_byte_output"], 16)
    assert runtime["countdown_calls"] == calls_after
    assert runtime["countdown_next_at"] == pytest.approx(
        vector["next_countdown_deadline_s"]
    )


@pytest.mark.parametrize("one_ulp_below", [False, True])
def test_source_countdown_decimal_boundary_uses_inclusive_callback_count(
    one_ulp_below, monkeypatch,
):
    vector = FIXTURE["lifecycle"]["udp_worker"]["synthetic_float_boundary_vector"]
    expected = vector["one_ulp_below"] if one_ulp_below else vector
    target = (
        math.nextafter(vector["target_monotonic_s"], -math.inf)
        if one_ulp_below else vector["target_monotonic_s"]
    )
    root = controller()
    clock = [vector["initial_monotonic_s"]]
    monkeypatch.setattr(family, "monotonic", lambda: clock[0])
    assert root.profile.handler.tick(root, clock[0]) == []
    runtime = root.state["_runtime"]
    assert runtime["countdown_next_at"] == vector["first_countdown_deadline_s"]
    runtime["countdown_bytes"][0] = int(vector["byte_input"], 16)

    clock[0] = target
    assert root.profile.handler.tick(root, clock[0]) == []
    runtime = root.state["_runtime"]
    assert runtime["countdown_bytes"][0] == int(expected["byte_output"], 16)
    assert runtime["countdown_calls"] == expected["expected_callbacks_due"]
    assert runtime["countdown_next_at"] == expected["next_countdown_deadline_s"]
    assert runtime["countdown_next_at"] > target



def test_ubindok_queues_type6_source_report_and_retries_four_times():
    queue = FIXTURE["lifecycle"]["raw_report_queue"]
    vectors = queue["synthetic_test_vectors"]
    address = "0x10016974"
    frame = bytes.fromhex(vectors["source_frames_by_address_hex"][address])
    root = controller()
    root.state["_runtime"]["ubind_gate_4ed"] = 1
    root.state["raw_status_frames"][int(address, 16)] = frame

    proactive = send(root, {"t": "UBindok", "host": HOST_MAC, "hostManaged": 1})
    assert_ubindok_proactive(proactive)
    runtime = root.state["_runtime"]
    assert runtime["report_ready"] == 1 and runtime["report_type"] == 6
    first_due = runtime["countdown_next_at"]
    assert first_due is not None
    virtual_time = vectors["virtual_clock_start"]
    runtime["time"] = runtime["virtual_clock_base"] = virtual_time
    runtime["virtual_clock_started_at"] = first_due
    runtime["virtual_clock_elapsed_seconds"] = 0
    runtime["raw_clock"] = bytes.fromhex(vectors["initial_virtual_raw_clock_hex"])

    before_msg_id = runtime["msg_id"]
    first = [
        item for item in decoded_tick(root, first_due)
        if item[1].get("t") == "binStatus"
    ]
    assert len(first) == 1
    outer, inner, destination = first[0]
    assert outer["i"] == 0 and "uid" not in outer and outer["msgId"] == before_msg_id == 2
    assert outer["cid"] == MAC and outer["tcid"] == HOST_MAC
    assert destination == (ADDR[0], 5000)
    clock_hex = vectors["type6_retry_raw_clock_hex"][0]
    assert inner == expected_raw_status(frame, clock_hex)
    assert base64.b64decode(inner["binStatus"], validate=True) == frame
    assert runtime["msg_id"] == before_msg_id
    assert runtime["report_marker"] == 0x4a and runtime["report_retry_count"] == 1

    for attempt in range(2, 5):
        due = first_due + attempt - 1
        early = decoded_tick(root, due - 0.001)
        assert not any(inner.get("t") == "binStatus" for _outer, inner, _destination in early)
        before_msg_id = root.state["_runtime"]["msg_id"]
        packets = [
            item for item in decoded_tick(root, due)
            if item[1].get("t") == "binStatus"
        ]
        assert len(packets) == 1
        outer, inner, destination = packets[0]
        assert outer["msgId"] == before_msg_id
        assert "uid" not in outer and outer["i"] == 0
        assert outer["cid"] == MAC and outer["tcid"] == HOST_MAC
        assert destination == (ADDR[0], 5000)
        clock_hex = vectors["type6_retry_raw_clock_hex"][attempt - 1]
        assert root.state["_runtime"]["raw_clock"].hex() == clock_hex
        assert inner == expected_raw_status(frame, clock_hex)
        runtime = root.state["_runtime"]
        if attempt < 4:
            assert runtime["report_ready"] == 1
            assert runtime["report_marker"] == 0x4a
            assert runtime["report_retry_count"] == attempt
        else:
            assert runtime["report_ready"] == 0 and runtime["report_type"] == 0
            assert runtime["report_marker"] == 0 and runtime["report_retry_count"] == -1

    assert not any(
        inner.get("t") == "binStatus"
        for _outer, inner, _destination in decoded_tick(root, first_due + 4)
    )


def test_ubindok_type6_report_waits_for_independent_network_ready_gate():
    root = controller()
    assert_ubindok_proactive(
        send(root, {"t": "UBindok", "host": HOST_MAC, "hostManaged": 1})
    )
    runtime = root.state["_runtime"]
    assert runtime["ubind_gate_4ed"] == 0
    assert runtime["report_type"] == 6 and runtime["report_ready"] == 0
    due = runtime["countdown_next_at"]
    assert due is not None
    assert not any(
        inner.get("t") == "binStatus"
        for _outer, inner, _destination in decoded_tick(root, due)
    )

def test_ret_r200_clears_pending_type6_retry_context_without_ack():
    queue = FIXTURE["lifecycle"]["raw_report_queue"]
    address = "0x10016974"
    frame = bytes.fromhex(queue["synthetic_test_vectors"]["source_frames_by_address_hex"][address])
    root = controller()
    root.state["_runtime"]["ubind_gate_4ed"] = 1
    root.state["raw_status_frames"][int(address, 16)] = frame
    assert_ubindok_proactive(
        send(root, {"t": "UBindok", "host": HOST_MAC, "hostManaged": 1})
    )
    runtime = root.state["_runtime"]
    first_due = runtime["countdown_next_at"]
    assert len([
        item for item in decoded_tick(root, first_due)
        if item[1].get("t") == "binStatus"
    ]) == 1
    assert root.state["_runtime"]["report_marker"] == 0x4a

    assert send(root, {"t": "ret", "r": 200}) == []
    assert root.state["_runtime"]["report_marker"] == 0
    next_callback = root.state["_runtime"]["countdown_next_at"]
    assert next_callback is not None
    assert not any(
        inner.get("t") == "binStatus"
        for _outer, inner, _destination in decoded_tick(root, next_callback)
    )
    runtime = root.state["_runtime"]
    assert runtime["report_ready"] == 0 and runtime["report_type"] == 0


def test_status_check_type7_selector_and_virtual_timestamp():
    queue = FIXTURE["lifecycle"]["raw_report_queue"]
    vectors = queue["synthetic_test_vectors"]
    root = controller()
    root.state["_runtime"]["ubind_gate_4ed"] = 1
    for address, raw_hex in vectors["source_frames_by_address_hex"].items():
        root.state["raw_status_frames"][int(address, 16)] = bytes.fromhex(raw_hex)

    caches = vectors["raw_cache_frames_hex"]
    raw_command = {"t": "binCmd"}
    raw_command.update({
        name: base64.b64encode(bytes.fromhex(caches[f"raw_{name}"])).decode("ascii")
        for name in ("hex92", "hex93", "hex6A")
    })
    ack, = send(root, raw_command)
    assert response(ack)[1] == {"t": "res", "r": 200, "mac": MAC}
    assert_ubindok_proactive(
        send(root, {"t": "UBindok", "host": HOST_MAC, "hostManaged": 1}),
        utm_msg_id=1,
        login_msg_id=2,
    )
    root.state["_runtime"]["raw_status_source_flag"] = 1
    assert send(root, {"t": "statusCheck"}) == []
    runtime = root.state["_runtime"]
    extended = bytes.fromhex(vectors["extended_aggregate_hex"])
    assert root.state["status_check"] == 0
    assert runtime["report_ready"] == 1 and runtime["report_type"] == 7

    first_due = runtime["countdown_next_at"]
    assert first_due is not None
    virtual_time = vectors["virtual_clock_start"]
    initial_clock = bytes.fromhex(vectors["initial_virtual_raw_clock_hex"])
    runtime["time"] = runtime["virtual_clock_base"] = virtual_time
    runtime["virtual_clock_started_at"] = first_due
    runtime["virtual_clock_elapsed_seconds"] = 0
    runtime["raw_clock"] = initial_clock
    before_msg_id = runtime["msg_id"]
    first = [
        item for item in decoded_tick(root, first_due)
        if item[1].get("t") == "statusCheckRes"
    ]
    assert len(first) == 1
    outer, inner, destination = first[0]
    assert outer["i"] == 0 and "uid" not in outer and outer["msgId"] == before_msg_id == 3
    assert outer["cid"] == MAC and outer["tcid"] == HOST_MAC
    assert destination == (ADDR[0], 5000)
    assert inner == {
        "t": "statusCheckRes",
        "timestamp": vectors["baseline_status_timestamp_signed32"],
        "binStatus": base64.b64encode(extended).decode("ascii"),
    }
    assert root.state["_runtime"]["msg_id"] == before_msg_id
    assert root.state["_runtime"]["report_ready"] == 0

    runtime = root.state["_runtime"]
    assert runtime["raw_status_source_flag"] == 1
    assert root.state["raw_hex6A"][3] == 0x6a
    runtime["raw_status_source_flag"] = 0
    assert send(root, {"t": "statusCheck"}) == []
    default = bytes.fromhex(vectors["default_aggregate_hex"])
    second_due = runtime["countdown_next_at"]
    assert second_due is not None
    runtime["time"] = runtime["virtual_clock_base"] = virtual_time
    runtime["virtual_clock_started_at"] = second_due
    runtime["virtual_clock_elapsed_seconds"] = 0
    runtime["raw_clock"] = initial_clock
    second = [
        item for item in decoded_tick(root, second_due)
        if item[1].get("t") == "statusCheckRes"
    ]
    assert len(second) == 1
    _outer, inner, _destination = second[0]
    assert inner == {
        "t": "statusCheckRes",
        "timestamp": vectors["baseline_status_timestamp_signed32"],
        "binStatus": base64.b64encode(default).decode("ascii"),
    }
    assert root.state["_runtime"]["report_ready"] == 0

    runtime["raw_status_source_flag"] = 1
    root.state["raw_hex6A"] = bytes(FIXTURE["raw_binary"]["buffer_capacities"]["hex6A"])
    assert send(root, {"t": "statusCheck"}) == []
    third_due = runtime["countdown_next_at"]
    assert third_due is not None
    runtime["time"] = runtime["virtual_clock_base"] = virtual_time
    runtime["virtual_clock_started_at"] = third_due
    runtime["virtual_clock_elapsed_seconds"] = 0
    runtime["raw_clock"] = initial_clock
    third = [
        item for item in decoded_tick(root, third_due)
        if item[1].get("t") == "statusCheckRes"
    ]
    assert len(third) == 1
    _outer, inner, _destination = third[0]
    assert inner == {
        "t": "statusCheckRes",
        "timestamp": vectors["baseline_status_timestamp_signed32"],
        "binStatus": base64.b64encode(default).decode("ascii"),
    }
    assert root.state["_runtime"]["report_ready"] == 0


def test_ret_hbok_utm_login_result_and_status_check_update_only_native_fields():
    root = controller()
    root.state["_runtime"].update({"report_timer": 0x4005, "report_marker": 0x4a})
    assert send(root, {"t": "ret", "r": 456}) == []
    runtime = root.state["_runtime"]
    assert runtime["report_marker"] == 0 and runtime["report_timer"] == 0x4005

    runtime["host_managed"] = 1
    runtime["host_addr"] = ADDR
    runtime["heartbeat_miss_count"] = 2
    assert send(root, {"t": "hbok", "r": 0}, selector=1) == []
    runtime = root.state["_runtime"]
    assert runtime["msg_id"] == 1 and runtime["heartbeat_miss_count"] == 0
    assert runtime["heartbeat_timer_active"] is True
    assert runtime["heartbeat_timer_ms"] == 61000
    assert runtime["heartbeat_watchdog_due"] is not None
    assert send(root, {"t": "hbok", "r": 1}, selector=1) == []
    runtime = root.state["_runtime"]
    assert runtime["msg_id"] == 2 and runtime["heartbeat_miss_count"] == 0

    assert send(root, {"t": "Utm", "time": "2026-01-02 03:04:05"}) == []
    runtime = root.state["_runtime"]
    assert runtime["time"] == "2026-01-02 03:04:05"
    assert runtime["status_save_pending"] is True

    assert send(root, {"t": "loginInfoRes", "r": 200, "result": {"platform": 3}}) == []
    runtime = root.state["_runtime"]
    assert runtime["cloud_platform"] == 3

    platform_vector = FIXTURE["lifecycle"]["loginInfoRes"][
        "synthetic_platform_u8_vector"
    ]
    login_info_res = {
        "t": "loginInfoRes", "r": 406,
        "result": {"platform": platform_vector["input"]},
    }
    assert send(root, login_info_res) == []
    runtime = root.state["_runtime"]
    assert runtime["cloud_platform"] == platform_vector["stored"]
    before = deepcopy(root.state)
    assert send(root, {"t": "loginInfoRes", "r": 404}) == []
    assert root.state == before

    assert send(root, {"t": "statusCheck"}) == []
    assert root.state["status_check"] == 0
    runtime = root.state["_runtime"]
    assert runtime["report_type"] == 7 and runtime["report_ready"] == 0


def test_hbok_on_unmanaged_device_clears_misses_and_leaves_watchdog_stopped():
    root = controller()
    runtime = root.state["_runtime"]
    runtime.update({
        "msg_id": 41, "heartbeat_miss_count": 2,
        "heartbeat_timer_active": True, "heartbeat_watchdog_due": 1234.0,
    })
    assert send(root, {"t": "hbok", "r": 0}, selector=1) == []
    runtime = root.state["_runtime"]
    assert runtime["msg_id"] == 42 and runtime["heartbeat_miss_count"] == 0
    assert runtime["heartbeat_timer_ms"] == 61000
    assert runtime["heartbeat_timer_active"] is False
    assert runtime["heartbeat_watchdog_due"] is None



def test_reset_matches_probe_interpreted_requested_length_comparison_and_missing_mac_has_no_effect():
    root = controller()

    def reset_projection():
        runtime = root.state["_runtime"]
        return {
            "reset_requested": runtime["reset_requested"],
            "host_managed": runtime["host_managed"],
            "host_mac": runtime["host_mac"],
            "host_addr": runtime["host_addr"],
        }

    before = reset_projection()
    for request in (
        {"t": "reset", "mac": "ff0000000000"},
        {"t": "reset"},
    ):
        assert send(root, request) == []
        assert reset_projection() == before

    matched = {**before, "reset_requested": True}
    for requested_mac in (MAC, MAC[:10], ""):
        reply, = send(root, {"t": "reset", "mac": requested_mac})
        assert response(reply)[1] == {"t": "ret", "r": 200, "mac": MAC}
        assert reset_projection() == matched


def test_raw_binary_frames_are_exact_cached_synthetic_bytes_and_ack_is_not_mcu_execution():
    root = controller()
    vectors = FIXTURE["raw_binary"]["synthetic_raw_frame_vectors"]
    raw = {name: bytes.fromhex(vectors[name]) for name in ("hex91", "hex92", "hex93", "hex6A")}
    request = {"t": "binCmd"}
    request.update({name: base64.b64encode(value).decode("ascii") for name, value in raw.items()})
    reply, = send(root, request)
    assert response(reply)[1] == {"t": "res", "r": 200, "mac": MAC}
    for name, data in raw.items():
        cache = root.state["raw_" + name]
        capacity = FIXTURE["raw_binary"]["buffer_capacities"][name]
        assert len(cache) == capacity and cache[:len(data)] == data
        assert cache[len(data):] == bytes(capacity - len(data))
    runtime = root.state["_runtime"]
    assert runtime["dirty"] == 0xE0 and runtime["pending"] == 5
    assert runtime["report_timer"] == 0x4005

def test_hex91_preserves_existing_raw_cache_when_source_metadata_gate_is_closed():
    root = controller()
    old = bytearray([0xA5] * FIXTURE["raw_binary"]["buffer_capacities"]["hex91"])
    old[3] = 0x91
    root.state["raw_hex91"] = bytes(old)
    frame = bytes.fromhex(FIXTURE["raw_binary"]["synthetic_raw_frame_vectors"]["hex91"])
    reply, = send(root, {"t": "binCmd", "hex91": base64.b64encode(frame).decode("ascii")})
    assert response(reply)[1] == {"t": "res", "r": 200, "mac": MAC}
    assert root.state["raw_hex91"] == bytes(old)
    assert root.state["_runtime"]["dirty"] == 0x20
    assert root.state["_runtime"]["pending"] == 0


@pytest.mark.parametrize(("field", "dirty", "pending"), [("hex92", 0x40, 1), ("hex93", 0x80, 4)])
def test_hex92_and_hex93_set_their_distinct_source_pending_bits(field, dirty, pending):
    root = controller()
    raw = bytes.fromhex(FIXTURE["raw_binary"]["synthetic_raw_frame_vectors"][field])
    reply, = send(root, {"t": "binCmd", field: base64.b64encode(raw).decode("ascii")})
    assert response(reply)[1] == {"t": "res", "r": 200, "mac": MAC}
    runtime = root.state["_runtime"]
    assert runtime["dirty"] == dirty and runtime["pending"] == pending
    assert runtime["report_timer"] == 0x4005


def test_temporary_hex6b_to_hex6e_frames_drive_only_their_source_side_effects():
    root = controller()
    vectors = FIXTURE["raw_binary"]["synthetic_raw_frame_vectors"]
    copy_vectors = FIXTURE["raw_binary"]["hex6D_copy_vectors"]
    mode_vectors = FIXTURE["raw_binary"]["hex6C_source_mode_transition_vectors"]
    frame_vectors = {
        "hex6B": vectors["hex6B_clock_2026_01_02T030405"],
        "hex6C": vectors["hex6C_type_3c"],
        "hex6D": vectors["hex6D_gnet_key_GNET_KEY"],
        "hex6E": vectors["hex6E_timer_value_10"],
    }
    frames = {name: bytes.fromhex(raw) for name, raw in frame_vectors.items()}
    first_mode = mode_vectors[0]
    root.state["_runtime"]["source_mode_0x4ac"] = (
        first_mode["previous_source_mode_0x4ac_u8"]
    )
    reply, = send(
        root,
        {"t": "binCmd", "hex6C": base64.b64encode(frames["hex6C"]).decode("ascii")},
    )
    assert response(reply)[1] == {"t": "res", "r": 200, "mac": MAC}
    runtime = root.state["_runtime"]
    assert runtime["source_mode_0x4ac"] == first_mode["next_source_mode_0x4ac_u8"]
    assert runtime["timer_0x06"] == first_mode["expected_timer_0x06_u16"]
    assert runtime["timer_0x08"] == first_mode["expected_timer_0x08_u16"]
    assert runtime["source_mode_0x4ac"] == mode_vectors[1]["previous_source_mode_0x4ac_u8"]
    request = {"t": "binCmd"}
    request.update({name: base64.b64encode(frame).decode("ascii") for name, frame in frames.items()})
    reply, = send(root, request)
    assert response(reply)[1] == {"t": "res", "r": 200, "mac": MAC}
    runtime = root.state["_runtime"]
    assert runtime["time"] == "2026-01-02 03:04:05"
    assert runtime["gnet_key"] == bytes.fromhex(copy_vectors[0]["copied_ascii_hex"])
    second_key_frame = bytes.fromhex(
        vectors[copy_vectors[1]["input_frame_vector"]]
    )
    reply, = send(
        root,
        {"t": "binCmd", "hex6D": base64.b64encode(second_key_frame).decode("ascii")},
    )
    assert response(reply)[1] == {"t": "res", "r": 200, "mac": MAC}
    runtime = root.state["_runtime"]
    assert runtime["gnet_key"] == bytes.fromhex(copy_vectors[1]["copied_ascii_hex"])
    assert runtime["timer_0x06"] == mode_vectors[1]["expected_timer_0x06_u16"]
    assert runtime["timer_0x08"] == mode_vectors[1]["expected_timer_0x08_u16"]
    assert runtime["source_mode_0x4ac"] == mode_vectors[1]["next_source_mode_0x4ac_u8"]
    assert runtime["timer_0x18"] == 0
    room_id = FIXTURE["raw_binary"]["room_id"]
    blocked_gates = room_id["synthetic_blocked_restart_vector"]
    runtime = root.state["_runtime"]
    assert runtime["gnet_key"] == bytes.fromhex(blocked_gates["gnet_key_hex"])
    runtime.update({
        "controller_id_available": blocked_gates["controller_id_available"],
        "ubind_gate_4e5": blocked_gates["ubind_gate_4e5"],
        "ubind_gate_4ed": blocked_gates["ubind_gate_4ed"],
        "network_restart_pending": False,
    })
    reply, = send(root, {"t": "binCmd", "roomId": room_id["synthetic_input"]})
    assert response(reply)[1] == {"t": "res", "r": 200, "mac": MAC}
    runtime = root.state["_runtime"]
    assert runtime["room_id"] == room_id["expected_low8"]
    assert runtime["network_restart_pending"] is (
        blocked_gates["expected_network_restart_pending"]
    )
    assert runtime["timer_0x1c"] == 0x400A


def test_fragment_mask_vectors_and_metadata_selector_match_source_mutation_abi():
    fragment = FIXTURE["raw_binary"]["fragment"]
    for vector in fragment["native_vectors"]:
        root = controller()
        field = "raw_" + fragment["cmd_type_buffers"][str(vector["cmd_type"])]
        data = bytearray(root.state[field])
        offset = vector["byte"] + fragment["buffer_offset_bias"]
        data[offset] = vector["before"]
        root.state[field] = bytes(data)
        reply, = send(root, {"t": "binCmd", "fragment": [[
            vector["cmd_type"], vector["byte"], vector["mask"], vector["value"],
        ]]})
        assert response(reply)[1] == {"t": "res", "r": 200, "mac": MAC}
        assert root.state[field][offset] == vector["after"]

    root = controller()
    before = {name: root.state[name] for name in ("raw_hex91", "raw_hex92", "raw_hex93")}
    special = fragment["metadata_special_record"]
    assert send(root, {"t": "binCmd", "fragment": [special]})
    assert root.state["raw_metadata_byte"] == 175
    assert {name: root.state[name] for name in before} == before


def _scene_record(scene_id, frames):
    scene = FIXTURE["raw_binary"]["scenes"]
    record = bytearray(scene["record_bytes"])
    frame_width = scene["frame_offsets"]["hex93"] - scene["frame_offsets"]["hex91"]
    for name, offset in scene["frame_offsets"].items():
        raw = bytes.fromhex(frames[name])
        record[offset:offset + frame_width] = raw + bytes(frame_width - len(raw))
    offset = scene["scene_id_offset"]
    record[offset:offset + 4] = scene_id.to_bytes(4, "little")
    return bytes(record)


def test_scene_create_update_delete_keep_source_frame_order_and_little_endian_id():
    root = controller()
    gate = FIXTURE["raw_binary"]["scenes"]["scene_controller_id_gate"]
    root.state["_runtime"][gate["runtime_key"]] = gate["synthetic_scene_table_gate"]
    scene = FIXTURE["raw_binary"]["scenes"]
    assert type(scene["synthetic_scene_id"]) is int
    frame_width = scene["frame_offsets"]["hex93"] - scene["frame_offsets"]["hex91"]
    assert (scene["slot_count"], scene["record_bytes"], frame_width, scene["scene_id_offset"]) == (20, 172, 55, 168)
    assert scene["frame_offsets"] == {"hex91": 0, "hex93": 0x37, "hex92": 0x6E}
    assert scene["frame_order"] == ["hex91", "hex93", "hex92"]
    assert len(root.state["raw_scenes"]) == scene["slot_count"]
    assert all(len(record) == scene["record_bytes"] for record in root.state["raw_scenes"])
    frames = scene["synthetic_frames_by_name"]
    request = {"t": "binCmd", "sceneId": scene["synthetic_scene_id"], "operType": 1,
               "sence_enable": 1}
    request.update({name: base64.b64encode(bytes.fromhex(raw)).decode("ascii")
                    for name, raw in frames.items()})
    reply, = send(root, request)
    assert response(reply)[1] == {"t": "res", "r": 200, "mac": MAC}
    expected = _scene_record(scene["synthetic_scene_id"], frames)
    assert root.state["raw_scenes"][0] == expected
    assert int.from_bytes(expected[scene["scene_id_offset"]:], "little") == scene["synthetic_scene_id"]

    updated_frame = bytes.fromhex(scene["synthetic_update_hex91"])
    reply, = send(root, {"t": "binCmd", "sceneId": scene["synthetic_scene_id"], "operType": 0,
                         "hex91": base64.b64encode(updated_frame).decode("ascii")})
    assert response(reply)[1] == {"t": "res", "r": 200, "mac": MAC}
    expected = bytearray(expected)
    offset = scene["frame_offsets"]["hex91"]
    expected[offset:offset + frame_width] = updated_frame + bytes(frame_width - len(updated_frame))
    assert root.state["raw_scenes"][0] == bytes(expected)

    reply, = send(root, {"t": "binCmd", "sceneId": scene["synthetic_scene_id"], "operType": 2})
    assert response(reply)[1] == {"t": "res", "r": 200, "mac": MAC}
    assert root.state["raw_scenes"][0] == bytes(scene["record_bytes"])


def test_scene_no_controller_id_reply_and_bounded_full_table_result():
    root = controller()
    scene = FIXTURE["raw_binary"]["scenes"]
    vector = scene["no_controller_id_vector"]
    reply, = send(root, vector["request"])
    assert response(reply)[1] == vector["reply"]
    gate = scene["scene_controller_id_gate"]
    assert root.state["_runtime"][gate["runtime_key"]] == gate["synthetic_default_gate"]
    root.state["_runtime"][gate["runtime_key"]] = gate["synthetic_scene_table_gate"]

    full_table = scene["full_table_safe_model_vector"]
    records = []
    for scene_id in full_table["occupied_scene_ids"]:
        record = bytearray(scene["record_bytes"])
        offset = scene["scene_id_offset"]
        record[offset:offset + 4] = scene_id.to_bytes(4, "little")
        records.append(bytes(record))
    assert len(records) == scene["slot_count"]
    root.state["raw_scenes"] = records
    before = list(records)
    reply, = send(root, full_table["request"])
    assert response(reply)[1] == full_table["reply"]
    assert root.state["raw_scenes"] == before


def test_raw_status_metadata_and_wrapper_match_independent_source_vectors():
    vector = FIXTURE["raw_binary"]["bin_status"]["metadata_test_vector"]
    root = controller(mac=vector["module_mac_hex"], mid=vector["formatted_mid_hex"])
    metadata = family.build_raw_status_metadata(
        root, vector["payload_base64_length"], clock=bytes.fromhex(vector["raw_clock_hex"]),
    )
    assert len(metadata) == FIXTURE["raw_binary"]["bin_status"]["metadata_length_bytes"]
    assert metadata.hex() == vector["metadata_hex"]
    assert base64.b64encode(metadata).decode("ascii") == vector["metadata_base64"]

    root = controller()
    assert root.state["_runtime"]["raw_clock"].hex() == (
        FIXTURE["raw_binary"]["bin_status"]["initial_synthetic_raw_clock_hex"]
    )
    root.state["_runtime"]["raw_clock"] = bytes.fromhex(
        FIXTURE["raw_binary"]["bin_status"]["wrapper_raw_clock_hex"]
    )
    payload = bytes.fromhex(FIXTURE["raw_binary"]["bin_status"]["opaque_payload_hex"])
    wrapped = family.build_raw_status(root, payload)
    assert wrapped == FIXTURE["raw_binary"]["bin_status"]["wrapper"]
    metadata = base64.b64decode(wrapped["header"], validate=True)
    assert metadata[:4].hex() == FIXTURE["raw_binary"]["bin_status"]["metadata_prefix_hex"]
    assert metadata[22:26].hex() == FIXTURE["raw_binary"]["bin_status"]["mid_uint32_be_hex"]
    bin_status = FIXTURE["raw_binary"]["bin_status"]
    flags = bytes.fromhex(bin_status["metadata_flags_hex"])
    flags_offset = bin_status["mid_uint32_be_offset"] + 4
    assert metadata[flags_offset:flags_offset + len(flags)] == flags
    assert len(metadata) == FIXTURE["raw_binary"]["bin_status"]["metadata_length_bytes"]
    assert wrapped["binStatus"] == FIXTURE["raw_binary"]["bin_status"]["opaque_payload_base64"]


def test_managed_pending_status_payload_stays_synthetic_and_ack_is_local_only():
    root = controller()
    host_addr = ("192.0.2.99", 5001)
    proactive = send(
        root, {"t": "UBindok", "host": HOST_MAC, "hostManaged": 1, "roomId": 2},
        addr=host_addr,
    )
    assert_ubindok_proactive(proactive)
    assert root.state["_runtime"]["host_addr"] == host_addr
    vectors = FIXTURE["raw_binary"]["synthetic_raw_frame_vectors"]
    frames = {name: bytes.fromhex(vectors[name]) for name in ("hex91", "hex92", "hex93")}
    command = {"t": "binCmd"}
    command.update({name: base64.b64encode(value).decode("ascii") for name, value in frames.items()})
    ack, = send(root, command, uid=0xFFFFFFFF)
    ack_outer, ack_inner = response(ack)
    assert ack_inner == {"t": "res", "r": 200, "mac": MAC}
    assert ack_outer["uid"] == 0xFFFFFFFF and ack_outer["tcid"] == HOST_MAC
    assert root.state["_runtime"]["pending"] == 5

    expected_payload = b"".join(frames[name] for name in ("hex91", "hex92", "hex93"))
    report = family.build_raw_status(root, expected_payload)
    assert report == expected_raw_status(
        expected_payload, root.state["_runtime"]["raw_clock"].hex()
    )
    assert root.state["_runtime"]["pending"] == 5
    assert "typed_status" not in report and "mcu_executed" not in report


def test_ubindok_proactive_counter_boundaries_and_dynamic_gnetid_byte():
    get_login_info = FIXTURE["lifecycle"]["ubindok"]["proactive_packets"]["getLoginInfo"]
    counter_vectors = FIXTURE["lifecycle"]["ubindok"]["proactive_packets"]["counter_boundary_vectors"]
    for counter_vector in counter_vectors:
        root = controller()
        root.state["_runtime"]["msg_id"] = counter_vector["initial_msg_id"]
        root.state["_runtime"]["controller_id_available"] = (
            get_login_info["synthetic_test_curGnetID_u8"]
        )
        replies = send(root, {"t": "UBindok", "host": HOST_MAC, "hostManaged": 1})
        assert_ubindok_proactive(
            replies,
            utm_msg_id=counter_vector["utm_msg_id"],
            login_msg_id=counter_vector["login_msg_id"],
            cur_gnet_id=get_login_info["synthetic_test_curGnetID_u8"],
        )
        assert root.state["_runtime"]["msg_id"] == counter_vector["post_ubindok_msg_id"]
        if "next_utm_msg_id" in counter_vector:
            next_replies = send(
                root, {"t": "UBindok", "host": HOST_MAC, "hostManaged": 1}
            )
            assert_ubindok_proactive(
                next_replies,
                utm_msg_id=counter_vector["next_utm_msg_id"],
                login_msg_id=counter_vector["next_login_msg_id"],
                cur_gnet_id=get_login_info["synthetic_test_curGnetID_u8"],
            )
            assert root.state["_runtime"]["msg_id"] == (
                counter_vector["next_post_ubindok_msg_id"]
            )


def test_message_id_counter_wraps_only_after_uint16_max_and_uid_is_echoed():
    root = controller()
    runtime = root.state["_runtime"]
    runtime["msg_id"] = 65535
    first, = send(root, {"t": "scan"}, selector=1, uid=0xFFFFFFFF)
    first_outer, _ = response(first)
    assert first_outer["msgId"] == 65535 and first_outer["uid"] == 0xFFFFFFFF
    second, = send(root, {"t": "scan"}, selector=1, uid=0)
    second_outer, _ = response(second)
    assert second_outer["msgId"] == 0 and second_outer["uid"] == 0
    assert root.state["_runtime"]["msg_id"] == 1


def test_timestamp_fragment_and_raw_capacity_failures_are_atomic():
    vectors = FIXTURE["raw_binary"]["synthetic_raw_frame_vectors"]
    oversize_cache = base64.b64encode(bytes(66)).decode("ascii")
    overdeclared = bytearray(65)
    overdeclared[2] = 63
    truncated = bytes.fromhex("7e7e056c3c")
    bad_clock = bytes.fromhex("7e7e146b") + b"2026/01/02 03:04:05"
    failures = [
        {"t": "binCmd", "hex91": "%%%"},
        {"t": "binCmd", "hex91": base64.b64encode(bytes.fromhex("7e7e0591a1b2c3")).decode("ascii")},
        {"t": "binCmd", "hex91": base64.b64encode(overdeclared).decode("ascii")},
        {"t": "binCmd", "hex91": oversize_cache},
        {"t": "binCmd", "hex6A": oversize_cache},
        {"t": "binCmd", "hex6C": base64.b64encode(bytes(56)).decode("ascii")},
        {"t": "binCmd", "hex6C": base64.b64encode(truncated).decode("ascii")},
        {"t": "binCmd", "hex6B": base64.b64encode(bad_clock).decode("ascii")},
        {"t": "binCmd", "hex91": base64.b64encode(bytes.fromhex(vectors["hex91"])).decode("ascii"),
         "fragment": [[145, 62, 1, 1]]},
    ]
    for field in ("hex6B", "hex6D", "hex6E"):
        capacity = FIXTURE["raw_binary"]["buffer_capacities"]["temporary_" + field]
        failures.append({
            "t": "binCmd",
            field: base64.b64encode(bytes(capacity + 1)).decode("ascii"),
        })
    for field in ("hex92", "hex93"):
        failures.append({"t": "binCmd", field: oversize_cache})
    for payload in failures:
        root = controller()
        before = deepcopy(root.state)
        with pytest.raises(InvalidPacket):
            send(root, payload)
        assert root.state == before
    root = controller()
    gate = FIXTURE["raw_binary"]["scenes"]["scene_controller_id_gate"]
    root.state["_runtime"][gate["runtime_key"]] = gate["synthetic_scene_table_gate"]
    scene = FIXTURE["raw_binary"]["scenes"]
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        send(root, {"t": "binCmd", "sceneId": scene["synthetic_scene_id"], "operType": 1,
                    "sence_enable": 1, "hex91": base64.b64encode(bytes(56)).decode("ascii")})
    assert root.state == before

    root = controller()
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        send(root, {"t": "Utm", "time": "not-a-source-time"})
    with pytest.raises(InvalidPacket):
        send(root, {"t": "Utm", "time": "x" * 32})
    assert root.state == before


def test_login_info_res_missing_r_clears_worker_state_without_ack():
    root = controller()
    runtime = root.state["_runtime"]
    runtime.update({
        "source_state_7": 0x4F,
        "ubind_gate_4e5": 1,
        "ubind_gate_4ed": 0,
        "network_restart_pending": False,
    })

    assert send(root, {"t": "loginInfoRes"}) == []
    runtime = root.state["_runtime"]
    contract = FIXTURE["lifecycle"]["loginInfoRes"]["missing_r"]
    assert runtime["source_state_7"] == contract["expected_source_state_byte"]
    assert runtime["ubind_gate_4ed"] == 0
    assert runtime["network_restart_pending"] is False


def test_login_info_res_r500_uses_both_native_gates_and_not_host_managed():
    vectors = FIXTURE["lifecycle"]["loginInfoRes"]["r_500"]["synthetic_gate_vectors"]
    for vector in vectors:
        root = controller()
        runtime = root.state["_runtime"]
        runtime.update({
            "source_state_7": 0x4F,
            "ubind_gate_4e5": vector["ubind_gate_4e5"],
            "ubind_gate_4ed": vector["ubind_gate_4ed"],
            "host_managed": vector["host_managed"],
            "network_restart_pending": False,
        })

        assert send(root, {"t": "loginInfoRes", "r": 500}) == []
        runtime = root.state["_runtime"]
        assert runtime["source_state_7"] == 0
        assert runtime["host_managed"] == vector["host_managed"]
        assert runtime["ubind_gate_4e5"] == vector["ubind_gate_4e5"]
        assert runtime["ubind_gate_4ed"] == vector["expected_ubind_gate_4ed"]
        assert runtime["network_restart_pending"] is vector["expected_network_restart_pending"]


def test_login_info_res_success_restart_uses_product_identity_and_ubind_gates():
    login_info = FIXTURE["lifecycle"]["loginInfoRes"]
    restart = login_info["successful_restart_gate"]
    for result in restart["synthetic_result_vectors"]:
        for gates in restart["synthetic_gate_vectors"]:
            root = controller()
            runtime = root.state["_runtime"]
            runtime.update({
                "source_state_7": 0x4F,
                "controller_id_available": gates["controller_id_available"],
                "ubind_gate_4e5": gates["ubind_gate_4e5"],
                "ubind_gate_4ed": gates["ubind_gate_4ed"],
                "gnet_key": b"",
                "network_restart_pending": False,
            })

            assert send(root, {
                "t": "loginInfoRes",
                "r": result["r"],
                "result": {"platform": result["platform_input"]},
            }) == []
            runtime = root.state["_runtime"]
            assert runtime["cloud_platform"] == result["stored_platform"]
            assert runtime["source_state_7"] == 0
            assert runtime["ubind_gate_4e5"] == gates["ubind_gate_4e5"]
            assert runtime["ubind_gate_4ed"] == gates["expected_ubind_gate_4ed"]
            assert runtime["network_restart_pending"] is gates["expected_network_restart_pending"]


def test_bin_cmd_room_id_restart_uses_source_gates_not_gnet_key_presence():
    room_id = FIXTURE["raw_binary"]["room_id"]
    gate_vectors = FIXTURE["lifecycle"]["loginInfoRes"][
        "successful_restart_gate"
    ]["synthetic_gate_vectors"]
    for gates in gate_vectors:
        root = controller()
        root.state["_runtime"].update({
            "controller_id_available": gates["controller_id_available"],
            "ubind_gate_4e5": gates["ubind_gate_4e5"],
            "ubind_gate_4ed": gates["ubind_gate_4ed"],
            "gnet_key": b"",
            "network_restart_pending": False,
        })

        reply, = send(root, {"t": "binCmd", "roomId": room_id["synthetic_input"]})
        assert response(reply)[1] == {"t": "res", "r": 200, "mac": MAC}
        runtime = root.state["_runtime"]
        assert runtime["room_id"] == room_id["expected_low8"]
        assert runtime["ubind_gate_4ed"] == gates["expected_ubind_gate_4ed"]
        assert runtime["network_restart_pending"] is gates["expected_network_restart_pending"]


def test_unmanaged_ubindok_room_update_does_not_restart_with_gates_open():
    vector = FIXTURE["lifecycle"]["ubindok"]["room_id_update"][
        "synthetic_unmanaged_no_restart_vector"
    ]
    root = controller()
    root.state["_runtime"].update({
        "controller_id_available": vector["controller_id_available"],
        "ubind_gate_4e5": vector["ubind_gate_4e5"],
        "ubind_gate_4ed": vector["ubind_gate_4ed"],
        "gnet_key": bytes.fromhex(vector["gnet_key_hex"]),
        "network_restart_pending": False,
    })

    assert send(root, {
        "t": "UBindok",
        "host": HOST_MAC,
        "hostManaged": vector["hostManaged"],
        "roomId": vector["room_id_input"],
    }) == []
    runtime = root.state["_runtime"]
    assert runtime["room_id"] == vector["expected_room_id"]
    assert runtime["network_restart_pending"] is vector["expected_network_restart_pending"]


def test_bin_cmd_unchanged_room_id_still_restarts_when_source_gates_allow():
    root = controller()
    root.state["_runtime"].update({
        "room_id": 7, "controller_id_available": 1,
        "ubind_gate_4e5": 1, "ubind_gate_4ed": 0,
        "gnet_key": b"", "network_restart_pending": False,
    })
    reply, = send(root, {"t": "binCmd", "roomId": 7})
    assert response(reply)[1] == {"t": "res", "r": 200, "mac": MAC}
    runtime = root.state["_runtime"]
    assert runtime["room_id"] == 7
    assert runtime["ubind_gate_4ed"] == 1
    assert runtime["network_restart_pending"] is True
