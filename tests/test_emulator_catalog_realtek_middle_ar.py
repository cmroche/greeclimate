"""Exact-source bounded LAN contracts for Realtek WB AR 0, 1, and 7."""

import base64
import copy
import json
from pathlib import Path

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles import catalog_realtek_middle_ar as ar
from gree_emulator.wire import InvalidPacket, encode_reply


FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "emulator" /
                      "catalog-realtek-middle-ar_research.json").read_text())
DEVICE_KEY = b"0123456789abcdef"
AR0_CHANNEL1_KEY = b"a3K8Bx%2r8Y7#xDh"


def device_for(profile, *, mac="020000000001", key=DEVICE_KEY):
    return EmulatedDevice("virtual", mac, "Synthetic module", profile.mids[0], key,
                          profile, copy.deepcopy(dict(profile.initial_state)), last_step=1000)


def packet(device, inner, *, channel=0):
    outer = {"t": "pack", "i": channel, "uid": 42, "cid": "controller",
             "tcid": device.mac}
    if channel == 2:
        outer["pack"] = inner
    else:
        key = (device.key if channel == 0 else
               AR0_CHANNEL1_KEY if device.profile.handler.source_index == 0 else
               device.state["udp_key1"])
        plain = json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode()
        encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(plain, AES.block_size))
        outer["pack"] = base64.b64encode(encrypted).decode()
    return outer


def decode_packet(data, key):
    outer = json.loads(data)
    encrypted = base64.b64decode(outer["pack"], validate=True)
    plain = unpad(AES.new(key, AES.MODE_ECB).decrypt(encrypted), AES.block_size)
    assert plain.endswith(b"\n")
    return outer, json.loads(plain[:-1])


def decode_reply(reply, key=None):
    outer = json.loads(encode_reply(reply))
    if isinstance(outer.get("pack"), dict):
        return outer, outer["pack"]
    assert key is not None
    encrypted = base64.b64decode(outer["pack"], validate=True)
    plain = unpad(AES.new(key, AES.MODE_ECB).decrypt(encrypted), AES.block_size)
    assert plain.endswith(b"\n")
    return outer, json.loads(plain[:-1])


def send(device, inner, *, channel=0):
    return device.profile.handler.handle(device, packet(device, inner, channel=channel))


def test_factory_requires_nonzero_mid_and_explicit_coordinator_key():
    with pytest.raises(ValueError):
        ar.profile_for_mcu_input(0, 0)
    with pytest.raises(ValueError):
        ar.profile_for_mcu_input(1, 0x10001)


@pytest.mark.parametrize("profile", ar.PROFILES, ids=lambda profile: profile.id)
def test_outer_headers_use_original_cjson_valueint_abi(profile):
    handler = profile.handler
    outer = handler.decode_outer(
        b'{"t":"pack","i":257,"uid":1e3,"cid":"controller",'
        b'"tcid":"020000000001","pack":"AA=="}'
    )
    assert outer["i"] == 1
    assert outer["uid"] == 1000

    outer = handler.decode_outer(
        b'{"t":"pack","i":"1","uid":true,"cid":"controller",'
        b'"tcid":"020000000001","pack":"AA=="}'
    )
    assert outer["i"] == 0
    assert outer["uid"] == 1

    if handler.source_index == 0:
        with pytest.raises(InvalidPacket):
            handler.decode_outer(b'{"t":"pack","uid":42,"pack":"AA=="}')
    else:
        outer = handler.decode_outer(b'{"t":"pack","pack":"AA=="}')
        assert outer["i"] == outer["uid"] == 0


@pytest.mark.parametrize("profile", ar.PROFILES[1:], ids=lambda profile: profile.id)
def test_c1r_plaintext_channel_has_no_registered_callback(profile):
    device = device_for(profile)
    outer = profile.handler.decode_outer(
        b'{"t":"pack","i":2,"uid":7,"cid":"controller",'
        b'"tcid":"020000000001","pack":{"t":"scan"}}'
    )
    assert profile.handler.handle(device, outer) == []

def test_source0_scan_status_and_channel_envelopes_stay_disjoint():
    device = device_for(ar.PROFILES[0])
    reply, = send(device, {"t": "scan"}, channel=2)
    outer, scan = decode_reply(reply)
    assert scan["t"] == "dev" and scan["mid"] == "10001"
    assert "hid" not in scan
    assert outer["i"] == 2 and outer["tcid"] == "app"
    assert reply.destination_port is None

    device.state.update(host="host.local", ver="module-v", name="local-name",
                        time="2026-05-01 11:45:00")
    cols = ["host", "ver", "hid", "mid", "unknown", "host", "time"]
    reply, = send(device, {"t": "status", "cols": cols})
    _, status = decode_reply(reply, DEVICE_KEY)
    assert status["t"] == "dat" and status["cols"] == cols
    assert status["dat"] == ["host.local", "module-v", ar.PROFILES[0].hid,
                             "10001", "host.local", "2026-05-01 11:45:00"]


def test_source0_cmd_query_wlan_time_and_raw_bin_callbacks():
    device = device_for(ar.PROFILES[0])
    reply, = send(device, {"t": "cmd", "opt": ["RawOnly", "time", "ReportClientID"],
                           "p": ["1e3", "2026-05-01 11:45:00", "local-client"]})
    _, response = decode_reply(reply, DEVICE_KEY)
    assert response["p"] == response["val"] == [1, "2026-05-01 11:45:00", "local-client"]
    assert device.state["time"] == "2026-05-01 11:45:00"
    assert device.state["_wb_ar_runtime"]["report_client_pending"] is True
    assert "RawOnly" not in device.state

    reply, = send(device, {"t": "queryT", "index": 260, "count": 9})
    assert decode_reply(reply, DEVICE_KEY)[1] == {"t": "listT", "total": 0, "index": 4}
    reply, = send(device, {"t": "wlan", "ssid": "ssid", "psw": "secret", "host": "host"},
                  channel=2)
    assert decode_reply(reply)[1]["t"] == "ret"
    assert device.state["wlan_config"] == {"ssid": "ssid", "psw": "secret",
                                           "host": "host", "mode": 3}

    fragments = [{"cmd_type": 0x91, "byte": 0, "mask": 0x0f, "value": 3}]
    reply, = send(device, {"t": "binCmd", "hex6C": [1, 2, 3], "fragment": fragments})
    assert decode_reply(reply, DEVICE_KEY)[1]["r"] == 200
    runtime = device.state["_wb_ar_runtime"]
    assert runtime["global_frames"][0x91][3] == 3
    assert runtime["hex6c_input"] == bytes((1, 2, 3))
    assert "hex6c_marker" not in runtime


def test_source1_scan_and_source7_input_scene_writer_are_distinct():
    profile1 = ar.PROFILES[1]
    device = device_for(profile1)
    reply, = send(device, {"t": "scan"}, channel=1)
    outer, scan = decode_reply(reply, profile1.initial_state["udp_key1"])
    assert set(scan) == {"t", "scene", "mid", "ver", "lock", "devkey", "hid"}
    assert scan["t"] == "UBind" and scan["mid"] == "10001"
    assert scan["hid"] == profile1.hid and "GnetID" not in scan
    assert reply.destination_port == 5000
    assert outer["tcid"] == "controller"

    profile7 = ar.PROFILES[2]
    device = device_for(profile7)
    reply, = send(device, {"t": "scan"}, channel=1)
    outer, scan = decode_reply(reply, profile7.initial_state["udp_key1"])
    assert set(scan) == {"t", "mid", "ver", "lock", "devkey", "hid"}
    assert scan["t"] == "UBind" and scan["mid"] == "10001"
    assert scan["hid"] == profile7.hid and "scene" not in scan
    assert reply.destination_port == 5000
    assert outer["tcid"] == "controller"

    device.state["gnet_ready"] = 1
    assert send(device, {"t": "scan", "allRange": 0}, channel=1) == []
    reply, = send(device, {"t": "scan", "allRange": 1}, channel=1)
    _, scan = decode_reply(reply, profile7.initial_state["udp_key1"])
    assert "scene" not in scan


@pytest.mark.parametrize("profile", ar.PROFILES[1:], ids=lambda profile: profile.id)
def test_c1r_ubindok_creates_local_encrypted_intents_not_direct_replies(profile):
    device = device_for(profile)
    request = {"t": "UBindok", "mac": "020000000099", "roomId": 7}
    if profile.handler.source_index == 1:
        request["hostManaged"] = 1
    assert send(device, request) == []
    assert device.state["gnet_ready"] == device.state["lock_word"] == 1
    assert device.state["group_id"] == 7
    runtime = device.state["_wb_ar_runtime"]
    assert runtime["group_save_requested"] is True
    assert runtime["heartbeat_running"] is True
    assert [entry["inner"]["t"] for entry in runtime["outbound_requests"]] == [
        "Utm", "getLoginInfo"]
    for entry in runtime["outbound_requests"]:
        outer, inner = decode_packet(entry["packet"], DEVICE_KEY)
        assert outer["tcid"] == "020000000099"
        assert entry["destination_port"] == 5000
        assert inner == entry["inner"]

    saved = ar.profile_for_mcu_input(
        1, 0x10001, channel1_key=b"AR1-udp-key-0001", saved_gnet_config=1)
    unbound = device_for(saved)
    assert send(unbound, {"t": "UBindok", "hostManaged": 0}) == []
    assert unbound.state["ver"] == "V3.5.M"
    assert unbound.state["no_host_managed"] == 1
    assert unbound.state["gnet_ready"] == 0
    assert unbound.state["_wb_ar_runtime"]["outbound_requests"] == []


@pytest.mark.parametrize("profile", ar.PROFILES[1:], ids=lambda profile: profile.id)
def test_c1r_report_and_heartbeat_callbacks_are_local_only(profile):
    device = device_for(profile)
    device.state.update(gnet_ready=1, report_transport_ready=1,
                        raw_report_records=[{"mask": 2, "frame_hex": "7e7e021001"}] +
                                           [{"mask": 0, "frame_hex": ""} for _ in range(7)])
    assert send(device, {"t": "statusCheck"}) == []
    runtime = device.state["_wb_ar_runtime"]
    assert runtime["report_pending"] is True
    assert runtime["queued_report"] == {"body": bytes.fromhex("7e7e021001"), "kind": 7}

    assert send(device, {"t": "hbok"}, channel=1) == []
    runtime = device.state["_wb_ar_runtime"]
    assert runtime["heartbeat_timer_created"] is True
    assert runtime["response_timer_period_ms"] == 61000
    assert runtime["response_timer_running"] is True
    runtime.update(heartbeat_running=True, heartbeat_period_ms=1000,
                   heartbeat_remaining_ms=1000, heartbeat_failure=2, timer_tick=1.0)
    device.profile.handler.tick(device, 2.0)
    assert device.state["gnet_ready"] == device.state["lock_word"] == 0
    assert runtime["heartbeat_failure"] == 0
    assert runtime["response_timer_running"] is False


@pytest.mark.parametrize("profile", ar.PROFILES[1:], ids=lambda profile: profile.id)
def test_c1r_scene_namespace_and_source_fragment_slots(profile):
    device = device_for(profile)
    reply, = send(device, {"t": "binCmd", "sceneId": 1, "operType": 1,
                           "sence_enable": 0})
    assert decode_reply(reply, DEVICE_KEY)[1]["r"] == 200
    runtime = device.state["_wb_ar_runtime"]
    assert [row["scene_id"] for row in runtime["scene_rows"][:2]] == [1, 2]

    frame = [0] * 0x37
    fragment = [{"cmd_type": 0x91, "byte": 0, "mask": 0x0f, "value": 5,
                 "initval": 9}]
    # The native gate compares the product `ver` buffer with V3.4.M.
    device.state["ver"] = "V3.4.M"
    reply, = send(device, {"t": "binCmd", "sceneId": 2, "operType": 1,
                           "sence_enable": 1, "hex91": frame, "fragment": fragment,
                           "roomId": 7})
    runtime = device.state["_wb_ar_runtime"]
    assert reply.destination_port == 5000
    row2 = next(row for row in runtime["scene_rows"] if row["scene_id"] == 2)
    assert row2["hex91"][3] == 5
    assert runtime["global_frames"][0x91][3] == 5
    assert runtime["product_fragments"] == [
        {"cmd_type": 0x91, "byte": 0, "mask": 0x0f, "value": 5, "initval": 9}
    ]
    assert device.state["group_id"] == 7

    replacement = [{**fragment[0], "value": 6, "initval": 11}]
    send(device, {"t": "binCmd", "fragment": replacement})
    runtime = device.state["_wb_ar_runtime"]
    assert runtime["global_frames"][0x91][3] == 6
    assert runtime["product_fragments"] == [
        {"cmd_type": 0x91, "byte": 0, "mask": 0x0f, "value": 6, "initval": 11}
    ]
    assert device.state["group_id"] == 7

    records = [{"cmd_type": 0x91, "byte": offset, "mask": 0x0f,
                "value": offset, "initval": offset + 10}
               for offset in range(5)]
    send(device, {"t": "binCmd", "fragment": records})
    runtime = device.state["_wb_ar_runtime"]
    assert runtime["product_fragments"] == records
    sixth = {"cmd_type": 0x91, "byte": 5, "mask": 0x0f,
             "value": 5, "initval": 15}
    reply, = send(device, {"t": "binCmd", "sceneId": 2, "operType": 1,
                           "sence_enable": 1, "fragment": [sixth]})
    assert decode_reply(reply, DEVICE_KEY)[1] == {
        "t": "res", "r": 200, "mac": device.mac}
    runtime = device.state["_wb_ar_runtime"]
    assert runtime["product_fragments"] == records
    assert runtime["global_frames"][0x91][8] == 5
    row2 = next(row for row in runtime["scene_rows"] if row["scene_id"] == 2)
    assert row2["hex91"][8] == 5

    replacement = {**records[0], "value": 6, "initval": 16}
    reply, = send(device, {"t": "binCmd", "sceneId": 2, "operType": 1,
                           "sence_enable": 1, "fragment": [replacement]})
    assert decode_reply(reply, DEVICE_KEY)[1]["r"] == 200
    runtime = device.state["_wb_ar_runtime"]
    assert runtime["product_fragments"] == [replacement, *records[1:]]

    scene_ids = [row["scene_id"] for row in runtime["scene_rows"]]
    send(device, {"t": "binCmd", "operType": 1, "sence_enable": 1,
                  "hex91": frame})
    assert ([row["scene_id"] for row in device.state["_wb_ar_runtime"]["scene_rows"]]
            == scene_ids)
    send(device, {"t": "binCmd", "sceneId": 19, "operType": 0, "hex91": frame})
    assert ([row["scene_id"] for row in device.state["_wb_ar_runtime"]["scene_rows"]]
            == scene_ids)

    before = copy.deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        send(device, {"t": "binCmd", "sceneId": 2, "operType": 1,
                      "sence_enable": 1, "fragment": [{"cmd_type": 0x91}]})
    assert device.state == before


@pytest.mark.parametrize("profile", ar.PROFILES[1:], ids=lambda profile: profile.id)
def test_c1r_reset_login_and_return_callbacks_use_source_channel_flags(profile):
    device = device_for(profile)
    reply, = send(device, {"t": "reset", "mac": device.mac[:6]})
    outer, response = decode_reply(reply, DEVICE_KEY)
    assert response == {"t": "res", "r": 200, "mac": device.mac}
    assert reply.destination_port == 5000 and outer["tcid"] == "controller"
    assert device.state["_wb_ar_runtime"]["reset_requested"] is True
    assert send(device, {"t": "Utm", "time": "2026-06-01 12:00:00"}) == []
    assert device.state["time"] == "2026-06-01 12:00:00"

    assert send(device, {"t": "loginInfoRes", "r": 200,
                         "loginInfo": {"GnetID": 258}}) == []
    assert device.state["gnet_id"] == 2
    assert send(device, {"t": "ret", "r": 200}) == []
    assert device.state["_wb_ar_runtime"]["response_marker"] == 0
    with pytest.raises(InvalidPacket):
        send(device, {"t": "reset", "mac": device.mac[:6]}, channel=1)

def test_source0_bind_tm_and_upgrade_keep_local_transport_and_no_flash_claim():
    device = device_for(ar.PROFILES[0])
    reply, = send(device, {"t": "bind", "mac": "ignored-target"}, channel=1)
    outer, response = decode_reply(reply, AR0_CHANNEL1_KEY)
    assert response == {"t": "bindok", "r": 200, "mac": device.mac,
                        "key": DEVICE_KEY.decode("ascii")}
    assert outer["tcid"] == "asvr"

    assert send(device, {"t": "tm", "time": "2026-06-01 12:00:00"}, channel=2) == []
    assert device.state["time"] == "2026-06-01 12:00:00"
    reply, = send(device, {"t": "upgrade", "mac": device.mac[:8],
                           "url": "https://example.invalid/update.bin"})
    assert decode_reply(reply, DEVICE_KEY)[1] == {"t": "ret", "r": 200, "mac": device.mac}
    runtime = device.state["_wb_ar_runtime"]
    assert runtime["ota_pending"] is True
    assert runtime["ota_url"] == "https://example.invalid/update.bin"
