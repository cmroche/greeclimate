"""Loopback acceptance for the native WB05C(RT) host-controller UDP contract.

Configured identities, keys, raw frames, and private timer backing below are
synthetic inputs. No test sends a packet to a broadcast address or hardware.
"""

import asyncio
import base64
import json
from pathlib import Path
import socket
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.__main__ import load_config
from gree_emulator.server import start_server
from tests.test_emulator_firmware_cli import cli_server, packet, unpack


FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-late-wb05crt-v203_research.json").read_text())
MAC = "020000000001"
HOST_MAC = "0200000000a5"
GENERIC_KEY = bytes.fromhex(FIXTURE["key_slots"]["generic_key_hex"])
PEER_IP = "127.0.0.1"
SYNTHETIC_SEED = "wb05crt-cli-synthetic-test"


def native_packet(inner, selector, key, *, uid=42, tcid="unmatched-target"):
    """Encode the source ECB + inner-LF format, keeping outer JSON unterminated."""
    outer = json.loads(packet({
        "t": "pack", "i": selector, "uid": uid,
        "cid": "synthetic-host", "tcid": tcid,
    }))
    if selector == 2:
        outer["pack"] = inner
    else:
        plaintext = json.dumps(inner, separators=(",", ":")).encode("utf-8") + b"\n"
        encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(plaintext, AES.block_size))
        outer["pack"] = base64.b64encode(encrypted).decode("ascii")
    return json.dumps(outer, separators=(",", ":")).encode("utf-8")


def native_response(data, key):
    assert b"\n" not in data and not data.endswith(b"\n")
    outer, inner = unpack(data, key)
    assert outer["t"] == "pack"
    plaintext = unpad(
        AES.new(key, AES.MODE_ECB).decrypt(base64.b64decode(outer["pack"], validate=True)),
        AES.block_size,
    )
    assert plaintext.endswith(b"\n") and plaintext.count(b"\n") == 1
    assert b"\r" not in plaintext
    assert json.loads(plaintext[:-1]) == inner
    return outer, inner


def send_native(sock, address, inner, selector, key, *, uid=42, tcid="unmatched-target"):
    sock.sendto(native_packet(inner, selector, key, uid=uid, tcid=tcid), address)


def receive_native(sock, address, key):
    data, sender = sock.recvfrom(65535)
    assert sender == address
    return native_response(data, key)


def assert_quiet(sock, timeout=0.15):
    previous = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        with pytest.raises(socket.timeout):
            sock.recvfrom(65535)
    finally:
        sock.settimeout(previous)


def synthetic_record():
    return {
        "id": "crt", "profile": FIXTURE["profile_id"],
        "mid": FIXTURE["configured_mid"], "mac": MAC,
        "name": "Synthetic WB05C(RT) CLI",
    }


def configured_device():
    _, _, devices = load_config({
        "listen": "127.0.0.1", "port": 0, "seed": SYNTHETIC_SEED,
        "devices": [synthetic_record()],
    })
    return devices[0]


class CaptureTransport:
    """Capture encoded server sends without forwarding them to any network peer."""

    def __init__(self, transport):
        self.transport = transport
        self.sent = []
        self.changed = asyncio.Event()

    def sendto(self, data, address):
        self.sent.append((time.monotonic(), bytes(data), address))
        self.changed.set()

    def close(self):
        self.transport.close()


async def wait_for_sends(capture, count, timeout):
    deadline = time.monotonic() + timeout
    while len(capture.sent) < count:
        capture.changed.clear()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(f"only captured {len(capture.sent)} of {count} sends")
        await asyncio.wait_for(capture.changed.wait(), remaining)
    return capture.sent


async def open_capture_server(device):
    transport, protocol = await start_server([device], "127.0.0.1", 0)
    address = transport.get_extra_info("sockname")[:2]
    capture = CaptureTransport(transport)
    protocol.transport = capture
    return address, protocol, capture


def assert_raw_status_report(inner, frame, raw_clock_hex):
    vector = FIXTURE["raw_binary"]["bin_status"]
    encoded_payload = base64.b64encode(frame).decode("ascii")
    expected_header = bytearray(base64.b64decode(vector["wrapper"]["header"], validate=True))
    expected_header[3] = len(encoded_payload)
    clock_offset = vector["metadata_clock_offset"]
    clock = bytes.fromhex(raw_clock_hex)
    expected_header[clock_offset:clock_offset + len(clock)] = clock
    assert inner == {
        "t": "binStatus", "mac": MAC, "binStatus": encoded_payload,
        "header": base64.b64encode(expected_header).decode("ascii"),
    }


def test_actual_cli_native_port_namespace_callbacks_and_fresh_restart():
    transport = FIXTURE["transport"]
    assert transport["accepted_source_port"] == 5001
    assert transport["reply_destination_port"] == 5000
    record = synthetic_record()
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind((PEER_IP, transport["reply_destination_port"]))
    sender.bind((PEER_IP, transport["accepted_source_port"]))
    receiver.settimeout(2)
    try:
        assert sender.getsockname()[1] == 5001
        assert receiver.getsockname()[1] == 5000
        with cli_server([record]) as (address, identities):
            identity = identities["crt"]
            assert identity["profile"] == FIXTURE["profile_id"]
            assert identity["mid"] == FIXTURE["configured_mid"]
            assert identity["mac"] == MAC

            # Ordinary unicast Gree LAN scan is not a native CRT operation.
            sender.sendto(b'{"t":"scan"}', address)
            assert_quiet(receiver)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as wrong_port:
                wrong_port.bind((PEER_IP, 0))
                send_native(wrong_port, address, {"t": "scan"}, 1, GENERIC_KEY)
                assert_quiet(receiver)

            # Invalid device-key, selector 2 object bypass, wrong selector, malformed JSON,
            # and an over-capacity datagram are silent; subsequent valid traffic recovers.
            synthetic_wrong_key = bytes.fromhex(FIXTURE["key_slots"]["synthetic_test_device_key_hex"])
            send_native(sender, address, {"t": "scan"}, 0, synthetic_wrong_key)
            assert_quiet(receiver)
            send_native(sender, address, {"t": "scan"}, 2, None)
            assert_quiet(receiver)
            send_native(sender, address, {"t": "scan"}, 3, GENERIC_KEY)
            assert_quiet(receiver)
            sender.sendto(b"{malformed JSON", address)
            assert_quiet(receiver)
            sender.sendto(b"x" * (transport["receive_buffer_bytes"] + 1), address)
            assert_quiet(receiver)
            send_native(sender, address, {"t": "scan"}, 1, GENERIC_KEY,
                        tcid="x" * transport["receive_buffer_bytes"])
            assert_quiet(receiver)

            # This is a directed request to the CLI socket, not a broadcast scan.
            send_native(sender, address, {"t": "scan"}, 1, GENERIC_KEY, uid=0xFFFFFFFF)
            outer, advertisement = receive_native(receiver, address, GENERIC_KEY)
            device_key = advertisement["devkey"].encode("ascii")
            assert advertisement == {
                "t": "UBind", "scene": 1, "mid": FIXTURE["configured_mid"],
                "ver": "V3.5.M", "lock": 0, "devkey": device_key.decode("ascii"),
                "hid": FIXTURE["hid"],
            }
            assert outer["i"] == 1 and outer["uid"] == 0xFFFFFFFF
            assert outer["cid"] == MAC and outer["tcid"] == ""
            assert outer["msgId"] == 0

            # A known wrong key and a mismatched callback slot are both rejected.
            wrong_key = bytes([device_key[0] ^ 1]) + device_key[1:]
            send_native(sender, address, {"t": "scan"}, 0, wrong_key)
            assert_quiet(receiver)
            send_native(sender, address, {"t": "scan"}, 0, device_key)
            assert_quiet(receiver)
            send_native(sender, address, {"t": "scan"}, 3, GENERIC_KEY)
            assert_quiet(receiver)

            # General/cloud-only callbacks and slot-two object bypass are not UDP admissions.
            for operation in transport["general_cloud_only"]:
                slot = operation["slot"]
                key = device_key if slot == 0 else GENERIC_KEY
                send_native(sender, address, {"t": operation["name"]}, slot, key)
                assert_quiet(receiver)

            room_id = FIXTURE["raw_binary"]["room_id"]["synthetic_input"]
            send_native(sender, address, {
                "t": "UBindok", "host": HOST_MAC, "hostManaged": 1, "roomId": room_id,
            }, 0, device_key, uid=19)
            proactive = [receive_native(receiver, address, device_key) for _ in range(2)]
            assert [inner for _, inner in proactive] == [
                {"t": "Utm"},
                {"t": "getLoginInfo", "loginInfo": ["GnetID"], "curGnetID": 0},
            ]
            assert [outer["msgId"] for outer, _ in proactive] == [1, 2]
            assert all("uid" not in outer and outer["i"] == 0 for outer, _ in proactive)
            assert all(outer["cid"] == MAC and outer["tcid"] == HOST_MAC
                       for outer, _ in proactive)

            # All remaining registered UDP callbacks are exercised using their source key slot.
            send_native(sender, address, {"t": "ret", "r": 200}, 0, device_key)
            send_native(sender, address, {"t": "hbok"}, 1, GENERIC_KEY)
            send_native(sender, address, {"t": "Utm", "time": "2026-01-02 03:04:05"},
                        0, device_key)
            send_native(sender, address, {
                "t": "loginInfoRes", "r": 200, "result": {"platform": 3},
            }, 0, device_key)
            send_native(sender, address, {"t": "statusCheck"}, 0, device_key)
            assert_quiet(receiver)

            raw_frame = bytes.fromhex(FIXTURE["raw_binary"]["synthetic_raw_frame_vectors"]["hex92"])
            bad_command = {"t": "binCmd", "hex92": base64.b64encode(raw_frame).decode("ascii")}
            send_native(sender, address, bad_command, 0, wrong_key)
            assert_quiet(receiver)
            send_native(sender, address, bad_command, 0, device_key, uid=71)
            outer, command_reply = receive_native(receiver, address, device_key)
            assert command_reply == {"t": "res", "r": 200, "mac": MAC}
            assert outer["uid"] == 71 and outer["msgId"] == 4

            send_native(sender, address, {"t": "reset", "mac": "0200000000ff"},
                        0, device_key)
            assert_quiet(receiver)
            send_native(sender, address, {"t": "reset", "mac": MAC}, 0, device_key, uid=73)
            outer, reset_reply = receive_native(receiver, address, device_key)
            assert reset_reply == {"t": "ret", "r": 200, "mac": MAC}
            assert outer["uid"] == 73

            # Private reset/report/heartbeat state has no public query; only these source replies
            # are asserted. A managed native scan proves the first process held its lock.
            send_native(sender, address, {"t": "scan", "i": 1}, 1, GENERIC_KEY)
            outer, managed_advertisement = receive_native(receiver, address, GENERIC_KEY)
            assert managed_advertisement["lock"] == 1
            assert outer["cid"] == MAC and outer["tcid"] == HOST_MAC

        with cli_server([record]) as (address, restarted):
            assert restarted["crt"]["mac"] == identity["mac"]
            send_native(sender, address, {"t": "scan", "i": 1}, 1, GENERIC_KEY)
            outer, advertisement = receive_native(receiver, address, GENERIC_KEY)
            assert advertisement["lock"] == 0
            assert advertisement["devkey"].encode("ascii") == device_key
            assert outer["msgId"] == 0 and outer["cid"] == MAC
    finally:
        sender.close()
        receiver.close()


def test_actual_cli_managed_login_info_waits_for_source_1500ms_countdown():
    record = synthetic_record()
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind((PEER_IP, 5000))
    sender.bind((PEER_IP, 5001))
    receiver.settimeout(2.5)
    try:
        with cli_server([record]) as (address, _identities):
            send_native(sender, address, {"t": "scan"}, 1, GENERIC_KEY)
            _, advertisement = receive_native(receiver, address, GENERIC_KEY)
            device_key = advertisement["devkey"].encode("ascii")

            started = time.monotonic()
            send_native(sender, address, {
                "t": "UBindok", "host": HOST_MAC, "hostManaged": 1,
            }, 0, device_key)
            first = receive_native(receiver, address, device_key)
            second = receive_native(receiver, address, device_key)
            assert [first[1]["t"], second[1]["t"]] == ["Utm", "getLoginInfo"]
            assert [first[0]["msgId"], second[0]["msgId"]] == [1, 2]

            # Source byte 0x4f expires after fifteen 100-ms callbacks. The shared
            # callback phase can shift the observed deadline by at most one interval.
            assert_quiet(receiver, timeout=1.3)
            outer, delayed_login = receive_native(receiver, address, device_key)
            elapsed = time.monotonic() - started
            assert 1.35 <= elapsed <= 2.1
            assert delayed_login["t"] == "getLoginInfo"
            assert delayed_login["loginInfo"] == ["GnetID"]
            # CLI config intentionally cannot override this private source identity byte.
            assert type(delayed_login["curGnetID"]) is int
            assert outer["i"] == 0 and outer["msgId"] == 4
            assert "uid" not in outer and outer["cid"] == MAC and outer["tcid"] == HOST_MAC
    finally:
        sender.close()
        receiver.close()


def test_real_300ms_unmanaged_retries_are_captured_before_broadcast_delivery():
    retry = FIXTURE["lifecycle"]["ubind_retry"]
    device = configured_device()
    runtime = device.state["_runtime"]
    runtime.update(retry["synthetic_test_initial_state"])
    runtime["ubind_gate_4ed"] = 1

    async def scenario():
        address, server, capture = await open_capture_server(device)
        try:
            assert address[1] > 0
            await wait_for_sends(capture, 1, 1.0)
            for count in (2, 3):
                await wait_for_sends(capture, count, 0.8)
                gap = capture.sent[count - 1][0] - capture.sent[count - 2][0]
                assert gap == pytest.approx(0.3, abs=0.15)
            assert [target for _, _, target in capture.sent] == [
                ("255.255.255.255", 5000),
            ] * 3
            for _, data, _ in capture.sent:
                outer, inner = native_response(data, GENERIC_KEY)
                assert "uid" not in outer and outer["i"] == 1 and outer["msgId"] == 0
                assert outer["cid"] == MAC and outer["tcid"] == ""
                assert inner == {
                    **retry["synthetic_test_outbound"]["inner"],
                    "devkey": device.key.decode("ascii"),
                }
            assert device.state["_runtime"]["ubind_retry_count"] == -1
            assert device.state["_runtime"]["ubind_timer"] == 0x401E
            await asyncio.sleep(0.35)
            assert len(capture.sent) == 3
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


def test_live_timer_capture_covers_type6_retry_type7_and_heartbeat_ack():
    queue = FIXTURE["lifecycle"]["raw_report_queue"]
    vectors = queue["synthetic_test_vectors"]
    source_address = "0x10016974"
    frame = bytes.fromhex(vectors["source_frames_by_address_hex"][source_address])
    device = configured_device()
    device.state["_runtime"]["ubind_gate_4ed"] = 1
    device.state["raw_status_frames"][int(source_address, 16)] = frame

    async def scenario():
        address, server, capture = await open_capture_server(device)
        peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        peer.bind((PEER_IP, 5001))
        peer.setblocking(False)
        try:
            loop = asyncio.get_running_loop()
            request = native_packet({
                "t": "UBindok", "host": HOST_MAC, "hostManaged": 1,
            }, 0, device.key)
            await loop.sock_sendto(peer, request, address)
            await wait_for_sends(capture, 2, 1.0)
            proactive = [native_response(data, device.key) for _, data, _ in capture.sent[:2]]
            assert [inner["t"] for _, inner in proactive] == ["Utm", "getLoginInfo"]
            assert [outer["msgId"] for outer, _ in proactive] == [0, 1]
            assert [target for _, _, target in capture.sent[:2]] == [(PEER_IP, 5000)] * 2

            # The real CLI node covers the 1.5-s source-state gate. Clear its private timer
            # here to isolate the independent raw-report retry worker.
            runtime = device.state["_runtime"]
            runtime["source_state_7"] = 0
            runtime["countdown_bytes"][7] = 0

            await wait_for_sends(capture, 6, 4.5)
            reports = []
            for index, (sent_at, data, target) in enumerate(capture.sent[2:6]):
                outer, inner = native_response(data, device.key)
                assert target == (PEER_IP, 5000)
                assert outer["i"] == 0 and outer["msgId"] == 2 and "uid" not in outer
                assert outer["cid"] == MAC and outer["tcid"] == HOST_MAC
                assert_raw_status_report(inner, frame, vectors["type6_retry_raw_clock_hex"][index])
                reports.append(sent_at)
            assert [reports[index + 1] - reports[index] for index in range(3)] == [
                pytest.approx(1.0, abs=0.2),
            ] * 3
            await asyncio.sleep(0.2)
            assert len(capture.sent) == 6
            assert device.state["_runtime"]["report_retry_count"] == -1

            # statusCheck has no direct ACK; its queued type-7 report is the observable result.
            before = len(capture.sent)
            await loop.sock_sendto(
                peer, native_packet({"t": "statusCheck"}, 0, device.key), address,
            )
            await wait_for_sends(capture, before + 1, 1.0)
            outer, status_report = native_response(capture.sent[before][1], device.key)
            assert capture.sent[before][2] == (PEER_IP, 5000)
            assert outer["i"] == 0 and outer["msgId"] == 2 and "uid" not in outer
            assert outer["cid"] == MAC and outer["tcid"] == HOST_MAC
            assert set(status_report) == {"t", "timestamp", "binStatus"}
            assert status_report["t"] == "statusCheckRes"
            baseline = vectors["baseline_status_timestamp_signed32"]
            assert type(status_report["timestamp"]) is int
            assert baseline <= status_report["timestamp"] <= baseline + 10
            assert base64.b64decode(status_report["binStatus"], validate=True) == frame

            # The timer deadline is seeded in private synthetic backing to avoid a real 60-s wait;
            # the server still emits through its live 100-ms ticker and captured send boundary.
            runtime = device.state["_runtime"]
            heartbeat = FIXTURE["lifecycle"]["heartbeat"]
            runtime.update({
                "rssi": heartbeat["synthetic_test_rssi_u32"],
                "heartbeat_timer_active": True,
                "heartbeat_period_due": time.monotonic() + 0.25,
                "heartbeat_period_ms": 60000,
                "heartbeat_watchdog_due": time.monotonic() + 61,
            })
            heartbeat_index = len(capture.sent)
            await wait_for_sends(capture, heartbeat_index + 1, 0.8)
            outer, heartbeat_packet = native_response(capture.sent[heartbeat_index][1], GENERIC_KEY)
            assert capture.sent[heartbeat_index][2] == (PEER_IP, 5000)
            assert outer["i"] == 1 and outer["uid"] == 0 and outer["msgId"] == 2
            assert outer["cid"] == MAC and outer["tcid"] == HOST_MAC
            assert heartbeat_packet == {
                "t": "hb", "cid": MAC,
                "RSSI": heartbeat["synthetic_test_rssi_u32"],
            }

            before_ack = len(capture.sent)
            await loop.sock_sendto(
                peer, native_packet({"t": "hbok"}, 1, GENERIC_KEY), address,
            )
            await asyncio.sleep(0.05)
            assert len(capture.sent) == before_ack
            updated = device.state["_runtime"]
            assert updated["heartbeat_miss_count"] == 0
            assert updated["heartbeat_timer_ms"] == 61000
            assert updated["heartbeat_watchdog_due"] is not None

            # Exercise the watchdog-to-1-s recovery callback with a synthetic due time;
            # the real server ticker still supplies each elapsed callback and send.
            watchdog_due = time.monotonic() + 0.2
            runtime = device.state["_runtime"]
            runtime.update({
                "heartbeat_watchdog_due": watchdog_due,
                "heartbeat_period_due": None,
                "heartbeat_period_ms": 61000,
                "heartbeat_miss_count": 0,
            })
            watchdog_packet_index = len(capture.sent)
            await wait_for_sends(capture, watchdog_packet_index + 1, 4.2)
            sent_at, data, target = capture.sent[watchdog_packet_index]
            assert 1.0 <= sent_at - watchdog_due <= 3.9
            assert target == (PEER_IP, 5000)
            outer, watchdog_packet = native_response(data, GENERIC_KEY)
            assert outer["i"] == 1 and outer["uid"] == 0 and outer["msgId"] == 3
            assert outer["cid"] == MAC and outer["tcid"] == HOST_MAC
            assert watchdog_packet == {
                "t": "hb", "cid": MAC,
                "RSSI": heartbeat["synthetic_test_rssi_u32"],
            }
            assert device.state["_runtime"]["heartbeat_miss_count"] == 1
        finally:
            peer.close()
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())
