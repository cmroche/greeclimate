"""Independent emulator protocol, configuration and thermal regressions."""

import asyncio
import base64
import json
import logging
import math
import socket
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from time import monotonic

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from gree_emulator.__main__ import load_config
from gree_emulator.device import EmulatedDevice, step_temperature
from gree_emulator.profiles import PROFILES, simulated
from gree_emulator.profiles.catalog_realtek_middle_wb import MiddleWBController
from gree_emulator.profiles.wb import WB04A
from gree_emulator.profiles.wb_remaining import WBRemainingFamily
from gree_emulator.server import start_server
from gree_emulator.wire import InvalidPacket, Reply, decode_outer, decode_pack, encode_reply


@pytest.mark.parametrize("room,target,ambient,action,elapsed,expected", [
    (26, 22, 28, "cool", 120, 24),
    (22.5, 22, 28, "cool", 120, 22),
    (20, 24, 28, "heat", 120, 22),
    (23.5, 24, 28, "heat", 120, 24),
    (20, 24, 28, "idle", 120, 20.2),
    (28, 24, 20, "idle", 120, 27.8),
    (20, 24, 20.1, "idle", 120, 20.1),
    (20, 22, 28, "cool", 120, 20),
    (26, 24, 28, "heat", 120, 26),
    (20, 24, 28, "auto", 120, 22),
    (26, 24, 28, "auto", 120, 24),
    (26, 24, 28, "cool", 0, 26),
])
def test_thermal_direction_rate_and_clamp(room, target, ambient, action, elapsed, expected):
    assert step_temperature(room, target, ambient, action, elapsed) == pytest.approx(expected)


@pytest.mark.parametrize("action", ["cool", "heat", "auto", "idle"])
def test_split_thermal_interval(action):
    first = step_temperature(26, 22, 28, action, 17)
    second = step_temperature(first, 22, 28, action, 103)
    assert second == pytest.approx(step_temperature(26, 22, 28, action, 120))


@pytest.mark.parametrize("elapsed", [-1, math.inf, math.nan])
def test_invalid_thermal_interval(elapsed):
    with pytest.raises(ValueError):
        step_temperature(26, 22, 28, "cool", elapsed)


@pytest.mark.parametrize("data", [
    b"\xff", b"[]", b"null", b'{"t":"scan"}{}',
    b'{"t":"scan","t":"pack"}', b'{"t":"pack","pack":{}}',
    b'{"t":"pack","pack":"AA==","i":true}',
    b'{"t":"scan","uid":NaN}', b'{"t":"scan","uid":1e999}',
    b'{"t":"scan","tcid":[]}',
    b'{"t":"scan","cid":"\\ud800"}',
    b'{"t":"scan","extra":["\\udfff"]}',
])
def test_reject_ambiguous_or_malformed_envelope(data):
    with pytest.raises(InvalidPacket):
        decode_outer(data)


@pytest.mark.parametrize("payload", ["!", "é", "", "AA==", "AAA=", "AAAA"])
def test_reject_invalid_encrypted_blocks(payload):
    with pytest.raises(InvalidPacket):
        decode_pack({"pack": payload}, b"0123456789abcdef", "aes-ecb-pkcs7")


def test_reject_padding_and_trailing_json():
    key = b"0123456789abcdef"
    for plain in (b'{"t":"status"}' + b"\x00\x02", pad(b'{"t":"status"}{}', 16)):
        payload = base64.b64encode(AES.new(key, AES.MODE_ECB).encrypt(plain)).decode()
        with pytest.raises(InvalidPacket):
            decode_pack({"pack": payload}, key, "aes-ecb-pkcs7")


@pytest.mark.parametrize("suffix,accepted", [(b"", True), (b"\0", True), (b"\0\0", False), (b"\0{}", False)])
def test_profile_specific_single_nul_input(suffix, accepted):
    key = b"0123456789abcdef"
    plain = b'{"t":"status"}' + suffix
    packed = {"pack": base64.b64encode(AES.new(key, AES.MODE_ECB).encrypt(pad(plain, 16))).decode()}
    if accepted:
        assert decode_pack(packed, key, "aes-ecb-pkcs7-nul-input") == {"t": "status"}
    else:
        with pytest.raises(InvalidPacket):
            decode_pack(packed, key, "aes-ecb-pkcs7-nul-input")
    if suffix:
        with pytest.raises(InvalidPacket):
            decode_pack(packed, key, "aes-ecb-pkcs7")


def test_encrypted_utf8_and_embedded_braces():
    inner = {"t": "status", "cols": ["name", "{not a delimiter}"], "name": "Büro"}
    plain = json.dumps(inner, ensure_ascii=False).encode()
    key = b"0123456789abcdef"
    payload = base64.b64encode(AES.new(key, AES.MODE_ECB).encrypt(pad(plain, 16))).decode()
    assert decode_pack({"pack": payload}, key, "aes-ecb-pkcs7") == inner

def test_source_scoped_ascii_space_lexer_keeps_json_validation():
    key = b"0123456789abcdef"
    plain = b'{"t": "status", "name": "A B", "escaped":"C\\u0020D", "tab":"\\t"}'
    packed = {"pack": base64.b64encode(
        AES.new(key, AES.MODE_ECB).encrypt(pad(plain, 16))).decode()}
    assert decode_pack(packed, key, "aes-ecb-pkcs7") == {
        "t": "status", "name": "A B", "escaped": "C D", "tab": "\t",
    }
    assert decode_pack(packed, key, "aes-ecb-pkcs7", strip_ascii_spaces=True) == {
        "t": "status", "name": "AB", "escaped": "C D", "tab": "\t",
    }
    duplicate = b'{"t":"status","t":"cmd"}'
    packed = {"pack": base64.b64encode(
        AES.new(key, AES.MODE_ECB).encrypt(pad(duplicate, 16))).decode()}
    with pytest.raises(InvalidPacket):
        decode_pack(packed, key, "aes-ecb-pkcs7", strip_ascii_spaces=True)


def test_independent_ciphertext_vector():
    # Native W06 framing and ROM AES ABI: private gree-research/tests/fixtures/emulator/gateway_research.json.
    cipher = bytes.fromhex(
        "2dbc97948aff4f4fea5a18123522b31271f54078b577168058719ea1ae7834eea3f"
        "66aecff4a7b1944dd5b198d68152d"
    )
    packed = base64.b64encode(cipher).decode()
    inner = {"t": "bind", "mac": "020000000001", "uid": 0}
    assert decode_pack({"pack": packed}, GENERIC_KEY, "aes-ecb-pkcs7") == inner
    encoded = encode_reply(Reply({"t": "pack"}, inner, GENERIC_KEY, "aes-ecb-pkcs7"))
    assert json.loads(encoded)["pack"] == packed


GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
VECTOR_DIRECTORY = Path(__file__).parent / "fixtures" / "emulator"


def peer_packet(outer, inner=None, key=GENERIC_KEY, *, nul_terminated=False):
    outer = dict(outer)
    if inner is not None:
        plaintext = json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode(errors="backslashreplace")
        if nul_terminated:
            plaintext += b"\0"
        encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(plaintext, 16))
        outer["pack"] = base64.b64encode(encrypted).decode()
    return json.dumps(outer, ensure_ascii=False).encode(errors="backslashreplace")


def peer_reply(data, key):
    outer = json.loads(data)
    if "pack" not in outer:
        return {"outer": outer}
    encrypted = base64.b64decode(outer.pop("pack"), validate=True)
    inner = json.loads(unpad(AES.new(key, AES.MODE_ECB).decrypt(encrypted), 16))
    return {"outer": outer, "inner": inner}


def peer_request(mac, command, fields=None, key=GENERIC_KEY):
    return peer_packet(
        {"cid": "app", "i": 1 if command == "bind" else 0,
         "t": "pack", "uid": 0, "tcid": mac},
        {"t": command, "mac": mac, **(fields or {})}, key,
    )


def receive(sock):
    return sock.recvfrom(65535)[0]


def conformance_vectors():
    return [
        (path.name, json.loads(path.read_text()))
        for path in sorted(VECTOR_DIRECTORY.glob("*.json"))
        if not path.stem.endswith("_research")
    ]


@pytest.mark.parametrize("filename,vector", conformance_vectors())
def test_generic_conformance_fixture_schema(filename, vector):
    assert {"profile", "mid", "initial_state", "requests", "expected_replies"} <= vector.keys(), filename
    assert isinstance(vector["requests"], list), filename
    assert isinstance(vector["expected_replies"], list), filename
    assert len(vector["requests"]) == len(vector["expected_replies"]), filename
    assert all(isinstance(replies, list) for replies in vector["expected_replies"]), filename


def vector_device(vector, parent_key=None):
    profile = PROFILES[vector["profile"]]
    identity = vector.get("device", {})
    device = EmulatedDevice(
        id=identity.get("id", "office"), mac=identity.get("mac", "020000000001"),
        name=identity.get("name", "Emulator Office"), mid=vector["mid"],
        key=parent_key or identity.get("key", "0123456789abcdef").encode(),
        profile=profile, state={**profile.initial_state, **vector["initial_state"]},
        room_c=identity.get("room_c", 26), ambient_c=identity.get("ambient_c", 26),
    )
    if profile.handler.thermal_target(device) is None:
        device.room_c = device.ambient_c = None
    profile.handler.encode_room(device)
    return device


@pytest.mark.parametrize("filename,vector", conformance_vectors())
async def test_protocol_and_model_vectors_over_udp(filename, vector):
    device = vector_device(vector)
    device.children = [vector_device(child, device.key) for child in vector.get("children", [])]
    validate_topology = getattr(device.profile.handler, "validate_topology", None)
    if validate_topology is not None:
        validate_topology(device)
    transport, server = await start_server([device, *device.children], "127.0.0.1", 0)
    address = transport.get_extra_info("sockname")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.settimeout(0.15)
            for request, expected in zip(vector["requests"], vector["expected_replies"], strict=True):
                if "raw_hex" in request:
                    packet = bytes.fromhex(request["raw_hex"])
                else:
                    key = request.get("key", "a3K8Bx%2r8Y7#xDh").encode()
                    packet = peer_packet(request["outer"], request.get("inner"), key,
                                         nul_terminated=request.get("nul_terminated", False))
                peer.sendto(packet, address)
                for reply in expected:
                    data = await asyncio.to_thread(receive, peer)
                    if "raw_hex" in reply:
                        assert data == bytes.fromhex(reply["raw_hex"]), filename
                    else:
                        key = GENERIC_KEY if reply["outer"].get("i") == 1 else device.key
                        assert peer_reply(data, key) == reply, filename
                if not expected:
                    with pytest.raises(socket.timeout):
                        await asyncio.to_thread(receive, peer)
            with pytest.raises(socket.timeout):
                await asyncio.to_thread(receive, peer)
            for name, expected_value in vector.get("expected_state", {}).items():
                assert device.state.get(name) == expected_value, filename
            if "expected_children" in vector:
                assert {child.mac for child in device.children} == vector["expected_children"].keys(), filename
                for mac, expected_state in vector["expected_children"].items():
                    if not expected_state:
                        continue
                    columns = list(expected_state)
                    peer.sendto(peer_request(device.mac, "status", {"mac": mac, "cols": columns}, device.key), address)
                    fresh = peer_reply(await asyncio.to_thread(receive, peer), device.key)["inner"]
                    assert fresh["cols"] == columns, filename
                    assert fresh["dat"] == list(expected_state.values()), filename
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.parametrize("config,field", [
    ({}, "devices"),
    ({"devices": []}, "devices"),
    ({"devices": [], "unexpected": 1}, "unexpected"),
    ({"devices": [], "listen": "::1"}, "listen"),
    ({"devices": [], "port": True}, "port"),
    ({"devices": [], "port": -1}, "port"),
    ({"devices": [], "port": 65536}, "port"),
    ({"devices": [], "seed": 42}, "seed"),
    ({"devices": [{"id": "office", "profile": "unverified", "mid": "3062"}]}, "profile"),
])
def test_invalid_config_is_rejected_before_startup(config, field):
    with pytest.raises(ValueError, match=field):
        load_config(config)


@pytest.mark.parametrize("args", [
    [], ["--profile", "missing"], ["--mid", "10001"], ["--count", "0"],
    ["--config", "missing.json", "--profile", "missing", "--mid", "10001"],
    ["--list-profiles", "--port", "0"],
])
def test_cli_rejects_invalid_selection(args):
    result = subprocess.run(
        [sys.executable, "-m", "gree_emulator", *args], capture_output=True, text=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert "Listening" not in result.stdout
    assert "error:" in result.stderr


@pytest.mark.parametrize("text", [
    '{"devices":[],"devices":[]}', '{"devices":[],"port":NaN}',
    '{"devices":[],"port":1e999}', "[" * 2000,
])
def test_cli_rejects_malformed_json(tmp_path, text):
    path = tmp_path / "devices.json"
    path.write_text(text)
    result = subprocess.run(
        [sys.executable, "-m", "gree_emulator", "--config", str(path)],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 2
    assert "Listening" not in result.stdout
    assert "Traceback" not in result.stderr


def standard_record(logical_id="office", **overrides):
    return {"id": logical_id, "profile": "sim-w04h-v3.55", "mid": "10001", **overrides}


def test_stable_identity_survives_reorder_and_other_devices():
    first = load_config({"seed": "ha-lab", "devices": [
        standard_record(), standard_record("bedroom"), standard_record("Büro"),
    ]})[2]
    restarted = load_config({"seed": "ha-lab", "devices": [
        standard_record("new"), standard_record("Büro", name="Renamed"),
        standard_record("bedroom"), standard_record(),
    ]})[2]
    expected = {
        "office": ("7acd2a730999", b"3e9792608c46a9b4"),
        "bedroom": ("dacfe6418480", b"326e93472ad63f95"),
        "Büro": ("aaa438a54a0f", b"3c917e7cd89f1188"),
    }
    assert {device.id: (device.mac, device.key) for device in first} == expected
    assert {device.id: (device.mac, device.key) for device in restarted if device.id in expected} == expected
    first[0].state["Pow"] = 1
    assert restarted[-1].state["Pow"] == 0
    assert first[1].state["Pow"] == 0


def test_ephemeral_seed_and_explicit_identity():
    config = {"devices": [standard_record(mac="02ABCDEF1234"), standard_record("random")]}
    first = load_config(config)[2]
    second = load_config(config)[2]
    assert first[0].mac == second[0].mac == "02abcdef1234"
    assert first[0].key != second[0].key
    assert first[1].mac != second[1].mac


@pytest.mark.parametrize("record,field", [
    ({"mid": "3062"}, "mid"),
    ({"unknown": True}, "unknown"),
    ({"state": {"hid": "forged"}}, "hid"),
    ({"state": {"name": "forged"}}, "name"),
    ({"state": {"_frame": "forged"}}, "private"),
    ({"state": {"not-a-property": 1}}, "state"),
    ({"state": {"Pow": "on"}}, "state"),
    ({"state": {"TemSen": 65536}}, "state"),
    ({"state": {"SetTem": -1}}, "state"),
    ({"state": {"Pow": True}}, "state"),
    ({"state": []}, "state"),
    ({"room_c": math.nan}, "room_c"),
    ({"ambient_c": math.inf}, "ambient_c"),
    ({"room_c": True}, "room_c"),
    ({"mac": "02:00:00:00:00:01"}, "mac"),
    ({"name": "\ud800"}, "name"),
    ({"parent": "missing"}, "parent"),
    ({"parent": "office"}, "cycle"),
])
def test_device_config_boundaries(record, field):
    with pytest.raises(ValueError, match=field):
        load_config({"devices": [standard_record(**record)]})


@pytest.mark.parametrize("records,field", [
    ([standard_record(), standard_record()], "duplicate id"),
    ([standard_record(mac="02ABCDEF1234"), standard_record("other", mac="02abcdef1234")], "duplicate"),
    ([standard_record(parent="other"), standard_record("other")], "unsupported parent"),
    ([standard_record(parent="other"), standard_record("other", parent="office")], "cycle"),
])
def test_topology_and_identity_collisions(records, field):
    with pytest.raises(ValueError, match=field):
        load_config({"devices": records})


def test_cli_occupied_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
        occupied.bind(("127.0.0.1", 0))
        result = subprocess.run(
            [sys.executable, "-m", "gree_emulator", "--profile", "sim-w04h-v3.55",
             "--mid", "10001", "--listen", "127.0.0.1", "--port", str(occupied.getsockname()[1])],
            capture_output=True, text=True, timeout=10,
        )
    assert result.returncode == 1
    assert "socket startup failed" in result.stderr
    assert "Listening" not in result.stdout


@pytest.mark.parametrize("atw_first", [True, False])
async def test_scan_rejection_is_isolated_per_device(atw_first):
    records = [
        {"id": "atw", "profile": "sim-w06a-p3-v6.04-9300", "mid": "9300"},
        {"id": "wb", "profile": "sim-wb04a-v1.49", "mid": "10f05"},
    ]
    if not atw_first:
        records.reverse()
    devices = load_config({"devices": records})[2]
    wb = next(device for device in devices if device.id == "wb")
    transport, server = await start_server(devices, "127.0.0.1", 0)
    address = transport.get_extra_info("sockname")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(0.2)
        try:
            peer.sendto(b'{"t":"scan","T":0}', address)
            reply = peer_reply(await asyncio.to_thread(receive, peer), GENERIC_KEY)["inner"]
            assert (reply["mac"], reply["mid"]) == (wb.mac, "10f05")
            with pytest.raises(socket.timeout):
                await asyncio.to_thread(receive, peer)
            peer.sendto(b'{"t":"scan"}', address)
            advertisements = [
                peer_reply(await asyncio.to_thread(receive, peer), GENERIC_KEY)["inner"]
                for _ in devices
            ]
            assert {reply["mac"] for reply in advertisements} == {device.mac for device in devices}
        finally:
            server.close()
            await server.wait_closed()


async def test_interleaved_clients_are_isolated_and_recover_after_bad_packets():
    devices = load_config({"seed": "ha-lab", "devices": [
        standard_record(room_c=22, ambient_c=22),
        standard_record("bedroom", room_c=28, ambient_c=28),
    ]})[2]
    transport, server = await start_server(devices, "127.0.0.1", 0)
    address = transport.get_extra_info("sockname")
    sockets = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in devices]
    try:
        for peer in sockets:
            peer.settimeout(0.2)
        for peer, device in zip(sockets, devices):
            peer.sendto(peer_request(device.mac, "bind", {"uid": 0}), address)
            reply = peer_reply(await asyncio.to_thread(receive, peer), GENERIC_KEY)["inner"]
            assert reply["key"].encode() == device.key
        for peer, device, target, mode in zip(sockets, devices, [22, 28], [1, 4]):
            peer.sendto(peer_request(device.mac, "cmd", {
                "opt": ["Pow", "Mod", "SetTem"], "p": [1, mode, target],
            }, device.key), address)
            assert peer_reply(await asyncio.to_thread(receive, peer), device.key)["inner"]["t"] == "res"
        first = devices[0]
        before = dict(first.state)
        malformed = [
            b"\xff", b'{"t":"scan","t":"pack"}',
            peer_request(first.mac, "cmd", {"opt": ["Pow"], "p": []}, first.key),
            peer_request(first.mac, "cmd", {"opt": ["Pow"], "p": [0]}, devices[1].key),
            peer_request(devices[1].mac, "cmd", {"opt": ["Pow"], "p": [0]}, first.key),
            peer_packet({"t": "pack", "i": 0, "uid": 0, "cid": "app", "tcid": first.mac},
                        {"t": "cmd", "mac": devices[1].mac, "opt": ["Pow"], "p": [0]}, first.key),
        ]
        for packet in malformed:
            sockets[0].sendto(packet, address)
            with pytest.raises(socket.timeout):
                await asyncio.to_thread(receive, sockets[0])
        assert first.state == before
        for peer, device, target, mode in zip(sockets, devices, [22, 28], [1, 4]):
            columns = ["SetTem", "Pow", "Mod", "SetTem"]
            peer.sendto(peer_request(device.mac, "status", {"cols": columns}, device.key), address)
            reply = peer_reply(await asyncio.to_thread(receive, peer), device.key)["inner"]
            assert reply["cols"] == columns
            assert reply["dat"] == [target, 1, mode, target]
        sockets[0].sendto(peer_request(first.mac, "bind", {"uid": 0}), address)
        assert peer_reply(await asyncio.to_thread(receive, sockets[0]), GENERIC_KEY)["inner"]["key"].encode() == first.key
        assert devices[1].state["SetTem"] == 28
    finally:
        for peer in sockets:
            peer.close()
        server.close()
        await server.wait_closed()


@pytest.mark.parametrize(
    "profile",
    [profile for profile in PROFILES.values()
     if isinstance(profile.handler, (WB04A, MiddleWBController, WBRemainingFamily))],
    ids=lambda profile: profile.id,
)
async def test_wb_non_string_operations_reject_atomically_and_recover(profile):
    device = load_config({"devices": [
        {"id": "office", "profile": profile.id, "mid": profile.mids[0]},
    ]})[2][0]
    transport, server = await start_server([device], "127.0.0.1", 0)
    address = transport.get_extra_info("sockname")
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.settimeout(0.2)
    codec = getattr(profile.handler, "codec", "aes-ecb-pkcs7")
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    unhandled = []
    loop.set_exception_handler(lambda _loop, context: unhandled.append(context))

    def packet(inner):
        return encode_reply(Reply(
            {"t": "pack", "i": 0, "uid": 42, "cid": "peer", "tcid": device.mac},
            inner, device.key, codec,
        ))

    try:
        before = deepcopy(device.state)
        for invalid_type in ([], {}):
            malformed = packet({"t": invalid_type})
            with pytest.raises(InvalidPacket):
                device.profile.handler.handle(device, json.loads(malformed))
            assert device.state == before
            peer.sendto(malformed, address)
            with pytest.raises(socket.timeout):
                await asyncio.to_thread(receive, peer)
            assert device.state == before

        peer.sendto(packet({"t": "status", "mac": device.mac, "cols": ["Pow"]}), address)
        response = json.loads(await asyncio.to_thread(receive, peer))
        assert decode_pack(response, device.key, codec)["t"] == "dat"
        assert not unhandled
    finally:
        loop.set_exception_handler(previous_handler)
        peer.close()
        server.close()
        await server.wait_closed()


@pytest.mark.parametrize("profile_id", ["sim-w04h-v3.55", "sim-w04n-v17"])
def test_command_between_ticks_uses_old_controls_then_new_controls(profile_id):
    device = load_config({"seed": "clock", "devices": [
        {"id": "office", "profile": profile_id, "mid": "10001", "room_c": 26,
         "state": {"Pow": 1, "Mod": 1, "SetTem": 22}},
    ]})[2][0]
    device.last_step = monotonic() - 30
    request = json.loads(peer_request(device.mac, "cmd", {
        "opt": ["Mod", "SetTem"], "p": [4, 28],
    }, device.key))
    device.profile.handler.handle(device, request)
    assert device.room_c == pytest.approx(25.5, abs=0.01)
    device.advance(device.last_step + 60)
    assert device.room_c == pytest.approx(26.5, abs=0.01)
    room = device.room_c
    device.advance(device.last_step)
    assert device.room_c == room


@pytest.mark.parametrize("profile_id,encoded", [
    ("sim-w04h-v3.55", 65), ("sim-w04n-v17", 25),
])
def test_display_units_do_not_change_room_sensor_bias(profile_id, encoded):
    device = load_config({"seed": "units", "devices": [
        {"id": "office", "profile": profile_id, "mid": "10001",
         "room_c": 25, "ambient_c": 25},
    ]})[2][0]
    for units, fraction in ((1, 1), (0, 0)):
        device.profile.handler.handle(device, json.loads(peer_request(device.mac, "cmd", {
            "opt": ["TemUn", "TemRec"], "p": [units, fraction],
        }, device.key)))
        replies = device.profile.handler.handle(device, json.loads(peer_request(
            device.mac, "status", {"cols": ["TemSen"]}, device.key)))
        assert replies[0].inner["dat"] == [encoded]


@pytest.mark.parametrize("names,values", [
    (["Pow", "SetTem"], [0, 31]),
    (["Pow", "TemSen"], [0, 65]),
    (["Pow", "unknown"], [0, 1]),
    (["Pow"], [True]),
    (["Pow"], ["1"]),
    (["Pow"], []),
])
def test_invalid_batch_does_not_apply_prefix_or_advance_clock(names, values):
    device = load_config({"devices": [
        standard_record(state={"Pow": 1, "Mod": 1, "SetTem": 22}),
    ]})[2][0]
    device.last_step = monotonic() - 120
    before = dict(device.state), device.room_c, device.last_step
    with pytest.raises(InvalidPacket):
        simulated.apply_command(device, names, values)
    assert (device.state, device.room_c, device.last_step) == before


def test_simulated_steady_heat_and_fan_are_explicit():
    device = load_config({"devices": [
        standard_record(room_c=7, state={"Pow": 1, "Mod": 4, "StHt": 1}),
    ]})[2][0]
    device.last_step = 0
    device.advance(120)
    assert device.room_c == 8
    device.state["Mod"] = 3
    device.advance(240)
    assert device.room_c == pytest.approx(8.2)


@pytest.mark.parametrize("profile_id", ["sim-w04h-v3.55", "sim-w04n-v17"])
def test_unadvertisable_metadata_is_rejected_before_startup(profile_id):
    with pytest.raises(ValueError, match="name"):
        load_config({"devices": [standard_record(profile=profile_id, name="x" * 2048)]})


def test_normalized_status_reply_cannot_overflow_output_buffer():
    device = load_config({"devices": [
        standard_record(profile="sim-w04n-v17", name="x" * 128),
    ]})[2][0]
    before = dict(device.state), device.last_step
    request = json.loads(peer_request(device.mac, "status", {"cols": ["name"] * 64}, device.key))
    with pytest.raises(InvalidPacket, match="buffer"):
        device.profile.handler.handle(device, request)
    assert (device.state, device.last_step) == before
    reply = device.profile.handler.handle(device, json.loads(peer_request(
        device.mac, "status", {"cols": ["Pow", "TemSen"]}, device.key)))[0]
    assert reply.inner["dat"] == [0, 26]


def test_gateway_children_link_before_parent_and_keep_parent_key():
    records = [
        {"id": "first", "profile": "sim-w06av-v30-ac", "mid": "6049", "parent": "gateway"},
        {"id": "gateway", "profile": "sim-w06av-v30", "mid": "60"},
        {"id": "second", "profile": "sim-w06av-v30-ac", "mid": "604a", "parent": "gateway"},
    ]
    first, gateway, second = load_config({"seed": "gateway-lab", "devices": records})[2]
    assert gateway.children == [first, second]
    assert first.key == second.key == gateway.key
    assert gateway.room_c is None and gateway.ambient_c is None
    assert len(first.mac) == len(second.mac) == 14 and first.mac != second.mac
    gateway.profile.handler.handle(gateway, json.loads(peer_request(
        gateway.mac, "cmd", {"sub": first.mac, "opt": ["Pow"], "p": [1]}, gateway.key)))
    for child, expected in ((first, 1), (second, 0)):
        reply = gateway.profile.handler.handle(gateway, json.loads(peer_request(
            gateway.mac, "status", {"mac": child.mac, "cols": ["Pow"]}, gateway.key)))[0]
        assert reply.inner["dat"] == [expected]


def test_gateway_child_count_does_not_wrap():
    records = [{"id": "gateway", "profile": "sim-w06av-v30", "mid": "60"}] + [
        {"id": f"child-{index}", "profile": "sim-w06av-v30-ac", "mid": "6049", "parent": "gateway"}
        for index in range(256)
    ]
    assert len(load_config({"devices": records[:-1]})[2][0].children) == 255
    with pytest.raises(ValueError, match="at most 255 children"):
        load_config({"devices": records})




def zone_records():
    return [
        {"id": "root", "profile": "sim-w05sa-v1.28", "mid": "50", "mac": "020000000001",
         "state": {"MasterPow": 1, "Mod": 1, "StTem": 6}},
        {"id": "master", "profile": "sim-w05sa-v1.28-master", "mid": "5000",
         "parent": "root", "mac": "02000000000100", "room_c": 26, "ambient_c": 26},
        {"id": "zone", "profile": "sim-w05sa-v1.28-zone", "mid": "5001",
         "parent": "root", "mac": "02000000000103", "room_c": 26, "ambient_c": 26,
         "state": {"Pow": 1, "StTem": 6}},
    ]


@pytest.mark.parametrize("case", ["missing-master", "wrong-prefix", "wrong-slot", "duplicate-slot"])
def test_zone_topology_rejects_unaddressable_children(case):
    records = zone_records()
    if case == "missing-master":
        records.pop(1)
    elif case == "wrong-prefix":
        records[2]["mac"] = "02000000000203"
    elif case == "wrong-slot":
        records[2]["mac"] = "02000000000109"
    else:
        records[2]["mac"] = records[1]["mac"]
    with pytest.raises(ValueError):
        load_config({"devices": records})


def test_zone_master_command_advances_every_room_under_old_controls():
    root, master, zone = load_config({"devices": zone_records()})[2]
    now = monotonic()
    master.last_step = zone.last_step = now - 30
    root.profile.handler.handle(root, json.loads(peer_request(root.mac, "cmd", {
        "sub": root.mac, "opt": ["Mod"], "p": [2],
    }, root.key)))
    assert master.room_c == pytest.approx(25.5, abs=0.01)
    assert zone.room_c == pytest.approx(25.5, abs=0.01)
    assert master.last_step == zone.last_step
    master.advance(master.last_step + 60)
    zone.advance(zone.last_step + 60)
    assert master.room_c == pytest.approx(25.5, abs=0.01)
    assert zone.room_c == pytest.approx(25.5, abs=0.01)


@pytest.mark.parametrize("target_id", ["master", "zone"])
async def test_zone_child_commands_and_status_resolve_shared_aliases(target_id):
    records = zone_records()
    records[2]["state"].update(Pow=0, StTem=9)
    devices = load_config({"devices": records})[2]
    root, master, zone = devices
    target = next(device for device in devices if device.id == target_id)
    transport, server = await start_server(devices, "127.0.0.1", 0)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.settimeout(1)

            async def request(command, fields):
                peer.sendto(peer_request(root.mac, command, fields, root.key),
                            transport.get_extra_info("sockname"))
                return peer_reply(await asyncio.to_thread(receive, peer), root.key)["inner"]

            columns = ["StTem3", "EnWdVlv3", "Mod"]
            reply = await request("status", {"mac": target.mac, "cols": columns})
            assert reply["cols"] == columns and reply["dat"] == [9, 0, 1]
            reply = await request("cmd", {
                "sub": target.mac, "opt": columns, "p": [10, 1, 2],
            })
            assert (reply["t"], reply["r"], reply["mac"]) == ("res", 200, target.mac)
            assert reply["opt"] == columns and reply["p"] == [10, 1, 2]
            for device in devices:
                reply = await request("status", {"mac": device.mac, "cols": columns})
                assert reply["cols"] == columns and reply["dat"] == [10, 1, 2]
            for device, expected in ((master, [1, 6]), (zone, [1, 10])):
                reply = await request("status", {"mac": device.mac, "cols": ["Pow", "StTem"]})
                assert reply["cols"] == ["Pow", "StTem"] and reply["dat"] == expected
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.parametrize("profile_id,mid", [
    ("sim-w04h-v3.55", "10001"), ("sim-w04hb-v1.20", "302b"),
    ("sim-wb04a-v1.49", "10f05"), ("sim-w06dv-v4.01", "3018"),
    ("sim-wb04brt13-v1.50-3019", "3019"),
])
async def test_oversized_raw_command_does_not_mutate(profile_id, mid):
    device = load_config({"devices": [{"id": "office", "profile": profile_id, "mid": mid}]})[2][0]
    transport, server = await start_server([device], "127.0.0.1", 0)
    address = transport.get_extra_info("sockname")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.settimeout(0.15)
            oversized = b" " * 1500 + peer_request(device.mac, "cmd", {"opt": ["Pow"], "p": [1]}, device.key)
            peer.sendto(oversized, address)
            with pytest.raises(socket.timeout):
                await asyncio.to_thread(receive, peer)
            peer.sendto(peer_request(device.mac, "status", {"cols": ["Pow"]}, device.key), address)
            status = peer_reply(await asyncio.to_thread(receive, peer), device.key)["inner"]
            assert status["cols"] == ["Pow"] and status["dat"] == [0]
    finally:
        server.close()
        await server.wait_closed()


async def test_scan_size_limit_is_applied_per_device():
    hb, wb = load_config({"devices": [
        {"id": "hb", "profile": "sim-w04hb-v1.20", "mid": "302b"},
        {"id": "wb", "profile": "sim-wb04a-v1.49", "mid": "10f05"},
    ]})[2]
    transport, server = await start_server([hb, wb], "127.0.0.1", 0)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.settimeout(0.15)
            peer.sendto(b" " * 1100 + b'{"t":"scan"}', transport.get_extra_info("sockname"))
            advertised = peer_reply(await asyncio.to_thread(receive, peer), GENERIC_KEY)["inner"]
            assert advertised["mac"] == wb.mac and advertised["mid"] == "10f05"
            with pytest.raises(socket.timeout):
                await asyncio.to_thread(receive, peer)
    finally:
        server.close()
        await server.wait_closed()


async def test_packet_logs_show_plaintext_without_ciphertext(caplog):
    device = load_config({"devices": [standard_record()]})[2][0]
    transport, server = await start_server([device], "127.0.0.1", 0)
    caplog.set_level(logging.INFO, logger="gree_emulator")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind(("127.0.0.1", 0))
            peer.settimeout(0.2)
            endpoint = transport.get_extra_info("sockname")
            peer_address = "%s:%s" % peer.getsockname()
            malformed = b"\xff\nforged log line"
            peer.sendto(malformed, endpoint)
            with pytest.raises(socket.timeout):
                await asyncio.to_thread(receive, peer)
            assert peer_address in caplog.text
            assert str(len(malformed)) in caplog.text
            assert repr(malformed) not in caplog.text

            for packet, key in [
                (b'{"t":"scan"}', GENERIC_KEY),
                (peer_request(device.mac, "bind", {"uid": 0}), GENERIC_KEY),
                (peer_request(device.mac, "status", {"cols": ["Pow"]}, device.key), device.key),
                (peer_request(device.mac, "cmd", {"opt": ["Pow"], "p": [1]}, device.key), device.key),
            ]:
                caplog.clear()
                peer.sendto(packet, endpoint)
                data = await asyncio.to_thread(receive, peer)
                reply = peer_reply(data, key)["inner"]
                request = json.loads(packet)
                if "pack" in request:
                    assert request["pack"] not in caplog.text
                    request = peer_reply(packet, key)["inner"]
                assert repr(request) in caplog.text
                assert repr(reply) in caplog.text
                assert json.loads(data)["pack"] not in caplog.text
                assert peer_address in caplog.text
                assert "RX" in caplog.text and "TX" in caplog.text
                assert str(len(packet)) in caplog.text and str(len(data)) in caplog.text
            assert device.state["Pow"] == 1
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.parametrize("case", ["missing-child", "wrong-prefix"])
def test_commercial_topology_requires_addressable_appliance(case):
    records = [
        {"id": "host", "profile": "sim-wb04brt13-v1.50-60", "mid": "60", "mac": "020000000001"},
        {"id": "unit", "profile": "sim-wb04brt13-v1.50-6400", "mid": "6400",
         "parent": "host", "mac": "02000000000100"},
    ]
    if case == "missing-child":
        records.pop()
    else:
        records[1]["mac"] = "02000000000200"
    with pytest.raises(ValueError):
        load_config({"devices": records})


async def test_example_config_starts_families_and_isolates_gateways():
    root = Path(__file__).resolve().parents[1]
    example = root / "examples" / "emulator-devices.json"
    records = json.loads(example.read_text(encoding="utf-8"))["devices"]
    process = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "gree_emulator", "--config", str(example),
        "--listen", "127.0.0.1", "--port", "0", cwd=root,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.settimeout(1)
    address = None
    startup_output = []
    startup_ready = False
    try:
        line = await asyncio.wait_for(process.stdout.readline(), 5)
        startup_output.append(line)
        prefix = b"Listening on 127.0.0.1:"
        assert line.startswith(prefix)
        port = int(line[len(prefix):])
        assert 0 < port <= 65535
        address = ("127.0.0.1", port)
        announcements = []
        for _ in records:
            line = await asyncio.wait_for(process.stdout.readline(), 5)
            startup_output.append(line)
            announcements.append(json.loads(line))
        assert len({item["mac"] for item in announcements}) == len(records)
        assert {item["id"] for item in announcements} == {record["id"] for record in records}
        devices = {item["id"]: item for item in announcements}
        for record in records:
            announced = devices[record["id"]]
            assert announced["profile"] == record["profile"]
            assert announced["mid"] == record["mid"]
            assert announced["parent"] == record.get("parent")
            assert announced["name"] == record["id"]
            if "mac" in record:
                assert announced["mac"] == record["mac"]
        startup_ready = True
        roots = [record for record in records if "parent" not in record]
        assert len(roots) == 9
        peer.sendto(b'{"t":"scan"}', address)
        advertisements = [
            peer_reply(await asyncio.to_thread(receive, peer), GENERIC_KEY)["inner"]
            for _ in roots
        ]
        assert all(reply["t"] == "dev" for reply in advertisements)
        assert {(reply["mac"], reply["mid"]) for reply in advertisements} == {
            (devices[record["id"]]["mac"], record["mid"]) for record in roots
        }
        peer.settimeout(0.2)
        with pytest.raises(socket.timeout):
            await asyncio.to_thread(receive, peer)
        peer.settimeout(1)

        keys = {}

        async def request(root_id, command, fields=None, *, key=None):
            key = keys[root_id] if key is None else key
            peer.sendto(peer_request(devices[root_id]["mac"], command, fields, key), address)
            return peer_reply(await asyncio.to_thread(receive, peer), key)["inner"]

        for record in roots:
            logical_id = record["id"]
            reply = await request(logical_id, "bind", {"uid": 0}, key=GENERIC_KEY)
            expected_kind = "bindOk" if logical_id in ("gateway-a", "gateway-b", "zones") else "bindok"
            assert reply["t"] == expected_kind
            assert reply["r"] == 200
            assert reply["mac"] == devices[logical_id]["mac"]
            keys[logical_id] = reply["key"].encode("ascii")
        assert keys["gateway-a"] != keys["gateway-b"]

        for parent in ("gateway-a", "gateway-b", "commercial-host", "zones"):
            reply = await request(parent, "subDev", {"i": 0})
            children = [record for record in records if record.get("parent") == parent]
            assert (reply["t"], reply["r"], reply["i"], reply["c"]) == ("subList", 200, 0, len(children))
            actual = [(child["mac"], child["mid"]) for child in reply["list"]]
            expected = [(devices[child["id"]]["mac"], child["mid"]) for child in children]
            if parent == "zones":
                assert actual == expected
            else:
                assert len(actual) == len(expected)
                assert set(actual) == set(expected)

        columns = ["Pow", "Mod", "SetTem"]

        async def status(parent, child, expected, cols=columns):
            reply = await request(parent, "status", {"mac": devices[child]["mac"], "cols": cols})
            assert (reply["t"], reply["r"], reply["mac"]) == ("dat", 200, devices[child]["mac"])
            assert reply["cols"] == cols
            assert reply["dat"] == expected

        for logical_id in ("w04h-ac", "w04n-ac", "wb04a-ac", "w04hb-controller", "w06dv-controller"):
            await status(logical_id, logical_id, [0, 0, 24])
        await status("commercial-host", "commercial-ac", [0, 0, 24])
        for child in ("zone-master", "zone-1"):
            await status("zones", child, [0, 0, 8], ["Pow", "Mod", "StTem"])

        for parent, values in (("gateway-a", [1, 1, 22]), ("gateway-b", [1, 4, 28])):
            child = parent + "-room-1"
            reply = await request(parent, "cmd", {
                "sub": devices[child]["mac"], "opt": columns, "p": values,
            })
            assert (reply["t"], reply["r"], reply["mac"]) == ("res", 200, devices[child]["mac"])
            assert reply["opt"] == columns
            assert reply["p"] == reply["val"] == values

        async def check_gateway_statuses():
            for parent, values in (("gateway-a", [1, 1, 22]), ("gateway-b", [1, 4, 28])):
                await status(parent, parent + "-room-1", values)
                await status(parent, parent + "-room-2", [0, 0, 24])

        await check_gateway_statuses()
        for parent in ("gateway-a", "gateway-b"):
            peer.sendto(peer_request(devices[parent]["mac"], "cmd", {
                "sub": devices["gateway-b-room-1"]["mac"], "opt": ["Pow"], "p": [0],
            }, keys["gateway-a"]), address)
            peer.settimeout(0.2)
            with pytest.raises(socket.timeout):
                await asyncio.to_thread(receive, peer)
            peer.settimeout(1)
            await check_gateway_statuses()
    finally:
        peer.close()
        if process.returncode is None:
            process.terminate()
        try:
            _, stderr = await asyncio.wait_for(process.communicate(), 5)
        except asyncio.TimeoutError:
            process.kill()
            _, stderr = await asyncio.wait_for(process.communicate(), 5)
        if address is not None:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as released:
                released.bind(address)
        if not startup_ready:
            pytest.fail(f"Invalid or incomplete startup: {startup_output!r}; stderr={stderr.decode(errors='replace')}")
