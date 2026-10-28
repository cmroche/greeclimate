"""Raw consumer expectations independent of emulator/client-generated vectors."""

import asyncio
import base64
from copy import deepcopy
import json
from pathlib import Path
import signal
import socket
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.catalog_esp_alarm import GENERIC_KEY, PROFILES
from gree_emulator.wire import InvalidPacket, decode_outer, encode_reply

VECTORS = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-esp-alarm-vectors_research.json").read_text())


@pytest.fixture
def device(monkeypatch):
    monkeypatch.setattr("gree_emulator.profiles.catalog_esp_alarm.monotonic", lambda: 1000)
    profile, = PROFILES
    return EmulatedDevice("alarm", VECTORS["mac"], "alarm-board", "80260",
                          VECTORS["key"].encode(), profile,
                          dict(profile.initial_state), last_step=1000)


def packet(device, inner, index=0, uid=37, key=None):
    plain = json.dumps(inner, separators=(",", ":")).encode()
    selected = key if key is not None else device.key if index & 255 == 0 else GENERIC_KEY
    payload = (plain.decode() if index & 255 == 2 else
               base64.b64encode(AES.new(selected, AES.MODE_ECB).encrypt(pad(plain, 16))).decode())
    return {"t": "pack", "i": index, "uid": uid, "tcid": device.mac,
            "cid": "not-an-echo-target", "pack": payload}


def reply(device, inner, *, expected_index=0, **kwargs):
    result, = device.profile.handler.handle(device, packet(device, inner, **kwargs))
    wire = encode_reply(result)
    assert not wire.endswith(b"\n")
    outer = json.loads(wire)
    assert {name: value for name, value in outer.items() if name != "pack"} == {
        "t": "pack", "i": expected_index, "uid": kwargs.get("uid", 37),
        "cid": device.mac, "tcid": "app"}
    key = GENERIC_KEY if expected_index else device.key
    return json.loads(unpad(AES.new(key, AES.MODE_ECB).decrypt(base64.b64decode(outer["pack"])), 16))


def status(device, columns):
    return reply(device, {"t": "status", "cols": columns})


def test_discovery_exact_fixed_mid_and_bind_session_lifecycle(device):
    handler = device.profile.handler
    advert, = handler.advertise(device, {"t": "scan"})
    outer = json.loads(encode_reply(advert))
    scan = json.loads(unpad(AES.new(GENERIC_KEY, AES.MODE_ECB).decrypt(base64.b64decode(outer["pack"])), 16))
    assert scan == {"t": "dev", "cid": device.mac, "bc": "gree", "brand": "gree",
                    "catalog": "gree", "mac": device.mac, "mid": "80260", "model": "gree",
                    "series": "gree", "name": "alarm-board", "vender": "1", "ver": "V1.0",
                    "lock": 0, "subCnt": 0}
    assert device.profile.mids == ("80260",)
    assert device.profile.max_request_bytes == 1460
    for index in (1, 257, -255, 2):
        assert reply(device, {"t": "bind", "mac": "source-ignores-inner-mac"},
                     index=index, expected_index=1) == {
            "t": "bindok", "mac": device.mac, "key": VECTORS["key"], "r": 200}
    reply(device, {"t": "cmd", "opt": ["AlarmTime"], "p": [19]})
    reply(device, {"t": "bind"}, index=1, expected_index=1)
    assert status(device, ["AlarmTime"])["dat"] == [19]


def test_all_five_fields_string_ack_and_independently_fresh_status(device):
    for vector in VECTORS["transactions"]:
        result = reply(device, {"t": "cmd", "opt": vector["opt"], "p": vector["p"]})
        assert result == {"t": "res", "r": 200, "mac": device.mac,
                          "opt": vector["opt"], "p": vector["ack"]}
        columns = vector.get("cols", VECTORS["fields"])
        fresh = status(device, columns)
        assert fresh == {"t": "dat", "r": 200, "mac": device.mac,
                         "cols": columns, "dat": vector["dat"]}


def test_complete_metadata_and_unknowns_are_not_typed_ac_support(device):
    vector = VECTORS["metadata"]
    assert status(device, vector["cols"])["dat"] == vector["dat"]
    reply(device, {"t": "cmd", "opt": ["host", "name", "hid", "lock", "TemSen"],
                   "p": ["changed", "changed", "changed", 17, 99]})
    assert status(device, vector["cols"])["dat"] == vector["dat"]
    assert status(device, ["_uid", "missing", "Pow", "missing"])["dat"] == [0, 0, 1, 0]
    assert device.profile.handler.thermal_target(device) is None


@pytest.mark.parametrize("bad", [True, False, None, [], {}, [1], 2147483648,
                                 -2147483649, "2147483648", "-2147483649", "[1]", "a\u0000b"])
def test_safe_atomic_rejection_keeps_cache_and_clock(device, bad):
    before, clock = deepcopy(device.state), device.last_step
    with pytest.raises(InvalidPacket):
        reply(device, {"t": "cmd", "opt": ["Pow", "AlarmTime"], "p": [1, bad]})
    assert device.state == before
    assert device.last_step == clock


@pytest.mark.parametrize("inner", [
    {"t": "cmd", "opt": ["Pow"], "p": []},
    {"t": "cmd", "opt": [], "p": []},
    {"t": "status", "cols": []},
    {"t": "status", "cols": [True]},
    {"t": "status", "cols": ["Pow"] * 65},
    {"t": "cmd", "opt": ["Pow"], "p": "1"},
])
def test_malformed_batch_and_bounded_parser_recovery(device, inner):
    with pytest.raises(InvalidPacket):
        reply(device, inner)
    assert status(device, ["Pow"])["dat"] == [1]


def test_wrong_keys_target_uid_and_strict_wire_recovery(device):
    request = packet(device, {"t": "status", "cols": ["Pow"]})
    for outer in ({**request, "tcid": "02000000a261"},
                  {**request, "i": True}, {**request, "uid": 1 << 32},
                  packet(device, {"t": "status", "cols": ["Pow"]}, key=b"wrongkeywrongkey")):
        with pytest.raises(InvalidPacket):
            device.profile.handler.handle(device, outer)
    with pytest.raises(InvalidPacket):
        decode_outer(b'{"t":"pack","i":0,"i":1,"pack":"x"}')
    assert reply(device, {"t": "status", "cols": ["Pow"]}, index=256, uid=-19)["dat"] == [1]
    assert reply(device, {"t": "status", "cols": ["Pow"]}, index=2)["dat"] == [1]
    assert device.profile.handler.handle(device, packet(device, {"t": "subDev"})) == []


def test_oversized_reply_preflight_prevents_mutation(device):
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        reply(device, {"t": "cmd", "opt": ["Pow", *(["unknown" * 8] * 39)],
                       "p": [1, *(["n" * 60] * 39)]})
    assert device.state == before


def test_isolation_restart_and_no_invented_alarm_or_temperature_actions(device):
    reply(device, {"t": "cmd", "opt": VECTORS["fields"], "p": [1, 2, 3, 4, 5]})
    device.advance(1060)
    assert device.room_c == 26.0
    profile = device.profile
    second = EmulatedDevice("other", "02000000a261", "other", "80260", device.key,
                            profile, dict(profile.initial_state), last_step=1000)
    assert status(second, VECTORS["fields"])["dat"] == [1, 1, 0, 0, 0]
    restarted = EmulatedDevice(device.id, device.mac, device.name, device.mid, device.key,
                               profile, dict(profile.initial_state), last_step=1000)
    assert status(restarted, VECTORS["fields"])["dat"] == [1, 1, 0, 0, 0]


def test_initial_state_rejects_identity_private_and_out_of_width_overrides(device):
    for state in ({"name": 1}, {"_uid": 1}, {"Pow": True}, {"AlarmTime": 1 << 32}):
        with pytest.raises(ValueError):
            device.profile.handler.validate_state(state)


def test_source_power_alias_and_no_separate_work_state_override(device):
    reply(device, {"t": "cmd", "opt": ["Pow", "WorkState"], "p": [7, -9]})
    assert status(device, ["Pow", "WorkState"])["dat"] == [-9, -9]
    with pytest.raises(ValueError):
        device.profile.handler.validate_state({"WorkState": 7})


def test_no_reply_management_time_watchdog_and_deferred_restart(device, monkeypatch):
    handler = device.profile.handler
    key = device.key
    reply(device, {"t": "cmd", "opt": ["Pow", "AlarmTime"], "p": [9, 77]})
    assert handler.handle(device, {"t": "tm", "time": "2026-10-24 12:30:09"}) == []
    assert handler.handle(device, {"t": "loginRes"}) == []
    assert status(device, ["time", "Pow", "WorkState"])["dat"] == [0, 9, 9]
    assert handler.handle(device, {"t": "restart", "delay": 5000}) == []
    monkeypatch.setattr("gree_emulator.profiles.catalog_esp_alarm.monotonic", lambda: 1004.999)
    assert status(device, ["AlarmTime"])["dat"] == [77]
    monkeypatch.setattr("gree_emulator.profiles.catalog_esp_alarm.monotonic", lambda: 1005)
    assert status(device, VECTORS["fields"])["dat"] == [1, 1, 0, 0, 0]
    assert device.key == key
    reply(device, {"t": "cmd", "opt": ["Pow"], "p": [17]})
    assert handler.handle(device, {"t": "hbok"}) == []
    monkeypatch.setattr("gree_emulator.profiles.catalog_esp_alarm.monotonic", lambda: 1184)
    assert status(device, ["Pow"])["dat"] == [17]
    assert handler.handle(device, {"t": "hbok"}) == []
    monkeypatch.setattr("gree_emulator.profiles.catalog_esp_alarm.monotonic", lambda: 1363.999)
    assert status(device, ["Pow"])["dat"] == [17]
    monkeypatch.setattr("gree_emulator.profiles.catalog_esp_alarm.monotonic", lambda: 1364)
    assert status(device, ["Pow"])["dat"] == [1]


def test_factory_reset_regenerates_synthetic_key_without_fake_ota_ack(device, monkeypatch):
    handler = device.profile.handler
    old_key = device.key
    reply(device, {"t": "cmd", "opt": ["Pow"], "p": [-3]})
    assert handler.handle(device, {"t": "reset", "delay": 0}) == []
    bound = reply(device, {"t": "bind"}, index=1, expected_index=1)
    assert bound["key"].encode() == device.key and device.key != old_key
    assert len(device.key) == 16
    assert status(device, ["Pow", "WorkState"])["dat"] == [1, 1]
    with pytest.raises(InvalidPacket):
        reply(device, {"t": "status", "cols": ["Pow"]}, key=old_key)
    before = deepcopy(device.state)
    for inner in ({"t": "upgrade", "url": "https://invalid.example/firmware.bin"},
                  {"t": "ota", "url": "https://invalid.example/firmware.bin"},
                  {"t": "tm", "time": "not-a-calendar"}, {"t": "restart", "delay": -1}):
        with pytest.raises(InvalidPacket):
            handler.handle(device, inner)
        assert device.state == before


async def test_actual_cli_plaintext_and_targeted_encrypted_admission(tmp_path):
    config = tmp_path / "alarm.json"
    config.write_text(json.dumps({"devices": [
        {"id": "first", "profile": "sim-mstwb801a-v1", "mid": "80260", "mac": "02000000a260"},
        {"id": "second", "profile": "sim-mstwb801a-v1", "mid": "80260", "mac": "02000000a261"},
    ]}))
    process = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "gree_emulator", "--config", str(config),
        "--listen", "127.0.0.1", "--port", "0",
        cwd=Path(__file__).resolve().parents[1],
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    address = None
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.settimeout(2)

    async def receive(key):
        raw = await asyncio.to_thread(peer.recv, 4096)
        assert not raw.endswith(b"\n")
        outer = json.loads(raw)
        assert outer["tcid"] == "app"
        return outer, json.loads(unpad(AES.new(key, AES.MODE_ECB).decrypt(
            base64.b64decode(outer["pack"])), 16))

    try:
        startup = await asyncio.wait_for(process.stdout.readline(), 10)
        assert startup.startswith(b"Listening on 127.0.0.1:")
        address = ("127.0.0.1", int(startup.split(b":")[-1]))
        announcements = [json.loads(await asyncio.wait_for(process.stdout.readline(), 5))
                         for _ in range(2)]
        assert {row["mid"] for row in announcements} == {"80260"}
        peer.sendto(b'{"t":"bind"}', address)
        bindings = [await receive(GENERIC_KEY) for _ in range(2)]
        keys = {inner["mac"]: inner["key"].encode() for _, inner in bindings}
        assert len(set(keys.values())) == 2
        peer.sendto(b'{"t":"cmd","opt":["Pow","AlarmTime"],"p":[7,"19minutes"]}', address)
        for _ in range(2):
            raw = await asyncio.to_thread(peer.recv, 4096)
            outer = json.loads(raw)
            inner = json.loads(unpad(AES.new(keys[outer["cid"]], AES.MODE_ECB).decrypt(
                base64.b64decode(outer["pack"])), 16))
            assert inner["p"] == ["7", "19minutes"] and "val" not in inner
        target = min(keys)
        command = b'{"t":"cmd","opt":["AlarmTime"],"p":["23minutes"]}'
        encrypted = base64.b64encode(AES.new(keys[target], AES.MODE_ECB).encrypt(
            pad(command, 16))).decode()
        peer.sendto(json.dumps({"t": "pack", "i": 0, "uid": -19, "tcid": target,
                                "pack": encrypted}).encode(), address)
        _, result = await receive(keys[target])
        assert result["p"] == ["23minutes"] and "val" not in result
        for mac in sorted(keys):
            raw = json.dumps({"t": "status", "cols": ["Pow", "AlarmTime"]}).encode()
            pack = base64.b64encode(AES.new(keys[mac], AES.MODE_ECB).encrypt(pad(raw, 16))).decode()
            peer.sendto(json.dumps({"t": "pack", "i": 0, "uid": -19,
                                    "tcid": mac, "pack": pack}).encode(), address)
            outer, inner = await receive(keys[mac])
            assert outer["uid"] == -19 and inner["dat"] == [7, 23 if mac == target else 19]
        # The shared server must bound original UDP bytes, not compacted JSON.
        peer.sendto(b" " * 1460 + b'{"t":"cmd","opt":["Pow"],"p":[1]}', address)
        peer.settimeout(0.15)
        with pytest.raises(socket.timeout):
            await asyncio.to_thread(peer.recv, 4096)
        peer.settimeout(2)
        peer.sendto(b'{"t":"status","cols":["Pow"]}', address)
        for _ in range(2):
            raw = await asyncio.to_thread(peer.recv, 4096)
            outer = json.loads(raw)
            inner = json.loads(unpad(AES.new(keys[outer["cid"]], AES.MODE_ECB).decrypt(
                base64.b64decode(outer["pack"])), 16))
            assert inner["dat"] == [7]
    finally:
        peer.close()
        if process.returncode is None:
            process.send_signal(signal.SIGINT)
        try:
            await asyncio.wait_for(process.wait(), 5)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
        stderr = await process.stderr.read()
        assert process.returncode == 0, stderr.decode(errors="replace")
        if address is not None:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reclaimed:
                reclaimed.bind(address)
