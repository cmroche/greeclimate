"""Independent corrected Z/BA probe values and declared synthetic IO policy."""

import asyncio
import base64
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.w05z import PROFILES
from gree_emulator.server import EmulatorServer
from gree_emulator.wire import InvalidPacket, encode_reply


FIXTURES = Path(__file__).parent / "fixtures" / "emulator"
VECTOR = json.loads((FIXTURES / "session-w05z.json").read_text())
QUIRKS = json.loads((FIXTURES / "session-w05z-quirks_research.json").read_text())
GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"


@pytest.fixture(params=PROFILES, ids=lambda profile: profile.id)
def device(request, monkeypatch):
    monkeypatch.setattr("gree_emulator.profiles.w05z.time.monotonic", lambda: 1000)
    profile = request.param
    return EmulatedDevice("socket", VECTOR["mac"], "", "80801", b"0123456789abcdef",
                          profile, deepcopy(dict(profile.initial_state)), room_c=None,
                          ambient_c=None, last_step=1000)


def packet(device, inner=None, *, index=0, key=None, plaintext=None):
    if plaintext is None:
        if inner.get("t") in ("bind", "status"):
            inner = {"mac": device.mac, **inner}
        plaintext = json.dumps(inner, separators=(",", ":")).encode()
    selected_key = key if key is not None else GENERIC_KEY if index else device.key
    ciphertext = AES.new(selected_key, AES.MODE_ECB).encrypt(pad(plaintext, 16))
    return {"t": "pack", "i": index, "uid": 42, "cid": "app", "tcid": device.mac,
            "pack": base64.b64encode(ciphertext).decode()}


def peer_reply(reply):
    raw = encode_reply(reply)
    assert raw.endswith(b"}\n") and not raw.endswith(b"\n\n")
    outer = json.loads(raw)
    ciphertext = base64.b64decode(outer.pop("pack"), validate=True)
    key = GENERIC_KEY if outer["i"] else b"0123456789abcdef"
    return outer, json.loads(unpad(AES.new(key, AES.MODE_ECB).decrypt(ciphertext), 16))


def exchange(device, inner, *, index=0):
    reply, = device.profile.handler.handle(device, packet(device, inner, index=index))
    outer, result = peer_reply(reply)
    assert outer == {"t": "pack", "i": 1 if inner["t"] == "bind" else 0,
                     "uid": 42, "cid": device.mac, "tcid": ""}
    return result


def command(device, names, values):
    return exchange(device, {"t": "cmd", "opt": names, "p": values})["p"]


def status(device, names):
    return exchange(device, {"t": "status", "cols": names})["dat"]


def test_source_discovery_and_exact_builds(device):
    reply, = device.profile.handler.advertise(device, {"t": "scan"})
    assert dict(zip(("outer", "inner"), peer_reply(reply))) == VECTOR["discovery"]
    assert status(device, ["hid"]) == [device.profile.hid]
    assert device.profile.handler.thermal_target(device) is None
    device.advance(100000)
    assert device.room_c is device.ambient_c is None
    assert status(device, ["TemSen", "BuzzerCtrl"]) == []


def test_corrected_native_width_cardinality_and_getter_vectors(device):
    for vector in QUIRKS["native_vectors"]:
        assert command(device, vector["opt"], vector["p"]) == vector["ack"]
        assert status(device, vector["cols"]) == vector["dat"]


def test_all_sixteen_selectors_and_metadata_scratch(device):
    names = QUIRKS["selectors"]
    reply = exchange(device, {"t": "status", "cols": names})
    assert reply["cols"] == names
    assert reply["dat"] == [0] * 9 + [[0] * 5, [0] * 5, device.profile.hid,
                                     "2026-01-01 00:00:00", 0, 0]
    assert command(device, ["hid", "time", "rssi", "StartTime", "EndTime"], [-1] * 5) == [
        device.profile.hid, "2026-01-01 00:00:00", 65535, 65535, 65535]
    assert status(device, ["hid", "time", "rssi", "StartTime", "EndTime"]) == [
        device.profile.hid, "2026-01-01 00:00:00", 0, [0] * 5, [0] * 5]
    device.state["_driver_signal"] = 73
    assert status(device, ["rssi"]) == [-73]


def test_overlapping_int32_windows_never_follow_command_scratch(device):
    device.state["_calendar_words"] = QUIRKS["calendar_backing"]
    expected = QUIRKS["calendar_windows"]
    assert status(device, ["StartTime", "EndTime"]) == expected
    assert command(device, ["StartTime", "EndTime"], [-1, 65537]) == [65535, 1]
    assert status(device, ["StartTime", "EndTime"]) == expected
    assert expected[0][3:] == expected[1][:2]


def test_meter_power_gating_and_raw_pow_callback(device):
    meters = ["RealTimeVoltage", "RealTimeEleCurrent", "RealTimePower"]
    assert command(device, meters, [-1, 65537, 42]) == [65535, 1, 42]
    for power, expected in [(0, [0, 0, 0]), (1, [65535, 1, 42]), (7, [0, 0, 0])]:
        assert command(device, ["Pow"], [power]) == [power]
        assert status(device, meters) == expected
    assert command(device, ["CountDownTime", "CountDownFlag", "Pow"], [2, 1, 7]) == [2, 1, 7]
    assert status(device, ["Pow", "CountDownFlag"]) == [7, 0]


def test_reset_accumulator_has_no_poll_value_and_does_not_invent_energy_conversion(device):
    device.state["_energy_accumulation"] = 123456
    command(device, ["EnergyOfTime", "EnergyOfTimeFlag"], [25, 2])
    assert command(device, ["Electnumzero", "Electnumzero"], [7, 1]) == [7, 0]
    assert device.state["_energy_accumulation"] == 0
    reply = exchange(device, {"t": "status", "cols": ["Electnumzero", "EnergyOfTime", "Electnumzero"]})
    assert reply["cols"] == ["Electnumzero", "EnergyOfTime", "Electnumzero"]
    assert reply["dat"] == [25]


def test_timer_minutes_rearm_and_expiry_state_distinction(device, monkeypatch):
    command(device, ["CountDownTime", "CountDownState", "CountDownFlag"], [2, 2, 1])
    monkeypatch.setattr("gree_emulator.profiles.w05z.time.monotonic", lambda: 1059)
    assert status(device, ["CountDownTime"]) == [2]
    monkeypatch.setattr("gree_emulator.profiles.w05z.time.monotonic", lambda: 1060)
    assert status(device, ["CountDownTime", "time"]) == [1, "2026-01-01 00:01:00"]
    command(device, ["CountDownFlag"], [1])
    assert device.state["_countdown_start"] == 60
    monkeypatch.setattr("gree_emulator.profiles.w05z.time.monotonic", lambda: 1120)
    assert status(device, ["CountDownFlag", "CountDownTime", "CountDownState", "Pow"]) == [0, 0, 2, 0]
    assert command(device, ["CountDownFlag"], [1]) == [1]
    assert device.state["Pow"] == 1  # Immediate state2 is ON; expiry state2 is OFF.
    assert device.state["CountDownState"] == 2


def test_late_ticks_wrap_and_only_flag_one_runs(device, monkeypatch):
    command(device, ["CountDownTime", "CountDownState", "CountDownFlag"], [2, 1, 1])
    monkeypatch.setattr("gree_emulator.profiles.w05z.time.monotonic", lambda: 1180)
    assert status(device, ["CountDownTime", "CountDownFlag", "Pow"]) == [65535, 0, 1]
    monkeypatch.setattr("gree_emulator.profiles.w05z.time.monotonic", lambda: 1240)
    assert status(device, ["CountDownTime"]) == [65535]
    command(device, ["CountDownFlag"], [2])
    monkeypatch.setattr("gree_emulator.profiles.w05z.time.monotonic", lambda: 1300)
    assert status(device, ["CountDownTime", "CountDownFlag"]) == [65535, 2]


def test_timer_uint32_wrap_and_writes_do_not_rearm(device, monkeypatch):
    command(device, ["CountDownTime", "CountDownFlag"], [2, 1])
    device.state["_countdown_start"] = 0xfffffff0
    monkeypatch.setattr("gree_emulator.profiles.w05z.time.monotonic", lambda: 1044)
    assert status(device, ["CountDownTime"]) == [1]  # wrapped elapsed60
    monkeypatch.setattr("gree_emulator.profiles.w05z.time.monotonic", lambda: 1045)
    command(device, ["CountDownTime", "CountDownState"], [7, 2])
    assert device.state["_countdown_start"] == 0xfffffff0
    assert device.state["_countdown_seconds"] == 120
    command(device, ["CountDownFlag"], [0])
    assert device.state["CountDownTime"] == 7
    assert device.state["_countdown_seconds"] == 120


@pytest.mark.parametrize("index", [0, 1, -1, 2, -(2**31), 2**31 - 1])
def test_request_key_selector_is_not_reply_key_or_authorization(device, index):
    assert exchange(device, {"t": "bind", "mac": device.mac}, index=index)["t"] == "bindok"
    assert exchange(device, {"t": "status", "cols": ["Pow"]}, index=index)["dat"] == [0]
    assert exchange(device, {"t": "cmd", "opt": ["Pow"], "p": [7]}, index=index)["p"] == [7]


@pytest.mark.parametrize("inner", [
    {"t": "status", "cols": "Pow"}, {"t": "status", "cols": [None]},
    {"t": "status", "cols": [""]}, {"t": "status", "cols": ["Pow\0"]},
    {"t": "cmd", "opt": ["Pow", "CountDownTime"], "p": [1, True]},
    {"t": "cmd", "opt": ["Pow", "unknown"], "p": [1, "bad"]},
    {"t": "cmd", "opt": ["Pow"], "p": [2**31]},
    {"t": "cmd", "opt": ["Pow"], "p": [-(2**31) - 1]},
    {"t": "cmd", "opt": ["Pow"], "p": [1.5]},
    {"t": "cmd", "opt": ["Pow"], "p": []},
    {"t": "cmd", "opt": ["Pow"], "p": [1, 2]},
    {"t": "cmd", "opt": ["CountDownFlag"] * 60, "p": [0] * 60},
    {"t": "status", "cols": ["StartTime"] * 60},
    {"t": "cmd", "opt": ["hid"] * 30, "p": [0] * 30},
    {"t": "status", "cols": ["hid"] * 30},
])
def test_full_preflight_is_atomic_including_expired_timer_and_uid(device, inner, monkeypatch):
    command(device, ["CountDownTime", "CountDownFlag"], [2, 1])
    before = deepcopy(device.state)
    monkeypatch.setattr("gree_emulator.profiles.w05z.time.monotonic", lambda: 1180)
    with pytest.raises(InvalidPacket):
        device.profile.handler.handle(device, {**packet(device, inner), "uid": 99})
    assert device.state == before


@pytest.mark.parametrize("changes", [{"i": True}, {"i": "0"}, {"i": 2**31},
                                     {"cid": None}, {"pack": "!"}, {"tcid": "wrong"}])
def test_bad_routes_keys_and_envelopes_do_not_mutate(device, changes):
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        device.profile.handler.handle(device, {**packet(device, {"t": "status", "cols": ["Pow"]}), **changes})
    assert device.state == before
    with pytest.raises(InvalidPacket):
        device.profile.handler.handle(device, packet(device, {"t": "status", "cols": ["Pow"]}, key=b"fedcba9876543210"))


def test_uid_retention_and_per_device_state(device):
    command(device, ["Pow"], [7])
    other = EmulatedDevice("other", "020000000002", "", "80801", device.key,
                           device.profile, deepcopy(dict(device.profile.initial_state)))
    for target, expected in [(device, 42), (other, 0)]:
        reply, = target.profile.handler.advertise(target, {"t": "scan"})
        assert peer_reply(reply)[0]["uid"] == expected
    request = {**packet(device, {"t": "status", "cols": ["Pow"]}), "uid": "nonnumeric"}
    reply, = device.profile.handler.handle(device, request)
    assert peer_reply(reply)[0]["uid"] == 42
    assert other.state["Pow"] == 0


@pytest.mark.parametrize("plaintext", [b'{"t":"cmd","t":"bind"}', b'{"t":"status"}\0',
                                       b'{"t":"status"}garbage', b'[]', b'{"t":NaN}'])
def test_strict_json_parser_deviations(device, plaintext):
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        device.profile.handler.handle(device, packet(device, plaintext=plaintext))
    assert device.state == before


@pytest.mark.parametrize("state", [{"TemSen": 40}, {"hid": "spoof"}, {"Pow": True},
                                   {"CountDownTime": -1}, {"CountDownTime": 65536}])
def test_configured_state_is_only_uint16_scratch(device, state):
    with pytest.raises(ValueError):
        device.profile.handler.validate_state(state)


def test_native_receive_limit_uses_original_bytes(device):
    async def scenario():
        server = EmulatorServer([device])
        sent = []
        server.transport = SimpleNamespace(sendto=lambda data, addr: sent.append((data, addr)))
        raw = json.dumps(packet(device, {"t": "cmd", "opt": ["Pow"], "p": [1]})).encode()
        server.datagram_received(raw + b" " * (1025 - len(raw)), ("127.0.0.1", 12345))
        assert not sent and device.state["Pow"] == 0
        server.datagram_received(raw + b" " * (1024 - len(raw)), ("127.0.0.1", 12345))
        assert len(sent) == 1 and device.state["Pow"] == 1
    asyncio.run(scenario())
