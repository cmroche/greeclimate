"""Exact older voice namespace and explicit safe synthetic cache behavior."""

import base64
import json
from pathlib import Path

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles import PROFILES
from gree_emulator.wire import InvalidPacket, encode_reply


VECTOR = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-othermcu-voice368-vectors_research.json").read_text())
GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"


def device_for(monkeypatch):
    monkeypatch.setattr("gree_emulator.profiles.voice.time.monotonic", lambda: 1000)
    profile = PROFILES[VECTOR["profile"]]
    return EmulatedDevice("voice368", VECTOR["mac"], "voice368", VECTOR["mid"],
                          VECTOR["key"].encode(), profile, dict(profile.initial_state),
                          room_c=None, ambient_c=None, last_step=1000)


def unpack(reply, key):
    raw = encode_reply(reply)
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    outer = json.loads(raw)
    ciphertext = base64.b64decode(outer.pop("pack"), validate=True)
    return outer, json.loads(unpad(AES.new(key, AES.MODE_ECB).decrypt(ciphertext), 16))


def exchange(device, inner, index=0):
    key = GENERIC_KEY if index else device.key
    ciphertext = AES.new(key, AES.MODE_ECB).encrypt(pad(json.dumps(inner, separators=(",", ":")).encode(), 16))
    outer = {"t": "pack", "i": index, "uid": -7, "cid": "app", "tcid": device.mac,
             "pack": base64.b64encode(ciphertext).decode()}
    reply, = device.profile.handler.handle(device, outer)
    envelope, result = unpack(reply, key)
    assert envelope == {"t": "pack", "i": index, "uid": -7, "cid": device.mac, "tcid": ""}
    return result


def test_older_voice_discovery_bind_and_every_source_getter(monkeypatch):
    device = device_for(monkeypatch)
    reply, = device.profile.handler.advertise(device, {"t": "scan"})
    _, advertisement = unpack(reply, GENERIC_KEY)
    assert advertisement == VECTOR["advertisement"]
    assert exchange(device, {"t": "bind", "mac": device.mac}, 1) == {
        "t": "bindok", "mac": device.mac, "r": 200, "key": VECTOR["key"]}
    names = list(VECTOR["initial_getters"])
    for start in range(0, len(names), 5):
        selected = names[start:start + 5]
        result = exchange(device, {"t": "status", "mac": device.mac, "cols": selected})
        assert result == {"t": "dat", "mac": device.mac, "r": 200, "cols": selected,
                          "dat": [value for name in selected for value in VECTOR["initial_getters"][name]]}
    assert device.room_c is device.ambient_c is None


def test_older_voice_requested_ack_and_independent_fresh_status(monkeypatch):
    device = device_for(monkeypatch)
    for vector in VECTOR["commands"]:
        result = exchange(device, {"t": "cmd", "opt": vector["opt"], "p": vector["p"]})
        assert result == {"t": "res", "mac": device.mac, "r": 200,
                          "opt": vector["opt"], "p": vector["expected_ack_p"]}
        result = exchange(device, {"t": "status", "mac": device.mac, "cols": vector["fresh_cols"]})
        assert result["dat"] == vector["fresh_dat"]
    other = device_for(monkeypatch)
    assert exchange(other, {"t": "status", "mac": other.mac, "cols": ["Pow", "SetTem"]})["dat"] == [0, 26]


@pytest.mark.parametrize("values", [[1], [1, True], [1, None], [1, 1.5]])
def test_older_voice_safe_atomic_rejection_then_recovery(monkeypatch, values):
    device = device_for(monkeypatch)
    before = dict(device.state)
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "cmd", "opt": ["Pow", "Mod"], "p": values})
    assert device.state == before
    assert exchange(device, {"t": "cmd", "opt": ["Pow"], "p": [1]})["p"] == [1]
    assert exchange(device, {"t": "status", "mac": device.mac, "cols": ["Pow", "hid"]})["dat"] == [1, VECTOR["hid"]]


@pytest.mark.parametrize("name", list(VECTOR["initial_getters"]))
def test_voice368_every_selector_has_source_specific_command_and_fresh_getter(monkeypatch, name):
    device = device_for(monkeypatch)
    value = "2024-02-29 23:59:59" if name == "time" else -1
    result = exchange(device, {"t": "cmd", "opt": [name], "p": [value]})
    assert result["opt"] == [name]
    if name in (
        "Pow", "Mod", "SwhSlp", "SwhSw", "WdSpd", "SetTem", "Blo", "Health",
        "Lig", "TemUn", "TemRec", "Air", "SwUpDn", "SwingLfRig", "SvSt", "StHt",
        "Intellblo1", "AirOpen", "SlpMod", "Tur", "Quiet", "VoltErr", "CurrErr",
        "PowerErr", "RelayErr",
    ):
        expected = [65535]
    elif name in ("ProTimePow", "ProTimeLen", "ProTimeReminder", "SendButton", "Studied"):
        expected = [-1]
    elif name == "DelButton":
        expected = [26]
    elif name == "hid":
        expected = [VECTOR["hid"]]
    elif name == "time":
        expected = [value]
    else:
        expected = []
    assert result["p"] == expected
    fresh = exchange(device, {"t": "status", "mac": device.mac, "cols": [name, name]})
    assert fresh["cols"] == [name, name]
    if name in ("Quiet", "Tur", "AddButton", "VoiceGate", "RealTimePower"):
        stored = [0]
    elif name == "SwhSw":
        stored = [0]
    elif name == "RefBtnList":
        stored = [[], []]
    elif name == "hid":
        stored = [VECTOR["hid"]]
    elif name == "time":
        stored = [value]
    else:
        stored = [65535]
    assert fresh["dat"] == stored * 2


@pytest.mark.parametrize(("power", "expected"), [
    (-1.25, 0), (0.99, 0), (123.75, 123), (16777217, 16777216),
    (4294967296, 4294967295),
])
def test_voice368_original_unsigned_float32_energy_getter(monkeypatch, power, expected):
    device = device_for(monkeypatch)
    device.profile.handler.validate_state({"_power": power})
    device.state["_power"] = power
    result = exchange(device, {"t": "status", "mac": device.mac,
                               "cols": ["RealTimePower", "RealTimePower"]})
    assert result["dat"] == [expected, expected]


@pytest.mark.parametrize(("power", "active", "ticks", "reminder", "expected"), [
    (4, 1, 3599, 0, (0, 0, 0)),
    (5, 0, 3599, 0, (0, 0, 0)),
    (5, 1, 3599, 0, (1, 1, 0)),
    (6, 0, 3599, 0, (1, 1, 0)),
    (4, 1, 17, 1, (0, 1, 17)),
    (5, 1, 17, 1, (1, 1, 17)),
    (6, 1, 17, 2, (2, 1, 17)),
])
def test_voice368_guard_original_threshold_and_reminder_branches(
        monkeypatch, power, active, ticks, reminder, expected):
    device = device_for(monkeypatch)
    now = [1000.0]
    monkeypatch.setattr("gree_emulator.profiles.voice.time.monotonic", lambda: now[0])
    exchange(device, {"t": "status", "mac": device.mac, "cols": []})
    device.state.update(ProTimePow=1, ProTimeLen=1, ProTimeReminder=reminder,
                        _power=power, _guard_active=active, _guard_ticks=ticks)
    now[0] += 1
    result = exchange(device, {"t": "status", "mac": device.mac, "cols": ["ProTimeReminder"]})
    assert (result["dat"][0], device.state["_guard_active"],
            device.state["_guard_ticks"]) == expected


def test_voice368_ir_audio_guard_order_and_clock_are_per_device(monkeypatch):
    device = device_for(monkeypatch)
    exchange(device, {"t": "cmd", "opt": ["AddButton"], "p": [28]})
    assert device.state["_ir_state"] == 5
    assert exchange(device, {"t": "cmd", "opt": ["Studied"], "p": [2]})["p"] == [2]
    assert exchange(device, {"t": "cmd", "opt": ["DelButton"], "p": [[1, -1]]})["p"] == [26]
    assert exchange(device, {"t": "status", "mac": device.mac,
                             "cols": ["Studied", "AddButton", "RefBtnList"]})["dat"] == [0, 0, [], []]
    assert exchange(device, {"t": "cmd", "opt": ["VoiceGate", "Unknown"],
                             "p": [-1, 0]})["p"] == [-1]
    assert exchange(device, {"t": "cmd", "opt": ["VoiceVolume", "Unknown"],
                             "p": [65537, 0]})["p"] == [65537]
    assert device.state["_audio_count"] == 0
    assert (device.state["_saved_gate"], device.state["_saved_volume"]) == (65535, 1)
    assert exchange(device, {"t": "cmd", "opt": ["VoiceVolume"], "p": [9]})["p"] == []
    device.state.update(Tur=300, Quiet=18)
    exchange(device, {"t": "cmd", "opt": ["ACCntlrShape", "ProTimePow"], "p": [7, 1]})
    assert (device.state["Tur"], device.state["Quiet"]) == (300, 18)
    exchange(device, {"t": "cmd", "opt": ["ProTimePow", "ACCntlrShape"], "p": [1, 7]})
    assert (device.state["Tur"], device.state["Quiet"]) == (0, 0)
    exchange(device, {"t": "cmd", "opt": ["time"], "p": ["2024-02-29 23:59:59"]})
    other = device_for(monkeypatch)
    assert exchange(other, {"t": "status", "mac": other.mac,
                            "cols": ["VoiceGate", "ProTimePow", "time"]})["dat"] == [
                                0, 0, "1970-01-01 00:00:00"]


def test_voice368_ir_total_count_boundary_keeps_general_cache_without_action_ack(monkeypatch):
    device = device_for(monkeypatch)
    names = ["AddButton"] + ["Pow"] * 44
    result = exchange(device, {"t": "cmd", "opt": names, "p": [28] + [0] * 44})
    assert result["opt"] == names and result["p"] == [0] * 44
    assert "_ir_state" not in device.state
    assert exchange(device, {"t": "status", "mac": device.mac,
                             "cols": ["AddButton", "RefBtnList"]})["dat"] == [28, [], []]
    assert exchange(device, {"t": "cmd", "opt": ["AddButton"], "p": [28]})["p"] == [26]
    assert device.state["_ir_state"] == 5
    assert exchange(device, {"t": "status", "mac": device.mac,
                             "cols": ["AddButton"]})["dat"] == [0]
