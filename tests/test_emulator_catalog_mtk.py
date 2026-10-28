"""Literal native byte semantics plus declared atomic synthetic board policy."""
import base64
from copy import deepcopy
import json
from pathlib import Path

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.catalog_mtk import GENERIC_KEY, PROFILES, MediaTek
from gree_emulator.wire import InvalidPacket, encode_reply

VECTORS = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-mtk-vectors_research.json").read_text())


@pytest.fixture(params=tuple(profile for profile in PROFILES if type(profile.handler) is MediaTek),
                ids=lambda profile: profile.id)
def device(request, monkeypatch):
    monkeypatch.setattr("gree_emulator.profiles.catalog_mtk.monotonic", lambda: 1000)
    profile = request.param
    return EmulatedDevice("raw", VECTORS["mac"], "board", "10001", VECTORS["key"].encode(),
                          profile, dict(profile.initial_state), last_step=1000)


def packet(device, inner, *, index=0, key=None, uid=37):
    plain = json.dumps(inner, separators=(",", ":")).encode()
    selected = key if key is not None else GENERIC_KEY if index else device.key
    return {"t": "pack", "i": index, "uid": uid, "cid": "raw-peer", "tcid": device.mac,
            "pack": base64.b64encode(AES.new(selected, AES.MODE_ECB).encrypt(pad(plain, 16))).decode()}


def reply(device, inner, **kwargs):
    result, = device.profile.handler.handle(device, packet(device, inner, **kwargs))
    wire = encode_reply(result)
    assert not wire.endswith(b"\n")
    outer = json.loads(wire)
    selected = GENERIC_KEY if outer["i"] else device.key
    decoded = json.loads(unpad(AES.new(selected, AES.MODE_ECB).decrypt(base64.b64decode(outer["pack"])), 16))
    assert {key: value for key, value in outer.items() if key != "pack"} == {
        "t": "pack", "i": kwargs.get("index", 0), "uid": kwargs.get("uid", 37),
        "cid": device.mac, "tcid": "raw-peer"}
    return decoded


def status(device, names):
    return reply(device, {"t": "status", "cols": names})


def command(device, names, values):
    return reply(device, {"t": "cmd", "opt": names, "p": values})


def test_scan_bind_fixed_build_hid_and_requested_mid(device):
    result, = device.profile.handler.advertise(device, {"t": "scan"})
    outer = json.loads(encode_reply(result))
    scan = json.loads(unpad(AES.new(GENERIC_KEY, AES.MODE_ECB).decrypt(base64.b64decode(outer["pack"])), 16))
    assert scan["cid"] == ""
    assert scan["mac"] == device.mac
    assert scan["mid"] == "10001"
    assert "hid" not in scan
    assert reply(device, {"t": "bind", "mac": device.mac}, index=1) == {
        "r": 200, "t": "bindok", "mac": device.mac, "key": VECTORS["key"]}
    assert status(device, ["hid", "mid"])["dat"] == [device.profile.hid, "10001"]


def test_raw_masks_noninverse_getters_and_fresh_status(device):
    for vector in VECTORS["native_callback_vectors"]:
        command(device, vector["opt"], vector["p"])
        result = status(device, vector["cols"])
        assert result["cols"] == vector["cols"]
        assert result["dat"] == vector["dat"]


def test_real_temperature_encoding_and_humidity_are_distinct_raw_fields(device):
    handler = device.profile.handler
    cache = handler._cache(device)
    offset = handler.getters["TemSen"][2][0]
    for raw, expected in VECTORS["sensor_vectors"]:
        cache[offset] = raw
        assert handler._read(cache, "TemSen") == expected
    result = status(device, ["HumSen", "DwatSen", "TemSen", "HumSen"])
    assert result["cols"] == ["HumSen", "TemSen", "HumSen"]
    assert result["dat"] == [0, 26, 0]


def test_late_buzzer_steady_heat_and_packed_sleep_fields(device):
    late = device.profile.id == "sim-cs532bh-v5"
    result = status(device, ["Buzzer_ON_OFF", "SmartSlpModEx", "StHt"])
    assert result["cols"] == (["Buzzer_ON_OFF", "SmartSlpModEx", "StHt"] if late else ["StHt"])
    if late:
        vector = VECTORS["late_only"]
        command(device, vector["opt"], vector["p"])
        assert status(device, vector["cols"])["dat"] == vector["dat"]
    else:
        assert command(device, ["StHt"], [1])["val"] == [0]
        assert status(device, ["StHt"])["dat"] == [0]


def test_duplicate_order_and_safe_atomic_batch(device):
    result = command(device, ["Pow", "Pow", "SetTem"], [1, 0, 40])
    assert result["p"] == result["val"] == [0, 0, 24]
    assert status(device, ["SetTem", "Pow", "SetTem"])["dat"] == [24, 0, 24]
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        command(device, ["Pow", "unknown"], [1, 7])
    assert device.state == before
    with pytest.raises(InvalidPacket):
        command(device, ["Pow", "Air"], [1, True])
    assert device.state == before


def test_wrong_keys_targets_and_malformed_recovery(device):
    for outer in [packet(device, {"t": "status", "cols": ["Pow"]}, key=b"wrongkeywrongkey"),
                  {**packet(device, {"t": "bind"}), "tcid": "02000000c002"},
                  packet(device, {"t": "cmd", "opt": ["Pow"], "p": []}),
                  packet(device, {"t": "status", "cols": ["Pow"] * 65})]:
        with pytest.raises(InvalidPacket):
            device.profile.handler.handle(device, outer)
    assert status(device, ["Pow"])["dat"] == [0]


def test_raw_only_mid_has_no_invented_ac_physics_and_cache_isolation(device):
    first = device
    second = EmulatedDevice("second", "02000000c002", "other", "13800", first.key,
                            first.profile, dict(first.profile.initial_state), last_step=1000)
    command(first, ["Pow", "SetTem"], [1, 21])
    assert status(second, ["Pow", "SetTem"])["dat"] == [0, 24]
    assert second.profile.handler.thermal_target(second) is None
    restarted = EmulatedDevice("raw", first.mac, "board", first.mid, first.key,
                              first.profile, dict(first.profile.initial_state), last_step=1000)
    assert status(restarted, ["Pow", "SetTem"])["dat"] == [0, 24]


def test_build_specific_non_ac_fields_are_not_silently_dropped(device):
    names = sorted(device.profile.handler.fields)
    cols = []
    for index in range(0, len(names), 32):
        cols.extend(status(device, names[index:index+32])["cols"])
    assert cols == names
    result = status(device, ["MOta", "not-a-property", "hid"])
    assert result["cols"] == ["MOta", "hid"]
    assert result["dat"] == [device.profile.hid]


def test_calendar_synthetic_temperature_direction_and_private_fields(device, monkeypatch):
    assert status(device, ["time"])["dat"] == ["2026-01-01 00:00:00"]
    command(device, ["Pow", "Mod", "SetTem"], [1, 1, 20])
    device.advance(1060)
    assert status(device, ["TemSen", "time"])["dat"] == [25, "2026-01-01 00:01:00"]
    monkeypatch.setattr("gree_emulator.profiles.catalog_mtk.monotonic", lambda: 1120)
    command(device, ["SetTem"], [30])
    assert device.room_c == 24
    assert status(device, ["TemSen", "SetTem"])["dat"] == [24, 30]
    assert status(device, ["_clock_origin", "_board", "_metadata"])["dat"] == []
