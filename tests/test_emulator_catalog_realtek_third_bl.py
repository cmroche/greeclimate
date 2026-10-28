"""Literal original callback vectors and bounded synthetic BL wire behavior."""
import base64
from copy import deepcopy
import json
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.catalog_realtek_third_bl import BlCache, JdrCache, PROFILES, SPEECH_KEY
from gree_emulator.wire import InvalidPacket, encode_reply

FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/catalog_realtek_third_bl_research.json").read_text())
KEY = b"a3K8Bx%2r8Y7#xDh"


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch):
    monkeypatch.setattr("gree_emulator.profiles.catalog_realtek_third_bl.monotonic", lambda: 1000)


def device(version=13, preset="controller"):
    if version == 3:
        preset = "heater"
    profile = next(profile for profile in PROFILES
                   if profile.handler.version == version and profile.handler.preset == preset)
    return EmulatedDevice("bl", FIXTURE["mac"], "", profile.mids[0],
                          FIXTURE["session_key"].encode(), profile, {},
                          room_c=None, ambient_c=None, last_step=1000)


def packet(unit, inner, *, index=0, uid=42, key=None):
    if key is None:
        key = SPEECH_KEY if unit.profile.handler.jdr and index == 3 else KEY if index else unit.key
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(json.dumps(inner, separators=(",", ":")).encode(), 16))
    return {"t": "pack", "i": index, "uid": uid, "cid": "app", "tcid": unit.mac,
            "pack": base64.b64encode(encrypted).decode()}


def exchange(unit, inner, **kwargs):
    reply, = unit.profile.handler.handle(unit, packet(unit, inner, **kwargs))
    raw = encode_reply(reply)
    outer = json.loads(raw)
    key = SPEECH_KEY if unit.profile.handler.jdr and outer["i"] == 3 else KEY if outer["i"] else unit.key
    plain = unpad(AES.new(key, AES.MODE_ECB).decrypt(base64.b64decode(outer["pack"])), 16)
    assert not raw.endswith(b"\n") and not plain.endswith(b"\n")
    assert outer["cid"] == unit.mac and outer["tcid"] == "app"
    return outer, json.loads(plain)


@pytest.mark.parametrize("row", FIXTURE["sources"], ids=lambda row: str(row["version"]))
def test_all_original_successful_callback_mutations_and_numeric_returns(row):
    handler = BlCache(row["version"])
    for vector in row["native_callback_vectors"]:
        cache = bytearray(0x600)
        handler.set(cache, vector["name"], vector["input"])
        assert [{"offset": i, "before": 0, "after": byte} for i, byte in enumerate(cache) if byte] == vector["cache_changes"], vector
        if vector["getter"] is not None:
            assert handler.get(cache, vector["name"], cloud=0) == vector["getter"], vector


@pytest.mark.parametrize("row", FIXTURE["sources"], ids=lambda row: str(row["version"]))
def test_every_declared_readout_including_previously_uninitialized_fields(row):
    handler = BlCache(row["version"])
    for vector in row["baseline_getters"]:
        assert handler.get(bytes(0x600), vector["name"]) == vector["expected"], vector
    assert len(row["baseline_getters"]) == 136
    assert row["native_faults"]  # Faults remain evidence; they are not synthetic success.


@pytest.mark.parametrize("version", [13, 11, 3])
def test_literal_wire_command_then_fresh_status(version):
    unit = device(version)
    for vector in FIXTURE["wire_vectors"]:
        if vector["version"] == version:
            outer, response = exchange(unit, vector["request"])
            assert response == vector["response"]
            assert outer["uid"] == 42 and outer["i"] == 0
    assert unit.room_c is None and unit.profile.handler.thermal_target(unit) is None


def test_jdr_every_numeric_getter_and_distinct_non_lan_alias_schema():
    handler = JdrCache()
    row = FIXTURE["jdr_baseline"]
    assert [handler.get(bytes(0x600), name) for name in row["columns"]] == row["values"]
    joylink = handler.joylink_readouts(bytes(0x600))
    assert joylink["CurrentTemperature"] == -100
    assert joylink["CurrentHotWater"] == 6 and joylink["State"] == 3
    assert joylink["TemperatureSet"] == 0
    cache = bytearray([255])*0x600
    assert handler.get(cache, "CurrentTemperature") == 255
    assert handler.joylink_readouts(cache)["CurrentTemperature"] == 155
    assert handler.joylink_readouts(cache)["BackwaterState"] == 2


def test_distinct_sensor_encodings_and_explicit_cloud_input():
    cache = bytearray(0x600)
    cache[0x180] = cache[0x18f] = 62
    assert BlCache(13).get(cache, "TemSen", cloud=9) == 62
    assert BlCache(13).get(cache, "TemSen", cloud=0) == 22
    assert BlCache(11).get(cache, "TemSen", cloud=9) == 22
    cache[0x25], cache[0x33] = 2, 7
    assert BlCache(13).get(cache, "WdSpd", "13000") == 3
    assert BlCache(13).get(cache, "WdSpd", "11000") == 7
    assert BlCache(11).get(cache, "WdSpd", "13000") == 7


def test_synthetic_platform_timer_selector_preserves_no_flash_boundary():
    handler, cache = BlCache(13), bytearray(0x600)
    handler.set(cache, "NewTimerSet", 255)
    assert cache[0x56f] == 255 and cache[0x49] == 2
    assert handler.get(cache, "NewTimerSet") == 0


def test_every_source_profile_field_can_be_read_without_mainboard_calibration():
    for profile in PROFILES:
        unit = device(profile.handler.version, profile.handler.preset)
        for name in profile.handler.fields:
            _, response = exchange(unit, {"t": "status", "cols": [name]})
            assert response["cols"] == [name] and len(response["dat"]) == 1
            assert type(response["dat"][0]) is int
        assert unit.profile.source_sha256 == profile.source_sha256


@pytest.mark.parametrize("version", [13, 11, 3])
def test_bind_rebind_identity_metadata_and_safe_key_selectors(version):
    unit = device(version)
    advert, = unit.profile.handler.advertise(unit, {"t": "scan"})
    assert advert.outer == {"t": "pack", "i": 1, "uid": 0, "cid": "", "tcid": ""}
    assert advert.inner["mid"] == unit.mid
    exchange(unit, {"t": "cmd", "opt": ["Pow"], "p": [1]})
    outer, result = exchange(unit, {"t": "bind", "mac": unit.mac}, index=1)
    assert outer["i"] == 1 and result == {"r": 200, "t": "bindok", "mac": unit.mac,
                                         "key": FIXTURE["session_key"]}
    _, fresh = exchange(unit, {"t": "status", "cols": ["Pow", "hid", "mid", "MOta"]})
    assert fresh["dat"] == [1, unit.profile.hid, unit.mid]
    assert fresh["cols"] == ["Pow", "hid", "mid", "MOta"]
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "status", "cols": ["Pow"]}, index=2)
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "status", "cols": ["Pow"]}, key=b"fedcba9876543210")


def test_sn_subdev_is_a_shared_cache_alias_not_an_independent_gateway_child():
    unit = device()
    _, listing = exchange(unit, {"t": "subDev", "i": 0})
    assert listing == {"r": 200, "t": "subList", "i": 0, "list": [
        {"mac": unit.mac+"01", "mid": unit.mid+"01", "name": "GreeHot", "model": "gree", "lock": 0}], "c": 1}
    _, empty = exchange(unit, {"t": "subDev", "i": 1})
    assert empty["list"] == [] and empty["c"] == 1
    exchange(unit, {"t": "cmd", "sub": unit.mac+"01", "opt": ["Pow"], "p": [1]})
    _, fresh = exchange(unit, {"t": "status", "cols": ["Pow"]})
    assert fresh["dat"] == [1]
    other = device()
    _, fresh = exchange(other, {"t": "status", "cols": ["Pow"]})
    assert fresh["dat"] == [0]


@pytest.mark.parametrize("bad", [None, True, 1.0, "1", [], {}, 1 << 31, -(1 << 31)-1])
def test_strict_atomic_commands_and_recovery(bad):
    unit = device()
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "cmd", "opt": ["Pow", "WdSpd"], "p": [1, bad]})
    assert unit.state == before and unit.last_step == 1000
    _, fresh = exchange(unit, {"t": "status", "cols": ["Pow"]})
    assert fresh["dat"] == [0]


def test_duplicates_readonly_unknown_metadata_and_explicit_timer_storage():
    unit = device()
    _, reply = exchange(unit, {"t": "cmd", "opt": ["Pow", "Pow", "AirQ", "missing"], "p": [1, 0, 9, 7]})
    assert reply["p"] == [1, 0, 9] and reply["val"] == [0, 0, 0]
    _, reply = exchange(unit, {"t": "cmd", "opt": ["Pow", "name"], "p": [1, "lab"]})
    assert reply["opt"] == ["name", "Pow"] and reply["p"] == ["lab", 1]
    exchange(unit, {"t": "cmd", "opt": ["time"], "p": ["2026-10-24 06:59:59"]})
    timer = {"t": "setT", "id": 1, "name": "timer", "enable": 0, "hr": 7,
             "min": 0, "sec": 0, "tz": 0, "week": [0]*7,
             "cmd": [{"mac": [unit.mac], "opt": ["Pow"], "p": [1]}]}
    _, reply = exchange(unit, timer)
    assert reply == {"t": "resT", "r": 200}
    _, reply = exchange(unit, {"t": "queryT", "index": 0, "count": 0})
    assert reply["total"] == 0 and reply["list"][0]["id"] == 1
    exchange(unit, {"t": "cmd", "opt": ["time"], "p": ["2026-10-24 07:00:01"]})
    _, fresh = exchange(unit, {"t": "status", "cols": ["Pow", "AppTimer"]})
    assert fresh["dat"] == [1, 0]
    _, fired = exchange(unit, {"t": "queryT", "index": 0, "count": 1})
    assert fired["list"][0]["enable"] == 1
    _, reply = exchange(unit, {"t": "dump"})
    assert reply == {"t": "res", "mac": unit.mac, "r": 200}


def test_request_name_bound_and_unsupported_upgrade_do_not_mutate():
    unit = device()
    for inner in ({"t": "status", "cols": ["Pow"]*65},
                  {"t": "status", "cols": ["x"*511, "y"]},
                  {"t": "cmd", "opt": ["Pow"], "p": []}):
        with pytest.raises(InvalidPacket):
            exchange(unit, inner)
    before = deepcopy(unit.state)
    assert unit.profile.handler.handle(unit, packet(unit, {"t": "upgrade", "url": "http://invalid/"})) == []
    assert unit.state == before


def test_all_initialized_original_sensor_inputs_and_jdr_serializers():
    for source in FIXTURE["native_readouts"]:
        handler = BlCache(source["version"])
        for vector in source["vectors"]:
            cache = bytes([vector["fill"]])*0x600
            assert [handler.get(cache, name, vector["mid"], vector["cloud"])
                    for name in source["columns"]] == vector["values"], vector
    handler = JdrCache()
    for vector in FIXTURE["jdr_native_serializers"]:
        cache = bytes([vector["fill"]])*0x600
        expected = vector["expected"]
        actual = (handler.joylink_readouts(cache) if vector["dialect"] == "joylink"
                  else {name: handler.get(cache, name) for name in expected})
        assert actual == expected


@pytest.mark.parametrize("row", FIXTURE["surver_native"], ids=lambda row: str(row["version"]))
def test_surver_native_non_json_inner_and_complete_outer(row):
    unit = device(row["version"])
    exchange(unit, {"t": "cmd", "opt": ["time"], "p": ["2026-10-24 00:00:00"]})
    reply, = unit.profile.handler.handle(unit, packet(unit, {"t": "surver"}))
    raw = encode_reply(reply)
    assert raw == reply.raw_payload == row["outer_ascii"].encode() and not raw.endswith(b"\n")
    outer = json.loads(raw)
    assert outer["i"] == 1 and outer["uid"] == 42
    assert outer["cid"] == unit.mac and outer["tcid"] == "app"
    inner = unpad(AES.new(KEY, AES.MODE_ECB).decrypt(base64.b64decode(outer["pack"])), 16)
    assert inner == row["inner_ascii"].encode()
    binary = base64.b64decode(inner[2:-1], validate=True)
    assert binary.hex() == row["header_hex"] and len(binary) == 39


def test_jdr_complete_native_token_lifecycle_and_synthetic_storage():
    unit = device(3)
    for row in FIXTURE["jdr_auxiliary"]:
        kind = row["request"]["t"]
        if not row["response"] or kind in ("rtoken", "newDev"):
            continue
        outer, response = exchange(unit, row["request"], index=3)
        assert outer["i"] == 3 and response == row["response"]
    assert unit.state["_bl"]["token"] == "synthetic-token"
    assert unit.state["_bl"]["vocmac"] == "020000000002"
    assert unit.state["_bl"]["speech_seen"] == 0 and unit.state["_bl"]["speech_peer"] == "app"
    assert unit.profile.handler.handle(unit, packet(unit, {"t": "rtoken"}, index=3)) == []
    assert unit.state["_bl"]["speech_seen"] == 0
    other = device(3)
    exchange(other, {"t": "shb"}, index=3)
    assert other.state["_bl"]["token"] == "" and unit.state["_bl"]["token"] == "synthetic-token"


def test_independent_energy_readout_flags_and_read_only_metadata_atomicity():
    for version in (11, 13):
        cache = bytes(0x600)
        assert BlCache(version).get(cache, "ElcEn", energy=(3, 1, 1)) == 0
        assert BlCache(version).get(cache, "ElcEn", energy=(4, 1, 1)) == 1
        assert BlCache(version).get(cache, "ElcEn", energy=(4, 1, 0)) == 0
    unit = device()
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "cmd", "opt": ["Pow", "hid"], "p": [1, "changed"]})
    assert unit.state == before
