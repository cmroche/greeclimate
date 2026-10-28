"""Independent BR root descriptor/callback vectors; never imports research code."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles import wb_root
from gree_emulator.wire import InvalidPacket
from tests.test_emulator_wb_gateway import exchange, gateway, outer, packet, PROFILES


VECTOR = json.loads((Path(__file__).parent / "fixtures/emulator/wb-root_research.json").read_text())


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch):
    monkeypatch.setattr(wb_root, "monotonic", lambda: 100.0)


def status(device, columns, kind="status"):
    return exchange(device, outer(), {"t": kind, "mac": device.mac, "cols": columns})[0]["inner"]


def command(device, names, values, kind="cmd"):
    return exchange(device, outer(), {"t": kind, "mac": device.mac,
                                      "opt": names, "p": values})[0]["inner"]


@pytest.mark.parametrize("source", VECTOR["sources"], ids=lambda source: source["version"])
@pytest.mark.parametrize("kind", ("status", "dat"))
def test_complete_exact_source_root_namespace(source, kind):
    device = gateway(source["version"])
    columns = VECTOR["columns"] + source["extra_columns"]
    expected = deepcopy(VECTOR["values"]) + source["extra_values"]
    expected[32] = source["hid"]
    assert len(columns) == source["common_count"]
    assert device.profile.source_sha256 == source["sha256"]
    assert status(device, columns, kind) == {
        "t": "dat", "mac": "020000000001", "cols": columns, "dat": expected, "r": 200}
    assert status(device, ["MIdType", "subCnt", "_clock_at", "unknown", "conf", "conf"])["dat"] == [
        "", "", "", "", None, None]


@pytest.mark.parametrize("source", VECTOR["sources"], ids=lambda source: source["version"])
@pytest.mark.parametrize("kind", ("cmd", "res"))
def test_raw_types_sequential_duplicates_and_fresh_status(source, kind):
    device = gateway(source["version"])
    raw = VECTOR["raw_command"]
    assert command(device, raw["opt"], raw["p"], kind) == {
        "t": "res", "mac": "020000000001", "r": 200,
        "opt": raw["opt"], "p": raw["p"], "val": raw["val"]}
    assert status(device, raw["fresh_columns"])["dat"] == raw["fresh_values"]
    assert status(gateway(source["version"]), ["lock", "configType"])["dat"] == [0, None]


@pytest.mark.parametrize("version", ("1.13", "1.16", "1.18", "1.22", "1.31", "1.38"))
def test_reported_identity_cache_does_not_rewire_configured_root(version):
    device = gateway(version)
    assert command(device, ["mac", "mid", "hid", "name"], ["reported", "raw", None, "Changed"])["val"] == [
        "reported", "raw", None, "Changed"]
    assert status(device, ["mac", "mid", "hid", "name"])["dat"] == ["reported", "raw", None, "Changed"]
    assert device.mac == "020000000001" and device.mid == "60"
    advertised = device.profile.handler.advertise(device, {})[0].inner
    assert advertised["mac"] == "reported" and advertised["name"] == "Changed"


@pytest.mark.parametrize("version,expected_ver", (("1.13", "V1.1"), ("1.16", "V1.1"),
    ("1.18", "V1.1"), ("1.22", "V3.2.M"), ("1.31", "V3.2.M"), ("1.38", "V3.2.M")))
def test_mqtt_callback_is_not_descriptor_default_and_ver_is_cached(version, expected_ver):
    device = gateway(version, 0)
    profile = next(profile for profile in PROFILES if profile.id == device.profile.id + "-filter")
    device.children.append(EmulatedDevice(id="filter", mac="0244668800017f", name="Filter",
        mid="6079", key=device.key, profile=profile, state=deepcopy(dict(profile.initial_state))))
    assert status(device, ["needMqtt", "ver"])["dat"] == [0 if version in ("1.13", "1.16", "1.18") else 1,
                                                              expected_ver]
    device.children.clear()
    assert status(device, ["needMqtt", "ver"])["dat"] == [1, expected_ver]
    assert command(device, ["conf", "needMqtt", "subList"], [True, 9, ["raw"]])["val"] == [True, 9, ["raw"]]
    assert status(device, ["needMqtt", "subList", "ver"])["dat"] == [9, ["raw"], expected_ver]


@pytest.mark.parametrize("version", ("1.13", "1.16", "1.18", "1.22", "1.31", "1.38"))
def test_root_time_command_and_clock_type_are_source_specific(version):
    device = gateway(version)
    assert command(device, ["time"], ["1970-01-01 01:00:00"])["val"] == ["1970-01-01 01:00:00"]
    expected_offset = None if version in ("1.31", "1.38") else "APPST-1:00:00"
    assert status(device, ["time", "appStdTime"])["dat"] == ["1970-01-01 01:00:00", expected_offset]
    bad = "UTC0" if version in ("1.31", "1.38") else 3600
    assert command(device, ["appStdTime"], [bad])["val"] == [bad]
    assert status(device, ["appStdTime"])["dat"] == [expected_offset]
    assert command(device, ["time"], [None])["val"] == [None]
    assert status(device, ["time"])["dat"] == ["1970-01-01 01:00:00"]


@pytest.mark.parametrize("zone,seconds,offset", (
    ("UTC0", 0, 0), ("APPST-1:30:15", 0, 5415), ("APPST+8", 0, -28800),
    ("EST5EDT,M3.2.0/2,M11.1.0/2", 0, -18000),
    ("EST5EDT,M3.2.0/2,M11.1.0/2", 1720000000, -14400),
    ("NZST-12NZDT-13,M9.5.0,M4.1.0", 0, 46800),
))
def test_posix_timezone_offsets_are_per_root_and_not_host_timezone(zone, seconds, offset):
    assert wb_root._timezone_offset(zone, seconds) == offset


def test_local_event_mutations_are_not_cloud_or_upgrade_acknowledgements():
    device = gateway("1.31")
    values = [{"opaque": 1}, False, 9, {"mac": "5", "url": "https://example.invalid/fw", "ver": "chosen"}]
    assert command(device, ["wlan", "svr", "loginRes", "upgrade"], values)["val"] == [None, None, None, None]
    assert status(device, ["conf", "wlan", "svr", "loginRes", "upgrade", "gcldhidownver"])["dat"] == [
        True, None, None, None, None, "chosen"]
    assert device.state["_wb_root"]["_event"] == 0x13


@pytest.mark.parametrize("source", VECTOR["sources"], ids=lambda source: source["version"])
def test_nested_root_callbacks_use_registered_child_category_and_cache(source):
    device = gateway(source["version"])
    payload = {"mac": "02446688000100", "res": {"Pow": 1, "WdSpd": 2}}
    assert command(device, ["res"], [payload])["val"] == [None]
    assert status(device, ["dat", "res"])["dat"] == [None, None]
    assert exchange(device, outer(), {"t": "status", "mac": "0244668800017f",
                                      "cols": ["Pow", "WdSpd"]})[0]["inner"]["dat"] == [1, 2]
    assert command(device, ["dat"], [{"mac": "02446688000100",
                                     "dat": {"Pow": None, "WdSpd": None}}])["val"] == [None]
    missing = {"mac": "02000000009900", "res": {"Pow": 0}}
    assert command(device, ["res"], [missing])["val"] == [missing]
    assert exchange(device, outer(), {"t": "status", "mac": "0244668800017f",
                                      "cols": ["Pow", "WdSpd"]})[0]["inner"]["dat"] == [1, 2]


def test_nested_callback_batch_failure_cannot_mutate_child_or_root():
    device = gateway()
    before = deepcopy(device.children[0].state)
    payload = {"mac": "02446688000100", "res": {"Pow": 1}}
    with pytest.raises(InvalidPacket):
        command(device, ["res", "key"], [payload, None])
    assert device.children[0].state == before and device.state == {}


@pytest.mark.parametrize("keys", (None, ["short", "0123456789abcdef"], ["0123456789abcdef"],
    ["0123456789abcdef", "é" * 16]))
def test_invalid_key_batch_and_oversized_reply_are_atomic(keys):
    device = gateway()
    with pytest.raises(InvalidPacket, match="two 16-byte"):
        command(device, ["lock", "key"], [4, keys])
    assert device.state == {}
    with pytest.raises(InvalidPacket, match="UDP payload"):
        command(device, ["lock"] * 7000, ["x" * 30] * 7000)
    assert device.state == {}


def test_valid_root_key_replacement_selects_both_actual_crypto_slots():
    device = gateway()
    keys = ["fedcba9876543210", "new-generic-0001"]
    replies = device.profile.handler.handle(device, packet(outer(), {
        "t": "cmd", "mac": device.mac, "opt": ["key"], "p": [keys]}))
    assert replies[0].key == b"fedcba9876543210"
    assert replies[0].inner["val"] == [keys]
    fresh = device.profile.handler.handle(device, packet(outer(), {
        "t": "status", "mac": device.mac, "cols": ["key"]}, b"fedcba9876543210"))
    assert fresh[0].inner["dat"] == [keys]
    bound = device.profile.handler.handle(device, packet(outer(1), {
        "t": "bind", "mac": device.mac}, b"new-generic-0001"))
    assert bound[0].key == b"new-generic-0001"
    assert bound[0].inner["key"] == "fedcba9876543210"
