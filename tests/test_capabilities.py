"""Capability evidence is separate from cached state and command acceptance."""
from unittest.mock import AsyncMock

import pytest

from greeclimate import device_profile, mid_profile
from greeclimate.air_conditioner import AirConditionerDevice
from greeclimate.cipher import CipherV1
from greeclimate.dehumidifier import DehumidifierDevice
from greeclimate.device import Device
from greeclimate.device_factory import create_device
from greeclimate.device_profile import DeviceProfile
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.mid_profile import MidProfile

pytestmark = pytest.mark.asyncio

AC_HID = "362001064973+U-W04NV17.bin"
AC_NAMES = frozenset({
    "power", "mode", "target_temperature", "temperature_units", "current_temperature",
    "fan_speed", "fresh_air", "xfan", "anion", "sleep", "light", "horizontal_swing",
    "vertical_swing", "quiet", "turbo", "steady_heat", "power_save", "lan_buzzer_control",
})
DEHUMIDIFIER_NAMES = frozenset({
    "power", "target_humidity", "dehumidifier_mode", "current_humidity", "clean_filter",
    "water_full", "current_temperature", "temperature_units", "fan_speed", "light",
    "vertical_swing", "anion", "quiet",
})
CAPABILITY_NAMES = AC_NAMES | DEHUMIDIFIER_NAMES


@pytest.fixture
def info():
    return DeviceInfo("127.0.0.1", 7000, "001122334455", "Capability test")


@pytest.mark.parametrize("kind,names", [
    (Device, CAPABILITY_NAMES),
    (AirConditionerDevice, AC_NAMES),
    (DehumidifierDevice, DEHUMIDIFIER_NAMES),
])
async def test_fixed_schema_distinguishes_unknown_from_outside_family(info, kind, names):
    unit = kind(info)
    snapshot = unit.capabilities
    assert len(snapshot) == 23
    assert set(snapshot) == CAPABILITY_NAMES
    assert all(snapshot[name] is None for name in names)
    assert all(snapshot[name] is False for name in CAPABILITY_NAMES - names)
    assert "buzzer" not in snapshot


@pytest.mark.parametrize("mid", [None, "10001", "13805", "3027", "60"])
async def test_neutral_device_stays_unknown_after_known_hid_and_raw_state(info, mid):
    info.mid = mid
    unit = Device(info)
    before = unit.capabilities
    unit.handle_state_update(hid=AC_HID, Pow=0, Mod=1, TemSen=65, DwatSen=45)
    unit.set_property("Pow", 1)
    info.model = "Known air conditioner"
    info.mid = "13805"
    assert all(value is None for value in unit.capabilities.values())
    assert unit.capabilities == before
    assert type(unit) is Device
    for name in ("power", "mode", "target_temperature", "target_humidity", "buzzer"):
        assert not hasattr(unit, name)


@pytest.mark.parametrize("hid,buzzer", [
    (None, None),
    ("malformed", None),
    ("999999999999+U-W04NV17.bin", None),
    ("362001000762", False),
    ("362001063967", True),
    ("362001064973", True),
    ("362001064973+", True),
    ("362001064973+different-module-V999.bin", True),
    (123, None),
    ([], None),
    ({}, None),
])
async def test_hid_only_supplies_independent_buzzer_evidence(info, hid, buzzer):
    unit = AirConditionerDevice(info)
    unit.handle_state_update(hid=AC_HID)
    unit.handle_state_update(hid=hid)
    snapshot = unit.capabilities
    assert all(snapshot[name] is None for name in AC_NAMES - {"lan_buzzer_control"})
    assert snapshot["lan_buzzer_control"] is buzzer
    assert snapshot["target_humidity"] is False
    assert unit.power is None
    assert unit.current_temperature is None


async def test_snapshots_are_fresh_immutable_and_keep_prior_hid_evidence(info):
    unit = AirConditionerDevice(info)
    before = unit.capabilities
    unit.handle_state_update(hid=AC_HID)
    supported = unit.capabilities
    assert unit.capabilities is not supported
    with pytest.raises(TypeError):
        supported["power"] = False
    with pytest.raises(TypeError):
        del supported["quiet"]
    with pytest.raises(TypeError):
        supported["invented"] = True
    with pytest.raises(AttributeError):
        unit.capabilities = {}
    unit.handle_state_update(hid="362001000762")
    excluded = unit.capabilities
    unit.handle_state_update(hid="malformed")
    assert before["lan_buzzer_control"] is None
    assert supported["lan_buzzer_control"] is True
    assert excluded["lan_buzzer_control"] is False
    assert unit.capabilities["lan_buzzer_control"] is None
    assert type(unit) is AirConditionerDevice


@pytest.mark.parametrize("kind,mid", [
    (AirConditionerDevice, None), (AirConditionerDevice, "10001"),
    (DehumidifierDevice, None), (DehumidifierDevice, "13805"),
])
async def test_cached_reports_local_values_and_connection_state_do_not_probe_or_add_evidence(
        info, kind, mid):
    info.mid = mid
    unit = kind(info)
    unit.bind = AsyncMock()
    unit.send = AsyncMock()
    before = unit.capabilities
    unit.handle_state_update(Pow=0, TemUn=0, TemSen=0, DwatSen=0)
    assert unit.capabilities == before
    unit.handle_state_update(hid=AC_HID)
    evidenced = unit.capabilities
    unit.handle_state_update(Pow=1, TemUn=1, TemSen=65, DwatSen=45)
    unit.set_property("Pow", 0)
    unit.set_property("SetTem", 23)
    info.model = "Unrelated model"
    unit.version = "999"
    unit.ready.set()
    assert unit.capabilities == evidenced
    unit.ready.clear()
    assert unit.capabilities == evidenced
    unit.bind.assert_not_awaited()
    unit.send.assert_not_awaited()


async def test_known_ac_mid_evidence_precedes_hid_and_survives_hid_loss(info):
    info.mid = "10001"
    unit = create_device(info)
    before = unit.capabilities
    for name in ("power", "mode", "target_temperature", "temperature_units",
                 "current_temperature", "fan_speed", "quiet", "turbo",
                 "steady_heat", "power_save"):
        assert before[name] is True
    assert before["sleep"] is None
    assert before["lan_buzzer_control"] is None
    assert before["dehumidifier_mode"] is False
    assert unit.power is None
    assert unit.current_temperature is None
    unit.handle_state_update(hid=AC_HID)
    assert unit.capabilities["lan_buzzer_control"] is True
    unit.handle_state_update(hid="malformed")
    assert unit.capabilities == before


async def test_known_dehumidifier_mid_does_not_invent_omitted_sensors(info):
    info.mid = "13805"
    unit = create_device(info)
    before = unit.capabilities
    for name in ("power", "target_humidity", "dehumidifier_mode", "current_humidity",
                 "clean_filter", "water_full", "fan_speed", "light", "vertical_swing",
                 "anion", "quiet"):
        assert before[name] is True
    assert before["current_temperature"] is None
    assert before["temperature_units"] is None
    assert before["mode"] is False
    unit.handle_state_update(hid=AC_HID, Pow=1, Dmod=0, Dwet=6, DwatSen=45,
                             Dfltr=0, DwatFul=0, WdSpd=1, Lig=1, Quiet=0)
    assert unit.capabilities == before
    assert unit.target_humidity == 45
    assert unit.clean_filter is False
    assert unit.capabilities["lan_buzzer_control"] is False


@pytest.mark.parametrize("code,excluded", [
    ("362001000835", ("steady_heat",)),
    ("362001063384", ("current_temperature", "anion", "light", "steady_heat")),
    ("362001067592", ("current_temperature", "anion", "light", "steady_heat")),
    ("362001065634", ("current_temperature",)),
    ("362001062617", ("current_temperature",)),
    ("362001067012", ("current_temperature",)),
    ("362001061649", ("target_temperature", "temperature_units", "current_temperature",
                      "sleep", "light", "turbo", "vertical_swing")),
])
@pytest.mark.parametrize("suffix", ["", "+different-module-V999.bin"])
async def test_firmware_exclusions_override_mid_without_erasing_other_features(
        info, code, excluded, suffix):
    info.mid = "10001"
    unit = AirConditionerDevice(info)
    baseline = unit.capabilities
    unit.handle_state_update(hid=code + suffix, TemSen=65, Pow=1)
    snapshot = unit.capabilities
    assert all(snapshot[name] is False for name in excluded)
    assert snapshot["power"] is True
    unit.handle_state_update(hid="unknown-code" + suffix)
    assert unit.capabilities == baseline
    assert snapshot[excluded[0]] is False


async def test_humidity_exclusion_does_not_alias_another_sensor_or_gate_raw_access(info):
    info.mid = "13805"
    unit = DehumidifierDevice(info)
    assert unit.capabilities["current_humidity"] is True
    unit.handle_state_update(hid="362001060499", HumSen=47)
    assert unit.capabilities["current_humidity"] is False
    assert unit.capabilities["target_humidity"] is True
    assert unit.current_humidity is None
    assert unit.get_property("HumSen") == 47
    unit.handle_state_update(hid="unknown")
    assert unit.capabilities["current_humidity"] is True


@pytest.mark.parametrize("kind,family,own_key,excluded,foreign", [
    (AirConditionerDevice, "air_conditioner", "quiet", "target_humidity", "dehumidifier"),
    (DehumidifierDevice, "dehumidifier", "target_humidity", "mode", "air_conditioner"),
])
async def test_firmware_entries_require_matching_family_and_public_typed_key(
        info, monkeypatch, kind, family, own_key, excluded, foreign):
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (
        DeviceProfile("362001064973", capabilities=(
            (foreign, "power", True),
            (family, own_key, True),
            (family, excluded, True),
            (family, "invented", True),
        )),
    ))
    unit = kind(info)
    unit.handle_state_update(hid=AC_HID)
    assert unit.capabilities["power"] is None
    assert unit.capabilities[own_key] is True
    assert unit.capabilities[excluded] is False
    assert "invented" not in unit.capabilities
    neutral = Device(info)
    neutral.handle_state_update(hid=AC_HID)
    assert all(value is None for value in neutral.capabilities.values())


@pytest.mark.parametrize("namespaces,expected", [
    (None, None),
    ((), False),
    (("Buzzer_ON_OFF",), True),
])
async def test_buzzer_baseline_comes_from_firmware_namespaces_not_mid_fields(
        info, monkeypatch, namespaces, expected):
    info.mid = "buzzer-fields"
    monkeypatch.setattr(mid_profile, "KNOWN_MID_PROFILES", (
        MidProfile("buzzer-fields", ("Buzzer_ON_OFF", "BuzzerCtrl"), "air_conditioner"),
    ))
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (
        DeviceProfile("362001064973", buzzer_properties=namespaces),
    ))
    unit = AirConditionerDevice(info)
    assert unit.capabilities["lan_buzzer_control"] is None
    unit.handle_state_update(hid=AC_HID)
    assert unit.capabilities["lan_buzzer_control"] is expected


async def test_instances_and_hid_profile_changes_do_not_merge_evidence(info, monkeypatch):
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (
        DeviceProfile("first", capabilities=(("air_conditioner", "power", True),)),
        DeviceProfile("second", capabilities=(("air_conditioner", "quiet", True),)),
    ))
    first = AirConditionerDevice(info)
    second = AirConditionerDevice(info)
    first.handle_state_update(hid="first+build")
    second.handle_state_update(hid="second+build")
    snapshot = first.capabilities
    assert snapshot["power"] is True
    assert snapshot["quiet"] is None
    assert second.capabilities["power"] is None
    assert second.capabilities["quiet"] is True
    first.handle_state_update(hid="second+other-build")
    assert first.capabilities == second.capabilities
    assert snapshot["power"] is True
    assert snapshot["quiet"] is None


@pytest.mark.parametrize("kind,mid,names", [
    (AirConditionerDevice, "13805", AC_NAMES),
    (DehumidifierDevice, "10001", DEHUMIDIFIER_NAMES),
])
async def test_direct_family_mismatch_does_not_import_mid_evidence(info, kind, mid, names):
    info.mid = mid
    unit = kind(info)
    assert all(unit.capabilities[name] is None for name in names)


@pytest.mark.parametrize("mid", [None, "unmapped", "3027", "6400", "60", 10001, "10001 "])
async def test_unknown_or_unimplemented_mid_adds_no_family_evidence(info, mid):
    info.mid = mid
    unit = AirConditionerDevice(info)
    assert all(unit.capabilities[name] is None for name in AC_NAMES)


async def test_retained_mid_is_fixed_and_registry_changes_only_affect_new_instances(info, monkeypatch):
    info.mid = "13805"
    original = DehumidifierDevice(info)
    snapshot = original.capabilities
    assert snapshot["current_humidity"] is True
    assert snapshot["current_temperature"] is None
    info.mid = "13802"
    replacement = DehumidifierDevice(info)
    assert replacement.capabilities["current_humidity"] is None
    assert replacement.capabilities["current_temperature"] is True
    assert original.capabilities == snapshot
    monkeypatch.setattr(mid_profile, "KNOWN_MID_PROFILES", ())
    unregistered = DehumidifierDevice(info)
    assert unregistered.capabilities["current_temperature"] is None
    assert replacement.capabilities["current_temperature"] is True
    assert original.capabilities == snapshot


@pytest.mark.parametrize("kind,mid,name,value,key,wire,hid,evidence", [
    (AirConditionerDevice, None, "quiet", True, "Quiet", 2, None, None),
    (DehumidifierDevice, None, "target_humidity", 45, "Dwet", 6, None, None),
    (AirConditionerDevice, "10001", "steady_heat", True, "StHt", 1, "362001000835", False),
])
async def test_capabilities_do_not_add_setter_rejection_gates(
        info, kind, mid, name, value, key, wire, hid, evidence):
    info.mid = mid
    unit = kind(info)
    try:
        await unit.bind(key="0123456789abcdef", cipher=CipherV1())
        unit.send = AsyncMock()
        if hid is not None:
            unit.handle_state_update(hid=hid)
        assert unit.capabilities[name] is evidence
        setattr(unit, name, value)
        await unit.push_state_update()
        pack = unit.send.await_args.args[0]["pack"]
        assert pack["t"] == "cmd"
        assert pack["opt"] == [key]
        assert pack["p"] == [wire]
        assert unit.capabilities[name] is evidence
    finally:
        unit.close()
