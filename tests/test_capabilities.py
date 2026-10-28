"""Capability evidence is separate from cached state and command acceptance."""
from unittest.mock import AsyncMock

import pytest

from greeclimate import device_profile, mid_profile
from greeclimate.air_conditioner import AirConditionerDevice
from greeclimate.air_to_water import AirToWaterDevice, AirToWaterMode
from greeclimate.cipher import CipherV1
from greeclimate.dehumidifier import DehumidifierDevice
from greeclimate.device import Device
from greeclimate.device_factory import create_device
from greeclimate.device_profile import DeviceProfile
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.mid_profile import MidProfile

pytestmark = pytest.mark.asyncio

AC_HID = "362001064973+U-W04NV17.bin"
ATW_HID = "362001066763+U-W06A(P3)V6.04.bin"
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
ATW_NAMES = frozenset({
    "power", "mode", "temperature_units", "inlet_water_temperature_c",
    "outlet_water_temperature_c", "room_temperature_c", "tank_temperature_c",
    "heating_room_target_temperature_c", "cooling_room_target_temperature_c",
    "heating_water_target_temperature_c", "cooling_water_target_temperature_c",
    "tank_target_temperature_c",
})
CAPABILITY_NAMES = AC_NAMES | DEHUMIDIFIER_NAMES | ATW_NAMES
ATW_SENSORS = {
    "inlet_water_temperature_c", "outlet_water_temperature_c",
    "room_temperature_c", "tank_temperature_c",
}
TARGETS = [
    ("heating_water_target_temperature_c", "HeWatOutTemSet", 40),
    ("cooling_water_target_temperature_c", "CoWatOutTemSet", 20),
    ("tank_target_temperature_c", "WatBoxTemSet", 50),
]


@pytest.fixture
def info():
    return DeviceInfo("127.0.0.1", 7000, "001122334455", "Capability test")


@pytest.mark.parametrize("kind,names", [
    (Device, CAPABILITY_NAMES),
    (AirConditionerDevice, AC_NAMES),
    (DehumidifierDevice, DEHUMIDIFIER_NAMES),
    (AirToWaterDevice, ATW_NAMES),
])
async def test_fixed_schema_distinguishes_unknown_from_outside_family(info, kind, names):
    unit = kind(info)
    snapshot = unit.capabilities
    assert len(snapshot) == 32
    assert set(snapshot) == CAPABILITY_NAMES
    if kind is AirConditionerDevice:
        assert snapshot["lan_buzzer_control"] is False
        assert all(snapshot[name] is None for name in names - {"lan_buzzer_control"})
    else:
        assert all(snapshot[name] is None for name in names)
    assert all(snapshot[name] is False for name in CAPABILITY_NAMES - names)
    assert "buzzer" not in snapshot
    assert "cooling_mode_value" not in snapshot


@pytest.mark.parametrize("mid", [None, "10001", "13805", "3027", "9300", "9301", "60"])
@pytest.mark.parametrize("hid", [AC_HID, ATW_HID])
async def test_neutral_device_stays_unknown_after_known_hid_and_raw_state(info, mid, hid):
    info.mid = mid
    unit = Device(info)
    before = unit.capabilities
    unit.handle_state_update(hid=hid, Pow=0, Mod=1, TemSen=65, DwatSen=45)
    unit.set_property("Pow", 1)
    info.model = "Known air conditioner"
    info.mid = "13805"
    assert all(value is None for value in unit.capabilities.values())
    assert unit.capabilities == before
    assert type(unit) is Device
    for name in ("power", "mode", "target_temperature", "target_humidity", "buzzer"):
        assert not hasattr(unit, name)


@pytest.mark.parametrize("hid,buzzer", [
    (None, False),
    ("malformed", False),
    ("999999999999+U-W04NV17.bin", False),
    ("362001000762", False),
    ("362001063967", True),
    ("362001064973", True),
    ("362001064973+", True),
    ("362001064973+different-module-V999.bin", True),
    (ATW_HID, False),
    (123, False),
    ([], False),
    ({}, False),
])
async def test_hid_only_reports_buzzer_opt_in_policy(info, hid, buzzer):
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
    assert before["lan_buzzer_control"] is False
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
    unsupported = unit.capabilities
    unit.handle_state_update(hid="malformed")
    assert before["lan_buzzer_control"] is False
    assert supported["lan_buzzer_control"] is True
    assert unsupported["lan_buzzer_control"] is False
    assert unit.capabilities["lan_buzzer_control"] is False
    assert type(unit) is AirConditionerDevice


@pytest.mark.parametrize("kind,mid", [
    (AirConditionerDevice, None), (AirConditionerDevice, "10001"),
    (DehumidifierDevice, None), (DehumidifierDevice, "13805"),
    (AirToWaterDevice, None), (AirToWaterDevice, "9300"),
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
    assert before["lan_buzzer_control"] is False
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
    ("362001061649", tuple(sorted(AC_NAMES - {"power", "lan_buzzer_control"}))),
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


@pytest.mark.parametrize("kind,names", [
    (AirConditionerDevice, AC_NAMES), (DehumidifierDevice, DEHUMIDIFIER_NAMES),
])
@pytest.mark.parametrize("mid", ["80241", "80242"])
async def test_sensor_host_does_not_borrow_forwarded_climate_capabilities(info, kind, names, mid):
    info.mid = mid
    unit = kind(info)
    unit.handle_state_update(hid="362001061649+U-W06KV4.4.bin",
                             Pow=1, TemSor=65535, HumSor=255, CO2=65535)
    assert unit.capabilities["power"] is None
    assert all(unit.capabilities[name] is False for name in names - {"power"})
    assert unit.current_temperature is None
    assert unit.get_property("TemSor") == 65535
    unit.handle_state_update(hid="unknown")
    assert all(unit.capabilities[name] is None for name in names - {"lan_buzzer_control"})
    assert unit.capabilities["lan_buzzer_control"] is False


@pytest.mark.parametrize("code,steady_heat", [
    ("362001000835", False), ("362001060200", False), ("362001060297", False),
    ("362001060498", False), ("362001060499", True),
])
async def test_mtk_steady_heat_distinguishes_implemented_bit_from_fixed_zero(info, code, steady_heat):
    info.mid = "10001"
    unit = create_device(info)
    unit.handle_state_update(hid=code, StHt=1)
    assert unit.steady_heat is True
    assert unit.capabilities["steady_heat"] is steady_heat


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
    (AirToWaterDevice, "air_to_water", "tank_target_temperature_c", "quiet", "dehumidifier"),
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


@pytest.mark.parametrize("profile,expected", [
    (DeviceProfile("362001064973"), False),
    (DeviceProfile("362001064973", buzzer_properties=()), False),
    (DeviceProfile("362001064973", buzzer_properties=("Buzzer_ON_OFF",)), True),
])
async def test_buzzer_opt_in_uses_profile_namespaces_not_mid_fields(
        info, monkeypatch, profile, expected):
    info.mid = "buzzer-fields"
    monkeypatch.setattr(mid_profile, "KNOWN_MID_PROFILES", (
        MidProfile("buzzer-fields", ("Buzzer_ON_OFF", "BuzzerCtrl"), "air_conditioner"),
    ))
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (
        profile,
    ))
    unit = AirConditionerDevice(info)
    assert unit.capabilities["lan_buzzer_control"] is False
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
    (AirToWaterDevice, "10001", ATW_NAMES),
])
async def test_direct_family_mismatch_does_not_import_mid_evidence(info, kind, mid, names):
    info.mid = mid
    unit = kind(info)
    assert all(unit.capabilities[name] is None for name in names - {"lan_buzzer_control"})
    assert unit.capabilities["lan_buzzer_control"] is False


@pytest.mark.parametrize("mid", [None, "unmapped", "3027", "6400", "60", 10001, "10001 "])
async def test_unknown_or_unimplemented_mid_adds_no_family_evidence(info, mid):
    info.mid = mid
    unit = AirConditionerDevice(info)
    assert all(unit.capabilities[name] is None for name in AC_NAMES - {"lan_buzzer_control"})
    assert unit.capabilities["lan_buzzer_control"] is False


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


@pytest.fixture
async def atw(info):
    info.mid = "9300"
    unit = AirToWaterDevice(info)
    await unit.bind(key="0123456789abcdef", cipher=CipherV1())
    unit.send = AsyncMock()
    yield unit
    unit.close()



def sent_properties(unit):
    pack = unit.send.await_args.args[0]["pack"]
    assert pack["t"] == "cmd"
    assert len(pack["opt"]) == len(pack["p"])
    return dict(zip(pack["opt"], pack["p"]))



@pytest.mark.parametrize("hid", [
    ATW_HID,
    "362001066763",
    "362001066763+",
    "362001066763+U-W06A(P3)V6.05.bin",
    "362001066763+U-W06A(P3)V6.04.0.bin",
    "362001066763+W06A(P3)V6.04.bin",
    "362001066763+U-W06A(P2)V6.04.bin",
    "362001066763+U-OTHER(P3)V6.04.bin",
])
async def test_atw_firmware_code_evidence_does_not_require_available_readings(info, hid):
    unit = AirToWaterDevice(info)
    unit.handle_state_update(hid=hid)
    assert all(unit.capabilities[name] is True for name in ATW_SENSORS)
    assert all(unit.capabilities[name] is None for name in ATW_NAMES - ATW_SENSORS)
    assert all(unit.capabilities[name] is False for name in CAPABILITY_NAMES - ATW_NAMES)
    assert unit.temperature_units is None
    assert unit.heating_water_target_temperature_c is None
    assert unit.inlet_water_temperature_c is None



@pytest.mark.parametrize("hid", [
    None, "malformed", AC_HID,
    "362001066764+U-W06A(P3)V6.04.bin",
    "0362001066763+U-W06A(P3)V6.04.bin",
    "3620010667630+U-W06A(P3)V6.04.bin",
    123, [], {},
])
async def test_atw_sensor_evidence_requires_matching_firmware_code(info, hid):
    unit = AirToWaterDevice(info)
    unit.handle_state_update(hid=ATW_HID)
    unit.handle_state_update(hid=hid)
    assert all(unit.capabilities[name] is None for name in ATW_NAMES)
    assert unit.capabilities["lan_buzzer_control"] is False



async def test_metadata_only_atw_firmware_excludes_mid_features_until_hid_changes(info):
    info.mid = "9300"
    unit = create_device(info)
    before = unit.capabilities
    assert before["power"] is True
    assert before["tank_target_temperature_c"] is True

    unit.handle_state_update(hid="362001069999+uninspected-module")
    excluded = unit.capabilities
    assert all(excluded[name] is False for name in ATW_NAMES)
    assert type(unit) is AirToWaterDevice

    unit.handle_state_update(hid="unknown")
    assert unit.capabilities["power"] is True
    assert unit.capabilities["tank_target_temperature_c"] is True
    assert unit.capabilities["room_temperature_c"] is None
    assert before["power"] is True
    assert excluded["power"] is False



@pytest.mark.parametrize("kind", [Device, DehumidifierDevice, AirToWaterDevice])
async def test_buzzer_namespace_does_not_enable_other_families(info, kind):
    unit = kind(info)
    unit.handle_state_update(hid=AC_HID)
    expected = None if kind is Device else False
    assert unit.capabilities["lan_buzzer_control"] is expected



@pytest.mark.parametrize("override", [None, 0, 5])
async def test_cooling_configuration_does_not_create_protocol_evidence(info, override):
    unit = AirToWaterDevice(info, cooling_mode_value=override)
    assert all(unit.capabilities[name] is None for name in ATW_NAMES)
    unit.handle_state_update(hid=ATW_HID)
    assert all(unit.capabilities[name] is True for name in ATW_SENSORS)
    assert all(unit.capabilities[name] is None for name in ATW_NAMES - ATW_SENSORS)



@pytest.mark.parametrize("name,key,value", TARGETS)
@pytest.mark.parametrize("units", [None, 1, True, 2])
async def test_evidenced_atw_target_still_requires_received_celsius(atw, name, key, value, units):
    atw.handle_state_update(hid=ATW_HID)
    if units is not None:
        atw.handle_state_update(TemUn=units)
    assert atw.capabilities[name] is True
    with pytest.raises(ValueError, match="require reported Celsius"):
        setattr(atw, name, value)
    atw.set_property("TemUn", 0)
    with pytest.raises(ValueError, match="require reported Celsius"):
        setattr(atw, name, value)
    atw.send.assert_not_awaited()



@pytest.mark.parametrize("name,key,value", TARGETS)
@pytest.mark.parametrize("power", [None, 1])
async def test_evidenced_atw_target_can_write_with_power_unknown_or_on(atw, name, key, value, power):
    atw.handle_state_update(hid=ATW_HID, TemUn=0)
    if power is not None:
        atw.handle_state_update(Pow=power)
    assert atw.capabilities[name] is True
    setattr(atw, name, value)
    await atw.push_state_update()
    assert sent_properties(atw) == {key: value}



@pytest.mark.parametrize("hid", [None, ATW_HID])
async def test_atw_power_can_write_before_any_power_or_unit_report(atw, hid):
    if hid is not None:
        atw.handle_state_update(hid=hid)
    assert atw.capabilities["power"] is True
    assert atw.power is None
    assert atw.temperature_units is None
    atw.power = True
    await atw.push_state_update()
    assert sent_properties(atw) == {"Pow": 1}



@pytest.mark.parametrize("power", [None, 1])
async def test_evidenced_atw_mode_still_requires_received_off(atw, power):
    atw.handle_state_update(hid=ATW_HID, Mod=1)
    if power is not None:
        atw.handle_state_update(Pow=power)
    assert atw.capabilities["mode"] is True
    with pytest.raises(ValueError, match="off power state must be received"):
        atw.mode = AirToWaterMode.HotWater
    atw.power = False
    with pytest.raises(ValueError, match="off power state must be received"):
        atw.mode = AirToWaterMode.HotWater
    atw.set_property("Mod", 2)
    with pytest.raises(ValueError, match="off power state must be received"):
        await atw.push_state_update()
    atw.send.assert_not_awaited()



async def test_evidenced_atw_mode_plus_power_on_batch_is_still_rejected(atw):
    atw.handle_state_update(hid=ATW_HID, Pow=0, Mod=1)
    atw.mode = AirToWaterMode.HotWater
    atw.power = True
    assert atw.capabilities["mode"] is True
    assert atw.capabilities["power"] is True
    with pytest.raises(ValueError, match="Push the ATW mode change before turning power on"):
        await atw.push_state_update()
    atw.send.assert_not_awaited()



@pytest.mark.parametrize("control", ["target", "mode"])
async def test_evidence_does_not_bypass_send_time_atw_state_revalidation(atw, control):
    atw.handle_state_update(hid=ATW_HID, Pow=0, Mod=1, TemUn=0)
    if control == "target":
        atw.heating_water_target_temperature_c = 40
        atw.handle_state_update(TemUn=1)
        message = "require reported Celsius"
    else:
        atw.mode = AirToWaterMode.HotWater
        atw.handle_state_update(Pow=1)
        message = "off power state must be received"
    assert all(atw.capabilities[name] is True for name in ATW_NAMES)
    with pytest.raises(ValueError, match=message):
        await atw.push_state_update()
    atw.send.assert_not_awaited()



@pytest.mark.parametrize("kind,name,value,key,wire,reported", [
    (AirConditionerDevice, "quiet", True, "Quiet", 2, {}),
    (DehumidifierDevice, "target_humidity", 45, "Dwet", 6, {}),
    (AirToWaterDevice, "heating_water_target_temperature_c", 40, "HeWatOutTemSet", 40,
     {"TemUn": 0}),
])
async def test_unknown_capability_does_not_add_a_setter_rejection_gate(
        info, kind, name, value, key, wire, reported):
    unit = kind(info)
    await unit.bind(key="0123456789abcdef", cipher=CipherV1())
    unit.send = AsyncMock()
    unit.handle_state_update(**reported)
    assert unit.capabilities[name] is None
    setattr(unit, name, value)
    await unit.push_state_update()
    assert sent_properties(unit) == {key: wire}
    assert unit.capabilities[name] is None
    unit.close()



@pytest.mark.parametrize("hid", [
    None, AC_HID, ATW_HID, "malformed", "362001066763",
    "362001066763+", "362001066763+different-module-V999.bin",
])
async def test_atw_mid_core_capabilities_do_not_depend_on_hid(info, hid):
    info.mid = "9300"
    unit = AirToWaterDevice(info)
    before = unit.capabilities
    unit.handle_state_update(hid=hid)
    assert all(unit.capabilities[name] is True for name in ATW_NAMES - ATW_SENSORS)
    assert all(before[name] is True for name in ATW_NAMES - ATW_SENSORS)
    expected = True if isinstance(hid, str) and hid.partition("+")[0] == "362001066763" else None
    assert all(unit.capabilities[name] is expected for name in ATW_SENSORS)



@pytest.mark.parametrize("kind,family,name,columns", [
    (AirConditionerDevice, "air_conditioner", "target_temperature", ("SetTem", "TemRec", "TemUn")),
    (AirConditionerDevice, "air_conditioner", "sleep", ("SwhSlp", "SlpMod")),
    (AirToWaterDevice, "air_to_water", "inlet_water_temperature_c",
     ("AllInWatTemHi", "AllInWatTemLo", "TemUn")),
    (AirToWaterDevice, "air_to_water", "outlet_water_temperature_c",
     ("AllOutWatTemHi", "AllOutWatTemLo", "TemUn")),
    (AirToWaterDevice, "air_to_water", "room_temperature_c",
     ("RmoHomTemHi", "RmoHomTemLo", "TemUn")),
    (AirToWaterDevice, "air_to_water", "tank_temperature_c",
     ("WatBoxTemHi", "WatBoxTemLo", "TemUn")),
])
async def test_composite_capabilities_require_every_exact_status_column(
        info, monkeypatch, kind, family, name, columns):
    info.mid = "composite"
    for omitted in columns:
        incomplete = tuple(column for column in columns if column != omitted)
        monkeypatch.setattr(mid_profile, "KNOWN_MID_PROFILES", (
            MidProfile("composite", incomplete, family=family),
        ))
        unit = kind(info)
        assert unit.capabilities[name] is None
    monkeypatch.setattr(mid_profile, "KNOWN_MID_PROFILES", (
        MidProfile("composite", tuple(column.lower() for column in columns), family=family),
    ))
    unit = kind(info)
    assert unit.capabilities[name] is None
    monkeypatch.setattr(mid_profile, "KNOWN_MID_PROFILES", (
        MidProfile("composite", columns, family=family),
    ))
    unit = kind(info)
    assert unit.capabilities[name] is True



async def test_atw_mid_targets_do_not_infer_auto_poll_sensor_support_or_bypass_safety(atw):
    snapshot = atw.capabilities
    for name in ("power", "mode", "temperature_units",
                 "heating_room_target_temperature_c", "cooling_room_target_temperature_c",
                 "heating_water_target_temperature_c", "cooling_water_target_temperature_c",
                 "tank_target_temperature_c"):
        assert snapshot[name] is True
    for name in ("inlet_water_temperature_c", "outlet_water_temperature_c",
                 "room_temperature_c", "tank_temperature_c"):
        assert snapshot[name] is None
    with pytest.raises(ValueError, match="require reported Celsius"):
        atw.heating_water_target_temperature_c = 40
    with pytest.raises(ValueError, match="off power state must be received"):
        atw.mode = AirToWaterMode.HotWater
    atw.send.assert_not_awaited()
    atw.handle_state_update(hid=ATW_HID)
    assert all(atw.capabilities[name] is True for name in ATW_NAMES)
    assert snapshot["inlet_water_temperature_c"] is None


@pytest.mark.parametrize("hid", [
    "362001061433+U-W06AV7.bin",
    "362001061437+U-W06BV9.bin",
    "362001067012+U-W06AV16.bin",
    "362001067012+U-W06AV20.bin",
    "362001067012+U-W06AV30.bin",
])
async def test_gateway_hid_excludes_typed_sensor_without_calibrating_raw_body(info, hid):
    info.mid = "10001"
    unit = create_device(info)
    assert unit.capabilities["current_temperature"] is True
    unit.handle_state_update(hid=hid, TemBody=85)
    excluded = unit.capabilities
    assert excluded["current_temperature"] is False
    assert excluded["lan_buzzer_control"] is False
    assert unit.current_temperature is None
    assert unit.get_property("TemBody") == 85
    assert excluded["target_temperature"] is True
    unit.handle_state_update(hid="unidentified+U-W06AV7.bin")
    assert unit.capabilities["current_temperature"] is True
    assert unit.capabilities["lan_buzzer_control"] is False
    assert excluded["current_temperature"] is False


@pytest.mark.parametrize("hid", [
    "362001066380+U-WB05BRV1.13.bin",
    "362001066326+U-WB05BRV1.16.bin",
    "362001066326+U-WB05BRV1.18.bin",
    "362001066380+U-WB05BRV1.22.bin",
    "362001066380+U-WB05BRV1.31.bin",
    "362001066380+U-WB05BRV1.38.bin",
])
async def test_wb_gateway_identity_keeps_other_traits_unknown_without_buzzer_opt_in(info, hid):
    unit = AirConditionerDevice(info)
    unit.handle_state_update(hid="362001061433+U-W06AV7.bin")
    assert unit.capabilities["current_temperature"] is False
    assert unit.capabilities["lan_buzzer_control"] is False
    unit.handle_state_update(hid=hid, TemSor=85)
    assert all(unit.capabilities[name] is None for name in AC_NAMES if name != "lan_buzzer_control")
    assert unit.capabilities["lan_buzzer_control"] is False
    assert unit.current_temperature is None
    assert unit.get_property("TemSor") == 85
    unit.version = "999"
    assert all(unit.capabilities[name] is None for name in AC_NAMES if name != "lan_buzzer_control")
    assert unit.capabilities["lan_buzzer_control"] is False


@pytest.mark.parametrize("hid,buzzer", [
    ("362001061433+U-W06AV7.bin", False),
    ("362001067012+U-W06AV16.bin", False),
    ("362001066326+U-WB05BRV1.18.bin", False),
    ("362001066380+U-WB05BRV1.38.bin", False),
    ("362001065279+U-WB05RT13V1.54.bin", True),
    ("362001065279+U-WB05RT13V1.64.bin", True),
])
async def test_firmware_namespace_only_adds_evidenced_buzzer_command(info, hid, buzzer):
    info.mid = "10001"
    unit = create_device(info)
    assert type(unit) is AirConditionerDevice
    await unit.bind(key="0123456789abcdef", cipher=CipherV1())
    unit.send = AsyncMock()
    unit.handle_state_update(hid=hid, Pow=0)
    unit.buzzer = False
    unit.power = True
    await unit.push_state_update()
    expected = {"Pow": 1}
    if buzzer is True:
        expected["Buzzer_ON_OFF"] = 1
    assert sent_properties(unit) == expected
    assert unit.capabilities["lan_buzzer_control"] is buzzer
    assert unit.capabilities["power"] is True
    unit.close()
