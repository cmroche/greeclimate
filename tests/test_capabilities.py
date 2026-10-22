"""Conservative protocol evidence is separate from state and command safety."""
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


@pytest.mark.parametrize("kind,names", [
    (Device, CAPABILITY_NAMES),
    (AirConditionerDevice, AC_NAMES),
    (DehumidifierDevice, DEHUMIDIFIER_NAMES),
    (AirToWaterDevice, ATW_NAMES),
])
async def test_fixed_schema_distinguishes_unknown_from_excluded(info, kind, names):
    unit = kind(info)
    snapshot = unit.capabilities
    assert len(snapshot) == 32
    assert set(snapshot) == CAPABILITY_NAMES
    assert all(snapshot[name] is None for name in names)
    assert all(snapshot[name] is False for name in CAPABILITY_NAMES - names)
    assert "buzzer" not in snapshot
    assert "cooling_mode_value" not in snapshot


@pytest.mark.parametrize("hid", [AC_HID, ATW_HID])
@pytest.mark.parametrize("value", [0, 1])
async def test_generic_remains_all_unknown_after_recognized_hid_and_raw_fields(info, hid, value):
    info.mid = "unmapped"
    unit = Device(info)
    before = unit.capabilities
    unit.handle_state_update(hid=hid, Pow=value, Mod=value, TemSen=value,
                             DwatSen=value, HeWatOutTemSet=value, Buzzer_ON_OFF=value)
    unit.set_property("Pow", 1 - value)
    info.model = "Known air conditioner and heat pump"
    info.mid = "9300"
    assert all(value is None for value in unit.capabilities.values())
    assert unit.capabilities == before
    assert type(unit) is Device
    for name in ("power", "mode", "target_temperature", "target_humidity", "buzzer"):
        assert not hasattr(unit, name)


async def test_ac_firmware_code_does_not_promote_core_without_mid(info):
    unit = AirConditionerDevice(info)
    unit.handle_state_update(hid=AC_HID)
    snapshot = unit.capabilities
    assert all(snapshot[name] is None for name in AC_NAMES - {"lan_buzzer_control"})
    assert snapshot["lan_buzzer_control"] is True
    assert all(snapshot[name] is False for name in CAPABILITY_NAMES - AC_NAMES)
    assert unit.current_temperature is None
    assert unit.power is None


@pytest.mark.parametrize("hid,buzzer", [
    (None, None),
    ("malformed", None),
    ("999999999999+U-W04NV17.bin", None),
    ("362001000762", False),
    ("362001063967", True),
    ("362001064973", True),
    ("362001064973+", True),
    ("362001064973+U-W04NV19.bin", True),
    (123, None),
    ([], None),
    ({}, None),
    ("362001064973+U-W04NV17.0.bin", True),
    ("362001064973+W04NV17.bin", True),
    ("362001064973+U-OTHERW04NV17.bin", True),
    (ATW_HID, False),
])
async def test_ac_hid_never_promotes_core_but_buzzer_has_independent_evidence(info, hid, buzzer):
    unit = AirConditionerDevice(info)
    unit.handle_state_update(hid=AC_HID)
    unit.handle_state_update(hid=hid)
    assert all(unit.capabilities[name] is None for name in AC_NAMES - {"lan_buzzer_control"})
    assert unit.capabilities["lan_buzzer_control"] is buzzer
    assert unit.capabilities["tank_target_temperature_c"] is False


async def test_native_noop_control_excludes_mid_feature_without_erasing_other_features(info):
    info.mid = "10001"
    unit = AirConditionerDevice(info)
    assert unit.capabilities["steady_heat"] is True

    unit.handle_state_update(hid="362001000835+different-build")
    assert unit.capabilities["steady_heat"] is False
    assert unit.capabilities["target_temperature"] is True
    assert unit.capabilities["current_temperature"] is True

    unit.handle_state_update(hid="362001060499")
    assert unit.capabilities["steady_heat"] is True
    assert unit.capabilities["lan_buzzer_control"] is True


async def test_firmware_excludes_typed_humidity_without_aliasing_another_sensor(info):
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


async def test_snapshots_are_fresh_immutable_and_keep_their_hid_evidence(info):
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
    unit.handle_state_update(hid=ATW_HID)
    excluded_buzzer = unit.capabilities
    unit.handle_state_update(hid="malformed")
    assert before["power"] is None
    assert supported["power"] is None
    assert supported["lan_buzzer_control"] is True
    assert excluded_buzzer["power"] is None
    assert excluded_buzzer["lan_buzzer_control"] is False
    assert unit.capabilities["lan_buzzer_control"] is None
    assert type(unit) is AirConditionerDevice


@pytest.mark.parametrize("kind,hid", [
    (AirConditionerDevice, AC_HID),
    (DehumidifierDevice, AC_HID),
    (AirToWaterDevice, ATW_HID),
])
async def test_reports_local_values_and_model_do_not_change_evidence_or_probe(info, kind, hid):
    unit = kind(info)
    unit.bind = AsyncMock()
    unit.send = AsyncMock()
    unknown = unit.capabilities
    unit.handle_state_update(Pow=0, TemUn=0, TemSen=0, DwatSen=0,
                             AllInWatTemHi=100, AllInWatTemLo=0)
    assert unit.capabilities == unknown
    unit.handle_state_update(hid=hid)
    evidenced = unit.capabilities
    unit.handle_state_update(Pow=1, TemUn=1, TemSen=65, DwatSen=45)
    unit.set_property("Pow", 0)
    unit.set_property("TemSen", 0)
    unit.set_property("SetTem", 23)
    info.model = "Unrelated model"
    unit.version = "999"
    unit.ready.set()
    assert unit.capabilities == evidenced
    unit.ready.clear()
    assert unit.capabilities == evidenced
    unit.bind.assert_not_awaited()
    unit.send.assert_not_awaited()


async def test_family_instances_keep_independent_hid_evidence(info):
    first = AirConditionerDevice(info)
    second = AirConditionerDevice(info)
    first.handle_state_update(hid=AC_HID)
    second.handle_state_update(hid=ATW_HID)
    assert first.capabilities["power"] is None
    assert first.capabilities["lan_buzzer_control"] is True
    assert second.capabilities["power"] is None
    assert second.capabilities["lan_buzzer_control"] is False
    second.handle_state_update(hid="malformed")
    assert first.capabilities["power"] is None
    assert first.capabilities["lan_buzzer_control"] is True


async def test_known_dehumidifier_mid_declares_status_features_before_hid(info):
    info.mid = "13805"
    unit = DehumidifierDevice(info)
    supported = {
        "power", "target_humidity", "dehumidifier_mode", "current_humidity",
        "clean_filter", "water_full", "fan_speed", "light", "vertical_swing",
        "anion", "quiet",
    }
    before = unit.capabilities
    assert all(before[name] is True for name in supported)
    assert before["current_temperature"] is None
    assert before["temperature_units"] is None
    assert before["mode"] is False
    unit.handle_state_update(hid=AC_HID, Pow=1, Dmod=0, Dwet=6, DwatSen=45,
                             Dfltr=0, DwatFul=0, WdSpd=1, Lig=1, Quiet=0)
    assert unit.capabilities == before
    assert unit.target_humidity == 45
    assert unit.clean_filter is False


@pytest.mark.parametrize("kind", [Device, DehumidifierDevice, AirToWaterDevice])
async def test_buzzer_namespace_does_not_enable_other_families(info, kind):
    unit = kind(info)
    unit.handle_state_update(hid=AC_HID)
    expected = None if kind is Device else False
    assert unit.capabilities["lan_buzzer_control"] is expected


@pytest.mark.parametrize("kind,family,own_key,excluded,foreign", [
    (AirConditionerDevice, "air_conditioner", "quiet", "tank_target_temperature_c", "air_to_water"),
    (DehumidifierDevice, "dehumidifier", "target_humidity", "mode", "air_conditioner"),
    (AirToWaterDevice, "air_to_water", "tank_target_temperature_c", "quiet", "dehumidifier"),
])
async def test_profile_entries_require_matching_family_and_typed_key(
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


async def test_external_duplicate_entries_apply_in_order(info, monkeypatch):
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (
        DeviceProfile("362001064973", capabilities=(
            ("air_conditioner", "power", True),
            ("air_conditioner", "mode", False),
            ("air_conditioner", "power", False),
            ("air_conditioner", "mode", True),
        )),
    ))
    unit = AirConditionerDevice(info)
    unit.handle_state_update(hid=AC_HID)
    assert unit.capabilities["power"] is False
    assert unit.capabilities["mode"] is True
    assert unit.capabilities["quiet"] is None


async def test_capabilities_come_only_from_the_selected_profile_without_merging(info, monkeypatch):
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (
        DeviceProfile("362001064973", capabilities=(("air_conditioner", "power", True),)),
        DeviceProfile("362001066763", capabilities=(("air_conditioner", "quiet", True),)),
        DeviceProfile("different-code", capabilities=(("air_conditioner", "turbo", True),)),
    ))
    unit = AirConditionerDevice(info)
    unit.handle_state_update(hid=AC_HID)
    assert unit.capabilities["power"] is True
    assert unit.capabilities["quiet"] is None
    assert unit.capabilities["turbo"] is None
    unit.handle_state_update(hid="362001066763+arbitrary-module-and-version")
    assert unit.capabilities["power"] is None
    assert unit.capabilities["quiet"] is True
    assert unit.capabilities["turbo"] is None


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


async def test_ac_mid_evidence_precedes_hid_and_survives_hid_loss(info):
    info.mid = "10001"
    unit = AirConditionerDevice(info)
    unit.bind = AsyncMock()
    unit.send = AsyncMock()
    before = unit.capabilities
    for name in ("power", "mode", "target_temperature", "temperature_units",
                 "current_temperature", "fan_speed", "quiet", "turbo",
                 "steady_heat", "power_save"):
        assert before[name] is True
    assert before["sleep"] is None
    assert before["lan_buzzer_control"] is None
    assert unit.power is None
    assert unit.current_temperature is None
    unit.handle_state_update(hid=AC_HID)
    assert unit.capabilities["lan_buzzer_control"] is True
    for hid in (AC_HID, ATW_HID, "362001064973+U-W04NV19.bin", "malformed", None):
        unit.handle_state_update(hid=hid)
        assert unit.capabilities["power"] is True
        assert unit.capabilities["mode"] is True
        assert unit.capabilities["target_temperature"] is True
        assert unit.capabilities["quiet"] is True
        assert unit.capabilities["current_temperature"] is True
    assert unit.capabilities == before
    unit.bind.assert_not_awaited()
    unit.send.assert_not_awaited()


@pytest.mark.parametrize("hid,excluded", [
    ("362001063384+U-W04HBV1.20.bin",
     ("current_temperature", "anion", "light", "steady_heat", "lan_buzzer_control")),
    ("362001067592+U-W06DV4.01.bin", ("current_temperature",)),
    ("362001065634+U-WB04BRT13V1.50.bin", ("current_temperature",)),
    ("362001062617+U-W05SAV1.28.bin", ("current_temperature",)),
    ("362001067012+U-W06AV30.bin", ("current_temperature", "lan_buzzer_control")),
])
@pytest.mark.parametrize("suffix", ["", "+", "+U-NEWV999.bin", "+different-module"])
async def test_firmware_code_exclusions_override_mid_evidence(info, hid, excluded, suffix):
    info.mid = "10001"
    unit = AirConditionerDevice(info)
    baseline = unit.capabilities
    assert unit.capabilities["current_temperature"] is True
    unit.handle_state_update(hid=hid.partition("+")[0] + suffix, TemSen=65, Pow=1)
    snapshot = unit.capabilities
    assert all(snapshot[name] is False for name in excluded)
    assert snapshot["power"] is True
    unit.handle_state_update(hid="unknown-code+" + hid.partition("+")[2])
    assert unit.capabilities == baseline
    assert unit.capabilities["current_temperature"] is True
    assert snapshot["current_temperature"] is False


@pytest.mark.parametrize("hid,buzzer", [
    ("362001065634", True),
    ("362001062617+U-W05SAV1.28.bin", None),
    ("362001067012+U-W06AV30.bin", False),
])
async def test_gateway_exclusions_follow_code_not_build_and_snapshots_stay_fixed(info, hid, buzzer):
    info.mid = "10001"
    unit = AirConditionerDevice(info)
    unit.handle_state_update(hid=hid)
    excluded = unit.capabilities
    assert excluded["current_temperature"] is False
    assert unit._device_profile.temperature_offset is None
    unit.handle_state_update(hid=hid.partition("+")[0] + "+different-module-V999.bin")
    assert unit.capabilities["current_temperature"] is False
    assert unit.capabilities["lan_buzzer_control"] is buzzer
    unit.handle_state_update(hid="unknown-code+" + hid.partition("+")[2])
    assert unit.capabilities["current_temperature"] is True
    assert unit.capabilities["lan_buzzer_control"] is None
    assert excluded["current_temperature"] is False


async def test_mid_selection_is_fixed_for_each_instance_and_new_construction_reselects(info):
    fallback = DehumidifierDevice(info)
    unknown = fallback.capabilities
    info.mid = "13805"
    humidity_unit = DehumidifierDevice(info)
    humidity = humidity_unit.capabilities
    assert humidity["current_humidity"] is True
    assert humidity["current_temperature"] is None
    info.mid = "13802"
    sensor_unit = DehumidifierDevice(info)
    sensor = sensor_unit.capabilities
    assert sensor["current_humidity"] is None
    assert sensor["current_temperature"] is True
    info.mid = "10001"
    mismatched = DehumidifierDevice(info)
    assert all(mismatched.capabilities[name] is None for name in DEHUMIDIFIER_NAMES)
    assert fallback.capabilities == unknown
    assert humidity_unit.capabilities == humidity
    assert sensor_unit.capabilities == sensor
    assert type(fallback) is type(humidity_unit) is type(sensor_unit) is DehumidifierDevice
    with pytest.raises(TypeError):
        humidity["current_humidity"] = False


async def test_registry_changes_only_affect_new_instances(info, monkeypatch):
    info.mid = "10001"
    original = AirConditionerDevice(info)
    snapshot = original.capabilities
    assert snapshot["power"] is True
    monkeypatch.setattr(mid_profile, "KNOWN_MID_PROFILES", ())
    replacement = AirConditionerDevice(info)
    assert replacement.capabilities["power"] is None
    assert original.capabilities == snapshot


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


@pytest.mark.parametrize("kind,mid,names", [
    (AirConditionerDevice, "13805", AC_NAMES),
    (DehumidifierDevice, "10001", DEHUMIDIFIER_NAMES),
    (AirToWaterDevice, "10001", ATW_NAMES),
])
async def test_mid_family_mismatch_does_not_add_typed_evidence(info, kind, mid, names):
    info.mid = mid
    unit = kind(info)
    assert all(unit.capabilities[name] is None for name in names)


@pytest.mark.parametrize("mid", [None, "unmapped", "3027", "6400", "9301", "60", 10001, "10001 "])
async def test_unknown_or_unimplemented_mid_adds_no_family_evidence(info, mid):
    info.mid = mid
    unit = AirConditionerDevice(info)
    assert all(unit.capabilities[name] is None for name in AC_NAMES)


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


async def test_explicit_firmware_code_buzzer_override_is_not_replaced_by_namespace(info, monkeypatch):
    info.mid = "10001"
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (
        DeviceProfile("362001064973",
                      buzzer_properties=("Buzzer_ON_OFF",),
                      capabilities=(("air_conditioner", "lan_buzzer_control", False),)),
    ))
    unit = AirConditionerDevice(info)
    unit.handle_state_update(hid=AC_HID)
    assert unit.capabilities["lan_buzzer_control"] is False
    assert unit.capabilities["power"] is True
