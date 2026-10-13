"""Explicit Sinclair air-to-water API and wire-command regressions."""
import asyncio
import enum
from unittest.mock import AsyncMock

import pytest

from greeclimate.atw import AirToWaterDevice, AirToWaterMode
from greeclimate.cipher import CipherV1
from greeclimate.device import Mode, Props
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.exceptions import DeviceTimeoutError

pytestmark = pytest.mark.asyncio


class Wire(enum.Enum):
    POWER = "Pow"
    MODE = "Mod"
    HEATING = "HeWatOutTemSet"
    COOLING = "CoWatOutTemSet"
    TANK = "WatBoxTemSet"
    ROOM = "HeHomTemSet"
    UNIT = "TemUn"
    UNKNOWN = "UnsupportedControl"


@pytest.fixture
async def device():
    unit = AirToWaterDevice(
        DeviceInfo("127.0.0.1", 7000, "001122334455", "Synthetic ATW")
    )
    await unit.bind(key="0123456789abcdef", cipher=CipherV1())
    unit.send = AsyncMock()
    return unit


def receive(device, properties, response="dat", values="val"):
    """Deliver a fresh decoded envelope through the production packet handler."""
    if response == "dat":
        pack = {"t": "dat", "cols": list(properties), "dat": list(properties.values())}
    else:
        pack = {"t": "res", "opt": list(properties), values: list(properties.values())}
    device.packet_received({"t": "pack", "pack": pack}, ("127.0.0.1", 7000))


def sent_properties(device):
    message = device.send.await_args.args[0]
    assert message["pack"]["t"] == "cmd"
    assert message["pack"]["mac"] == "001122334455"
    pack = message["pack"]
    result = dict(zip(pack["opt"], pack["p"]))
    assert len(result) == len(pack["opt"]) == len(pack["p"])
    assert not {"SetTem", "TemRec", "TemUn", "BuzzerCtrl", "Buzzer_ON_OFF"} & result.keys()
    return result


async def test_issue_style_named_readings(device):
    receive(device, {
        "Pow": 0, "Mod": 1, "TemUn": 0,
        "AllInWatTemHi": 132, "AllInWatTemLo": 4,
        "AllOutWatTemHi": 132, "AllOutWatTemLo": 2,
        "RmoHomTemHi": 121, "RmoHomTemLo": 0,
        "WatBoxTemHi": 150, "WatBoxTemLo": 5,
        "HeWatOutTemSet": 35, "CoWatOutTemSet": 18, "WatBoxTemSet": 50,
        "HeHomTemSet": 20, "CoHomTemSet": 24,
        "HepOutWatTemHi": 70, "HepOutWatTemLo": 0,
        "AllErr": 0, "UnknownSensor": 123,
    })
    assert device.has_valid_state
    assert device.inlet_water_temperature_c == 32.4
    assert device.outlet_water_temperature_c == 32.2
    assert device.room_temperature_c == 21.0
    assert device.tank_temperature_c == 50.5
    assert device.heating_water_target_temperature_c == 35
    assert device.cooling_water_target_temperature_c == 18
    assert device.tank_target_temperature_c == 50
    assert device.heating_room_target_temperature_c == 20
    assert device.cooling_room_target_temperature_c == 24
    assert device.temperature_units == 0
    assert device.mode is AirToWaterMode.Heat
    assert device.power is False
    assert device.raw_properties["UnknownSensor"] == 123
    assert device.raw_properties["HepOutWatTemHi"] == 70
    for name in ("current_temperature", "target_temperature", "fan_speed", "buzzer"):
        assert not hasattr(device, name)


@pytest.mark.parametrize("properties", [
    {"TemUn": 0, "AllInWatTemHi": 132},
    {"TemUn": 0, "AllInWatTemLo": 4},
    {"TemUn": 0, "AllInWatTemHi": None, "AllInWatTemLo": 4},
    {"TemUn": 0, "AllInWatTemHi": 132, "AllInWatTemLo": None},
    {"TemUn": 0, "AllInWatTemHi": 132.0, "AllInWatTemLo": 4},
    {"TemUn": 0, "AllInWatTemHi": 132, "AllInWatTemLo": "4"},
    {"TemUn": 0, "AllInWatTemHi": True, "AllInWatTemLo": 4},
    {"TemUn": 0, "AllInWatTemHi": 132, "AllInWatTemLo": False},
    {"AllInWatTemHi": 132, "AllInWatTemLo": 4},
    {"TemUn": 1, "AllInWatTemHi": 132, "AllInWatTemLo": 4},
    {"TemUn": True, "AllInWatTemHi": 132, "AllInWatTemLo": 4},
    {"TemUn": None, "AllInWatTemHi": 132, "AllInWatTemLo": 4},
    {"TemUn": 2, "AllInWatTemHi": 132, "AllInWatTemLo": 4},
])
async def test_unavailable_temperature_preserves_raw_data(device, properties):
    receive(device, properties)
    assert device.inlet_water_temperature_c is None
    for key, value in properties.items():
        assert device.raw_properties[key] == value


async def test_partial_updates_and_negative_temperature(device):
    receive(device, {"TemUn": 0, "AllInWatTemHi": 70, "AllInWatTemLo": 0})
    assert device.inlet_water_temperature_c == -30.0
    receive(device, {"AllInWatTemHi": 132})
    assert device.inlet_water_temperature_c == 32.0
    receive(device, {"AllInWatTemLo": 4})
    assert device.inlet_water_temperature_c == 32.4
    receive(device, {"AllInWatTemLo": None})
    assert device.inlet_water_temperature_c is None
    receive(device, {"AllInWatTemLo": 2})
    assert device.inlet_water_temperature_c == 32.2


@pytest.mark.parametrize("name", [
    "heating_water_target_temperature_c", "cooling_water_target_temperature_c",
    "tank_target_temperature_c", "heating_room_target_temperature_c",
    "cooling_room_target_temperature_c",
])
async def test_targets_have_no_default(device, name):
    receive(device, {"TemUn": 0})
    assert getattr(device, name) is None


@pytest.mark.parametrize("value", [None, True, 20.0, "20"])
async def test_target_getters_require_integer(device, value):
    receive(device, {"TemUn": 0, "HeWatOutTemSet": value, "CoWatOutTemSet": value,
                     "WatBoxTemSet": value, "HeHomTemSet": value, "CoHomTemSet": value})
    for name in ("heating_water_target_temperature_c", "cooling_water_target_temperature_c",
                 "tank_target_temperature_c", "heating_room_target_temperature_c",
                 "cooling_room_target_temperature_c"):
        assert getattr(device, name) is None


async def test_target_getters_do_not_clip_and_require_celsius(device):
    receive(device, {"TemUn": 0, "HeWatOutTemSet": 90, "CoWatOutTemSet": -1,
                     "WatBoxTemSet": 100, "HeHomTemSet": -5, "CoHomTemSet": 99})
    names = ("heating_water_target_temperature_c", "cooling_water_target_temperature_c",
             "tank_target_temperature_c", "heating_room_target_temperature_c",
             "cooling_room_target_temperature_c")
    assert [getattr(device, name) for name in names] == [90, -1, 100, -5, 99]
    receive(device, {"TemUn": 1})
    assert all(getattr(device, name) is None for name in names)


@pytest.mark.parametrize("name", ["temperature_units", "heating_room_target_temperature_c",
                                  "cooling_room_target_temperature_c", "cooling_mode_value"])
async def test_read_only_properties(device, name):
    with pytest.raises(AttributeError):
        setattr(device, name, 0)


TARGETS = [
    ("heating_water_target_temperature_c", "HeWatOutTemSet", 20, 60),
    ("cooling_water_target_temperature_c", "CoWatOutTemSet", 7, 25),
    ("tank_target_temperature_c", "WatBoxTemSet", 40, 80),
]


@pytest.mark.parametrize("name,key,minimum,maximum", TARGETS)
@pytest.mark.parametrize("endpoint", ["minimum", "maximum"])
async def test_target_endpoints_emit_only_named_command(device, name, key, minimum, maximum, endpoint):
    receive(device, {"TemUn": 0})
    value = minimum if endpoint == "minimum" else maximum
    setattr(device, name, value)
    await device.push_state_update()
    assert sent_properties(device) == {key: value}


@pytest.mark.parametrize("name,key,minimum,maximum", TARGETS)
@pytest.mark.parametrize("invalid", ["below", "above", "float", "bool"])
async def test_invalid_target_preserves_pending_value(device, name, key, minimum, maximum, invalid):
    receive(device, {"TemUn": 0})
    setattr(device, name, minimum)
    value = {"below": minimum - 1, "above": maximum + 1,
             "float": float(minimum), "bool": True}[invalid]
    with pytest.raises(ValueError):
        setattr(device, name, value)
    assert getattr(device, name) == minimum
    device.send.assert_not_awaited()
    await device.push_state_update()
    assert sent_properties(device) == {key: minimum}


async def test_three_targets_share_unaugmented_command(device):
    receive(device, {"TemUn": 0})
    device.heating_water_target_temperature_c = 36
    device.cooling_water_target_temperature_c = 19
    device.tank_target_temperature_c = 51
    await device.push_state_update()
    assert sent_properties(device) == {"HeWatOutTemSet": 36, "CoWatOutTemSet": 19, "WatBoxTemSet": 51}


@pytest.mark.parametrize("configuration", [True, False, 1, 4, 0.0, 5.0, "5"])
async def test_invalid_cooling_configuration(configuration):
    with pytest.raises(ValueError):
        AirToWaterDevice(DeviceInfo("127.0.0.1", 7000, "001122334455", "ATW"),
                         cooling_mode_value=configuration)


@pytest.mark.parametrize("mode,wire", [
    (AirToWaterMode.Heat, 1), (AirToWaterMode.HotWater, 2),
    (AirToWaterMode.CoolHotWater, 3), (AirToWaterMode.HeatHotWater, 4),
])
async def test_named_mode_transitions(device, mode, wire):
    receive(device, {"Pow": 0, "Mod": 99})
    device.mode = mode
    await device.push_state_update()
    assert sent_properties(device) == {"Mod": wire}
    receive(device, {"Mod": wire}, response="res")
    assert device.mode is mode


@pytest.mark.parametrize("code", [0, 5])
async def test_explicit_cooling_mode(code):
    unit = AirToWaterDevice(DeviceInfo("127.0.0.1", 7000, "001122334455", "ATW"),
                            cooling_mode_value=code)
    await unit.bind(key="0123456789abcdef", cipher=CipherV1())
    unit.send = AsyncMock()
    assert unit.cooling_mode_value == code
    receive(unit, {"Pow": 0, "Mod": 1})
    unit.mode = AirToWaterMode.Cool
    await unit.push_state_update()
    assert sent_properties(unit) == {"Mod": code}
    receive(unit, {"Mod": code}, response="res", values="p")
    assert unit.mode is AirToWaterMode.Cool
    receive(unit, {"Mod": 5 if code == 0 else 0})
    assert unit.mode is None


@pytest.mark.parametrize("wire", [0, 5, 99, None, True, 1.0, "1"])
async def test_unknown_mode_readings(device, wire):
    receive(device, {"Mod": wire})
    assert device.mode is None


@pytest.mark.parametrize("value", [Mode.Cool, 1, "heat", None])
async def test_reject_non_atw_modes(device, value):
    receive(device, {"Pow": 0})
    with pytest.raises(ValueError):
        device.mode = value
    await device.push_state_update()
    device.send.assert_not_awaited()
    assert "Mod" not in device.raw_properties


async def test_cooling_requires_configuration(device):
    receive(device, {"Pow": 0, "Mod": 0})
    with pytest.raises(ValueError):
        device.mode = AirToWaterMode.Cool
    await device.push_state_update()
    device.send.assert_not_awaited()


@pytest.mark.parametrize("power", [1, None, True, 0.0, "0", 2])
async def test_changed_mode_requires_received_off_state(device, power):
    receive(device, {"Pow": power, "Mod": 1})
    with pytest.raises(ValueError):
        device.mode = AirToWaterMode.HotWater
    device.power = False
    with pytest.raises(ValueError):
        device.mode = AirToWaterMode.HotWater
    receive(device, {"Pow": 0})
    device.mode = AirToWaterMode.HotWater
    await device.push_state_update()
    command = sent_properties(device)
    assert command["Mod"] == 2
    assert command.keys() <= {"Pow", "Mod"}
    if "Pow" in command:
        assert command["Pow"] == 0


async def test_initially_unknown_power_and_omitted_reports(device):
    receive(device, {"Mod": 1})
    assert device.power is None
    with pytest.raises(ValueError):
        device.mode = AirToWaterMode.HotWater
    receive(device, {"Pow": 0})
    receive(device, {"AllErr": 0})
    device.mode = AirToWaterMode.HotWater
    await device.push_state_update()
    assert sent_properties(device) == {"Mod": 2}


async def test_identical_mode_is_noop_even_when_on(device):
    receive(device, {"Pow": 1, "Mod": 1})
    device.mode = AirToWaterMode.Heat
    await device.push_state_update()
    device.send.assert_not_awaited()


async def test_mode_revalidates_latest_power_and_retains_pending_command(device):
    receive(device, {"Pow": 0, "Mod": 1})
    device.mode = AirToWaterMode.HotWater
    receive(device, {"Pow": 1})
    with pytest.raises(ValueError):
        await device.push_state_update()
    device.send.assert_not_awaited()
    receive(device, {"Pow": 0})
    await device.push_state_update()
    assert sent_properties(device) == {"Mod": 2}


async def test_mode_and_power_on_cannot_be_batched(device):
    receive(device, {"Pow": 0, "Mod": 1})
    device.mode = AirToWaterMode.HotWater
    device.power = True
    with pytest.raises(ValueError):
        await device.push_state_update()
    device.send.assert_not_awaited()
    device.power = False
    await device.push_state_update()
    assert sent_properties(device) == {"Mod": 2, "Pow": 0}


@pytest.mark.parametrize("unit", [None, 1, True, 2])
async def test_target_writes_require_reported_celsius(device, unit):
    receive(device, {"TemUn": unit})
    for name, key, minimum, maximum in TARGETS:
        with pytest.raises(ValueError):
            setattr(device, name, minimum)
        assert key not in device.raw_properties
    await device.push_state_update()
    device.send.assert_not_awaited()
    device.power = True
    await device.push_state_update()
    assert sent_properties(device) == {"Pow": 1}


async def test_queued_targets_revalidate_reported_units(device):
    receive(device, {"TemUn": 0})
    device.heating_water_target_temperature_c = 35
    receive(device, {"TemUn": 1})
    with pytest.raises(ValueError):
        await device.push_state_update()
    device.send.assert_not_awaited()
    receive(device, {"TemUn": 0})
    await device.push_state_update()
    assert sent_properties(device) == {"HeWatOutTemSet": 35}


@pytest.mark.parametrize("value", [0, 1, None, "on"])
async def test_power_setter_requires_bool(device, value):
    with pytest.raises(ValueError):
        device.power = value
    await device.push_state_update()
    device.send.assert_not_awaited()


@pytest.mark.parametrize("wire,expected", [(0, False), (1, True), (None, None),
                                            (True, None), (0.0, None), (2, None)])
async def test_power_getter_requires_integer_wire_value(device, wire, expected):
    receive(device, {"Pow": wire})
    assert device.power is expected


@pytest.mark.parametrize("prop,value", [
    (Props.TEMP_SET, 25), (Wire.ROOM, 20), (Wire.UNIT, 1), (Wire.UNKNOWN, 1),
    (Wire.POWER, True), (Wire.POWER, 2), (Wire.MODE, True), (Wire.MODE, 99),
    (Wire.MODE, 5), (Wire.HEATING, 19), (Wire.COOLING, 26), (Wire.TANK, 39),
    (Wire.HEATING, 35.0), (Wire.COOLING, True),
])
async def test_generic_setter_cannot_bypass_command_validation(device, prop, value):
    receive(device, {"Pow": 0, "TemUn": 0})
    device.set_property(prop, value)
    with pytest.raises(ValueError):
        await device.push_state_update()
    device.send.assert_not_awaited()
    assert device.raw_properties[prop.value] == value


async def test_generic_mode_and_targets_still_require_reported_state(device):
    device.set_property(Wire.MODE, 2)
    with pytest.raises(ValueError):
        await device.push_state_update()
    device.send.assert_not_awaited()
    receive(device, {"Pow": 0})
    device.set_property(Wire.HEATING, 35)
    with pytest.raises(ValueError):
        await device.push_state_update()
    device.send.assert_not_awaited()
    receive(device, {"TemUn": 0})
    await device.push_state_update()
    assert sent_properties(device) == {"Mod": 2, "HeWatOutTemSet": 35}


async def test_timeout_retains_dirty_values_until_success(device):
    receive(device, {"TemUn": 0})
    device.heating_water_target_temperature_c = 36
    device.send.side_effect = asyncio.TimeoutError
    with pytest.raises(DeviceTimeoutError):
        await device.push_state_update()
    assert sent_properties(device) == {"HeWatOutTemSet": 36}
    device.send.side_effect = None
    await device.push_state_update()
    assert sent_properties(device) == {"HeWatOutTemSet": 36}
    assert device.send.await_count == 2
    await device.push_state_update()
    assert device.send.await_count == 2


@pytest.mark.parametrize("values", ["val", "p"])
async def test_result_response_updates_named_readings(device, values):
    receive(device, {"TemUn": 0, "AllInWatTemHi": 132, "AllInWatTemLo": 4,
                     "HeWatOutTemSet": 36, "CoWatOutTemSet": 19, "WatBoxTemSet": 51},
            response="res", values=values)
    assert device.inlet_water_temperature_c == 32.4
    assert device.heating_water_target_temperature_c == 36
    assert device.cooling_water_target_temperature_c == 19
    assert device.tank_target_temperature_c == 51


async def test_status_poll_requests_atw_sensors_not_ac_controls(device):
    await device.update_state()
    message = device.send.await_args.args[0]
    assert message["pack"]["t"] == "status"
    columns = message["pack"]["cols"]
    assert {"Pow", "Mod", "TemUn", "AllErr", "HeWatOutTemSet", "CoWatOutTemSet",
            "WatBoxTemSet", "HeHomTemSet", "CoHomTemSet", "AllInWatTemHi",
            "AllInWatTemLo", "AllOutWatTemHi", "AllOutWatTemLo", "RmoHomTemHi",
            "RmoHomTemLo", "WatBoxTemHi", "WatBoxTemLo", "HepOutWatTemHi",
            "HepOutWatTemLo", "WatBoxElcHeRunSta", "SyAnFroRunSta", "ElcHe1RunSta",
            "ElcHe2RunSta", "AnFrzzRunSta", "hid"} <= set(columns)
    assert len(columns) == len(set(columns))
    assert not {"SetTem", "TemSen", "WdSpd", "TemRec", "BuzzerCtrl"} & set(columns)
    receive(device, {"hid": "362001066763+U-W06A(P3)V6.04.bin"})
    assert device.hid == "362001066763+U-W06A(P3)V6.04.bin"
    await device.update_state()
    assert "hid" not in device.send.await_args.args[0]["pack"]["cols"]


async def test_local_unit_staging_does_not_establish_reported_celsius(device):
    device.set_property(Wire.UNIT, 0)
    assert device.temperature_units is None
    with pytest.raises(ValueError):
        device.heating_water_target_temperature_c = 35
    device.send.assert_not_awaited()


@pytest.mark.parametrize("value", [False, True])
async def test_power_commands_work_before_any_report(device, value):
    device.power = value
    assert device.power is value
    await device.push_state_update()
    assert sent_properties(device) == {"Pow": int(value)}


async def test_received_invalid_unit_clears_previous_celsius(device):
    receive(device, {"TemUn": 0, "AllInWatTemHi": 132, "AllInWatTemLo": 4})
    assert device.temperature_units == 0
    receive(device, {"TemUn": True})
    assert device.temperature_units is None
    assert device.inlet_water_temperature_c is None
    receive(device, {"AllInWatTemLo": 2})
    assert device.temperature_units is None
    with pytest.raises(ValueError):
        device.heating_water_target_temperature_c = 35
