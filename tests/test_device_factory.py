"""Exact-MID family selection without binding or firmware inference."""
import asyncio
from unittest.mock import AsyncMock, Mock

import pytest

from greeclimate import device_profile
from greeclimate.air_conditioner import AirConditionerDevice
from greeclimate.air_to_water import AirToWaterDevice, AirToWaterMode
from greeclimate.cipher import CipherV1
from greeclimate.dehumidifier import DehumidifierDevice
from greeclimate.device import Device, TemperatureUnits
from greeclimate.device_factory import create_device
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.discovery import Discovery, Listener

pytestmark = pytest.mark.asyncio

KNOWN_HID = "362001066763+U-W06A(P3)V6.04.bin"


def info(mid=None):
    return DeviceInfo("127.0.0.1", 7000, "001122334455", "SMH-100IRB",
                      "gree", "gree", mid=mid)



async def capture(unit):
    await unit.bind(key="0123456789abcdef", cipher=CipherV1())
    unit.connection_made(Mock(get_extra_info=Mock(return_value=("127.0.0.1", 7000))))
    unit.ready.set()
    unit.send = AsyncMock()
    return unit



def receive(unit, properties):
    unit.packet_received({"t": "pack", "pack": {
        "t": "dat", "cols": list(properties), "dat": list(properties.values()),
    }}, ("127.0.0.1", 7000))



def command(unit):
    pack = unit.send.await_args.args[0]["pack"]
    assert pack["t"] == "cmd"
    return dict(zip(pack["opt"], pack["p"]))



@pytest.mark.parametrize("mid,device_type", [
    *((mid, AirConditionerDevice) for mid in (
        "0001", "10f01", "10f02", "10001", "10002", "10007", "11001", "11002",
        "12000", "12001", "12002", "12003", "13000", "15000", "809032", "3018",
        "3019", "302b", "3062", "4005",
    )),
    *((mid, DehumidifierDevice) for mid in (
        "13800", "13802", "13803", "13804", "13805", "13806",
    )),
    ("9300", AirToWaterDevice),
])
async def test_factory_selects_exact_implemented_family_without_binding(monkeypatch, mid, device_type):
    bind = AsyncMock()
    send = AsyncMock()
    monkeypatch.setattr(Device, "bind", bind)
    monkeypatch.setattr(Device, "send", send)
    metadata = info(mid)
    unit = create_device(metadata)
    assert type(unit) is device_type
    assert unit.device_info is metadata
    assert unit.device_info.mid == mid
    assert unit.hid is None
    bind.assert_not_awaited()
    send.assert_not_awaited()



async def test_ac_factory_result_encodes_typed_temperature_command():
    unit = await capture(create_device(info("10001")))
    assert type(unit) is AirConditionerDevice
    receive(unit, {"TemUn": 0, "TemRec": 0, "SetTem": 20,
                   "hid": "362001064973+U-W04NV17.bin"})
    unit.temperature_units = TemperatureUnits.C
    unit.target_temperature = 23
    await unit.push_state_update()
    assert command(unit) == {"SetTem": 23, "TemRec": 0, "TemUn": 0}
    assert unit.target_temperature == 23



async def test_dehumidifier_factory_result_encodes_only_humidity_command():
    unit = await capture(create_device(info("13805")))
    assert type(unit) is DehumidifierDevice
    receive(unit, {"Dwet": 0, "TemUn": 0, "TemRec": 0, "SetTem": 20,
                   "hid": "362001064973+U-W04NV17.bin"})
    unit.target_humidity = 45
    await unit.push_state_update()
    assert command(unit) == {"Dwet": 6}
    assert unit.target_humidity == 45
    for name in ("mode", "target_temperature", "buzzer"):
        assert not hasattr(unit, name)



@pytest.mark.parametrize("mid", [
    None, "", "unknown", 9300, 10001, "9300 ", " 10001", "10001 ", "10F01",
    "302B", "010001", "100010", [], {}, "13801", "11000", "11005", "11010",
    "3027", "6000", "6400", "807002", "9301", "9302", "60", "82000", "82002",
    "5000", "5001", "605d", "6098", "828100", "828214", "910001",
])
@pytest.mark.parametrize("hid", [KNOWN_HID, "362001064973+U-W04NV17.bin"])
async def test_unmatched_mid_remains_raw_only_after_known_hid_and_model(mid, hid):
    metadata = info(mid)
    metadata.model = "10001"
    unit = await capture(create_device(metadata))
    assert type(unit) is Device
    receive(unit, {"Pow": 0, "Mod": 1, "TemUn": 0, "hid": hid,
                   "TemRec": 0, "SetTem": 20, "TemSen": 20})
    metadata.model = "9300"
    assert unit.device_info.mid == mid
    assert unit.get_property("TemSen") == 20
    for name in ("power", "mode", "current_temperature", "target_temperature",
                 "target_humidity", "buzzer", "cooling_mode_value"):
        assert not hasattr(unit, name)
    unit.set_property("SetTem", 23)
    await unit.push_state_update()
    assert command(unit) == {"SetTem": 23}
    assert type(unit) is Device



@pytest.mark.parametrize("mid", [None, "10001", "13805", "9300"])
async def test_factory_forwards_timeouts_and_loop(mid):
    loop = asyncio.get_running_loop()
    unit = create_device(info(mid), timeout=23, bind_timeout=7, loop=loop)
    try:
        assert unit._timeout == 23
        assert unit._bind_timeout == 7
        assert unit._loop is loop
    finally:
        unit.close()


@pytest.mark.parametrize("mid", [None, "10001", "13805", "9300"])
async def test_selected_constructor_rejects_unsupported_settings(mid):
    with pytest.raises(TypeError):
        create_device(info(mid), unsupported_setting=True)


async def test_atw_factory_result_accepts_bounded_explicit_status_query():
    unit = await capture(create_device(info("9300")))
    columns = ["Pow", "Mod", "TemUn", "HeWatOutTemSet"]
    await unit.update_state(columns)
    pack = unit.send.await_args.args[0]["pack"]
    assert pack["t"] == "status"
    assert pack["cols"] == ["Pow", "Mod", "TemUn", "HeWatOutTemSet"]
    assert columns == ["Pow", "Mod", "TemUn", "HeWatOutTemSet"]



async def test_discovery_mid_selects_atw_before_reported_firmware():
    delivered = asyncio.Queue()

    class Receiver(Listener):
        async def device_found(self, device_info):
            delivered.put_nowait(device_info)

    discovery = Discovery()
    discovery.add_listener(Receiver())
    discovery.packet_received({"t": "pack", "pack": {
        "t": "dev", "mac": "001122334455", "mid": "9300",
        "name": "Synthetic", "brand": "gree", "model": "gree",
    }}, ("127.0.0.1", 7000))
    await asyncio.gather(*discovery.tasks)
    unit = create_device(delivered.get_nowait())
    assert isinstance(unit, AirToWaterDevice)
    assert unit.hid is None and unit.cooling_mode_value is None
    await capture(unit)
    receive(unit, {"Pow": 0, "Mod": 2, "TemUn": 0,
                   "AllInWatTemHi": 132, "AllInWatTemLo": 4,
                   "HeWatOutTemSet": 35})
    assert unit.inlet_water_temperature_c == 32.4
    unit.heating_water_target_temperature_c = 36
    await unit.push_state_update()
    assert command(unit) == {"HeWatOutTemSet": 36}
    unit.mode = AirToWaterMode.Heat
    await unit.push_state_update()
    assert command(unit) == {"Mod": 1}
    with pytest.raises(ValueError):
        unit.mode = AirToWaterMode.Cool
    receive(unit, {"hid": KNOWN_HID})
    assert unit.inlet_water_temperature_c == 32.4
    assert unit.heating_water_target_temperature_c == 36
    unit.mode = AirToWaterMode.Cool
    await unit.push_state_update()
    assert command(unit) == {"Mod": 5}



@pytest.mark.parametrize("hid", [
    KNOWN_HID,
    "362001066763+W06A(P3)V6.0.bin",
    "362001066763+U-OTHER(LT)V7.12.bin",
    "362001066763", "362001066763+", "362001066763+incomplete",
    KNOWN_HID.replace("6.04", "6..04"), KNOWN_HID + "extra",
])
async def test_sinclair_ignores_module_and_version(hid):
    unit = await capture(create_device(info("9300")))
    receive(unit, {"Pow": 0, "Mod": 1, "hid": hid})
    unit.mode = AirToWaterMode.Cool
    await unit.push_state_update()
    assert command(unit) == {"Mod": 5}



@pytest.mark.parametrize("hid", [
    None, "", 9300, "unknown", "362001066763extra", "extra362001066763",
    KNOWN_HID.replace("362001066763", "3620010667630"),
])
async def test_sinclair_mid_without_matching_hid_retains_atw_without_cooling(hid):
    unit = await capture(create_device(info("9300")))
    assert isinstance(unit, AirToWaterDevice)
    assert unit.cooling_mode_value is None
    receive(unit, {"Pow": 0, "Mod": 1, "hid": hid, "TemUn": 0,
                   "HeWatOutTemSet": 35})
    assert unit.cooling_mode_value is None
    with pytest.raises(ValueError):
        unit.mode = AirToWaterMode.Cool
    unit.heating_water_target_temperature_c = 36
    await unit.push_state_update()
    assert command(unit) == {"HeWatOutTemSet": 36}



@pytest.mark.parametrize("mid", ["9300", None, "unknown"])
async def test_cooling_uses_firmware_code_not_discovery_or_display_version(monkeypatch, mid):
    profile = device_profile.DeviceProfile(
        firmware_code="362001066763", cooling_mode_value=5)
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (profile,))
    metadata = info(mid)
    metadata.version = "99.0"
    unit = await capture(AirToWaterDevice(metadata))
    assert unit.cooling_mode_value is None
    receive(unit, {"Pow": 0, "Mod": 1,
                   "hid": "999999999999+U-OTHERV99.bin"})
    assert unit.cooling_mode_value is None
    with pytest.raises(ValueError):
        unit.mode = AirToWaterMode.Cool
    for hid in ["362001066763", "362001066763+",
                "362001066763+U-OTHERV6.9.bin",
                "362001066763+U-OTHERV6.10.0.bin"]:
        receive(unit, {"hid": hid})
        assert unit.cooling_mode_value == 5
        unit.version = "0"
        assert unit.cooling_mode_value == 5
        unit.mode = AirToWaterMode.Cool
        await unit.push_state_update()
        assert command(unit) == {"Mod": 5}
        receive(unit, {"Mod": 1})



@pytest.mark.parametrize("options,expected", [
    ({}, 5), ({"cooling_mode_value": 0}, 0),
    ({"cooling_mode_value": 5}, 5), ({"cooling_mode_value": None}, None),
])
async def test_explicit_cooling_override_is_independent(options, expected):
    unit = await capture(create_device(info("9300"), **options))
    receive(unit, {"Pow": 0, "Mod": 1, "hid": KNOWN_HID})
    assert unit.cooling_mode_value == expected
    if expected is None:
        with pytest.raises(ValueError):
            unit.mode = AirToWaterMode.Cool
        await unit.push_state_update()
        unit.send.assert_not_awaited()
    else:
        unit.mode = AirToWaterMode.Cool
        await unit.push_state_update()
        assert command(unit) == {"Mod": expected}
    for hid in (KNOWN_HID, "unrecognized", KNOWN_HID):
        receive(unit, {"hid": hid})
        assert unit.cooling_mode_value == (expected if options or hid == KNOWN_HID else None)
    separate = await capture(create_device(info("9300")))
    receive(separate, {"hid": KNOWN_HID})
    assert separate.cooling_mode_value == 5



@pytest.mark.parametrize("value", [True, 3])
async def test_selected_constructor_rejects_invalid_cooling(value):
    with pytest.raises(ValueError, match="cooling_mode_value must be None, 0 or 5"):
        create_device(info("9300"), cooling_mode_value=value)



@pytest.mark.parametrize("mid", ["unknown", "10001", "13805"])
async def test_non_atw_constructor_rejects_atw_only_settings(mid):
    with pytest.raises(TypeError):
        create_device(info(mid), cooling_mode_value=0)



async def test_profile_instances_have_independent_staged_state():
    first = await capture(create_device(info("9300")))
    second = await capture(create_device(info("9300")))
    for unit in (first, second):
        receive(unit, {"Pow": 0, "Mod": 1, "hid": KNOWN_HID,
                       "TemUn": 0, "HeWatOutTemSet": 35})
    first.heating_water_target_temperature_c = 36
    await first.push_state_update()
    await second.push_state_update()
    assert command(first) == {"HeWatOutTemSet": 36}
    assert second.heating_water_target_temperature_c == 35
    second.send.assert_not_awaited()

