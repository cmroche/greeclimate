import asyncio
import enum
from unittest.mock import patch, AsyncMock

import pytest

from greeclimate.device import Device, DeviceInfo, Props, TemperatureUnits
from greeclimate.discovery import Discovery
from greeclimate.exceptions import DeviceNotBoundError, DeviceTimeoutError


class FakeProps(enum.Enum):
    FAKE = "fake"


def get_mock_info():
    return (
        "1.1.1.0",
        "7000",
        "aabbcc001122",
        "MockDevice1",
        "MockBrand",
        "MockModel",
        "0.0.1-fake",
    )


def get_mock_state():
    return {
        "Pow": 1,
        "Mod": 3,
        "SetTem": 25,
        "TemSen": 29,
        "TemUn": 0,
        "WdSpd": 0,
        "Air": 0,
        "Blo": 0,
        "Health": 0,
        "SwhSlp": 0,
        "SlpMod": 0,
        "Lig": 1,
        "SwingLfRig": 1,
        "SwUpDn": 1,
        "Quiet": 0,
        "Tur": 0,
        "StHt": 0,
        "SvSt": 0,
        "TemRec": 0,
        "HeatCoolType": 0,
        "hid": "362001000762+U-CS532AE(LT)V3.31.bin",
        "Dmod": 0,
        "Dwet": 5,
        "DwatSen": 58,
        "Dfltr": 0,
        "DwatFul": 0,
    }


def get_mock_state_off():
    return {
        "Pow": 0,
        "Mod": 0,
        "SetTem": 0,
        "TemSen": 0,
        "TemUn": 0,
        "WdSpd": 0,
        "Air": 0,
        "Blo": 0,
        "Health": 0,
        "SwhSlp": 0,
        "SlpMod": 0,
        "Lig": 0,
        "SwingLfRig": 0,
        "SwUpDn": 0,
        "Quiet": 0,
        "Tur": 0,
        "StHt": 0,
        "SvSt": 0,
        "TemRec": 0,
        "HeatCoolType": 0,
        "Dmod": 0,
        "Dwet": 0,
        "DwatSen": 0,
        "Dfltr": 0,
        "DwatFul": 0,
    }


def get_mock_state_on():
    return {
        "Pow": 1,
        "Mod": 1,
        "SetTem": 1,
        "TemSen": 1,
        "TemUn": 1,
        "WdSpd": 1,
        "Air": 1,
        "Blo": 1,
        "Health": 1,
        "SwhSlp": 1,
        "SlpMod": 1,
        "Lig": 1,
        "SwingLfRig": 1,
        "SwUpDn": 1,
        "Quiet": 2,
        "Tur": 1,
        "StHt": 1,
        "SvSt": 1,
        "TemRec": 0,
        "HeatCoolType": 0,
        "Dmod": 0,
        "Dwet": 3,
        "DwatSen": 1,
        "Dfltr": 0,
        "DwatFul": 0,
    }


def get_mock_state_no_temperature():
    return {
        "Pow": 1,
        "Mod": 3,
        "SetTem": 25,
        "TemUn": 0,
        "WdSpd": 0,
        "Air": 0,
        "Blo": 0,
        "Health": 0,
        "SwhSlp": 0,
        "SlpMod": 0,
        "Lig": 1,
        "SwingLfRig": 1,
        "SwUpDn": 1,
        "Quiet": 0,
        "Tur": 0,
        "StHt": 0,
        "SvSt": 0,
        "TemRec": 0,
        "HeatCoolType": 0,
        "Dmod": 0,
        "Dwet": 1,
        "DwatSen": 1,
        "Dfltr": 0,
        "DwatFul": 0,
    }


def get_mock_state_bad_temp():
    return {"TemSen": 69, "hid": "362001060297+U-CS532AF(MTK).bin"}


def get_mock_state_0c_v4_temp():
    return {"TemSen": 0, "hid": "362001000762+U-CS532AE(LT)V4.bin"}


def get_mock_state_0c_v3_temp():
    return {"TemSen": 0, "hid": "362001000762+U-CS532AE(LT)V3.31.bin"}


async def generate_device_mock_async():
    d = Device(DeviceInfo("192.168.1.29", 7000, "f4911e7aca59", "1e7aca59"))
    await d.bind(key="St8Vw1Yz4Bc7Ef0H")
    return d


def test_device_info_equality():
    """The only way to get the key through binding is by scanning first"""

    props = [
        "1.1.1.0",
        "7000",
        "aabbcc001122",
        "MockDevice1",
        "MockBrand",
        "MockModel",
        "0.0.1-fake",
    ]

    # When all properties match the device info is the same
    assert DeviceInfo(*props) == DeviceInfo(*props)

    # When any property differs the device info is not the same
    for i in range(2, len(props)):
        new_props = props.copy()
        new_props[i] = "modified_prop"
        assert DeviceInfo(*new_props) != DeviceInfo(*props)


@pytest.mark.asyncio
async def test_get_device_info():
    """Initialize device, check properties."""

    info = DeviceInfo(*get_mock_info())
    device = Device(info)

    assert device.device_info == info

    fake_key = "abcdefgh12345678"
    await device.bind(key=fake_key)

    assert device.device_key == fake_key


@pytest.mark.asyncio
async def test_device_bind():
    """Check that the device returns a device key when binding."""

    info = DeviceInfo(*get_mock_info())
    device = Device(info, timeout=1)

    assert device.device_info == info

    fake_key = "abcdefgh12345678"

    def fake_send(*args):
        """Emulate a bind event"""
        device.ready.set()
        device.handle_device_bound(fake_key)

    with patch.object(Device, "send", side_effect=fake_send) as mock:
        await device.bind()
        assert mock.call_count == 1

    assert device.device_key == fake_key


@pytest.mark.asyncio
async def test_device_bind_timeout():
    """Check that the device handles timeout errors when binding."""

    info = DeviceInfo(*get_mock_info())
    device = Device(info, timeout=1)

    assert device.device_info == info

    with pytest.raises(DeviceTimeoutError):
        with patch.object(Device, "send", return_value=None) as mock:
            await device.bind()
            assert mock.call_count == 1

    assert device.device_key is None


@pytest.mark.asyncio
async def test_device_bind_none():
    """Check that the device handles bad binding sequences."""

    info = DeviceInfo(*get_mock_info())
    device = Device(info)

    assert device.device_info == info

    fake_key = None

    def fake_send(*args):
        """Emulate a bind event"""
        device.ready.set()

    with pytest.raises(DeviceNotBoundError):
        with patch.object(Device, "send", side_effect=fake_send) as mock:
            await device.bind()
            assert mock.call_count == 1

    assert device.device_key is None


@pytest.mark.asyncio
@patch("greeclimate.network.request_state")
@patch("greeclimate.network.send_state")
async def test_device_late_bind(mock_push, mock_update):
    """Check that the device handles late binding sequences."""
    mock_update.return_value = {}
    mock_push.return_value = []

    info = DeviceInfo(*get_mock_info())
    device = Device(info, timeout=1)
    assert device.device_info == info

    fake_key = "abcdefgh12345678"

    def fake_send(*args):
        """Emulate a bind event"""
        device.handle_device_bound(fake_key)
        device.ready.set()

    with patch.object(Device, "send", side_effect=fake_send) as mock:
        await device.update_state()
        assert mock.call_count == 1
        assert device.device_key == fake_key

        device.device_key = None
        device.power = True
        await device.push_state_update()
        assert device.device_key == fake_key


@pytest.mark.asyncio
@patch("greeclimate.network.request_state")
async def test_update_properties(mock_request):
    """Check that properties can be updates."""
    mock_request.return_value = get_mock_state()
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    await device.update_state()

    for p in Props:
        assert device.get_property(p) is not None
        assert device.get_property(p) == get_mock_state()[p.value]


@pytest.mark.asyncio
@patch("greeclimate.network.request_state", side_effect=asyncio.TimeoutError)
async def test_update_properties_timeout(mock_request):
    """Check that timeouts are handled when properties are updates."""
    mock_request.return_value = get_mock_state()
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    with pytest.raises(DeviceTimeoutError):
        await device.update_state()


@pytest.mark.asyncio
@patch("greeclimate.network.send_state")
async def test_set_properties_not_dirty(mock_request):
    """Check that teh state isn't pushed when properties unchanged."""
    device = await generate_device_mock_async()

    await device.push_state_update()

    assert mock_request.call_count == 0


@pytest.mark.asyncio
@patch("greeclimate.network.send_state")
async def test_set_properties(mock_request):
    """Check that state is pushed when properties are updated."""
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    device.power = True
    device.mode = 1
    device.temperature_units = 1
    device.fan_speed = 1
    device.fresh_air = True
    device.xfan = True
    device.anion = True
    device.sleep = True
    device.light = True
    device.horizontal_swing = 1
    device.vertical_swing = 1
    device.quiet = True
    device.turbo = True
    device.steady_heat = True
    device.power_save = True
    device.target_humidity = 30

    await device.push_state_update()

    mock_request.assert_called_once()

    for p in Props:
        if p not in (
            Props.TEMP_SENSOR,
            Props.TEMP_SET,
            Props.TEMP_BIT,
            Props.UNKNOWN_HEATCOOLTYPE,
            Props.HUM_SENSOR,
            Props.DEHUMIDIFIER_MODE,
            Props.WATER_FULL,
            Props.CLEAN_FILTER,
        ):
            assert device.get_property(p) is not None
            assert device.get_property(p) == get_mock_state_on()[p.value]


@pytest.mark.asyncio
@patch("greeclimate.network.send_state", side_effect=asyncio.TimeoutError)
async def test_set_properties_timeout(mock_request):
    """Check timeout handling when pushing state changes."""
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    device.power = True
    device.mode = 1
    device.temperature_units = 1
    device.fan_speed = 1
    device.fresh_air = True
    device.xfan = True
    device.anion = True
    device.sleep = True
    device.light = True
    device.horizontal_swing = 1
    device.vertical_swing = 1
    device.quiet = True
    device.turbo = True
    device.steady_heat = True
    device.power_save = True

    with pytest.raises(DeviceTimeoutError):
        await device.push_state_update()


@pytest.mark.asyncio
async def test_uninitialized_properties():
    """Check uninitialized property handling."""
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    assert not device.power
    assert device.mode is None
    assert device.target_temperature is None
    assert device.current_temperature is None
    assert device.temperature_units is None
    assert device.fan_speed is None
    assert not device.fresh_air
    assert not device.xfan
    assert not device.anion
    assert not device.sleep
    assert not device.light
    assert device.horizontal_swing is None
    assert device.vertical_swing is None
    assert not device.quiet
    assert not device.turbo
    assert not device.steady_heat
    assert not device.power_save


@pytest.mark.asyncio
@patch("greeclimate.network.request_state")
async def test_update_current_temp_unsupported(mock_request):
    """Check that properties can be updates."""
    mock_request.return_value = get_mock_state_no_temperature()
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    await device.update_state()

    assert device.get_property(Props.TEMP_SENSOR) is None
    assert device.current_temperature == device.target_temperature


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "temsen,hid",
    [
        (69, "362001000762+U-CS532AE(LT)V3.31.bin"),
        (61, "362001061060+U-W04HV3.29.bin"),
        (62, "362001061147+U-ZX6045RV1.01.bin"),
    ],
)
@patch("greeclimate.network.request_state")
async def test_update_current_temp_v3(mock_request, temsen, hid):
    """Check that properties can be updates."""
    mock_request.return_value = {"TemSen": temsen, "hid": hid}
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    await device.update_state()

    assert device.get_property(Props.TEMP_SENSOR) is not None
    assert device.current_temperature == temsen - 40


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "temsen,hid",
    [
        (21, "362001060297+U-CS532AF(MTK)V4.bin"),
        (21, "362001060297+U-CS532AF(MTK)V2.bin"),
        (22, "362001061383+U-BL3332_JDV1.bin"),
        (23, "362001061217+U-W04NV7.bin"),
    ],
)
@patch("greeclimate.network.request_state")
async def test_update_current_temp_v4(mock_request, temsen, hid):
    """Check that properties can be updates."""
    mock_request.return_value = {"TemSen": temsen, "hid": hid}
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    await device.update_state()

    assert device.get_property(Props.TEMP_SENSOR) is not None
    assert device.current_temperature == temsen


@pytest.mark.asyncio
@patch("greeclimate.network.request_state")
async def test_update_current_temp_bad(mock_request):
    """Check that properties can be updates."""
    mock_request.return_value = get_mock_state_bad_temp()
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    await device.update_state()

    assert device.current_temperature == get_mock_state_bad_temp()["TemSen"] - 40


@pytest.mark.asyncio
@patch("greeclimate.network.request_state")
async def test_update_current_temp_0C_v4(mock_request):
    """Check that properties can be updates."""
    mock_request.return_value = get_mock_state_0c_v4_temp()
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    await device.update_state()

    assert device.current_temperature == get_mock_state_0c_v4_temp()["TemSen"]


@pytest.mark.asyncio
@patch("greeclimate.network.request_state")
async def test_update_current_temp_0C_v3(mock_request):
    """Check for devices without a temperature sensor."""
    mock_request.return_value = get_mock_state_0c_v3_temp()
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    await device.update_state()

    assert device.current_temperature == device.target_temperature


@pytest.mark.asyncio
@pytest.mark.parametrize("temperature", [18, 19, 20, 21, 22])
@patch("greeclimate.network.send_state")
@patch("greeclimate.network.request_state")
async def test_send_temperature_celsius(mock_request, mock_push, temperature):
    """Check that temperature is set and read properly in C."""
    state = get_mock_state()
    state["TemSen"] = temperature + 40
    mock_request.return_value = state
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    device.temperature_units = TemperatureUnits.C
    device.target_temperature = temperature
    await device.push_state_update()
    await device.update_state()

    assert device.current_temperature == temperature
    assert mock_push.call_count == 1
    assert mock_push.call_args.args[0] == {
        "SetTem": temperature,
        "TemRec": None,
        "TemUn": 0,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "temperature", [60, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 86]
)
@patch("greeclimate.network.send_state")
@patch("greeclimate.network.request_state")
async def test_send_temperature_farenheit(mock_request, mock_push, temperature):
    """Check that temperature is set and read properly in F."""
    temSet = round((temperature - 32.0) * 5.0 / 9.0)
    temRec = (int)((((temperature - 32.0) * 5.0 / 9.0) - temSet) > 0)

    state = get_mock_state()
    state["TemSen"] = temSet + 40
    state["TemRec"] = temRec
    state["TemUn"] = 1
    mock_request.return_value = state
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    device.temperature_units = TemperatureUnits.F
    device.target_temperature = temperature
    await device.push_state_update()
    await device.update_state()

    assert device.current_temperature == temperature
    assert mock_push.call_count == 1
    assert mock_push.call_args.args[0] == {
        "SetTem": temSet,
        "TemRec": temRec,
        "TemUn": 1,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("temperature", [-270, -61, 61, 100])
async def test_send_temperature_out_of_range_celsius(temperature):
    """Check that bad temperatures raise the appropriate error."""
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    device.temperature_units = TemperatureUnits.C
    with pytest.raises(ValueError):
        device.target_temperature = temperature


@pytest.mark.asyncio
@pytest.mark.parametrize("temperature", [-270, -61, 141])
async def test_send_temperature_out_of_range_farenheit_set(temperature):
    """Check that bad temperatures raise the appropriate error."""
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    device.temperature_units = TemperatureUnits.F
    with pytest.raises(ValueError):
        device.target_temperature = temperature


@pytest.mark.asyncio
@pytest.mark.parametrize("temperature", [-270, 150])
async def test_send_temperature_out_of_range_farenheit_get(temperature):
    """Check that bad temperatures raise the appropriate error."""
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    device.set_property(Props.TEMP_SET, 20)
    device.set_property(Props.TEMP_SENSOR, temperature)
    device.set_property(Props.TEMP_BIT, 0)
    device.temperature_units = TemperatureUnits.F

    t = device.current_temperature
    assert t == 68


@pytest.mark.asyncio
@patch("greeclimate.network.send_state")
async def test_enable_disable_sleep_mode(mock_request):
    """Check that properties can be updates."""
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    device.sleep = True
    await device.push_state_update()

    assert device.get_property(Props.SLEEP) == 1
    assert device.get_property(Props.SLEEP_MODE) == 1

    device.sleep = False
    await device.push_state_update()

    assert device.get_property(Props.SLEEP) == 0
    assert device.get_property(Props.SLEEP_MODE) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "temperature", [59, 77, 86]
)
@patch("greeclimate.network.send_state")
@patch("greeclimate.network.request_state")
async def test_mismatch_temrec_farenheit(mock_request, mock_push, temperature):
    """Check that temperature is set and read properly in F."""
    temSet = round((temperature - 32.0) * 5.0 / 9.0)
    temRec = (int)((((temperature - 32.0) * 5.0 / 9.0) - temSet) > 0)
    
    state = get_mock_state()
    state["TemSen"] = temSet + 40
    # Now, we alter the temRec on the device so it is not found in the table.
    state["TemRec"] = (temRec + 1) % 2
    state["TemUn"] = 1
    mock_request.return_value = state
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    device.temperature_units = TemperatureUnits.F
    device.target_temperature = temperature
    await device.push_state_update()
    await device.update_state()

    assert device.current_temperature == temperature
    assert mock_push.call_count == 1
    assert mock_push.call_args.args[0] == {
        "SetTem": temSet,
        "TemRec": temRec,
        "TemUn": 1,
    }
