import asyncio
import enum
from unittest.mock import patch

import pytest

from greeclimate.device import Device, DeviceInfo, Props
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
        "Quiet": 1,
        "Tur": 1,
        "StHt": 1,
        "SvSt": 1,
        "TemRec": 0,
        "HeatCoolType": 0,
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
    }


def get_mock_state_v3_temp():
    return {"TemSen": 69, "hid": "362001000762+U-CS532AE(LT)V3.31.bin"}


def get_mock_state_v4_temp():
    return {"TemSen": 29, "hid": "362001060297+U-CS532AF(MTK)V4.bin"}


def get_mock_state_bad_temp():
    return {"TemSen": 69, "hid": "362001060297+U-CS532AF(MTK).bin"}


def get_mock_state_0c_temp():
    return {"TemSen": 0, "hid": "362001000762+U-CS532AE(LT)V4.bin"}


async def generate_device_mock_async():
    d = Device(("192.168.1.29", 7000, "f4911e7aca59", "1e7aca59"))
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
@patch("greeclimate.network.bind_device")
async def test_get_device_info(mock_bind):
    """Initialize device, check properties."""

    info = DeviceInfo(*get_mock_info())
    device = Device(info)

    assert device.device_info == info

    fake_key = "abcdefgh12345678"
    await device.bind(key=fake_key)

    assert device.device_key == fake_key


@pytest.mark.asyncio
@patch("greeclimate.network.bind_device")
async def test_device_bind(mock_bind):
    """Check that the device returns a device key when binding."""

    info = DeviceInfo(*get_mock_info())
    device = Device(info)

    assert device.device_info == info

    fake_key = "abcdefgh12345678"
    mock_bind.return_value = fake_key
    await device.bind()

    assert device.device_key == fake_key


@pytest.mark.asyncio
@patch("greeclimate.network.bind_device")
async def test_device_bind_timeout(mock_bind):
    """Check that the device handles timeout errors when binding."""

    info = DeviceInfo(*get_mock_info())
    device = Device(info)

    assert device.device_info == info

    mock_bind.side_effect = asyncio.TimeoutError

    with pytest.raises(DeviceTimeoutError):
        await device.bind()

    assert device.device_key is None


@pytest.mark.asyncio
@patch("greeclimate.network.bind_device")
async def test_device_bind_none(mock_bind):
    """Check that the device handles bad binding sequences."""

    info = DeviceInfo(*get_mock_info())
    device = Device(info)

    assert device.device_info == info

    mock_bind.return_value = None

    with pytest.raises(DeviceNotBoundError):
        await device.bind()

    assert device.device_key is None


@pytest.mark.asyncio
@patch("greeclimate.network.bind_device")
@patch("greeclimate.network.request_state")
@patch("greeclimate.network.send_state")
async def test_device_late_bind(mock_push, mock_update, mock_bind):
    """Check that the device handles late binding sequences."""
    fake_key = "abcdefgh12345678"
    mock_bind.return_value = fake_key
    mock_update.return_value = {}
    mock_push.return_value = []

    info = DeviceInfo(*get_mock_info())
    device = Device(info)
    assert device.device_info == info

    await device.update_state()
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
    device.target_temperature = 1
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

    await device.push_state_update()

    mock_request.assert_called_once()

    for p in Props:
        if p not in (Props.TEMP_SENSOR, Props.TEMP_BIT, Props.UNKNOWN_HEATCOOLTYPE):
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
    device.target_temperature = 1
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
@patch("greeclimate.network.request_state")
async def test_update_current_temp_v3(mock_request):
    """Check that properties can be updates."""
    mock_request.return_value = get_mock_state_v3_temp()
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    await device.update_state()

    assert device.get_property(Props.TEMP_SENSOR) is not None
    assert device.current_temperature == get_mock_state_v3_temp()["TemSen"] - 40


@pytest.mark.asyncio
@patch("greeclimate.network.request_state")
async def test_update_current_temp_v4(mock_request):
    """Check that properties can be updates."""
    mock_request.return_value = get_mock_state_v4_temp()
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    await device.update_state()

    assert device.get_property(Props.TEMP_SENSOR) is not None
    assert device.current_temperature == get_mock_state_v4_temp()["TemSen"]


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
async def test_update_current_temp_0C(mock_request):
    """Check that properties can be updates."""
    mock_request.return_value = get_mock_state_0c_temp()
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    await device.update_state()

    assert device.current_temperature == get_mock_state_0c_temp()["TemSen"]


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
