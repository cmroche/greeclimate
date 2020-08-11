import enum
import pytest
import socket
from unittest.mock import patch

from greeclimate.discovery import Discovery
from greeclimate.device import Device, DeviceInfo, Props
from greeclimate.exceptions import DeviceNotBoundError, DeviceTimeoutError

class FakeProps(enum.Enum):
    FAKE = "fake"

def get_mock_state():
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

def get_mock_state_off():
    return {
        "Pow": 0,
        "Mod": 0,
        "SetTem": 0,
        "TemUn": 0,
        "WdSpd": 0,
        "Air": 0,
        "Blo": 0,
        "Health": 0,
        "SwhSlp": 0,
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
        "TemUn": 1,
        "WdSpd": 1,
        "Air": 1,
        "Blo": 1,
        "Health": 1,
        "SwhSlp": 1,
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

async def generate_device_mock_async():
    d = Device(
        ("192.168.1.29", 7000, "f4911e7aca59", "1e7aca59")
    )
    await d.bind(key="St8Vw1Yz4Bc7Ef0H")
    return d

@pytest.mark.asyncio
@patch("greeclimate.network_helper.search_devices")
@patch("greeclimate.network_helper.bind_device")
async def test_get_device_info(mock_bind, mock_search):
    # DeviceInfo("192.168.1.29", 7000, "f4911e7aca59", "1e7aca59")

    mock_info = ("1.1.1.0", "7000", "aabbcc001122", "MockDevice1", "MockBrand", "MockModel", "0.0.1-fake")
    mock_search.return_value = [mock_info]
    mock_bind.return_value = "St8Vw1Yz4Bc7Ef0H"

    """ The only way to get the key through binding is by scanning first
    """
    devices = await Discovery.search_devices()
    device = Device(devices[0])
    await device.bind()

    assert devices is not None
    assert len(devices) == 1
    
    assert devices[0].ip ==  mock_info[0]
    assert devices[0].port ==  mock_info[1]
    assert devices[0].mac ==  mock_info[2]
    assert devices[0].name ==  mock_info[3]
    assert devices[0].brand ==  mock_info[4]
    assert devices[0].model ==  mock_info[5]
    assert devices[0].version ==  mock_info[6]

    assert device is not None
    assert device.device_key ==  "St8Vw1Yz4Bc7Ef0H"

@pytest.mark.asyncio
@patch("greeclimate.network_helper.search_devices")
@patch("greeclimate.network_helper.bind_device")
async def test_get_device_key_timeout(mock_bind, mock_search):

    mock_search.return_value = [
        ("1.1.1.0", "7000", "aabbcc001122", "MockDevice1")
    ]
    mock_bind.side_effect = socket.timeout

    """ The only way to get the key through binding is by scanning first
    """
    devices = await Discovery.search_devices()
    device = Device(devices[0])

    with pytest.raises(DeviceNotBoundError):
        await device.bind()

    assert device is not None
    assert device.device_key is None

@pytest.mark.asyncio
@patch("greeclimate.network_helper.request_state")
async def test_update_properties(mock_request):
    mock_request.return_value = get_mock_state()
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    await device.update_state()

    for p in Props:
        assert device.get_property(p) is not None
        assert device.get_property(p) == get_mock_state()[p.value]

@pytest.mark.asyncio
@patch("greeclimate.network_helper.request_state", side_effect=socket.timeout)
async def test_update_properties_timeout(mock_request):
    mock_request.return_value = get_mock_state()
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    with pytest.raises(DeviceTimeoutError):
        await device.update_state()

@pytest.mark.asyncio
@patch("greeclimate.network_helper.send_state")
async def test_set_properties(mock_request):
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
        if p not in (Props.TEMP_BIT, Props.UNKNOWN_HEATCOOLTYPE):
            assert device.get_property(p) is not None
            assert device.get_property(p) == get_mock_state_on()[p.value]

@pytest.mark.asyncio
@patch("greeclimate.network_helper.send_state", side_effect=socket.timeout)
async def test_set_properties_timeout(mock_request):
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
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    assert not device.power
    assert device.mode is None
    assert device.target_temperature is None
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


