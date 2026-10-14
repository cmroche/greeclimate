from unittest.mock import patch

import pytest

from greeclimate.device import Props, Device
from tests.common import get_mock_device_info


@pytest.mark.asyncio
async def test_issue_69_TemSen_40_should_not_set_firmware_v4():
    from tests.test_device import generate_device_mock_async

    mock_v3_state = { "TemSen": 40 }
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    def fake_send(*args, **kwargs):
        device.handle_state_update(**mock_v3_state)

    with patch.object(Device, "send", wraps=fake_send()):
        await device.update_state()
        assert device.version is None

"""Tests for issue 72"""

@pytest.mark.asyncio
async def test_issue_87_quiet_should_set_2():
    """Check that quiet mode uses 2 instead of 1"""
    from tests.test_device import generate_device_mock_async

    mock_v3_state = { "Quiet": 2 }
    device = await generate_device_mock_async()

    assert device.get_property(Props.QUIET) is None
    device.quiet = True

    def fake_send(*args, **kwargs):
        device.handle_state_update(**mock_v3_state)

    with patch.object(Device, "send", wraps=fake_send()) as mock:
        await device.push_state_update()
        mock.assert_called_once()

    assert device.get_property(Props.QUIET) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("response_order", ["firmware_first", "temperature_first", "combined"])
@pytest.mark.parametrize(
    "temperature, unit, bit, expected",
    [(28, 0, 0, 28), (68, 0, 0, 28), (40, 0, 0, 0), (28, 1, 0, 82)],
)
async def test_current_temperature_with_separate_firmware_response(response_order, temperature, unit, bit, expected):
    """Firmware and temperature responses may arrive in either order."""
    device = Device(get_mock_device_info())
    firmware = {"hid": "362001061217+U-W04NV7.bin"}
    state = {"TemSen": temperature, "TemUn": unit, "TemRec": bit}

    if response_order == "firmware_first":
        device.handle_state_update(**firmware)
        device.handle_state_update(**state)
    elif response_order == "temperature_first":
        device.handle_state_update(**state)
        device.handle_state_update(**firmware)
    else:
        device.handle_state_update(**firmware, **state)

    assert device.current_temperature == expected
    assert device.get_property(Props.TEMP_SENSOR) == temperature


@pytest.mark.asyncio
@pytest.mark.parametrize("initial_state", [{}, {"TemSen": None}, {"TemSen": 0}])
async def test_current_temperature_after_invalid_initial_reading(initial_state):
    """A missing or zero initial reading must not consume offset detection."""
    device = Device(get_mock_device_info())
    device.handle_state_update(hid="362001061217+U-W04NV7.bin", **initial_state)
    device.handle_state_update(TemSen=28, TemUn=0, TemRec=0)

    assert device.current_temperature == 28


@pytest.mark.asyncio
@pytest.mark.parametrize("temperature", [0, 40, 45])
async def test_detected_temperature_encoding_survives_later_firmware_response(temperature):
    """Keep the detected encoding even when later readings cannot identify it."""
    device = Device(get_mock_device_info())
    device.handle_state_update(TemSen=28, TemUn=0, TemRec=0, SetTem=29)
    device.handle_state_update(TemSen=temperature)
    device.handle_state_update(hid="362001061217+U-W04NV7.bin")

    assert device.current_temperature == temperature
