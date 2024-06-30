from unittest.mock import patch

import pytest

from greeclimate.device import Props, Device


@pytest.mark.asyncio
async def test_issue_69_TemSen_40_should_not_set_firmware_v4():
    from tests.test_device import generate_device_mock_async

    mock_v3_state = { "TemSen": 40 }
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    def fake_send(*args):
        device.handle_state_update(**mock_v3_state)

    with patch.object(Device, "send", wraps=fake_send()):
        await device.update_state()
        assert device.version is None

"""Tests for issue 72"""

@pytest.mark.asyncio
@patch("greeclimate.network.send_state")
async def test_issue_87_quiet_should_set_2(mock_request):
    """Check that quiet mode uses 2 instead of 1"""
    from tests.test_device import generate_device_mock_async

    mock_v3_state = { "Quiet": 2 }
    mock_request.return_value = mock_v3_state
    device = await generate_device_mock_async()

    assert device.get_property(Props.QUIET) is None
    device.quiet = True
    await device.push_state_update()

    mock_request.assert_called_once()
    assert device.get_property(Props.QUIET) == 2
