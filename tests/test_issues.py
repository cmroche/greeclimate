from unittest.mock import patch

import pytest

from greeclimate.device import Props


@pytest.mark.asyncio
@patch("greeclimate.network.request_state")
async def test_issue_69_TemSen_40_should_not_set_firmware_v4(mock_request):
    from tests.test_device import generate_device_mock_async

    mock_v3_state = { "TemSen": 40 }
    mock_request.return_value = mock_v3_state
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    await device.update_state()
    assert device.version is None
