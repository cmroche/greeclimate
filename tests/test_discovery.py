from unittest.mock import patch

import pytest

from greeclimate.discovery import Discovery


@pytest.mark.asyncio
@patch("greeclimate.network.search_devices")
async def test_discover_device(mock_search_devices):
    mock_search_devices.return_value = [
        ("1.1.1.0", "7000", "aabbcc001122", "MockDevice1")
    ]

    devices = await Discovery.search_devices()

    assert devices is not None
    assert len(devices) > 0


@pytest.mark.asyncio
@patch("greeclimate.network.search_devices")
async def test_discover_no_devices(mock_search_devices):
    mock_search_devices.return_value = []

    devices = await Discovery.search_devices()

    assert devices is not None
    assert len(devices) == 0


@pytest.mark.asyncio
@patch("greeclimate.network.search_devices")
async def test_discover_deduplicate_multiple_discoveries(mock_search_devices):
    mock_search_devices.return_value = [
        ("1.1.1.1", "7000", "aabbcc001122", "MockDevice1"),
        ("1.1.1.1", "7000", "aabbcc001122", "MockDevice1"),
        ("1.1.1.2", "7000", "aabbcc001123", "MockDevice2"),
    ]

    devices = await Discovery.search_devices()

    assert devices is not None
    assert len(devices) == 2
