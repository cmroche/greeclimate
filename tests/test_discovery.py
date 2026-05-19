import asyncio
import json
import socket
from threading import Thread
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from greeclimate.discovery import Discovery, Listener
from .common import (
    DEFAULT_TIMEOUT,
    DISCOVERY_REQUEST,
    DISCOVERY_RESPONSE,
    Responder,
    get_mock_device_info, encrypt_payload,
)


@pytest.mark.asyncio
async def test_discovery_device_update_events():
    discovery = Discovery(allow_loopback=True)
    discovery.packet_received(
        {
            "pack": {
                "mac": "aa11bb22cc33",
                "cid": 1,
                "name": "MockDevice",
                "brand": "",
                "model": "",
                "ver": "1.0.0",
            }
        },
        ("1.1.1.1", 7000),
    )

    await asyncio.gather(*discovery.tasks, return_exceptions=True)

    assert len(discovery.devices) == 1
    assert discovery.devices[0].mac == "aa11bb22cc33"
    assert discovery.devices[0].ip == "1.1.1.1"

    discovery.packet_received(
        {
            "pack": {
                "mac": "aa11bb22cc33",
                "cid": 1,
                "name": "MockDevice",
                "brand": "",
                "model": "",
                "ver": "1.0.0",
            }
        },
        ("1.1.2.2", 7000),
    )

    await asyncio.gather(*discovery.tasks, return_exceptions=True)

    assert len(discovery.devices) == 1
    assert discovery.devices[0].mac == "aa11bb22cc33"
    assert discovery.devices[0].ip == "1.1.2.2"


@pytest.mark.asyncio
async def test_add_new_listener():
    """Register a listener, test that is registered."""

    listener = MagicMock(spec_set=Listener)
    discovery = Discovery()

    result = discovery.add_listener(listener)
    assert result is not None

    result = discovery.add_listener(listener)
    assert result is None


@pytest.mark.asyncio
async def test_add_new_listener_with_devices():
    """Register a listener, test that is registered."""

    with patch.object(Discovery, "devices", new_callable=PropertyMock) as mock:
        mock.return_value = [get_mock_device_info()]
        listener = MagicMock(spec_set=Listener)
        discovery = Discovery()

        result = discovery.add_listener(listener)
        await asyncio.gather(*discovery.tasks)

        assert result is not None
        assert len(result) == 1
        assert listener.device_found.call_count == 1


@pytest.mark.asyncio
async def test_remove_listener():
    """Register, remove listener, test results."""

    listener = MagicMock(spec_set=Listener)
    discovery = Discovery()

    result = discovery.add_listener(listener)
    assert result is not None

    result = discovery.remove_listener(listener)
    assert result is True

    result = discovery.remove_listener(listener)
    assert result is False
