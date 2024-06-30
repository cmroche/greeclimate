import asyncio
import json
import socket
from asyncio.tasks import wait_for
from threading import Thread
from unittest.mock import MagicMock, PropertyMock, create_autospec, patch

import pytest

from greeclimate.device import DeviceInfo
from greeclimate.discovery import Discovery, Listener
from greeclimate.network import DatagramStream, DeviceProtocolBase2

from .common import (
    DEFAULT_TIMEOUT,
    DISCOVERY_REQUEST,
    DISCOVERY_RESPONSE,
    DISCOVERY_RESPONSE_NO_CID,
    Responder,
    encrypt_payload,
    get_mock_device_info,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,family", [(("127.0.0.1", 7000), socket.AF_INET)]
)
async def test_discover_devices(netifaces, addr, family):
    netifaces.return_value = {
        2: [{"addr": addr[0], "netmask": "255.0.0.0", "peer": addr[0]}]
    }

    devices = [
        {"cid": "aabbcc001122", "mac": "aabbcc001122", "name": "MockDevice1"},
        {"cid": "aabbcc001123", "mac": "aabbcc001123", "name": "MockDevice2"},
        {"cid": "", "mac": "aabbcc001124", "name": "MockDevice3"},
    ]

    with Responder(family, addr[1]) as sock:

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)
            assert p == DISCOVERY_REQUEST

            for d in devices:
                r = DISCOVERY_RESPONSE.copy()
                r["pack"].update(d)
                p = json.dumps(encrypt_payload(r))
                s.sendto(p.encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        discovery = Discovery(allow_loopback=True)
        devices = await discovery.scan(wait_for=DEFAULT_TIMEOUT)
        assert devices is not None
        assert len(devices) == 3

        sock.close()
        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
async def test_discover_no_devices(netifaces):
    netifaces.return_value = {
        2: [{"addr": "127.0.0.1", "netmask": "255.0.0.0", "peer": "127.0.0.1"}]
    }

    discovery = Discovery(allow_loopback=True)
    devices = await discovery.scan(wait_for=DEFAULT_TIMEOUT)

    assert devices is not None
    assert len(devices) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,family", [(("127.0.0.1", 7000), socket.AF_INET)]
)
async def test_discover_deduplicate_multiple_discoveries(
    netifaces, addr, family
):
    netifaces.return_value = {
        2: [{"addr": addr[0], "netmask": "255.0.0.0", "peer": addr[0]}]
    }

    devices = [
        {"cid": "aabbcc001122", "mac": "aabbcc001122", "name": "MockDevice1"},
        {"cid": "aabbcc001123", "mac": "aabbcc001123", "name": "MockDevice2"},
        {"cid": "aabbcc001123", "mac": "aabbcc001123", "name": "MockDevice2"},
    ]

    with Responder(family, addr[1]) as sock:

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)
            assert p == DISCOVERY_REQUEST

            for d in devices:
                r = DISCOVERY_RESPONSE.copy()
                r["pack"].update(d)
                p = json.dumps(encrypt_payload(r))
                s.sendto(p.encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        discovery = Discovery(allow_loopback=True)
        devices = await discovery.scan(wait_for=DEFAULT_TIMEOUT)
        assert devices is not None
        assert len(devices) == 2

        sock.close()
        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,family", [(("127.0.0.1", 7000), socket.AF_INET)]
)
async def test_discovery_events(netifaces, addr, family):
    netifaces.return_value = {
        2: [{"addr": addr[0], "netmask": "255.0.0.0", "peer": addr[0]}]
    }

    with Responder(family, addr[1]) as sock:

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)
            assert p == DISCOVERY_REQUEST

            p = json.dumps(encrypt_payload(DISCOVERY_RESPONSE))
            s.sendto(p.encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        with patch.object(Discovery, "packet_received", return_value=None) as mock:
            discovery = Discovery(allow_loopback=True)
            await discovery.scan()
            await asyncio.sleep(DEFAULT_TIMEOUT)

            assert mock.call_count == 1

        sock.close()
        serv.join(timeout=DEFAULT_TIMEOUT)


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
@pytest.mark.parametrize(
    "addr,family", [(("127.0.0.1", 7000), socket.AF_INET)]
)
async def test_discover_devices_bad_data(netifaces, addr, family):
    """Create a socket broadcast responder, an async broadcast listener,
    test discovery responses.
    """
    netifaces.return_value = {
        2: [{"addr": addr[0], "netmask": "255.0.0.0", "peer": addr[0]}]
    }

    with Responder(family, addr[1]) as sock:

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)
            assert p == DISCOVERY_REQUEST

            s.sendto("garbage data".encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        # Run the listener portion now
        discovery = Discovery(allow_loopback=True)
        response = await discovery.scan(wait_for=DEFAULT_TIMEOUT)

        assert response is not None
        assert len(response) == 0

        sock.close()
        serv.join(timeout=DEFAULT_TIMEOUT)


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
