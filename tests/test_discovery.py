import asyncio
import json
import pytest
import socket

from threading import Thread
from unittest.mock import create_autospec

from greeclimate.discovery import Discovery
from greeclimate.device import DeviceInfo
from greeclimate.network import DatagramStream

from .common import (
    DEFAULT_TIMEOUT,
    DISCOVERY_REQUEST,
    DISCOVERY_RESPONSE,
    DISCOVERY_RESPONSE_NO_CID,
)


@pytest.fixture
def mock_socket():
    s = create_autospec(socket.socket)
    s.family = socket.AF_INET
    s.type = socket.SOCK_DGRAM

    return s


@pytest.mark.asyncio
async def test_discover_device(netifaces, search_devices):
    search_devices.return_value = [("1.1.1.0", "7000", "aabbcc001122", "MockDevice1")]

    discovery = discovery = Discovery(allow_loopback=True)
    devices, _ = await discovery.search_devices()

    assert devices is not None
    assert len(devices) > 0


@pytest.mark.asyncio
async def test_discover_no_devices(netifaces, search_devices):
    search_devices.return_value = []

    discovery = discovery = Discovery(allow_loopback=True)
    devices, _ = await discovery.search_devices()

    assert devices is not None
    assert len(devices) == 0


@pytest.mark.asyncio
async def test_discover_deduplicate_multiple_discoveries(netifaces, search_devices):
    search_devices.return_value = [
        ("1.1.1.1", "7000", "aabbcc001122", "MockDevice1"),
        ("1.1.1.1", "7000", "aabbcc001122", "MockDevice1"),
        ("1.1.1.2", "7000", "aabbcc001123", "MockDevice2"),
    ]

    discovery = discovery = Discovery(allow_loopback=True)
    devices, _ = await discovery.search_devices()

    assert devices is not None
    assert len(devices) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,bcast,family", [(("127.0.0.1", 7000), "127.255.255.255", socket.AF_INET)]
)
async def test_discovery_callback(netifaces, addr, bcast, family):
    netifaces.return_value = {
        2: [{"addr": addr[0], "netmask": "255.0.0.0", "peer": bcast}]
    }

    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", addr[1]))

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)
            assert p == DISCOVERY_REQUEST

            r = DISCOVERY_RESPONSE
            r["pack"] = DatagramStream.encrypt_payload(r["pack"])
            p = json.dumps(r)
            s.sendto(p.encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        loop = asyncio.get_running_loop()
        fut = loop.create_future()

        async def cb(device_info: DeviceInfo):
            fut.set_result(True)
            assert device_info is not None

        discovery = discovery = Discovery(allow_loopback=True)
        devices, _ = await discovery.search_devices(async_callback=cb)
        done, _ = await asyncio.wait([fut], timeout=12)

        assert devices is not None
        assert done is not None
        assert len(devices) > 0
        assert len(done) == len(devices)

        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,bcast,family,dresp",
    [
        (
            ("127.0.0.1", 7000),
            "127.255.255.255",
            socket.AF_INET,
            DISCOVERY_RESPONSE_NO_CID,
        ),
    ],
)
async def test_search_devices(netifaces, addr, bcast, family, dresp):
    """Create a socket broadcast responder, an async broadcast listener, test
    discovery responses.
    """
    netifaces.return_value = {
        2: [{"addr": addr[0], "netmask": "255.0.0.0", "peer": bcast}]
    }

    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", addr[1]))

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)
            assert p == DISCOVERY_REQUEST

            r = dresp
            r["pack"] = DatagramStream.encrypt_payload(r["pack"])
            p = json.dumps(r)
            s.sendto(p.encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        # Run the listener portion now
        discovery = discovery = Discovery(allow_loopback=True)
        response, _ = await discovery.search_devices()

        assert response
        assert len(response) == 1
        assert response[0].ip == "127.0.0.1"

        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,bcast,family", [(("127.0.0.1", 7000), "127.255.255.255", socket.AF_INET)]
)
async def test_search_devices_bad_data(netifaces, addr, bcast, family):
    """Create a socket broadcast responder, an async broadcast listener,
    test discovery responses.
    """
    netifaces.return_value = {
        2: [{"addr": addr[0], "netmask": "255.0.0.0", "peer": bcast}]
    }

    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", addr[1]))

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)
            assert p == DISCOVERY_REQUEST

            s.sendto("garbage data".encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        # Run the listener portion now
        discovery = discovery = Discovery(allow_loopback=True)
        response, _ = await discovery.search_devices()

        assert response is not None
        assert len(response) == 0

        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,bcast,family", [(("127.0.0.1", 7000), "127.255.255.255", socket.AF_INET)]
)
async def test_search_devices_timeout(netifaces, addr, bcast, family):
    """Create an async broadcast listener, test discovery responses."""
    netifaces.return_value = {
        2: [{"addr": addr[0], "netmask": "255.0.0.0", "peer": bcast}]
    }

    # Run the listener portion now
    discovery = discovery = Discovery(allow_loopback=True)
    response, _ = await discovery.search_devices()

    assert response is not None
    assert len(response) == 0
