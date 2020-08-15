import asyncio
import json
import socket
from threading import Thread
from unittest.mock import create_autospec, patch, MagicMock

import pytest

from greeclimate.network import BroadcastListenerProtocol, DatagramStream, get_broadcast_addresses

DISCOVERY_REQUEST = {"t": "scan"}
DISCOVERY_RESPONSE = {
    "t": "pack",
    "i": 1,
    "uid": 0,
    "cid": "aabbcc112233",
    "tcid": "",
    "pack": "FAKE"
}


@pytest.fixture
def mock_socket():
    s = create_autospec(socket.socket)
    s.family = socket.AF_INET
    s.type = socket.SOCK_DGRAM

    return s


MOCK_INTERFACES = ['lo']
MOCK_LO_IFACE = {2: [{'addr': '10.0.0.1', 'netmask': '255.0.0.0', 'peer': '10.255.255.255'}]}


@patch("netifaces.interfaces", return_value=MOCK_INTERFACES)
@patch("netifaces.ifaddresses", return_value=MOCK_LO_IFACE)
def test_get_interfaces(mock_interfaces, mock_ifaddresses):
    """Query available interfaces, should be returned in a list."""
    ifaces = get_broadcast_addresses()

    assert ifaces
    assert len(ifaces) > 0
    assert ifaces[0].ip_address == "10.0.0.1"
    assert ifaces[0].bcast_address == "10.255.255.255"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,bcast,family",
    [
        (("127.0.0.1", 7000), "127.255.255.255", socket.AF_INET)
    ]
)
async def test_broadcast_recv(addr, bcast, family):
    """Create a socket broadcast responder, an async broadcast listener, test discovery responses."""
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('', addr[1]))

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)
            assert p == DISCOVERY_REQUEST

            p = json.dumps(DISCOVERY_RESPONSE)
            s.sendto(p.encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        # Run the listener portion now
        loop = asyncio.get_event_loop()
        recvq = asyncio.Queue()
        excq = asyncio.Queue()
        drained = asyncio.Event()

        bcast = (bcast, 7000)
        local_addr = (addr[0], 0)

        transport, _ = await loop.create_datagram_endpoint(
            lambda: BroadcastListenerProtocol(recvq, excq, drained), local_addr=local_addr,
        )
        stream = DatagramStream(transport, recvq, excq, drained)

        # Send the scan command
        data = json.dumps({"t": "scan"}).encode()
        await stream.send(data, bcast)

        # Wait on the scan response
        task = asyncio.create_task(stream.recv())
        await asyncio.wait_for(task, timeout=10)
        (response, _) = task.result()

        assert response
        assert len(response) > 0
        assert json.loads(response) == DISCOVERY_RESPONSE

        serv.join()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,bcast,family",
    [
        (("127.0.0.1", 7000), "127.255.255.255", socket.AF_INET)
    ]
)
async def test_broadcast_timeout(addr, bcast, family):
    """Create an async broadcast listener, test discovery responses."""

    # Run the listener portion now
    loop = asyncio.get_event_loop()
    recvq = asyncio.Queue()
    excq = asyncio.Queue()
    drained = asyncio.Event()

    bcast = (bcast, 7000)
    local_addr = (addr[0], 0)

    transport, _ = await loop.create_datagram_endpoint(
        lambda: BroadcastListenerProtocol(recvq, excq, drained), local_addr=local_addr,
    )
    stream = DatagramStream(transport, recvq, excq, drained)

    # Send the scan command
    data = json.dumps({"t": "scan"}).encode()
    await stream.send(data, bcast)

    # Wait on the scan response
    with pytest.raises(asyncio.TimeoutError):
        task = asyncio.create_task(stream.recv())
        await asyncio.wait_for(task, timeout=2)
