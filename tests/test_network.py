import asyncio
import json
import socket
from threading import Thread
from unittest.mock import Mock, create_autospec, patch

import pytest

from greeclimate.network import (
    BroadcastListenerProtocol,
    DatagramStream,
    DeviceProtocol,
    IPInterface,
    bind_device,
    create_datagram_stream,
    get_broadcast_addresses,
    request_state,
    search_on_interface,
    send_state,
)

DEFAULT_TIMEOUT = 5
DISCOVERY_REQUEST = {"t": "scan"}
DISCOVERY_RESPONSE = {
    "t": "pack",
    "i": 1,
    "uid": 0,
    "cid": "aabbcc112233",
    "tcid": "",
    "pack": {
        "t": "dev",
        "cid": "aabbcc112233",
        "bc": "gree",
        "brand": "gree",
        "catalog": "gree",
        "mac": "aabbcc112233",
        "mid": "10001",
        "model": "gree",
        "name": "fake unit",
        "series": "gree",
        "vender": "1",
        "ver": "V1.1.13",
        "lock": 0,
    },
}
DISCOVERY_RESPONSE_NO_CID = {
    "t": "pack",
    "i": 1,
    "uid": 0,
    "cid": "",
    "tcid": "",
    "pack": {
        "t": "dev",
        "cid": "",
        "bc": "gree",
        "brand": "gree",
        "catalog": "gree",
        "mac": "aabbcc112233",
        "mid": "10001",
        "model": "gree",
        "name": "fake unit",
        "series": "gree",
        "vender": "1",
        "ver": "V1.1.13",
        "lock": 0,
    },
}
DEFAULT_RESPONSE = {
    "t": "pack",
    "i": 1,
    "uid": 0,
    "cid": "aabbcc112233",
    "tcid": "",
    "pack": {},
}


def get_mock_device_info():
    return Mock(
        name="device-info",
        ip="127.0.0.1",
        port="7000",
        mac="aabbcc112233",
        brand="gree",
        model="gree",
        version="1.1.13",
    )


@pytest.fixture
def mock_socket():
    s = create_autospec(socket.socket)
    s.family = socket.AF_INET
    s.type = socket.SOCK_DGRAM

    return s


MOCK_INTERFACES = ["lo"]
MOCK_LO_IFACE = {
    2: [{"addr": "10.0.0.1", "netmask": "255.0.0.0", "peer": "10.255.255.255"}]
}


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
    "addr,bcast,family", [(("127.0.0.1", 7000), "127.255.255.255", socket.AF_INET)]
)
async def test_broadcast_recv(addr, bcast, family):
    """Create a socket broadcast responder, an async broadcast listener, test discovery responses."""
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", addr[1]))

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
            lambda: BroadcastListenerProtocol(recvq, excq, drained),
            local_addr=local_addr,
        )
        stream = DatagramStream(transport, recvq, excq, drained)

        # Send the scan command
        data = json.dumps(DISCOVERY_REQUEST).encode()
        await stream.send(data, bcast)

        # Wait on the scan response
        task = asyncio.create_task(stream.recv())
        await asyncio.wait_for(task, timeout=DEFAULT_TIMEOUT)
        (response, _) = task.result()

        assert response
        assert len(response) > 0
        assert json.loads(response) == DISCOVERY_RESPONSE

        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,bcast,family",
    [
        (("127.0.0.1", 7000), "127.255.255.255", socket.AF_INET),
        (("127.0.0.1", 7000), "255.255.255.255", socket.AF_INET),
    ],
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
        lambda: BroadcastListenerProtocol(recvq, excq, drained),
        local_addr=local_addr,
    )
    stream = DatagramStream(transport, recvq, excq, drained, timeout=DEFAULT_TIMEOUT)

    # Send the scan command
    data = json.dumps(DISCOVERY_REQUEST).encode()
    await stream.send(data, bcast)

    # Wait on the scan response
    with pytest.raises(asyncio.TimeoutError):
        await stream.recv()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,bcast,family,dresp",
    [
        (("127.0.0.1", 7000), "127.255.255.255", socket.AF_INET, DISCOVERY_RESPONSE),
        (
            ("127.0.0.1", 7000),
            "127.255.255.255",
            socket.AF_INET,
            DISCOVERY_RESPONSE_NO_CID,
        ),
    ],
)
async def test_search_on_interface(addr, bcast, family, dresp):
    """Create a socket broadcast responder, an async broadcast listener, test discovery responses."""
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
        response = await search_on_interface(
            IPInterface(addr[0], bcast), timeout=DEFAULT_TIMEOUT
        )

        assert response
        assert response == [
            ("127.0.0.1", 7000, "aabbcc112233", "fake unit", "gree", "gree", "V1.1.13")
        ]

        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,bcast,family", [(("127.0.0.1", 7000), "127.255.255.255", socket.AF_INET)]
)
async def test_search_on_interface_bad_data(addr, bcast, family):
    """Create a socket broadcast responder, an async broadcast listener, test discovery responses."""
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
        response = await search_on_interface(
            IPInterface(addr[0], bcast), timeout=DEFAULT_TIMEOUT
        )

        assert response is not None
        assert len(response) == 0

        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,bcast,family", [(("127.0.0.1", 7000), "127.255.255.255", socket.AF_INET)]
)
async def test_search_on_interface_timeout(addr, bcast, family):
    """Create an async broadcast listener, test discovery responses."""
    # Run the listener portion now
    response = await search_on_interface(
        IPInterface(addr[0], bcast), timeout=DEFAULT_TIMEOUT
    )

    assert response is not None
    assert len(response) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("addr,family", [(("127.0.0.1", 7000), socket.AF_INET)])
async def test_datagram_connect(addr, family):
    """Create a socket responder, an async connection, test send and recv."""
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.bind(("", addr[1]))

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

        remote_addr = (addr[0], 7000)

        transport, _ = await loop.create_datagram_endpoint(
            lambda: DeviceProtocol(recvq, excq, drained), remote_addr=remote_addr
        )
        stream = DatagramStream(transport, recvq, excq, drained)

        # Send the scan command
        data = json.dumps(DISCOVERY_REQUEST).encode()
        await stream.send(data, None)

        # Wait on the scan response
        task = asyncio.create_task(stream.recv())
        await asyncio.wait_for(task, timeout=DEFAULT_TIMEOUT)
        (response, _) = task.result()

        assert response
        assert len(response) > 0
        assert json.loads(response) == DISCOVERY_RESPONSE

        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
@pytest.mark.parametrize("addr,family", [(("127.0.0.1", 7000), socket.AF_INET)])
async def test_create_stream(addr, family):
    """Create a socket responder, a network stream, test send and recv."""
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.bind(("", addr[1]))

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)
            assert p == DISCOVERY_REQUEST

            p = json.dumps(DISCOVERY_RESPONSE)
            s.sendto(p.encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        # Run the listener portion now
        stream = await create_datagram_stream(addr)

        # Send the scan command
        data = json.dumps(DISCOVERY_REQUEST).encode()
        await stream.send(data)

        # Wait on the scan response
        task = asyncio.create_task(stream.recv())
        await asyncio.wait_for(task, timeout=DEFAULT_TIMEOUT)
        (response, _) = task.result()

        assert response
        assert len(response) > 0
        assert json.loads(response) == DISCOVERY_RESPONSE

        serv.join(timeout=DEFAULT_TIMEOUT)


def test_encrypt_decrypt_payload():
    test_object = {"fake-key": "fake-value"}

    encrypted = DatagramStream.encrypt_payload(test_object)
    assert encrypted != test_object

    decrypted = DatagramStream.decrypt_payload(encrypted)
    assert decrypted == test_object


@pytest.mark.asyncio
@pytest.mark.parametrize("addr,family", [(("127.0.0.1", 7000), socket.AF_INET)])
async def test_send_receive_device_data(addr, family):
    """Create a socket responder, a network stream, test send and recv."""
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.bind(("", addr[1]))

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)
            assert p == DISCOVERY_REQUEST

            # Echoing because part of the request is encrypted
            p = json.dumps(DISCOVERY_REQUEST)
            s.sendto(p.encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        # Run the listener portion now
        stream = await create_datagram_stream(addr)

        # Send the scan command
        await stream.send_device_data(DISCOVERY_REQUEST)

        # Wait on the scan response
        task = asyncio.create_task(stream.recv_device_data())
        await asyncio.wait_for(task, timeout=DEFAULT_TIMEOUT)
        (response, _) = task.result()

        assert response
        assert response == DISCOVERY_REQUEST

        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
@pytest.mark.parametrize("addr,family", [(("127.0.0.1", 7000), socket.AF_INET)])
async def test_bind_device(addr, family):
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", addr[1]))

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)

            r = DEFAULT_RESPONSE
            r["pack"] = DatagramStream.encrypt_payload(
                {"t": "bindok", "key": "acbd1234"}
            )
            p = json.dumps(r)
            s.sendto(p.encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        # Run the listener portion now
        response = await bind_device(get_mock_device_info())

        assert response
        assert response == "acbd1234"

        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
@pytest.mark.parametrize("addr,family", [(("127.0.0.1", 7000), socket.AF_INET)])
async def test_send_and_update_device_status(addr, family):
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", addr[1]))

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)

            r = DEFAULT_RESPONSE
            r["pack"] = DatagramStream.encrypt_payload(
                {"opt": ["prop-a", "prop-b"], "val": ["val-a", "val-b"]}
            )
            p = json.dumps(r)
            s.sendto(p.encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        # Run the listener portion now
        properties = {"prop-a": "val-a", "prop-b": "val-b"}
        response = await send_state(properties, get_mock_device_info())

        assert response
        assert response == properties

        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
@pytest.mark.parametrize("addr,family", [(("127.0.0.1", 7000), socket.AF_INET)])
async def test_request_device_status(addr, family):
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", addr[1]))

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)

            r = DEFAULT_RESPONSE
            r["pack"] = DatagramStream.encrypt_payload(
                {"cols": ["prop-a", "prop-b"], "dat": ["val-a", "val-b"]}
            )
            p = json.dumps(r)
            s.sendto(p.encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        # Run the listener portion now
        properties = {"prop-a": "val-a", "prop-b": "val-b"}
        response = await request_state(properties, get_mock_device_info())

        assert response
        assert response == properties

        serv.join(timeout=DEFAULT_TIMEOUT)
