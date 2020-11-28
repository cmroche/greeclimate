import asyncio
import json
import socket
from threading import Thread
from unittest.mock import create_autospec, patch

import pytest

from greeclimate.network import (BroadcastListenerProtocol, DatagramStream,
                                 DeviceProtocol, DeviceProtocol2, IPAddr,
                                 bind_device, create_datagram_stream,
                                 request_state, send_state)

from .common import (DEFAULT_RESPONSE, DEFAULT_TIMEOUT, DISCOVERY_REQUEST,
                     DISCOVERY_RESPONSE, Responder, encrypt_payload,
                     get_mock_device_info)


class FakeDiscovery(BroadcastListenerProtocol):
    """Fake discovery class."""

    def __init__(self):
        super(BroadcastListenerProtocol, self).__init__()
        self.packets = []

    def packet_received(self, obj, addr: IPAddr) -> None:
        self.packets.append(obj)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,bcast,family", [(("127.0.0.1", 7000), "127.255.255.255", socket.AF_INET)]
)
async def test_close_connection(addr, bcast, family):
    """Test closing the connection."""
    # Run the listener portion now
    loop = asyncio.get_event_loop()

    bcast = (bcast, 7000)
    local_addr = (addr[0], 0)

    with patch.object(DeviceProtocol2, "connection_lost") as mock:
        dp2 = FakeDiscovery()
        await loop.create_datagram_endpoint(
            lambda: dp2,
            local_addr=local_addr,
        )

        # Send the scan command
        data = DISCOVERY_REQUEST
        await dp2.send(data, bcast)
        dp2.close()

        # Wait on the scan response
        await asyncio.sleep(DEFAULT_TIMEOUT)
        response = dp2.packets

        assert not response
        assert len(response) == 0
        assert mock.call_count == 1


@pytest.mark.asyncio
async def test_set_get_key():
    """Test the encryption key property."""
    key = "faketestkey"
    dp2 = DeviceProtocol2()
    dp2.device_key = key
    assert dp2.device_key == key


@pytest.mark.asyncio
@pytest.mark.parametrize("addr,bcast", [(("127.0.0.1", 7001), "127.255.255.255")])
async def test_connection_error(addr, bcast):
    """Test the encryption key property."""
    dp2 = DeviceProtocol2()

    loop = asyncio.get_event_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: dp2,
        local_addr=addr,
    )

    # Send the scan command
    data = DISCOVERY_REQUEST
    await dp2.send(data, bcast)
    dp2.connection_lost(RuntimeError())
    assert transport.is_closing()


@pytest.mark.asyncio
@pytest.mark.parametrize("addr,bcast", [(("127.0.0.1", 7001), "127.255.255.255")])
async def test_pause_resume(addr, bcast):
    """Test the encryption key property."""
    event = asyncio.Event()
    dp2 = DeviceProtocol2(drained=event)

    loop = asyncio.get_event_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: dp2,
        local_addr=addr,
    )

    dp2.pause_writing()
    assert not event.is_set()

    dp2.resume_writing()
    assert event.is_set()

    dp2.close()
    assert transport.is_closing()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,bcast,family", [(("127.0.0.1", 7000), "127.255.255.255", socket.AF_INET)]
)
async def test_broadcast_recv(addr, bcast, family):
    """Create a socket broadcast responder, an async broadcast listener, test discovery responses."""
    with Responder(family, addr[1]) as sock:

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)
            assert p == DISCOVERY_REQUEST

            p = json.dumps(encrypt_payload(DISCOVERY_RESPONSE))
            s.sendto(p.encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        # Run the listener portion now
        loop = asyncio.get_event_loop()

        bcast = (bcast, 7000)
        local_addr = (addr[0], 0)

        dp2 = FakeDiscovery()
        await loop.create_datagram_endpoint(
            lambda: dp2,
            local_addr=local_addr,
        )

        # Send the scan command
        data = DISCOVERY_REQUEST
        await dp2.send(data, bcast)

        # Wait on the scan response
        await asyncio.sleep(DEFAULT_TIMEOUT)
        response = dp2.packets

        assert response
        assert len(response) == 1
        assert response[0] == DISCOVERY_RESPONSE

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

    bcast = (bcast, 7000)
    local_addr = (addr[0], 0)

    dp2 = FakeDiscovery()
    await loop.create_datagram_endpoint(
        lambda: dp2,
        local_addr=local_addr,
    )

    # Send the scan command
    await dp2.send(DISCOVERY_REQUEST, bcast)

    # Wait on the scan response
    await asyncio.sleep(DEFAULT_TIMEOUT)
    response = dp2.packets

    assert response is not None
    assert len(response) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("addr,family", [(("127.0.0.1", 7000), socket.AF_INET)])
async def test_datagram_connect(addr, family):
    """Create a socket responder, an async connection, test send and recv."""
    with Responder(family, addr[1]) as sock:

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

        sock.close()
        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
@pytest.mark.parametrize("addr,family", [(("127.0.0.1", 7000), socket.AF_INET)])
async def test_create_stream(addr, family):
    """Create a socket responder, a network stream, test send and recv."""
    with Responder(family, addr[1]) as sock:

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

        sock.close()
        serv.join(timeout=DEFAULT_TIMEOUT)


def test_encrypt_decrypt_payload():
    test_object = {"fake-key": "fake-value"}

    encrypted = DeviceProtocol2.encrypt_payload(test_object)
    assert encrypted != test_object

    decrypted = DeviceProtocol2.decrypt_payload(encrypted)
    assert decrypted == test_object


@pytest.mark.asyncio
@pytest.mark.parametrize("addr,family", [(("127.0.0.1", 7000), socket.AF_INET)])
async def test_send_receive_device_data(addr, family):
    """Create a socket responder, a network stream, test send and recv."""
    with Responder(family, addr[1]) as sock:

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
    with Responder(family, addr[1]) as sock:

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)

            r = DEFAULT_RESPONSE
            r["pack"] = DeviceProtocol2.encrypt_payload(
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
    with Responder(family, addr[1]) as sock:

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)

            r = DEFAULT_RESPONSE
            r["pack"] = DeviceProtocol2.encrypt_payload(
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
    with Responder(family, addr[1]) as sock:

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)

            r = DEFAULT_RESPONSE
            r["pack"] = DeviceProtocol2.encrypt_payload(
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
