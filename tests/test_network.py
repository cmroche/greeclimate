import asyncio
import json
import socket
from threading import Thread
from unittest.mock import create_autospec, patch, MagicMock

import pytest

from greeclimate.network import (
    BroadcastListenerProtocol,
    DatagramStream,
    DeviceProtocol,
    DeviceProtocolBase2,
    IPAddr,
    create_datagram_stream,
    request_state,
    send_state, DeviceProtocol2,
)

from .common import (
    DEFAULT_RESPONSE,
    DEFAULT_TIMEOUT,
    DISCOVERY_REQUEST,
    DISCOVERY_RESPONSE,
    Responder,
    encrypt_payload,
    get_mock_device_info, DEFAULT_REQUEST, generate_response,
)


class FakeDiscoveryProtocol(BroadcastListenerProtocol):
    """Fake discovery class."""

    def __init__(self):
        super().__init__(timeout=1, drained=None)
        self.packets = asyncio.Queue()

    def packet_received(self, obj, addr: IPAddr) -> None:
        self.packets.put_nowait(obj)


class FakeDeviceProtocol(DeviceProtocol2):
    """Fake discovery class."""

    def __init__(self, drained: asyncio.Event = None):
        super().__init__(timeout=1, drained=drained)
        self.packets = asyncio.Queue()

    def packet_received(self, obj, addr: IPAddr) -> None:
        self.packets.put_nowait(obj)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,family", [(("127.0.0.1", 7000), socket.AF_INET)]
)
async def test_close_connection(addr, family):
    """Test closing the connection."""
    # Run the listener portion now
    loop = asyncio.get_event_loop()

    bcast = (addr[0], 7000)
    local_addr = (addr[0], 0)

    with patch.object(DeviceProtocolBase2, "connection_lost") as mock:
        dp2 = FakeDiscoveryProtocol()
        await loop.create_datagram_endpoint(
            lambda: dp2,
            local_addr=local_addr,
        )

        # Send the scan command
        data = DISCOVERY_REQUEST
        await dp2.send(data, bcast)
        dp2.close()

        # Wait on the scan response
        with pytest.raises(asyncio.TimeoutError):
            task = asyncio.create_task(dp2.packets.get())
            await asyncio.wait_for(task, DEFAULT_TIMEOUT)
            (response, _) = task.result()

            assert not response
            assert len(response) == 0

        assert mock.call_count == 1


@pytest.mark.asyncio
async def test_set_get_key():
    """Test the encryption key property."""
    key = "faketestkey"
    dp2 = DeviceProtocolBase2()
    dp2.device_key = key
    assert dp2.device_key == key


@pytest.mark.asyncio
@pytest.mark.parametrize("addr", [(("127.0.0.1", 7001))])
async def test_connection_error(addr):
    """Test the encryption key property."""
    dp2 = DeviceProtocolBase2()

    loop = asyncio.get_event_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: dp2,
        local_addr=addr,
    )

    # Send the scan command
    data = DISCOVERY_REQUEST
    await dp2.send(data, (addr[0], 7000))

    with pytest.raises(RuntimeError):
        dp2.connection_lost(RuntimeError())
    assert transport.is_closing()


@pytest.mark.asyncio
@pytest.mark.parametrize("addr", [(("127.0.0.1", 7001))])
async def test_pause_resume(addr):
    """Test the encryption key property."""
    event = asyncio.Event()
    dp2 = DeviceProtocolBase2(drained=event)

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
    "addr,family", [(("127.0.0.1", 7000), socket.AF_INET)]
)
async def test_broadcast_recv(addr, family):
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

        bcast = (addr[0], 7000)
        local_addr = (addr[0], 0)

        dp2 = FakeDiscoveryProtocol()
        await loop.create_datagram_endpoint(
            lambda: dp2,
            local_addr=local_addr,
        )

        # Send the scan command
        data = DISCOVERY_REQUEST
        await dp2.send(data, bcast)

        # Wait on the scan response
        task = asyncio.create_task(dp2.packets.get())
        await asyncio.wait_for(task, DEFAULT_TIMEOUT)
        response = task.result()

        assert response == DISCOVERY_RESPONSE
        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,family",
    [
        (("127.0.0.1", 7000), socket.AF_INET),
    ],
)
async def test_broadcast_timeout(addr, family):
    """Create an async broadcast listener, test discovery responses."""

    # Run the listener portion now
    loop = asyncio.get_event_loop()

    bcast = (addr[0], 7000)
    local_addr = (addr[0], 0)

    dp2 = FakeDiscoveryProtocol()
    await loop.create_datagram_endpoint(
        lambda: dp2,
        local_addr=local_addr,
    )

    # Send the scan command
    await dp2.send(DISCOVERY_REQUEST, bcast)

    # Wait on the scan response
    task = asyncio.create_task(dp2.packets.get())
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(task, DEFAULT_TIMEOUT)

    with pytest.raises(asyncio.CancelledError):
        response = task.result()
        assert len(response) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("addr,family", [(("127.0.0.1", 7000), socket.AF_INET)])
async def test_datagram_connect(addr, family):
    """Create a socket responder, an async connection, test send and recv."""
    with Responder(family, addr[1], bcast=False) as sock:

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.dumps(DEFAULT_RESPONSE)
            s.sendto(p.encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        # Run the listener portion now
        loop = asyncio.get_event_loop()
        drained = asyncio.Event()

        remote_addr = (addr[0], 7000)
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: FakeDeviceProtocol(drained=drained), remote_addr=remote_addr
        )

        with patch("greeclimate.network.DeviceProtocolBase2.decrypt_payload", new_callable=MagicMock) as mock:
            mock.side_effect = lambda x, y: x

            # Send the scan command
            await protocol.send(DEFAULT_REQUEST, None)

            # Wait on the scan response
            task = asyncio.create_task(protocol.packets.get())
            await asyncio.wait_for(task, DEFAULT_TIMEOUT)
            response = task.result()

            assert response == DEFAULT_RESPONSE

        sock.close()
        serv.join(timeout=DEFAULT_TIMEOUT)


def test_encrypt_decrypt_payload():
    test_object = {"fake-key": "fake-value"}

    encrypted = DeviceProtocolBase2.encrypt_payload(test_object)
    assert encrypted != test_object

    decrypted = DeviceProtocolBase2.decrypt_payload(encrypted)
    assert decrypted == test_object


@pytest.mark.asyncio
def test_bindok_handling():
    """Test the bindok response."""
    response = generate_response({"t": "bindok", "key": "fake-key"})
    protocol = DeviceProtocol2(timeout=DEFAULT_TIMEOUT)
    with patch("greeclimate.network.DeviceProtocolBase2.decrypt_payload", new_callable=MagicMock) as mock_decrypt:
        mock_decrypt.side_effect = lambda x, y: x
        with patch.object(DeviceProtocol2, "handle_device_bound") as mock:
            protocol.datagram_received(json.dumps(response).encode(), ("0.0.0.0", 0))
            assert mock.call_count == 1
            assert mock.call_args[0][0] == "fake-key"
    
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
async def test_send_and_update_device_status_using_val(addr, family):
    with Responder(family, addr[1]) as sock:

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)

            r = DEFAULT_RESPONSE
            r["pack"] = DeviceProtocolBase2.encrypt_payload(
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
async def test_send_and_update_device_status_using_p(addr, family):
    with Responder(family, addr[1]) as sock:

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)

            r = DEFAULT_RESPONSE
            r["pack"] = DeviceProtocolBase2.encrypt_payload(
                {"opt": ["prop-a", "prop-b"], "p": ["val-a", "val-b"]}
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
            r["pack"] = DeviceProtocolBase2.encrypt_payload(
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
