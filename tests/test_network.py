import asyncio
import json
import socket
from threading import Thread
from typing import Any
from unittest.mock import create_autospec, patch, MagicMock

import pytest

from greeclimate.deviceinfo import DeviceInfo
from greeclimate.network import (
    BroadcastListenerProtocol,
    DeviceProtocolBase2,
    IPAddr,
    DeviceProtocol2, Commands, Response,
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
from .test_device import get_mock_info


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


def test_create_bind_message():
    # Arrange
    device_info = DeviceInfo(*get_mock_info())
    protocol = DeviceProtocol2()

    # Act
    result = protocol.create_bind_message(device_info)

    # Assert
    assert isinstance(result, dict)
    assert result == {
        'cid': 'app',
        'i': 1,  # Default key encryption
        't': 'pack',
        'uid': 0,
        'tcid': device_info.mac,
        'pack': {
            't': 'bind',
            'mac': device_info.mac,
            'uid': 0
        }
    }


def test_create_status_message():
    # Arrange
    device_info = DeviceInfo(*get_mock_info())
    protocol = DeviceProtocol2()

    # Act
    result = protocol.create_status_message(device_info, 'test')

    # Assert
    assert isinstance(result, dict)
    assert result == {
        'cid': 'app',
        'i': 0,  # Device key encryption
        't': 'pack',
        'uid': 0,
        'tcid': device_info.mac,
        'pack': {
            't': 'status',
            'mac': device_info.mac,
            'cols': ['test'],
        }
    }

def test_create_command_message():
    # Arrange
    device_info = DeviceInfo(*get_mock_info())
    protocol = DeviceProtocol2()

    # Act
    result = protocol.create_command_message(device_info, **{'key': 'value'})

    # Assert
    assert isinstance(result, dict)
    assert result == {
        'cid': 'app',
        'i': 0,  # Device key encryption
        't': 'pack',
        'uid': 0,
        'tcid': device_info.mac,
        'pack': {
            't': 'cmd',
            'mac': device_info.mac,
            'opt': ['key'],
            'p': ['value'],
        }
    }


class DeviceProtocol2Test(DeviceProtocol2):
    def __init__(self):
        super().__init__(timeout=DEFAULT_TIMEOUT)
        self.state = {}
        self.key = None
        self.unknown = False

    def handle_state_update(self, **kwargs) -> None:
        self.state = dict(kwargs)

    def handle_device_bound(self, key: str) -> None:
        self._ready.set()
        self.key = key

    def handle_unknown_packet(self, obj, addr: IPAddr) -> None:
        self.unknown = True


def test_handle_state_update():

    # Arrange
    protocol = DeviceProtocol2Test()
    state = {'key': 'value'}

    # Act
    protocol.packet_received({
        'pack': {
            't': 'dat',
            'cols': list(state.keys()),
            'dat': list(state.values())
        }
    }, ("0.0.0.0", 0))

    # Assert
    assert protocol.state == state
    assert protocol.state == {'key': 'value'}


def test_handle_result_update():

    # Arrange
    protocol = DeviceProtocol2Test()
    state = {'key': 'value'}

    # Act
    protocol.packet_received({
        'pack': {
            't': 'res',
            'opt': list(state.keys()),
            'val': list(state.values())
        }
    }, ("0.0.0.0", 0))

    # Assert
    assert protocol.state == state
    assert protocol.state == {'key': 'value'}


def test_handle_device_bound():
    # Arrange
    protocol = DeviceProtocol2Test()

    # Act
    protocol.packet_received({
        'pack': {
            't': 'bindok',
            'key': 'fake-key'
        }
    }, ("0.0.0.0", 0))

    # Assert
    assert protocol._ready.is_set()
    assert protocol.key is "fake-key"


def test_handle_unknown_packet():
    # Arrange
    protocol = DeviceProtocol2Test()

    # Act
    protocol.packet_received({
        'pack': {
            't': 'unknown'
        }
    }, ("0.0.0.0", 0))

    # Assert
    assert protocol.unknown is True


@pytest.mark.parametrize("use_default_key,command,data",
                         [(1, Commands.BIND, {"uid": 0}),
                          (1, Commands.SCAN, None),
                          (0, Commands.STATUS, {'cols': ['test']}),
                          (0, Commands.CMD, {'opt': ['key'], 'p': ['value']})])
def test_generate_payload(use_default_key, command, data):
    # Arrange
    device_info = DeviceInfo(*get_mock_info())
    protocol = DeviceProtocol2()

    # Act
    result = protocol._generate_payload(command, device_info, data)

    # Assert
    expected = {
        'cid': 'app',
        'i': use_default_key,  # Device key encryption
        't': Commands.PACK.value if data is not None else command.value,
        'uid': 0,
        'tcid': device_info.mac,
    }
    if data:
        expected['pack'] = {'t': command.value, 'mac': device_info.mac}
        expected['pack'].update(data)

    assert isinstance(result, dict)
    assert result == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("event_name, data",[
    (Response.BIND_OK, {'key': 'fake-key'}),
    (Response.DATA, {'cols': ['test'], 'dat': ['value']}),
    (Response.RESULT, {'opt': ['key'], 'val': ['value']})
])
async def test_add_and_remove_handler(event_name, data):
    # Arrange
    protocol = DeviceProtocol2()
    callback = MagicMock()
    event_data = {'pack': {'t': event_name.value}}
    event_data['pack'].update(data)

    # Act
    protocol.add_handler(event_name, callback)

    # Assert that the handler was added
    assert event_name in protocol._handlers
    assert callback in protocol._handlers[event_name]

    # Trigger the event
    protocol.packet_received(event_data, ("0.0.0.0", 0))

    # Check that the callback was called
    callback.assert_called_once_with(*data.values())

    # Now remove the handler
    protocol.remove_handler(event_name, callback)

    # Assert that the handler was removed
    assert callback not in protocol._handlers[event_name]

    # Reset the callback
    callback.reset_mock()

    # Trigger the event again
    protocol.packet_received(event_data, ("0.0.0.0", 0))

    # Check that the callback was not called this time
    callback.assert_not_called()

