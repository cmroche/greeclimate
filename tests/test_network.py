import asyncio
import json
import socket
from threading import Thread
from unittest.mock import patch, MagicMock

import pytest

from greeclimate.cipher import CipherV1, CipherV2
from greeclimate.exceptions import DeviceNotBoundError
from greeclimate.taskable import Taskable
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
    DEFAULT_REQUEST, generate_response, FakeCipher,
    udp_peer,
)
from .test_device import (
    RECOVERY_MAC,
    get_mock_info,
    recovery_packet,
    recovery_receive,
    recovery_session,
)
from .test_emulator import peer_packet, peer_reply


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
        self.device_cipher = FakeCipher(b"1234567890123456")

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
    dp2.device_cipher = FakeCipher(key.encode())
    assert dp2.device_cipher.key == key


@pytest.mark.asyncio
async def test_connection_error():
    """A lost connection releases a pending send through the library contract."""
    loop = asyncio.get_running_loop()
    errors = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda loop, context: errors.append(context))
    protocol = DeviceProtocolBase2()
    pending = None
    async with udp_peer() as (peer, received):
        transport, _ = await loop.create_datagram_endpoint(
            lambda: protocol, remote_addr=peer.get_extra_info("sockname")
        )
        try:
            protocol.pause_writing()
            pending = asyncio.create_task(protocol.send({"t": "scan"}))
            await asyncio.wait_for(received.get(), 1)
            transport.close()
            with pytest.raises(DeviceNotBoundError):
                await asyncio.wait_for(pending, 1)
            protocol.close()
            assert transport.is_closing()
            assert not errors
        finally:
            transport.close()
            if pending is not None and not pending.done():
                pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)
            loop.set_exception_handler(previous_handler)


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

            p = json.dumps(DISCOVERY_RESPONSE)
            s.sendto(p.encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        # Run the listener portion now
        loop = asyncio.get_event_loop()

        bcast = (addr[0], 7000)
        local_addr = (addr[0], 0)

        dp2 = FakeDiscoveryProtocol()
        dp2.device_cipher = FakeCipher(b"1234567890123456")
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

        # Send the scan command
        await protocol.send(DEFAULT_REQUEST, None, FakeCipher(b"1234567890123456"))

        # Wait on the scan response
        task = asyncio.create_task(protocol.packets.get())
        await asyncio.wait_for(task, DEFAULT_TIMEOUT)
        response = task.result()

        assert response == DEFAULT_RESPONSE

        sock.close()
        serv.join(timeout=DEFAULT_TIMEOUT)


def test_bindok_handling():
    """Test the bindok response."""
    response = generate_response({"t": "bindok", "key": "fake-key"})
    protocol = DeviceProtocol2(timeout=DEFAULT_TIMEOUT)
    protocol.device_cipher = FakeCipher(b"1234567890123456")
    
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


@pytest.mark.parametrize("values", [
    {"val": ["value"]},
    {"p": ["value"]},
    {"val": ["value"], "p": ["ignored"]},
    {"val": [], "p": ["value"]},
    {"val": None, "p": ["value"]},
])
def test_handle_result_update(values):
    protocol = DeviceProtocol2Test()
    callback = MagicMock()
    protocol.add_handler(Response.RESULT, callback)
    protocol.packet_received({
        "pack": {"t": "RES", "opt": ["key"], **values}
    }, ("0.0.0.0", 0))
    assert protocol.state == {"key": "value"}
    callback.assert_called_once_with({"key": "value"})


@pytest.mark.parametrize("pack, expected", [
    ({"t": "DAT", "cols": [], "dat": []}, {}),
    ({"t": "res", "opt": [], "p": []}, {}),
    ({"t": "dat", "cols": ["Pow", "Pow"], "dat": [0, 1]}, {"Pow": 1}),
    ({"t": "res", "opt": ["Pow", "Pow"], "p": [0, 1]}, {"Pow": 1}),
    (
        {"t": "dat", "cols": ["vendor-field", "hid"], "dat": [None, "firmware.bin"]},
        {"vendor-field": None, "hid": "firmware.bin"},
    ),
])
def test_response_property_array_variants(pack, expected):
    protocol = DeviceProtocol2Test()
    callback = MagicMock()
    protocol.add_handler(Response(pack["t"].casefold()), callback)
    protocol.packet_received({"pack": pack}, ("127.0.0.1", 1))
    assert protocol.state == expected
    callback.assert_called_once_with(expected)


@pytest.mark.parametrize("response, arrays, hook, value", [
    (Response.DATA, {"cols": ["Pow"], "dat": [0]}, "handle_data_update", 0),
    (Response.RESULT, {"opt": ["Pow"], "p": [1]}, "handle_result_update", 1),
])
def test_response_specific_hook_preserves_normalized_callback(response, arrays, hook, value):
    protocol = DeviceProtocol2Test()
    callback = MagicMock()
    update = MagicMock()
    setattr(protocol, hook, update)
    protocol.add_handler(response, callback)

    protocol.packet_received({
        "pack": {"t": response.value.upper(), **arrays}
    }, ("127.0.0.1", 1))

    expected = {"Pow": value}
    update.assert_called_once_with(**expected)
    callback.assert_called_once_with(expected)
    assert protocol.state == {}


def test_sublist_dispatch_retains_page_metadata():
    protocol = DeviceProtocol2Test()
    protocol.handle_sublist = MagicMock()
    callback = MagicMock()
    protocol.add_handler(Response.SUBLIST, callback)
    pack = {"t": "subList", "r": 200, "c": 7, "i": 5, "list": [{"mac": "aabbccddeeff00"}]}

    protocol.packet_received({"pack": pack}, ("127.0.0.1", 1))

    protocol.handle_sublist.assert_called_once_with(pack)
    callback.assert_called_once_with(pack)
    assert protocol.state == {}


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
    assert protocol.key == "fake-key"


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
    callback.assert_called_once()

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


def test_packet_received_not_implemented():
    # Arrange
    protocol = DeviceProtocolBase2()

    # Act
    with pytest.raises(NotImplementedError):
        protocol.packet_received({}, ("0.0.0.0", 0))
        
        
def test_packet_received_invalid_data():
    # Arrange
    protocol = DeviceProtocol2()

    # Act
    protocol.packet_received(None, ("0.0.0.0", 0))
    protocol.packet_received({}, ("0.0.0.0", 0))
    protocol.packet_received({"pack"}, ("0.0.0.0", 0))
    
    with patch.object(protocol, "handle_unknown_packet") as mock:
        protocol.packet_received({"pack": {"t": "unknown"}}, ("0.0.0.0", 0))
        mock.assert_called_once()


def test_set_get_cipher():
    # Arrange
    protocol = DeviceProtocolBase2()
    cipher = FakeCipher(b"1234567890123456")

    # Act
    protocol.device_cipher = cipher

    # Assert
    assert protocol.device_cipher == cipher


def test_cipher_is_not_set():
    # Arrange
    protocol = DeviceProtocolBase2()

    # Act
    key = None
    with pytest.raises(ValueError):
        key = protocol.device_key
        
    assert key is None
    
    with pytest.raises(ValueError):
        protocol.device_key = "fake-key"
    
    
def test_add_invalid_handler():
    # Arrange
    protocol = DeviceProtocol2()
    callback = MagicMock()
    
    # Act
    with pytest.raises(ValueError):
        protocol.add_handler(Response("invalid"), callback)
    
    with pytest.raises(ValueError):
        protocol.add_handler(Response("invalid"), callback)


@pytest.mark.asyncio
@pytest.mark.parametrize("event", [Response.DATA, Response.RESULT])
async def test_recovery_handler_ownership_and_close_isolation(event):
    """The same callable belongs independently to each protocol instance."""
    loop = asyncio.get_running_loop()
    first, second = DeviceProtocol2(), DeviceProtocol2()
    key = b"0123456789abcdef"
    first.device_cipher = CipherV1(key)
    second.device_cipher = CipherV1(key)
    callbacks = asyncio.Queue()
    shared = callbacks.put_nowait
    first.add_handler(event, shared)
    second.add_handler(event, shared)
    payload = (
        {"t": "dat", "cols": ["Pow"], "dat": [1]}
        if event is Response.DATA
        else {"t": "res", "opt": ["Pow"], "val": [1]}
    )
    wire = peer_packet({}, payload, key)
    async with udp_peer() as (peer, received):
        transports = []
        try:
            for protocol in (first, second):
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: protocol, remote_addr=peer.get_extra_info("sockname")
                )
                transports.append(transport)
            for transport in transports:
                peer.sendto(wire, transport.get_extra_info("sockname"))
                assert await asyncio.wait_for(callbacks.get(), 1) == {"Pow": 1}
                assert callbacks.empty()
            first.remove_handler(event, shared)
            first.close()
            peer.sendto(wire, transports[1].get_extra_info("sockname"))
            assert await asyncio.wait_for(callbacks.get(), 1) == {"Pow": 1}
            assert callbacks.empty()
            await second.send({"t": "still-open"})
            data, _ = await asyncio.wait_for(received.get(), 1)
            assert json.loads(data) == {"t": "still-open"}
        finally:
            for transport in transports:
                transport.close()
            for protocol in (first, second):
                if shared in protocol._handlers.get(event, []):
                    protocol.remove_handler(event, shared)


@pytest.mark.asyncio
@pytest.mark.parametrize("close_during_dispatch", [False, True])
async def test_recovery_dispatch_snapshot_and_stop_on_close(close_during_dispatch):
    loop = asyncio.get_running_loop()
    protocol = DeviceProtocol2()
    key = b"0123456789abcdef"
    protocol.device_cipher = CipherV1(key)
    calls = []
    dispatched = asyncio.Event()

    def last(data):
        calls.append("last")
        dispatched.set()

    def added(data):
        calls.append("added")

    def first(data):
        calls.append("first")
        if close_during_dispatch:
            protocol.close()
            dispatched.set()
        else:
            protocol.remove_handler(Response.DATA, last)
            protocol.add_handler(Response.DATA, added)

    protocol.add_handler(Response.DATA, first)
    protocol.add_handler(Response.DATA, last)
    async with udp_peer() as (peer, _):
        transport, _ = await loop.create_datagram_endpoint(
            lambda: protocol, remote_addr=peer.get_extra_info("sockname")
        )
        try:
            peer.sendto(
                peer_packet({}, {"t": "dat", "cols": ["Pow"], "dat": [1]}, key),
                transport.get_extra_info("sockname"),
            )
            await asyncio.wait_for(dispatched.wait(), 1)
            assert calls == (["first"] if close_during_dispatch else ["first", "last"])
        finally:
            transport.close()
            for callback in (first, last, added):
                if callback in protocol._handlers.get(Response.DATA, []):
                    protocol.remove_handler(Response.DATA, callback)


@pytest.mark.asyncio
async def test_recovery_close_before_connect_and_paused_send():
    protocol = DeviceProtocolBase2()
    protocol.close()
    protocol.close()
    with pytest.raises(DeviceNotBoundError):
        await protocol.send({"t": "scan"})

    loop = asyncio.get_running_loop()
    async with udp_peer() as (peer, received):
        transport, _ = await loop.create_datagram_endpoint(
            lambda: protocol, remote_addr=peer.get_extra_info("sockname")
        )
        pending = None
        try:
            protocol.pause_writing()
            pending = asyncio.create_task(protocol.send({"t": "scan"}))
            await asyncio.wait_for(received.get(), 1)
            assert not pending.done()
            protocol.close()
            protocol.close()
            with pytest.raises(DeviceNotBoundError):
                await asyncio.wait_for(pending, 1)
            with pytest.raises(DeviceNotBoundError):
                await protocol.send({"t": "scan"})
            assert transport.is_closing()
        finally:
            transport.close()
            if pending is not None and not pending.done():
                pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("cipher_type", [CipherV1, CipherV2])
async def test_recovery_malformed_datagrams_do_not_break_next_reply(cipher_type):
    """Bad wire input is ignored; a later real encrypted reply still dispatches."""
    loop = asyncio.get_running_loop()
    errors = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda loop, context: errors.append(context))
    protocol = DeviceProtocol2Test()
    state_update = MagicMock(wraps=protocol.handle_state_update)
    protocol.handle_state_update = state_update
    protocol.device_cipher = cipher_type(b"0123456789abcdef")
    replies = asyncio.Queue()
    callback = replies.put_nowait
    protocol.add_handler(Response.DATA, callback)
    protocol.add_handler(Response.RESULT, callback)
    encrypted, tag = protocol.device_cipher.encrypt(
        {"t": "dat", "cols": ["Pow"], "dat": [1]}
    )
    valid = {"pack": encrypted}
    if tag:
        valid["tag"] = tag
    malformed = [
        b"{",
        b"\xff",
        b"null",
        b"[]",
        b"42",
        b'{"pack": null}',
        b'{"pack": []}',
        b'{"pack": 7}',
        b'{"pack": ""}',
        b'{"pack": "%%%"}',
        b'{"pack": "YQ=="}',
        b'{"pack": "AAAAAAAAAAAAAAAAAAAAAA=="}',
    ]
    malformed_packs = [{"t": []}, {"t": {}}, {"t": 7}]
    for response, columns, values in [
        ("dat", "cols", "dat"), ("res", "opt", "val"), ("res", "opt", "p")
    ]:
        base = {"t": response, columns: ["Pow"], values: [9]}
        for field in (columns, values):
            for invalid in (7, None, "Pow", {"Pow": 9}, False, ""):
                malformed_packs.append(dict(base, **{field: invalid}))
            missing = dict(base)
            del missing[field]
            malformed_packs.append(missing)
        for invalid in (7, None, [], {}, "", "self"):
            malformed_packs.append(dict(base, **{columns: [invalid]}))
        for bad_columns, bad_values in [
            (["Pow", "Mod"], [9]), (["Pow"], [9, 2]),
            ([], [9]), (["Pow"], []),
        ]:
            malformed_packs.append(
                dict(base, **{columns: bad_columns, values: bad_values})
            )
    for pack in malformed_packs:
        encrypted, tag = protocol.device_cipher.encrypt(pack)
        envelope = {"pack": encrypted}
        if tag:
            envelope["tag"] = tag
        malformed.append(json.dumps(envelope).encode())
    async with udp_peer() as (peer, _):
        transport, _ = await loop.create_datagram_endpoint(
            lambda: protocol, remote_addr=peer.get_extra_info("sockname")
        )
        try:
            endpoint = transport.get_extra_info("sockname")
            for packet in malformed:
                peer.sendto(packet, endpoint)
                peer.sendto(json.dumps(valid).encode(), endpoint)
                assert await asyncio.wait_for(replies.get(), 1) == {"Pow": 1}
                assert replies.empty()
                state_update.assert_called_once_with(Pow=1)
                assert protocol.state == {"Pow": 1}
                state_update.reset_mock()
            assert not errors
        finally:
            transport.close()
            protocol.remove_handler(Response.DATA, callback)
            protocol.remove_handler(Response.RESULT, callback)
            loop.set_exception_handler(previous_handler)


@pytest.mark.asyncio
@pytest.mark.parametrize("decrypted", [None, [], 7, "not-a-pack"])
async def test_recovery_decrypted_pack_must_be_dictionary(decrypted):
    protocol = FakeDeviceProtocol()
    with patch.object(protocol, "_decrypt_pack", return_value=decrypted):
        protocol.datagram_received(b'{"pack": "encrypted"}', ("127.0.0.1", 1))
    assert protocol.packets.empty()
    protocol.datagram_received(b'{"t": "unwrapped"}', ("127.0.0.1", 1))
    assert await asyncio.wait_for(protocol.packets.get(), 1) == {"t": "unwrapped"}


@pytest.mark.asyncio
@pytest.mark.parametrize("error_type", [ValueError, KeyError, AttributeError, TypeError])
async def test_recovery_application_callback_errors_are_not_decode_errors(error_type):
    protocol = DeviceProtocol2()
    protocol.device_cipher = CipherV1(b"0123456789abcdef")

    def callback(data):
        raise error_type("application callback failed")

    protocol.add_handler(Response.DATA, callback)
    try:
        with pytest.raises(error_type, match="application callback failed"):
            protocol.datagram_received(
                peer_packet(
                    {}, {"t": "dat", "cols": ["Pow"], "dat": [1]},
                    b"0123456789abcdef",
                ),
                ("127.0.0.1", 1),
            )
    finally:
        protocol.remove_handler(Response.DATA, callback)


@pytest.mark.asyncio
async def test_recovery_tracked_task_cancellation_is_instance_local_and_safe():
    loop = asyncio.get_running_loop()
    errors = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda loop, context: errors.append(context))
    owner, other = Taskable(), Taskable()
    started = asyncio.Event()
    blocked = asyncio.Event()
    task = other_task = cancelling_task = None

    async def work():
        started.set()
        await blocked.wait()

    async def cancel_owned_tasks():
        owner._cancel_tasks()
        return "survived"

    async def failed_work():
        raise RuntimeError("synthetic listener failure")

    try:
        task = owner._create_task(work())
        other_task = other._create_task(blocked.wait())
        await asyncio.wait_for(started.wait(), 1)
        cancelling_task = owner._create_task(cancel_owned_tasks())
        assert await asyncio.wait_for(cancelling_task, 1) == "survived"
        await asyncio.gather(task, return_exceptions=True)
        assert task.cancelled()
        assert not other_task.done()
        failed = owner._create_task(failed_work())
        with pytest.raises(RuntimeError):
            await asyncio.wait_for(failed, 1)
        assert owner.tasks == [] and not other_task.done()
        owner._cancel_tasks()
        blocked.set()
        await asyncio.wait_for(other_task, 1)
        callbacks_done = loop.create_future()
        loop.call_soon(callbacks_done.set_result, None)
        await callbacks_done
        assert not errors
    finally:
        tasks = [item for item in (task, other_task, cancelling_task) if item is not None]
        for item in tasks:
            if not item.done():
                item.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        loop.set_exception_handler(previous_handler)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "identity,canonical",
    [
        ("AA:BB:CC:11:22:33", "aabbcc112233"),
        ("AA-BB-CC-11-22-33", "aabbcc112233"),
        ("AABB.CC11.2233", "aabbcc112233"),
        ("AA:BB:CC:11:22:33:44", "aabbcc11223344"),
    ],
)
@pytest.mark.parametrize("command", [Commands.BIND, Commands.STATUS, Commands.CMD])
async def test_recovery_outbound_identity_is_canonical(identity, canonical, command):
    protocol = DeviceProtocol2()
    info = DeviceInfo("127.0.0.1", 1, identity, "synthetic")
    key = b"0123456789abcdef"
    cipher = CipherV1(key)
    protocol.device_cipher = cipher
    loop = asyncio.get_running_loop()
    async with udp_peer() as (peer, received):
        transport, _ = await loop.create_datagram_endpoint(
            lambda: protocol, remote_addr=peer.get_extra_info("sockname")
        )
        try:
            payload = protocol._generate_payload(command, info, {"synthetic": 1})
            await protocol.send(payload, cipher=cipher)
            packet, _ = await asyncio.wait_for(received.get(), 1)
            decoded = peer_reply(packet, key)
            assert decoded["outer"]["tcid"] == canonical
            assert decoded["inner"]["mac"] == canonical
            assert decoded["inner"]["t"] == command.value
            assert info.mac == identity
        finally:
            transport.close()


async def test_recovery_packets_without_session_or_after_close_never_dispatch():
    protocol = FakeDeviceProtocol()
    protocol.device_cipher = None
    endpoint = ("127.0.0.1", 7000)
    wire = peer_packet({}, {"t": "dat", "cols": ["Pow"], "dat": [1]})
    protocol.datagram_received(b"", endpoint)
    protocol.datagram_received(wire, endpoint)
    assert protocol.packets.empty()
    protocol.device_cipher = CipherV1()
    protocol.datagram_received(wire, endpoint)
    assert (await asyncio.wait_for(protocol.packets.get(), 1))["pack"]["dat"] == [1]
    protocol.close()
    protocol.datagram_received(wire, endpoint)
    assert protocol.packets.empty()


async def test_recovery_incomplete_response_does_not_dispatch_or_block_next_reply():
    protocol = DeviceProtocol2()
    protocol.device_cipher = CipherV1()
    events = asyncio.Queue()
    protocol.add_handler(Response.DATA, events.put_nowait)
    endpoint = ("127.0.0.1", 7000)
    try:
        protocol.datagram_received(peer_packet({}, {"t": "dat", "cols": ["Pow"]}), endpoint)
        assert events.empty()
        protocol.datagram_received(
            peer_packet({}, {"t": "dat", "cols": ["Pow"], "dat": [1]}), endpoint
        )
        assert await asyncio.wait_for(events.get(), 1) == {"Pow": 1}
    finally:
        protocol.close()


async def test_recovery_socket_error_releases_pending_send():
    protocol = DeviceProtocolBase2()
    loop = asyncio.get_running_loop()
    async with udp_peer() as (peer, received):
        transport, _ = await loop.create_datagram_endpoint(
            lambda: protocol, remote_addr=peer.get_extra_info("sockname")
        )
        protocol.pause_writing()
        pending = asyncio.create_task(protocol.send({"t": "scan"}))
        try:
            await asyncio.wait_for(received.get(), 1)
            failure = OSError("synthetic socket loss")
            protocol.connection_lost(failure)
            with pytest.raises(DeviceNotBoundError):
                await asyncio.wait_for(pending, 1)
            assert protocol._transport is None
        finally:
            transport.close()
            protocol.close()
            await asyncio.gather(pending, return_exceptions=True)


@pytest.mark.asyncio
async def test_ordinary_device_sublist_callback_preserves_metadata_and_reported_state():
    async with recovery_session(CipherV1()) as (device, peer, queue, addr):
        inventory, data, results = asyncio.Queue(), asyncio.Queue(), asyncio.Queue()
        device.add_handler(Response.SUBLIST, inventory.put_nowait)
        device.add_handler(Response.DATA, data.put_nowait)
        device.add_handler(Response.RESULT, results.put_nowait)
        await recovery_receive(queue, device.device_cipher)
        outer = {"cid": RECOVERY_MAC, "tcid": "app", "i": 0}
        peer.sendto(recovery_packet(
            {"t": "dat", "mac": RECOVERY_MAC, "cols": ["Pow"], "dat": [1]},
            device.device_cipher, outer,
        ), addr)
        assert await asyncio.wait_for(data.get(), 2) == {"Pow": 1}
        pack = {
            "t": "subList", "mac": RECOVERY_MAC, "r": 200, "c": 7, "i": 5,
            "list": [{"mac": "ab123456000001", "mid": "604a"}],
        }
        peer.sendto(recovery_packet(pack, device.device_cipher, outer), addr)
        assert await asyncio.wait_for(inventory.get(), 2) == pack
        assert device.raw_properties == {"Pow": 1} and device.has_valid_state
        assert device.ready.is_set() and data.empty() and results.empty()
        peer.sendto(recovery_packet(
            {"t": "dat", "mac": RECOVERY_MAC, "cols": ["Pow"], "dat": [0]},
            device.device_cipher, outer,
        ), addr)
        assert await asyncio.wait_for(data.get(), 2) == {"Pow": 0}
        assert device.get_property("Pow") == 0 and inventory.empty() and results.empty()
