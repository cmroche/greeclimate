import asyncio
import base64
import json
import logging
import socket
from dataclasses import dataclass
from typing import Any, Dict, Text, Tuple, Union

from Crypto.Cipher import AES

from greeclimate.deviceinfo import DeviceInfo

NETWORK_TIMEOUT = 10
GENERIC_KEY = ["a3K8Bx%2r8Y7#xDh"]
GCM_NONCE = b'\x54\x40\x78\x44\x49\x67\x5a\x51\x6c\x5e\x63\x13'
GCM_AEAD = b'qualcomm-test'

_LOGGER = logging.getLogger(__name__)


IPAddr = Tuple[str, int]


class Commands:
    SCAN = "scan"
    BIND = "bind"
    PACK = "pack"

@dataclass
class IPInterface:
    ip_address: str
    bcast_address: str


class DeviceProtocolBase2(asyncio.DatagramProtocol):
    """Event driven device protocol class."""

    def __init__(self, timeout: int = 10, drained: asyncio.Event = None) -> None:
        """Initialize the device protocol object.

        Args:
            timeout (int): Packet send timeout
            drained (asyncio.Event): Packet send drain event signal
        """
        self._timeout = timeout
        self._drained = drained or asyncio.Event()
        self._drained.set()
        self._transport = None
        self._key = None

    # This event need to be implemented to handle incoming requests
    def packet_received(self, obj, addr: IPAddr) -> None:
        """Event called when a packet is received and decoded.

        Args:
            obj (JSON): Json object with decoded UDP data
            addr (IPAddr): Endpoint address of the sender
        """
        raise NotImplementedError("packet_received must be implemented in a subclass")

    @property
    def device_key(self) -> str:
        """Sets the encryption key used for device data."""
        return self._key

    @device_key.setter
    def device_key(self, value: str):
        """Gets the encryption key used for device data."""
        self._key = value

    def close(self) -> None:
        """Close the UDP transport."""
        try:
            self._transport.close()
            self._transport = None
        except RuntimeError:
            pass

    def connection_made(self, transport: asyncio.transports.DatagramTransport) -> None:
        """Called when the Datagram protocol handler is initialized."""
        self._transport = transport

    def connection_lost(self, exc: Exception) -> None:
        """Handle a closed socket."""

        if self._transport is not None:
            self._transport.close()
            self._transport = None

        # In this case the connection was closed unexpectedly
        if exc is not None:
            _LOGGER.exception("Connection was closed unexpectedly", exc_info=exc)
            raise exc

    def error_received(self, exc: Exception) -> None:
        """Handle error while sending/receiving datagrams."""
        _LOGGER.exception("Connection reported an exception", exc_info=exc)
        raise exc

    def pause_writing(self) -> None:
        """Stop writing additional data to the transport."""
        self._drained.clear()
        super().pause_writing()

    def resume_writing(self) -> None:
        """Resume writing data to the transport."""
        self._drained.set()
        super().resume_writing()

    @staticmethod
    def decrypt_payload(payload, key=GENERIC_KEY[0]):
        cipher = AES.new(key.encode(), AES.MODE_ECB)
        decoded = base64.b64decode(payload)
        decrypted = cipher.decrypt(decoded).decode()
        t = decrypted.replace(decrypted[decrypted.rindex("}") + 1 :], "")
        return json.loads(t)

    @staticmethod
    def encrypt_payload(payload, key=GENERIC_KEY[0]):
        def pad(s):
            bs = 16
            return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

        cipher = AES.new(key.encode(), AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(json.dumps(payload)).encode())
        encoded = base64.b64encode(encrypted).decode()
        return encoded

    def datagram_received(self, data: bytes, addr: IPAddr) -> None:
        """Handle an incoming datagram."""
        if len(data) == 0:
            return

        obj = json.loads(data)

        # It could be either a v1 or v2 key
        key = GENERIC_KEY[0] if obj.get("i") == 1 else self._key

        if obj.get("pack"):
            obj["pack"] = DeviceProtocolBase2.decrypt_payload(obj["pack"], key)

        _LOGGER.debug("Received packet from %s:\n%s", addr[0], json.dumps(obj))

        self.packet_received(obj, addr)

    async def send(self, obj, addr: IPAddr = None) -> None:
        """Send encode and send JSON command to the device."""
        _LOGGER.debug("Sending packet:\n%s", json.dumps(obj))

        if obj.get("pack"):
            key = GENERIC_KEY[0] if obj.get("i") == 1 else self._key
            obj["pack"] = DeviceProtocolBase2.encrypt_payload(obj["pack"], key)

        data_bytes = json.dumps(obj).encode()
        self._transport.sendto(data_bytes, addr)

        task = asyncio.create_task(self._drained.wait())
        await asyncio.wait_for(task, self._timeout)



class BroadcastListenerProtocol(DeviceProtocolBase2):
    """Special protocol handler for when broadcast is needed."""

    def connection_made(self, transport: asyncio.transports.DatagramTransport) -> None:
        """Called when the Datagram protocol handler is initialized."""
        super().connection_made(transport)

        sock = transport.get_extra_info("socket")  # type: socket.socket
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


class DeviceProtocol2(DeviceProtocolBase2):
    """Protocol handler for direct device communication."""

    def __init__(self, timeout: int = 10, drained: asyncio.Event = None) -> None:
        """Initialize the device protocol object.

        Args:
            timeout (int): Packet send timeout
            drained (asyncio.Event): Packet send drain event signal
        """
        DeviceProtocolBase2.__init__(self, timeout, drained)
        self._ready = asyncio.Event()
        self._ready.clear()

    @property
    def ready(self) -> asyncio.Event:
        return self._ready

    def packet_received(self, obj, addr: IPAddr) -> None:
        """Event called when a packet is received and decoded.

        Args:
            obj (JSON): Json object with decoded UDP data
            addr (IPAddr): Endpoint address of the sender
        """
        handlers = {
            "bindok": lambda o, a: self.__handle_device_bound(o["pack"]["key"]),
        }
        resp = obj.get("pack", {}).get("t")
        handler = handlers.get(resp, self.handle_unknown_packet)
        try:
            handler(obj, addr)
        except KeyError as e:
            _LOGGER.exception("Error while handling packet", exc_info=e)

    def handle_unknown_packet(self, obj, addr: IPAddr) -> None:
        _LOGGER.warning("Received unknown packet from %s:\n%s", addr[0], json.dumps(obj))

    def __handle_device_bound(self, key: str) -> None:
        self._ready.set()
        self.handle_device_bound(key)

    def handle_device_bound(self, key: str) -> None:
        """ Implement this function to handle device bound events. """
        pass

    def _generate_payload(self, command: str, device_info: DeviceInfo, data: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "cid": "app",
            "i": 1,
            "t": Commands.PACK if data is not None else command,
            "uid": 0,
            "tcid": device_info.mac
        }
        if data is not None:
            payload["pack"] = {
                "t": command,
                "mac": device_info.mac
            }
        return payload

    def create_bind_message(self, device_info: DeviceInfo) -> Dict[str, Any]:
        return self._generate_payload(Commands.BIND, device_info, {"t": "bind", "uid": 0})


class DeviceProtocol(asyncio.DatagramProtocol):
    def __init__(
        self, recvq: asyncio.Queue, excq: asyncio.Queue, drained: asyncio.Event
    ) -> None:
        self._loop = asyncio.get_event_loop()

        self._recvq = recvq
        self._excq = excq
        self._drained = drained

        self._drained.set()

        # Transports are connected at the time a connection is made.
        self._transport = None

    def connection_made(self, transport: asyncio.transports.DatagramTransport) -> None:

        self._transport = transport

    def datagram_received(self, data, addr: IPAddr) -> None:
        self._recvq.put_nowait((data, addr))

    def connection_lost(self, exc) -> None:
        if exc is not None:
            self._excq.put_nowait(exc)

        if self._transport is not None:
            self._transport.close()
            self._transport = None

    def error_received(self, exc) -> None:
        self._excq.put_nowait(exc)

    def pause_writing(self) -> None:
        self._drained.clear()
        super().pause_writing()

    def resume_writing(self) -> None:
        self._drained.set()
        super().resume_writing()


# Concepts and code here were taken from https://github.com/jsbronder/asyncio-dgram
class DatagramStream:
    def __init__(self, transport, recvq, excq, drained, timeout: int = 120):
        self._transport = transport
        self._recvq = recvq
        self._excq = excq
        self._drained = drained
        self._timeout = timeout

    def __del__(self):
        self.close()

    @property
    def exception(self):
        try:
            exc = self._excq.get_nowait()
            raise exc
        except asyncio.queues.QueueEmpty:
            pass

    @property
    def socket(self):
        return self._transport.get_extra_info("socket")

    def close(self):
        try:
            self._transport.close()
        except RuntimeError:
            pass

    async def send(self, data, addr=None) -> None:
        _ = self.exception
        self._transport.sendto(data, addr)

        task = asyncio.create_task(self._drained.wait())
        await asyncio.wait_for(task, self._timeout)

    async def send_device_data(self, data, key=GENERIC_KEY[0]) -> None:
        """Send a formatted request to the device."""
        _LOGGER.debug("Sending packet:\n%s", json.dumps(data))

        if "pack" in data:
            data["pack"] = DatagramStream.encrypt_payload(data["pack"], key)

        data_bytes = json.dumps(data).encode()
        await self.send(data_bytes)

    def recv_ready(self):
        _ = self.exception
        return not self._recvq.empty()

    async def recv(self):
        _ = self.exception

        task = asyncio.create_task(self._recvq.get())
        await asyncio.wait_for(task, self._timeout)
        return task.result()

    async def recv_device_data(self, key=GENERIC_KEY[0]):
        """Receive a formatted request from the device."""
        (data_bytes, addr) = await self.recv()
        if len(data_bytes) == 0:
            return

        data = json.loads(data_bytes)

        if "pack" in data:
            data["pack"] = DatagramStream.decrypt_payload(data["pack"], key)

        _LOGGER.debug("Received packet:\n%s", json.dumps(data))
        return (data, addr)

    @staticmethod
    def decrypt_payload(payload, key=GENERIC_KEY[0]):
        cipher = AES.new(key.encode(), AES.MODE_ECB)
        decoded = base64.b64decode(payload)
        decrypted = cipher.decrypt(decoded).decode()
        t = decrypted.replace(decrypted[decrypted.rindex("}") + 1 :], "")
        return json.loads(t)

    @staticmethod
    def encrypt_payload(payload, key=GENERIC_KEY[0]):
        def pad(s):
            bs = 16
            return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

        cipher = AES.new(key.encode(), AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(json.dumps(payload)).encode())
        encoded = base64.b64encode(encrypted).decode()
        return encoded


async def create_datagram_stream(target: IPAddr) -> DatagramStream:
    loop = asyncio.get_event_loop()
    recvq = asyncio.Queue()
    excq = asyncio.Queue()
    drained = asyncio.Event()

    transport, _ = await loop.create_datagram_endpoint(
        lambda: DeviceProtocol(recvq, excq, drained), remote_addr=target
    )
    return DatagramStream(transport, recvq, excq, drained, timeout=NETWORK_TIMEOUT)



async def send_state(property_values, device_info, key=GENERIC_KEY[0]):
    payload = {
        "cid": "app",
        "i": 0,
        "t": "pack",
        "uid": 0,
        "tcid": device_info.mac,
        "pack": {
            "opt": list(property_values.keys()),
            "p": list(property_values.values()),
            "t": "cmd",
        },
    }

    remote_addr = (device_info.ip, device_info.port)
    stream = await create_datagram_stream(remote_addr)
    try:
        await stream.send_device_data(payload, key)
        (r, _) = await stream.recv_device_data(key)
    except asyncio.TimeoutError as e:
        raise e
    except Exception as e:
        _LOGGER.exception("Encountered an error sending state to device")
        raise e
    finally:
        stream.close()

    cols = r["pack"]["opt"]

    # Some devices only return only "p" and not both "p" and "val"
    dat = r["pack"].get("val") or r["pack"].get("p")
    return dict(zip(cols, dat))


async def request_state(properties, device_info, key=GENERIC_KEY[0]):
    payload = {
        "cid": "app",
        "i": 0,
        "t": "pack",
        "uid": 0,
        "tcid": device_info.mac,
        "pack": {"mac": device_info.mac, "t": "status", "cols": list(properties)},
    }

    remote_addr = (device_info.ip, device_info.port)
    stream = await create_datagram_stream(remote_addr)
    try:
        await stream.send_device_data(payload, key)
        (r, _) = await stream.recv_device_data(key)
    except asyncio.TimeoutError as e:
        raise e
    except Exception as e:
        _LOGGER.exception("Encountered an error requesting update from device")
        raise e
    finally:
        stream.close()

    cols = r["pack"]["cols"]
    dat = r["pack"]["dat"]
    return dict(zip(cols, dat))
