import asyncio
import json
import logging
import socket
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Tuple, Union

from greeclimate.cipher import CipherBase
from greeclimate.deviceinfo import DeviceInfo

NETWORK_TIMEOUT = 10
_LOGGER = logging.getLogger(__name__)

IPAddr = Tuple[str, int]


class Commands(Enum):
    BIND = "bind"
    CMD = "cmd"
    PACK = "pack"
    SCAN = "scan"
    STATUS = "status"


class Response(Enum):
    BIND_OK = "bindok"
    DATA = "dat"
    RESULT = "res"


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
        self._timeout: int = timeout
        self._drained: asyncio.Event = drained or asyncio.Event()
        self._drained.set()

        self._transport: Union[asyncio.transports.DatagramTransport, None] = None
        self._cipher: Union[CipherBase, None] = None


    # This event need to be implemented to handle incoming requests
    def packet_received(self, obj, addr: IPAddr) -> None:
        """Event called when a packet is received and decoded.

        Args:
            obj (JSON): Json object with decoded UDP data
            addr (IPAddr): Endpoint address of the sender
        """
        raise NotImplementedError("packet_received must be implemented in a subclass")

    @property
    def device_cipher(self) -> CipherBase:
        """Sets the encryption key used for device data."""
        return self._cipher

    @device_cipher.setter
    def device_cipher(self, value: CipherBase):
        """Gets the encryption key used for device data."""
        self._cipher = value

    @property
    def device_key(self) -> str:
        """Gets the encryption key used for device data."""
        if self._cipher is None:
            raise ValueError("Cipher object not set")
        return self._cipher.key

    @device_key.setter
    def device_key(self, value: str):
        """Sets the encryption key used for device data."""
        if self._cipher is None:
            raise ValueError("Cipher object not set")
        self._cipher.key = value

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

    def pause_writing(self) -> None:
        """Stop writing additional data to the transport."""
        self._drained.clear()
        super().pause_writing()

    def resume_writing(self) -> None:
        """Resume writing data to the transport."""
        self._drained.set()
        super().resume_writing()

    def datagram_received(self, data: bytes, addr: IPAddr) -> None:
        """Handle an incoming datagram."""
        if len(data) == 0:
            return

        obj = json.loads(data)

        if obj.get("pack"):
            obj["pack"] = self._cipher.decrypt(obj["pack"])

        _LOGGER.debug("Received packet from %s:\n<- %s", addr[0], json.dumps(obj))
        self.packet_received(obj, addr)

    async def send(self, obj, addr: IPAddr = None, cipher: Union[CipherBase, None] = None) -> None:
        """Send encode and send JSON command to the device.

        Args:
            addr (object): (Optional) Address to send the message
            cipher (object): (Optional) Initial cipher to use for SCANNING and BINDING 
        """
        _LOGGER.debug("Sending packet:\n-> %s", json.dumps(obj))

        if obj.get("pack"):
            if obj.get("i") == 1:
                if cipher is None:
                    raise ValueError("Cipher must be supplied for SCAN or BIND messages")
                self._cipher = cipher

            obj["pack"], tag = self._cipher.encrypt(obj["pack"])
            if tag:
                obj["tag"] = tag

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
    _handlers = {}

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

    def add_handler(self, event_name: Response, callback):
        """Add a callback for a specific event."""
        if event_name not in Response:
            raise ValueError(f"Invalid event name: {event_name.value}")

        if event_name not in self._handlers:
            self._handlers[event_name] = []
        self._handlers[event_name].append(callback)

    def remove_handler(self, event_name: Response, callback):
        """Remove a specific callback for a specific event."""
        if event_name not in Response:
            raise ValueError(f"Invalid event name: {event_name.value}")

        if event_name in self._handlers:
            self._handlers[event_name].remove(callback)

    def packet_received(self, obj, addr: IPAddr) -> None:
        """Event called when a packet is received and decoded.

        Args:
            obj (JSON): Json object with decoded UDP data
            addr (IPAddr): Endpoint address of the sender
        """
        params = {
            Response.BIND_OK.value: lambda o, a: [o["pack"]["key"]],
            Response.DATA.value: lambda o, a: [dict(zip(o["pack"]["cols"], o["pack"]["dat"]))],
            Response.RESULT.value: lambda o, a: [dict(zip(o["pack"]["opt"], o["pack"]["val"]))],
        }
        handlers = {
            Response.BIND_OK.value: lambda *args: self.__handle_device_bound(*args),
            Response.DATA.value: lambda *args: self.__handle_state_update(*args),
            Response.RESULT.value: lambda *args: self.__handle_state_update(*args),
        }
        try:
            resp = obj.get("pack", {}).get("t")
            handler = handlers.get(resp, self.handle_unknown_packet)
            param = params.get(resp, lambda o, a: (o, a))(obj, addr)
            handler(*param)
        except AttributeError as e:
            _LOGGER.exception("Error while handling packet", exc_info=e)
        except KeyError as e:
            _LOGGER.exception("Error while handling packet", exc_info=e)
        else:
            # Call any registered callbacks for this event
            if resp in handlers:
                for callback in self._handlers.get(Response(resp), []):
                    callback(*param)

    def handle_unknown_packet(self, obj, addr: IPAddr) -> None:
        _LOGGER.warning("Received unknown packet from %s:\n%s", addr[0], json.dumps(obj))

    def __handle_device_bound(self, key: str) -> None:
        self._ready.set()
        self.handle_device_bound(key)

    def handle_device_bound(self, key: str) -> None:
        """ Implement this function to handle device bound events. """
        pass

    def __handle_state_update(self, data) -> None:
        self.handle_state_update(**data)

    def handle_state_update(self, **kwargs) -> None:
        """ Implement this function to handle device state updates. """
        pass

    def _generate_payload(self, command: Commands, device_info: DeviceInfo, data: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "cid": "app",
            "i": 1 if command in [Commands.BIND, Commands.SCAN] else 0,
            "t": Commands.PACK.value if data is not None else command.value,
            "uid": 0,
            "tcid": device_info.mac
        }
        if data is not None:
            payload["pack"] = {
                "t": command.value,
                "mac": device_info.mac
            }
            payload["pack"].update(data)
        return payload

    def create_bind_message(self, device_info: DeviceInfo) -> Dict[str, Any]:
        return self._generate_payload(Commands.BIND, device_info, {"uid": 0})

    def create_status_message(self, device_info: DeviceInfo, *args) -> Dict[str, Any]:
        return self._generate_payload(Commands.STATUS, device_info, {"cols": list(args)})

    def create_command_message(self, device_info: DeviceInfo, **kwargs) -> Dict[str, Any]:
        return self._generate_payload(Commands.CMD, device_info,
                                      {"opt": list(kwargs.keys()), "p": list(kwargs.values())})
