import asyncio
import json
import logging
import socket
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Tuple, Union

from greeclimate.cipher import CipherBase
from greeclimate.deviceinfo import DeviceInfo, _canonical_mac
from greeclimate.exceptions import DeviceNotBoundError

NETWORK_TIMEOUT = 10
_LOGGER = logging.getLogger(__name__)

IPAddr = Tuple[str, int]


class Commands(Enum):
    BIND = "bind"
    CMD = "cmd"
    PACK = "pack"
    SCAN = "scan"
    STATUS = "status"
    SUBDEV = "subDev"


class Response(Enum):
    BIND_OK = "bindok"
    DATA = "dat"
    RESULT = "res"
    SUBLIST = "sublist"


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
        self._closing = False
        self._transport_closed = asyncio.Event()
        self._transport_closed.set()


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
        """Idempotently close this transport and wake pending sends."""
        self._closing = True
        transport, self._transport = self._transport, None
        self._drained.set()
        if transport is not None:
            transport.close()

    def connection_made(self, transport: asyncio.transports.DatagramTransport) -> None:
        """Install a transport after the preceding transport has finished closing."""
        self._closing = False
        self._transport_closed.clear()
        self._transport = transport

    def connection_lost(self, exc: Exception) -> None:
        """Finalize transport closure without raising from the event loop callback."""
        self._transport = None
        self._closing = True
        self._drained.set()
        self._transport_closed.set()
        if exc is not None:
            _LOGGER.error("Connection was closed unexpectedly", exc_info=exc)

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

    def _decrypt_pack(self, pack, tag=None):
        """Decrypt the pack field of a received packet.

        Override to customize cipher selection (e.g. trying more than one
        cipher for replies from not-yet-identified devices).
        """
        if self._cipher is None:
            raise ValueError("No cipher available for incoming packet")
        return self._cipher.decrypt(pack, tag)

    def datagram_received(self, data: bytes, addr: IPAddr) -> None:
        """Handle an incoming datagram."""
        if not data or self._closing:
            return
        try:
            obj = json.loads(data)
            if not isinstance(obj, dict):
                raise ValueError("Envelope is not a dictionary")
            if "pack" in obj:
                obj["pack"] = self._decrypt_pack(obj["pack"], obj.get("tag"))
                if not isinstance(obj["pack"], dict):
                    raise ValueError("Decrypted pack is not a dictionary")
        except (ValueError, UnicodeError, TypeError) as exc:
            _LOGGER.debug("Ignoring undecodable packet from %s: %s", addr, exc)
            return

        _LOGGER.debug("Received packet from %s:\n<- %s", addr[0], json.dumps(obj))
        self.packet_received(obj, addr)

    async def send(self, obj, addr: IPAddr = None, cipher: Union[CipherBase, None] = None) -> None:
        """Encode and send a command; completion does not imply a reply.

        Args:
            addr (object): (Optional) Address to send the message
            cipher (object): (Optional) Initial cipher to use for SCANNING and BINDING 
        """
        transport = self._transport
        if transport is None or self._closing:
            raise DeviceNotBoundError
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
        transport.sendto(data_bytes, addr)
        await asyncio.wait_for(self._drained.wait(), self._timeout)
        if self._closing or self._transport is not transport:
            raise DeviceNotBoundError


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
        self._handlers = {}
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
            Response.SUBLIST.value: lambda o, a: [o["pack"]],
        }
        handlers = {
            Response.BIND_OK.value: lambda *args: self.__handle_device_bound(*args),
            Response.DATA.value: lambda data: self.handle_data_update(**data),
            Response.RESULT.value: lambda data: self.handle_result_update(**data),
            Response.SUBLIST.value: self.handle_sublist,
        }
        try:
            pack = obj.get("pack", {})
            resp = pack.get("t")
            if not isinstance(resp, str):
                return
            resp = resp.casefold()
            handler = handlers.get(resp, self.handle_unknown_packet)
            if resp in (Response.DATA.value, Response.RESULT.value):
                if resp == Response.DATA.value:
                    columns, values = pack.get("cols"), pack.get("dat")
                else:
                    columns = pack.get("opt")
                    values = pack.get("val")
                    if values is not None and not isinstance(values, list):
                        raise ValueError("RESULT val is not a list")
                    values = values or pack.get("p", [])
                if (
                    not isinstance(columns, list)
                    or not isinstance(values, list)
                    or len(columns) != len(values)
                    # Property names become keyword arguments to a bound handler.
                    or any(
                        not isinstance(name, str) or not name or name == "self"
                        for name in columns
                    )
                ):
                    raise ValueError("Invalid response property arrays")
                param = [dict(zip(columns, values))]
            else:
                param = params.get(resp, lambda o, a: (o, a))(obj, addr)
        except ValueError as e:
            _LOGGER.debug("Ignoring malformed response from %s: %s", addr, e)
        except AttributeError as e:
            _LOGGER.exception("Error while handling packet", exc_info=e)
        except KeyError as e:
            _LOGGER.exception("Error while handling packet", exc_info=e)
        else:
            handler(*param)
            if resp in handlers:
                for callback in tuple(self._handlers.get(Response(resp), ())):
                    if self._closing:
                        break
                    callback(*param)

    def handle_unknown_packet(self, obj, addr: IPAddr) -> None:
        _LOGGER.warning("Received unknown packet from %s:\n%s", addr[0], json.dumps(obj))

    def __handle_device_bound(self, key: str) -> None:
        self.handle_device_bound(key)

    def handle_device_bound(self, key: str) -> None:
        """ Implement this function to handle device bound events. """
        self._ready.set()

    def handle_data_update(self, **data) -> None:
        """Handle reported DATA; default to the existing state-update hook."""
        self.handle_state_update(**data)

    def handle_result_update(self, **data) -> None:
        """Handle command RESULT; default to the existing state-update hook."""
        self.handle_state_update(**data)

    def handle_sublist(self, pack) -> None:
        """Handle an inventory response with its pagination metadata intact."""
        pass

    def handle_state_update(self, **kwargs) -> None:
        """ Implement this function to handle device state updates. """
        pass

    def _generate_payload(self, command: Commands, device_info: DeviceInfo, data: Dict[str, Any]) -> Dict[str, Any]:
        mac = _canonical_mac(device_info.mac)
        payload = {
            "cid": "app",
            "i": 1 if command in [Commands.BIND, Commands.SCAN] else 0,
            "t": Commands.PACK.value if data is not None else command.value,
            "uid": 0,
            "tcid": mac
        }
        if data is not None:
            payload["pack"] = {
                "t": command.value,
                "mac": mac
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
