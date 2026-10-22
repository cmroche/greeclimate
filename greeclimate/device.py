import asyncio
import enum
import logging
import re
from asyncio import AbstractEventLoop
from collections.abc import Mapping, Sequence
from copy import copy
from enum import IntEnum, unique
from types import MappingProxyType
from typing import Union, Optional, Any, List, Dict

from greeclimate.cipher import CipherV1, CipherV2
from greeclimate.deviceinfo import DeviceInfo, _canonical_mac
from greeclimate.device_profile import DeviceProfile, match_device_profile
from greeclimate.exceptions import DeviceNotBoundError, DeviceTimeoutError
from greeclimate.mid_profile import match_mid_profile
from greeclimate.network import DeviceProtocol2, IPAddr
from greeclimate.taskable import Taskable


class Props(enum.Enum):
    POWER = "Pow"
    MODE = "Mod"

    # Dehumidifier fields
    HUM_SET = "Dwet"
    HUM_SENSOR = "DwatSen"
    CLEAN_FILTER = "Dfltr"
    WATER_FULL = "DwatFul"
    DEHUMIDIFIER_MODE = "Dmod"

    TEMP_SET = "SetTem"
    TEMP_SENSOR = "TemSen"
    TEMP_UNIT = "TemUn"
    TEMP_BIT = "TemRec"
    FAN_SPEED = "WdSpd"
    FRESH_AIR = "Air"
    XFAN = "Blo"
    ANION = "Health"
    SLEEP = "SwhSlp"
    SLEEP_MODE = "SlpMod"
    LIGHT = "Lig"
    SWING_HORIZ = "SwingLfRig"
    SWING_VERT = "SwUpDn"
    QUIET = "Quiet"
    TURBO = "Tur"
    STEADY_HEAT = "StHt"
    POWER_SAVE = "SvSt"
    UNKNOWN_HEATCOOLTYPE = "HeatCoolType"


@unique
class TemperatureUnits(IntEnum):
    C = 0
    F = 1


@unique
class Mode(IntEnum):
    Auto = 0
    Cool = 1
    Dry = 2
    Fan = 3
    Heat = 4


@unique
class FanSpeed(IntEnum):
    Auto = 0
    Low = 1
    MediumLow = 2
    Medium = 3
    MediumHigh = 4
    High = 5


@unique
class HorizontalSwing(IntEnum):
    Default = 0
    FullSwing = 1
    Left = 2
    LeftCenter = 3
    Center = 4
    RightCenter = 5
    Right = 6


@unique
class VerticalSwing(IntEnum):
    Default = 0
    FullSwing = 1
    FixedUpper = 2
    FixedUpperMiddle = 3
    FixedMiddle = 4
    FixedLowerMiddle = 5
    FixedLower = 6
    SwingUpper = 7
    SwingUpperMiddle = 8
    SwingMiddle = 9
    SwingLowerMiddle = 10
    SwingLower = 11


class DehumidifierMode(IntEnum):
    Default = 0
    AnionOnly = 9


_CAPABILITY_NAMES = (
    "power", "mode", "target_temperature", "temperature_units", "current_temperature",
    "fan_speed", "fresh_air", "xfan", "anion", "sleep", "light", "horizontal_swing",
    "vertical_swing", "quiet", "turbo", "steady_heat", "power_save", "lan_buzzer_control",
    "target_humidity", "dehumidifier_mode", "current_humidity", "clean_filter", "water_full",
)


def _property_name(name: Union[str, enum.Enum]) -> str:
    if isinstance(name, enum.Enum):
        name = name.value
    if not isinstance(name, str):
        raise TypeError("Property name must be a string or an enum with a string value")
    if not name:
        raise ValueError("Property name must not be empty")
    if name == "self":
        raise ValueError("Property name 'self' is reserved")
    return name


_TEMPERATURE_PROPERTIES = (Props.TEMP_SET.value, Props.TEMP_BIT.value, Props.TEMP_UNIT.value)


class Device(DeviceProtocol2, Taskable):
    """Shared binding, state cache and transport lifecycle."""

    _capability_family = None
    _capability_names = frozenset()

    def __init__(self, device_info: DeviceInfo, timeout: int = 120, bind_timeout: int = 10, loop: AbstractEventLoop = None):
        """Initialize the device object

        Args:
            device_info (DeviceInfo): Information about the physical device
            timeout (int): Timeout for device communication
            bind_timeout (int): Timeout for binding to the device, keep this short to prevent delays determining the
                                correct device cipher to use
            loop (AbstractEventLoop): The event loop to run the device operations on
        """
        DeviceProtocol2.__init__(self, timeout)
        Taskable.__init__(self, loop)
        self._logger = logging.getLogger(__name__)
        self.device_info: DeviceInfo = device_info
        self._mid_profile = match_mid_profile(device_info.mid if device_info is not None else None)
        
        self._bind_timeout = bind_timeout
        self._closed = False
        self._bind_lock = asyncio.Lock()
        self._bind_waiter: asyncio.Future | None = None
        
        """ Device properties """
        self.hid = None
        self._hid_logged = False
        self.version = None
        self._matched_hid = None
        self._matched_profile: Optional[DeviceProfile] = None
        self._properties = {}
        self._dirty = {}

        self._valid_state: asyncio.Event = asyncio.Event()
        self._valid_state.clear()

    async def bind(
        self,
        key: str = None,
        cipher: Union[CipherV1, CipherV2, None] = None,
    ):
        """Freshly bind directly to DeviceInfo's IP/port, without discovery.

        Some firmware requires the caller to scan immediately before binding.
        An explicit cipher is copied for fresh negotiation; otherwise V1 then
        V2 are tried on timeout. Concurrent fresh binds share the first session.
        After explicit close, construct a replacement Device instead.

        Supplying a key still only configures the supplied cipher and does not
        open a transport; a cipher is required for this legacy behavior.

        Raises:
            DeviceNotBoundError: Closed object, invalid identity/key, or lost transport.
            DeviceTimeoutError: No identified bind reply within the cipher attempts.
            OSError: UDP endpoint creation failed.
        """
        if self._closed:
            raise DeviceNotBoundError
        if key:
            if not cipher:
                raise ValueError("cipher must be provided when key is provided")
            cipher.key = key
            self.device_cipher = cipher
            return

        async with self._bind_lock:
            if self._closed:
                raise DeviceNotBoundError
            if self.ready.is_set() and self.device_cipher is not None:
                return
            if self.device_info is None or _canonical_mac(self.device_info.mac) is None:
                raise DeviceNotBoundError

            bound = False
            try:
                if self._transport is None:
                    await self._transport_closed.wait()
                    if self._closed:
                        raise DeviceNotBoundError
                    transport, _ = await self._loop.create_datagram_endpoint(
                        lambda: self, remote_addr=(self.device_info.ip, self.device_info.port)
                    )
                    if self._closed:
                        transport.close()
                        raise DeviceNotBoundError

                self._logger.info("Starting device binding to %s", self.device_info)
                if cipher is not None:
                    await self.__bind_internal(copy(cipher))
                else:
                    try:
                        await self.__bind_internal(CipherV1())
                    except asyncio.TimeoutError:
                        if self._closed:
                            raise DeviceNotBoundError
                        await self.__bind_internal(CipherV2())
                if self._closed or not self.ready.is_set() or self.device_cipher is None:
                    raise DeviceNotBoundError
                bound = True
            except asyncio.TimeoutError as exc:
                raise DeviceTimeoutError from exc
            finally:
                if not bound:
                    self.device_cipher = None
                    self.ready.clear()
                    self._valid_state.clear()
                    self._cancel_tasks()
                    DeviceProtocol2.close(self)

    async def __bind_internal(self, cipher: Union[CipherV1, CipherV2]):
        """Wait for this attempt's identified bind reply, not an old ready event."""
        self.ready.clear()
        waiter = self._loop.create_future()
        self._bind_waiter = waiter
        bound = False
        try:
            await self.send(self.create_bind_message(self.device_info), cipher=cipher)
            await asyncio.wait_for(waiter, timeout=self._bind_timeout)
            bound = True
        finally:
            if not waiter.done():
                waiter.cancel()
            elif not waiter.cancelled():
                waiter.exception()
            if self._bind_waiter is waiter:
                self._bind_waiter = None
            if not bound:
                self.device_cipher = None
                self.ready.clear()

    def handle_device_bound(self, key: str) -> None:
        """Install the negotiated session before notifying callers or polling."""
        waiter = self._bind_waiter
        if self._closed or waiter is None or waiter.done():
            return
        self.device_cipher.key = key
        self.ready.set()
        waiter.set_result(None)
        self._create_task(self.update_state())

    def close(self) -> None:
        """Idempotently retire this Device; reconnect using a new instance."""
        self._closed = True
        self._handlers.clear()
        self.device_cipher = None
        self.ready.clear()
        self._valid_state.clear()
        if self._bind_waiter is not None and not self._bind_waiter.done():
            self._bind_waiter.set_exception(DeviceNotBoundError())
        self._cancel_tasks()
        DeviceProtocol2.close(self)

    def connection_lost(self, exc: Exception) -> None:
        """Invalidate this session and fail pending binding on socket loss."""
        self.device_cipher = None
        self.ready.clear()
        self._valid_state.clear()
        if self._bind_waiter is not None and not self._bind_waiter.done():
            self._bind_waiter.set_exception(DeviceNotBoundError())
        self._cancel_tasks()
        DeviceProtocol2.connection_lost(self, exc)

    def packet_received(self, obj, addr: IPAddr) -> None:
        """Dispatch only packets belonging to this connected peer and session."""
        if self._closed or self._closing or self._transport is None:
            self._logger.debug("Ignoring packet for a closed device")
            return
        if addr != self._transport.get_extra_info("peername"):
            self._logger.debug("Ignoring packet from unexpected peer %s", addr)
            return
        pack = obj.get("pack") if isinstance(obj, dict) else None
        if not isinstance(pack, dict):
            self._logger.debug("Ignoring device packet without dictionary pack")
            return
        expected = _canonical_mac(self.device_info.mac)
        identified = False
        for value in (pack.get("mac"), pack.get("cid"), obj.get("cid")):
            if value is None or value == "":
                continue
            if expected is None or _canonical_mac(value) != expected:
                self._logger.debug("Ignoring packet with conflicting sender identity")
                return
            identified = True

        response = pack.get("t")
        response = response.casefold() if isinstance(response, str) else None
        if response == "bindok":
            waiter = self._bind_waiter
            if waiter is None or waiter.done() or not identified:
                self._logger.debug("Ignoring bind reply outside identified negotiation")
                return
            key = pack.get("key")
            try:
                valid_key = isinstance(key, str) and len(key.encode("utf-8")) in (16, 24, 32)
            except UnicodeError:
                valid_key = False
            if not valid_key or ("r" in pack and (type(pack["r"]) is not int or pack["r"] != 200)):
                self._logger.debug("Rejecting matching bind reply with invalid key or result")
                waiter.set_exception(DeviceNotBoundError())
                return
        elif not self.ready.is_set() or self.device_cipher is None:
            self._logger.debug("Ignoring packet without a negotiated session")
            return
        DeviceProtocol2.packet_received(self, obj, addr)

    async def request_version(self) -> None:
        """Send a firmware-version request; observe DATA for the reply."""
        if self._closed or (self._bind_waiter is not None and not self._bind_waiter.done()):
            raise DeviceNotBoundError
        if not self.device_cipher:
            await self.bind()

        try:
            await self.send(self.create_status_message(self.device_info, "hid"))

        except asyncio.TimeoutError:
            raise DeviceTimeoutError

    async def update_state(self, columns: Optional[Sequence[str]] = None) -> None:
        """Send a status request; state changes only when a DATA reply arrives."""
        if self._closed or (self._bind_waiter is not None and not self._bind_waiter.done()):
            raise DeviceNotBoundError
        if columns is not None:
            if isinstance(columns, (str, bytes)) or not isinstance(columns, Sequence):
                raise TypeError("Status columns must be a sequence of nonempty strings")
            columns = list(columns)
            if not columns or any(not isinstance(name, str) or not name or name == "self" for name in columns):
                raise ValueError("Status columns must contain nonempty strings other than 'self'")
        if not self.device_cipher:
            await self.bind()

        self._logger.debug("Updating device properties for (%s)", str(self.device_info))

        props = self._status_columns() if columns is None else columns
        if columns is None and not self.hid and "hid" not in props:
            props.append("hid")

        try:
            await self.send(self.create_status_message(self.device_info, *props))

        except asyncio.TimeoutError:
            raise DeviceTimeoutError

    def handle_state_update(self, **kwargs) -> None:
        """Handle incoming device properties and reported firmware metadata."""

        # Ex: hid = 362001000762+U-CS532AE(LT)V3.31.bin
        if "hid" in kwargs:
            hid = kwargs.pop("hid")
            self.hid = hid
            match = re.search(r"(?<=V)([\d.]+)\.bin$", hid) if isinstance(hid, str) else None
            self.version = match and match.group(1)
            if self.ready.is_set() and not self._hid_logged:
                self._logger.info("Device MID %s has HID %s (version %s)", self.device_info.mid, hid, self.version)
                self._hid_logged = True

        self._properties.update(kwargs)
        self._handle_properties_updated(kwargs)
        self._valid_state.set()

    async def push_state_update(self):
        """Send pending controls; observe RESULT for the device's response."""
        if self._closed or (self._bind_waiter is not None and not self._bind_waiter.done()):
            raise DeviceNotBoundError
        if not self._dirty:
            return

        if not self.device_cipher:
            await self.bind()

        self._logger.debug("Pushing state updates to (%s)", str(self.device_info))

        pending = self._dirty.copy()
        props = self._command_properties()

        try:
            await self.send(self.create_command_message(self.device_info, **props))

        except asyncio.TimeoutError:
            raise DeviceTimeoutError
        else:
            temperature_changed = any(
                self._dirty.get(name) != pending.get(name) for name in _TEMPERATURE_PROPERTIES
            )
            for name, value in pending.items():
                if temperature_changed and name in _TEMPERATURE_PROPERTIES:
                    continue
                if self._dirty.get(name) == value:
                    self._dirty.pop(name, None)


    def __eq__(self, other):
        """Compare two devices for equality based on their properties state and device info."""
        return self.device_info == other.device_info \
            and self.raw_properties == other.raw_properties \
            and self.device_cipher.key == other.device_cipher.key

    def __ne__(self, other):
        return not self.__eq__(other)

    @property
    def raw_properties(self) -> dict:
        return self._properties

    @property
    def capabilities(self) -> Mapping[str, Optional[bool]]:
        """Snapshot typed protocol evidence, not physical features or permission.

        True means declared protocol feature support, not every writable value.
        False means outside this family's typed API or explicitly excluded;
        None means support has not been established.
        """
        capabilities = {
            name: None if self._capability_family is None or name in self._capability_names else False
            for name in _CAPABILITY_NAMES
        }
        if self._capability_family is not None:
            mid_profile = self._mid_profile
            if mid_profile.family == self._capability_family:
                for name, supported in mid_profile.capabilities.items():
                    if name in self._capability_names:
                        capabilities[name] = supported
            profile = self._device_profile
            if self._capability_family == "air_conditioner":
                buzzer_properties = profile.buzzer_properties if profile is not None else None
                capabilities["lan_buzzer_control"] = (
                    bool(buzzer_properties) if buzzer_properties is not None else None
                )
            if profile is not None:
                for family, name, supported in profile.capabilities:
                    if family == self._capability_family and name in self._capability_names:
                        capabilities[name] = supported
        return MappingProxyType(capabilities)

    def get_property(self, name: Union[str, enum.Enum]) -> Optional[Any]:
        """Look up a raw protocol property without inferring appliance support."""
        name = _property_name(name)
        return self._properties.get(name)

    def set_property(self, name: Union[str, enum.Enum], value: Any) -> None:
        """Stage an explicit raw protocol property without appliance validation."""
        name = _property_name(name)
        if self._properties.get(name) == value and (
            name not in self._dirty or self._dirty[name] == value
        ):
            return
        self._properties[name] = value
        self._dirty[name] = value

    @property
    def has_valid_state(self) -> bool:
        return self._valid_state.is_set()

    @property
    def _device_profile(self) -> Optional[DeviceProfile]:
        if self.hid != self._matched_hid:
            self._matched_profile = match_device_profile(self.hid)
            self._matched_hid = self.hid
        return self._matched_profile

    def _status_columns(self) -> List[str]:
        return list(self._mid_profile.status_columns)

    def _command_properties(self) -> Dict[str, Any]:
        props = {}
        for name, value in self._dirty.items():
            self._logger.debug("Sending remote state update %s -> %s", name, value)
            props[name] = value
        return props

    def _handle_properties_updated(self, properties: Dict[str, Any]) -> None:
        pass
