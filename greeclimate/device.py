import asyncio
import enum
import logging
import re
import typing
from asyncio import AbstractEventLoop
from copy import copy
from enum import IntEnum, unique
from typing import Union, Optional, Any

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


def generate_temperature_record(temp_f):
    temSet = round((temp_f - 32.0) * 5.0 / 9.0)
    temRec = (int)((((temp_f - 32.0) * 5.0 / 9.0) - temSet) > 0)
    return {"f": temp_f, "temSet": temSet, "temRec": temRec}


TEMP_MIN = 8
TEMP_MAX = 30
TEMP_OFFSET = 40
TEMP_SENSOR_MIN = -20
TEMP_SENSOR_MAX = 50
TEMP_MIN_F = 46
TEMP_MAX_F = 86
TEMP_MIN_TABLE = -60
TEMP_MAX_TABLE = 60
TEMP_MIN_TABLE_F = -76
TEMP_MAX_TABLE_F = 140
TEMP_TABLE = [generate_temperature_record(x) for x in range(TEMP_MIN_TABLE_F, TEMP_MAX_TABLE_F + 1)]
HUMIDITY_MIN = 30
HUMIDITY_MAX = 80

_TEMPERATURE_PROPERTIES = (Props.TEMP_SET.value, Props.TEMP_BIT.value, Props.TEMP_UNIT.value)


class Device(DeviceProtocol2, Taskable):
    """Class representing a physical device, it's state and properties.

    Devices can freshly bind using saved DeviceInfo without discovery. Some firmware
    requires a caller-initiated scan first. Explicit close retires the object; callers
    replace it and freshly bind for recovery. See `bind` for key-supplied semantics.

    Once a device is bound occasionally call `update_state` to request and update state from
    the HVAC, as it is possible that it changes state from other sources.

    Attributes:
        power: A boolean indicating if the unit is on or off
        mode: An int indicating operating mode, see `Mode` enum for possible values
        target_temperature: The target temperature, ignore if in Auto, Fan or Steady Heat mode
        temperature_units: An int indicating unit of measurement, see `TemperatureUnits` enum for possible values
        current_temperature: The current temperature
        fan_speed: An int indicating fan speed, see `FanSpeed` enum for possible values
        fresh_air: A boolean indicating if fresh air valve is open, if present
        xfan: A boolean to enable the fan to dry the coil, only used for cool and dry modes
        anion: A boolean to enable the ozone generator, if present
        sleep: A boolean to enable sleep mode, which adjusts temperature over time
        light: A boolean to enable the light on the unit, if present
        horizontal_swing: An int to control the horizontal blade position, see `HorizontalSwing` enum for possible values
        vertical_swing: An int to control the vertical blade position, see `VerticalSwing` enum for possible values
        quiet: A boolean to enable quiet operation
        turbo: A boolean to enable turbo operation (heat or cool faster initially)
        steady_heat: When enabled unit will maintain a target temperature of 8 degrees C
        power_save: A boolen to enable power save operation
        target_humidity: An int to set the target relative humidity
        current_humidity: The current relative humidity
        clean_filter: A bool to indicate the filter needs cleaning
        water_full: A bool to indicate the water tank is full
    """

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
        
        self._bind_timeout = bind_timeout
        self._closed = False
        self._bind_lock = asyncio.Lock()
        self._bind_waiter: asyncio.Future | None = None
        
        """ Device properties """
        self.hid = None
        self.version = None
        self._matched_hid = None
        self._matched_profile: Optional[DeviceProfile] = None
        self._learned_temperature_offset: Optional[int] = None
        self._guessed_temperature_offset: Optional[int] = None
        self._properties = {}
        self._dirty = {}
        self._buzzer = True

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

    async def update_state(self):
        """Send a status request; state changes only when a DATA reply arrives."""
        if self._closed or (self._bind_waiter is not None and not self._bind_waiter.done()):
            raise DeviceNotBoundError
        if not self.device_cipher:
            await self.bind()

        self._logger.debug("Updating device properties for (%s)", str(self.device_info))

        profile = match_mid_profile(self.device_info.mid)
        props = list(profile.status_columns)
        if not self.hid and "hid" not in props:
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
            self._logger.info(f"Device version is {self.version}, hid {self.hid}")

        self._properties.update(kwargs)

        if Props.TEMP_SENSOR.value in kwargs:
            profile = self._device_profile
            relearn = profile is not None and profile.relearn_temperature_offset
            temp = kwargs[Props.TEMP_SENSOR.value]
            # shortcut: ranges were checked on only some firmware versions; use version-specific profiles if others differ.
            minimum = 0 if relearn else TEMP_SENSOR_MIN
            plain_limit = TEMP_OFFSET if relearn else TEMP_SENSOR_MIN + TEMP_OFFSET
            # shortcut: detection assumes indoor temperatures of -20..50 C; revise if real temperatures exceed this range.
            if (
                (relearn or self._learned_temperature_offset is None)
                and type(temp) is int
                and minimum <= temp <= TEMP_SENSOR_MAX + TEMP_OFFSET
                and temp != 0
            ):
                if temp < plain_limit:
                    self._learned_temperature_offset = 0
                elif temp > TEMP_SENSOR_MAX:
                    self._learned_temperature_offset = TEMP_OFFSET
                elif self._learned_temperature_offset is None and self._guessed_temperature_offset is None:
                    self._guessed_temperature_offset = 0 if temp < TEMP_OFFSET else TEMP_OFFSET

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
        props = {}
        for name, value in pending.items():
            self._logger.debug("Sending remote state update %s -> %s", name, value)
            props[name] = value
            if name == Props.TEMP_SET.value:
                props[Props.TEMP_BIT.value] = pending.get(
                    Props.TEMP_BIT.value, self._properties.get(Props.TEMP_BIT.value)
                )
                props[Props.TEMP_UNIT.value] = pending.get(
                    Props.TEMP_UNIT.value, self._properties.get(Props.TEMP_UNIT.value)
                )

        profile = self._device_profile
        buzzer_properties = (profile.buzzer_properties or ()) if profile is not None else ()
        if not self._buzzer and "Buzzer_ON_OFF" in buzzer_properties:
            self._logger.debug("Disabling buzzer for command")
            props["Buzzer_ON_OFF"] = 1

        if "BuzzerCtrl" in buzzer_properties:
            props["BuzzerCtrl"] = 1 if self._buzzer else 0

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

    def get_property(self, name) -> Optional[Any]:
        """Generic lookup of properties tracked from the physical device"""
        if self._properties:
            return self._properties.get(name.value)
        return None

    def set_property(self, name, value):
        """Generic setting of properties for the physical device"""
        if not self._properties:
            self._properties = {}

        if self._properties.get(name.value) == value and (
            name.value not in self._dirty or self._dirty[name.value] == value
        ):
            return
        else:
            self._properties[name.value] = value
            self._dirty[name.value] = value

    @property
    def has_valid_state(self) -> bool:
        return self._valid_state.is_set()

    @property
    def power(self) -> Optional[bool]:
        prop = self.get_property(Props.POWER)
        return bool(prop) if prop is not None else None

    @power.setter
    def power(self, value: int):
        self.set_property(Props.POWER, int(value))

    @property
    def mode(self) -> Optional[int]:
        return self.get_property(Props.MODE)

    @mode.setter
    def mode(self, value: int):
        self.set_property(Props.MODE, int(value))

    def _convert_to_units(self, value, bit):
        if self.temperature_units != TemperatureUnits.F.value:
            return value

        if value < TEMP_MIN_TABLE or value > TEMP_MAX_TABLE:
            raise ValueError(f"Specified temperature {value} is out of range.")

        matching_temset = [t for t in TEMP_TABLE if t["temSet"] == value]

        try:
            f = next(t for t in matching_temset if t["temRec"] == bit)
        except StopIteration:
            f = matching_temset[0]

        return f["f"]

    @property
    def target_temperature(self) -> Optional[int]:
        temset = self.get_property(Props.TEMP_SET)
        temrec = self.get_property(Props.TEMP_BIT)
        if temset is None or temrec is None:
            return None
        return self._convert_to_units(temset, temrec)

    @target_temperature.setter
    def target_temperature(self, value: int):
        def validate(val):
            if val > TEMP_MAX or val < TEMP_MIN:
                raise ValueError(f"Specified temperature {val} is out of range.")

        if self.temperature_units == 1:
            rec = generate_temperature_record(value)
            validate(rec["temSet"])
            self.set_property(Props.TEMP_SET, rec["temSet"])
            self.set_property(Props.TEMP_BIT, rec["temRec"])
        else:
            validate(value)
            self.set_property(Props.TEMP_SET, int(value))

        if Props.TEMP_SET.value in self._dirty or Props.TEMP_BIT.value in self._dirty:
            # A target and its encoding must survive reports and sends as one command.
            for name in _TEMPERATURE_PROPERTIES:
                self._dirty.setdefault(name, self._properties.get(name))
            self._dirty[Props.TEMP_UNIT.value] = self.temperature_units

    @property
    def temperature_units(self) -> Optional[int]:
        return self.get_property(Props.TEMP_UNIT)

    @temperature_units.setter
    def temperature_units(self, value: int):
        self.set_property(Props.TEMP_UNIT, int(value))

    @property
    def _device_profile(self) -> Optional[DeviceProfile]:
        if self.hid != self._matched_hid:
            self._matched_profile = match_device_profile(self.hid)
            self._matched_hid = self.hid
        return self._matched_profile

    @property
    def _temperature_offset(self) -> Optional[int]:
        if self._learned_temperature_offset is not None:
            return self._learned_temperature_offset
        profile = self._device_profile
        if profile is not None and profile.temperature_offset is not None:
            if profile.relearn_temperature_offset and self._guessed_temperature_offset is not None:
                return self._guessed_temperature_offset
            return profile.temperature_offset
        return self._guessed_temperature_offset

    @property
    def current_temperature(self) -> Optional[int]:
        prop = self.get_property(Props.TEMP_SENSOR)
        bit = self.get_property(Props.TEMP_BIT)
        offset = self._temperature_offset
        profile = self._device_profile
        minimum = 0 if profile is not None and profile.relearn_temperature_offset else TEMP_SENSOR_MIN
        if (
            offset is not None
            and type(prop) is int
            and minimum <= prop <= TEMP_SENSOR_MAX + TEMP_OFFSET
            and (prop != 0 or offset == 0)
        ):
            bit = bit if bit is not None else 0
            try:
                return self._convert_to_units(prop - offset, bit)
            except ValueError:
                logging.warning("Converting unexpected set temperature value %s", prop)

        return None

    @property
    def fan_speed(self) -> Optional[int]:
        return self.get_property(Props.FAN_SPEED)

    @fan_speed.setter
    def fan_speed(self, value: int):
        self.set_property(Props.FAN_SPEED, int(value))

    @property
    def fresh_air(self) -> Optional[bool]:
        prop = self.get_property(Props.FRESH_AIR)
        return bool(prop) if prop is not None else None

    @fresh_air.setter
    def fresh_air(self, value: bool):
        self.set_property(Props.FRESH_AIR, int(value))

    @property
    def xfan(self) -> Optional[bool]:
        prop = self.get_property(Props.XFAN)
        return bool(prop) if prop is not None else None

    @xfan.setter
    def xfan(self, value: bool):
        self.set_property(Props.XFAN, int(value))

    @property
    def anion(self) -> Optional[bool]:
        prop = self.get_property(Props.ANION)
        return bool(prop) if prop is not None else None

    @anion.setter
    def anion(self, value: bool):
        self.set_property(Props.ANION, int(value))

    @property
    def sleep(self) -> Optional[bool]:
        prop = self.get_property(Props.SLEEP)
        return bool(prop) if prop is not None else None

    @sleep.setter
    def sleep(self, value: bool):
        self.set_property(Props.SLEEP, int(value))
        self.set_property(Props.SLEEP_MODE, int(value))

    @property
    def light(self) -> Optional[bool]:
        prop = self.get_property(Props.LIGHT)
        return bool(prop) if prop is not None else None

    @light.setter
    def light(self, value: bool):
        self.set_property(Props.LIGHT, int(value))

    @property
    def horizontal_swing(self) -> Optional[int]:
        return self.get_property(Props.SWING_HORIZ)

    @horizontal_swing.setter
    def horizontal_swing(self, value: int):
        self.set_property(Props.SWING_HORIZ, int(value))

    @property
    def vertical_swing(self) -> Optional[int]:
        return self.get_property(Props.SWING_VERT)

    @vertical_swing.setter
    def vertical_swing(self, value: int):
        self.set_property(Props.SWING_VERT, int(value))

    @property
    def quiet(self) -> Optional[int]:
        return self.get_property(Props.QUIET)

    @quiet.setter
    def quiet(self, value: bool):
        self.set_property(Props.QUIET, 2 if value else 0)

    @property
    def turbo(self) -> Optional[bool]:
        prop = self.get_property(Props.TURBO)
        return bool(prop) if prop is not None else None

    @turbo.setter
    def turbo(self, value: bool):
        self.set_property(Props.TURBO, int(value))

    @property
    def steady_heat(self) -> Optional[bool]:
        prop = self.get_property(Props.STEADY_HEAT)
        return bool(prop) if prop is not None else None

    @steady_heat.setter
    def steady_heat(self, value: bool):
        self.set_property(Props.STEADY_HEAT, int(value))

    @property
    def power_save(self) -> Optional[bool]:
        prop = self.get_property(Props.POWER_SAVE)
        return bool(prop) if prop is not None else None

    @power_save.setter
    def power_save(self, value: bool):
        self.set_property(Props.POWER_SAVE, int(value))

    @property
    def target_humidity(self) -> Optional[int]:
        prop = self.get_property(Props.HUM_SET)
        return 15 + (prop * 5) if prop is not None else None

    @target_humidity.setter
    def target_humidity(self, value: int):
        def validate(val):
            if value > HUMIDITY_MAX or val < HUMIDITY_MIN:
                raise ValueError(f"Specified temperature {val} is out of range.")

        self.set_property(Props.HUM_SET, (value - 15) // 5)

    @property
    def dehumidifier_mode(self) -> Optional[int]:
        return self.get_property(Props.DEHUMIDIFIER_MODE)

    @property
    def current_humidity(self) -> Optional[int]:
        return self.get_property(Props.HUM_SENSOR)

    @property
    def clean_filter(self) -> Optional[bool]:
        prop = self.get_property(Props.CLEAN_FILTER)
        return bool(prop) if prop is not None else None

    @property
    def water_full(self) -> Optional[bool]:
        prop = self.get_property(Props.WATER_FULL)
        return bool(prop) if prop is not None else None

    @property
    def buzzer(self) -> bool:
        return self._buzzer

    @buzzer.setter
    def buzzer(self, value: bool):
        self._buzzer = bool(value)
