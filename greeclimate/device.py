import asyncio
import enum
import logging
import re
from asyncio import AbstractEventLoop
from enum import IntEnum, unique
from typing import List

import greeclimate.network as network
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.network import DeviceProtocol2, IPAddr
from greeclimate.exceptions import DeviceNotBoundError, DeviceTimeoutError
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
TEMP_MIN_F = 46
TEMP_MAX_F = 86
TEMP_MIN_TABLE = -60
TEMP_MAX_TABLE = 60
TEMP_MIN_TABLE_F = -76
TEMP_MAX_TABLE_F = 140
TEMP_TABLE = [generate_temperature_record(x) for x in range(TEMP_MIN_TABLE_F, TEMP_MAX_TABLE_F + 1)]
HUMIDITY_MIN = 30
HUMIDITY_MAX = 80


class Device(DeviceProtocol2, Taskable):
    """Class representing a physical device, it's state and properties.

    Devices must be bound, either by discovering their presence, or supplying a persistent
    device key which is then used for communication (and encryption) with the unit. See the
    `bind` function for more details on how to do this.

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
    def __init__(self, device_info: DeviceInfo, timeout: int = 120, loop: AbstractEventLoop = None):
        """Initialize the device object

        Args:
            device_info (DeviceInfo): Information about the physical device
            timeout (int): Timeout for device communication
            loop (AbstractEventLoop): The event loop to run the device operations on
        """
        DeviceProtocol2.__init__(self, timeout)
        Taskable.__init__(self, loop)
        self._logger = logging.getLogger(__name__)

        self.device_info: DeviceInfo = device_info
        self.device_key = None

        """ Device properties """
        self.hid = None
        self.version = None
        self._properties = None
        self._dirty = []

    async def bind(self, key=None):
        """Run the binding procedure.

        Binding is a finicky procedure, and happens in 1 of 2 ways:
            1 - Without the key, binding must pass the device info structure immediately following
                the search devices procedure. There is only a small window to complete registration.
            2 - With a key, binding is implicit and no further action is required

            Both approaches result in a device_key which is used as like a persistent session id.

        Args:
            key (str): The device key, when provided binding is a NOOP, if None binding will
                       attempt to negotiate the key with the device.

        Raises:
            DeviceNotBoundError: If binding was unsuccessful and no key returned
            DeviceTimeoutError: The device didn't respond
        """

        if not self.device_info:
            raise DeviceNotBoundError

        if self._transport is None:
            self._transport, _ = await self._loop.create_datagram_endpoint(
                lambda: self, remote_addr=(self.device_info.ip, self.device_info.port)
            )

        self._logger.info("Starting device binding to %s", str(self.device_info))

        try:
            if key:
                self.device_key = key
            else:
                await self.send(self.create_bind_message(self.device_info))
                # Special case, wait for binding to complete so we know that the device is ready
                task = asyncio.create_task(self.ready.wait())
                await asyncio.wait_for(task, timeout=self._timeout)

        except asyncio.TimeoutError:
            raise DeviceTimeoutError

        if not self.device_key:
            raise DeviceNotBoundError
        else:
            self._logger.info("Bound to device using key %s", self.device_key)

    def handle_device_bound(self, key) -> None:
        """Handle the device bound message from the device"""
        self.device_key = key

    async def request_version(self) -> None:
        """Request the firmware version from the device."""
        if not self.device_key:
            await self.bind()

        try:
            await self.send(self.create_status_message(self.device_info, ["hid"]))

        except asyncio.TimeoutError:
            raise DeviceTimeoutError

    def handle_state_update(self, **kwargs) -> None:
        """Handle incoming information about the firmware version of the device"""

        # Ex: hid = 362001000762+U-CS532AE(LT)V3.31.bin
        if hid:
            self.hid = hid
            match = re.search(r"(?<=V)([\d.]+)\.bin$", self.hid)
            self.version = match and match.group(1)

    async def update_state(self):
        """Update the internal state of the device structure of the physical device"""
        if not self.device_key:
            await self.bind()

        self._logger.debug("Updating device properties for (%s)", str(self.device_info))

        props = [x.value for x in Props]

        try:
            self._properties = await network.request_state(
                props, self.device_info, self.device_key
            )

            # This check should prevent need to do version & device overrides
            # to correctly compute the temperature. Though will need to confirm
            # that it resolves all possible cases.
            if not self.hid:
                await self.request_version()

            temp = self.get_property(Props.TEMP_SENSOR)
            if temp and temp < TEMP_OFFSET:
                self.version = "4.0"

        except asyncio.TimeoutError:
            raise DeviceTimeoutError

    async def push_state_update(self):
        """Push any pending state updates to the unit"""
        if not self._dirty:
            return

        if not self.device_key:
            await self.bind()

        self._logger.debug("Pushing state updates to (%s)", str(self.device_info))

        props = {}
        for name in self._dirty:
            value = self._properties.get(name)
            self._logger.debug("Sending remote state update %s -> %s", name, value)
            props[name] = value
            if name == Props.TEMP_SET.value:
                props[Props.TEMP_BIT.value] = self._properties.get(Props.TEMP_BIT.value)
                props[Props.TEMP_UNIT.value] = self._properties.get(
                    Props.TEMP_UNIT.value
                )

        self._dirty.clear()

        try:
            await network.send_state(props, self.device_info, key=self.device_key)
        except asyncio.TimeoutError:
            raise DeviceTimeoutError

    def get_property(self, name):
        """Generic lookup of properties tracked from the physical device"""
        if self._properties:
            return self._properties.get(name.value)
        return None

    def set_property(self, name, value):
        """Generic setting of properties for the physical device"""
        if not self._properties:
            self._properties = {}

        if self._properties.get(name.value) == value:
            return
        else:
            self._properties[name.value] = value
            if name.value not in self._dirty:
                self._dirty.append(name.value)

    @property
    def power(self) -> bool:
        return bool(self.get_property(Props.POWER))

    @power.setter
    def power(self, value: int):
        self.set_property(Props.POWER, int(value))

    @property
    def mode(self) -> int:
        return self.get_property(Props.MODE)

    @mode.setter
    def mode(self, value: int):
        self.set_property(Props.MODE, int(value))

    def _convert_to_units(self, value, bit):
        if self.temperature_units != TemperatureUnits.F.value:
            return value

        if value < TEMP_MIN_TABLE or value > TEMP_MAX_TABLE:
            raise ValueError(f"Specified temperature {value} is out of range.")

        matching_temSet = [t for t in TEMP_TABLE if t["temSet"] == value]

        try:
            f = next(t for t in matching_temSet if t["temRec"] == bit)
        except StopIteration:
            f = matching_temSet[0]

        return f["f"]

    @property
    def target_temperature(self) -> int:
        temSet = self.get_property(Props.TEMP_SET)
        temRec = self.get_property(Props.TEMP_BIT)
        return self._convert_to_units(temSet, temRec)

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

    @property
    def temperature_units(self) -> int:
        return self.get_property(Props.TEMP_UNIT)

    @temperature_units.setter
    def temperature_units(self, value: int):
        self.set_property(Props.TEMP_UNIT, int(value))

    @property
    def current_temperature(self) -> int:
        prop = self.get_property(Props.TEMP_SENSOR)
        bit = self.get_property(Props.TEMP_BIT)
        if prop is not None:
            v = self.version and int(self.version.split(".")[0])
            try:
                if v == 4:
                    return self._convert_to_units(prop, bit)
                elif prop != 0:
                    return self._convert_to_units(prop - TEMP_OFFSET, bit)
            except ValueError:
                logging.warning("Converting unexpected set temperature value %s", prop)

        return self.target_temperature

    @property
    def fan_speed(self) -> int:
        return self.get_property(Props.FAN_SPEED)

    @fan_speed.setter
    def fan_speed(self, value: int):
        self.set_property(Props.FAN_SPEED, int(value))

    @property
    def fresh_air(self) -> bool:
        return bool(self.get_property(Props.FRESH_AIR))

    @fresh_air.setter
    def fresh_air(self, value: bool):
        self.set_property(Props.FRESH_AIR, int(value))

    @property
    def xfan(self) -> bool:
        return bool(self.get_property(Props.XFAN))

    @xfan.setter
    def xfan(self, value: bool):
        self.set_property(Props.XFAN, int(value))

    @property
    def anion(self) -> bool:
        return bool(self.get_property(Props.ANION))

    @anion.setter
    def anion(self, value: bool):
        self.set_property(Props.ANION, int(value))

    @property
    def sleep(self) -> bool:
        return bool(self.get_property(Props.SLEEP))

    @sleep.setter
    def sleep(self, value: bool):
        self.set_property(Props.SLEEP, int(value))
        self.set_property(Props.SLEEP_MODE, int(value))

    @property
    def light(self) -> bool:
        return bool(self.get_property(Props.LIGHT))

    @light.setter
    def light(self, value: bool):
        self.set_property(Props.LIGHT, int(value))

    @property
    def horizontal_swing(self) -> int:
        return self.get_property(Props.SWING_HORIZ)

    @horizontal_swing.setter
    def horizontal_swing(self, value: int):
        self.set_property(Props.SWING_HORIZ, int(value))

    @property
    def vertical_swing(self) -> int:
        return self.get_property(Props.SWING_VERT)

    @vertical_swing.setter
    def vertical_swing(self, value: int):
        self.set_property(Props.SWING_VERT, int(value))

    @property
    def quiet(self) -> bool:
        return self.get_property(Props.QUIET)

    @quiet.setter
    def quiet(self, value: bool):
        self.set_property(Props.QUIET, 2 if value else 0)

    @property
    def turbo(self) -> bool:
        return bool(self.get_property(Props.TURBO))

    @turbo.setter
    def turbo(self, value: bool):
        self.set_property(Props.TURBO, int(value))

    @property
    def steady_heat(self) -> bool:
        return bool(self.get_property(Props.STEADY_HEAT))

    @steady_heat.setter
    def steady_heat(self, value: bool):
        self.set_property(Props.STEADY_HEAT, int(value))

    @property
    def power_save(self) -> bool:
        return bool(self.get_property(Props.POWER_SAVE))

    @power_save.setter
    def power_save(self, value: bool):
        self.set_property(Props.POWER_SAVE, int(value))

    @property
    def target_humidity(self) -> int:
        15 + (self.get_property(Props.HUM_SET) * 5)

    @target_humidity.setter
    def target_humidity(self, value: int):
        def validate(val):
            if value > HUMIDITY_MAX or val < HUMIDITY_MIN:
                raise ValueError(f"Specified temperature {val} is out of range.")

        self.set_property(Props.HUM_SET, (value - 15) // 5)

    @property
    def dehumidifier_mode(self):
        return self.get_property(Props.DEHUMIDIFIER_MODE)

    @property
    def current_humidity(self) -> int:
        return self.get_property(Props.HUM_SENSOR)

    @property
    def clean_filter(self) -> bool:
        return bool(self.get_property(Props.CLEAN_FILTER))

    @property
    def water_full(self) -> bool:
        return bool(self.get_property(Props.WATER_FULL))
