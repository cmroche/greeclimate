import asyncio
import enum
import logging
import re
from enum import IntEnum, unique

import greeclimate.network as network
from greeclimate.exceptions import DeviceNotBoundError, DeviceTimeoutError


class Props(enum.Enum):
    POWER = "Pow"
    MODE = "Mod"
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


def generate_temperature_record(temp_f):
    temSet = round((temp_f - 32.0) * 5.0 / 9.0)
    temRec = (int)((((temp_f - 32.0) * 5.0 / 9.0) - temSet) > 0)
    return {"f": temp_f, "temSet": temSet, "temRec": temRec}


TEMP_MIN = 16
TEMP_MAX = 30
TEMP_MIN_F = 60
TEMP_MAX_F = 86
TEMP_TABLE = [generate_temperature_record(x) for x in range(TEMP_MIN_F, TEMP_MAX_F + 1)]


class DeviceInfo:
    """Device information class, used to identify and connect

    Attributes
        ip: IP address (ipv4 only) of the physical device
        port: Usually this will always be 7000
        mac: mac address, in the format 'aabbcc112233'
        name: Name of unit, if available
    """

    def __init__(self, ip, port, mac, name, brand=None, model=None, version=None):
        self.ip = ip
        self.port = port
        self.mac = mac
        self.name = name if name else mac.replace(":", "")
        self.brand = brand
        self.model = model
        self.version = version

    def __str__(self):
        return f"Device: {self.name} @ {self.ip}:{self.port} (mac: {self.mac})"

    def __eq__(self, other):
        """Check equality based on Device Info properties"""
        if isinstance(other, DeviceInfo):
            return (
                self.mac == other.mac
                and self.name == other.name
                and self.brand == other.brand
                and self.model == other.model
                and self.version == other.version
            )
        return False

    def __ne__(self, other):
        """Check inequality based on Device Info properties"""
        return not self.__eq__(other)


class Device:
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
    """

    def __init__(self, device_info):
        self._logger = logging.getLogger(__name__)

        self.device_info = device_info
        self.device_key = None

        """ Device properties """
        self.hid = None
        self.version = None
        self._properties = None
        self._dirty = []

    async def bind(self, key=None):
        """Run the binding procedure.

        Binding is a finnicky procedure, and happens in 1 of 2 ways:
            1 - Without the key, binding must pass the device info structure immediately following
                the search devices procedure. There is only a small window to complete registration.
            2 - With a key, binding is implicit and no further action is required

            Both approaches result in a device_key which is used as like a persitent session id.

        Args:
            key (str): The device key, when provided binding is a NOOP, if None binding will
                       attempt to negatiate the key with the device.

        Raises:
            DeviceNotBoundError: If binding was unsuccessful and no key returned
            DeviceTimeoutError: The device didn't respond
        """

        if not self.device_info:
            raise DeviceNotBoundError

        self._logger.info("Starting device binding to %s", str(self.device_info))

        try:
            if key:
                self.device_key = key
            else:
                self.device_key = await network.bind_device(
                    self.device_info, announce=False
                )
        except asyncio.TimeoutError:
            raise DeviceTimeoutError

        if not self.device_key:
            raise DeviceNotBoundError
        else:
            self._logger.info("Bound to device using key %s", self.device_key)

    async def request_version(self) -> None:
        """Request the firmware version from the device."""
        ret = await network.request_state(["hid"], self.device_info, self.device_key)
        self.hid = ret.get("hid")

        # Ex: hid = 362001000762+U-CS532AE(LT)V3.31.bin
        if self.hid:
            match = re.search(r"(?<=V)([\d.]+)\.bin$", self.hid)
            self.version = match and match.group(1)

            # Special case firmwares ...
            if (
                self.hid.endswith("_JDV1.bin")
                or self.hid.endswith("362001000967V2.bin")
                or re.match("^.*\(MTK\)V[1-3]{1}\.bin", self.hid)  # (MTK)V[1-3].bin
            ):
                self.version = "4.0"

    async def update_state(self):
        """Update the internal state of the device structure of the physical device"""
        if not self.device_key:
            await self.bind()

        self._logger.debug("Updating device properties for (%s)", str(self.device_info))

        props = [x.value for x in Props]

        try:
            if not self.hid:
                await self.request_version()

            self._properties = await network.request_state(
                props, self.device_info, self.device_key
            )
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

        f = next(t for t in TEMP_TABLE if t["temSet"] == value and t["temRec"] == bit)
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
            if v == 4:
                return self._convert_to_units(prop, bit)
            elif prop != 0:
                return self._convert_to_units(prop - 40, bit)

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
        self.set_property(Props.QUIET, int(value))

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
