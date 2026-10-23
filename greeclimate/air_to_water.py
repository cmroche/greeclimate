"""Explicit Celsius API for Sinclair SMH-100IRB and SMH-60IRB heat pumps."""

import enum
from asyncio import AbstractEventLoop
from collections.abc import Sequence
from typing import Any, Dict, List, Optional

from greeclimate.device import Device
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.mid_profile import match_mid_profile


class _AtwProps(enum.Enum):
    POWER = "Pow"
    MODE = "Mod"
    TEMP_UNIT = "TemUn"
    ERROR = "AllErr"
    HEATING_WATER_TARGET = "HeWatOutTemSet"
    COOLING_WATER_TARGET = "CoWatOutTemSet"
    TANK_TARGET = "WatBoxTemSet"
    HEATING_ROOM_TARGET = "HeHomTemSet"
    COOLING_ROOM_TARGET = "CoHomTemSet"
    INLET_HIGH = "AllInWatTemHi"
    INLET_LOW = "AllInWatTemLo"
    OUTLET_HIGH = "AllOutWatTemHi"
    OUTLET_LOW = "AllOutWatTemLo"
    AUX_OUTLET_HIGH = "HepOutWatTemHi"
    AUX_OUTLET_LOW = "HepOutWatTemLo"
    TANK_HIGH = "WatBoxTemHi"
    TANK_LOW = "WatBoxTemLo"
    ROOM_HIGH = "RmoHomTemHi"
    ROOM_LOW = "RmoHomTemLo"
    TANK_HEATER_STATE = "WatBoxElcHeRunSta"
    SYSTEM_ANTIFROST_STATE = "SyAnFroRunSta"
    HEATER_ONE_STATE = "ElcHe1RunSta"
    HEATER_TWO_STATE = "ElcHe2RunSta"
    ANTIFREEZE_STATE = "AnFrzzRunSta"


class AirToWaterMode(enum.Enum):
    Heat = "heat"
    HotWater = "hot_water"
    CoolHotWater = "cool_hot_water"
    HeatHotWater = "heat_hot_water"
    Cool = "cool"


_MODE_VALUES = {
    AirToWaterMode.Heat: 1,
    AirToWaterMode.HotWater: 2,
    AirToWaterMode.CoolHotWater: 3,
    AirToWaterMode.HeatHotWater: 4,
}
_TARGET_RANGES = {
    _AtwProps.HEATING_WATER_TARGET: (20, 60),
    _AtwProps.COOLING_WATER_TARGET: (7, 25),
    _AtwProps.TANK_TARGET: (40, 80),
}
_AUTO = object()


def _validate_cooling_mode_value(value: Any) -> Optional[int]:
    if value is not None and (type(value) is not int or value not in (0, 5)):
        raise ValueError("cooling_mode_value must be None, 0 or 5")
    return value


class AirToWaterDevice(Device):
    """Opt-in ATW controls; reported units and power govern safe writes."""

    _capability_family = "air_to_water"
    _capability_names = frozenset({
        "power", "mode", "temperature_units", "inlet_water_temperature_c",
        "outlet_water_temperature_c", "room_temperature_c", "tank_temperature_c",
        "heating_room_target_temperature_c", "cooling_room_target_temperature_c",
        "heating_water_target_temperature_c", "cooling_water_target_temperature_c",
        "tank_target_temperature_c",
    })

    def __init__(
        self, device_info: DeviceInfo, timeout: int = 120,
        bind_timeout: int = 10, loop: AbstractEventLoop = None, *,
        cooling_mode_value: Any = _AUTO,
    ):
        if cooling_mode_value is not _AUTO:
            _validate_cooling_mode_value(cooling_mode_value)
        super().__init__(device_info, timeout, bind_timeout, loop)
        self._cooling_mode_value = cooling_mode_value
        self._reported_power: Optional[bool] = None
        self._reported_temperature_units: Optional[int] = None

    @property
    def cooling_mode_value(self) -> Optional[int]:
        if self._cooling_mode_value is not _AUTO:
            return self._cooling_mode_value
        profile = self._device_profile
        return _validate_cooling_mode_value(profile.cooling_mode_value if profile is not None else None)

    def _status_columns(self) -> List[str]:
        columns = list(match_mid_profile("9300").status_columns)
        columns.extend(p.value for p in _AtwProps if p.value not in columns)
        return columns

    async def update_state(self, columns: Optional[Sequence[str]] = None) -> None:
        """Bound default ATW polls; explicit columns remain one exact request."""
        if columns is not None:
            await super().update_state(columns)
            return
        props = self._status_columns()
        if not self.hid and "hid" not in props:
            props.append("hid")
        # Twenty existing ATW names keep encrypted packs below the firmware's 700-byte limit.
        for start in range(0, len(props), 20):
            await super().update_state(props[start:start + 20])

    def _handle_properties_updated(self, properties: Dict[str, Any]) -> None:
        if "Pow" in properties:
            value = properties["Pow"]
            self._reported_power = bool(value) if type(value) is int and value in (0, 1) else None
        if "TemUn" in properties:
            value = properties["TemUn"]
            self._reported_temperature_units = value if type(value) is int and value in (0, 1) else None

    @property
    def temperature_units(self) -> Optional[int]:
        return self._reported_temperature_units

    def _temperature_c(self, high: _AtwProps, low: _AtwProps) -> Optional[float]:
        hi, lo = self.get_property(high), self.get_property(low)
        if self.temperature_units != 0 or type(hi) is not int or type(lo) is not int:
            return None
        return hi - 100 + lo / 10.0

    def _target_temperature_c(self, prop: _AtwProps) -> Optional[int]:
        value = self.get_property(prop)
        return value if self.temperature_units == 0 and type(value) is int else None

    @property
    def inlet_water_temperature_c(self) -> Optional[float]:
        return self._temperature_c(_AtwProps.INLET_HIGH, _AtwProps.INLET_LOW)

    @property
    def outlet_water_temperature_c(self) -> Optional[float]:
        return self._temperature_c(_AtwProps.OUTLET_HIGH, _AtwProps.OUTLET_LOW)

    @property
    def room_temperature_c(self) -> Optional[float]:
        return self._temperature_c(_AtwProps.ROOM_HIGH, _AtwProps.ROOM_LOW)

    @property
    def tank_temperature_c(self) -> Optional[float]:
        return self._temperature_c(_AtwProps.TANK_HIGH, _AtwProps.TANK_LOW)

    @property
    def heating_room_target_temperature_c(self) -> Optional[int]:
        return self._target_temperature_c(_AtwProps.HEATING_ROOM_TARGET)

    @property
    def cooling_room_target_temperature_c(self) -> Optional[int]:
        return self._target_temperature_c(_AtwProps.COOLING_ROOM_TARGET)

    def _validate_target_temperature_c(self, prop: _AtwProps, value: int, minimum: int, maximum: int) -> None:
        if self.temperature_units != 0:
            raise ValueError("ATW temperature writes require reported Celsius units")
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError(f"{prop.value} must be an integer in {minimum}–{maximum} Celsius")

    def _set_target_temperature_c(self, prop: _AtwProps, value: int, minimum: int, maximum: int) -> None:
        self._validate_target_temperature_c(prop, value, minimum, maximum)
        self.set_property(prop, value)

    @property
    def heating_water_target_temperature_c(self) -> Optional[int]:
        return self._target_temperature_c(_AtwProps.HEATING_WATER_TARGET)

    @heating_water_target_temperature_c.setter
    def heating_water_target_temperature_c(self, value: int):
        self._set_target_temperature_c(_AtwProps.HEATING_WATER_TARGET, value, 20, 60)

    @property
    def cooling_water_target_temperature_c(self) -> Optional[int]:
        return self._target_temperature_c(_AtwProps.COOLING_WATER_TARGET)

    @cooling_water_target_temperature_c.setter
    def cooling_water_target_temperature_c(self, value: int):
        self._set_target_temperature_c(_AtwProps.COOLING_WATER_TARGET, value, 7, 25)

    @property
    def tank_target_temperature_c(self) -> Optional[int]:
        return self._target_temperature_c(_AtwProps.TANK_TARGET)

    @tank_target_temperature_c.setter
    def tank_target_temperature_c(self, value: int):
        self._set_target_temperature_c(_AtwProps.TANK_TARGET, value, 40, 80)

    @property
    def power(self) -> Optional[bool]:
        value = self.get_property(_AtwProps.POWER)
        return bool(value) if type(value) is int and value in (0, 1) else None

    @power.setter
    def power(self, value: bool):
        if type(value) is not bool:
            raise ValueError("ATW power must be bool")
        self.set_property(_AtwProps.POWER, int(value))

    @property
    def mode(self) -> Optional[AirToWaterMode]:
        value = self.get_property(_AtwProps.MODE)
        if type(value) is not int:
            return None
        for mode, wire_value in _MODE_VALUES.items():
            if value == wire_value:
                return mode
        cooling_mode_value = self.cooling_mode_value
        if cooling_mode_value is not None and value == cooling_mode_value:
            return AirToWaterMode.Cool
        return None

    def _mode_value(self, value: AirToWaterMode) -> int:
        if not isinstance(value, AirToWaterMode):
            raise ValueError("ATW mode must be an AirToWaterMode member")
        if value is AirToWaterMode.Cool:
            cooling_mode_value = self.cooling_mode_value
            if cooling_mode_value is None:
                raise ValueError("Configure cooling_mode_value as 0 or 5 before selecting cooling")
            return cooling_mode_value
        return _MODE_VALUES[value]

    def _require_reported_off(self) -> None:
        if self._reported_power is not False:
            raise ValueError("An off power state must be received before changing ATW mode")

    @mode.setter
    def mode(self, value: AirToWaterMode):
        wire_value = self._mode_value(value)
        cached = self.get_property(_AtwProps.MODE)
        if type(cached) is not int or cached != wire_value:
            self._require_reported_off()
        self.set_property(_AtwProps.MODE, wire_value)

    def _command_properties(self) -> Dict[str, Any]:
        props = super()._command_properties()
        allowed = {_AtwProps.POWER.value, _AtwProps.MODE.value}
        allowed.update(prop.value for prop in _TARGET_RANGES)
        if any(name not in allowed for name in props):
            raise ValueError("Unsupported ATW command properties")
        if _AtwProps.POWER.value in props:
            value = props[_AtwProps.POWER.value]
            if type(value) is not int or value not in (0, 1):
                raise ValueError("ATW wire power must be integer 0 or 1")
        for prop, bounds in _TARGET_RANGES.items():
            if prop.value in props:
                self._validate_target_temperature_c(prop, props[prop.value], *bounds)
        if _AtwProps.MODE.value in props:
            value = props[_AtwProps.MODE.value]
            modes = list(_MODE_VALUES.values())
            cooling_mode_value = self.cooling_mode_value
            if cooling_mode_value is not None:
                modes.append(cooling_mode_value)
            if type(value) is not int or value not in modes:
                raise ValueError("Invalid or unconfigured ATW wire mode")
            self._require_reported_off()
            if props.get(_AtwProps.POWER.value) == 1:
                raise ValueError("Push the ATW mode change before turning power on")
        if props.get(_AtwProps.POWER.value) == 1:
            # A send may reach the appliance even if its reply or UDP drain is lost.
            self._reported_power = None
        return props
