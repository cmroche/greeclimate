"""Conventional air-conditioner controls and temperature decoding."""

from asyncio import AbstractEventLoop
from typing import Any, Dict, List, Optional

from greeclimate._temperature import (
    TEMP_MAX,
    TEMP_MIN,
    _TemperatureSensor,
    _convert_to_units,
    generate_temperature_record,
)
from greeclimate.device import Device, Props, _TEMPERATURE_PROPERTIES
from greeclimate.deviceinfo import DeviceInfo


class AirConditionerDevice(Device):
    """Air-conditioner controls; raw properties remain available for explicit use."""

    def __init__(self, device_info: DeviceInfo, timeout: int = 120, bind_timeout: int = 10, loop: AbstractEventLoop = None):
        super().__init__(device_info, timeout, bind_timeout, loop)
        self._temperature_sensor = _TemperatureSensor()
        self._buzzer = True

    def _status_columns(self) -> List[str]:
        profile = self._mid_profile
        if profile.mid is not None:
            return list(profile.status_columns)
        return ["Pow", "Mod", "SetTem", "TemUn", "TemRec", "TemSen"]

    def _command_properties(self) -> Dict[str, Any]:
        props = super()._command_properties()
        if Props.TEMP_SET.value in props:
            props[Props.TEMP_BIT.value] = self._dirty.get(
                Props.TEMP_BIT.value, self._properties.get(Props.TEMP_BIT.value)
            )
            props[Props.TEMP_UNIT.value] = self._dirty.get(
                Props.TEMP_UNIT.value, self._properties.get(Props.TEMP_UNIT.value)
            )
        profile = self._device_profile
        buzzer_properties = (profile.buzzer_properties or ()) if profile is not None else ()
        if not self._buzzer and "Buzzer_ON_OFF" in buzzer_properties:
            self._logger.debug("Disabling buzzer for command")
            props["Buzzer_ON_OFF"] = 1

        if "BuzzerCtrl" in buzzer_properties:
            props["BuzzerCtrl"] = 1 if self._buzzer else 0
        return props

    def _handle_properties_updated(self, properties: Dict[str, Any]) -> None:
        if Props.TEMP_SENSOR.value in properties:
            self._temperature_sensor.update(properties[Props.TEMP_SENSOR.value], self._device_profile)

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

    @property
    def target_temperature(self) -> Optional[int]:
        temset = self.get_property(Props.TEMP_SET)
        temrec = self.get_property(Props.TEMP_BIT)
        if temset is None or temrec is None:
            return None
        return _convert_to_units(temset, temrec, self.temperature_units)

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
    def current_temperature(self) -> Optional[int]:
        return self._temperature_sensor.read(
            self.get_property(Props.TEMP_SENSOR),
            self.get_property(Props.TEMP_BIT),
            self.temperature_units,
            self._device_profile,
        )

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
    def buzzer(self) -> bool:
        return self._buzzer

    @buzzer.setter
    def buzzer(self, value: bool):
        self._buzzer = bool(value)
