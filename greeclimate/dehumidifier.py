"""Dehumidifier controls and calibrated ambient temperature decoding."""

from asyncio import AbstractEventLoop
from typing import Any, Dict, List, Optional

from greeclimate._temperature import _TemperatureSensor
from greeclimate.device import Device, Props
from greeclimate.deviceinfo import DeviceInfo


class DehumidifierDevice(Device):
    """Humidity controls and the optional dehumidifier wire properties."""

    def __init__(self, device_info: DeviceInfo, timeout: int = 120, bind_timeout: int = 10, loop: AbstractEventLoop = None):
        super().__init__(device_info, timeout, bind_timeout, loop)
        self._temperature_sensor = _TemperatureSensor()

    def _status_columns(self) -> List[str]:
        profile = self._mid_profile
        if profile.mid is not None:
            return list(profile.status_columns)
        return [
            "Pow", "Dmod", "Dwet", "DwatSen", "Dfltr", "DwatFul", "TemSen", "TemUn", "TemRec",
            "WdSpd", "Lig", "SwUpDn", "Health", "Quiet",
        ]

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
    def target_humidity(self) -> Optional[int]:
        prop = self.get_property(Props.HUM_SET)
        return 15 + (prop * 5) if prop is not None else None

    @target_humidity.setter
    def target_humidity(self, value: int):
        if not 30 <= value <= 80:
            raise ValueError(f"Specified humidity {value} is out of range.")
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
    def temperature_units(self) -> Optional[int]:
        return self.get_property(Props.TEMP_UNIT)

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
    def light(self) -> Optional[bool]:
        prop = self.get_property(Props.LIGHT)
        return bool(prop) if prop is not None else None

    @light.setter
    def light(self, value: bool):
        self.set_property(Props.LIGHT, int(value))

    @property
    def vertical_swing(self) -> Optional[int]:
        return self.get_property(Props.SWING_VERT)

    @vertical_swing.setter
    def vertical_swing(self, value: int):
        self.set_property(Props.SWING_VERT, int(value))

    @property
    def anion(self) -> Optional[bool]:
        prop = self.get_property(Props.ANION)
        return bool(prop) if prop is not None else None

    @anion.setter
    def anion(self, value: bool):
        self.set_property(Props.ANION, int(value))

    @property
    def quiet(self) -> Optional[int]:
        return self.get_property(Props.QUIET)

    @quiet.setter
    def quiet(self, value: bool):
        self.set_property(Props.QUIET, 2 if value else 0)
