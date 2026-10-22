"""Temperature conversion and per-device ambient sensor calibration."""

import logging
from typing import Any, Optional

from greeclimate.device import TemperatureUnits
from greeclimate.device_profile import DeviceProfile


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


def _convert_to_units(value, bit, units):
    if units != TemperatureUnits.F.value:
        return value

    if value < TEMP_MIN_TABLE or value > TEMP_MAX_TABLE:
        raise ValueError(f"Specified temperature {value} is out of range.")

    matching_temset = [t for t in TEMP_TABLE if t["temSet"] == value]

    try:
        f = next(t for t in matching_temset if t["temRec"] == bit)
    except StopIteration:
        f = matching_temset[0]

    return f["f"]


class _TemperatureSensor:
    def __init__(self):
        self.learned_offset: Optional[int] = None
        self.guessed_offset: Optional[int] = None

    def update(self, raw: Any, profile: Optional[DeviceProfile]) -> None:
        relearn = profile is not None and profile.relearn_temperature_offset
        # shortcut: ranges were checked on only some firmware versions; use version-specific profiles if others differ.
        minimum = 0 if relearn else TEMP_SENSOR_MIN
        plain_limit = TEMP_OFFSET if relearn else TEMP_SENSOR_MIN + TEMP_OFFSET
        # shortcut: detection assumes indoor temperatures of -20..50 C; revise if real temperatures exceed this range.
        if (
            (relearn or self.learned_offset is None)
            and type(raw) is int
            and minimum <= raw <= TEMP_SENSOR_MAX + TEMP_OFFSET
            and raw != 0
        ):
            if raw < plain_limit:
                self.learned_offset = 0
            elif raw > TEMP_SENSOR_MAX:
                self.learned_offset = TEMP_OFFSET
            elif self.learned_offset is None and self.guessed_offset is None:
                self.guessed_offset = 0 if raw < TEMP_OFFSET else TEMP_OFFSET

    def read(
        self, raw: Any, bit: Any, units: Optional[int], profile: Optional[DeviceProfile]
    ) -> Optional[int]:
        if self.learned_offset is not None:
            offset = self.learned_offset
        elif profile is not None and profile.temperature_offset is not None:
            if profile.relearn_temperature_offset and self.guessed_offset is not None:
                offset = self.guessed_offset
            else:
                offset = profile.temperature_offset
        else:
            offset = self.guessed_offset
        minimum = 0 if profile is not None and profile.relearn_temperature_offset else TEMP_SENSOR_MIN
        if (
            offset is not None
            and type(raw) is int
            and minimum <= raw <= TEMP_SENSOR_MAX + TEMP_OFFSET
            and (raw != 0 or offset == 0)
        ):
            bit = bit if bit is not None else 0
            try:
                return _convert_to_units(raw - offset, bit, units)
            except ValueError:
                logging.warning("Converting unexpected set temperature value %s", raw)

        return None
