"""Construct device families from discovery MID without network I/O."""

from asyncio import AbstractEventLoop
from typing import Any, Dict, Type

from greeclimate.air_conditioner import AirConditionerDevice
from greeclimate.air_to_water import AirToWaterDevice
from greeclimate.device import Device
from greeclimate.dehumidifier import DehumidifierDevice
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.mid_profile import KNOWN_MID_PROFILES


_DEVICE_FAMILIES = {
    "air_conditioner": AirConditionerDevice,
    "dehumidifier": DehumidifierDevice,
    "air_to_water": AirToWaterDevice,
}
DEVICE_TYPES: Dict[str, Type[Device]] = {
    profile.mid: _DEVICE_FAMILIES[profile.family]
    for profile in KNOWN_MID_PROFILES
    if profile.family is not None
}


def create_device(
    device_info: DeviceInfo,
    timeout: int = 120,
    bind_timeout: int = 10,
    loop: AbstractEventLoop = None,
    **settings: Any,
) -> Device:
    """Select a family once by exact MID, passing explicit settings unchanged."""
    mid = device_info.mid
    device_type = DEVICE_TYPES.get(mid, Device) if isinstance(mid, str) and mid else Device
    return device_type(device_info, timeout, bind_timeout, loop, **settings)
