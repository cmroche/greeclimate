"""Construct device families from discovery MID without network I/O."""

from asyncio import AbstractEventLoop
from typing import Any, Dict, Type, Union

from greeclimate.atw import AirToWaterDevice
from greeclimate.device import Device
from greeclimate.deviceinfo import DeviceInfo


DEVICE_TYPES: Dict[str, Union[Type[Device], Type[AirToWaterDevice]]] = {
    "9300": AirToWaterDevice,
}


def create_device(
    device_info: DeviceInfo,
    timeout: int = 120,
    bind_timeout: int = 10,
    loop: AbstractEventLoop = None,
    **settings: Any,
) -> Union[Device, AirToWaterDevice]:
    """Select a family once by exact MID, passing explicit settings unchanged."""
    mid = device_info.mid
    device_type = DEVICE_TYPES.get(mid, Device) if isinstance(mid, str) and mid else Device
    return device_type(device_info, timeout, bind_timeout, loop, **settings)
