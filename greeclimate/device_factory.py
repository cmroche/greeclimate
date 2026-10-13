"""Construct devices from exact, already-known discovery or hardware IDs."""

from asyncio import AbstractEventLoop
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple, Type, Union

from greeclimate.atw import AirToWaterDevice
from greeclimate.device import Device
from greeclimate.deviceinfo import DeviceInfo


@dataclass(frozen=True)
class DeviceProfile:
    device_type: Union[Type[Device], Type[AirToWaterDevice]]
    mids: Tuple[str, ...] = ()
    hids: Tuple[str, ...] = ()
    settings: Dict[str, Any] = field(default_factory=dict)


KNOWN_DEVICES: Tuple[DeviceProfile, ...] = (
    # Sinclair SMH-100IRB / SMH-60IRB:
    DeviceProfile(
        device_type=AirToWaterDevice,
        mids=("9300",),
        hids=("362001066763+U-W06A(P3)V6.04.bin",),
        settings={"cooling_mode_value": 5},
    ),
)


def create_device(
    device_info: DeviceInfo,
    timeout: int = 120,
    bind_timeout: int = 10,
    loop: AbstractEventLoop = None,
    *,
    hid: Optional[str] = None,
    **settings: Any,
) -> Union[Device, AirToWaterDevice]:
    """Select a family once, without binding, polling or changing metadata.

    Exact nonempty string HIDs outrank MIDs; the first row wins within each
    kind. Unknown HIDs still permit MID lookup. Caller settings override profile
    defaults and are validated by the selected constructor. Lookup HID is not
    reported state. Late discovery metadata requires deliberate reconstruction.
    """
    profile = None
    if isinstance(hid, str) and hid:
        for candidate in KNOWN_DEVICES:
            if hid in candidate.hids:
                profile = candidate
                break
    if profile is None and isinstance(device_info.mid, str) and device_info.mid:
        for candidate in KNOWN_DEVICES:
            if device_info.mid in candidate.mids:
                profile = candidate
                break
    device_type = profile.device_type if profile is not None else Device
    kwargs = dict(profile.settings) if profile is not None else {}
    kwargs.update(settings)
    return device_type(device_info, timeout, bind_timeout, loop, **kwargs)
