"""Match device traits against discovery MID and reported firmware HID."""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple


@dataclass(frozen=True)
class DeviceProfile:
    mid: Optional[str] = None
    firmware_code: Optional[str] = None
    module: Optional[str] = None
    version: Optional[str] = None
    settings: Dict[str, Any] = field(default_factory=dict)


# See OFFSETS.md for inspected-build provenance and identity limitations.
KNOWN_PROFILES: Tuple[DeviceProfile, ...] = (
    DeviceProfile(firmware_code="362001000748", settings={"temperature_offset": 40}),
    DeviceProfile(firmware_code="362001000762", settings={"temperature_offset": 40}),
    DeviceProfile(firmware_code="362001000835", settings={"temperature_offset": 0}),
    DeviceProfile(firmware_code="362001060200", settings={"temperature_offset": 0}),
    DeviceProfile(firmware_code="362001060297", settings={"temperature_offset": 0}),
    DeviceProfile(firmware_code="362001061665", settings={"temperature_offset": 40}),
    DeviceProfile(firmware_code="362001062107", settings={"temperature_offset": 40}),
    DeviceProfile(firmware_code="362001063794", settings={"temperature_offset": 40}),
    DeviceProfile(firmware_code="362001065279", settings={"temperature_offset": 40}),
    DeviceProfile(firmware_code="362001065280", settings={"temperature_offset": 40}),
    DeviceProfile(firmware_code="362001065735", settings={"temperature_offset": 40}),
    DeviceProfile(firmware_code="362001065736", settings={"temperature_offset": 40}),
    DeviceProfile(firmware_code="362001067541", settings={"temperature_offset": 40}),
    DeviceProfile(firmware_code="362001068254", settings={"temperature_offset": 40}),
)


def match_device_profile(mid: Optional[str], hid: Optional[str]) -> Optional[DeviceProfile]:
    """Return the first conjunctive match; callers must not mutate its settings."""
    firmware = re.fullmatch(
        r"([0-9]+)\+(?:U-)?([^+()\s]+?)(?:\([^()]+\))?"
        r"V([0-9]+(?:\.[0-9]+)*)\.bin",
        hid,
    ) if isinstance(hid, str) else None
    mid = mid if isinstance(mid, str) and mid else None
    identity = (mid, *(firmware.groups() if firmware else (None, None, None)))
    for candidate in KNOWN_PROFILES:
        criteria = (candidate.mid, candidate.firmware_code, candidate.module, candidate.version)
        if any(criteria) and all(
            expected is None or expected == actual
            for expected, actual in zip(criteria, identity)
        ):
            return candidate
    return None
