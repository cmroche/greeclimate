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


KNOWN_PROFILES: Tuple[DeviceProfile, ...] = (
    # Sinclair SMH-100IRB / SMH-60IRB:
    DeviceProfile(
        mid="9300",
        firmware_code="362001066763",
        settings={"cooling_mode_value": 5},
    ),
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
