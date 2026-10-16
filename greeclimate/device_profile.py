"""Match firmware-family quirks against a complete reported firmware HID."""

import re
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class DeviceProfile:
    firmware_code: str
    temperature_offset: int
    min_version: Optional[str] = None
    relearn_temperature_offset: bool = False


# See OFFSETS.md for inspected-build provenance and identity limitations.
# Appliance names below are reported examples from docs/HIDS.md, not exclusive code-to-model mappings.
KNOWN_PROFILES: Tuple[DeviceProfile, ...] = (
    DeviceProfile("362001000748", 40),  # Gree Amber Standard
    DeviceProfile("362001000762", 40),  # Gree Vireo+ (VIR12HP115V1B model number tentative)
    DeviceProfile("362001000835", 0),
    DeviceProfile("362001003795", 40),
    DeviceProfile("362001060200", 0),
    DeviceProfile("362001060297", 0),
    DeviceProfile("362001060498", 0),
    DeviceProfile("362001060499", 0),
    DeviceProfile("362001060990", 40),
    DeviceProfile("362001060991", 40),
    DeviceProfile("362001061023", 40),
    DeviceProfile("362001061060", 40),
    DeviceProfile("362001061111", 40),
    DeviceProfile("362001061234", 40),
    DeviceProfile("362001061359", 40),
    DeviceProfile("362001061380", 0),
    DeviceProfile("362001061381", 40, relearn_temperature_offset=True),
    DeviceProfile("362001061383", 40, relearn_temperature_offset=True),
    DeviceProfile("362001061462", 40),
    DeviceProfile("362001061665", 40),  # Gree GWH09AGA-K6DNA1A/I
    DeviceProfile("362001062025", 40),
    DeviceProfile("362001062107", 40),
    DeviceProfile("362001062214", 40),
    DeviceProfile("362001062293", 40),
    DeviceProfile("362001062295", 40),
    DeviceProfile("362001062557", 40, relearn_temperature_offset=True),
    DeviceProfile("362001062637", 40),
    DeviceProfile("362001062842", 40),
    DeviceProfile("362001063794", 40),
    DeviceProfile("362001063903", 40),
    DeviceProfile("362001063967", 40),
    DeviceProfile("362001064270", 40, relearn_temperature_offset=True),
    DeviceProfile("362001064304", 40),
    DeviceProfile("362001064973", 40, relearn_temperature_offset=True),
    DeviceProfile("362001065016", 40),
    DeviceProfile("362001065029", 40),
    DeviceProfile("362001065130", 40),
    DeviceProfile("362001065279", 40),  # Gree Bora A5 GWH09AAB-K6DNA5A/I; Lomo Nordic (archive report); Heiwa Essential ZEN+; Cooper & Hunter
    DeviceProfile("362001065280", 40),
    DeviceProfile("362001065517", 40),
    DeviceProfile("362001065602", 0),
    DeviceProfile("362001065701", 40),
    DeviceProfile("362001065734", 40),
    DeviceProfile("362001065735", 40),
    DeviceProfile("362001065736", 40),  # Gree Amber Nordic / Prestige (GWH09YD-S6DBA2A outdoor; S6DBA1A indoor)
    DeviceProfile("362001066140", 40),
    DeviceProfile("362001066300", 40),
    DeviceProfile("362001066308", 40),
    DeviceProfile("362001066511", 40),
    DeviceProfile("362001066962", 40),
    DeviceProfile("362001067419", 40),
    DeviceProfile("362001067422", 40),
    DeviceProfile("362001067427", 40),
    DeviceProfile("362001067540", 40),
    DeviceProfile("362001067541", 40),  # Gree GWH12ATCXB-D6DNA4B/I (GWHD(24)ND6MO outdoor)
    DeviceProfile("362001067928", 40),
    DeviceProfile("362001068254", 40),  # Gree Airy (GWH09AVCXB-K6DNA1B/I, GWH12AVCXD-K6DNA1A); Gree Clivia
    DeviceProfile("362001068295", 40),
    DeviceProfile("362001068411", 40),
    DeviceProfile("362001068458", 40),
    DeviceProfile("362001071519", 40),
)


def _version_key(version: str) -> Tuple[int, ...]:
    components = [int(part) for part in version.split(".")]
    while components and components[-1] == 0:
        components.pop()
    return tuple(components)


def match_device_profile(hid: Optional[str]) -> Optional[DeviceProfile]:
    """Select the greatest eligible version floor, otherwise the code fallback."""
    firmware = re.fullmatch(
        r"([0-9]+)\+(?:U-)?([^+()\s]+?)(?:\([^()]+\))?"
        r"V([0-9]+(?:\.[0-9]+)*)\.bin",
        hid,
    ) if isinstance(hid, str) else None
    if firmware is None:
        return None
    code, _, version = firmware.groups()
    reported = None
    fallback = None
    selected = None
    selected_floor = None
    for candidate in KNOWN_PROFILES:
        if candidate.firmware_code != code:
            continue
        if candidate.min_version is None:
            if fallback is None:
                fallback = candidate
            continue
        if reported is None:
            reported = _version_key(version)
        floor = _version_key(candidate.min_version)
        if floor <= reported and (selected_floor is None or floor > selected_floor):
            selected = candidate
            selected_floor = floor
    return selected if selected is not None else fallback
