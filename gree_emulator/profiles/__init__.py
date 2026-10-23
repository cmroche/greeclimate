"""Explicit appliance models with independently evidenced LAN packet formats."""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True)
class Profile:
    id: str
    mids: tuple[str, ...]
    hid: str
    source_sha256: str
    initial_state: Mapping[str, object]
    handler: object
    identity_bytes: int = 6
    parent_profiles: tuple[str, ...] = ()
    max_children: int = 0
    max_request_bytes: int | None = None

    def __post_init__(self):
        object.__setattr__(self, "initial_state", MappingProxyType(dict(self.initial_state)))


# Families import Profile, so registration follows its definition.
from . import atw, commercial, controller, gateway, hb, w04, w04n, wb, zones  # noqa: E402


PROFILES = {
    profile.id: profile
    for family in (w04, w04n, wb, hb, commercial, controller, gateway, zones, atw)
    for profile in family.PROFILES
}
