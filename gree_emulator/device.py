"""Per-device state and the deliberately linear room-temperature simulation."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .profiles import Profile


def step_temperature(room_c: float, target_c: float, ambient_c: float,
                     action: str, dt: float) -> float:
    """Move at 1°C/min active or 0.1°C/min idle, without overshooting."""
    if not all(math.isfinite(value) for value in (room_c, target_c, ambient_c, dt)):
        raise ValueError("temperatures and elapsed time must be finite")
    if dt < 0:
        raise ValueError("elapsed time must be nonnegative")
    if action not in ("cool", "heat", "auto", "idle"):
        raise ValueError(f"unknown thermal action: {action}")
    if action == "cool" and room_c <= target_c:
        return room_c
    if action == "heat" and room_c >= target_c:
        return room_c
    destination = ambient_c if action == "idle" else target_c
    change = min(abs(destination - room_c), dt / (600 if action == "idle" else 60))
    return room_c + math.copysign(change, destination - room_c)


@dataclass
class EmulatedDevice:
    id: str
    mac: str
    name: str
    mid: str
    key: bytes
    profile: Profile
    state: dict = field(default_factory=dict)
    children: list["EmulatedDevice"] = field(default_factory=list)
    room_c: float | None = 26.0
    ambient_c: float | None = 26.0
    last_step: float = field(default_factory=time.monotonic)

    def advance(self, now: float) -> None:
        """Consume elapsed time once, using controls in effect before a command."""
        if now < self.last_step:
            raise ValueError("device clock must be monotonic")
        controls = self.profile.handler.thermal_target(self)
        if controls is not None:
            action, target = controls
            self.room_c = step_temperature(
                self.room_c, target, self.ambient_c, action, now - self.last_step
            )
            self.profile.handler.encode_room(self)
        self.last_step = now
