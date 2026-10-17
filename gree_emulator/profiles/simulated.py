"""Synthetic AC behavior, deliberately separate from firmware LAN framing."""

from math import floor
from time import monotonic

from ..wire import InvalidPacket


CONTROL_RANGES = {
    "Pow": (0, 1), "Mod": (0, 4), "SetTem": (16, 30), "WdSpd": (0, 5),
    "TemUn": (0, 1), "TemRec": (0, 1), "Air": (0, 1), "Blo": (0, 1),
    "Health": (0, 1), "SwhSlp": (0, 1), "SlpMod": (0, 3), "Lig": (0, 1),
    "SwingLfRig": (0, 6), "SwUpDn": (0, 11), "Quiet": (0, 3), "Tur": (0, 1),
    "StHt": (0, 1), "SvSt": (0, 1), "Buzzer_ON_OFF": (0, 1), "BuzzerCtrl": (0, 1),
}
INITIAL_STATE = {name: 0 for name in CONTROL_RANGES}
INITIAL_STATE["SetTem"] = 24
INITIAL_STATE["Lig"] = 1


def validate_state(state):
    for name, value in state.items():
        if name.startswith("_"):
            continue
        if name not in CONTROL_RANGES:
            raise ValueError(f"state field {name!r} is not a configurable simulated control")
        lower, upper = CONTROL_RANGES[name]
        if type(value) is not int or not lower <= value <= upper:
            raise ValueError(f"state field {name!r} must be an integer in {lower}..{upper}")


def thermal_target(device):
    state = device.state
    target = state["SetTem"]
    if not state["Pow"] or state["Mod"] == 3:
        return "idle", target
    if state["Mod"] == 4:
        return "heat", 8 if state.get("StHt", 0) else target
    return ("auto" if state["Mod"] == 0 else "cool"), target


def encode_room(device, bias, upper):
    device.state["TemSen"] = max(0, min(upper, floor(device.room_c) + bias))


def apply_command(device, names, values):
    if (not isinstance(names, list) or not isinstance(values, list)
            or not names or len(names) != len(values)):
        raise InvalidPacket("command requires equally sized nonempty opt and p arrays")
    for name, value in zip(names, values):
        if not isinstance(name, str) or name not in CONTROL_RANGES:
            raise InvalidPacket("command names an unsupported or read-only simulated field")
        lower, upper = CONTROL_RANGES[name]
        if type(value) is not int or not lower <= value <= upper:
            raise InvalidPacket(f"invalid simulated value for {name}")
    device.advance(monotonic())
    device.state.update(zip(names, values))
    device.profile.handler.encode_room(device)
