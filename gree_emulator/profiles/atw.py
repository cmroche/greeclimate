"""Exact W06A(P3) V6.04 LAN dialect with explicit single-medium simulation."""

import json
import time
from math import floor

from ..wire import InvalidPacket, Reply, decode_pack
from . import Profile

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
HID = "362001066763+U-W06A(P3)V6.04.bin"
SOURCE_SHA256 = "37ab39b75436448b7153fbbd781a21c93b83f74a236354c93aafcf9b10ed039a"
CONTROL_RANGES = {
    "Pow": (0, 1), "TemUn": (0, 1), "Mod": (1, 5),
    "CoWatOutTemSet": (7, 25), "HeWatOutTemSet": (20, 60),
    "WatBoxTemSet": (40, 80), "CoHomTemSet": (16, 30), "HeHomTemSet": (16, 30),
}
INITIAL_STATE = {
    "Pow": 0, "TemUn": 0, "Mod": 1, "CoWatOutTemSet": 18,
    "HeWatOutTemSet": 35, "WatBoxTemSet": 50, "CoHomTemSet": 24, "HeHomTemSet": 24,
}
_SENSOR_PAIRS = {
    "9300": (("RmoHomTemHi", "RmoHomTemLo"),),
    "9301": (("WatBoxTemHi", "WatBoxTemLo"),),
    "9302": (("AllInWatTemHi", "AllInWatTemLo"),
             ("AllOutWatTemHi", "AllOutWatTemLo")),
}


def _members(value, maximum):
    if not isinstance(value, dict) or len(value) > maximum:
        raise InvalidPacket("invalid ATW object size")
    normalized = {}
    for name, item in value.items():
        if not isinstance(name, str) or name.lower() in normalized:
            raise InvalidPacket("ambiguous ATW JSON field")
        normalized[name.lower()] = item
    return normalized


def _text_size(value):
    if not isinstance(value, str) or "\0" in value:
        raise InvalidPacket("invalid ATW text")
    try:
        return len(value.encode("utf-8"))
    except UnicodeError as exc:
        raise InvalidPacket("invalid ATW UTF-8") from exc


def _names(value, maximum):
    if (not isinstance(value, list) or len(value) > maximum
            or any(_text_size(name) > 19 for name in value)):
        raise InvalidPacket("invalid ATW property names")
    return value


def _reply(device, outer, inner, *, generic=False):
    plain_size = len(json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    # Bound encrypted base64 to 1496 bytes before a command can mutate state.
    if plain_size > 1119:
        raise InvalidPacket("ATW reply exceeds the safe firmware buffer")
    envelope = {"t": "pack", "i": 1 if generic else 0,
                "uid": outer["uid"], "cid": device.mac, "tcid": outer["cid"]}
    return Reply(envelope, inner, GENERIC_KEY if generic else device.key, CODEC)


class Atw:
    def validate_state(self, state):
        for name, value in state.items():
            if name not in CONTROL_RANGES:
                raise ValueError(f"state field {name!r} is not a configurable ATW control")
            lower, upper = CONTROL_RANGES[name]
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError(f"state field {name!r} must be an integer in {lower}..{upper}")

    def thermal_target(self, device):
        state = device.state
        mode = state["Mod"]
        if device.mid == "9301":
            target = state["WatBoxTemSet"]
            action = "heat" if mode in (2, 3, 4) else "idle"
        else:
            heating = mode in (1, 4)
            cooling = mode in (3, 5)
            suffix = "HomTemSet" if device.mid == "9300" else "WatOutTemSet"
            target = state[("He" if heating else "Co") + suffix]
            action = "heat" if heating else "cool" if cooling else "idle"
        return (action if state["Pow"] else "idle"), target

    def _sensors(self, device):
        # Consumer-compatible chosen calibration, not established by firmware bytes.
        tenths = floor(max(-100.0, min(155.9, device.room_c)) * 10) + 1000
        high, low = divmod(tenths, 10)
        return {name: value for pair in _SENSOR_PAIRS[device.mid]
                for name, value in zip(pair, (high, low))}

    def encode_room(self, device):
        device.state.update(self._sensors(device))

    def advertise(self, device, outer):
        outer = _members(outer, 20)
        if outer.get("t") != "scan":
            return []
        inner = {
            "t": "dev", "cid": device.mac, "bc": "gree", "brand": "gree",
            "catalog": "gree", "mac": device.mac, "mid": device.mid, "hid": HID,
            "ModelType": "simulated-atw", "model": "gree", "name": device.name,
            "series": "gree", "vender": "1", "ver": "V6.04", "lock": 0,
        }
        return [_reply(device, {"uid": 0, "cid": ""}, inner, generic=True)]

    def handle(self, device, outer):
        # Shared UDP routing still requires lowercase t/pack/tcid; inner lookup is native-style.
        outer = _members(outer, 20)
        if (outer.get("t") != "pack"
                or not {"pack", "i", "uid", "cid", "tcid"} <= outer.keys()
                or outer["tcid"] != device.mac
                or type(outer["i"]) is not int or outer["i"] < 0
                or type(outer["uid"]) is not int
                or _text_size(outer["cid"]) > 19):
            raise InvalidPacket("invalid ATW target or envelope")
        pack = outer["pack"]
        if not isinstance(pack, str) or not pack.isascii() or len(pack) >= 700:
            raise InvalidPacket("ATW encrypted pack exceeds the firmware buffer")
        key = GENERIC_KEY if outer["i"] & 255 else device.key
        inner = _members(decode_pack(outer, key, CODEC), 30)
        for selector in ("mac", "sub"):
            if selector in inner and inner[selector] != device.mac:
                raise InvalidPacket("conflicting ATW inner target")
        operation = inner.get("t")
        if operation == "bind":
            if inner.get("mac") != device.mac:
                raise InvalidPacket("ATW bind requires matching mac")
            reply = {"t": "bindok", "mac": device.mac,
                     "key": device.key.decode("ascii"), "r": 200}
            return [_reply(device, outer, reply, generic=True)]
        if operation not in ("status", "cmd"):
            return []
        if outer["i"] != 0:
            raise InvalidPacket("ATW controls require bound selector zero")
        if operation == "status":
            if inner.get("mac") != device.mac:
                raise InvalidPacket("ATW status requires matching mac")
            names = _names(inner.get("cols"), 50)
            metadata = {
                "mid": device.mid, "hid": HID, "name": device.name, "mac": device.mac,
                "host": "", "ModelType": "simulated-atw", "vender": "1",
                "ver": "V6.04", "AllErr": 0,
            }
            values = {name: device.state[name] for name in CONTROL_RANGES}
            values.update(self._sensors(device))
            values.update(metadata)
            cols = [] if len(names) == 50 else [name for name in names if name in values]
            reply = {"t": "dat", "r": 200, "mac": device.mac,
                     "cols": cols, "dat": [values[name] for name in cols]}
            return [_reply(device, outer, reply)]
        names = _names(inner.get("opt"), 49)
        values = inner.get("p")
        if (not names or not isinstance(values, list) or len(names) != len(values)
                or "cols" in inner):
            raise InvalidPacket("ATW command requires unambiguous equal nonempty opt/p arrays")
        for name, value in zip(names, values):
            if name not in CONTROL_RANGES:
                raise InvalidPacket("unsupported or read-only ATW control")
            lower, upper = CONTROL_RANGES[name]
            if type(value) is not int or not lower <= value <= upper:
                raise InvalidPacket(f"invalid simulated ATW value for {name}")
        reply = _reply(device, outer, {"t": "res", "r": 200, "opt": list(names),
                                       "p": list(values), "val": list(values)})
        device.advance(time.monotonic())
        device.state.update(zip(names, values))
        self.encode_room(device)
        return [reply]


_HANDLER = Atw()
PROFILES = tuple(
    Profile(f"sim-w06a-p3-v6.04-{mid}", (mid,), HID, SOURCE_SHA256,
            {**INITIAL_STATE, "Mod": 2 if mid == "9301" else 1}, _HANDLER,
            max_request_bytes=1024)
    for mid in ("9300", "9301", "9302")
)
