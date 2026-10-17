"""W04N V17 LAN framing with the explicitly synthetic AC model."""

import json

from ..wire import InvalidPacket, Reply, decode_pack
from . import Profile
from . import simulated

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
HID = "362001064973+U-W04NV17.bin"
SOURCE_SHA256 = "b0b7f5d428858ca5e5ad29a8afcfaa0da4063fe36e98fae7c447047163112727"
# BuzzerCtrl is not in this build's recovered property table.
INITIAL_STATE = {name: value for name, value in simulated.INITIAL_STATE.items()
                 if name != "BuzzerCtrl"}


def _reply(outer, inner, key):
    envelope = {"t": "pack", "i": outer["i"], "uid": outer.get("uid", 0),
                "cid": outer.get("tcid", ""), "tcid": outer.get("cid", "")}
    plain_size = len(json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode())
    cipher_size = 16 * (plain_size // 16 + 1)
    envelope_size = len(json.dumps({**envelope, "pack": ""}, ensure_ascii=False,
                                   separators=(",", ":")).encode())
    if envelope_size + 4 * ((cipher_size + 2) // 3) >= 0x7b4:
        raise InvalidPacket("W04N reply exceeds the firmware buffer")
    return Reply(envelope, inner, key, CODEC)


def _columns(inner):
    names = inner.get("cols", inner.get("opt"))
    if (not isinstance(names, list) or len(names) > 64
            or any(not isinstance(name, str) or "\0" in name for name in names)
            or sum(len(name.encode("utf-8")) + 1 for name in names) > 512):
        raise InvalidPacket("invalid W04N column array")
    if "cols" not in inner:
        numeric = sum(name not in _METADATA_NAMES for name in names)
        values = inner.get("p")
        if (not isinstance(values, list) or len(values) != numeric
                or any(type(value) is not int for value in values)):
            raise InvalidPacket("W04N opt requires numeric p values")
    return names


_METADATA_NAMES = frozenset((
    "time", "name", "lock", "AutoUpdate", "host", "hid", "mid", "bc",
    "DevID", "MafIdf", "AppTimer", "MidType", "rssi", "ReportClientID",
    "ver", "vender",
))


class W04N:
    def validate_state(self, state):
        for name in state:
            if name not in INITIAL_STATE and not name.startswith("_"):
                raise ValueError(f"state field {name!r} is unsupported by simulated W04N")
        simulated.validate_state(state)

    def thermal_target(self, device):
        return simulated.thermal_target(device)

    def encode_room(self, device):
        simulated.encode_room(device, 0, 50)

    def advertise(self, device, outer):
        if outer.get("t") != "scan":
            return []
        inner = {
            "t": "dev", "cid": device.mac, "bc": "00000", "brand": "",
            "catalog": "", "mac": device.mac, "mid": device.mid, "model": "",
            "name": device.name, "lock": 0, "series": "", "vender": "",
            "ver": "V3.0.0", "hid": HID,
        }
        return [_reply({"i": 1, "uid": 0, "cid": "", "tcid": ""}, inner, GENERIC_KEY)]

    def handle(self, device, outer):
        if (outer.get("t") != "pack" or outer.get("tcid") != device.mac
                or type(outer.get("i")) is not int or outer["i"] not in (0, 1)
                or not isinstance(outer.get("cid", ""), str)
                or type(outer.get("uid", 0)) is not int):
            raise InvalidPacket("invalid W04N target or envelope")
        key = GENERIC_KEY if outer["i"] == 1 else device.key
        inner = decode_pack(outer, key, CODEC)
        for selector in ("mac", "sub"):
            if selector in inner and inner[selector] != device.mac:
                raise InvalidPacket("conflicting W04N inner identity")
        operation = inner.get("t")
        if operation == "bind":
            reply = {"r": 200, "t": "bindok", "mac": device.mac,
                     "key": device.key.decode("ascii")}
        elif operation == "status":
            names = _columns(inner)
            self.encode_room(device)
            metadata = {
                "name": device.name, "hid": HID, "mid": device.mid, "host": "",
                "lock": 0, "AutoUpdate": 0, "bc": "3030303030", "DevID": "",
                "MafIdf": 0, "MidType": "", "ver": "V3.0.0", "vender": "",
            }
            # Unmodeled firmware properties are omitted, never synthesized as zeros.
            values = {**device.state, **metadata}
            cols = [name for name in names if name in values and not name.startswith("_")]
            reply = {"t": "dat", "uid": outer.get("uid", 0), "mac": device.mac,
                     "cid": device.mac, "dat": [values[name] for name in cols],
                     "cols": cols, "r": 200}
        elif operation == "cmd":
            names = inner.get("opt")
            values = inner.get("p")
            _columns({"cols": names})
            if not names or any(name not in INITIAL_STATE for name in names):
                raise InvalidPacket("unsupported W04N simulated command")
            if "cols" in inner:
                # Firmware's extractor prioritizes cols; reject ambiguous writes safely.
                raise InvalidPacket("ambiguous W04N command columns")
            if not isinstance(values, list) or len(values) != len(names):
                raise InvalidPacket("invalid W04N command values")
            final_values = dict(zip(names, values))
            reply = _reply(outer, {"t": "res", "mac": device.mac,
                                   "val": [final_values[name] for name in names],
                                   "p": list(values), "opt": list(names), "r": 200}, key)
            simulated.apply_command(device, names, values)
            return [reply]
        else:
            return []
        return [_reply(outer, reply, key)]


PROFILES = (Profile("sim-w04n-v17", (
    "10001", "10002", "10014", "10015", "10016", "10017", "11000", "11001",
    "11002", "11010", "11f00", "11f01", "11f02", "11f03", "13000",
), HID, SOURCE_SHA256, INITIAL_STATE, W04N()),)
