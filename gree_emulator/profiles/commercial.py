"""WB04BRT13 V1.50 standalone LAN dialects with explicitly synthetic controls."""

import json
from math import floor

from ..wire import InvalidPacket, Reply, decode_pack
from . import Profile, simulated

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7-nul-input"
HID = "362001065634+U-WB04BRT13V1.50.bin"
SOURCE_SHA256 = "44c79dc1a2dba15123f4ae9cc9a90a14234459ba6aa04df8eee2e98ef406e660"
PACKET_LIMIT = 1460  # Native packet builders0x9b02dee8/0x9b02dd40 use0x5b4.
# Exact native property table0x10000c8c; BuzzerCtrl is absent in this build.
_CONTROL_NAMES = frozenset((
    "Pow", "Mod", "SetTem", "WdSpd", "TemUn", "TemRec", "Air", "Blo",
    "Health", "SwhSlp", "SlpMod", "Lig", "SwingLfRig", "SwUpDn", "Quiet",
    "Tur", "StHt", "SvSt", "Buzzer_ON_OFF",
))
INITIAL_STATE = {name: value for name, value in simulated.INITIAL_STATE.items()
                 if name in _CONTROL_NAMES}


def _columns(names):
    if (not isinstance(names, list) or len(names) > 64
            or any(not isinstance(name, str) or not name.isascii() or "\0" in name
                   for name in names)
            or sum(len(name) + 1 for name in names) > 512):
        raise InvalidPacket("invalid commercial property array")
    return names


def _size(value):
    try:
        return len(json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                              allow_nan=False).encode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise InvalidPacket("invalid commercial text or number") from exc


def _reply(outer, inner, key):
    padded_size = 16 * (_size(inner) // 16 + 1)
    packet_size = _size({**outer, "pack": ""}) + 4 * ((padded_size + 2) // 3)
    if packet_size >= PACKET_LIMIT:
        raise InvalidPacket("commercial reply exceeds native packet buffer")
    return Reply(outer, inner, key, CODEC)


class Commercial:
    def __init__(self, gateway=False, child=False):
        self.gateway = gateway
        self.child = child

    def validate_state(self, state):
        if self.gateway:
            if state:
                raise ValueError("commercial host60 has no independent AC state")
            return
        for name in state:
            if name not in INITIAL_STATE and not name.startswith("_"):
                raise ValueError(f"state field {name!r} is unsupported by simulated commercial")
        simulated.validate_state(state)

    def validate_topology(self, device):
        if not self.gateway:
            return
        if len(device.children) != 1:
            raise ValueError(f"commercial host {device.mac} requires exactly one AC child")
        child = device.children[0]
        if child.profile.id != f"sim-wb04brt13-v1.50-{child.mid}" or child.mid not in ("6400", "6045", "609d"):
            raise ValueError(f"commercial child {child.mac} requires an evidenced AC child profile")
        if child.mac != device.mac + "00":
            raise ValueError(f"commercial child MAC {child.mac} must be {device.mac}00")

    def thermal_target(self, device):
        return None if self.gateway else simulated.thermal_target(device)

    def encode_room(self, device):
        if self.gateway:
            return
        # InTem is an unsigned16-bit cache field. Celsius here is simulation policy,
        # not a claim about the physical mainboard's uncalibrated sensor encoding.
        device.state["InTem"] = max(0, min(65535, floor(device.room_c)))

    def advertise(self, device, outer):
        if self.child or outer.get("t") != "scan":
            return []
        inner = {
            "t": "dev", "cid": "", "bc": "00000", "brand": "gree",
            "catalog": "gree", "mac": device.mac, "mid": device.mid,
            "model": "Commercial Simulator", "name": device.name, "lock": 0,
            "series": "", "vender": "", "ver": "V1.50", "mqttVer": "",
        }
        if self.gateway:
            inner["subCnt"] = 1
        return [_reply({"t": "pack", "i": 1, "uid": 0, "cid": "", "tcid": ""},
                       inner, GENERIC_KEY)]

    def handle(self, device, outer):
        if self.child:
            return []
        if (outer.get("t") != "pack" or outer.get("tcid") != device.mac
                or type(outer.get("i")) is not int or outer["i"] not in (0, 1)
                or not isinstance(outer.get("cid", ""), str)
                or type(outer.get("uid", 0)) is not int):
            raise InvalidPacket("invalid commercial target or envelope")
        key = GENERIC_KEY if outer["i"] == 1 else device.key
        inner = decode_pack(outer, key, CODEC)
        target = device.children[0] if self.gateway else device
        target_mac = inner.get("mac", inner.get("sub", device.mac))
        allowed_macs = (device.mac, target.mac) if self.gateway else (device.mac,)
        if (target_mac not in allowed_macs
                or ("mac" in inner and inner["mac"] not in allowed_macs)
                or ("sub" in inner and inner["sub"] != target.mac)):
            raise InvalidPacket("conflicting commercial inner identity")
        envelope = {"t": "pack", "i": outer["i"], "uid": outer.get("uid", 0),
                    "cid": outer.get("tcid", ""), "tcid": outer.get("cid", "")}
        operation = inner.get("t")
        if operation == "bind":
            if target_mac != device.mac or "sub" in inner:
                raise InvalidPacket("only the commercial LAN host may bind")
            reply = {"r": 200, "t": "bindok", "mac": device.mac,
                     "key": device.key.decode("ascii")}
        elif operation == "subDev" and self.gateway:
            start = inner.get("i")
            if (target_mac != device.mac or type(start) is not int
                    or not -(2**31) <= start < 2**31):
                raise InvalidPacket("commercial enumeration requires host mac and integer i")
            children = [{"mac": target.mac, "name": "ACUnit", "mid": target.mid,
                         "model": "gree", "lock": 0}] if start == 0 else []
            reply = {"t": "subList", "r": 200, "c": 1, "i": start, "list": children}
        elif operation == "status":
            names = _columns(inner.get("cols", inner.get("opt")))
            if "cols" not in inner:
                values = inner.get("p")
                if (not isinstance(values, list) or len(values) != len(names)
                        or any(type(value) is not int for value in values)
                        or any(name in ("hid", "mid", "name", "lock", "bc", "ver", "vender")
                               for name in names)):
                    raise InvalidPacket("commercial opt status requires numeric p values")
            target.profile.handler.encode_room(target)
            metadata = {
                "hid": HID, "mid": target.mid, "name": device.name, "lock": 0,
                "bc": "00000", "ver": "V1.50", "vender": "",
            }
            values = {**target.state, **metadata}
            cols = [name for name in names if name in values and not name.startswith("_")]
            reply = {"t": "dat", "uid": 0, "mac": target_mac,
                     "cid": device.mac, "dat": [values[name] for name in cols],
                     "cols": cols, "r": 200}
        elif operation == "cmd":
            names = _columns(inner.get("opt"))
            if "cols" in inner or any(name not in INITIAL_STATE for name in names):
                raise InvalidPacket("unsupported or ambiguous simulated commercial command")
            reply = {"t": "res", "mac": target_mac, "p": inner.get("p"),
                     "opt": list(names), "r": 200}
            response = _reply(envelope, reply, key)
            # Validate every property before thermal advance or any state mutation.
            simulated.apply_command(target, names, inner.get("p"))
            return [response]
        else:
            return []
        return [_reply(envelope, reply, key)]


PROFILES = tuple(
    Profile(f"sim-wb04brt13-v1.50-{mid}", (mid,), HID, SOURCE_SHA256,
            INITIAL_STATE, Commercial(), max_request_bytes=PACKET_LIMIT - 1)
    for mid in ("3019", "3027", "4005")
) + (
    Profile("sim-wb04brt13-v1.50-60", ("60",), HID, SOURCE_SHA256,
            {}, Commercial(gateway=True), max_children=1, max_request_bytes=PACKET_LIMIT - 1),
) + tuple(
    Profile(f"sim-wb04brt13-v1.50-{mid}", (mid,), HID, SOURCE_SHA256,
            INITIAL_STATE, Commercial(child=True), identity_bytes=7,
            parent_profiles=("sim-wb04brt13-v1.50-60",))
    for mid in ("6400", "6045", "609d")
)
