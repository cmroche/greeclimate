"""W05SA V1.28 LAN dialect; appliance temperatures are explicitly synthetic."""

import time
from datetime import datetime

from ..wire import InvalidPacket, Reply, decode_pack
from . import Profile
from .commercial import _columns, _size

HID = "362001062617+U-W05SAV1.28.bin"
SOURCE_SHA256 = "aae6c0782b8d2a3d7fd5c071fbd23ab292dc1d42cf864c1307df961d9305e864"
ROOT_ID = "sim-w05sa-v1.28"
MASTER_ID = ROOT_ID + "-master"
ZONE_ID = ROOT_ID + "-zone"
CODEC = "aes-ecb-pkcs7"
GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
PACKET_LIMIT = 1024  # Native0x805e6fc clears and serializes into0x400-byte buffers.
# Numeric cache is unsigned halfwords, not the narrower mainboard frame bitfields.
_SHARED = (
    "Pow Mod StTem WdSpd EnSvSt StFahFlg HeatSvStTemMax CoolSvStTemMin TemUnit "
    "Dry OMod Quier LowDeHumi HSvStTemMaxFlg CSvStTemMinFlg ColdMod ErWdVlv "
    "ErVavle RmType RmNum WdVlvAllOnNum IndoorType AllErr Dred VavleAllOn "
    "Demand InProtocol NoD MasterPow IntProVer MainConProVer SubConProVer "
    "Tcloud AppTimer ElcErg ElcGear Elc1Kwh AutoUpdate AutoComnCloud lock"
).split()
_ALIASES = {"Pow": "EnWdVlv", "StTem": "StTem", "StFahFlg": "StFahFlg",
            "RmType": "RmType", "RmNum": "RmNum", "EnValve": "EnValve"}
ROOT_STATE = dict.fromkeys(_SHARED, 0)
ROOT_STATE.update({prefix + str(slot): 0 for prefix in _ALIASES.values()
                   for slot in range(1, 9)})
ROOT_STATE["StTem"] = 8
ROOT_STATE.update({"StTem" + str(slot): 8 for slot in range(1, 9)})
ZONE_STATE = dict.fromkeys(_ALIASES, 0)
ZONE_STATE["StTem"] = 8
_FOOTER = frozenset((
    "apssid appsw host name time lat lon vender bc mid model series brand catalog "
    "country hid mac ver HidSvrVer InHid InHidSvrVer OEEPHid OEEPHidSvrVer"
).split())
_STRING_LIMITS = {"apssid": (1, 32), "appsw": (0, 32), "host": (1, 20),
                  "name": (0, 31), "lat": (1, 10), "lon": (1, 10)}


def _metadata(root):
    # Explicit synthetic platform/cache defaults, not original calibration/startup.
    return root.state.setdefault("_zone_metadata", {
        "name": root.name, "host": "", "lat": "", "lon": "", "vender": "",
        "bc": "gree", "mid": "50", "hid": HID, "mac": root.mac, "ver": "",
        "time": "2000-01-01 00:00:00", "apssid": "", "appsw": "",
    })


def _value(root, obj, field, metadata):
    if field in _FOOTER:
        return metadata.get(field) if field not in ("apssid", "appsw") else None
    return obj.state.get(field)


def _string_write(field, value):
    if not isinstance(value, str) or "\0" in value or not value.isascii():
        raise InvalidPacket("invalid zone metadata string")
    if field == "time":
        try:
            datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
            if len(value) != 19:
                raise ValueError("zone time requires fixed-width fields")
        except ValueError as error:
            raise InvalidPacket("invalid zone time") from error
    elif field in _STRING_LIMITS:
        low, high = _STRING_LIMITS[field]
        if not low <= len(value) <= high:
            raise InvalidPacket("invalid zone metadata length")


def _reply(outer, inner, key):
    padded = 16 * (_size(inner) // 16 + 1)
    if _size(inner) >= PACKET_LIMIT or _size({**outer, "pack": ""}) + 4 * ((padded + 2) // 3) >= PACKET_LIMIT:
        raise InvalidPacket("zone reply exceeds native packet buffer")
    return Reply(outer, inner, key, CODEC)


def _root(device):
    return device.state.get("_zone_root", device)


def _sync(root):
    for child in root.children:
        if child.mid == "5000":
            child.state["Pow"] = root.state["MasterPow"]
        else:
            for alias, prefix in _ALIASES.items():
                root.state[prefix + child.mac[-1]] = child.state[alias]


def _energy_limits(root):
    state = root.state
    if not state["EnSvSt"] or state["Mod"] not in (1, 2):
        return
    limit = state["CoolSvStTemMin"] if state["Mod"] == 1 else state["HeatSvStTemMax"]
    for slot in range(1, 9):
        obj, field = _location(root, root, "StTem" + str(slot))
        obj.state[field] = (max if state["Mod"] == 1 else min)(obj.state[field], limit)


def _cloud_control(root):
    if root.state["Tcloud"] != 1:
        return
    flags = 0
    for slot in range(1, 9):
        obj, field = _location(root, root, "EnWdVlv" + str(slot))
        bit = 1 << (slot - 1)
        flags = ((flags & ~bit) | (obj.state[field] << (slot - 1))) & 255
    # Synthetic mainboard-selected slot0: native shift255 removes no zone bit.
    root.state["Tcloud"] = 0
    root.state["MasterPow"] = int(flags != 0)


def _location(root, device, name):
    if device is not root:
        if device.mid == "5000":
            if name == "Pow":
                return root, "MasterPow"
        elif name in ZONE_STATE:
            return device, name
    for alias, prefix in _ALIASES.items():
        if name.startswith(prefix) and name[len(prefix):] in tuple("12345678"):
            slot = int(name[-1])
            for child in root.children:
                if child.mid == "5001" and int(child.mac[-1]) == slot:
                    return child, alias
    return root, name


class Zones:

    def __init__(self, role):
        self.role = role

    def validate_state(self, state):
        allowed = ROOT_STATE if self.role == "root" else ZONE_STATE if self.role == "zone" else {}
        for name, value in state.items():
            if name not in allowed or type(value) is not int or not 0 <= value <= 65535:
                raise ValueError(f"invalid simulated zone state field {name!r}")

    def validate_topology(self, device):
        if self.role != "root":
            return
        slots = set()
        for child in device.children:
            suffix = child.mac[len(device.mac):]
            if (not child.mac.startswith(device.mac) or len(suffix) != 2
                    or suffix[0] != "0" or suffix[1] not in "012345678"):
                raise ValueError(
                    f"zone MAC {child.mac!r} must equal parent {device.mac!r} + '0' + slot0..8; "
                    "configure explicit matching MACs"
                )
            slot = int(suffix[1])
            if slot in slots:
                raise ValueError(f"zone MAC {child.mac!r} duplicates slot {slot}")
            expected_mid = "5000" if slot == 0 else "5001"
            if child.mid != expected_mid:
                raise ValueError(f"zone MAC {child.mac!r} slot {slot} requires MID{expected_mid}, not {child.mid}")
            slots.add(slot)
        # Native compaction supports gaps, but assigns MID5000 to the first online entry.
        if slots and 0 not in slots:
            raise ValueError(
                f"zone parent MAC {device.mac!r} requires master MAC {device.mac + '00'!r} before other slots; "
                f"configured MACs: {[child.mac for child in device.children]}"
            )
        device.children.sort(key=lambda child: child.mac[-1])
        for child in device.children:
            child.state["_zone_root"] = device
            if child.mid == "5001":
                for alias, prefix in _ALIASES.items():
                    field = prefix + child.mac[-1]
                    parent_value, child_value = device.state[field], child.state[alias]
                    if parent_value != ROOT_STATE[field]:
                        if child_value != ZONE_STATE[alias] and child_value != parent_value:
                            raise ValueError(f"conflicting zone cache aliases {field!r}/{alias!r}")
                        child.state[alias] = parent_value
        _sync(device)

    def thermal_target(self, device):
        if self.role == "root":
            return None
        root = _root(device)
        state = root.state if root is not device else ROOT_STATE
        target = 16 + (device.state.get("StTem", state.get("StTem", 8)) & 15)
        # Synthetic appliance policy: master power gates every zone; Mod1 cool/2 heat.
        powered = state.get("MasterPow", 0) == 1 and (device.state.get("Pow", 0) & 1)
        action = {1: "cool", 2: "heat"}.get(state.get("Mod", 0), "idle") if powered else "idle"
        return action, target

    def encode_room(self, device):
        # Native zone namespace has no ambient sensor; never invent a LAN field.
        return None

    def advertise(self, device, outer):
        if self.role != "root" or outer.get("t") != "scan":
            return []
        inner = {"t": "dev", "bc": "gree", "catalog": "gree", "mid": "50",
                 "lock": 0, "model": "gree", "name": device.name, "series": "gree",
                 "vender": "", "ver": "", "brand": "gree", "mac": device.mac,
                 "subCnt": len(device.children)}
        return [_reply({"t": "pack", "i": 1, "uid": 0, "cid": device.mac, "tcid": "app"}, inner, GENERIC_KEY)]

    def handle(self, device, outer):
        root = _root(device)
        if (outer.get("t") != "pack" or outer.get("tcid") != root.mac
                or type(outer.get("i")) is not int or outer["i"] not in (0, 1)
                or type(outer.get("uid", 0)) is not int
                or not -(1 << 31) <= outer.get("uid", 0) < (1 << 31)
                or not isinstance(outer.get("cid", ""), str)):
            raise InvalidPacket("invalid zone envelope or parent target")
        inner = decode_pack(outer, GENERIC_KEY if outer["i"] else root.key, CODEC)
        operation = inner.get("t")
        envelope = {"t": "pack", "i": 0, "uid": outer.get("uid", 0),
                    "cid": root.mac, "tcid": "app"}
        if operation in ("bind", "subDev"):
            if inner.get("mac") != root.mac:
                raise InvalidPacket("zone bind/enumeration requires parent MAC")
            if operation == "bind":
                envelope["i"] = 1
                return [_reply(envelope, {"t": "bindOk", "mac": root.mac, "r": 200,
                                          "key": root.key.decode("ascii")}, GENERIC_KEY)]
            index = inner.get("i", 0)
            if type(index) is not int or not 0 <= index <= 255:
                raise InvalidPacket("invalid zone enumeration index")
            reply = {"t": "subList", "r": 200, "c": len(root.children), "i": index,
                     "list": [{"mac": child.mac, "mid": child.mid, "name": "zone",
                               "model": "gree", "lock": 0}
                              for child in root.children[index:index + 5]]}
            return [_reply(envelope, reply, root.key)]
        if operation not in ("status", "cmd") or outer["i"] != 0:
            return []
        selector = "mac" if operation == "status" else "sub"
        mac = inner.get(selector, root.mac)
        target = root if mac == root.mac else next((child for child in root.children if child.mac == mac), None)
        if target is None:
            raise InvalidPacket("unknown zone inner identity")
        if "mac" in inner and inner["mac"] not in (root.mac, target.mac):
            raise InvalidPacket("conflicting zone inner MAC")
        names = _columns(inner.get("cols" if operation == "status" else "opt"))
        if len(names) > 30 or any(len(name) >= 16 for name in names):
            raise InvalidPacket("zone property array exceeds native status limits")
        if operation == "status" and "" in names:
            names = names[:names.index("")]
        locations = [_location(root, target, name) for name in names]
        if operation == "status":
            metadata = _metadata(root)
            accepted = [(name, _value(root, obj, field, metadata))
                        for name, (obj, field) in zip(names, locations)
                        if (field in obj.state and not field.startswith("_")) or field in _FOOTER]
            if len(names) == 30:
                accepted = []  # Original exact-capacity counter wraps to zero.
            reply = ({"t": "dat", "mac": target.mac, "r": 200} if target is root
                     else {"t": "dat", "r": 200, "mac": target.mac})
            reply.update(cols=[name for name, _ in accepted],
                         dat=[value for _, value in accepted if value is not None])
            return [_reply(envelope, reply, root.key)]
        values = inner.get("p")
        if ("cols" in inner or not names or not isinstance(values, list) or len(values) != len(names)):
            raise InvalidPacket("invalid simulated zone command batch")
        metadata = _metadata(root)
        proposed = metadata.copy()
        acknowledged = []
        numeric = {}
        for (obj, field), value in zip(locations, values):
            if (field not in obj.state or field.startswith("_")) and field not in _FOOTER:
                raise InvalidPacket("unknown zone command property")
            if isinstance(value, str):
                _string_write(field, value)
                if field in _STRING_LIMITS or field == "time":
                    proposed[field] = value
            elif type(value) is not int or not -(1 << 31) <= value < (1 << 31):
                raise InvalidPacket("invalid zone numeric value")
            if field in _FOOTER:
                if field in proposed and field not in ("apssid", "appsw"):
                    acknowledged.append(proposed[field])
            else:
                location = (id(obj), field)
                numeric[location] = value & 65535 if type(value) is int else numeric.get(location, obj.state[field])
                acknowledged.append(numeric[location])
        reply = ({"t": "res", "mac": target.mac, "r": 200} if target is root
                 else {"t": "res", "r": 200, "mac": target.mac})
        reply.update(opt=names, p=acknowledged)
        response = _reply(envelope, reply, root.key)
        now = time.monotonic()
        for child in root.children:
            child.advance(now)
        for (obj, field), value in zip(locations, values):
            if field not in _FOOTER and type(value) is int:
                obj.state[field] = value & 65535
        metadata.update(proposed)
        root.name = metadata["name"]
        _energy_limits(root)
        _cloud_control(root)
        _sync(root)
        return [response]


PROFILES = (
    Profile(ROOT_ID, ("50",), HID, SOURCE_SHA256, ROOT_STATE, Zones("root"),
            max_children=9, max_request_bytes=PACKET_LIMIT),
    Profile(MASTER_ID, ("5000",), HID, SOURCE_SHA256, {}, Zones("master"),
            identity_bytes=7, parent_profiles=(ROOT_ID,)),
    Profile(ZONE_ID, ("5001",), HID, SOURCE_SHA256, ZONE_STATE, Zones("zone"),
            identity_bytes=7, parent_profiles=(ROOT_ID,)),
)
