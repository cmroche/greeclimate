"""WB05BR LAN formats with a sensorless, explicitly synthetic indoor cache.

PR148 exact-image ARM probes establish list traversal and dispatch, not a booted
mainboard. Controls below are immediate integer-Celsius simulation policy; no
TemBody/TemSor calibration, serial frames, physical reversion or thermal model
is claimed. Child MIDs608f/605c were independently observed in the PR hardware log.
"""

from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile, simulated


GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
BUILDS = (
    ("1.13", "362001066380", "897f4ebe52618702c5dc1310fa06a9349ccbf98dd988aa0b74a42303e6206d6e"),
    ("1.16", "362001066326", "8d09158d365e633e093a17ee0b4477b381fee78c8189f20bbbdd77a8ad79a23b"),
    ("1.18", "362001066326", "92213de63cf4d486dcc6d5ddddd81218b9e83debfc3b20845d8e5cc9c99c0786"),
    ("1.22", "362001066380", "7684d712ddb4b6b330b2ac1697c04ed7a381643b86ab8afa86c81d5306fe74c4"),
    ("1.31", "362001066380", "35c6a04be944e945b4660c2ff6f77a4bc5251420654fdb4b0ab1917dd473e56e"),
    ("1.38", "362001066380", "47b25da11516d27cfc0af1fe4f027a860edc00a0b2c6b0ed14566ffab34d2b1d"),
)
CHILD_MIDS = ("608f", "605c")
INITIAL_STATE = {"Pow": 0, "Mod": 1, "SetTem": 24, "WdSpd": 0}


def _reply(device, outer, inner, index=None):
    index = outer["i"] if index is None else index
    return Reply({"t": "pack", "cid": device.mac, "tcid": outer["cid"],
                  "uid": outer["uid"], "i": index}, inner,
                 GENERIC_KEY if index == 1 else device.key, CODEC)


def _child(device, identity):
    for child in device.children:
        if child.mac == identity:
            return child
    raise InvalidPacket("unknown WB05BR child")


def _columns(value):
    if (not isinstance(value, list)
            or any(not isinstance(name, str) or not name or "\0" in name for name in value)):
        raise InvalidPacket("WB05BR columns must be nonempty strings")
    return value


class WBGatewayFamily:
    def __init__(self, child=False):
        self.child = child

    def validate_state(self, state):
        for name in state:
            if not self.child or name not in INITIAL_STATE:
                raise ValueError(f"state field {name!r} is not a simulated WB05BR control")
        simulated.validate_state(state)

    def validate_topology(self, device):
        if self.child:
            return
        child_profile = device.profile.id + "-ac"
        for child in device.children:
            if child.profile.id != child_profile or child.mid not in CHILD_MIDS:
                raise ValueError("WB05BR children must match their exact parent firmware profile")
            if (len(child.mac) != 14
                    or any(character not in "0123456789abcdef" for character in child.mac)):
                raise ValueError("WB05BR children require complete seven-byte hexadecimal identities")

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        # shortcut: no calibrated gateway sensor, add one only with exact-source proof.
        return None

    def advertise(self, device, outer):
        if self.child:
            return []
        # json_create_dev lists these fields, not W06's extra brand/cid/hid.
        inner = {"t": "dev", "bc": "", "catalog": "gree", "series": "gree",
                 "model": "gree", "lock": 0, "vender": "1", "mid": device.mid,
                 "name": device.name, "ver": "V3.2.M", "mac": device.mac,
                 "subCnt": len(device.children)}
        return [_reply(device, {"i": 1, "cid": "", "uid": 0}, inner)]

    def handle(self, device, outer):
        if self.child:
            return []
        if outer.get("tcid") != device.mac:
            raise InvalidPacket("wrong WB05BR outer target")
        index, uid, peer = outer.get("i"), outer.get("uid"), outer.get("cid")
        if type(index) is not int or index not in (0, 1):
            raise InvalidPacket("invalid WB05BR key slot")
        if type(uid) is not int or not -(2**31) <= uid < 2**31:
            raise InvalidPacket("invalid WB05BR uid")
        if not isinstance(peer, str) or len(peer.encode()) > 14 or "\0" in peer:
            raise InvalidPacket("invalid WB05BR peer identity")
        if outer.get("t") == "subList":
            # The direct dispatcher does not inspect/decrypt any pack member.
            inner = outer
        elif outer.get("t") == "pack":
            inner = decode_pack(outer, GENERIC_KEY if index else device.key, CODEC)
        else:
            raise InvalidPacket("unsupported WB05BR envelope")
        kind = inner.get("t")
        if kind == "bind":
            if index != 1 or inner.get("mac") != device.mac:
                raise InvalidPacket("WB05BR bind requires root identity and generic slot")
            return [_reply(device, outer, {"t": "bindOk", "r": 200,
                                           "mac": device.mac, "key": device.key.decode("ascii")}, 1)]
        if kind in ("subList", "subDev"):
            offset = inner.get("i")
            if type(offset) is not int or not 0 <= offset < 2**31:
                raise InvalidPacket("WB05BR list requires a nonnegative integer child offset")
            # Safe boundary: do not reproduce native substring/unchecked cache matching.
            if "mac" in inner and inner["mac"] != device.mac:
                raise InvalidPacket("wrong WB05BR list identity")
            entries = [{"mac": child.mac, "mid": child.mid}
                       for child in device.children[offset:offset + 5]]
            return [_reply(device, outer, {"t": "subList", "i": offset,
                                           "c": len(device.children), "r": 200, "list": entries})]
        if kind == "status":
            if index != 0:
                raise InvalidPacket("WB05BR status requires device key slot")
            identity = inner.get("mac")
            target = device if identity == device.mac else _child(device, identity)
            columns = _columns(inner.get("cols"))
            metadata = {"mac": device.mac, "mid": device.mid, "hid": device.profile.hid,
                        "name": device.name, "ver": "V3.2.M", "vender": "1",
                        "bc": "", "catalog": "gree", "series": "gree", "model": "gree",
                        "lock": 0, "subCnt": len(device.children)}
            # Mainboard callbacks are replaced only by the declared sensorless cache.
            available = {**metadata, **target.state}
            return [_reply(device, outer, {"t": "dat", "mac": target.mac, "cols": columns,
                                           "dat": [available.get(name, "") for name in columns], "r": 200})]
        if kind == "cmd":
            if index != 0:
                raise InvalidPacket("WB05BR command requires device key slot")
            identity = inner.get("sub", inner.get("mac"))
            target = _child(device, identity)
            if "sub" in inner and inner.get("mac", device.mac) not in (device.mac, target.mac):
                raise InvalidPacket("conflicting WB05BR command identity")
            names, values = _columns(inner.get("opt")), inner.get("p")
            if (not names or not isinstance(values, list) or len(names) != len(values)
                    or any(name not in INITIAL_STATE for name in names)):
                raise InvalidPacket("WB05BR command requires modeled opt and p arrays")
            reply = _reply(device, outer, {"t": "res", "mac": target.mac, "opt": names,
                                           "p": values, "val": values, "r": 200})
            if len(encode_reply(reply)) > 65507:
                raise InvalidPacket("WB05BR response exceeds the UDP payload limit")
            simulated.apply_command(target, names, values)
            return [reply]
        return []


PROFILES = tuple(
    profile
    for version, code, sha256 in BUILDS
    for profile in (
        Profile(id=f"sim-wb05br-v{version}", mids=("60",),
                hid=f"{code}+U-WB05BRV{version}.bin", source_sha256=sha256,
                initial_state={}, handler=WBGatewayFamily(), max_children=100),
        Profile(id=f"sim-wb05br-v{version}-ac", mids=CHILD_MIDS,
                hid=f"{code}+U-WB05BRV{version}.bin", source_sha256=sha256,
                initial_state=INITIAL_STATE, handler=WBGatewayFamily(child=True),
                identity_bytes=7, parent_profiles=(f"sim-wb05br-v{version}",)),
    )
)
