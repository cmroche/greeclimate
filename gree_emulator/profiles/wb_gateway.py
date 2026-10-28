"""Exact WB05BR LAN category models with synthetic, uncalibrated tuple reports.

Only608f/605c are prior physically observed child MIDs; other category presets
are source-qualified configured/emitted synthetic roles, not observed devices.
"""

from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile
from .wb_adr import (FILTER_MIDS, category_state, command_values, commit_state,
                     emitted_mid, raw_value, reported_state, stage_command)
from .wb_catalog import BUILD_SCHEMAS
from .wb_root import root_command, root_state, root_value


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


def _key(device, index, state=None):
    state = device.state.get("_wb_root") if state is None else state
    if state is not None:
        return state["key"][index].encode("ascii")
    return GENERIC_KEY if index == 1 else device.key


def _reply(device, outer, inner, index=None, state=None):
    index = outer["i"] if index is None else index
    return Reply({"t": "pack", "cid": device.mac, "tcid": outer["cid"],
                  "uid": outer["uid"], "i": index}, inner,
                 _key(device, index, state), CODEC)


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
    build = "BR"

    def __init__(self, version, child=False, category=None):
        self.child = child
        self.version = version
        self.category = category
        self.schema = BUILD_SCHEMAS[version][category] if child else None
        self.categories = BUILD_SCHEMAS[version]
        self.boolean_half_degree = version in ("1.13", "1.16", "1.18", "1.22")
        self.unit_conversion = version not in ("1.13", "1.16", "1.18")
        self.mode_preserves_power = version in ("1.16", "1.18")

    def validate_state(self, state):
        expected = category_state("BR", self.category, self.schema) if self.child else {}
        if state != expected:
            raise ValueError("WB raw reports cannot be configured as LAN controls")

    def validate_topology(self, device):
        if self.child:
            return
        allowed = tuple(device.profile.id + "-" + role for role in
                        ("ac", "filter", "water", "energy") if
                        {"water": "water_floor"}.get(role, role) in self.categories)
        for child in device.children:
            if child.profile.id not in allowed or child.mid not in child.profile.mids:
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
        staged = root_state(device, self.version)
        inner = {"t": "dev", **{name: root_value(device, self.version, staged, name)
                               for name in ("bc", "catalog", "series", "model", "lock",
                                            "vender", "mid", "name", "ver", "mac")},
                 "subCnt": len(device.children)}
        reply = _reply(device, {"i": 1, "cid": "", "uid": 0}, inner, state=staged)
        if len(encode_reply(reply)) > 65507:
            raise InvalidPacket("WB05BR response exceeds the UDP payload limit")
        device.state["_wb_root"] = staged
        return [reply]

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
            inner = decode_pack(outer, _key(device, index), CODEC)
        else:
            raise InvalidPacket("unsupported WB05BR envelope")
        kind = inner.get("t")
        if kind == "bind":
            if index != 1 or inner.get("mac") != device.mac:
                raise InvalidPacket("WB05BR bind requires root identity and generic slot")
            return [_reply(device, outer, {"t": "bindok" if not device.children else "bindOk", "r": 200,
                                           "mac": device.mac,
                                           "key": _key(device, 0).decode("ascii")}, 1)]
        if kind in ("subList", "subDev"):
            offset = inner.get("i")
            if type(offset) is not int or not 0 <= offset < 2**31:
                raise InvalidPacket("WB05BR list requires a nonnegative integer child offset")
            # Safe boundary: do not reproduce native substring/unchecked cache matching.
            if "mac" in inner and inner["mac"] != device.mac:
                raise InvalidPacket("wrong WB05BR list identity")
            entries = [{"mac": child.mac,
                        "mid": emitted_mid(child.mid)}
                       for child in device.children[offset:offset + 5]]
            return [_reply(device, outer, {"t": "subList", "i": offset,
                                           "c": len(device.children), "r": 200, "list": entries})]
        if kind in ("status", "dat"):
            if index != 0:
                raise InvalidPacket("WB05BR status requires device key slot")
            identity = inner.get("mac")
            target = device if identity == device.mac else _child(device, identity)
            columns = _columns(inner.get("cols"))
            if target is device:
                staged = root_state(device, self.version)
                dat = [root_value(device, self.version, staged, name) for name in columns]
                reply = _reply(device, outer, {"t": "dat", "mac": device.mac,
                                               "cols": columns, "dat": dat, "r": 200},
                               state=staged)
                if len(encode_reply(reply)) > 65507:
                    raise InvalidPacket("WB05BR response exceeds the UDP payload limit")
                device.state["_wb_root"] = staged
                return [reply]
            if kind == "dat":
                return []
            metadata = {"mac": device.mac, "mid": device.mid, "hid": device.profile.hid,
                        "name": device.name, "ver": "V3.2.M", "vender": "1",
                        "bc": "", "catalog": "gree", "series": "gree", "model": "gree",
                        "lock": 0, "subCnt": len(device.children)}
            staged = reported_state(device, target)
            dat = [metadata[name] if name in metadata else raw_value(target, name, staged)
                   if target is not device else "" for name in columns]
            reply = _reply(device, outer, {"t": "dat", "mac": target.mac, "cols": columns,
                                           "dat": dat, "r": 200})
            if len(encode_reply(reply)) > 65507:
                raise InvalidPacket("WB05BR response exceeds the UDP payload limit")
            commit_state(device, target, staged)
            return [reply]
        if kind in ("cmd", "res"):
            if index != 0:
                raise InvalidPacket("WB05BR command requires device key slot")
            identity = inner.get("sub", inner.get("mac"))
            if identity == device.mac:
                names, values = _columns(inner.get("opt")), inner.get("p")
                if not isinstance(values, list) or len(names) != len(values):
                    raise InvalidPacket("WB05BR command requires matching opt and p arrays")
                staged = root_state(device, self.version)
                child_states = {}
                effective = root_command(device, self.version, staged, names, values, child_states)
                reply = _reply(device, outer, {"t": "res", "mac": device.mac,
                                               "opt": names, "p": values,
                                               "val": effective, "r": 200}, state=staged)
                if len(encode_reply(reply)) > 65507:
                    raise InvalidPacket("WB05BR response exceeds the UDP payload limit")
                device.state["_wb_root"] = staged
                for child in device.children:
                    if child.mac in child_states:
                        commit_state(device, child, child_states[child.mac])
                if "_shared" in child_states:
                    device.state["_wb_shared"] = child_states["_shared"]
                return [reply]
            target = _child(device, identity)
            if "sub" in inner and inner.get("mac", device.mac) not in (device.mac, target.mac):
                raise InvalidPacket("conflicting WB05BR command identity")
            names, values = _columns(inner.get("opt")), inner.get("p")
            if not names or not isinstance(values, list) or len(names) != len(values):
                raise InvalidPacket("WB05BR command requires matching opt and p arrays")
            staged = stage_command(target, names, values, device.state.get("_wb_shared"))
            reply = _reply(device, outer, {"t": "res", "mac": target.mac, "opt": names,
                                           "p": values,
                                           "val": command_values(target, names, values),
                                           "r": 200})
            if len(encode_reply(reply)) > 65507:
                raise InvalidPacket("WB05BR response exceeds the UDP payload limit")
            commit_state(device, target, staged)
            return [reply]
        return []


PROFILES = tuple(
    profile
    for version, code, sha256 in BUILDS
    for profile in (
        Profile(id=f"sim-wb05br-v{version}", mids=("60",),
                hid=f"{code}+U-WB05BRV{version}.bin", source_sha256=sha256,
                initial_state={}, handler=WBGatewayFamily(version), max_children=100),
        *tuple(
            Profile(id=f"sim-wb05br-v{version}-" + suffix, mids=mids,
                    hid=f"{code}+U-WB05BRV{version}.bin", source_sha256=sha256,
                    initial_state=category_state("BR", category, BUILD_SCHEMAS[version][category]),
                    handler=WBGatewayFamily(version, child=True, category=category),
                    identity_bytes=7, parent_profiles=(f"sim-wb05br-v{version}",))
            for suffix, mids, category in (
                ("ac", CHILD_MIDS, "ac"), ("filter", FILTER_MIDS, "filter"),
                ("water", ("6036",), "water_floor"), ("energy", ("6083", "6094"), "energy"))
            if category in BUILD_SCHEMAS[version]
        ),
    )
)
