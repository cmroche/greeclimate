"""W06DV4.01 LAN framing with synthetic controls and no advertised thermometer."""

from time import monotonic

from ..wire import InvalidPacket, decode_pack
from . import Profile, simulated
from .gateway import CODEC, GENERIC_KEY, _reply

HID = "362001067592+U-W06DV4.01.bin"
SOURCE_SHA256 = "eabd04d49c518699f2800805bd4f6085ff3b2092b8a2394fb1e22c04fb7f7c9f"
# Scalar selector0xa10c68 intersected with the approved synthetic controls.
CONTROL_FIELDS = frozenset((
    "Pow", "Blo", "SwhSlp", "Air", "SvSt", "Quiet", "Tur", "Mod", "SetTem",
    "WdSpd", "SwUpDn", "SwingLfRig", "TemUn", "TemRec", "SlpMod",
))
INITIAL_STATE = {name: value for name, value in simulated.INITIAL_STATE.items()
                 if name in CONTROL_FIELDS}


def _fields(value):
    if (not isinstance(value, list) or len(value) > 49
            or any(not isinstance(name, str) or not name or len(name.encode()) >= 16
                   for name in value)):
        raise InvalidPacket("controller requires at most49 fields shorter than16 bytes")
    return value


def _metadata(device):
    return {"mac": device.mac, "mid": device.mid, "hid": HID, "name": device.name,
            "vender": "1", "ver": "V1.0.0.0", "bc": "", "host": "", "lock": 0}


class ControllerFamily:
    def validate_state(self, state):
        for name in state:
            if name not in CONTROL_FIELDS:
                raise ValueError(f"state field {name!r} is not a simulated controller control")
        simulated.validate_state(state)
        if state.get("Quiet", 0) not in (0, 1):
            raise ValueError("state field 'Quiet' must be an integer in0..1")

    thermal_target = staticmethod(simulated.thermal_target)

    def encode_room(self, device):
        # No ambient scalar selector exists; synthetic room temperature stays internal.
        pass

    def advertise(self, device, outer):
        inner = {"t": "dev", "cid": device.mac, "bc": "gree", "brand": "gree",
                 "catalog": "gree", "mac": device.mac, "mid": device.mid, "hid": HID,
                 "model": "gree", "name": device.name, "series": "gree",
                 "vender": "1", "ver": "V1.0.0.0", "lock": 0}
        return [_reply(device, inner, 1, 0, "")]

    def handle(self, device, outer):
        if outer.get("tcid") != device.mac or len(outer) > 20:
            raise InvalidPacket("invalid controller target or envelope")
        index, uid, peer = outer.get("i"), outer.get("uid"), outer.get("cid")
        if type(index) is not int or not 0 <= index < 2**31:
            raise InvalidPacket("missing controller key selector")
        if type(uid) is not int or not -(2**31) <= uid < 2**31:
            raise InvalidPacket("missing controller uid")
        if not isinstance(peer, str) or len(peer.encode()) >= 20:
            raise InvalidPacket("missing controller cid")
        pack = outer.get("pack")
        if not isinstance(pack, str) or len(pack) >= 700:
            raise InvalidPacket("controller encrypted request exceeds firmware buffer")
        inner = decode_pack(outer, GENERIC_KEY if index else device.key, CODEC)
        if len(inner) > 20:
            raise InvalidPacket("controller request has too many fields")
        for selector in ("mac", "sub"):
            if selector in inner and inner[selector] != device.mac:
                raise InvalidPacket("conflicting controller inner identity")
        kind = inner.get("t")
        if kind == "bind":
            if inner.get("mac") != device.mac:
                raise InvalidPacket("wrong controller bind identity")
            return [_reply(device, {"t": "bindok", "mac": device.mac,
                                    "key": device.key.decode("ascii"), "r": 200}, 1, uid, peer)]
        if kind not in ("status", "cmd"):
            return []
        if index:
            raise InvalidPacket("controller controls require the bound key")
        if kind == "status":
            if inner.get("mac") != device.mac:
                raise InvalidPacket("wrong controller status identity")
            columns = _fields(inner.get("cols"))
            available = {**_metadata(device), **device.state}
            selected = [name for name in columns if name in available]
            reply = _reply(device, {"t": "dat", "r": 200, "mac": device.mac,
                                    "cols": selected, "dat": [available[name] for name in selected]},
                           0, uid, peer)
            device.advance(monotonic())
            return [reply]
        names, values = _fields(inner.get("opt")), inner.get("p")
        if (not isinstance(values, list) or not names or len(names) != len(values)
                or any(name not in CONTROL_FIELDS for name in names)):
            raise InvalidPacket("controller command requires modeled opt and p arrays")
        if any(name == "Quiet" and (type(value) is not int or value not in (0, 1))
               for name, value in zip(names, values)):
            raise InvalidPacket("controller Quiet must be0 or1")
        reply = _reply(device, {"t": "res", "r": 200, "opt": names,
                                "p": values, "val": values}, 0, uid, peer)
        simulated.apply_command(device, names, values)
        return [reply]


PROFILES = (
    Profile(id="sim-w06dv-v4.01", mids=("3018",), hid=HID, source_sha256=SOURCE_SHA256,
            initial_state=INITIAL_STATE, handler=ControllerFamily(), max_request_bytes=1024),
)
