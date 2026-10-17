"""Exact W04HB V1.20 LAN framing with sensorless synthetic appliance controls."""

import json

from ..wire import InvalidPacket, Reply, decode_pack
from . import Profile, simulated

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
HID = "362001063384+U-W04HBV1.20.bin"
SOURCE_SHA256 = "5a4705122e69dfb99462fdeef1d19e8b7ce7315d6cdad895849c87ef0cfdfea8"
CONTROL_FIELDS = frozenset((
    "Pow Blo SwhSlp Air SvSt Quiet Tur HeatCoolType Mod SetTem HeatSvStTemMax "
    "CoolSvStTemMin WdSpd SwUpDn SwingLfRig AllErr TemUn TemRec SlpMod TemRecH "
    "TemRecC WifiOff WifiRest AutoSetTem RemoteLock APPNotCtrl LowDeHumi Omod "
    "Demand Tcloud AppTimer ElcErg ElcGear Elc1Kwh AutoUpdate AutoComnCloud lock"
).split())


def _reply(device, inner, index, uid, peer):
    if len(json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode()) >= 1024:
        raise InvalidPacket("W04HB reply exceeds firmware buffer")
    return Reply({"t": "pack", "i": index, "uid": uid, "cid": device.mac, "tcid": peer},
                 inner, GENERIC_KEY if index else device.key, CODEC)


class W04HB:
    def validate_state(self, state):
        simulated.validate_state(state)

    def thermal_target(self, device):
        return simulated.thermal_target(device)

    def encode_room(self, device):
        # This build exposes no room-temperature property; internal Celsius stays internal.
        return None

    def advertise(self, device, outer):
        inner = {"t": "dev", "cid": "", "bc": "gree", "catalog": "gree", "mid": device.mid,
                 "lock": 0, "model": "gree", "name": device.name, "series": "gree",
                 "vender": "", "ver": "", "brand": "gree", "mac": device.mac}
        return [_reply(device, inner, 1, device.state["_uid"], device.state["_peer"])]

    def handle(self, device, outer):
        if outer.get("tcid") != device.mac or type(outer.get("i")) is not int:
            raise InvalidPacket("invalid W04HB target or key selector")
        inner = decode_pack(outer, GENERIC_KEY if outer["i"] else device.key, CODEC)
        for selector in ("mac", "sub"):
            if selector in inner and inner[selector] != device.mac:
                raise InvalidPacket("conflicting W04HB identity")
        uid, peer = outer.get("uid", device.state["_uid"]), outer.get("cid", device.state["_peer"])
        kind = inner.get("t")
        if kind == "bind":
            if inner.get("mac") != device.mac:
                raise InvalidPacket("missing W04HB bind identity")
            reply = _reply(device, {"t": "bindok", "mac": device.mac, "r": 200,
                                    "key": device.key.decode("ascii")}, 1, uid, peer)
        elif kind == "status":
            columns = inner.get("cols")
            if not isinstance(columns, list) or len(columns) > 30 or any(not isinstance(name, str) for name in columns):
                raise InvalidPacket("invalid W04HB status columns")
            requested = []
            for name in columns:
                if not name or len(name.encode()) >= 16:
                    break
                requested.append(name)
            if len(requested) == 30:
                requested.clear()
            values = {name: value for name, value in device.state.items() if name in CONTROL_FIELDS}
            selected = [name for name in requested if name in values]
            reply = _reply(device, {"t": "dat", "mac": device.mac, "r": 200,
                                    "cols": selected, "dat": [values[name] for name in selected]}, 0, uid, peer)
        elif kind == "cmd":
            names, values = inner.get("opt"), inner.get("p")
            if not isinstance(names, list) or not isinstance(values, list) or len(names) != len(values) or len(names) > 30:
                raise InvalidPacket("invalid W04HB command arrays")
            if any(not isinstance(name, str) or name not in CONTROL_FIELDS for name in names):
                raise InvalidPacket("unsupported W04HB model command")
            reply = _reply(device, {"t": "res", "mac": device.mac, "r": 200, "opt": names, "p": values}, 0, uid, peer)
            simulated.apply_command(device, names, values)
        else:
            return []
        device.state["_uid"], device.state["_peer"] = uid, peer
        return [reply]


HANDLER = W04HB()
PROFILES = (Profile(id="sim-w04hb-v1.20", mids=("302b",), hid=HID, source_sha256=SOURCE_SHA256,
                    initial_state={**{name: value for name, value in simulated.INITIAL_STATE.items()
                                      if name in CONTROL_FIELDS}, "_uid": 0, "_peer": "app"},
                    handler=HANDLER, max_request_bytes=1024),)
