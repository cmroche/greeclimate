"""WB04AV1.49 LAN framing with explicitly synthetic AC controls and temperature."""

import json

from ..wire import InvalidPacket, Reply, decode_pack
from . import Profile, simulated


HID = "362001062295+U-WB04AV1.49.bin"
SOURCE_SHA256 = "0d5ee6fda1678084e1fa29e6267941afae304090b5b97f7b4264f9cee7fd461b"
GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7-nul-input"
# Exact source table 0x10000a38 intersected with the shared simulation controls.
CONTROLS = frozenset("""
Pow Mod SetTem WdSpd TemUn TemRec Air Blo Health SwhSlp SlpMod Lig SwingLfRig
SwUpDn Quiet Tur StHt SvSt Buzzer_ON_OFF
""".split())
INITIAL_STATE = {name: value for name, value in simulated.INITIAL_STATE.items()
                 if name in CONTROLS}


def _metadata(device):
    return {"hid": HID, "mid": device.mid, "ver": "V3.0.0", "vender": "2",
            "name": device.name, "bc": "00000", "host": ""}


def _reply(device, inner, index, uid=0, peer="", *, scan=False):
    outer = {"t": "pack", "i": index, "uid": uid,
             "cid": "" if scan else device.mac, "tcid": peer}
    plain_size = len(json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode())
    cipher_size = 16 * (plain_size // 16 + 1)
    outer_size = len(json.dumps({**outer, "pack": ""}, ensure_ascii=False,
                                separators=(",", ":")).encode())
    if outer_size + 4 * ((cipher_size + 2) // 3) >= 1460:
        raise InvalidPacket("WB reply exceeds the firmware packet buffer")
    return Reply(outer, inner, GENERIC_KEY if index else device.key, CODEC)


class WB04A:
    def validate_state(self, state):
        for name in state:
            if not name.startswith("_") and name not in CONTROLS:
                raise ValueError(f"unsupported WB state field {name!r}")
        simulated.validate_state(state)

    def thermal_target(self, device):
        return simulated.thermal_target(device)

    def encode_room(self, device):
        simulated.encode_room(device, 40, 255)

    def advertise(self, device, outer):
        inner = {"t": "dev", "cid": "", "bc": "00000", "brand": "gree",
                 "catalog": "gree", "mac": device.mac, "mid": device.mid,
                 "model": "gree", "name": device.name, "lock": 0,
                 "series": "gree", "vender": "2", "ver": "V3.0.0", "hid": HID}
        return [_reply(device, inner, 1, scan=True)]

    def handle(self, device, outer):
        if outer.get("tcid") != device.mac:
            raise InvalidPacket("wrong WB target")
        index = outer.get("i")
        if type(index) is not int or index not in (0, 1):
            raise InvalidPacket("invalid WB key selector")
        inner = decode_pack(outer, GENERIC_KEY if index else device.key, CODEC)
        for selector in ("mac", "sub"):
            if selector in inner and inner[selector] != device.mac:
                raise InvalidPacket("conflicting WB inner identity")
        uid, peer = outer.get("uid", 0), outer.get("cid", "")
        if type(uid) is not int or not isinstance(peer, str):
            raise InvalidPacket("invalid WB reply route")
        kind = inner.get("t")
        if kind == "bind":
            if inner.get("mac") != device.mac:
                raise InvalidPacket("missing WB bind identity")
            return [_reply(device, {"r": 200, "t": "bindok", "mac": device.mac,
                                    "key": device.key.decode("ascii")}, 1, uid, peer)]
        if kind == "status":
            columns = inner.get("cols")
            if (not isinstance(columns, list) or len(columns) > 32
                    or any(not isinstance(name, str) or not name
                           or len(name.encode()) >= 32 for name in columns)):
                raise InvalidPacket("invalid WB status columns")
            # Unmodelled fields are omitted, not fabricated from the UART cache.
            values = {**_metadata(device), **{name: value for name, value in device.state.items()
                                              if name in CONTROLS or name == "TemSen"}}
            selected = [name for name in columns if name in values]
            return [_reply(device, {"t": "dat", "uid": 0, "mac": device.mac,
                                    "cid": device.mac, "dat": [values[name] for name in selected],
                                    "cols": selected, "r": 200}, 0, uid, peer)]
        if kind == "cmd":
            options, values = inner.get("opt"), inner.get("p")
            if (not isinstance(options, list) or len(options) > 32
                    or any(not isinstance(name, str) or name not in CONTROLS for name in options)):
                raise InvalidPacket("unsupported WB command field")
            reply = _reply(device, {"t": "res", "mac": device.mac,
                                    "p": values, "opt": options, "r": 200}, 0, uid, peer)
            simulated.apply_command(device, options, values)
            return [reply]
        return []


HANDLER = WB04A()
PROFILES = (Profile(id="sim-wb04a-v1.49", mids=("10f05", "10010", "10011", "11011", "11012"),
                    hid=HID, source_sha256=SOURCE_SHA256,
                    initial_state=INITIAL_STATE, handler=HANDLER, max_request_bytes=1460),)
