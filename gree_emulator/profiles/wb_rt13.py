"""WB05RT13 standalone LAN dialect with an explicitly synthetic AC/mainboard.

UDP uses authenticated GCM; discovery alone uses the separate ECB wrapper.
The source transports TemSen's unsigned UART byte unchanged. Celsius+40 below
is a chosen common-UART simulation policy, not same-mainboard calibration.
"""

import json

from ..wire import InvalidPacket, Reply, decode_pack
from . import Profile, simulated


SCAN_KEY = b"a3K8Bx%2r8Y7#xDh"
GENERIC_KEY = b"{yxAHAY_Lm6pbC/<"
CODEC = "aes-gcm"
CONTROLS = frozenset("""
Pow Mod SetTem WdSpd TemUn TemRec Air Blo Health SwhSlp SlpMod Lig SwingLfRig
SwUpDn Quiet Tur StHt SvSt Buzzer_ON_OFF
""".split())
INITIAL_STATE = {name: value for name, value in simulated.INITIAL_STATE.items()
                 if name in CONTROLS}
BUILDS = (
    ("1.45", "2f12c03c97e4e7302acbc8ee72cda18e31e7d9843519d5a3fb1bdcb1a4f2ffec", 1460),
    ("1.54", "86799311e40abaa97be624e11d8e16c45cafb7dd113b8b690728d075d77c8a39", 1536),
    ("1.64", "c4b744a28a5a6b2d2d7ace4a0a2845a336ce629a72367af41bde708f0bd1dbc1", 1536),
)


def _metadata(device):
    # Mainboard-supplied fields use explicit synthetic values, not firmware defaults.
    return {"hid": device.profile.hid, "mid": device.mid, "ver": "V3.4.M",
            "vender": "1", "name": device.name, "bc": "0000000000000",
            "host": "", "ModelType": "0", "lock": 0}


def _reply(device, inner, index, uid, peer):
    # All three builds stage authenticated output in a 1000-byte scratch buffer.
    if len(json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode()) >= 1000:
        raise InvalidPacket("WB05RT13 reply exceeds the firmware scratch buffer")
    return Reply({"t": "pack", "i": index, "uid": uid,
                  "cid": device.mac, "tcid": peer}, inner,
                 GENERIC_KEY if index else device.key, CODEC)


def _columns(value):
    # Reject unsafe native buffer overflow rather than reproducing memory corruption.
    if (not isinstance(value, list) or len(value) > 64
            or any(not isinstance(name, str) or not name or "\0" in name for name in value)
            or sum(len(name.encode()) + 1 for name in value) >= 512):
        raise InvalidPacket("invalid WB05RT13 property array")
    return value


class WB05RT13:
    def validate_state(self, state):
        if any(name not in CONTROLS for name in state):
            raise ValueError("unsupported WB05RT13 simulated control")
        simulated.validate_state(state)

    def thermal_target(self, device):
        return simulated.thermal_target(device)

    def encode_room(self, device):
        simulated.encode_room(device, 40, 255)

    def advertise(self, device, outer):
        metadata = _metadata(device)
        inner = {"t": "dev", "cid": device.mac, "bc": metadata["bc"],
                 "brand": "gree", "catalog": "gree", "mac": device.mac,
                 "mid": device.mid, "model": "gree", "name": device.name,
                 "lock": 0, "series": "gree", "vender": metadata["vender"],
                 "ver": metadata["ver"], "ModelType": metadata["ModelType"],
                 "hid": device.profile.hid}
        return [Reply({"t": "pack", "i": 1, "uid": 0, "cid": "", "tcid": ""},
                      inner, SCAN_KEY, "aes-ecb-pkcs7")]

    def handle(self, device, outer):
        if outer.get("t") != "pack" or outer.get("tcid") != device.mac:
            raise InvalidPacket("wrong WB05RT13 target")
        index = outer.get("i")
        uid, peer = outer.get("uid", 0), outer.get("cid", "")
        if (type(index) is not int or index not in (0, 1)
                or type(uid) is not int or not isinstance(peer, str)):
            raise InvalidPacket("invalid WB05RT13 key selector or route")
        inner = decode_pack(outer, GENERIC_KEY if index else device.key, CODEC)
        for selector in ("mac", "sub"):
            if selector in inner and inner[selector] != device.mac:
                raise InvalidPacket("conflicting WB05RT13 inner identity")
        kind = inner.get("t")
        if kind == "bind":
            return [_reply(device, {"r": 200, "t": "bindok", "mac": device.mac,
                                    "key": device.key.decode("ascii")}, index, uid, peer)]
        if kind == "status":
            columns = _columns(inner.get("cols", inner.get("opt")))
            values = {**_metadata(device), **device.state}
            selected = [name for name in columns if name in values and not name.startswith("_")]
            return [_reply(device, {"t": "dat", "uid": 0, "mac": device.mac,
                                    "cid": device.mac, "dat": [values[name] for name in selected],
                                    "cols": selected, "r": 200}, index, uid, peer)]
        if kind == "cmd":
            options = _columns(inner.get("cols", inner.get("opt")))
            values = inner.get("p")
            if any(name not in CONTROLS for name in options):
                raise InvalidPacket("unsupported WB05RT13 simulated command field")
            reply = _reply(device, {"t": "res", "mac": device.mac,
                                    "p": values, "opt": options, "r": 200}, index, uid, peer)
            # Atomic immediate control/readback is model policy, not a UART confirmation.
            simulated.apply_command(device, options, values)
            return [reply]
        return []


HANDLER = WB05RT13()
PROFILES = tuple(Profile(id=f"sim-wb05rt13-v{version}", mids=("10001",),
                         hid=f"362001065279+U-WB05RT13V{version}.bin", source_sha256=sha,
                         initial_state=INITIAL_STATE, handler=HANDLER,
                         max_request_bytes=limit)
                 for version, sha, limit in BUILDS)
