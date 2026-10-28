"""Exact W04HB V1.20 LAN framing and complete named uint16 control cache."""

from copy import deepcopy
from datetime import datetime, timedelta
import json
from time import monotonic

from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile, simulated

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
HID = "362001063384+U-W04HBV1.20.bin"
SOURCE_SHA256 = "5a4705122e69dfb99462fdeef1d19e8b7ce7315d6cdad895849c87ef0cfdfea8"
CONTROL_FIELDS = frozenset((
    "Pow Blo SwhSlp Air SvSt Quiet Tur HeatCoolType Mod SetTem HeatSvStTemMax "
    "CoolSvStTemMin WdSpd SwUpDn SwingLfRig AllErr TemUn TemRec SlpMod TemRecH "
    "TemRecC WifiOff WifiRest AutoSetTem RemoteLock APPNotCtrl LowDeHumi Omod "
    "Demand Tcloud AppTimer ElcErg ElcGear Elc1Kwh AutoUpdate AutoComnCloud lock No"
).split())
METADATA_FIELDS = (
    "apssid", "appsw", "host", "name", "time", "lat", "lon", "rssi",
    "vender", "bc", "mid", "model", "series", "brand", "catalog", "country",
    "hid", "mac", "ver", "HidSvrVer", "InHid", "InHidSvrVer",
    "OEEPHid", "OEEPHidSvrVer",
)
TEXT_CONTROLS = {"apssid": 32, "appsw": 32, "host": 20, "name": 100,
                 "time": 19, "lat": 10, "lon": 10}


def _runtime(device, state, now):
    if "_runtime" not in state:
        state["_runtime"] = {
            "name": device.name, "host": "", "lat": "", "lon": "",
            "clock": "2026-01-01 00:00:00", "clock_origin": now,
        }
    return state["_runtime"]


def _metadata(device, runtime, now):
    try:
        calendar = datetime.strptime(runtime["clock"], "%Y-%m-%d %H:%M:%S")
        calendar += timedelta(seconds=int(now - runtime["clock_origin"]))
    except (ValueError, OverflowError) as exc:
        raise InvalidPacket("W04HB synthetic calendar is out of range") from exc
    values = dict.fromkeys(METADATA_FIELDS, ())
    values.update({"name": (runtime["name"],), "host": (runtime["host"],),
                   "lat": (runtime["lat"],), "lon": (runtime["lon"],),
                   "hid": (HID,), "mac": (device.mac,), "mid": ("",),
                   "vender": ("",), "bc": ("",), "ver": ("",),
                   "time": (f"{calendar.year}-{calendar:%m-%d %H:%M:%S}",), "rssi": (0,)})
    return values



def _reply(device, inner, index, uid, peer):
    if len(json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode()) >= 1024:
        raise InvalidPacket("W04HB reply exceeds firmware buffer")
    reply = Reply({"t": "pack", "i": index, "uid": uid, "cid": device.mac, "tcid": peer},
                  inner, GENERIC_KEY if index else device.key, CODEC)
    encode_reply(reply)
    return reply


class W04HB:
    def validate_state(self, state):
        for name, value in state.items():
            if name.startswith("_"):
                continue
            if name not in CONTROL_FIELDS or type(value) is not int or not 0 <= value <= 65535:
                raise ValueError("W04HB state requires named unsigned16 control values")

    def thermal_target(self, device):
        return simulated.thermal_target(device)

    def encode_room(self, device):
        # This build exposes no room-temperature property; internal Celsius stays internal.
        return None

    def advertise(self, device, outer):
        inner = {"t": "dev", "cid": "", "bc": "gree", "catalog": "gree", "mid": device.mid,
                 "lock": 0, "model": "gree",
                 "name": device.state.get("_runtime", {}).get("name", device.name), "series": "gree",
                 "vender": "", "ver": "", "brand": "gree", "mac": device.mac}
        return [_reply(device, inner, 1, device.state["_uid"], device.state["_peer"])]

    def handle(self, device, outer):
        if (outer.get("t") != "pack" or outer.get("tcid") != device.mac
                or type(outer.get("i")) is not int
                or not -(1 << 31) <= outer["i"] < (1 << 31)):
            raise InvalidPacket("invalid W04HB target or key selector")
        inner = decode_pack(outer, GENERIC_KEY if outer["i"] else device.key, CODEC)
        for selector in ("mac", "sub"):
            if selector in inner and inner[selector] != device.mac:
                raise InvalidPacket("conflicting W04HB identity")
        uid, peer = outer.get("uid", device.state["_uid"]), outer.get("cid", device.state["_peer"])
        if (type(uid) is not int or not -(1 << 31) <= uid < (1 << 31)
                or not isinstance(peer, str) or len(peer.encode()) >= 20 or "\0" in peer):
            raise InvalidPacket("invalid W04HB peer route")
        candidate = deepcopy(device.state)
        now = monotonic()
        runtime = _runtime(device, candidate, now)
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
                if not name or len(name.encode()) >= 16 or "\0" in name:
                    break
                requested.append(name)
            if len(requested) == 30:
                requested.clear()
            values = {name: (candidate[name],) for name in CONTROL_FIELDS}
            values.update(_metadata(device, runtime, now))
            selected = [name for name in requested if name in values]
            reply = _reply(device, {"t": "dat", "mac": device.mac, "r": 200,
                                    "cols": selected,
                                    "dat": [item for name in selected for item in values[name]]}, 0, uid, peer)
        elif kind == "cmd":
            names, values = inner.get("opt"), inner.get("p")
            if not isinstance(names, list) or not isinstance(values, list) or len(names) != len(values) or len(names) > 30:
                raise InvalidPacket("invalid W04HB command arrays")
            for name, value in zip(names, values):
                if isinstance(name, str) and name in CONTROL_FIELDS:
                    if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
                        raise InvalidPacket("W04HB raw controls require signed32 integers")
                    candidate[name] = value & 65535
                elif isinstance(name, str) and name in TEXT_CONTROLS:
                    if (not isinstance(value, str) or "\0" in value
                            or len(value.encode()) > TEXT_CONTROLS[name]
                            or (not value and name not in ("name", "appsw"))):
                        raise InvalidPacket("invalid W04HB metadata string")
                    if name == "time":
                        try:
                            calendar = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
                        except ValueError as exc:
                            raise InvalidPacket("invalid W04HB calendar") from exc
                        runtime["clock"], runtime["clock_origin"] = calendar.strftime("%Y-%m-%d %H:%M:%S"), now
                    elif name != "appsw":
                        runtime[name] = value
                else:
                    raise InvalidPacket("unsupported W04HB control")
            reply = _reply(device, {"t": "res", "mac": device.mac, "r": 200, "opt": names, "p": values}, 0, uid, peer)
        else:
            return []
        candidate["_uid"], candidate["_peer"] = uid, peer
        device.advance(now)
        device.state = candidate
        return [reply]


HANDLER = W04HB()
PROFILES = (Profile(id="sim-w04hb-v1.20", mids=("3018", "302b"), hid=HID, source_sha256=SOURCE_SHA256,
                    initial_state={**dict.fromkeys(CONTROL_FIELDS, 0), "SetTem": 24,
                                   "_uid": 0, "_peer": "app"},
                    handler=HANDLER, max_request_bytes=1024),)
