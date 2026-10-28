"""Flat R1 AB/W65/DF/UR raw cache controllers, never calibrated appliances.

The four words absent from AB's table are not inferred from neighboring builds.
Metadata getter storage and numeric setter storage are deliberately separate.
WB UDP discovery uses legacy ECB; original UDP callbacks select GCM for packs.
"""
from copy import deepcopy
import json

from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile
from .catalog_early_frvr import (
    CODEC, GENERIC_KEY, VR_NUMERIC, FrVrController, _fields, _runtime,
)

GCM_GENERIC_KEY = b"{yxAHAY_Lm6pbC/<"

LOCAL = frozenset((
    "time", "name", "lock", "AutoUpdate", "host", "hid", "mid", "bc",
    "DevID", "MafIdf", "AppTimer", "MidType", "BleON", "Mesh", "Unbind",
    "Meshid", "lat", "lon", "ReportClientID", "Onoff", "ModelType",
))
LOCAL_WRITABLE = frozenset((
    "time", "name", "host", "AppTimer", "BleON", "Mesh", "Unbind", "Meshid",
    "lat", "lon", "ReportClientID", "Onoff", "ModelType",
))

def _reply(device, inner, index, uid, peer="", *, discovery=False):
    codec = CODEC if discovery else device.profile.handler.codec
    generic_key = GENERIC_KEY if discovery else device.profile.handler.generic_key
    reply = Reply({"t": "pack", "i": index, "uid": uid,
                   "cid": "" if discovery else device.mac, "tcid": peer}, inner,
                  generic_key if index else device.key, codec)
    plain = json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode()
    encrypted_size = len(plain) if codec == "aes-gcm" else (len(plain) // 16 + 1) * 16
    if encrypted_size > 1024 or len(encode_reply(reply)) > 1460:
        raise InvalidPacket("hybrid response exceeds source packet capacity")
    return reply



class HybridController(FrVrController):
    """Source-evidenced finite raw namespace with safe atomic parser policy."""
    plaintext_types = ("hbok", "tm", "wlan")


    def __init__(self, *, ab=False, wb=False):
        super().__init__(vr=True)
        self.ab = ab
        self.wb = wb
        self.codec = "aes-gcm" if wb else CODEC
        self.generic_key = GCM_GENERIC_KEY if wb else GENERIC_KEY
        table = tuple("NoD" if ab and 199 <= index <= 202 else name
                      for index, name in enumerate(VR_NUMERIC))
        self.ordered_names = table
        self.numeric = frozenset(name for name in table if name)
        self.fields = self.numeric | self.special

    def validate_state(self, state):
        for name, value in state.items():
            if name == "_uid" and type(value) is int and -(1 << 31) <= value < (1 << 31):
                continue
            if (name not in self.numeric or name in LOCAL
                    or type(value) is not int or not 0 <= value <= 65535):
                raise ValueError("hybrid state requires writable uint16 raw cache words")

    def _get(self, device, state, runtime, name):
        if name in ("bc", "ver", "mac", "host") or (self.wb and name == "name"):
            return [""]
        return super()._get(device, state, runtime, name)

    def advertise(self, device, outer):
        inner = {"t": "dev", "cid": "", "bc": "", "brand": "gree",
                 "catalog": "gree", "mac": device.mac, "mid": device.mid,
                 "model": "gree", "name": device.name, "lock": 0,
                 "series": "gree", "vender": "", "ver": ""}
        if not self.ab:
            inner["hid"] = device.profile.hid
        return [_reply(device, inner, 1, 0 if self.wb else device.state["_uid"],
                       discovery=self.wb)]

    def _plaintext(self, device, outer):
        if outer.get("tcid", device.mac) != device.mac:
            raise InvalidPacket("wrong hybrid plaintext target")
        pending = deepcopy(device.state)
        runtime = _runtime(device, pending)
        kind = outer["t"]
        replies = []
        if kind == "hbok":
            runtime["heartbeat_retries"], runtime["heartbeat_pending"] = 0, 0
        elif kind == "tm":
            value = outer.get("time")
            if not isinstance(value, str):
                raise InvalidPacket("hybrid time synchronization requires a calendar string")
            self._set_special(device, pending, runtime, "time", value)
        else:
            network = {}
            for name, bound in (("host", 20), ("ssid", 32), ("psw", 64)):
                value = outer.get(name)
                if not isinstance(value, str) or "\0" in value or len(value.encode()) > bound:
                    raise InvalidPacket("hybrid WLAN requires bounded host/ssid/psw strings")
                network[name] = value
            # Synthetic radio application retains config; no flash or host-network changes.
            runtime["network"] = network
            replies = [Reply({"t": "ret", "r": 200, "mac": ""})]
        device.state.clear()
        device.state.update(pending)
        return replies

    def handle(self, device, outer):
        if outer.get("t") in self.plaintext_types:
            return self._plaintext(device, outer)
        if outer.get("t") != "pack" or outer.get("tcid") != device.mac:
            raise InvalidPacket("wrong hybrid root target")
        index, uid = outer.get("i"), outer.get("uid")
        if (type(index) is not int or index not in (0, 1)
                or type(uid) is not int or not -(1 << 31) <= uid < (1 << 31)
                or not isinstance(outer.get("cid", ""), str)
                or ("tag" in outer) != self.wb):
            raise InvalidPacket("invalid hybrid session envelope")
        peer = outer.get("cid", "") if self.wb else ""
        if "\0" in peer or len(peer.encode()) > 63:
            raise InvalidPacket("hybrid peer identifier exceeds source buffer")
        inner = decode_pack(outer, self.generic_key if index else device.key, self.codec)
        reply_index = index if self.wb else 0
        for selector in ("mac", "sub"):
            if selector in inner and inner[selector] != device.mac:
                raise InvalidPacket("conflicting hybrid inner identity")
        kind = inner.get("t")
        if not isinstance(kind, str) or not kind or "\0" in kind:
            raise InvalidPacket("invalid hybrid request type")
        pending = deepcopy(device.state)
        runtime = _runtime(device, pending)
        if kind == "bind":
            response = {"r": 200, "t": "bindok", "mac": device.mac,
                        "key": device.key.decode("ascii")}
            reply = _reply(device, response, index if self.wb else 1, uid, peer)
        elif kind == "status":
            names = _fields(inner.get("cols"))
            selected, values = [], []
            for name in names:
                if name in self.fields and name not in self.write_only:
                    selected.append(name)
                    values.extend(self._get(device, pending, runtime, name))
            target = inner.get("sub", inner.get("mac", "")) if self.wb else device.mac
            reply = _reply(device, {"t": "dat", "uid": uid, "mac": target,
                                    "cid": device.mac, "dat": values,
                                    "cols": selected, "r": 200}, reply_index, uid, peer)
        elif kind == "cmd":
            names, values = _fields(inner.get("opt")), inner.get("p")
            if not isinstance(values, list) or len(names) != len(values):
                raise InvalidPacket("hybrid requires matching command arrays")
            local, numeric = [], []
            for name, value in zip(names, values):
                if name in LOCAL:
                    if name not in LOCAL_WRITABLE:
                        raise InvalidPacket("hybrid local property has no native setter")
                    if not isinstance(value, str) or "\0" in value:
                        raise InvalidPacket("hybrid local command requires a string scalar")
                    local.append((name, value))
                elif name in self.numeric:
                    if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
                        raise InvalidPacket("hybrid numeric command requires signed32 integer")
                    numeric.append((name, value))
                else:
                    raise InvalidPacket("hybrid unknown command crosses opaque board boundary")
            if self.wb and local and numeric:
                raise InvalidPacket("hybrid mixed scalar namespaces require separate atomic commands")
            if any(name == "Onoff" for name, _ in local):
                runtime["onoff_frames"] = []
            for name, value in local:
                self._set_special(device, pending, runtime, name, value)
            for name, value in numeric:
                pending[name] = value & 65535
            selected, applied = [], []
            for name, _ in local:
                if name not in self.write_only:
                    selected.append(name)
                    applied.extend(self._get(device, pending, runtime, name))
            for name, value in numeric:
                selected.append(name)
                applied.append(value)
            reply = _reply(device, {"t": "res", "mac": "" if self.wb else device.mac,
                                    "p": applied, "opt": selected, "r": 200}, reply_index, uid, peer)
        elif kind in ("setT", "queryT", "deleteT", "updateT"):
            timer_input = inner
            missing_seconds = self.wb and kind in ("setT", "updateT") and "sec" not in inner
            if self.wb and kind in ("setT", "updateT") and isinstance(inner.get("cmd"), list):
                for command in inner["cmd"]:
                    if isinstance(command, dict):
                        if "mac" in command and command["mac"] != [device.mac]:
                            raise InvalidPacket("hybrid timer requires the exact root MAC array")
                        if isinstance(command.get("opt"), list) and any(
                                name != "Pow" for name in command["opt"]):
                            raise InvalidPacket("hybrid timer supports only raw Pow commands")
            if missing_seconds:
                timer_input = {**inner, "sec": 0}
            response = self._timer(device, runtime, timer_input)
            if missing_seconds:
                timer = runtime["timers"].get(inner["id"] & 255)
                if timer is not None:
                    # Missing sec retains parsed min; a successful sec parse instead stores zero.
                    timer["sec"] = inner["min"] & 255
            if self.wb and kind == "queryT":
                for record in response["list"]:
                    record["cmd"][0]["mac"] = [device.mac]
            reply = _reply(device, response, reply_index, uid, peer)
        elif kind == "dump":
            if (type(inner.get("period")) is not int or type(inner.get("cnt")) is not int):
                raise InvalidPacket("hybrid dump requires integer period and count")
            reply = _reply(device, {"t": "ret", "r": 200}, reply_index, uid, peer)
        elif kind == "upgrade":
            url = inner.get("url")
            if not isinstance(url, str) or "\0" in url or len(url.encode()) > 119:
                raise InvalidPacket("hybrid upgrade requires bounded URL string")
            # Native ret acknowledges the request, not completed installation.
            runtime["upgrade_url"] = url
            reply = _reply(device, {"t": "ret", "r": 200}, reply_index, uid, peer)
        else:
            return []
        pending["_uid"] = uid
        device.state.clear()
        device.state.update(pending)
        return [reply]


# Explicit synthetic mainboard inputs, never fixed compiled/physical MID claims.
PROFILES = tuple(
    Profile(
        id=profile_id, mids=("10001",), hid=hid, source_sha256=sha,
        initial_state={**dict.fromkeys(
            (name for name in handler.numeric if name not in LOCAL), 0), "_uid": 0},
        handler=handler, max_request_bytes=1460,
    )
    for profile_id, hid, sha, handler in (
        ("sim-w05ab-v1.73-10001", "362001062842+U-W05ABV1.73.bin",
         "8b9ea176ff32901eb67d28d507900c174732dff9bcc3d2e90f543c4f02ac6e9d",
         HybridController(ab=True)),
        ("sim-w65-v1.03-10001", "362001065029+U-W65V1.03.bin",
         "a0df8b286a0ec544fd9e3ef2467557eef15631fa1f5be4d12f09d85b1ddec937",
         HybridController()),
        ("sim-wb05df13-v2.01-10001", "362001066308+U-WB05DF13V2.01.bin",
         "ae9d42c6272c71a7c2ee4fd500ad4427c99b64a01aafc61daa109025eb37e9ec",
         HybridController(wb=True)),
        ("sim-wb05ur-v1.05-10001", "362001067422+U-WB05URV1.05.bin",
         "078ff7ab76a0c86335c535f802d463a281ca1a26f4bdde91e24faaa1efd9076c",
         HybridController(wb=True)),
    )
)

# Preserve paused non-WB definitions without admitting them to the active catalog.
PAUSED_PROFILES = PROFILES[:2]
WB_PROFILES = PROFILES[2:]
PROFILES = WB_PROFILES
