"""MC-ETSBH01 root LAN controller; no mesh, CAN/485 children or climate model."""

import json
import re
import time

from ..wire import InvalidPacket, Reply, decode_pack
from . import Profile


HID = "362001063066+MC-ETSBH01V1.38.img"
SOURCE_SHA256 = "d605815976c047153c82f5affcc33f39f6b60f4ddc8d5cfb224282876a52d12e"
GENERIC_KEY = b"{yxAHAY_Lm6pbCtd"
CODEC = "aes-ecb-pkcs7"
INITIAL_STATE = {"Meshid": "0000", "Unbind": ""}
READABLE = {
    "Mesh": 0, "Meshota": "", "SubOnline": [], "Proaddr": "", "Random": "00000000",
    "Subcount": 0, "Pow": 1, "Onoff": "OK", "text": "ok", "hid": HID,
    "InHid": 0, "OEEPHid": 0, "BtHid": 0, "GcloudHid": 0,
}
UNAVAILABLE = {
    "BleON", "Reota", "Lpn", "No", "apssid", "appsw", "host", "name", "lat", "lon",
    "vender", "bc", "mid", "model", "series", "brand", "catalog", "country", "ver",
    "HidSvrVer", "InHidSvrVer", "OEEPHidSvrVer",
}


def _clock():
    # Chosen UTC host readout; root time commands never change the host clock.
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())


def _integer(value, label, minimum=-(2**31), maximum=2**31 - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise InvalidPacket(f"central {label} requires an integer {minimum}..{maximum}")
    return value


def _timer(inner):
    identifier = _integer(inner.get("id"), "timer id", 0, 999)
    name = inner.get("name")
    if not isinstance(name, str) or len(name.encode("utf-8")) > 128 or "\0" in name:
        raise InvalidPacket("central timer name requires at most128 UTF8 bytes without NUL")
    week = inner.get("week")
    if not isinstance(week, list) or len(week) != 7:
        raise InvalidPacket("central timer week requires seven integers")
    week = [_integer(value, "timer week") for value in week]
    commands = inner.get("cmd")
    if not isinstance(commands, list) or not commands or not isinstance(commands[0], dict):
        raise InvalidPacket("central timer requires a command record")
    command = commands[0]
    for field in ("mac", "opt", "p"):
        if not isinstance(command.get(field), list) or not command[field]:
            raise InvalidPacket("central timer requires nonempty mac/opt/p arrays")
    mac, option, value = command["mac"][0], command["opt"][0], command["p"][0]
    if (not isinstance(mac, str) or re.fullmatch("[0-9a-fA-F]{12}", mac) is None
            or not isinstance(option, str) or not option or len(option.encode("utf-8")) >= 16):
        raise InvalidPacket("central timer requires a12hex mac and short option")
    value = _integer(value, "timer command")
    encoded = json.dumps({"mac": mac, "opt": [option], "p": [value]},
                         separators=(",", ":"), ensure_ascii=False)
    # Source CMD storage is lossy even inside names, not just JSON punctuation.
    decoded = encoded.replace(",", "_").replace('"', "|").replace("_", ",").replace("|", '"')
    try:
        stored = json.loads(decoded)
    except ValueError as exc:
        raise InvalidPacket("central timer CMD codec produced invalid JSON") from exc
    return {"id": identifier, "name": name,
            "enable": _integer(inner.get("enable"), "timer enable"), "tz": 8, "sec": 0,
            "hr": _integer(inner.get("hr"), "timer hour", 0, 23),
            "min": _integer(inner.get("min"), "timer minute", 0, 59),
            "week": week, "cmd": [{"mac": [stored["mac"]], "opt": stored["opt"], "p": stored["p"]}]}


def _reply(device, inner, index, uid):
    plain = json.dumps(inner, ensure_ascii=False, separators=(",", ":"),
                       allow_nan=False).encode("utf-8")
    padded_length = (len(plain) // 16 + 1) * 16
    if len(plain) + 1 > 1024 or 4 * ((padded_length + 2) // 3) + 1 > 1024:
        raise InvalidPacket("central reply exceeds native plaintext/base64 scratch including NUL")
    return Reply({"t": "pack", "i": index, "uid": uid, "cid": device.mac, "tcid": "app"},
                 inner, GENERIC_KEY if index else device.key, CODEC, trailing_newline=True)


def _metadata(device, kind):
    result = {"t": kind, "cid": "", "bc": "gree", "catalog": "gree", "mid": device.mid,
              "lock": 0, "model": "gree"}
    if kind == "dev":
        result["name"] = "linkpad"
    result.update(series="gree", vender="2", ver="V1.2.1", brand="gree", mac=device.mac)
    return result


class CentralFamily:
    def validate_state(self, state):
        for name, value in state.items():
            width = {"Meshid": 4, "Unbind": 12}.get(name)
            characters = "0-9a-f" if name == "Meshid" else "0-9a-fA-F"
            if (width is None or not isinstance(value, str)
                    or (not (name == "Unbind" and value == "")
                        and re.fullmatch(rf"[{characters}]{{{width}}}", value) is None)):
                raise ValueError("central state supports only lowercase Meshid4hex and Unbind12hex")

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        # The source has no root thermometer or appliance controls.
        pass

    def advertise(self, device, outer):
        return [_reply(device, _metadata(device, "dev"), 1, device.state.get("_uid", 0))]

    def mate(self, device, outer):
        # decode_outer validates the synthetic host; identity selectors are natively ignored.
        inner = _metadata(device, "remate")
        inner.update(private_key=device.key.decode("ascii"), ssid="", submac="",
                     devicename="linkpad", devType=2, sub485Type=1, subMid="60", subCnt=0)
        reply = _reply(device, inner, 1, device.state.get("_uid", 0))
        device.state["_host"] = outer["host"]
        return [reply]

    def handle(self, device, outer):
        if outer.get("t") != "pack" or outer.get("tcid") != device.mac:
            raise InvalidPacket("central requires a root-targeted encrypted pack")
        index = outer.get("i")
        uid = outer.get("uid", device.state.get("_uid", 0))
        if (type(index) is not int or index not in (0, 1)
                or type(uid) is not int or not -(2**31) <= uid < 2**31):
            raise InvalidPacket("invalid central key selector or uid")
        inner = decode_pack(outer, GENERIC_KEY if index else device.key, CODEC)
        kind = inner.get("t")
        if kind not in ("status", "cmd", "subDev", "subdev", "setT", "updateT", "deleteT", "queryT"):
            # Ordinary bind is genuinely silent, but still updates the source pack uid cache.
            device.state["_uid"] = uid
            return []
        if index != 0 or "sub" in inner:
            raise InvalidPacket("central exposes only bound root operations")
        pending = {}
        if kind == "status":
            if inner.get("mac") != device.mac:
                raise InvalidPacket("central status requires the root identity")
            columns = inner.get("cols")
            if not isinstance(columns, list):
                raise InvalidPacket("central status requires a cols array")
            available = {**READABLE, **{name: device.state[name] for name in INITIAL_STATE},
                         "mac": device.mac, "time": _clock(), "Mesh": device.state.get("_mesh", 0)}
            selected, data = [], []
            for name in columns:
                if not isinstance(name, str) or len(name.encode("utf-8")) >= 16:
                    continue
                if name in available:
                    selected.append(name)
                    data.append(available[name])
                elif name in UNAVAILABLE:
                    selected.extend([name] * (21 if name == "No" else 1))
            result = {"t": "dat", "mac": device.mac, "r": 200, "cols": selected, "dat": data}
        elif kind == "subDev":
            page = inner.get("i")
            if type(page) is not int or not 0 <= page < 2**31:
                raise InvalidPacket("central page must be a nonnegative signed integer")
            result = {"t": "subList", "r": 200, "c": 0, "i": page, "list": []}
        elif kind == "subdev":
            page = _integer(inner.get("i", 0), "mesh page") & 255
            result = {"t": "sublist", "r": 200, "c": 0, "i": page, "list": []}
        elif kind in ("setT", "updateT"):
            timer = _timer(inner)
            timers = dict(device.state.get("_timers", {}))
            # SQLite REPLACE deletes the old row and inserts a new trailing rowid.
            timers.pop(timer["id"], None)
            timers[timer["id"]] = timer
            pending["_timers"] = timers
            result = {"t": "resT", "r": 200}
        elif kind == "deleteT":
            identifier = _integer(inner.get("id"), "timer id", 0, 999)
            timers = dict(device.state.get("_timers", {}))
            timers.pop(identifier, None)
            pending["_timers"] = timers
            result = {"t": "resT", "r": 200}
        elif kind == "queryT":
            start = _integer(inner.get("index"), "timer index", 0)
            count = _integer(inner.get("count"), "timer count", 0)
            timers = device.state.get("_timers", {})
            # Chosen safe ownership: each stored row owns its own week/CMD arrays.
            result = {"t": "listT", "index": start, "total": len(timers),
                      "list": list(timers.values())[start:start + count]}
        else:
            names, values = inner.get("opt"), inner.get("p")
            if (not isinstance(names, list) or not isinstance(values, list) or not names
                    or len(names) != len(values)):
                raise InvalidPacket("central command requires nonempty matching opt/p arrays")
            pending = {}
            for name, value in zip(names, values):
                if name == "Pow":
                    if type(value) is not int or not 0 <= value <= 65535:
                        raise InvalidPacket("central Pow requires an integer0..65535")
                elif (isinstance(name, str)
                      and name in (READABLE.keys() | UNAVAILABLE | INITIAL_STATE.keys() | {"mac", "time"})
                      and type(value) is int):
                    _integer(value, "parameter")
                elif name == "time" and isinstance(value, str):
                    pass
                elif isinstance(name, str) and name in INITIAL_STATE:
                    width = 4 if name == "Meshid" else 12
                    if not isinstance(value, str) or re.fullmatch(rf"[0-9a-fA-F]{{{width}}}", value) is None:
                        raise InvalidPacket("central string command requires exact hexadecimal width")
                    pending[name] = value.lower() if name == "Meshid" else value
                else:
                    raise InvalidPacket("unsupported central root command or side effect")
            if names[0] == "Mesh":
                pending["_mesh"] = 2
            acknowledged = []
            for name, value in zip(names, values):
                if name == "Meshid" and isinstance(value, str):
                    acknowledged.append(value.lower())
                elif name == "time" and isinstance(value, str):
                    acknowledged.append(_clock())
                else:
                    acknowledged.append(value & 65535 if type(value) is int else value)
            result = {"t": "res", "mac": device.mac, "r": 200, "opt": names, "p": acknowledged}
        reply = _reply(device, result, 0, uid)
        device.state.update(pending)
        device.state["_uid"] = uid
        return [reply]


PROFILES = (
    Profile(id="sim-mc-etsbh01-v1.38", mids=("80901",), hid=HID,
            source_sha256=SOURCE_SHA256, initial_state=INITIAL_STATE,
            handler=CentralFamily(), max_request_bytes=2048),
)
