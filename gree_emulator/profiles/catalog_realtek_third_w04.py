"""SDK9 W04 snapshots with chosen synthetic serial caches, not physical boards.

Original status/cmd callbacks dispatch SDK9 into the serial snapshot serializers.
Strict bounded atomic input validation replaces native unchecked buffers. Timers,
network settings and requested/effective values are synthetic volatile storage;
no flash, radio, UART delivery, peripheral calibration or full boot is claimed.
"""
import base64
from copy import deepcopy
from datetime import timedelta
import json
from time import monotonic

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile
from .catalog_realtek_third_tables import CODEC, KEY, FiniteTables, _clock, _integer, _members, _text

BUILDS = {
    "w04a-v16": ("94c2051f932b1eb62b869af7b150e12c8b41a058dfdaf438046e80d00d48a52c", "16"),
    "w04a-v8": ("ddc6056bf0972ecaf1e64f6d7014193160d94961e662a45e4ff878183cb8994b", "8"),
    "w04b-v12": ("3473b2bcdf3eeb00634a66e8a9e0cf81664cde83dd60dffe5f2c9eaada64b4a9", "12"),
}
PREFIXES = {"828140": "362001061704+U-W04W", "828401": "362001061820+U-W05E",
            "828402": "362001061820+U-W05E", "828a04": "362001063062+U-W04A"}
EMPTY_SNAPSHOT_MIDS = ("828200", "828202", "828203", "828900")
PURIFIER = {"Pow": (4, 128, 7), "Mode": (4, 7, 0), "Wspd": (5, 255, 0),
            "Light": (6, 255, 0), "AirChildLock": (7, 1, 0), "RefreshWater": (7, 2, 1),
            "FiltUPercent": (14, 255, 0), "ReplaceFilter": (16, 3, 0),
            "SetHumidity": (17, 255, 0), "EnvHumidity": (18, 255, 0)}
HEATER = {"Pow": (4, 128, 7), "AirChildLock": (4, 16, 4), "SetTemp": (5, 255, 0),
          "HeatMod": (11, 255, 0), "TemEnv": (6, 255, 0)}
COOKER = {"mode": (4, 31, 0), "Pow": (4, 128, 7), "Lig": (4, 32, 5),
          "TmrOn": (5, 96, 5), "TmrEn": (5, 128, 7), "SchOnOff": (7, 96, 5),
          "SchEn": (7, 128, 7), "Rice": (9, 15, 0), "Textre": (9, 240, 4),
          "Prsure": (10, 240, 4), "sealve": (10, 15, 0), "KpTpOnOFF": (11, 96, 5),
          "KpTpEn": (11, 128, 7), "StpRic": (15, 15, 0), "ElcP": (18, 255, 0),
          "TmpUp": (19, 255, 0), "TmpDn": (20, 255, 0)}
MINUTES = {"StTmr": (5, 6), "SchTmr": (7, 8), "KpTpTmr": (11, 12), "ModeTmr": (13, 14)}
METADATA = ("time", "name", "lock", "AutoUpdate", "host", "hid", "mid", "bc", "DevID",
            "MafIdf", "AppTimer", "MidType", "rssi")


def _columns(value):
    if not isinstance(value, list) or len(value) > 32:
        raise InvalidPacket("SDK9 permits at most 32 bounded columns")
    names = [_text(name, 511, empty=False) for name in value]
    if sum(len(name.encode())+1 for name in names) > 512:
        raise InvalidPacket("SDK9 column strings exceed the original 512-byte workspace")
    return names


class W04Snapshots(FiniteTables):
    plaintext_types = ("tm",)

    def __init__(self, build, mid):
        self.build, self.mid = build, mid
        self.mapping = PURIFIER if mid == "828140" else HEATER if mid == "828a04" else COOKER
        self.writable = (set(("Pow", "Mode", "Wspd", "Light", "AirChildLock", "SetHumidity",
                              "TmrOn", "TmrAction", "TmrHour", "TmrMin")) if mid == "828140" else
                         set(("Pow", "AirChildLock", "SetTemp", "HeatMod", "TimeStart", "TmrAction",
                              "TmrHour", "TmrMin")) if mid == "828a04" else
                         set(("mode", "Pow", "StTmr", "TmrOn", "TmrEn", "SchTmr", "SchOnOff",
                              "SchEn", "Rice", "Textre", "sealve", "Prsure", "KpTpTmr",
                              "KpTpOnOFF", "KpTpEn")))
        if mid in EMPTY_SNAPSHOT_MIDS:
            self.mapping, self.writable = {}, set()
        self.fields = tuple(self.writable)

    def validate_state(self, state):
        for name, value in state.items():
            if name not in self.writable:
                raise ValueError("only this source-selected branch's writable fields may be configured")
            try:
                _integer(value)
            except InvalidPacket as error:
                raise ValueError(str(error)) from error

    def _runtime(self, device, state):
        runtime = super()._runtime(device, state)
        if "serial" not in runtime:
            # Chosen synthetic frame, identical to the independent original snapshot vectors.
            runtime.update(serial=list(bytes.fromhex("7e7e1c94000102030405060708090a0b0c0d0e0f101112131415161718c00000")),
                           timer=[0]*7, lock=0, AutoUpdate=0, dwTsk=-1, dwRpt=-1,
                           rssi=0, DevID="", MidType="", bc="", name=device.name)
            overrides = {name: value for name, value in state.items() if name in self.writable}
            self._mutate(runtime, overrides)
        return runtime

    def _timer(self, inner):
        timer_id = _integer(inner.get("id"), 0, 254)
        record = {name: _integer(inner.get(name)) for name in ("enable", "hr", "min", "tz")}
        if not 0 <= record["hr"] < 24 or not 0 <= record["min"] < 60:
            raise InvalidPacket("timer time must be valid")
        record.update(id=timer_id, name=_text(inner.get("name"), 31),
                      enable=int(record["enable"] == 1), sec=0)
        week = inner.get("week")
        if not isinstance(week, list) or len(week) != 7:
            raise InvalidPacket("SDK9 timer requires seven weekday entries")
        record["week"] = [_integer(value, 0, 1) for value in week]
        commands = inner.get("cmd")
        if not isinstance(commands, list) or len(commands) != 1 or not isinstance(commands[0], dict):
            raise InvalidPacket("SDK9 timer serializes only the first command object")
        names, values = _columns(commands[0].get("opt")), commands[0].get("p")
        if not isinstance(values, list) or len(names) != len(values):
            raise InvalidPacket("timer command arrays must match")
        record["cmd"] = [{"mac": [inner.get("mac", "")], "opt": names,
                          "p": [_integer(value) for value in values]}]
        if len(json.dumps(dict(zip(names, values)), separators=(",", ":")).encode()) >= 200:
            raise InvalidPacket("timer command exceeds the original 200-byte record")
        return timer_id, record

    def _time(self, state, runtime, value):
        old, new = _clock(runtime["time"]), _clock(value)
        if (new-old).days > 366:
            raise InvalidPacket("synthetic scheduler advance is bounded to one year")
        day = old.replace(hour=0, minute=0, second=0)
        while day <= new:
            for record in runtime["timers"].values():
                event = day.replace(hour=record["hr"], minute=record["min"], second=record["sec"])
                repeating = any(record["week"])
                if (record["enable"] and old < event <= new
                        and (not repeating or record["week"][(event.weekday()+1) % 7])):
                    command = record["cmd"][0]
                    self._command(state, runtime, command["opt"], command["p"])
                    if not repeating:
                        record["enable"] = 0
            if day.date() == new.date():
                break  # Synthetic calendar: native clock wrap is not established.
            day += timedelta(days=1)
        runtime["time"] = value

    def _metadata(self, device, runtime):
        return {"name": runtime["name"], "host": runtime["host"], "time": runtime["time"],
                "lock": runtime["lock"], "AutoUpdate": runtime["AutoUpdate"], "hid": device.profile.hid,
                "mid": device.mid, "bc": runtime["bc"], "DevID": runtime["DevID"], "MafIdf": 0,
                "AppTimer": int(any(record["enable"] == 1 for record in runtime["timers"].values())),
                "MidType": runtime["MidType"], "rssi": runtime["rssi"]}

    def _readouts(self, runtime):
        if self.mid in EMPTY_SNAPSHOT_MIDS:
            return {}
        frame = runtime["serial"]
        result = {name: (frame[offset] & mask) >> shift for name, (offset, mask, shift) in self.mapping.items()}
        if self.mid in ("828401", "828402"):
            result.update({name: (frame[hour] & 31)*60+(frame[minute] & 63)
                           for name, (hour, minute) in MINUTES.items()})
            result["Volt"] = frame[17] | (frame[16] & 15) << 8
            result.update(estate=0, estate2=0, estate3=0, estate4=0)
        else:
            timer = runtime["timer"]
            result.update(TmrAction=(timer[4] & 127) >> 5, TmrHour=timer[4] & 31,
                          TmrMin=timer[5] & (31 if self.mid == "828140" else 63))
            result["TmrOn" if self.mid == "828140" else "TimeStart"] = timer[4] >> 7
            result.update(estate=0, estate2=0, estate3=0)
            if self.mid == "828140":
                result.update(PM25=frame[10]*256+frame[11], PM25Level=frame[10], estate1=0)
            else:
                result["TimeWork"] = frame[7]*60+frame[8]
                if self.build != "w04a-v8":
                    result["JFerr"] = 0
        return result

    def _mutate(self, runtime, requested):
        frame = runtime["serial"]
        timer = runtime["timer"]
        normal = self.mid in ("828401", "828402") or any(
            name in requested for name in self.writable-{"TmrOn", "TimeStart", "TmrAction", "TmrHour", "TmrMin"})
        if not normal:
            timer = runtime["timer"] = [0]*7
        for name, value in requested.items():
            if name not in self.writable:
                continue
            if name in self.mapping and normal:
                offset, mask, shift = self.mapping[name]
                if self.mid == "828a04" and name == "HeatMod":
                    offset = 7  # Native setter writes work-hour storage, not its getter's byte 11.
                frame[offset] = ((frame[offset] & ~mask) | (value << shift)) & 255
            elif name in MINUTES and self.mid in ("828401", "828402"):
                hour, minute = MINUTES[name]
                quotient = abs(value)//60 * (-1 if value < 0 else 1)
                frame[hour] = ((frame[hour] & 224) | quotient) & 255
                frame[minute] = ((frame[minute] & 192) | (value-quotient*60)) & 255
            elif not normal:
                offset, mask, shift = {"TmrOn": (4,128,7), "TimeStart": (4,128,7),
                                      "TmrAction": (4,96,5), "TmrHour": (4,31,0), "TmrMin": (5,63,0)}[name]
                timer[offset] = ((timer[offset] & ~mask) | (value << shift)) & 255

    def _command(self, state, runtime, names, values):
        requested = dict(zip(names, values))  # Native JSON getter selects the first duplicate.
        requested = {name: values[names.index(name)] for name in requested}
        self._mutate(runtime, {name: _integer(value) for name, value in requested.items() if name not in METADATA})
        return names, values

    def _reply(self, device, outer, inner, selector=None):
        plain = json.dumps(inner, separators=(",", ":")).encode()
        if len(plain) >= 1460 or 4*((((len(plain)//16+1)*16)+2)//3) >= 1460:
            raise InvalidPacket("SDK9 response exceeds its original 1460-byte workspace")
        selector = outer.get("i", 1) if selector is None else selector
        reply = Reply({"t": "pack", "i": selector, "uid": outer.get("uid", 0),
                       "cid": outer.get("tcid", ""), "tcid": outer.get("cid", "")},
                      inner, device.key if selector == 0 else KEY, CODEC)
        encode_reply(reply)
        return reply

    def advertise(self, device, outer):
        runtime = self._runtime(device, deepcopy(device.state))
        inner = {"t": "dev", "cid": "", "bc": "", "brand": "", "catalog": "", "mac": device.mac,
                 "mid": device.mid, "model": "", "name": runtime["name"], "lock": runtime["lock"],
                 "series": "", "vender": "", "ver": ""}
        return [self._reply(device, {}, inner, 1)]


    def _surver(self, device, outer, runtime):
        encrypted = base64.b64decode(outer["pack"], validate=True)
        block = AES.new(device.key if outer["i"] == 0 else KEY, AES.MODE_ECB).decrypt(encrypted)
        unpadded = unpad(block, 16)
        header = bytearray(39)
        header[:min(39, len(block))] = block[:39]
        if len(unpadded) < 39:
            header[len(unpadded)] = 0
        header[:15] = b'{"t":"surver"}\0'
        header[2:4] = b"\0\0"  # RTC returns status0; original AES receives -39 and returns zero bytes.
        header[4:10] = header[16:22] = bytes.fromhex(device.mac)
        clock = _clock(runtime["time"])
        header[32:38] = bytes(((clock.year+48) & 255, clock.month, clock.day,
                               clock.hour, clock.minute, clock.second))
        payload = b"!!"+base64.b64encode(header)+b"\n"
        packed = base64.b64encode(AES.new(KEY, AES.MODE_ECB).encrypt(pad(payload, 16))).decode()
        complete = json.dumps({"t": "pack", "i": 1, "uid": outer.get("uid", 0),
                               "cid": outer.get("tcid", ""), "tcid": outer.get("cid", ""),
                               "pack": packed}, separators=(",", ":")).encode()
        return Reply({}, raw_payload=complete)
    def handle(self, device, outer):
        _members(outer)
        if outer.get("t") == "wlan":
            state = deepcopy(device.state)
            runtime = self._runtime(device, state)
            runtime["host"] = _text(outer.get("host"), 31)
            _text(outer.get("ssid"), 32)
            _text(outer.get("psw"), 64)
            reply = Reply({"t": "ret", "r": 200})
            encode_reply(reply)
            device.state = state
            return [reply]
        if outer.get("t") == "tm":
            state = deepcopy(device.state)
            runtime = self._runtime(device, state)
            value = _text(outer.get("time"), 32, empty=False)
            value = value if len(value) > 10 and value[10] == " " else value[:10]+" "+value[10:]
            self._time(state, runtime, value)
            device.state = state
            return []
        if outer.get("t") != "pack" or outer.get("tcid") != device.mac:
            raise InvalidPacket("SDK9 encrypted request must target this root")
        selector = _integer(outer.get("i"))
        if selector not in (0, 1):
            return []
        _integer(outer.get("uid", 0))
        _text(outer.get("cid", ""), 63)
        inner = decode_pack(outer, device.key if selector == 0 else KEY, CODEC)
        _members(inner)
        state = deepcopy(device.state)
        runtime = self._runtime(device, state)
        now = monotonic()
        self._advance(state, runtime, now)
        kind = inner.get("t")
        if kind == "bind":
            response = {"r": 200, "t": "bindok", "mac": _text(inner.get("mac", device.mac), 31),
                        "key": device.key.decode("ascii")}
        elif kind == "status":
            names = _columns(inner.get("cols", inner.get("opt")))
            metadata, readouts = self._metadata(device, runtime), self._readouts(runtime)
            if self.mid in EMPTY_SNAPSHOT_MIDS and any(name not in metadata for name in names):
                return []  # Original serializer returns -1; the status callback aborts.
            columns = [name for name in names if name in metadata or name in readouts]
            response = {"t": "dat", "uid": outer.get("uid", 0), "mac": inner.get("mac", device.mac),
                        "cid": device.mac, "dat": [metadata[name] if name in metadata else readouts[name]
                                                  for name in columns], "cols": columns,
                        "r": 200}
        elif kind == "cmd":
            names, values = _columns(inner.get("opt")), inner.get("p")
            if not isinstance(values, list) or len(names) != len(values):
                raise InvalidPacket("SDK9 command arrays must match")
            result_code = 200
            if "dwTsk" in names or "dwRpt" in names:
                columns = [name for name in ("dwTsk", "dwRpt") if name in names]
                effective = [_integer(values[names.index(name)]) for name in columns]
                runtime.update(zip(columns, effective))
            else:
                metadata_names = [name for name in names if name in METADATA]
                board_names = [name for name in names if name not in METADATA]
                if not board_names:
                    for name in metadata_names:
                        value = values[0] if values else None
                        if name in ("name", "host"):
                            runtime[name] = _text(value, 31)
                        elif name in ("lock", "AutoUpdate"):
                            value = _integer(value)
                            runtime[name] = int(value != 0) if name == "lock" else value & 255
                        elif name == "time":
                            self._time(state, runtime, value)
                        else:
                            return []
                else:
                    self._command(state, runtime, board_names, values[:len(board_names)])
                meta = self._metadata(device, runtime)
                result_code = 408 if self.mid in EMPTY_SNAPSHOT_MIDS and board_names else 200
                columns = metadata_names + ([] if result_code == 408 else board_names)
                effective = [meta[name] if name in meta else values[board_names.index(name)] for name in columns]
            response = {"t": "res", "mac": inner.get("mac", device.mac), "val": effective,
                        "p": effective[:], "opt": columns, "r": result_code}
        elif kind == "subDev":
            index = _integer(inner.get("i"))
            response = {"r": 200, "t": "subList", "i": index, "list": [
                {"mac": device.mac+"01", "mid": device.mid+"01", "name": "GreeHot", "model": "gree", "lock": 0}
            ] if index == 0 else [], "c": 1}
        elif kind in ("setT", "updateT"):
            timer_id, record = self._timer(inner)
            if kind == "setT" and (timer_id in runtime["timers"] or len(runtime["timers"]) >= 10):
                return []
            if kind == "updateT" and timer_id not in runtime["timers"]:
                raise InvalidPacket("native update search can overrun a missing companion timer")
            runtime["timers"][timer_id] = record
            response = {"t": "resT", "r": 200}
        elif kind == "deleteT":
            timer_id = _integer(inner.get("id")) & 255
            if timer_id not in runtime["timers"]:
                raise InvalidPacket("native missing-timer search can overrun the companion list")
            del runtime["timers"][timer_id]
            response = {"t": "resT", "r": 200}
        elif kind == "queryT":
            start, count = (_integer(inner.get(name)) for name in ("index", "count"))
            if start < 0 or count < 0:
                raise InvalidPacket("timer pagination must be nonnegative")
            response = {"t": "listT", "total": len(runtime["timers"]), "index": start,
                        "list": list(runtime["timers"].values())[start:start+count]}
        elif kind == "dump":
            runtime["dump"] = (_integer(inner.get("period", 60)), _integer(inner.get("cnt", 1)))
            response = {"t": "res", "mac": device.mac, "r": 200}
        elif kind == "upgrade":
            _text(inner.get("url"), 119, empty=False)
            if "sub" in inner:
                _text(inner["sub"], 15)
                _integer(inner.get("otatype"))
            response = {"t": "ret", "r": 200}  # Receipt only; no download or flash operation.
        elif kind == "surver":
            if self.mid in EMPTY_SNAPSHOT_MIDS:
                return []
            self._mutate(runtime, {})
            reply = self._surver(device, outer, runtime)
            encode_reply(reply)
            device.advance(now)
            device.state = state
            return [reply]
        else:
            return []
        reply = self._reply(device, outer, response)
        device.advance(now)
        device.state = state
        return [reply]


def _profile(build, mid):
    sha, version = BUILDS[build]
    prefix = "362001063082+U-W04B" if mid == "828a04" and build == "w04b-v12" else PREFIXES.get(mid, "")
    return Profile(id="sim-"+build+"-"+mid, mids=(mid,), hid=prefix+"V"+version+".bin",
                   source_sha256=sha, initial_state={}, handler=W04Snapshots(build, mid))


PROFILES = tuple(_profile(build, mid) for build in BUILDS for mid in (*PREFIXES, *EMPTY_SNAPSHOT_MIDS))
