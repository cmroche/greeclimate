"""W05M/W06T finite serial-cache LAN, with explicitly synthetic board readouts.

W06T's first allocator wins; W05M's synthetic companion identity is held fixed.
UART refresh/physical calibration, cloud services and flash writes are not
simulated. Commands retain requested int32 cache values until synthetic input
changes them; serial masks do not silently clamp the LAN cache. Strict atomic
validation replaces native unchecked copies and its past-end command iteration.
"""
from copy import deepcopy
from datetime import datetime, timedelta
import json
from time import monotonic

from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile

KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
W05_SHA = "691414326dc552ba12daea9bc7bd48428af80e4953caa56f2781f682646bfac6"
W06_SHA = "6e2139501799bc09a846caa59562fc955d9cfbd0b51df0c394e8bce81561507b"
W05_HID = "362001062030+U-W05MV1.18.bin"
W06_HID = "362001063012+U-W06TV1.10.bin"
TABLES = {
    "w05-fan": ("Pow", "Rotate", "Mod", "WdSpd", "RotateAg", "TmrOn", "TmrAction",
                "TmrHour", "TmrMin", "estate", "MidType"),
    "w05-washer": ("Pow", "PauseStart", "Wash", "Mod", "Disinfect", "Dry", "WashDone",
                   "RmTmrHour", "RmTmrMin", "WorkStatus", "estate1", "estate2", "MidType", "JFerr"),
    "w06-metadata": ("MidType",),
    "w06-power": ("Pow", "MidType"),
    "w06-humidifier": ("Pow", "UV", "Mode", "Sleep", "FogLevel", "Humidity", "HumiditySet",
                       "TmrOn", "TmrAction", "TmrHour", "TmrMin", "Estate1", "Estate2", "JFerr", "MidType"),
    "w06-washer": ("Pow", "PauseStart", "Wash", "Mod", "Disinfect", "Dry", "WashDone",
                   "RmTmrHour", "RmTmrMin", "WorkStatus", "estate1", "estate2", "JFerr", "MidType"),
    "w06-joylink-fan": ("Power", "Mode", "Wind", "Horizontal", "Vertical", "Timing",
                        "TimingSetHour", "TimingSetMinute", "Error"),
    "w06-joylink-humidifier": ("Power", "UV", "Sleep", "Mode", "Wind", "CurrentHumidity",
                               "HumiditySet", "Timing", "Reserve", "TimingSetHour", "TimingSetMinute", "Error"),
    "w06-joylink-washer": ("Power", "Work", "Wash", "Mode", "Dry", "DisInfect", "EndTone",
                           "WorkTimeRemainingHour", "WorkTimeRemainingMinute", "State", "Error"),
}
METADATA = ("apssid", "appsw", "host", "name", "time", "lat", "lon", "vender", "bc", "mid",
            "model", "series", "brand", "catalog", "country", "hid", "mac", "ver", "HidSvrVer",
            "InHid", "InHidSvrVer", "OEEPHid", "OEEPHidSvrVer")


def _integer(value, low=-(1 << 31), high=(1 << 31)-1):
    if type(value) is not int or not low <= value <= high:
        raise InvalidPacket("finite-table value must be a bounded integer")
    return value


def _text(value, maximum, *, empty=True):
    if (not isinstance(value, str) or (not empty and not value)
            or len(value.encode()) > maximum or any(ord(c) < 32 for c in value)):
        raise InvalidPacket("finite-table string is invalid or too long")
    return value


def _columns(value):
    if not isinstance(value, list) or len(value) > 34:
        raise InvalidPacket("finite-table request permits at most 34 columns")
    return [_text(item, 1023) for item in value]


def _members(value):
    if isinstance(value, dict):
        keys = [key.casefold() for key in value]
        if len(keys) != len(set(keys)):
            raise InvalidPacket("ambiguous case-insensitive cJSON member")
        for item in value.values():
            _members(item)
    elif isinstance(value, list):
        for item in value:
            _members(item)


def _clock(value):
    value = _text(value, 19, empty=False)
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError as error:
        raise InvalidPacket("finite-table time requires YYYY-MM-DD HH:MM:SS") from error


def _reply(device, inner, uid=0, selector=0, *, newline=True):
    plain = json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode()
    if len(plain) >= 1024 or 4*((((len(plain)//16+1)*16)+2)//3) >= 1024:
        raise InvalidPacket("finite-table response exceeds the original 1024-byte scratch buffer")
    reply = Reply({"t": "pack", "i": selector, "uid": uid, "cid": device.mac, "tcid": ""},
                  inner, KEY if selector else device.key, CODEC, trailing_newline=newline)
    encode_reply(reply)
    return reply


class FiniteTables:
    def __init__(self, table):
        self.table = table
        self.fields = TABLES[table]
        self.w05 = table.startswith("w05-")

    def validate_state(self, state):
        for name, value in state.items():
            if name not in self.fields:
                raise ValueError("only the startup-selected raw cache fields may be configured")
            try:
                _integer(value)
            except InvalidPacket as error:
                raise ValueError(str(error)) from error

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        return None

    def _runtime(self, device, state):
        if "_tables" not in state:
            state["_tables"] = {"time": "1970-01-01 00:00:00", "timers": {},
                                "host": "", "name": device.name, "svline": [0]*24}
        return state["_tables"]

    def _advance(self, state, runtime, now):
        elapsed = max(0.0, now-runtime.get("clock_at", now)) + runtime.get("fraction", 0.0)
        seconds = int(elapsed)
        fraction = elapsed-seconds
        if seconds:
            current = _clock(runtime["time"])
            remaining = datetime.max-current
            remaining_seconds = remaining.days*86400 + remaining.seconds
            advanced = min(seconds, remaining_seconds)
            if advanced:
                value = (current+timedelta(seconds=advanced)).strftime("%Y-%m-%d %H:%M:%S")
                self._time(state, runtime, value)
            if advanced == remaining_seconds:
                # No source-proven clock wrap: the synthetic calendar saturates.
                fraction = 0.0
        runtime["clock_at"], runtime["fraction"] = now, fraction

    def _metadata(self, device, runtime):
        result = dict.fromkeys(METADATA, "")
        result.update(hid=device.profile.hid, host=runtime["host"], name=runtime["name"],
                      time=runtime["time"])
        if not self.w05:
            result["rssi"] = 0  # Explicit synthetic RSSI, not a calibrated radio measurement.
        if self.w05:
            result["SvLine"] = runtime["svline"][:]
        return result

    def advertise(self, device, outer):
        state = deepcopy(device.state)
        runtime = self._runtime(device, state)
        inner = {"t": "dev", "cid": "", "bc": "gree", "catalog": "gree", "mid": device.mid,
                 "lock": 0, "model": "gree", "name": runtime["name"], "series": "gree",
                 "vender": "0", "ver": "", "brand": "gree", "mac": device.mac}
        return [_reply(device, inner, selector=1)]

    def _timer(self, inner):
        timer_id = _integer(inner.get("id")) & 255
        name = _text(inner.get("name"), 19)
        enabled = int(bool(_integer(inner.get("enable"))))
        hour, minute, second = (_integer(inner.get(field)) for field in ("hr", "min", "sec"))
        if not 0 <= hour < 24 or not 0 <= minute < 60 or not 0 <= second < 60:
            raise InvalidPacket("finite-table timer requires a valid time of day")
        timezone = _integer(inner.get("tz")) & 255
        week = inner.get("week")
        if not isinstance(week, list) or len(week) > 7:
            raise InvalidPacket("finite-table timer requires at most seven weekday entries")
        week = [_integer(value) for value in week] + [0]*(7-len(week))
        commands = inner.get("cmd")
        if not isinstance(commands, list) or len(commands) > 10:
            raise InvalidPacket("finite-table timer requires at most ten command records")
        parsed = []
        for command in commands:
            if not isinstance(command, dict):
                raise InvalidPacket("invalid timer command record")
            macs = command.get("mac")
            if not isinstance(macs, list) or len(macs) > 10:
                raise InvalidPacket("invalid timer identity array")
            macs = [_text(mac, 19, empty=False) for mac in macs]
            names = _columns(command.get("opt"))
            values = command.get("p")
            if len(names) > 30 or not isinstance(values, list) or len(names) != len(values):
                raise InvalidPacket("timer command arrays require at most thirty matching entries")
            parsed.append({"mac": macs, "opt": names, "p": [_integer(value) for value in values]})
        return timer_id, {"id": timer_id, "name": name, "enable": enabled, "hr": hour,
                          "min": minute, "sec": second, "tz": timezone, "week": week, "cmd": parsed}

    def _command(self, state, runtime, names, values):
        columns, effective = [], []
        for name, value in zip(names, values):
            if name in self.fields:
                state[name] = _integer(value)
            elif name == "time":
                previous = runtime["time"]
                self._time(state, runtime, value)
                value = previous
            else:
                # Native unknown and read-only metadata requests are omitted.
                continue
            columns.append(name)
            effective.append(value)
        return columns, effective

    def _time(self, state, runtime, value):
        old, new = _clock(runtime["time"]), _clock(value)
        if new < old or not runtime["timers"]:
            runtime["time"] = value
            return
        # Chosen synthetic scheduler: apply each crossed event once; no flash/radio/physics.
        if (new-old).days > 366:
            raise InvalidPacket("synthetic timer advance is bounded to one year")
        day = old.replace(hour=0, minute=0, second=0)
        while day <= new:
            for record in runtime["timers"].values():
                event = day.replace(hour=record["hr"], minute=record["min"], second=record["sec"])
                repeating = any(record["week"])
                weekday = (event.weekday()+1) % 7
                if (not record["enable"] and old < event <= new
                        and event >= datetime(2018, 5, 22, 6, 10, 36)
                        and (not repeating or record["week"][weekday])):
                    for command in record["cmd"]:
                        # The original software-timer executor uses the local cache, not a child route.
                        for name, command_value in zip(command["opt"], command["p"]):
                            if name in self.fields:
                                state[name] = command_value
                    if not repeating:
                        record["enable"] = 1
            if day.date() == new.date():
                break
            day += timedelta(days=1)
        runtime["time"] = value

    def wlan(self, device, outer):
        _members(outer)
        _text(outer.get("ssid"), 31)
        _text(outer.get("psw"), 31)
        host = _text(outer.get("host"), 19)
        _text(outer.get("lat"), 11)
        _text(outer.get("lon"), 11)
        state = deepcopy(device.state)
        runtime = self._runtime(device, state)
        now = monotonic()
        self._advance(state, runtime, now)
        runtime["host"] = host
        reply = Reply({"t": "ret", "r": 0, "mac": device.mac}, trailing_newline=True)
        encode_reply(reply)
        device.advance(now)
        device.state = state
        return [reply]

    def handle(self, device, outer):
        _members(outer)
        if outer.get("t") == "wlan":
            return self.wlan(device, outer)
        if outer.get("t") != "pack" or outer.get("tcid") != device.mac:
            raise InvalidPacket("finite-table request must target this root")
        index = _integer(outer.get("i"))
        uid = _integer(outer.get("uid", 0))
        inner = decode_pack(outer, KEY if index else device.key, CODEC)
        _members(inner)
        if "sub" in inner or ("mac" in inner and inner["mac"] != device.mac):
            raise InvalidPacket("finite-table cache has no child identity aliases")
        kind = inner.get("t")
        state = deepcopy(device.state)
        runtime = self._runtime(device, state)
        now = monotonic()
        self._advance(state, runtime, now)
        newline = True
        selector = 0
        if kind == "bind":
            response = {"t": "bindok", "mac": device.mac, "r": 0, "key": device.key.decode("ascii")}
            selector = 1
        elif kind == "status":
            requested = _columns(inner.get("cols"))
            metadata = self._metadata(device, runtime)
            columns = []
            for name in requested:
                if not name or len(name.encode()) >= 16:
                    break
                if name in self.fields or name in metadata:
                    columns.append(name)
            response = {"t": "dat", "mac": device.mac, "r": 0, "cols": columns,
                        "dat": [state[name] if name in self.fields else metadata[name] for name in columns]}
        elif kind == "cmd":
            names, values = _columns(inner.get("opt")), inner.get("p")
            if not isinstance(values, list) or len(names) != len(values):
                raise InvalidPacket("finite-table command arrays must match")
            columns, effective = self._command(state, runtime, names, values)
            response = {"t": "res", "mac": device.mac, "r": 0, "opt": columns, "p": effective}
        elif kind in ("setT", "updateT"):
            timer_id, record = self._timer(inner)
            if timer_id not in runtime["timers"] and len(runtime["timers"]) >= 10:
                return [] if kind == "updateT" else [_reply(device, {"t": "resT", "r": 500}, uid, newline=False)]
            runtime["timers"][timer_id] = record
            response, newline = {"t": "resT", "r": 200}, False
        elif kind == "deleteT":
            runtime["timers"].pop(_integer(inner.get("id")) & 255, None)
            response, newline = {"t": "resT", "r": 200}, False
        elif kind == "queryT":
            start, count = (_integer(inner.get(field)) & 255 for field in ("index", "count"))
            response = {"t": "listT", "total": count, "index": start}
            if runtime["timers"]:
                response["list"] = [
                    {field: deepcopy(record[field]) for field in
                     ("id", "name", "enable", "hr", "min", "sec", "week", "cmd")}
                    for ordinal, record in enumerate(runtime["timers"].values())
                    if start <= ordinal <= start+count]
            newline = False
        elif kind == "surver":
            return []  # Both original request-kind 9 builders have no reply case.
        else:
            return []
        reply = _reply(device, response, uid, selector, newline=newline)
        device.advance(now)
        device.state = state
        return [reply]


def _profile(table, mid, hid, sha, suffix):
    state = dict.fromkeys(TABLES[table], 0)
    return Profile(id="sim-"+suffix, mids=(mid,), hid=hid, source_sha256=sha,
                   initial_state=state, handler=FiniteTables(table), max_request_bytes=1024)


PROFILES = (
    _profile("w05-fan", "828211", W05_HID, W05_SHA, "w05m-v118-fan"),
    _profile("w05-washer", "828901", W05_HID, W05_SHA, "w05m-v118-washer"),
    _profile("w06-humidifier", "828503", W06_HID, W06_SHA, "w06t-v110-humidifier"),
    _profile("w06-washer", "828901", W06_HID, W06_SHA, "w06t-v110-washer"),
    _profile("w06-joylink-humidifier", "828503", W06_HID, W06_SHA, "w06t-v110-jd-cache-humidifier"),
    _profile("w06-joylink-washer", "828901", W06_HID, W06_SHA, "w06t-v110-jd-cache-washer"),
)
