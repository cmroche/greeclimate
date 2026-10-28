"""WB05BR root parameter cache, separate from child tuple reports.

Defaults are descriptor JSON, not callback results. The simulated LAN has no
cloud/peripheral events: RSSI is -50 dBm, GcloudHid is an empty tuple readout,
and its uncalibrated clock starts at the Unix epoch on the first root request.
"""

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import calendar
import re
from time import monotonic

from ..wire import InvalidPacket
from .wb_adr import SHARED_FIELDS, raw_value, reported_state, stage_command


_NULL_FIELDS = (
    "conf", "configType", "time", "appStdTime", "wlan", "psw", "ssid",
    "svr", "achost", "tcpPort", "datHostPort", "datHost", "mqttInfo",
    "loginRes", "dat", "host", "rssi", "res", "upgrade", "subList",
)
_EMPTY_FIELDS = (
    "bc", "InHid", "OEEPHid", "GcloudHid", "deveephidownver",
    "devinhidownver", "gcldhidownver",
)
_ZERO_FIELDS = (
    "lock", "HidDownPer", "OEEPHidDownPer", "InHidDownPer",
    "GcldHidDownPer", "outUpStat", "inUpStat", "gcldUpStat",
)
_GENERIC_KEY = "a3K8Bx%2r8Y7#xDh"


def root_state(device, version):
    cached = device.state.get("_wb_root")
    if cached is not None:
        return deepcopy(cached)
    state = dict.fromkeys(_NULL_FIELDS)
    state.update(dict.fromkeys(_EMPTY_FIELDS, ""))
    state.update(dict.fromkeys(_ZERO_FIELDS, 0))
    state.update(mac=device.mac, mid=device.mid, name=device.name,
                 key=[device.key.decode("ascii"), _GENERIC_KEY], ver=None,
                 vender="1", brand="gree", catalog="gree", series="gree",
                 model="gree", productName="Gcloud", BLEMTU=500,
                 needMqtt=0 if version in ("1.13", "1.16", "1.18") else 1,
                 dishost="dis.gree.com", hid=device.profile.hid,
                 _clock_at=monotonic(), _clock_seconds=0, _tz=None)
    if version not in ("1.16", "1.18"):
        state.update(connect_flag=None, num=None)
    if version in ("1.22", "1.31", "1.38"):
        state["gcloud_flag"] = None
    if version in ("1.31", "1.38"):
        state.update(homeid=0, reportflag=None)
    return state


def _timezone_rule(rule, year):
    day, _, hour = rule.partition("/")
    parts = hour.split(":") if hour else ["2"]
    seconds = sum((int(part) & 65535) * unit
                  for part, unit in zip(parts, (3600, 60, 1)))
    first = datetime(year, 1, 1, tzinfo=timezone.utc)
    if day.startswith("M"):
        month, week, weekday = map(int, day[1:].split("."))
        if not 1 <= month <= 12 or not 1 <= week <= 5 or not 0 <= weekday <= 6:
            raise ValueError("invalid POSIX transition")
        start, count = calendar.monthrange(year, month)
        number = 1 + (weekday - (start + 1) % 7) % 7 + 7 * (week - 1)
        if number > count:
            number -= 7
        first = first.replace(month=month, day=number)
    else:
        julian = day.startswith("J")
        number = int(day[1:] if julian else day) & 65535
        if julian:
            number -= 1
            if calendar.isleap(year) and number >= 59:
                number += 1
        first += timedelta(days=number)
    return first.timestamp() + seconds


def _timezone_offset(expression, seconds):
    """The source newlib parser uses POSIX TZ offsets (west is positive)."""
    match = re.match(r":?[^0-9,+-]{1,10}([+-]?)(\d+)(?::(\d+))?(?::(\d+))?(.*)", expression)
    if match is None:
        return None
    sign, hours, minutes, remainder, rest = match.groups()
    standard = sum((int(part or 0) & 65535) * unit
                   for part, unit in zip((hours, minutes, remainder), (3600, 60, 1)))
    if sign == "-":
        standard = -standard
    daylight = re.match(r"[^0-9,+-]{1,10}([+-]?)(\d*)(?::(\d+))?(?::(\d+))?(.*)", rest)
    if daylight is None:
        return -standard
    sign, hours, minutes, remainder, rules = daylight.groups()
    dst = (sum((int(part or 0) & 65535) * unit
               for part, unit in zip((hours, minutes, remainder), (3600, 60, 1)))
           * (-1 if sign == "-" else 1)) if hours else standard - 3600
    rules = rules.removeprefix(",").split(",") if rules else ["M3.2.0", "M11.1.0"]
    if len(rules) != 2:
        raise ValueError("invalid POSIX transitions")
    year = datetime.fromtimestamp(seconds, timezone.utc).year
    start = _timezone_rule(rules[0], year) + standard
    end = _timezone_rule(rules[1], year) + dst
    active = start <= seconds < end if start < end else seconds >= start or seconds < end
    return -dst if active else -standard


def root_value(device, version, state, name):
    if name.startswith("_") or name not in state:
        return ""
    if name in ("mac", "name") and state[name] is None:
        state[name] = device.mac if name == "mac" else device.name
    configured = state["conf"] is True
    if name == "needMqtt" and not configured:
        state[name] = int(version not in ("1.13", "1.16", "1.18") or not any(
            child.profile.handler.category == "filter" for child in device.children))
    elif name == "subList" and not configured:
        # Native cache IDs serialize the six NIC bytes followed by literal 00.
        state[name] = "".join(
            child.mac[:12] + "00|" +
            ("6079" if child.mid in ("608d", "6091", "6099", "60a9") else child.mid) + "#"
            for child in device.children)
    elif name == "GcloudHid":
        state[name] = ""
    elif name == "rssi":
        state[name] = -50
    elif name == "host":
        state[name] = deepcopy(state["dishost"])
    elif name == "ver" and state[name] is None:
        mqtt = root_value(device, version, state, "needMqtt")
        state[name] = ("V3.2.M" if type(mqtt) in (int, float) and mqtt == 1
                       else "V1.1" if version in ("1.13", "1.16", "1.18") else "V2.0.0")
    elif name == "time":
        offset = state["appStdTime"] if version in ("1.31", "1.38") else 0
        seconds = state["_clock_seconds"] + monotonic() - state["_clock_at"]
        if version not in ("1.31", "1.38") and state["_tz"] is not None:
            seconds += _timezone_offset(state["_tz"], seconds) or 0
        elif type(offset) in (int, float):
            seconds += max(-(2**31), min(2**31 - 1, int(offset)))
        state[name] = datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    return deepcopy(state[name])


def root_command(device, version, state, names, values, child_states):
    """Stage the complete batch; callers bound the reply before committing it."""
    effective = []
    for name, value in zip(names, values, strict=True):
        if name.startswith("_") or name not in state:
            effective.append(deepcopy(value))
            continue
        if name in ("dat", "res"):
            if not isinstance(value, dict):
                raise InvalidPacket("WB nested root callback requires an object")
            identity = value.get("mac")
            target = next((child for child in device.children
                           if identity == child.mac[:12] + "00"), None)
            if identity is not None and target is None:
                effective.append(deepcopy(value))
                continue
            if target is not None:
                fields = value.get(name)
                if not isinstance(fields, dict):
                    raise InvalidPacket("WB nested root callback requires named fields")
                staged = child_states.get(target.mac, reported_state(device, target))
                shared = child_states.get("_shared", device.state.get("_wb_shared"))
                if name == "res":
                    staged = stage_command(replace(target, state=staged), list(fields),
                                           list(fields.values()), shared)
                else:
                    for field in fields:
                        raw_value(target, field, staged)
                child_states[target.mac] = staged
                child_states["_shared"] = {field: staged[field] for field in SHARED_FIELDS}
            effective.append(root_value(device, version, state, name))
            continue
        if name == "key":
            if (not isinstance(value, list) or len(value) != 2
                    or any(not isinstance(key, str) or not key.isascii() or len(key) != 16
                           for key in value)):
                raise InvalidPacket("WB root key requires two 16-byte ASCII keys")
        if name == "time":
            now = monotonic()
            seconds = state["_clock_seconds"] + now - state["_clock_at"]
            try:
                desired = datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(
                    tzinfo=timezone.utc).timestamp() if isinstance(value, str) else None
            except ValueError:
                desired = None
            if desired is None or datetime.fromtimestamp(seconds, timezone.utc).year < 1952:
                effective.append(deepcopy(value))
                continue
            if version in ("1.31", "1.38"):
                state["_clock_seconds"], state["_clock_at"] = desired, now
            elif abs(int(seconds - desired)) <= 86399:
                delta = int(seconds - desired)
                hours = abs(delta) // 3600 * (-1 if delta < 0 else 1)
                zone = f"APPST{hours:+2d}:{abs(delta) % 3600 // 60:02d}:{abs(delta) % 60:02d}"
                state["appStdTime"], state["_tz"] = zone, zone
            else:
                effective.append(deepcopy(value))
                continue
            effective.append(root_value(device, version, state, name))
            continue
        if name == "appStdTime":
            valid = (type(value) in (int, float) if version in ("1.31", "1.38")
                     else isinstance(value, str))
            if not valid:
                effective.append(deepcopy(value))
                continue
            if version not in ("1.31", "1.38"):
                try:
                    offset = _timezone_offset(value, state["_clock_seconds"])
                except (ValueError, OverflowError):
                    raise InvalidPacket("invalid WB root POSIX timezone") from None
                if offset is not None:
                    state["_tz"] = value
        if name in ("wlan", "svr", "loginRes"):
            # Model the local event post, never cloud delivery or a network reset.
            state["_event"] = {"wlan": 0x10, "svr": 0x80, "loginRes": 0x100}[name]
            if name == "wlan":
                state["conf"] = True
            effective.append(root_value(device, version, state, name))
            continue
        if name == "upgrade":
            if (not isinstance(value, dict) or not isinstance(value.get("mac"), str)
                    or not isinstance(value.get("url"), str)
                    or value["mac"] not in (state["mac"], "1", "5")):
                effective.append(deepcopy(value))
                continue
            state["_event"] = 0x13
            if value["mac"] == "5" and "ver" in value:
                state["gcldhidownver"] = deepcopy(value["ver"])
            effective.append(root_value(device, version, state, name))
            continue
        if name == "conf" and value is True:
            state["_event"] = 0x10
        state[name] = deepcopy(value)
        effective.append(root_value(device, version, state, name))
    return effective
