"""Source-qualified RT13 and WB04A LAN operations; queues are synthetic.

No network download, firmware flashing, UART delivery or calibrated RTC is
performed. Native unsafe pointer/buffer paths are rejected, never fake-ACKed.
"""
import base64
import binascii
from itertools import islice
import re

from ..wire import InvalidPacket
from . import wb_raw
from .wb_rt13_legacy import (source_integer, source_number_has_suffix,
                             source_values)


RT13_V145_SHA256 = "2f12c03c97e4e7302acbc8ee72cda18e31e7d9843519d5a3fb1bdcb1a4f2ffec"
RT13_V145_OPERATIONS = frozenset((
    "freqCount", "upgrade", "setT", "queryT", "deleteT", "updateT", "dump",
    "ReportCtrl", "binCmd", "reset",
))
SOURCES = frozenset((
    RT13_V145_SHA256,
    "86799311e40abaa97be624e11d8e16c45cafb7dd113b8b690728d075d77c8a39",
    "c4b744a28a5a6b2d2d7ace4a0a2845a336ce629a72367af41bde708f0bd1dbc1",
    "e1d186072abfd51e71874fe6904cca132f22e6ebaaef9a0cac39f59de7194105",
    "c9e8d4b563f7573c553d5004809080ed53b66d5d1533c76f7c877fcc79242b46",
))
OPERATIONS = frozenset(("setT", "updateT", "deleteT", "queryT", "dump", "Ackup",
                        "ReportCtrl", "freqCount", "binCmd", "upgrade", "reset"))
WB04_SOURCE_SHA256 = "0d5ee6fda1678084e1fa29e6267941afae304090b5b97f7b4264f9cee7fd461b"
WB04_OPERATIONS = frozenset(("freqCount", "upgrade", "setT", "queryT", "deleteT", "updateT"))


def supports(source_sha256, kind):
    if not isinstance(kind, str):
        return False
    if source_sha256 == RT13_V145_SHA256:
        return kind in RT13_V145_OPERATIONS
    return source_sha256 in SOURCES and kind in OPERATIONS


def _wb04_columns(inner):
    names = inner.get("cols")
    if isinstance(names, list):
        return names, True
    return inner.get("opt"), False


def _integer(value):
    return source_integer(value)


def _text(value, maximum):
    if not isinstance(value, str) or "\0" in value or len(value.encode()) > maximum:
        raise InvalidPacket("WB operation requires bounded text")
    return value


def stage_v145_report_client(device, staged):
    if device.profile.source_sha256 == RT13_V145_SHA256 and "_wb_report_client" in staged:
        client = _text(staged["_wb_report_client"], 26)
        encoded = client.encode()
        frame = bytearray(30)
        frame[:4] = b"~~\x12\x6a"
        frame[4:4 + len(encoded)] = encoded
        staged.update(_wb_report_client=client, _wb_report_client_frame=list(frame),
                      _wb_report_client_set=1)


def _timer(inner, *, wb04=False, v145=False):
    identifier = _integer(inner.get("id")) & 255
    name = _text(inner.get("name"), 31)
    enabled = int(_integer(inner.get("enable")) == 1)
    _integer(inner.get("tz"))  # Required by the source parser, not retained in listT.
    hour, minute = (_integer(inner.get(field)) & 255 for field in ("hr", "min"))
    second = 0
    if "sec" in inner:
        second = _integer(inner["sec"]) & 255 if v145 else 0
    elif not v145:
        # This older parser reuses min when optional sec is absent.
        second = minute
    week = inner.get("week")
    if not isinstance(week, list) or len(week) != 7:
        raise InvalidPacket("WB timer requires seven weekday integers")
    mask = 0
    previous_suffix = False
    for position, value in enumerate(week):
        if previous_suffix:
            raise InvalidPacket("legacy RT13 numeric suffix prevents the next weekday")
        previous_suffix = source_number_has_suffix(value)
        mask |= (_integer(value) << position) & 255
    if v145 and previous_suffix:
        raise InvalidPacket("legacy RT13 numeric suffix leaves the weekday array unclosed")
    if wb04:
        command = inner.get("cmd")
        if not isinstance(command, dict):
            raise InvalidPacket("WB04 timer requires a nested command object")
    else:
        commands = inner.get("cmd")
        if not isinstance(commands, list) or not commands or not isinstance(commands[0], dict):
            raise InvalidPacket("WB timer requires a command object")
        command = commands[0]
    options, values = command.get("opt"), command.get("p")
    # WB04's native p-value scratch array has 32 entries.
    if (not isinstance(options, list) or not isinstance(values, list)
            or len(options) != len(values) or len(options) > (32 if wb04 else 64)
            or any(not isinstance(option, str) or "\0" in option
                   or v145 and not option for option in options)
            or v145 and sum(len(option.encode()) + 1 for option in options) >= 512):
        raise InvalidPacket("invalid WB timer command arrays")
    power = 0
    previous_suffix = False
    for option, value in zip(options, values):
        if previous_suffix:
            raise InvalidPacket("legacy RT13 numeric suffix prevents the next timer command value")
        previous_suffix = source_number_has_suffix(value)
        value = _integer(value)
        if option == "Pow":
            power = value & 255
    return {"id": identifier, "name": name, "enable": enabled,
            "week": [(mask >> bit) & 1 for bit in range(7)],
            "hr": hour, "min": minute, "sec": second, "power": power}


def _version(value):
    text = _text(value, 8)
    match = re.fullmatch(r"(?:V)?([0-9]+)(?:\.([0-9]+))?", text)
    if not match:
        raise InvalidPacket("invalid WB OTA version")
    return int(match[1]) * 100 + int(match[2] or 0)


def operation(device, inner, *, raw_fields=wb_raw.RT13_FIELDS, clock=True):
    kind = inner["t"]
    source = device.profile.source_sha256
    v145 = source == RT13_V145_SHA256
    if kind in ("setT", "updateT", "deleteT", "queryT"):
        wb04 = device.profile.source_sha256 == WB04_SOURCE_SHA256
        timers = device.state.get("_wb_timers", {})
        count = device.state.get("_wb_timer_count", 0)
        if kind == "queryT":
            index, limit = _integer(inner.get("index")), _integer(inner.get("count"))
            if index < 0:
                raise InvalidPacket("negative WB timer indices are unsafe in the native loop")
            entries = []
            if wb04:
                stop = max(index, min(10, index + max(0, limit)))
                timer_rows = islice(timers.values(), index, stop)
            else:
                stop = min(10, index + max(0, limit))
                timer_rows = (timers[identifier] for identifier in range(index, stop)
                              if identifier in timers)
            for timer in timer_rows:
                entries.append({name: timer[name] for name in ("id", "name", "enable", "week", "hr", "min", "sec")})
                entries[-1]["cmd"] = {"mac": [device.mac], "opt": ["Pow"], "p": [timer["power"]]}
            return {"t": "listT", "total": count, "index": index, "list": entries}, {}
        if kind == "deleteT":
            identifier = _integer(inner.get("id")) & 255
            updated = dict(timers)
            updated.pop(identifier, None)
            # Native decrements the byte count even when lookup finds no such ID.
            return {"t": "resT", "r": 200}, {"_wb_timers": updated, "_wb_timer_count": (count - 1) & 255}
        if kind == "setT" and count >= 10:
            return None, {}
        timer = _timer(inner, wb04=wb04, v145=v145)
        updated = dict(timers)
        if kind == "setT" or timer["id"] in timers:
            updated[timer["id"]] = timer
        return {"t": "resT", "r": 200}, {"_wb_timers": updated,
                "_wb_timer_count": (count + int(kind == "setT" and timer["id"] not in timers)) & 255}
    if kind == "dump":
        period, count = _integer(inner.get("period")), _integer(inner.get("cnt"))
        period = 60 if period < 1 else max(5, min(4096, period))
        return {"t": "ret", "r": 200}, {"_wb_dump": {"period": period, "cnt": max(1, count)}}
    if kind == "Ackup":
        if "OTAType" in inner:
            _integer(inner["OTAType"])
        if "code" in inner:
            _text(inner["code"], 12)
        # Receipt is acknowledged by the source independently of an actual update.
        return {"t": "ret", "r": 200}, {"_wb_ota_ack": dict(inner)}
    if kind == "upgrade":
        if v145:
            url = _text(inner.get("url"), 119)
            return {"t": "ret", "r": 200}, {"_wb_ota_queue": {"url": url}}
        if source == WB04_SOURCE_SHA256:
            _text(inner.get("url"), 119)
            # Native starts an OTA request; synthetic devices must not access the network.
            return {"t": "ret", "r": 200}, {}
        if device.state.get("_wb_upgrade_status", 0):
            return None, {}
        versions, urls, codes = (inner.get(field) for field in ("OTAVer", "OTAUrl", "OTACode"))
        if (not isinstance(versions, list) or not isinstance(urls, list)
                or not isinstance(codes, list) or not 1 <= len(versions) <= 2
                or len(versions) != len(urls) or len(versions) != len(codes)):
            raise InvalidPacket("WB upgrade requires matching bounded version/url/code arrays")
        rows = [(_version(version), _text(url, 149), _text(code, 12))
                for version, url, code in zip(versions, urls, codes)]
        current = _version(device.profile.hid.split("V", 1)[1].removesuffix(".bin"))
        root_code = device.profile.hid.split("+", 1)[0]
        board_code = device.state.get("_wb_companion_code", "")
        board_version = device.state.get("_wb_companion_version", 0)
        for version, url, code in rows:
            if (code == root_code and version > max(current, device.state.get("_wb_server_version", 0))
                    or board_code and code == board_code and version // 100 > board_version):
                return {"t": "ret", "r": 200}, {"_wb_ota_queue": {"code": code, "version": version, "url": url},
                                                  "_wb_upgrade_status": 16387}
        return None, {"_wb_upgrade_status": 16387}
    if kind == "binCmd":
        encoded = _text(inner.get("hex01", inner.get("hex15")), 80 if v145 else 1023)
        try:
            frame = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise InvalidPacket("invalid WB binary base64") from exc
        length = frame[2] + 2 if len(frame) >= 3 else 0
        if (len(frame) < (3 if v145 else 8) or frame[:2] != b"~~"
                or length > min(60, len(frame)) or not v145 and length < 8):
            raise InvalidPacket("unsafe WB mainboard frame")
        staged = {}
        if "ReportClientID" in inner:
            if v145:
                staged["_wb_report_client"] = inner["ReportClientID"]
                stage_v145_report_client(device, staged)
            else:
                staged["_wb_report_client"] = _text(inner["ReportClientID"], 63)
        outgoing = frame[:length] if v145 else bytearray(60)
        if not v145:
            outgoing[:length] = frame[:length]
            outgoing[43] |= 2
        if "ReportFreq" in inner:
            if v145:
                requested = _integer(inner["ReportFreq"])
                current = device.state.get("_wb_report_frequency", 0)
                if (requested & 0xffffffff) != current:
                    frequency = 300 if requested == 255 else requested & 65535
                    staged["_wb_report_frequency"] = frequency
                    staged["_wb_report_frequency_word"] = (frequency + 16384) & 65535
            else:
                frequency = _integer(inner["ReportFreq"])
                staged["_wb_report_frequency"] = 300 if frequency == 255 else frequency & 65535
                outgoing[7] = 0
        elif not v145 and outgoing[3] == 1:
            outgoing[7] = 175
        staged["_wb_uart_frame"] = list(outgoing)
        return {"t": "res", "r": 200}, staged
    if kind == "ReportCtrl":
        reporting = dict(device.state.get("_wb_reporting", {}))
        prefix = device.state.get("_wb_report_client", "request/" + device.mac).partition("/")[0]
        old_active = (reporting.get("request", {}).get("ActiveTime", 0)
                      or reporting.get("homeAlive", {}).get("ActiveTime", 0) or 1)
        old_interval = next((reporting.get(prefix, {}).get("ReportInterval", 0)
                             for prefix in ("request", "midSetting", "homeAlive")
                             if reporting.get(prefix, {}).get("ReportInterval", 0)), 1)
        active_value, interval_value = inner.get("ActiveTime"), inner.get("ReportInterval")
        if v145:
            try:
                active = _integer(active_value)
            except InvalidPacket:
                active = 5 if old_active == 1 else old_active
            try:
                interval = _integer(interval_value)
            except InvalidPacket:
                interval = 10 if old_interval == 1 else old_interval
        else:
            active = _integer(inner.get("ActiveTime", 5 if old_active == 1 else 0))
            interval = _integer(inner.get("ReportInterval", 10 if old_interval == 1 else 0))
        if prefix in ("request", "homeAlive", "midSetting"):
            reporting[prefix] = {"ReportInterval": interval,
                                 **({"ActiveTime": active} if prefix != "midSetting" else {})}
        staged = {"_wb_reporting": reporting,
                  "_wb_report_active_word": (active * 60 + 16384) & 65535}
        if v145:
            if type(inner.get("reportAnyway")) is bool:
                staged["_wb_report_state"] = 2 if inner["reportAnyway"] else 1
        else:
            if "reportAnyway" in inner and type(inner["reportAnyway"]) is not bool:
                raise InvalidPacket("WB reportAnyway requires a JSON boolean")
            staged["_wb_report_state"] = 2 if inner.get("reportAnyway") else 1
        return None, staged
    if kind == "freqCount":
        wb04 = device.profile.source_sha256 == WB04_SOURCE_SHA256
        if wb04:
            names, read_mode = _wb04_columns(inner)
            values = None if read_mode else inner.get("p")
        else:
            names, values = inner.get("opt", inner.get("cols")), inner.get("p")
            if v145:
                values = source_values(values)
            read_mode = False
        if (not isinstance(names, list)
                or (not read_mode and
                    (not isinstance(values, list) or len(names) != len(values)))
                or wb04 and len(names) > 128
                or wb04 and any(not isinstance(name, str) or not name or "\0" in name
                                or not name.isascii() or len(name) >= 32 for name in names)
                or v145 and (len(names) > 64
                             or any(not isinstance(name, str) or not name or "\0" in name
                                    for name in names)
                             or sum(len(name.encode()) + 1 for name in names) >= 512)):
            raise InvalidPacket("WB frequency command requires matching bounded arrays")
        staged = {}
        excluded = ("SendFreq", "FreqTime") if wb04 else ("SendFreq", "FreqTime", "DRTime")
        if not read_mode:
            ordinary = [(name, values[index]) for index, name in enumerate(names)
                        if name not in excluded]
            if ordinary:
                staged.update(wb_raw.stage_command(device, [name for name, value in ordinary],
                                                   [value for name, value in ordinary], raw_fields,
                                                   clock=clock))
        if v145:
            stage_v145_report_client(device, staged)
        for index, name in enumerate(names):
            if wb04:
                value = 0 if read_mode else _integer(values[index])
                if name == "SendFreq" and value == 1:
                    staged["_wb_send_freq_pending"] = 1
                elif name == "FreqTime":
                    value &= 65535
                    value = value - 65536 if value & 32768 else value
                    staged["_wb_frequency_timer_word"] = (value + 16384) & 65535
            elif name in ("SendFreq", "FreqTime", "DRTime"):
                value = _integer(values[index])
                staged["_wb_" + name] = value
        return None, staged
    if kind == "reset" and v145:
        mac = _text(inner.get("mac"), 12)
        if not mac:
            raise InvalidPacket("WB reset requires a MAC string")
        staged = {"_wb_reset_flag": 1}
        if mac == device.mac:
            # Native sets the flag before the unresolved match-only string-pointer path.
            return None, staged
        return {}, staged
    # Other RT13 reset serializers point at an unresolved ROM string.
    return None, {}
