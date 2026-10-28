"""Exact-source WB05RT13 V1.10 ECB runtime with bounded synthetic backing."""


from ..wire import InvalidPacket, decode_pack
from . import Profile, simulated, wb_raw
from .wb_rt13_legacy import (BUFFER_BYTES, CODEC, GENERIC_KEY, SCAN_KEY,
                             LegacyRT13Handler, packed_reply as _packed_reply,
                             reply as _reply, source_integer as _integer,
                             source_number, source_number_has_suffix)


SOURCE_SHA256 = "caa7f0ac2ba63b7ecd4aef0073ba5d21b2f06b53f2b13ae04d8f2948b07a766e"
HID = "362001065279+U-WB05RT13V1.10.bin"
MID_FALLBACK = "10001"
CONTROLS = wb_raw.RT13_110_FIELDS - wb_raw.LOCAL_FIELDS - {"FaultDisplay"}
OPERATIONS = frozenset(("bind", "status", "cmd", "upgrade", "setT", "queryT",
                        "deleteT", "updateT", "dump"))

# AC controls and local metadata are explicit emulator policy, not hardware readback.
INITIAL_STATE = {name: value for name, value in simulated.INITIAL_STATE.items()
                 if name in CONTROLS}



def _columns(value):
    if (not isinstance(value, list) or len(value) > 128
            or any(not isinstance(name, str) or not name or "\0" in name for name in value)):
        raise InvalidPacket("invalid WB05RT13 V1.10 property array")
    try:
        size = sum(len(name.encode("utf-8")) + 1 for name in value)
    except UnicodeError as exc:
        raise InvalidPacket("invalid WB05RT13 V1.10 property array") from exc
    if size >= 512:
        raise InvalidPacket("invalid WB05RT13 V1.10 property array")
    return value




def _text(value, capacity):
    if not isinstance(value, str) or "\0" in value:
        raise InvalidPacket("WB05RT13 V1.10 operation requires bounded text")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError as exc:
        raise InvalidPacket("WB05RT13 V1.10 operation requires bounded text") from exc
    if size >= capacity:
        raise InvalidPacket("WB05RT13 V1.10 operation requires bounded text")
    return value


def _metadata(device, *, fault_display=True):
    values = wb_raw.metadata(device, fault_display=fault_display)
    # Both exact builds read distinct metadata RAM; empty is the bounded synthetic baseline.
    values["mid"] = ""
    return values


def _stage_command(device, columns, values, fields):
    try:
        staged = wb_raw.stage_command(device, columns, values, fields, clock=True)
        client = staged.get("_wb_report_client")
        if client is not None:
            client = client.encode("utf-8")
    except UnicodeError as exc:
        raise InvalidPacket("WB05RT13 V1.10 command requires valid UTF-8 text") from exc
    if client is not None:
        if len(client) > 26:
            raise InvalidPacket("WB05RT13 V1.10 ReportClientID exceeds its 30-byte target")
        staged["_wb_report_client_target"] = b"\x7e\x7e\x12\x6a" + client.ljust(26, b"\0")
        staged["_wb_report_client_enabled"] = 1
    return staged


def _target(device, inner):
    for selector in ("mac", "sub"):
        if selector in inner:
            value = _text(inner[selector], 32)
            if value != device.mac:
                raise InvalidPacket("conflicting WB05RT13 V1.10 inner identity")


def _command_values(inner, names):
    values = inner.get("p")
    if not isinstance(values, list) or len(values) != len(names) or len(values) > 128:
        raise InvalidPacket("WB05RT13 operation requires parallel property values")
    parsed = []
    previous_suffix = False
    for name, value in zip(names, values):
        if previous_suffix:
            raise InvalidPacket("legacy RT13 numeric suffix prevents the next array value")
        parsed.append(value if name in wb_raw.LOCAL_COMMAND_FIELDS and name != "AppTimer"
                      else _integer(value))
        previous_suffix = source_number_has_suffix(value)
    return parsed


def _timer_record(inner, *, include_name=True):
    record = {"id": 0, "enable": 0, "week": [0] * 7,
              "hr": 0, "min": 0, "sec": 0, "power": 0}
    if include_name:
        record["name"] = ""
    try:
        record["id"] = _integer(inner.get("id")) & 255
        if include_name:
            record["name"] = _text(inner.get("name"), 0x20)
        record["enable"] = int(_integer(inner.get("enable")) == 1)
        _integer(inner.get("tz"))
        record["hr"] = _integer(inner.get("hr")) & 255
        record["min"] = _integer(inner.get("min")) & 255
        if "sec" in inner:
            record["sec"] = _integer(inner["sec"]) & 255
        week = inner.get("week")
        if not isinstance(week, list) or len(week) != 7:
            raise InvalidPacket("WB05RT13 timer requires seven numeric weekdays")
        mask = 0
        previous_suffix = False
        for bit, value in enumerate(week):
            if previous_suffix:
                raise InvalidPacket("legacy RT13 numeric suffix prevents the next array value")
            mask |= (_integer(value) << bit) & 255
            record["week"] = [(mask >> position) & 1 for position in range(7)]
            previous_suffix = source_number_has_suffix(value)
        if previous_suffix:
            raise InvalidPacket("legacy RT13 numeric suffix leaves the array unclosed")
        commands = inner.get("cmd")
        if (not isinstance(commands, list) or not commands
                or not isinstance(commands[0], dict)):
            raise InvalidPacket("WB05RT13 timer requires a command array")
        options, values = commands[0].get("opt"), commands[0].get("p")
        if (not isinstance(options, list) or not isinstance(values, list)
                or len(options) != len(values) or len(options) > 32
                or any(not isinstance(name, str) or "\0" in name for name in options)):
            raise InvalidPacket("invalid WB05RT13 timer command arrays")
        previous_suffix = False
        for name, value in zip(options, values):
            if previous_suffix:
                raise InvalidPacket("legacy RT13 numeric suffix prevents the next array value")
            parsed_value = _integer(value)
            if name == "Pow":
                record["power"] = parsed_value & 255
            previous_suffix = source_number_has_suffix(value)
    except InvalidPacket:
        # setT/updateT log this parser failure but still call their native mutator.
        pass
    return record


def legacy_operation(device, inner, kind, index, uid, peer, *, fields=None,
                     include_timer_name=True, fault_display=True,
                     empty_fields=wb_raw.EMPTY_FIELDS,
                     local_read_fields=wb_raw.LOCAL_COMMAND_FIELDS):
    fields = fields or wb_raw.RT13_110_FIELDS
    if kind == "bind":
        try:
            mac = _text(inner.get("mac"), 0x20)
        except InvalidPacket:
            mac = device.mac
        return [_reply(device, {"r": 200, "t": "bindok", "mac": mac,
                                "key": device.key.decode("ascii")}, index, uid, peer)]

    if kind == "status":
        _target(device, inner)
        columns = _columns(inner.get("cols", inner.get("opt")))
        staged = {}
        if "cols" not in inner:
            values = _command_values(inner, columns)
            staged = _stage_command(device, columns, values, fields) if columns else {}
        metadata = _metadata(device, fault_display=fault_display)
        metadata["time"] = staged.get("_wb_time", metadata["time"])
        selected, values = wb_raw.status(device, columns, metadata, fields, staged,
                                         empty=empty_fields)
        reply = _reply(device, {"t": "dat", "uid": uid, "mac": device.mac,
                                "cid": device.mac, "dat": values,
                                "cols": selected, "r": 200}, index, uid, peer)
        if staged:
            device.state.update(staged)
        return [reply]

    if kind == "cmd":
        _target(device, inner)
        columns = _columns(inner.get("cols", inner.get("opt")))
        if "cols" in inner:
            if any(name not in fields | local_read_fields for name in columns):
                raise InvalidPacket("unsupported WB05RT13 read field")
            metadata = _metadata(device, fault_display=fault_display)
            values = [metadata.get(name, device.state.get(name, 0)) for name in columns]
            staged = {}
        else:
            values = _command_values(inner, columns)
            staged = _stage_command(device, columns, values, fields) if columns else {}
        columns, values = wb_raw.command_response(
            device, columns, values, staged, fault_display=fault_display,
            current=_metadata(device, fault_display=fault_display),
            local_fields=local_read_fields)
        reply = _reply(device, {"t": "res", "mac": device.mac,
                                "p": values, "opt": columns, "r": 200},
                       index, uid, peer)
        device.state.update(staged)
        return [reply]

    if kind == "upgrade":
        url = _text(inner.get("url"), 0x78)
        reply = _reply(device, {"t": "ret", "r": 200}, index, uid, peer)
        # Captures the native OTA dispatch request only; no network or flash action is claimed.
        device.state["_wb_upgrade_url"] = url
        return [reply]

    if kind in ("setT", "updateT"):
        timers = device.state.get("_wb_timers", {})
        count = device.state.get("_wb_timer_count", len(timers))
        if kind == "setT" and count >= 10:
            raise InvalidPacket("WB05RT13 V1.10 timer table is full")
        if kind == "setT":
            identifier = _integer(inner.get("id")) & 255
            if identifier in timers:
                raise InvalidPacket("WB05RT13 V1.10 timer ID already exists")
            record = _timer_record(inner, include_name=include_timer_name)
            record["id"] = identifier
            updated = dict(timers)
            updated[identifier] = record
            next_count = count + 1
        else:
            record = _timer_record(inner, include_name=include_timer_name)
            identifier = record["id"]
            updated = dict(timers)
            if identifier in updated:
                updated[identifier] = record
            next_count = count
        reply = _reply(device, {"t": "resT", "r": 200}, index, uid, peer)
        device.state["_wb_timers"] = updated
        device.state["_wb_timer_count"] = next_count
        return [reply]

    if kind == "queryT":
        start, count = (_integer(inner.get(name)) for name in ("index", "count"))
        # shortcut: reject wrapped negative scans until native traversal can be bounded.
        if start < 0:
            raise InvalidPacket("negative WB05RT13 V1.10 timer index is unsafe")
        timers = device.state.get("_wb_timers", {})
        total = device.state.get("_wb_timer_count", len(timers))
        stop = min(10, start + max(0, count))
        rows = []
        for slot in range(start, stop):
            timer = timers.get(slot)
            if timer is not None:
                row = {"id": timer["id"], "enable": timer["enable"],
                       "week": list(timer["week"]), "hr": timer["hr"],
                       "min": timer["min"], "sec": timer["sec"],
                       "cmd": {"mac": [device.mac], "opt": ["Pow"],
                               "p": [timer["power"]]}}
                if include_timer_name:
                    row["name"] = timer["name"]
                rows.append(row)
        return [_reply(device, {"t": "listT", "total": total, "index": start,
                               "list": rows}, index, uid, peer)]

    if kind == "deleteT":
        identifier = _integer(inner.get("id")) & 255
        timers = dict(device.state.get("_wb_timers", {}))
        timers.pop(identifier, None)
        reply = _reply(device, {"t": "resT", "r": 200}, index, uid, peer)
        device.state["_wb_timers"] = timers
        device.state["_wb_timer_count"] = len(timers)
        return [reply]

    if kind == "dump":
        period, count = (_integer(inner.get(name)) for name in ("period", "cnt"))
        period = 60 if period < 1 else max(5, min(4096, period))
        reply = _reply(device, {"t": "ret", "r": 200}, index, uid, peer)
        device.state["_wb_dump"] = {
            "period": period, "cnt": max(1, count), "enabled": True}
        return [reply]

    return []


class WB05RT13V110(LegacyRT13Handler):


    # Synthetic scan labels are policy; the MID models only the conditional case-4 fallback.
    def advertise(self, device, outer):
        inner = {"t": "dev", "cid": device.mac, "bc": "", "brand": "gree", "catalog": "gree",
                 "mac": device.mac, "mid": device.mid or MID_FALLBACK,
                 "model": "gree", "name": device.name,
                 "lock": 0, "series": "gree", "vender": "1", "ver": "V1.10"}
        return [_packed_reply({"t": "pack", "i": 1, "uid": 0, "cid": "", "tcid": ""},
                              inner, SCAN_KEY)]

    def handle(self, device, outer):
        if outer.get("t") != "pack" or outer.get("tcid") != device.mac:
            raise InvalidPacket("wrong WB05RT13 V1.10 target")
        if any(name not in outer for name in ("i", "uid", "cid", "pack")):
            raise InvalidPacket("incomplete WB05RT13 V1.10 pack route")
        index = outer["i"]
        uid = outer["uid"]
        peer = outer["cid"]
        if (type(index) is not int or index not in (0, 1)
                or type(uid) is not int or not -(1 << 31) <= uid < (1 << 32)
                or not isinstance(peer, str)):
            raise InvalidPacket("invalid WB05RT13 V1.10 key selector or route")
        peer = _text(peer, 0x40)
        uid &= 0xffffffff
        inner = decode_pack(outer, GENERIC_KEY if index else device.key, CODEC,
                            number_parser=source_number)
        kind = inner.get("t")
        if not isinstance(kind, str) or kind not in OPERATIONS:
            return []
        return legacy_operation(device, inner, kind, index, uid, peer)


HANDLER = WB05RT13V110()
PROFILES = (Profile(id="sim-wb05rt13-v1.10", mids=(MID_FALLBACK,), hid=HID,
                    source_sha256=SOURCE_SHA256, initial_state=INITIAL_STATE,
                    handler=HANDLER, max_request_bytes=BUFFER_BYTES),)
