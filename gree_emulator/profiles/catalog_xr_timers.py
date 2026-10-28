"""063967/source074938b9 bounded timer list and local UTC scheduler.

Original primary 0x1430700/0x142ada0/0x1430954/0x142aabc and contained
cJSON ABI are qualified in catalog-xr-timers_research.json. The parent owns
routing, atomic pending-state commits, device-key encryption and cached reply i.
Timer output is a synthetic six-byte mainboard-facing register, NOT Pow/cache
readback: the reachable scheduler never calls the root command dispatcher.
"""
from datetime import datetime, timezone

from ..wire import InvalidPacket


OPERATIONS = frozenset(("setT", "updateT", "deleteT", "queryT"))
_CLOCK_THRESHOLD = 0x5b03b45b
_OFF = [23, 59, 59, 23, 59, 59]


def _member(value, name, default=None):
    if not isinstance(value, dict):
        raise InvalidPacket("XR timer requires an object")
    for key, item in value.items():
        if isinstance(key, str) and key.lower() == name:
            return item
    return default


def _integer(value, name):
    # Safe boundary: reject cJSON's untyped valueint coercion and undefined casts.
    if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
        raise InvalidPacket(f"invalid XR timer {name}")
    return value


def _string(value, name, maximum=1023):
    if not isinstance(value, str) or "\0" in value:
        raise InvalidPacket(f"invalid XR timer {name}")
    try:
        length = len(value.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise InvalidPacket(f"invalid XR timer {name}") from error
    if length > maximum:
        raise InvalidPacket(f"unsafe XR timer {name} length")
    return value


def _array(value, name, maximum):
    if not isinstance(value, list) or len(value) > maximum:
        raise InvalidPacket(f"unsafe XR timer {name} array")
    return value


def _signed(value):
    value &= 0xffffffff
    return value if value < 0x80000000 else value - 0x100000000


def _remaining(seconds, clock, valid):
    return _signed(seconds - int(clock) % 86400) if valid else 0


def _record(request, clock, valid):
    seconds = sum(_integer(_member(request, key), key) * scale
                  for key, scale in (("hr", 3600), ("min", 60), ("sec", 1))) & 0xffffffff
    week = [_integer(value, "week") for value in
            _array(_member(request, "week", []), "week", 7)]
    commands = []
    for item in _array(_member(request, "cmd"), "cmd", 10):
        macs = [_string(value, "mac") for value in
                _array(_member(item, "mac", []), "mac", 10)]
        options = _member(item, "opt")
        if not isinstance(options, list) or not options:
            raise InvalidPacket("XR timer requires a first opt")
        option = _string(options[0], "opt")
        parameters = [_integer(value, "p") for value in
                      _array(_member(item, "p", []), "p", 30)]
        # Original stores up to30 values but hardcodes optcount1 at query/output.
        commands.append({"mac": macs, "opt": [option], "p": [parameters[0] if parameters else 0]})
    if not commands:
        raise InvalidPacket("XR timer empty cmd would fault on one-shot expiration")
    return {
        "id": _integer(_member(request, "id"), "id") & 255,
        "name": _string(_member(request, "name"), "name", 19),
        "enable": int(_integer(_member(request, "enable"), "enable") != 0),
        "_seconds": seconds,
        "_remaining": _remaining(seconds, clock, valid),
        "week": week + [0] * (7 - len(week)),
        "tz": _integer(_member(request, "tz"), "tz") & 255,
        "cmd": commands,
    }


def _replacement(previous, record):
    # Original reuses old allocations, and memcpy(p,newp,oldoptcount) copies ONE
    # BYTE, not one int32. Reject native pointer/string overflows atomically.
    if len(record["cmd"]) > len(previous["cmd"]):
        raise InvalidPacket("unsafe XR timer replacement cmd growth")
    for old, new in zip(previous["cmd"], record["cmd"]):
        if (len(new["mac"]) > len(old["mac"])
                or len(new["opt"][0].encode()) > len(old["opt"][0].encode())
                or any(len(value.encode()) > len(before.encode())
                       for before, value in zip(old["mac"], new["mac"]))):
            raise InvalidPacket("unsafe XR timer replacement allocation growth")
        new["p"][0] = _signed((old["p"][0] & 0xffffff00) | (new["p"][0] & 255))
    return record


def _query_record(record):
    seconds = record["_seconds"]
    return {
        "id": record["id"], "name": record["name"], "enable": record["enable"],
        "hr": seconds // 3600, "min": seconds % 3600 // 60, "sec": seconds % 60,
        "week": record["week"].copy(),
        "cmd": [{"mac": command["mac"].copy(), "opt": command["opt"].copy(),
                 "p": command["p"].copy()} for command in record["cmd"]],
    }


def handle_timer(device, state, request):
    """Return the exact inner timer reply, or None for a source-silent branch.

    All validation precedes mutation, including replacements. The parent bounds
    the eventual reply before committing its pending per-device state. Storage is
    in-memory only; no hardware flash or process-restart persistence is claimed.
    """
    operation = _member(request, "t")
    if not isinstance(operation, str) or operation not in OPERATIONS:
        return None
    records = state.get("_timers", [])
    if operation == "queryT":
        index = _integer(_member(request, "index"), "index") & 255
        count = _integer(_member(request, "count"), "count") & 255
        response = {"t": "listT", "total": count, "index": index}
        if records:
            response["list"] = [_query_record(record) for record in records[index:index + count + 1]]
        return response
    identifier = _integer(_member(request, "id"), "id") & 255
    position = next((index for index, record in enumerate(records)
                     if record["id"] == identifier), None)
    if operation == "deleteT":
        if position is None:
            return {"t": "resT", "r": 200}
        del records[position]
    else:
        clock = state.get("_clock", 0)
        valid = state.get("_timer_clock_valid", clock > _CLOCK_THRESHOLD)
        record = _record(request, clock, valid)
        if position is None:
            if len(records) == 10:
                return {"t": "resT", "r": 500} if operation == "setT" else None
            records = [*records, record]
        else:
            record = _replacement(records[position], record)
            records = [*records[:position], record, *records[position + 1:]]
        # Native flash window is <0x2000 and may overrun its last write; keep the
        # entire serialized list in bounds before committing any replacement.
        size = sum(0x40 + sum(0x7a + len(command["opt"][0].encode()) + 1
                             + sum(len(mac.encode()) + 1 for mac in command["mac"])
                             for command in item["cmd"]) for item in records)
        if size > 0x2000:
            return {"t": "resT", "r": 500} if operation == "setT" else None
        if not record["enable"] and record["_remaining"] < 0:
            state["_timer_output"] = _OFF.copy()
    state["_timers"] = records
    return {"t": "resT", "r": 200}


def refresh_clock(state, current_clock):
    """Original explicit time setter/midnight refresh of every relative counter."""
    valid = current_clock > _CLOCK_THRESHOLD
    state["_timer_clock_valid"] = valid
    for record in state.get("_timers", []):
        record["_remaining"] = _remaining(record["_seconds"], current_clock, valid)


def _advance_record(record, state, first, ticks, weekday):
    if record["enable"]:
        return
    repeating = any(record["week"])
    if repeating and not record["week"][weekday]:
        return
    remaining = record["_remaining"]
    if remaining < 0:
        return
    if repeating:
        if (remaining >= 2 and ticks >= remaining - 1) or ticks > remaining:
            state["_timer_dirty"] = True
        record["_remaining"] = remaining - ticks if ticks <= remaining else _signed(-(first + remaining))
    elif ticks > remaining:
        record["_remaining"] = _signed(-(first + remaining))
        record["enable"] = 1
        state["_timer_dirty"] = True
    else:
        record["_remaining"] = remaining - ticks


def advance(device, state, previous_clock, current_clock):
    """Run source-local whole-second callbacks without replaying arbitrary cmd.

    Source 0x1427bf8's 100ms callback divides by10; disabled is enable!=0.
    Week is Sunday-first int32/nonzero, timezone is stored but not consulted.
    One-shot expiry disables/persists; repeated expiry does not delete/disable.
    Source due code marks the six-byte UART timer register dirty, not the root
    cache. Startup clears both power-staging flag arrays; their only Pow-reading
    producer 0x142aa60/0x142a298 has no caller/registration in this exact primary.
    Consequently no locally reachable root command batch can be returned.
    """
    records = state.get("_timers", [])
    first, last = int(previous_clock) + 1, int(current_clock)
    if not records or last < first:
        return []
    valid = state.get("_timer_clock_valid", previous_clock > _CLOCK_THRESHOLD)
    if not valid:
        return []
    state.setdefault("_timer_output", [0] * 6)
    # Skip straight between UTC day boundaries, rather than iterating seconds.
    while first <= last:
        midnight = first // 86400 * 86400
        end = min(last, midnight + 86399)
        weekday = (datetime.fromtimestamp(first, timezone.utc).weekday() + 1) % 7
        if first == midnight:
            # Each callback refreshes ALL nodes, even a disabled last node; the
            # next callback can undo the previous node's countdown decrement.
            for record in records:
                refresh_clock(state, first)
                _advance_record(record, state, first, 1, weekday)
            first += 1
            continue
        ticks = end - first + 1
        for record in records:
            _advance_record(record, state, first, ticks, weekday)
        first = end + 1
    return []
