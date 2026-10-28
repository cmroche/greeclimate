"""062071 W06MV1.03 timer arrays, independently qualified from CV linked lists.

``schedule(inner, runtime, root_mac, full_index)`` returns an inner reply or None
for unrelated operations, raising InvalidPacket for recognized rejected input.
The owner passes candidateatomic per-device runtime. ``timers`` holds ten fixed
ID slots (including invalid/deleted slots whose other bytes survive deletion).
``due`` programs raw serial timer fields and disables elapsed one-shots; it does
not fabricate effective appliance power or mainboard completion.

Source: Xtensa-1/65da0894f3b7 a0df24/a0cf38/a08acc. Synthetic startup is zeroed
RAM. Strict integer/string/full-week validation and rejecting source's ID10
out-of-bounds write are deliberate safe parser policy, not native validation.
Python retains the request DOM: original parsing deletes both root and its child
iterator. This safe ownership policy is not a successful native ingress replay.
"""
from ..wire import InvalidPacket


OPERATIONS = frozenset(("setT", "updateT", "deleteT", "queryT"))


def _integer(value, name, lower=-(1 << 31), upper=(1 << 31) - 1):
    if type(value) is not int or not lower <= value <= upper:
        raise InvalidPacket(f"invalid W06M timer {name}")
    return value


def _text(value, name, maximum):
    if not isinstance(value, str) or "\0" in value:
        raise InvalidPacket(f"invalid W06M timer {name}")
    try:
        length = len(value.encode("ascii"))
    except UnicodeEncodeError as error:
        raise InvalidPacket(f"invalid W06M timer {name}") from error
    if length > maximum:
        raise InvalidPacket(f"unsafe W06M timer {name} length")
    return value


def _single(value, name):
    if not isinstance(value, list) or len(value) != 1:
        raise InvalidPacket(f"W06M timer {name} requires one element")
    return value[0]


def _slots(runtime):
    if "timers" not in runtime:
        runtime["timers"] = [
            {"id": identifier, "_valid": 0, "name": "", "enable": 0,
             "hr": 0, "min": 0, "sec": 0, "week": [0] * 7, "p": 0}
            for identifier in range(10)]
    return runtime["timers"]


def schedule(inner, runtime, root_mac, full_index):
    operation = inner.get("t")
    if not isinstance(operation, str) or operation not in OPERATIONS:
        return None
    if full_index != 0:
        raise InvalidPacket("W06M timers require the complete index to equal zero")
    if operation == "queryT":
        index = _integer(inner.get("index"), "index", 0, 9)
        count = _integer(inner.get("count"), "count", 1, 10)
        if index + count > 10:
            raise InvalidPacket("W06M timer query exceeds fixed array")
        slots = _slots(runtime)
        entries = []
        for record in slots[index:index + count]:
            if not record["_valid"]:
                continue
            entry = {name: record[name] for name in ("id", "name", "enable", "hr", "min", "sec")}
            entry["week"] = record["week"].copy()
            entry["cmd"] = [{"mac": [root_mac], "opt": ["Pow"], "p": [record["p"]]}]
            entries.append(entry)
        return {"t": "listT", "total": sum(record["_valid"] == 1 for record in slots),
                "index": index, "list": entries}
    identifier = _integer(inner.get("id"), "id", 0, 9)
    if operation == "deleteT":
        record = _slots(runtime)[identifier]
        record["_valid"], record["enable"] = 0, 1
    else:
        command = _single(inner.get("cmd"), "cmd")
        if not isinstance(command, dict):
            raise InvalidPacket("W06M timer cmd requires an object")
        target = _text(_single(command.get("mac"), "mac"), "mac", 20)
        if target != root_mac:
            raise InvalidPacket("W06M timer command MAC does not match root")
        changes = {}
        for name in ("enable", "hr", "min", "sec"):
            if name in inner:
                changes[name] = _integer(inner[name], name) & 255
        if "name" in inner:
            changes["name"] = _text(inner["name"], "name", 31)
        if "week" in inner:
            week = inner["week"]
            if not isinstance(week, list) or not 7 <= len(week) <= 30:
                raise InvalidPacket("W06M timer requires seven initialized week slots")
            changes["week"] = [_integer(value, "week") & 255 for value in week[:7]]
        selector = runtime.get("_timer_opt", "")
        if "opt" in command:
            selector = _text(_single(command["opt"], "opt"), "opt", 31)
        value = 0
        if "p" in command:
            value = _integer(_single(command["p"], "p"), "p")
        if selector == "Pow":
            changes["p"] = value & 255
        record = _slots(runtime)[identifier]
        record.update(changes)
        record["_valid"] = 1
        runtime["_timer_opt"] = selector
    # Source queues serial commit/refresh; this is not local firmware flash.
    runtime["_timer_dirty"] = True
    return {"t": "resT", "r": 200}


def due(runtime, hour, minute, second, weekday):
    """Run the original next-countdown/one-shot walk, returning raw timer fields.

    ``flags`` is source timer frame byte+4 (bit7 on/bit6 off), ``on``/``off``
    are source frame bytes+8..10/+11..13, not clock times or effective Pow.
    ``event`` is packet byte+12, ``notify`` is auxiliary byte+5. Consumers must
    not interpret timer programming as confirmed physical mainboard action.
    """
    slots = _slots(runtime)
    program = runtime.setdefault("_timer_program", {
        "flags": 0, "on": [0, 0, 0], "off": [0, 0, 0],
        "event": 0, "notify": 0, "trigger": False})
    active = [record for record in slots if record["_valid"] == 1 and record["enable"] == 0]
    if not active:
        program["event"] |= 0x80
        return program
    day = weekday if 0 <= weekday < 7 else 0
    candidates = [record for record in active
                  if record["week"][day] == 1 or 1 not in record["week"]]
    now = hour * 3600 + minute * 60 + second
    if not candidates:
        for power, name, bit in ((0, "off", 0x40), (1, "on", 0x80)):
            enabled = any(record["p"] == power for record in active)
            program[name] = [23, 59, 59] if enabled else [0, 0, 0]
            program["flags"] = (program["flags"] & ~bit) | (bit if enabled else 0)
    else:
        # Native insertion sort is stable and orders absolute seconds ascending.
        candidates.sort(key=lambda record: record["hr"] * 3600 + record["min"] * 60 + record["sec"])
        upcoming = next((record for record in candidates
                         if record["hr"] * 3600 + record["min"] * 60 + record["sec"] >= now), None)
        chosen = upcoming if upcoming is not None else candidates[0]
        delta = (chosen["hr"] * 3600 + chosen["min"] * 60 + chosen["sec"] - now
                 if upcoming is not None else 86399)
        selected_on = chosen["p"] != 0
        for is_on, name, bit in ((False, "off", 0x40), (True, "on", 0x80)):
            if is_on == selected_on:
                program[name] = [(delta // 3600) & 255, (delta // 60) % 60, delta % 60]
                program["flags"] |= bit
            else:
                enabled = any(record["p"] == int(is_on) for record in active)
                program[name] = [23, 59, 59] if enabled else [0, 0, 0]
                program["flags"] = (program["flags"] & ~bit) | (bit if enabled else 0)
        if delta in (0, 15) or delta % 60 == 0:
            program["notify"] |= 0x80
        if delta == 0:
            program["event"] = 0x5e
            program["trigger"] = True
    # This source checks every slot, even invalid ones, once any active slot exists.
    for record in slots:
        timestamp = record["hr"] * 3600 + record["min"] * 60 + record["sec"]
        if record["enable"] == 0 and timestamp == now and 1 not in record["week"]:
            record["enable"] = 1
            runtime["_timer_dirty"] = True
    return program
