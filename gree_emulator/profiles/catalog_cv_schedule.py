"""CV2/V7 local schedule list, not the unrelated W06M timer arrays.

API: keep a fresh ``list`` in each owning device's state and pass it to ``handle``.
The parent owns target/key/envelope routing. ``due_queue`` runs one source task
iteration with supplied calendar fields and returns the serial queue byte, never
an effective appliance Pow value. Persistence/lifecycle remain parent policy.

Original evidence: private CatalogQuirks/Xtensa/cv-schedules_research.json.
Safe parser policy rejects indeterminate stack and unsafe string-copy inputs;
valid update byte wrapping, query's repeated-ID bug, and due's week carry survive.
The parent may stage upgrade acceptance before dispatch here; this schedule-only
helper rejects upgrade. Neither layer may fetch firmware, flash or claim completion.
"""
from ..wire import InvalidPacket


OPERATIONS = frozenset(("setT", "updateT", "queryT", "deleteT", "upgrade"))
SELECTORS = (
    "Pow", "HeatCoolType", "AcPctCle", "AllErr", "Mod", "ForceMode", "WdSpd",
    "SetTemInt", "SetTemDec", "EnvTem", "SwUpDn", "SwingLfRig", "TemUn",
)


def _member(value, name):
    if not isinstance(value, dict):
        raise InvalidPacket("CV schedule requires an object")
    for key, item in value.items():
        if isinstance(key, str) and key.lower() == name:
            return item
    return None


def _integer(value, name, lower=-(1 << 31), upper=(1 << 31) - 1):
    if type(value) is not int or not lower <= value <= upper:
        raise InvalidPacket(f"invalid CV schedule {name}")
    return value


def _string(value, name, maximum):
    if not isinstance(value, str) or "\0" in value:
        raise InvalidPacket(f"invalid CV schedule {name}")
    try:
        length = len(value.encode("ascii"))
    except UnicodeEncodeError as error:
        raise InvalidPacket(f"invalid CV schedule {name}") from error
    if length > maximum:
        raise InvalidPacket(f"unsafe CV schedule {name} length")
    return value


def _singleton(value, name):
    if not isinstance(value, list) or len(value) != 1:
        raise InvalidPacket(f"CV schedule {name} requires one element")
    return value[0]


def _record(request, updating):
    record = {"id": _integer(_member(request, "id"), "id", 0, 9)}
    for name, upper in (("enable", 1), ("hr", 23), ("min", 59), ("sec", 59)):
        value = _member(request, name)
        record[name] = (_integer(value, name) & 255 if updating
                        else _integer(value, name, 0, upper))
    record["tz"] = _integer(_member(request, "tz"), "tz") & 255
    # Source permits a 40-byte strcpy into a 32-byte field; never copy that defect.
    record["name"] = _string(_member(request, "name"), "name", 31)
    week = _member(request, "week")
    if not isinstance(week, list) or (len(week) & 255) < 7:
        raise InvalidPacket("CV schedule requires seven initialized week slots")
    record["week"] = [_integer(value, "week") & 0xffffffff for value in week[:7]]
    command = _singleton(_member(request, "cmd"), "cmd")
    record["_mac"] = _string(_singleton(_member(command, "mac"), "mac"), "mac", 15)
    selector = _string(_singleton(_member(command, "opt"), "opt"), "opt", 32)
    if selector not in SELECTORS:
        raise InvalidPacket("unknown CV schedule selector")
    record["_selector"] = SELECTORS.index(selector)
    parameters = _member(command, "p")
    value = parameters[0] if isinstance(parameters, list) and len(parameters) == 1 else None
    record["p"] = _integer(value, "p") & 0xffffffff if type(value) is int else 0
    return record


def handle(schedules, request, root_mac):
    """Mutate this device's list atomically and return its exact inner reply.

    Unknown operations return None. Recognized invalid operations raise
    InvalidPacket so the owning handler emits no fabricated success or error ACK.
    """
    operation = _member(request, "t")
    if not isinstance(operation, str) or operation not in OPERATIONS:
        return None
    if operation == "upgrade":
        raise InvalidPacket("CV firmware upgrade action is not emulated")
    if operation == "queryT":
        index = _integer(_member(request, "index"), "index", 0, 9)
        count = _integer(_member(request, "count"), "count", 1, 10)
        if index + count > 10:
            raise InvalidPacket("CV schedule query exceeds ID namespace")
        # Original count loop repeatedly searches index; it does not page IDs.
        record = next((record for record in schedules if record["id"] == index), None)
        entries = []
        if record is not None:
            entry = {name: record[name] for name in ("id", "name", "enable", "hr", "min", "sec")}
            entry["week"] = record["week"].copy()
            entry["cmd"] = [{"mac": [root_mac], "opt": ["Pow"], "p": [record["p"]]}]
            entries.append(entry)
        return {"t": "listT", "total": 10, "index": index, "list": entries}
    identifier = _integer(_member(request, "id"), "id", 0, 9)
    position = next((index for index, record in enumerate(schedules)
                     if record["id"] == identifier), None)
    if operation == "deleteT":
        if position is None:
            raise InvalidPacket("no such CV schedule")
        del schedules[position]
    else:
        record = _record(request, operation == "updateT")
        if position is None:
            if operation == "updateT":
                raise InvalidPacket("no such CV schedule")
            if len(schedules) >= 10:
                raise InvalidPacket("CV schedule list is full")
            schedules.append(record)
        else:
            schedules[position] = record
    return {"t": "resT", "r": 200}


def due_queue(schedules, hour, minute, second, queue_byte, *, inhibited=False):
    """Execute one original due-list walk; preserve queued byte's upper six bits.

    No weekday inference, one-shot deletion, seconds matching, timezone conversion
    or deduplication: none exists in these source routines. Parent supplies the
    source calendar and inhibition bit and owns eventual mainboard reconciliation.
    """
    has_week = False
    for record in schedules:
        if record["enable"] != 0:
            continue
        if any(record["week"]):
            has_week = True
            eligible = True
        else:
            # Original carry survives earlier nodes and slot 7 aliases p.
            eligible = not has_week or record["p"] != 0
        if (eligible and record["hr"] == hour and record["min"] == minute
                and second == 0 and not inhibited and record["_selector"] in (0, 1)):
            queue_byte = (queue_byte & 0xfc) | 1 | ((record["p"] & 1) << 1)
    return queue_byte
