"""W05F hydronic LAN cache with explicitly synthetic, stationary board reports.

The serial queue ACK is not an appliance ACK. Commands stage the original control
bits; only six source-evidenced 12-second overrides affect immediate status.
"""

from copy import deepcopy
import json
from time import monotonic

from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
HID = "362001060629+W05F(QCOM)V4.2.bin"
SHA = "c8b8bc33f76cc835d2b265dd56d6ed320353f647d3e6bfa1253815e4e32035ba"

_BITS = {"Pow": (0x60, 1), "Quiet": (0x60, 8), "OutMode": (0x60, 0x20),
         "AssHt": (0x61, 1), "SvSt": (0x60, 0x80), "AcSvSt": (0x60, 0x40),
         "SvStDebug": (0x64, 2), "DebugOK": (0x64, 0x10),
         "AntiF": (0x67, 8), "Machine": (0x0c, 0xf0)}
_TEMPERATURES = {"ColWtSetTem": 0x10, "HtWtSetTem": 0x11,
                 "ColSetTem": 0x13, "HtSetTem": 0x14,
                 "HSMax": 0x18, "HSMin": 0x19, "HWMax": 0x1a,
                 "HWMin": 0x1b, "CWMax": 0x1c, "CWMin": 0x1d,
                 "CSMax": 0x1e, "CSMin": 0x1f}
_OVERRIDES = ("Pow", "Mod", "ColWtSetTem", "HtWtSetTem", "HtSetTem", "ColSetTem")
_FLAGS = {"Pow": 1, "Quiet": 2, "AssHt": 4, "SvSt": 8,
          "OutMode": 0x10, "AcSvSt": 0x20, "Ocmd": 0x80}
_SETPOINTS = {"ColWtSetTem": (2, 0x1d), "HtWtSetTem": (4, 0x1e),
              "HtSetTem": (0x10, 0x20), "ColSetTem": (0x20, 0x21)}
WRITABLE = frozenset((*_FLAGS, *_SETPOINTS, "ClrEr", "Mod", "lock", "name"))
READABLE = frozenset((*_BITS, *_TEMPERATURES, "Mod", "WtTemp", "Temp", "Ocmd",
                      "Er", "err", "enAcSvSt", "TemUn", "lock", "host", "hid",
                      "as1", "as2", "as3"))


def _fold(name):
    raw = name.encode()
    if len(raw) < 3:
        return int.from_bytes(raw[:2], "little", signed=True) & 0xffffffff
    return (int.from_bytes(raw[:4].ljust(4, b"\0"), "little") + len(raw)) & 0xffffffff


_NAMES = (*READABLE, *WRITABLE, "as", "mac", "svr", "bind", "cmd", "status",
          "upgrade", "setT", "queryT", "updateT", "deleteT", "loginRes")
_HASH_NAMES = {_fold(name): name for name in _NAMES}


def _canonical(name):
    return _HASH_NAMES.get(_fold(name))


def _integer(value):
    if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
        raise InvalidPacket("W05F requires a signed32-bit integer")
    return value


def _text(value, maximum):
    if (not isinstance(value, str) or len(value.encode()) > maximum
            or any(ord(character) < 32 for character in value)):
        raise InvalidPacket("W05F requires a bounded printable string")
    return value


def _names(value):
    if not isinstance(value, list) or len(value) > 64:
        raise InvalidPacket("W05F requires a bounded property array")
    return [_text(name, 63) for name in value]


def _reply(device, response, selector=0, uid=0, peer="null"):
    size = len(json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode())
    # Original0xa05418 reserves128 bytes in its1400-byte output scratch buffer.
    if ((size * 4 + 64) // 3) + 4 >= 1272:
        raise InvalidPacket("W05F response exceeds the original output capacity")
    reply = Reply({"t": "pack", "i": selector, "uid": uid,
                   "cid": device.mac, "tcid": peer}, response,
                  GENERIC_KEY if selector else device.key, CODEC)
    if len(encode_reply(reply)) >= 1400:
        raise InvalidPacket("W05F envelope exceeds the original output buffer")
    return reply


def _runtime(device, state):
    if "_hydronic" not in state:
        report = bytearray(8 * 0x74)
        report[1], report[8], report[0xf] = 3, 1, state["Mod"]
        for offset in (*_TEMPERATURES.values(), 0x27, 0x2c, 0x31, 0x35):
            report[offset] = 122
        for name, (offset, mask) in _BITS.items():
            if state.get(name, 0) == 1:
                report[offset] |= mask
        for name in _SETPOINTS:
            report[_TEMPERATURES[name]] = (state[name] + 100) & 255
        state["_hydronic"] = {"report": report, "pending": {}, "errors": [],
                               "name": device.name, "host": "", "timers": [],
                               "control": bytearray(128), "server": {}}
    return state["_hydronic"]


def _read(device, state, runtime, name, now):
    report = runtime["report"]
    pending = runtime["pending"].get(name)
    if pending is not None and (now - pending[1] < 12 or runtime["errors"]):
        return pending[0]
    if pending is not None:
        del runtime["pending"][name]
    if name in _BITS:
        offset, mask = _BITS[name]
        return int(bool(report[offset] & mask))
    if name in _TEMPERATURES:
        return report[_TEMPERATURES[name]] - 100
    if name == "Mod":
        return report[0xf]
    if name == "WtTemp":
        return report[0x2c if report[0xc] & 0xf0 == 0 else 0x27] - 100
    if name == "Temp":
        return report[0x31 if report[0x62] & 0x40 == 0 else 0x35] - 100
    if name == "Ocmd":
        return int(bool(report[0x5e]))
    if name == "enAcSvSt":
        return int(bool(report[0x63] & 4 or report[0x62] & 0x40))
    if name == "Er":
        return int(bool(runtime["errors"]))
    if name == "err":
        return runtime["errors"][:]
    if name in ("lock", "TemUn"):
        return state["lock"] if name == "lock" else 0
    if name == "hid":
        return HID
    if name == "host":
        return runtime["host"]
    start, count = {"as1": (0, 2), "as2": (2, 3), "as3": (5, 3)}[name]
    return [bytes(report[index * 0x74 + 10:index * 0x74 + 110]).hex()
            if report[index * 0x74 + 8] else "" for index in range(start, start + count)]


def _write(state, runtime, control, name, value, now):
    if name == "name":
        runtime["name"] = value.encode()[:31].decode("utf-8", errors="ignore")
        return True
    value = _integer(value)
    if name == "lock":
        if value not in (0, 1):
            return False
        state[name] = value
        return True
    if name == "Mod":
        if value not in (1, 2):
            return False
        control[1] = 1
        control[0x1b] |= 1
        control[0x1c] = value
    elif name in _SETPOINTS:
        mask, offset = _SETPOINTS[name]
        control[1] = 1
        control[0x1b] |= mask
        control[offset] = (value + 100) & 255
    elif name == "ClrEr":
        control[0] = 1
        control[12] |= 2
        if value == 1:
            control[13] |= 2
    else:
        mask = _FLAGS[name]
        control[0] = 1
        control[10] |= mask
        if value == 1:
            control[11] |= mask
            if name == "AcSvSt":
                control[10] |= 0x10
            if name == "Ocmd":
                runtime["report"][0x5e] = 0
    if name in _OVERRIDES:
        runtime["pending"][name] = (value & 255, now)
    state[name] = value
    return True


_TIMER_ERRORS = {416: "name/enable/hr/min/sec/week/tz err!",
                 407: "cmd/id/mac/opt/p err!", 403: "id has been exsit!",
                 500: "local err!", 503: "no place to set time.", 504: "id no exsit!"}


def _timer_record(inner):
    record = deepcopy(inner)
    record.pop("t")
    _text(record.get("name"), 63)
    _integer(record.get("enable"))
    for name, maximum in (("hr", 23), ("min", 59), ("sec", 59)):
        if not 0 <= _integer(record.get(name)) <= maximum:
            return None, 416
    if not -12 <= _integer(record.get("tz")) <= 12:
        return None, 416
    week = record.get("week")
    if not isinstance(week, list) or len(week) != 7:
        return None, 416
    for day in week:
        _integer(day)
    if _integer(record.get("id")) < 1:
        return None, 407
    commands = record.get("cmd")
    if not isinstance(commands, list) or not 1 <= len(commands) <= 64:
        return None, 407
    for command in commands:
        if not isinstance(command, dict):
            return None, 407
        macs = command.get("mac")
        if not isinstance(macs, list) or not 1 <= len(macs) <= 64:
            return None, 407
        for mac in macs:
            _text(mac, 63)
        options, values = _names(command.get("opt")), command.get("p")
        if not isinstance(values, list) or len(options) != len(values):
            return None, 407
        for name, value in zip(options, values):
            if name == "name":
                _text(value, 1024)
            else:
                _integer(value)
    return record, 200


def _timers(runtime, inner):
    records = runtime["timers"]
    kind = inner["t"]
    if kind == "queryT":
        if "index" not in inner or "count" not in inner:
            return None
        index, count = _integer(inner["index"]), _integer(inner["count"])
        if index < 0 or count < 0:
            raise InvalidPacket("W05F safe timer pagination requires nonnegative integers")
        selected, size = [], 0
        for record in records[index:index + count]:
            size += len(json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode())
            if size >= 900:
                break
            selected.append(record)
        return {"t": "listT", "total": len(records), "index": index, "list": selected}
    if kind == "deleteT":
        timer_id = _integer(inner.get("id"))
        found = next((index for index, record in enumerate(records)
                      if record["id"] == timer_id), None)
        code = 504 if found is None else 200
        if found is not None:
            del records[found]
    else:
        record, code = _timer_record(inner)
        if code == 200:
            found = next((index for index, old in enumerate(records)
                          if old["id"] == record["id"]), None)
            if kind == "setT":
                code = 403 if found is not None else 503 if len(records) >= 10 else 200
                if code == 200:
                    records.append(record)
            elif found is None:
                code = 504
            else:
                records[found] = record
    response = {"t": "resT", "r": code}
    if code in _TIMER_ERRORS:
        response["msg"] = _TIMER_ERRORS[code]
    return response


def _upgrade(runtime, inner, mac):
    if "upgrade" in runtime:
        code, message = 505, "being Escalating!"
    elif "url" not in inner:
        code, message = 407, "url err!"
    else:
        url = _text(inner["url"], 1024)
        if not url.startswith("http://") or "/" not in url[7:]:
            raise InvalidPacket("unsafe native W05F URL scan")
        authority, _, path = url[7:].partition("/")
        host, colon, port_text = authority.partition(":")
        if not host:
            raise InvalidPacket("missing W05F update host")
        port = 0 if colon else 80
        for digit in port_text:
            if not "1" <= digit <= "9":
                break
            port = (port * 10 + int(digit)) & 65535
        # Only the native request-queue boundary is modeled, never HTTP or flash.
        runtime["upgrade"] = {"url": url, "host": host, "path": "/" + path, "port": port}
        code, message = 200, None
    response = {"t": "ret", "mac": mac, "r": code}
    if message is not None:
        response["msg"] = message
    return response


class Hydronic:
    def validate_state(self, state):
        for name, value in state.items():
            if name not in WRITABLE - {"name"}:
                raise ValueError("W05F initial state accepts only writable numeric controls")
            try:
                _integer(value)
            except InvalidPacket as exc:
                raise ValueError(str(exc)) from exc
            if name == "Mod" and value not in (1, 2):
                raise ValueError("W05F mode requires1 or2")
            if name == "lock" and value not in (0, 1):
                raise ValueError("W05F lock requires0 or1")

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        return None

    def advertise(self, device, outer):
        runtime = _runtime(device, device.state)
        response = {"t": "dev", "cid": device.mac, "mac": device.mac,
                    "key": device.key.decode("ascii"), "lock": device.state["lock"],
                    "mid": device.mid, "name": runtime["name"]}
        return [_reply(device, response, 1)]

    def wlan(self, device, outer):
        candidate = deepcopy(device.state)
        runtime = _runtime(device, candidate)
        ssid = _text(outer.get("ssid"), 1024)
        password = _text(outer.get("psw"), 1024)
        host = _text(outer.get("host"), 1024)
        valid = 1 <= len(ssid.encode()) <= 31 and len(password.encode()) <= 63 and len(host.encode()) <= 63
        response = {"t": "ret", "mac": device.mac, "r": 200 if valid else 416}
        if valid:
            runtime["ssid"], runtime["host"] = ssid, host
            # The simulated network configuration never retains credentials.
        else:
            response["msg"] = "ssid/psw/host len err!"
        reply = Reply(response)
        encode_reply(reply)
        device.advance(monotonic())
        device.state = candidate
        return [reply]

    def handle(self, device, outer):
        if outer.get("t") != "pack":
            raise InvalidPacket("unsupported W05F envelope")
        selector = _integer(outer.get("i"))
        if selector < 0:
            raise InvalidPacket("negative W05F key selector")
        uid = _integer(outer.get("uid", 0))
        peer = _text(outer.get("cid", "null"), 63)
        if selector == 2:
            inner = outer.get("pack")
            if not isinstance(inner, dict):
                raise InvalidPacket("W05F selector2 requires an object pack")
        else:
            inner = decode_pack(outer, device.key if selector == 0 else GENERIC_KEY, CODEC)
        now = monotonic()
        candidate = deepcopy(device.state)
        runtime = _runtime(device, candidate)
        kind = _canonical(_text(inner.get("t"), 63))
        reply_selector = 0
        if kind == "bind":
            if candidate["lock"] == 1:
                return []
            response = {"t": "bindok", "r": 200, "mac": device.mac,
                        "key": device.key.decode("ascii")}
            reply_selector, uid, peer = 1, 0, "null"
        elif kind == "status":
            columns = _names(inner.get("cols"))
            mac = _text(inner.get("mac"), 63)
            accepted = [name for name in columns if _canonical(name) in READABLE]
            code = 404 if mac != device.mac else 200 if accepted else 417
            response = {"t": "dat", "r": code, "cid": device.mac, "mac": mac}
            if code == 200:
                response.update(cols=accepted, dat=[_read(device, candidate, runtime, _canonical(name), now)
                                                    for name in accepted])
            else:
                response["cols"] = columns
                if code == 417:
                    response["msg"] = "cols para err!"
        elif kind == "cmd":
            options = _names(inner.get("opt"))
            values = inner.get("p")
            if not isinstance(values, list) or len(values) != len(options):
                raise InvalidPacket("W05F command arrays must match atomically")
            for name, value in zip(options, values):
                canonical = _canonical(name)
                if canonical == "name":
                    _text(value, 1024)
                elif canonical in WRITABLE:
                    _integer(value)
            accepted, echoed = [], []
            control = bytearray(128)
            ready = runtime["report"][1] in (2, 3)
            if ready:
                for name, value in zip(options, values):
                    canonical = _canonical(name)
                    if canonical in WRITABLE and _write(candidate, runtime, control, canonical, value, now):
                        accepted.append(name)
                        echoed.append(value)
                runtime["control"] = control
            code = 404 if not ready else 200 if accepted else 417
            response = {"t": "res", "opt": accepted if code == 200 else options,
                        "p": echoed if code == 200 else values, "r": code}
            if code != 200:
                response["msg"] = "dev exit!" if code == 404 else "opt para err!"
            if "sub" in inner or "mac" in inner:
                response["mac"] = inner.get("sub", inner.get("mac"))
        elif kind in ("setT", "updateT", "deleteT", "queryT"):
            response = _timers(runtime, {**inner, "t": kind})
        elif kind == "upgrade":
            reply = Reply(_upgrade(runtime, inner, device.mac))
            encode_reply(reply)
            device.advance(now)
            device.state = candidate
            return [reply]
        elif kind == "svr":
            for port, host in (("datHostPort", "datHost"), ("tcpPort", "host")):
                if port in inner and host in inner and _integer(inner[port]) != 0:
                    runtime["server"][port] = inner[port] & 65535
                    runtime["server"][host] = _text(inner[host], 63)
            response = None
        elif kind == "loginRes":
            runtime["server"]["authenticated"] = _integer(inner.get("r", 0)) == 200
            response = None
        else:
            return []
        reply = None if response is None else _reply(device, response, reply_selector, uid, peer)
        device.advance(now)
        device.state = candidate
        return [] if reply is None else [reply]


PROFILES = (Profile(
    id="sim-catalog-w05f-hydronic-v4.2", mids=("809030",), hid=HID,
    source_sha256=SHA,
    initial_state={"Pow": 0, "Mod": 1, "Quiet": 0, "OutMode": 0, "AssHt": 0,
                   "SvSt": 0, "AcSvSt": 0, "Ocmd": 0, "ClrEr": 0,
                   "ColSetTem": 22, "HtSetTem": 22, "ColWtSetTem": 22,
                   "HtWtSetTem": 22, "lock": 0},
    handler=Hydronic(), max_request_bytes=3072,
),)
