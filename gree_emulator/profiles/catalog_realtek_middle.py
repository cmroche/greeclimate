"""Historical raw controllers with exact source-qualified bounded namespaces.

W05R's original one-past-end command fault is retained in research evidence;
the reused model deliberately validates and commits a finite batch atomically.
Its clock, IR/flash records and power readouts are synthetic per-device state,
not calibrated mainboard input or a claim of a complete firmware boot.
"""

import base64
import binascii
import re
from copy import deepcopy
from datetime import datetime, timedelta

from ..wire import InvalidPacket, Reply
from . import Profile
from .realtek_controller import (
    RealtekController, W05G_FIELDS, W05R_CONTROLS, W05R_FIELDS, _clock, _reply, _runtime,
)


def _integer(value):
    if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
        raise InvalidPacket("historical controller requires signed32 integers")
    return value


def _text(value, maximum):
    if not isinstance(value, str) or "\0" in value or len(value.encode()) > maximum:
        raise InvalidPacket("historical controller string exceeds its source field")
    return value


class MiddleRController(RealtekController):
    """R241's original software timers with explicitly virtual persistence."""

    def _advance(self, device, state, runtime):
        current = _clock(device, runtime)
        previous = runtime.get("schedule_at", current)
        runtime["schedule_at"] = current
        old, new = (datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
                    for value in (previous, current))
        timers = runtime.get("schedules", {})
        if not timers or new <= old:
            return
        if (new - old).days > 366:
            raise InvalidPacket("synthetic timer advance exceeds one year")
        day = old.replace(hour=0, minute=0, second=0)
        while day <= new:
            for record in timers.values():
                event = day.replace(hour=record["hr"], minute=record["min"], second=record["sec"])
                repeating = any(record["week"])
                if (record["enable"] or not old < event <= new
                        or event < datetime(2018, 5, 22, 6, 10, 36)
                        or repeating and not record["week"][(event.weekday() + 1) % 7]):
                    continue
                for command in record["cmd"]:
                    for name, value in zip(command["opt"], command["p"]):
                        if name in W05R_CONTROLS:
                            state[name] = value & 65535
                        elif name in self.fields:
                            runtime["scratch"][name] = value & 65535
                runtime["send_pending"] = True
                if not repeating:
                    record["enable"] = 1
            day += timedelta(days=1)

    def _get(self, device, state, runtime, name, *, command=False):
        self._advance(device, state, runtime)
        return super()._get(device, state, runtime, name, command=command)

    def _r_command(self, device, state, runtime, name, value):
        self._advance(device, state, runtime)
        return super()._r_command(device, state, runtime, name, value)

    def _timer(self, inner):
        timer_id = _integer(inner.get("id")) & 255
        hour, minute, second = (_integer(inner.get(name)) for name in ("hr", "min", "sec"))
        if not 0 <= hour < 24 or not 0 <= minute < 60 or not 0 <= second < 60:
            raise InvalidPacket("historical timer requires a valid time of day")
        week = inner.get("week")
        commands = inner.get("cmd")
        if not isinstance(week, list) or len(week) > 7:
            raise InvalidPacket("historical timer requires at most seven weekday entries")
        if not isinstance(commands, list) or len(commands) > 10:
            raise InvalidPacket("historical timer requires at most ten command records")
        parsed = []
        for command in commands:
            if not isinstance(command, dict):
                raise InvalidPacket("invalid historical timer command")
            macs, names, values = (command.get(name) for name in ("mac", "opt", "p"))
            if (not isinstance(macs, list) or len(macs) > 10
                    or not isinstance(names, list) or len(names) != 1
                    or not isinstance(values, list) or not 1 <= len(values) <= 30):
                raise InvalidPacket("historical timer requires one property per command")
            # Original parser fixes opt count to one but stages up to thirty p.
            parsed.append({"mac": [_text(mac, 19) for mac in macs],
                           "opt": [_text(names[0], 15)], "p": [_integer(values[0])]})
            for value in values[1:]:
                _integer(value)
        return timer_id, {
            "id": timer_id, "name": _text(inner.get("name"), 19),
            "enable": int(bool(_integer(inner.get("enable")))),
            "hr": hour, "min": minute, "sec": second,
            "tz": _integer(inner.get("tz")) & 255,
            "week": [_integer(value) for value in week] + [0] * (7 - len(week)),
            "cmd": parsed,
        }

    def _handle(self, device, inner, uid):
        kind = inner["t"]
        if kind not in ("setT", "updateT", "queryT", "deleteT", "upgrade", "surver"):
            return super()._handle(device, inner, uid)
        pending = deepcopy(device.state)
        runtime = _runtime(device, pending)
        self._advance(device, pending, runtime)
        timers = runtime.setdefault("schedules", {})
        if kind in ("setT", "updateT"):
            timer_id, record = self._timer(inner)
            if timer_id not in timers and len(timers) >= 10:
                if kind == "updateT":
                    return []
                response = {"t": "resT", "r": 500}
            else:
                timers[timer_id] = record
                response = {"t": "resT", "r": 200}
        elif kind == "deleteT":
            timers.pop(_integer(inner.get("id")) & 255, None)
            response = {"t": "resT", "r": 200}
        elif kind == "queryT":
            start, count = (_integer(inner.get(name)) & 255 for name in ("index", "count"))
            response = {"t": "listT", "total": count, "index": start}
            if timers:
                response["list"] = [
                    {name: deepcopy(record[name]) for name in
                     ("id", "name", "enable", "hr", "min", "sec", "week", "cmd")}
                    for ordinal, record in enumerate(timers.values())
                    if start <= ordinal <= start + count
                ]
        elif kind == "surver":
            # Native base64 preflight rejects its mismatched three-argument call.
            response = {"t": "pack", "i": 1, "uid": uid, "cid": device.mac,
                        "tcid": "", "pack": "fg\x01"}
        else:
            runtime["upgrade_url"] = _text(inner.get("url"), 159)
            response = {"t": "ret", "r": 200, "mac": device.mac}
        reply = (Reply(response, trailing_newline=True) if kind == "surver"
                 else _reply(device, response, 0, uid))
        pending["_uid"] = uid
        device.state.clear()
        device.state.update(pending)
        return [reply]


class MiddleGController(RealtekController):
    """G44's finite BLE request queues, with no invented downstream devices."""

    routed_selectors = (("bin", "sub"), ("dump", "mac"))

    def _address(self, value, width):
        if not isinstance(value, str) or not re.fullmatch(rf"[0-9a-fA-F]{{{width}}}", value):
            raise InvalidPacket("historical BLE address has the wrong hexadecimal width")
        return bytes.fromhex(value)

    def _enqueue(self, runtime, address, raw, *, kind=1):
        queue = runtime.setdefault("binary_queue", [])
        if len(queue) >= 5:
            return
        frame = [0] * 250
        frame[:2] = [0xaa, 0xaa]
        frame[2:2 + len(address)] = address
        frame[8] = kind & 255
        if kind == 1:
            frame[9] = raw[7] + 8
            frame[10:17 + raw[7]] = raw[:7 + raw[7]]
        else:
            sequence = runtime.get("binary_sequence", 30) + 1
            runtime["binary_sequence"] = 31 if sequence == 255 else sequence & 255
            frame[9:11] = [raw[0] + 2, runtime["binary_sequence"]]
            frame[11:11 + raw[0]] = raw[:raw[0]]
        queue.append({"frame": frame, "origin": "LAN", "peer": None})

    def _binary(self, inner, runtime):
        if not _integer(inner.get("stm")):
            return
        targets, values, kinds = (inner.get(name) for name in ("sub", "bin", "type"))
        if (not all(isinstance(value, list) for value in (targets, values, kinds))
                or not len(targets) == len(values) == len(kinds) or len(targets) > 5):
            raise InvalidPacket("historical BLE binary arrays must match and fit five records")
        for target, value, kind in zip(targets, values, kinds):
            kind = _integer(kind)
            address = self._address(target, 12 if kind == 1 else 4)
            if not isinstance(value, str):
                raise InvalidPacket("historical BLE binary payload must be base64")
            try:
                raw = base64.b64decode(value, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise InvalidPacket("invalid historical BLE base64") from exc
            if (kind == 1 and (len(raw) < 8 or raw[7] + 8 >= 201
                              or len(raw) < raw[7] + 7)
                    or kind != 1 and (not raw or raw[0] + 1 >= 201 or len(raw) < raw[0])):
                raise InvalidPacket("historical BLE binary frame exceeds its declared payload")
            self._enqueue(runtime, address, raw, kind=kind)

    def handle_from(self, device, outer, addr):
        before = len(device.state.get("_runtime", {}).get("binary_queue", []))
        replies = self.handle(device, outer)
        for queued in device.state.get("_runtime", {}).get("binary_queue", [])[before:]:
            queued["peer"] = addr
        return replies

    def _handle(self, device, inner, uid):
        kind = inner["t"]
        if kind not in ("subDev", "meshstatus", "onoffse", "bin", "dump", "upgrade"):
            return super()._handle(device, inner, uid)
        pending = deepcopy(device.state)
        runtime = _runtime(device, pending)
        response = None
        if kind == "subDev":
            index = _integer(inner.get("i", 0))
            response = {"t": "subList", "r": 200, "c": 0, "i": index, "list": []}
        elif kind == "meshstatus":
            addresses, lengths = inner.get("meshmac"), inner.get("len")
            if (not isinstance(addresses, list) or not isinstance(lengths, list)
                    or len(addresses) != len(lengths) or len(addresses) > 50):
                raise InvalidPacket("historical mesh status arrays must match")
            for address, length in zip(addresses, lengths):
                self._address(address, 12)
                if not 0 <= _integer(length) <= 20:
                    raise InvalidPacket("historical mesh status length exceeds its raw cache")
            # No attached/mainboard-provided BLE descriptors in this root preset.
            response = {"t": "substatus", "mac": device.mac, "meshmac": [], "status": []}
        elif kind == "onoffse":
            self._address(inner.get("meshid"), 4)
            for name in ("on", "off", "lpn"):
                _integer(inner.get(name))
            response = {"t": "onoffse", "res": 200}
        elif kind == "bin":
            self._binary(inner, runtime)
        elif kind == "dump":
            address = self._address(inner.get("mac"), 12)
            period, count = (_integer(inner.get(name)) & 255 for name in ("period", "cnt"))
            raw = bytes((0, 1, 0, 0x12, 0x34, 0, 0, 5, 10, 3, period, count))
            self._enqueue(runtime, address, raw)
        else:
            runtime["upgrade_url"] = _text(inner.get("url"), 159)
            response = {"t": "ret", "r": 200, "mac": device.mac}
        replies = [] if response is None else [_reply(device, response, 0, uid)]
        pending["_uid"] = uid
        device.state.clear()
        device.state.update(pending)
        return replies


PROFILES = (
    Profile(
        id="sim-w05r-v2.41", mids=("80221",),
        hid="362001061917+W05RV2.41.bin",
        source_sha256="36a09eebfbe20ad9fb8248b00e3b5a13360133a78a683ac47c71974ca0160322",
        initial_state={**dict.fromkeys(W05R_FIELDS[:33], 0), "_uid": 0},
        handler=MiddleRController(), max_request_bytes=1024,
    ),
    Profile(
        id="sim-w05g-v4.4", mids=("80300",),
        hid="362001061996+U-W05G(RELT)V4.4.bin",
        source_sha256="3c0ac3e4a236e9d679e8e879ba181703fcd7b9947276852a521620fb432443fe",
        initial_state={**dict.fromkeys(W05G_FIELDS, 0), "_uid": 0},
        handler=MiddleGController(gateway=True), max_request_bytes=1024,
    ),
)
