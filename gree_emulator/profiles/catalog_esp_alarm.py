"""MSTWB801A's raw alarm cache; no synthetic alarm actuation or AC physics.

The original string-array/atoi command path echoes strings, not effective values.
Strict parsing, bounded batches and atomic commits deliberately replace unchecked
native copies, skipped bool/null slots and sequential partial mutation.
"""

from base64 import b64encode
from copy import deepcopy
from datetime import datetime
from hashlib import sha256
import math
import re
from time import monotonic

from ..wire import InvalidPacket, Reply, _json, decode_pack, encode_reply
from . import Profile

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
FIELDS = ("Pow", "WorkState", "AlarmCancel", "AlarmTmrEnable", "AlarmTime")
INITIAL_STATE = {"Pow": 1, "AlarmCancel": 0, "AlarmTmrEnable": 0, "AlarmTime": 0}
_INT_PREFIX = re.compile(r"^[\t\n\v\f\r ]*([+-]?[0-9]+)")


def _integer(value):
    if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
        raise InvalidPacket("alarm integer exceeds signed32")
    return value


def _names(value):
    # Safe model limit, not a source table or native receive limit.
    if (not isinstance(value, list) or not 1 <= len(value) <= 64
            or any(not isinstance(name, str) or not name or len(name.encode()) > 64
                   or any(ord(char) < 32 for char in name) for name in value)):
        raise InvalidPacket("alarm requires1..64 bounded property names")
    return value


def _requested(value):
    if type(value) in (int, float):
        if type(value) is float and not math.isfinite(value):
            raise InvalidPacket("alarm requires finite numbers")
        # Safe input range avoids implementation-dependent native numeric overflow.
        text = str(_integer(int(value)))
    elif isinstance(value, str):
        if (len(value.encode()) > 64 or any(ord(char) < 32 for char in value)
                or value.startswith(("[", "{"))):
            raise InvalidPacket("alarm requires a bounded scalar string")
        text = value
    else:
        raise InvalidPacket("alarm rejects native unsafe bool/null/container slots")
    match = _INT_PREFIX.match(text)
    number = int(match[1]) if match else 0
    # Native atoi overflow is not a portable contract.
    _integer(number)
    return text, number


def _reply(device, inner, selector, uid, key=None):
    reply = Reply({"t": "pack", "i": selector, "uid": uid,
                   "cid": device.mac, "tcid": "app"}, inner,
                  GENERIC_KEY if selector else key or device.key, CODEC)
    # Source common handler owns a1024-byte envelope scratch buffer.
    if len(encode_reply(reply)) >= 1024:
        raise InvalidPacket("alarm reply exceeds native envelope scratch")
    return reply


def _snapshot(device, now):
    state, key = deepcopy(device.state), device.key
    pending = state.get("_restart")
    watchdog = state.get("_watchdog")
    if watchdog is not None and (pending is None or watchdog < pending[0]):
        pending = (watchdog, False)
    if pending is not None and now >= pending[0]:
        state = dict(INITIAL_STATE)
        if pending[1]:
            # Chosen reproducible replacement for source random12bytes -> base64.
            key = b64encode(sha256(key + b"alarm-reset").digest()[:12])
    return state, key


def _commit(device, state, key, now):
    device.advance(now)
    device.state, device.key = state, key


class Alarm:
    plaintext_types = ("bind", "status", "cmd", "upgrade", "ota", "restart",
                       "reset", "hbok", "loginRes", "tm")

    def validate_state(self, state):
        for name, value in state.items():
            if name not in INITIAL_STATE or type(value) is not int or not -(1 << 31) <= value < (1 << 31):
                raise ValueError("alarm state requires canonical signed32 fields; configure Pow for WorkState")

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        return None

    def advertise(self, device, outer):
        now = monotonic()
        candidate, key = _snapshot(device, now)
        inner = {"t": "dev", "cid": device.mac, "bc": "gree", "brand": "gree",
                 "catalog": "gree", "mac": device.mac, "mid": "80260",
                 "model": "gree", "series": "gree", "name": device.name,
                 "vender": "1", "ver": "V1.0", "lock": 0, "subCnt": 0}
        reply = _reply(device, inner, 1, candidate.get("_uid", 0), key)
        _commit(device, candidate, key, now)
        return [reply]

    def handle(self, device, outer):
        now = monotonic()
        candidate, key = _snapshot(device, now)
        if outer.get("t") == "pack":
            if outer.get("tcid") != device.mac:
                # Source parses tcid without comparing it; strict target admission is policy.
                raise InvalidPacket("wrong alarm target")
            selector = _integer(outer.get("i")) & 255
            uid = _integer(outer.get("uid", candidate.get("_uid", 0)))
            if selector == 2:
                payload = outer.get("pack")
                if not isinstance(payload, str):
                    raise InvalidPacket("alarm plaintext pack must be a string")
                inner = _json(payload.encode())
            else:
                inner = decode_pack(outer, key if selector == 0 else GENERIC_KEY, CODEC)
        else:
            if outer.get("t") not in self.plaintext_types:
                raise InvalidPacket("unsupported alarm plaintext request")
            inner, uid = outer, candidate.get("_uid", 0)
        candidate["_uid"] = uid
        kind = inner.get("t")
        if kind == "bind":
            response = {"t": "bindok", "mac": device.mac,
                        "key": key.decode("ascii"), "r": 200}
            reply_selector = 1
        elif kind == "scan":
            _commit(device, candidate, key, now)
            return self.advertise(device, outer)
        elif kind == "status":
            columns = _names(inner.get("cols"))
            values = {**candidate, "WorkState": candidate["Pow"],
                      "host": "ts.dis.gree.com", "name": device.name,
                      "rssi": "", "hid": device.profile.hid,
                      "InHid": "", "OEEPHid": "", "AllErr": ""}
            # Unknowns are readable zero, not proof of typed property support.
            response = {"t": "dat", "r": 200, "mac": device.mac,
                        "cols": columns, "dat": [values.get(name, 0) if not name.startswith("_")
                                                   else 0 for name in columns]}
            reply_selector = 0
        elif kind == "cmd":
            options = _names(inner.get("opt"))
            values = inner.get("p")
            if not isinstance(values, list) or len(values) != len(options):
                raise InvalidPacket("alarm opt/p arrays must match")
            requested = []
            for name, value in zip(options, values):
                text, number = _requested(value)
                requested.append(text)
                if name in FIELDS:
                    candidate["Pow" if name == "WorkState" else name] = number
            # Unknown and metadata names are source no-ops, still acknowledged.
            response = {"t": "res", "r": 200, "mac": device.mac,
                        "opt": options, "p": requested}
            reply_selector = 0
        elif kind in ("upgrade", "ota"):
            raise InvalidPacket("alarm OTA requires external HTTP/flash, not simulated")
        elif kind in ("restart", "reset"):
            delay = _integer(inner.get("delay", 5000))
            if delay < 0:
                raise InvalidPacket("alarm lifecycle delay must be nonnegative")
            # shortcut: native delay is ticks, use synthetic1ms until tick rate is qualified.
            pending = (now + delay / 1000, kind == "reset")
            if "_restart" not in candidate or pending[0] < candidate["_restart"][0]:
                candidate["_restart"] = pending
            response = None
        elif kind == "hbok":
            candidate["_watchdog"] = now + 180
            response = None
        elif kind == "tm":
            value = inner.get("time")
            if not isinstance(value, str) or len(value) > 19:
                raise InvalidPacket("alarm time must be a calendar string")
            try:
                datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
            except ValueError as exc:
                raise InvalidPacket("invalid alarm calendar") from exc
            # Source discards the requested calendar conversion; no LAN time getter.
            response = None
        else:
            response = None
        replies = [] if response is None else [_reply(device, response, reply_selector, uid, key)]
        _commit(device, candidate, key, now)
        return replies


PROFILES = (Profile(
    "sim-mstwb801a-v1", ("80260",), "362001062978+U-MSTWB801AV1.01.bin",
    "5102a8e6c0efc5fe850a3767709c60fd20433b4a0e25bc165e3cb5917f5d095f",
    INITIAL_STATE, Alarm(), max_request_bytes=1460,
),)
