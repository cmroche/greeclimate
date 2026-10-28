"""Source-qualified W05Z/BA raw power controllers, not calibrated appliances.

Synthetic IO: command GPIO is already at the requested level (raw Pow survives),
timer actions set the virtual relay to 0/1, and neither changes meter caches.
RTC starts at 2026-01-01 on the first accepted operation; monotonic seconds are
sampled once per accepted status/command (late ticks preserve native wrap).
Strict JSON, matching signed32 batches, universal target/conflict checks and
post-validation UID mutation deliberately replace unsafe native parsing/order.
"""

from datetime import datetime, timedelta
import json
import time

from ..wire import InvalidPacket, Reply, decode_pack
from . import Profile


GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
FIELDS = ("Pow", "CountDownTime", "CountDownState", "CountDownFlag",
          "RealTimeVoltage", "RealTimeEleCurrent", "RealTimePower", "EnergyOfTime",
          "EnergyOfTimeFlag", "StartTime", "EndTime", "Electnumzero", "hid", "time",
          "MessagePushFlag", "rssi")
CONTROLS = frozenset(FIELDS)
INITIAL_STATE = dict.fromkeys(FIELDS, 0)
METERS = frozenset(FIELDS[4:7])


def _reply(device, inner, index, uid):
    length = len(json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode())
    encrypted_length = (length // 16 + 1) * 16
    if encrypted_length > 1024 or 4 * ((encrypted_length + 2) // 3) >= 1024:
        raise InvalidPacket("W05Z reply exceeds the firmware scratch buffer")
    return Reply({"t": "pack", "i": index, "uid": uid,
                  "cid": device.mac, "tcid": ""}, inner,
                 GENERIC_KEY if index else device.key, CODEC, trailing_newline=True)


def _columns(value):
    if (not isinstance(value, list)
            or any(not isinstance(name, str) or not name or "\0" in name for name in value)):
        raise InvalidPacket("invalid W05Z property array")
    return value


def _clock(state, now):
    origin = state.setdefault("_clock_origin", now)
    seconds = int(max(0, now - origin))
    return seconds & 0xffffffff, (datetime(2026, 1, 1)
                                + timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S")


def _tick(state, now):
    if state["CountDownFlag"] != 1:
        return
    elapsed = (now - state.get("_countdown_start", 0)) & 0xffffffff
    duration = state.get("_countdown_seconds", 0)
    if elapsed >= duration:
        state["CountDownFlag"] = 0
        state["Pow"] = int(state["CountDownState"] == 1)
    if elapsed % 60 == 0 and state["CountDownTime"] != 0:
        state["CountDownTime"] = (duration // 60 - elapsed // 60) & 65535


def _get(device, state, name, calendar):
    if name in METERS:
        return state[name] if state["Pow"] == 1 else 0
    if name in ("StartTime", "EndTime"):
        # One shared readout, not command scratch or invented calendar writes.
        backing = state.get("_calendar_words", (0,) * 8)
        start = 0 if name == "StartTime" else 3
        return list(backing[start:start + 5])
    if name == "hid":
        return device.profile.hid
    if name == "time":
        return calendar
    if name == "rssi":
        return -state.get("_driver_signal", 0)
    return state[name]


class W05Z:

    def validate_state(self, state):
        if any(name not in CONTROLS or type(value) is not int or not 0 <= value <= 65535
               for name, value in state.items()):
            raise ValueError("W05Z state must contain modeled uint16 cache fields")

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        """No ambient LAN field exists in this raw controller."""

    def advertise(self, device, outer):
        inner = {"t": "dev", "cid": "", "bc": "gree", "catalog": "gree",
                 "mid": device.mid, "lock": 0, "model": "gree", "name": device.name,
                 "series": "gree", "vender": "2", "ver": "V1.2.1",
                 "brand": "gree", "mac": device.mac}
        return [_reply(device, inner, 1, device.state.get("_uid", 0))]

    def handle(self, device, outer):
        if outer.get("t") != "pack" or outer.get("tcid") != device.mac:
            raise InvalidPacket("wrong W05Z target")
        index = outer.get("i")
        uid = outer.get("uid", device.state.get("_uid", 0))
        if (type(index) is not int or not -(1 << 31) <= index < (1 << 31)
                or not isinstance(outer.get("cid", ""), str)):
            raise InvalidPacket("invalid W05Z key selector or route")
        if type(uid) is not int:
            uid = device.state.get("_uid", 0)
        elif not -(1 << 31) <= uid < (1 << 31):
            raise InvalidPacket("invalid W05Z UID")
        packed = outer.get("pack")
        if not isinstance(packed, str) or len(packed) >= 1024:
            raise InvalidPacket("W05Z request exceeds the firmware scratch buffer")
        inner = decode_pack(outer, GENERIC_KEY if index else device.key, CODEC)
        for selector in ("mac", "sub"):
            if selector in inner and inner[selector] != device.mac:
                raise InvalidPacket("conflicting W05Z inner identity")
        kind = inner.get("t")
        if kind in ("bind", "status") and inner.get("mac") != device.mac:
            raise InvalidPacket("W05Z operation requires root inner identity")
        if kind == "bind":
            reply = _reply(device, {"t": "bindok", "mac": device.mac, "r": 200,
                                    "key": device.key.decode("ascii")}, 1, uid)
            device.state["_uid"] = uid
            return [reply]
        if kind not in ("status", "cmd"):
            device.state["_uid"] = uid
            return []
        columns = _columns(inner.get("cols" if kind == "status" else "opt"))
        if kind == "cmd":
            values = inner.get("p")
            if (not isinstance(values, list) or len(columns) != len(values)
                    or any(type(value) is not int or not -(1 << 31) <= value < (1 << 31)
                           for value in values)):
                raise InvalidPacket("W05Z command requires matching signed32 integer values")
        # All work, including timers, happens on a pending snapshot until sizing passes.
        pending = dict(device.state)
        now, calendar = _clock(pending, time.monotonic())
        _tick(pending, now)
        selected, applied = [], []
        for offset, name in enumerate(columns):
            if name not in CONTROLS:
                continue
            selected.append(name)
            if kind == "status":
                if name != "Electnumzero":
                    applied.append(_get(device, pending, name, calendar))
                continue
            pending[name] = values[offset] & 65535
            if name == "Electnumzero" and pending[name] == 1:
                pending[name] = 0
                pending["_energy_accumulation"] = 0
            if name in ("hid", "time"):
                applied.append(_get(device, pending, name, calendar))
            else:
                applied.append(pending[name])
            if name == "Pow" and pending["CountDownFlag"] == 1:
                pending["CountDownFlag"] = 0
            if name == "CountDownFlag":
                if pending[name] == 0:
                    applied.append(0)
                elif pending[name] == 1:
                    if pending["CountDownTime"]:
                        pending["_countdown_start"] = now
                        pending["_countdown_seconds"] = pending["CountDownTime"] * 60
                    else:
                        pending["Pow"] = int(pending["CountDownState"] != 0)
        reply = _reply(device, {"t": "dat" if kind == "status" else "res",
                                "mac": device.mac, "r": 200,
                                "cols" if kind == "status" else "opt": selected,
                                "dat" if kind == "status" else "p": applied}, 0, uid)
        pending["_uid"] = uid
        device.state.update(pending)
        return [reply]


PROFILES = (
    Profile(id="sim-w05z-v2.28", mids=("80801",),
            hid="362001063300+U-W05ZV2.28.bin",
            source_sha256="8c4c8ee3bf03c9ba9f7760d02a90dec13341b6a6a2704bfed119222f2f0e7bd2",
            initial_state=INITIAL_STATE, handler=W05Z(), max_request_bytes=1024),
    Profile(id="sim-w05ba-v1.11", mids=("80801",),
            hid="362001064475+W05BAV1.11.bin",
            source_sha256="cbc64ae1288306b8deabcc16a9d00d8b23a38c7581ff8a948a1acb258659cfca",
            initial_state=INITIAL_STATE, handler=W05Z(), max_request_bytes=1024),
)
