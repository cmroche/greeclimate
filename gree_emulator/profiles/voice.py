"""Complete IS-T3BBW03 V3.62/V3.68 root LAN caches, not physical appliances.

Clock starts at the Unix epoch; power defaults to zero and IR learning has no
synthetic receiver. Audio/FIFO/database/clock writes never touch host devices.
Strict typed, atomic batches replace unsafe native parsing and partial writes.
"""

import json
import math
import re
import struct
import time
from datetime import datetime, timedelta, timezone

from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile


GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
CONTROLS = frozenset((
    "Pow", "Mod", "SwhSlp", "SwhSw", "WdSpd", "SetTem", "Blo", "Health",
    "Lig", "TemUn", "TemRec", "Air", "SwUpDn", "SwingLfRig", "SvSt", "StHt",
    "Intellblo1", "AirOpen", "SlpMod", "Tur", "Quiet", "VoltErr", "CurrErr",
    "PowerErr", "RelayErr",
))
SELECTORS = (
    "Pow", "Mod", "SwhSlp", "SwhSw", "WdSpd", "SetTem", "Blo", "Health",
    "Lig", "TemUn", "TemRec", "Air", "SwUpDn", "SwingLfRig", "SvSt", "StHt",
    "Intellblo1", "AirOpen", "SlpMod", "Tur", "Quiet", "VoltErr", "CurrErr",
    "PowerErr", "RelayErr", "ACCntlrShape", "AppTimer", "RealTimePower", "Savpow",
    "ProTimePow", "ProTimeLen", "ProTimeReminder", "SendButton", "AddButton",
    "DelButton", "Studied", "ConBtnNum", "ConBtnName", "RefBtnList", "Electnumzero",
    "hid", "time", "MidType", "VoiceVolume", "VoiceGate",
)
CACHE_FIELDS = frozenset(SELECTORS) - {"hid", "time", "RealTimePower", "RefBtnList"}
GUARDS = frozenset(("ProTimePow", "ProTimeLen", "ProTimeReminder"))
AUDIO = frozenset(("VoiceVolume", "VoiceGate"))
INITIAL_STATE = {**dict.fromkeys(sorted(CACHE_FIELDS), 0),
                 "Mod": 1, "WdSpd": 1, "SetTem": 26, "Lig": 1, "_uid": 0}
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _clock_value(value):
    if not isinstance(value, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", value):
        raise InvalidPacket("voice time requires YYYY-MM-DD HH:MM:SS")
    try:
        return (datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc) - EPOCH).total_seconds()
    except ValueError as exc:
        raise InvalidPacket("invalid voice calendar time") from exc


def _advance(state, now):
    elapsed = max(0, now - state.get("_tick_at", now))
    state["_tick_at"] = now
    state["_clock"] = min(253402300799, state.get("_clock", 0) + elapsed)
    ticks = int(state.get("_guard_fraction", 0) + elapsed)
    state["_guard_fraction"] = state.get("_guard_fraction", 0) + elapsed - ticks
    if state["ProTimePow"] != 1 or not ticks:
        return
    power = struct.unpack("<f", struct.pack("<f", state.get("_power", 0)))[0]
    if state["ProTimeReminder"] == 1:
        if power < 5:
            state["ProTimeReminder"] = 0
            if ticks > 1:
                state.update(_guard_active=0, _guard_ticks=0)
        return
    if state["ProTimeReminder"] != 0:
        return
    if power > 5:
        state["_guard_active"] = 1
    elif power < 5:
        state["_guard_active"] = 0
    if not state.get("_guard_active", 0):
        state["_guard_ticks"] = 0
        return
    previous = state.get("_guard_ticks", 0)
    target = state["ProTimeLen"] * 3600
    distance = ((target - previous) & 0xffffffff) or (1 << 32)
    if distance <= ticks:
        state.update(ProTimeReminder=1, _guard_ticks=0)
    else:
        state["_guard_ticks"] = (previous + ticks) & 0xffffffff


def _read(device, state, name):
    if name == "hid":
        return [device.profile.hid]
    if name == "time":
        clock = EPOCH + timedelta(seconds=int(state.get("_clock", 0)))
        return [f"{clock.year}-{clock:%m-%d %H:%M:%S}"]
    if name == "RealTimePower":
        power = struct.unpack("<f", struct.pack("<f", state.get("_power", 0)))[0]
        return [max(0, min(0xffffffff, int(power)))]
    if name == "RefBtnList":
        # No synthetic IR receiver: learning requests never invent received codes.
        return [[], []]
    return [state[name]]


def _validate_value(name, value):
    if name == "time":
        _clock_value(value)
    elif name in ("ConBtnName", "hid") and isinstance(value, str):
        if "\0" in value or len(value.encode("utf-8")) > 19:
            raise InvalidPacket("voice string exceeds safe shared name buffer")
    elif name == "DelButton" and isinstance(value, list):
        if len(value) > 128 or any(type(item) is not int or not -(1 << 31) <= item < (1 << 31)
                                   for item in value):
            raise InvalidPacket("voice deletion requires bounded int32 indices")
    elif type(value) is not int or not -(1 << 31) <= value < (1 << 31):
        raise InvalidPacket("voice command requires signed int32 values")


def _command(device, state, names, values, now):
    selected, applied = [], []
    skip_ir = False
    for name, value in zip(names, values):
        if name not in SELECTORS:
            continue
        selected.append(name)
        if type(value) is int and name in CACHE_FIELDS:
            state[name] = value & 65535
        if isinstance(value, str):
            state["_command_string"] = value
        if name in CONTROLS:
            applied.append(state[name])
            if name in ("SwhSlp", "SlpMod") and value == 1 and state["SvSt"] == 1:
                state.update(SwhSlp=1, SlpMod=1, SvSt=0)
            elif name == "SvSt" and value == 1 and state["SwhSlp"] == state["SlpMod"] == 1:
                state.update(SwhSlp=0, SlpMod=0)
        elif name in GUARDS:
            skip_ir = True
            applied.append(value)
            if name == "ProTimePow":
                state["ProTimeReminder"] = 0
        elif name in AUDIO:
            skip_ir = True
            if len(names) == 1:
                state["_saved_gate"] = state["VoiceGate"]
                state["VoiceGate"] = 0
                state["_saved_volume"] = state["VoiceVolume"]
            elif len(names) == 2:
                state["_audio_count"] = state.get("_audio_count", 0) + 1
                applied.append(value)
                if state["_audio_count"] == 2:
                    state.update(_audio_count=0, _saved_gate=state["VoiceGate"],
                                 _saved_volume=state["VoiceVolume"])
        elif name in ("hid", "time"):
            skip_ir = True
            if name == "hid":
                applied.append(device.profile.hid)
            else:
                state.update(_clock=_clock_value(value), _tick_at=now)
                applied.append(value)
        elif name in ("SendButton", "AddButton", "DelButton", "Studied",
                      "ConBtnNum", "ConBtnName", "RefBtnList"):
            if len(names) >= 45:
                continue
            skip_ir = True
            if name == "DelButton":
                # Original vmov.f64 immediate is 26, not the old decompiler's zero.
                applied.append(26)
                if isinstance(value, list) and value:
                    state["AddButton"] = 0
            else:
                state["AddButton"] = 0
                if name == "SendButton":
                    applied.append(value)
                elif name == "AddButton" and value == 28:
                    state["_ir_state"] = 5
                    applied.append(26)
                elif name == "Studied":
                    applied.append(value)
                    if value == 2:
                        state.update(_ir_state=6, Studied=0)
                elif name == "ConBtnNum" and state.get("_ir_state", 0) == 1:
                    state.update(_ir_state=2, _button_number=value)
                    applied.append(value)
                elif name == "ConBtnName" and state.get("_ir_state", 0) == 2:
                    state["_ir_state"] = 0
                    applied.append(state.get("_command_string", ""))
        else:
            skip_ir = name == "Electnumzero"
    if not skip_ir:
        state.update(SwhSw=int(bool(state["SwUpDn"] or state["SwingLfRig"])),
                     Tur=int(state["WdSpd"] == 6), Quiet=int(state["WdSpd"] == 7))
    return selected, applied


def _reply(device, inner, index, uid):
    size = len(json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode())
    encrypted_size = (size // 16 + 1) * 16
    if size >= 1024 or 4 * ((encrypted_size + 2) // 3) >= 1024:
        raise InvalidPacket("voice reply exceeds native plaintext/base64 scratch")
    reply = Reply({"t": "pack", "i": index, "uid": uid,
                   "cid": device.mac, "tcid": ""}, inner,
                  GENERIC_KEY if index else device.key, CODEC, trailing_newline=True)
    # Model safety bound, not the independently evidenced native receive limit.
    if len(encode_reply(reply)) > 1024:
        raise InvalidPacket("voice reply exceeds model datagram limit including LF")
    return reply


def _fields(value):
    # Native loops have no count guard; finite arrays are an explicit safe policy.
    if (not isinstance(value, list) or len(value) > 128
            or any(not isinstance(name, str) or not name or "\0" in name for name in value)):
        raise InvalidPacket("voice requires at most128 nonempty property names")
    return value


class VoiceController:
    def validate_state(self, state):
        for name, value in state.items():
            if name == "_uid" and type(value) is int and -(1 << 31) <= value < (1 << 31):
                continue
            if (name == "_power" and type(value) in (int, float)
                    and math.isfinite(value) and abs(value) <= 3.4028234663852886e38):
                continue
            if name not in CACHE_FIELDS or type(value) is not int or not 0 <= value <= 65535:
                raise ValueError("voice state requires uint16 cache or finite synthetic power")

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        """This roomless IR controller has no ambient LAN field."""

    def advertise(self, device, outer):
        inner = {"t": "dev", "cid": "", "bc": "gree", "catalog": "gree",
                 "mid": device.mid, "lock": 0, "model": "gree", "name": device.name,
                 "series": "gree", "vender": "2", "ver": "V1.2.1",
                 "brand": "gree", "mac": device.mac}
        return [_reply(device, inner, 1, device.state["_uid"])]

    def handle(self, device, outer):
        if outer.get("t") != "pack" or outer.get("tcid") != device.mac:
            raise InvalidPacket("wrong voice controller target")
        index, uid = outer.get("i"), outer.get("uid")
        if (type(index) is not int or index not in (0, 1) or type(uid) is not int
                or not -(1 << 31) <= uid < (1 << 31)
                or not isinstance(outer.get("cid", ""), str)):
            raise InvalidPacket("invalid voice key selector or route")
        inner = decode_pack(outer, GENERIC_KEY if index else device.key, CODEC)
        # Native cmd ignores inner identity; strict root-only policy rejects conflicts.
        for selector in ("mac", "sub"):
            if selector in inner and inner[selector] != device.mac:
                raise InvalidPacket("conflicting voice inner identity")
        kind = inner.get("t")
        if kind == "bind":
            if index != 1 or inner.get("mac") != device.mac:
                raise InvalidPacket("voice bind requires default key and matching mac")
            reply = _reply(device, {"t": "bindok", "mac": device.mac, "r": 200,
                                    "key": device.key.decode("ascii")}, 1, uid)
        elif kind == "status":
            if index != 0 or inner.get("mac") != device.mac:
                raise InvalidPacket("voice status requires device key and matching mac")
            columns = _fields(inner.get("cols"))
            pending = dict(device.state)
            _advance(pending, time.monotonic())
            selected = [name for name in columns if name in SELECTORS]
            reply = _reply(device, {"t": "dat", "mac": device.mac, "r": 200,
                                    "cols": selected,
                                    "dat": [value for name in selected
                                            for value in _read(device, pending, name)]}, 0, uid)
            device.state.update(pending)
        elif kind == "cmd":
            if index != 0:
                raise InvalidPacket("voice commands require device key")
            names, values = _fields(inner.get("opt")), inner.get("p")
            if not isinstance(values, list) or len(names) != len(values):
                raise InvalidPacket("voice command requires equal opt/p arrays")
            for name, value in zip(names, values):
                _validate_value(name, value)
            pending = dict(device.state)
            now = time.monotonic()
            _advance(pending, now)
            selected, applied = _command(device, pending, names, values, now)
            reply = _reply(device, {"t": "res", "mac": device.mac, "r": 200,
                                    "opt": selected, "p": applied}, 0, uid)
            device.state.update(pending)
        else:
            device.state["_uid"] = uid
            return []
        device.state["_uid"] = uid
        return [reply]


PROFILES = (Profile(
    id="sim-is-t3bbw03-v3.62", mids=("80222",),
    hid="362001062573+IS-T3BBW03V3.62.img",
    source_sha256="c5d79f0aa5767afcea98d1b6e333eefcb74f7adfa8a37e8870bb0f92fd7d913c",
    initial_state=INITIAL_STATE, handler=VoiceController(), max_request_bytes=1024,
), Profile(
    id="sim-is-t3bbw03-v3.68", mids=("80222",),
    hid="362001062573+IS-T3BBW03V3.68.img",
    source_sha256="633ddc7cf1f64c7d02faba8e7dd614dc20b0d1c4549bb7d0b4c86eabff8130b7",
    initial_state=INITIAL_STATE, handler=VoiceController(), max_request_bytes=1024,
))
