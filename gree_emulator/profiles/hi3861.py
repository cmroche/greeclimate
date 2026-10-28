"""Hi3861 V1.13 raw schemas; source wire semantics, synthetic immediate board echo.

Scalar bodies were qualified natively; wire bodies by byte-asserted translations.
No vendor runtime, calibrated appliance physics, hardware AES, or full-boot claim.
"""

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
import json
import re

from ..wire import InvalidPacket, Reply, decode_pack
from . import Profile


HID = "362001063856+U-Hi3861-OldV1.13.bin"
SOURCE_SHA256 = "a81b9911635f3dcb00c0949d0881843c354cc070f3cf56de2f70ca6da1f79171"
GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
# Chosen safe model bounds, not a claimed native UDP receive limit.
MAX_PACKET = 1460
MAX_FIELDS = 64
LOCAL = frozenset("time name lock AutoUpdate host hid mid bc DevID MafIdf AppTimer lat lon ReportClientID".split())
# Original descriptor order: name, type, write index/mask/callback, read index/mask/callback.
SCHEMAS = {
    9: (
        ('Pow', 0x94, 1, 128, 0x0, 1, 128, 0x0),
        ('wspd', 0x94, 2, 255, 0x0, 2, 255, 0x0),
        ('mode', 0x94, 1, 7, 0x0, 1, 7, 0x0),
        ('PM2P5', 0x94, 1, 64, 0x0, 1, 64, 0x0),
        ('light', 0x94, 3, 255, 0x0, 3, 255, 0x0),
        ('AirChildLock', 0x94, 4, 1, 0x0, 4, 1, 0x0),
        ('FiltUT', 0x94, 0, 0, 0x0, 12, 255, 0x419b9e),
        ('FiltBT', 0x94, 0, 0, 0x0, 15, 255, 0x419b9e),
        ('wipm25', 0x94, 0, 0, 0x0, 7, 0, 0x419bbe),
        ('wopm25', 0x94, 0, 0, 0x0, 9, 0, 0x419bbe),
        ('ErrorCode', 0x94, 0, 0, 0x0, 11, 255, 0x0),
        ('FiltUPercent', 0x94, 0, 0, 0x0, 17, 255, 0x0),
        ('LifeTimeMesh1', 0x94, 0, 0, 0x0, 18, 255, 0x0),
        ('LifeTimeMesh2', 0x94, 0, 0, 0x0, 22, 255, 0x0),
        ('MeshWarning1', 0x94, 0, 0, 0x0, 19, 3, 0x0),
        ('FomadeValue', 0x94, 0, 0, 0x0, 20, 0, 0x419bca),
        ('TmrOff', 0x93, 1, 0, 0x419bfe, 1, 0, 0x419bd6),
        ('TmrOn', 0x93, 1, 0, 0x419c58, 1, 0, 0x419c2e),
        ('StTmr', 0x93, 1, 0, 0x419cb8, 1, 0, 0x419c8c),
        ('RemLifePerErr1', 0x92, 0, 0, 0x0, 1, 1, 0x0),
        ('RemLifePerErr2', 0x92, 0, 0, 0x0, 1, 2, 0x0),
        ('estate', 0x95, 0, 0, 0x0, 1, 255, 0x0),
        ('estate1', 0x95, 0, 0, 0x0, 2, 31, 0x0),
        ('estate2', 0x95, 0, 0, 0x0, 3, 63, 0x0),
        ('JFerr', 0x95, 0, 0, 0x0, 3, 255, 0x419a9a),
        ('MidType', 0x94, 0, 0, 0x0, 0, 0, 0x419a8c),
        ('meshid', 0x0, 0, 0, 0x0, 0, 0, 0x0),
        ('LifeTimeError', 0x0, 0, 0, 0x0, 0, 0, 0x0),
        ('MsgPM', 0x0, 0, 0, 0x0, 0, 0, 0x0),
        ('fltrst', 0x0, 0, 0, 0x0, 0, 0, 0x0),
    ),
    3: (
        ('Pow', 0x94, 1, 128, 0x0, 1, 128, 0x0),
        ('Humidification', 0x94, 1, 64, 0x0, 1, 64, 0x0),
        ('Swing', 0x94, 1, 32, 0x0, 1, 32, 0x0),
        ('ChildLock', 0x94, 1, 16, 0x0, 1, 16, 0x0),
        ('HeatLevel', 0x94, 1, 7, 0x0, 1, 7, 0x0),
        ('SetTemp', 0x94, 2, 255, 0x0, 2, 255, 0x0),
        ('EnvTemp', 0x94, 0, 0, 0x0, 3, 255, 0x0),
        ('WorkTimeHour', 0x94, 0, 0, 0x0, 4, 255, 0x0),
        ('WorkTimeSec', 0x94, 0, 0, 0x0, 5, 255, 0x0),
        ('RealHeatLevel', 0x94, 0, 0, 0x0, 6, 255, 0x0),
        ('FanLevel', 0x94, 3, 255, 0x0, 7, 255, 0x0),
        ('HeatMode', 0x94, 4, 255, 0x0, 8, 255, 0x0),
        ('TmrOn', 0x93, 1, 128, 0x0, 1, 128, 0x0),
        ('TmrAction', 0x93, 1, 96, 0x0, 1, 96, 0x0),
        ('TmrHour', 0x93, 1, 31, 0x0, 1, 31, 0x0),
        ('TmrMin', 0x93, 2, 63, 0x0, 2, 63, 0x0),
        ('estate', 0x95, 0, 0, 0x0, 1, 255, 0x0),
        ('estate2', 0x95, 0, 0, 0x0, 2, 255, 0x0),
        ('estate3', 0x95, 0, 0, 0x0, 3, 255, 0x0),
        ('JFerr', 0x95, 0, 0, 0x0, 3, 255, 0x419a9a),
        ('MidType', 0x94, 0, 0, 0x0, 0, 0, 0x419a8c),
    ),
    0: (
        ('Pow', 0x94, 1, 128, 0x0, 1, 128, 0x0),
        ('WdSpd', 0x94, 2, 255, 0x419ae4, 2, 255, 0x0),
        ('Mod', 0x94, 1, 7, 0x419b04, 1, 7, 0x0),
        ('Rotate', 0x94, 1, 8, 0x0, 1, 8, 0x0),
        ('Cycle', 0x94, 5, 224, 0x0, 5, 224, 0x0),
        ('SwUpDn', 0x94, 5, 2, 0x0, 5, 2, 0x0),
        ('SwingLfRig', 0x94, 1, 8, 0x0, 1, 8, 0x0),
        ('Wet', 0x94, 1, 64, 0x0, 1, 64, 0x0),
        ('Anion', 0x94, 5, 4, 0x0, 5, 4, 0x0),
        ('HotWind', 0x94, 6, 255, 0x0, 6, 255, 0x0),
        ('TmrHour', 0x93, 1, 31, 0x0, 1, 31, 0x0),
        ('TmrMin', 0x93, 2, 63, 0x0, 2, 63, 0x0),
        ('TmrOn', 0x93, 1, 128, 0x0, 1, 128, 0x0),
        ('TmrAction', 0x93, 1, 96, 0x0, 1, 96, 0x0),
        ('SmartMod', 0x94, 1, 16, 0x0, 1, 16, 0x0),
        ('WetLevel', 0x94, 4, 3, 0x0, 4, 3, 0x0),
        ('Light', 0x94, 5, 1, 0x0, 5, 1, 0x0),
        ('UpDnAngle', 0x94, 7, 255, 0x0, 7, 255, 0x0),
        ('LRAngle', 0x94, 8, 255, 0x0, 8, 255, 0x0),
        ('Temperature', 0x94, 3, 255, 0x0, 3, 255, 0x0),
        ('PM25', 0x94, 0, 0, 0x0, 0, 0, 0x419b40),
        ('estate', 0x95, 0, 0, 0x0, 1, 255, 0x0),
        ('estate1', 0x95, 0, 0, 0x0, 1, 255, 0x0),
        ('estate2', 0x95, 0, 0, 0x0, 2, 255, 0x0),
        ('estate3', 0x95, 0, 0, 0x0, 3, 255, 0x0),
        ('JFerr', 0x95, 0, 0, 0x0, 3, 255, 0x419a9a),
        ('MidType', 0x94, 0, 0, 0x0, 0, 0, 0x419a8c),
    ),
    7: (
        ('WorkStatus', 0x94, 1, 120, 0x0, 1, 120, 0x0),
        ('TotalPureWater', 0x94, 0, 0, 0x0, 27, 255, 0x419d24),
        ('FilterNum', 0x92, 0, 0, 0x0, 1, 255, 0x0),
        ('LifeTimeFilter1', 0x94, 0, 0, 0x0, 4, 255, 0x0),
        ('LifeTimeFilter2', 0x94, 0, 0, 0x0, 5, 255, 0x0),
        ('LifeTimeFilter3', 0x94, 0, 0, 0x0, 6, 255, 0x0),
        ('LifeTimeFilter4', 0x94, 0, 0, 0x0, 7, 255, 0x0),
        ('LifeTimeFilter5', 0x94, 0, 0, 0x0, 8, 255, 0x0),
        ('FilterWarning1', 0x94, 0, 0, 0x0, 2, 3, 0x0),
        ('FilterWarning2', 0x94, 0, 0, 0x0, 2, 12, 0x0),
        ('FilterWarning3', 0x94, 0, 0, 0x0, 2, 3, 0x0),
        ('FilterWarning4', 0x94, 0, 0, 0x0, 2, 12, 0x0),
        ('FilterWarning5', 0x94, 0, 0, 0x0, 3, 3, 0x0),
        ('LifeFilterDays1', 0x94, 0, 0, 0x0, 9, 255, 0x419d18),
        ('LifeFilterDays2', 0x94, 0, 0, 0x0, 11, 255, 0x419d18),
        ('LifeFilterDays3', 0x94, 0, 0, 0x0, 13, 255, 0x419d18),
        ('LifeFilterDays4', 0x94, 0, 0, 0x0, 15, 255, 0x419d18),
        ('LifeFilterDays5', 0x94, 0, 0, 0x0, 17, 255, 0x419d18),
        ('FilterKind1', 0x92, 0, 0, 0x0, 2, 15, 0x0),
        ('FilterKind2', 0x92, 0, 0, 0x0, 2, 240, 0x0),
        ('FilterKind3', 0x92, 0, 0, 0x0, 3, 15, 0x0),
        ('FilterKind4', 0x92, 0, 0, 0x0, 3, 240, 0x0),
        ('FilterKind5', 0x92, 0, 0, 0x0, 4, 15, 0x0),
        ('ErrorCode1', 0x95, 0, 0, 0x0, 1, 255, 0x419d30),
        ('ErrorCode2', 0x95, 0, 0, 0x0, 3, 255, 0x0),
        ('JFerr', 0x95, 0, 0, 0x0, 3, 255, 0x419a9a),
        ('MidType', 0x94, 0, 0, 0x0, 0, 0, 0x419a8c),
    ),
    8: (
        ('Pow', 0x94, 1, 128, 0x0, 1, 128, 0x0),
        ('Status', 0x94, 1, 3, 0x0, 1, 3, 0x0),
        ('SaltStatus', 0x94, 2, 6, 0x0, 2, 6, 0x0),
        ('RecycleStatus', 0x94, 1, 4, 0x0, 1, 4, 0x0),
        ('MotorStatus', 0x94, 0, 0, 0x0, 2, 1, 0x0),
        ('RecycleRemainT', 0x94, 0, 0, 0x0, 3, 255, 0x0),
        ('RecycleTotalT', 0x94, 0, 0, 0x0, 4, 255, 0x419b54),
        ('InsFlowRate', 0x94, 0, 0, 0x0, 8, 255, 0x419b7a),
        ('CycleFlowRate', 0x94, 0, 0, 0x0, 10, 255, 0x419b86),
        ('SaltTotalT', 0x94, 0, 0, 0x0, 12, 255, 0x419b92),
        ('RecycleHour', 0x92, 1, 255, 0x0, 1, 255, 0x0),
        ('RecycleMin', 0x92, 2, 255, 0x0, 2, 255, 0x0),
        ('BJHour', 0x92, 3, 255, 0x0, 0, 0, 0x0),
        ('BJMin', 0x92, 4, 255, 0x0, 0, 0, 0x0),
        ('BJSec', 0x92, 5, 255, 0x0, 0, 0, 0x0),
        ('TmrOn', 0x93, 1, 128, 0x0, 1, 128, 0x0),
        ('TmrAction', 0x93, 1, 96, 0x0, 1, 96, 0x0),
        ('TmrHour', 0x93, 1, 31, 0x0, 1, 31, 0x0),
        ('TmrMin', 0x93, 2, 63, 0x0, 2, 63, 0x0),
        ('eState', 0x95, 0, 0, 0x0, 1, 255, 0x0),
        ('JFerr', 0x95, 0, 0, 0x0, 3, 255, 0x419a9a),
        ('MidType', 0x94, 0, 0, 0x0, 0, 0, 0x419a8c),
    ),
}


def _signed(value):
    return (value + 0x80000000) % 0x100000000 - 0x80000000


def _atoi(value):
    match = re.match(r"^[ \t\n\v\f\r]*([+-]?)([0-9]+)", str(value))
    if match is None:
        return 0
    number = 0
    for digit in match[2]:
        number = (10 * number + ord(digit) - 48) & 0xffffffff
    return _signed(-number if match[1] == "-" else number)


def _shift(mask):
    return (mask & -mask).bit_length() - 1 if mask else 8


def _text(value, maximum, *, empty=False):
    if (not isinstance(value, str) or (not empty and not value)
            or len(value.encode("utf-8")) > maximum or "\0" in value):
        raise InvalidPacket("invalid Hi3861 string")
    return value


def _names(value):
    if not isinstance(value, list) or len(value) > MAX_FIELDS:
        raise InvalidPacket("invalid Hi3861 property batch")
    for name in value:
        _text(name, 19)
        if not name.isascii() or not name.isprintable():
            raise InvalidPacket("invalid Hi3861 property name")
    return value


def _reply(device, inner, index, uid=0, peer="", *, scan=False):
    outer = {"t": "pack", "i": index, "uid": uid,
             "cid": "" if scan else device.mac, "tcid": peer}
    size = len(json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode())
    cipher_size = 16 * (size // 16 + 1)
    envelope_size = len(json.dumps({**outer, "pack": ""}, separators=(",", ":")).encode())
    if envelope_size + 4 * ((cipher_size + 2) // 3) > MAX_PACKET:
        raise InvalidPacket("Hi3861 reply exceeds safe model limit")
    return Reply(outer, inner, GENERIC_KEY if index else device.key, CODEC)


def _write(state, mid, row, request):
    name, flag, wi, wm, callback, _, _, _ = row
    if flag not in (0x92, 0x93, 0x94, 0x95):
        return
    old = state[name]
    state[name] = _signed(request)
    frame = state["_controls"][0x91 if flag == 0x94 else flag]
    index = wi + 3
    if callback == 0x419ae4:
        frame[5] = 1 if frame[9] == 1 else request & 255
        if frame[9] == 1:
            state[name] = old
    elif callback == 0x419b04:
        if mid != "828210" and frame[9] == 1:
            frame[5], state[name] = 0, 0
        else:
            frame[4] = (frame[4] & 0xf8) | (request & 7)
    elif callback in (0x419bfe, 0x419c58):
        if request == 1:
            frame[index] = (frame[index] & 31) | (0x80 if callback == 0x419bfe else 0xa0)
    elif callback == 0x419cb8:
        value = min(request, 1440)
        state[name] = value
        if value <= 0:
            frame[index:index + 2] = b"\0\0"
        else:
            frame[index] = (frame[index] & 0xe0) + value // 60
            frame[index + 1] = (frame[index + 1] & 0xc0) | value % 60
    elif wi:
        shift = _shift(wm)
        frame[index] = ((frame[index] & ~wm) + ((request & (wm >> shift)) << shift)) & 255


def _project(state, mid, rows, flag, data):
    state["_reports"][flag][:] = data
    for row in rows:
        name, kind, _, _, _, ri, rm, callback = row
        if kind != flag:
            continue
        index = ri + 3
        old = state[name]
        if callback == 0x419a8c:
            value = state["_midtype"]
        elif callback == 0x419a9a:
            first, second = state["_error_flags"]
            value = int(bool(first & 0x40)) + 2 * int(bool(second & 0x10))
        elif callback == 0x419b40:
            value = data[12] | data[13] << 8
        elif callback in (0x419b54, 0x419b7a, 0x419b86, 0x419b92, 0x419d18, 0x419d24, 0x419d30):
            value = data[index] | data[index + 1] << 8
        elif callback in (0x419b9e, 0x419bbe, 0x419bca):
            value = data[index] << 8 | data[index + 1]
        elif callback in (0x419bd6, 0x419c2e):
            value = int(bool(data[index] & 0x80) and bool(data[index] & 0x20) == (callback == 0x419c2e))
        elif callback == 0x419c8c:
            value = (data[index] & 31) * 60 + (data[index + 1] & 63)
        elif ri:
            value = (data[index] & rm) >> _shift(rm)
        else:
            continue
        state[name] = value
        if value != old and flag in (0x92, 0x93, 0x94):
            _write(state, mid, row, value)


def _echo(state, mid, rows):
    # Synthetic board: echo encoded controls into matching report fields, not sensors.
    for _, flag, wi, wm, wc, ri, rm, _ in rows:
        if not wi or flag not in (0x92, 0x93, 0x94):
            continue
        control = state["_controls"][0x91 if flag == 0x94 else flag]
        report = state["_reports"][flag]
        if wc in (0x419bfe, 0x419c58, 0x419cb8):
            report[ri + 3:ri + 5] = control[wi + 3:wi + 5]
        elif ri:
            value = (control[wi + 3] & wm) >> _shift(wm)
            report[ri + 3] = (report[ri + 3] & ~rm) | ((value << _shift(rm)) & rm)
    for flag, report in state["_reports"].items():
        _project(state, mid, rows, flag, bytes(report))


def _get(device, state, name):
    clock = state["_clock"]
    metadata = {
        "name": device.name, "host": state["_host"], "lat": state["_lat"], "lon": state["_lon"],
        "time": f"{int.from_bytes(clock[:2], 'little'):04d}-{clock[7]:02d}-{clock[6]:02d} {clock[4]:02d}:{clock[3]:02d}:{clock[2]:02d}",
        "rssi": (state["_rssi"] + 128) % 256 - 128,
        "lock": 0, "AutoUpdate": 0, "hid": HID, "BtHid": 0, "mid": "", "MOta": 0,
        "bc": "67726565", "DevID": 0, "MafIdf": 0, "Proaddr": 0, "Subcount": 0,
        "vender": "", "mac": device.mac, "ver": "V3.0.0",
    }
    return metadata[name] if name in metadata else state.get(name, 0) if not name.startswith("_") else 0


@dataclass(frozen=True)
class _Number:
    # Keep JSON number tokens distinct from quoted strings until source atoi.
    token: str


def _prepare(names, values):
    if not isinstance(values, list) or len(names) != len(values):
        raise InvalidPacket("mismatched Hi3861 command arrays")
    local, normal = [], []
    for name, value in zip(names, values):
        if type(value) is _Number:
            token = value.token
            if len(token) > 64:
                raise InvalidPacket("Hi3861 numeric token model limit")
            try:
                number = Decimal(token).copy_abs()
            except InvalidOperation as exc:
                raise InvalidPacket("Hi3861 numeric model limit") from exc
            if number > 0xffffffffffffffff:
                raise InvalidPacket("Hi3861 numeric model limit")
        elif type(value) is str:
            _text(value, 64, empty=True)
        else:
            raise InvalidPacket("unsafe Hi3861 scalar token")
        if name in LOCAL:
            if name in ("lat", "lon", "host", "time", "ReportClientID"):
                maximum = 10 if name in ("lat", "lon") else 20 if name == "host" else 19 if name == "time" else 16
                _text(value, maximum, empty=name == "ReportClientID")
                if name == "ReportClientID" and not value.isascii():
                    raise InvalidPacket("Hi3861 client ID must be ASCII")
                if name == "time":
                    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}", value) is None:
                        raise InvalidPacket("incomplete Hi3861 time")
                    try:
                        datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
                    except ValueError as exc:
                        raise InvalidPacket("invalid Hi3861 calendar time") from exc
            local.append((name, value))
        else:
            if type(value) is _Number and value.token.startswith("-") and "." not in value.token:
                raise InvalidPacket("unsafe Hi3861 bare-negative token")
            normal.append((name, _atoi(value.token if type(value) is _Number else value)))
    return local, normal


class Hi3861:
    def __init__(self, schema):
        self.rows = SCHEMAS[schema]
        self.by_name = {row[0]: row for row in self.rows}

    def validate_state(self, state):
        for name, value in state.items():
            if name.startswith("_"):
                continue
            if (name not in self.by_name or type(value) is not int
                    or not -0x80000000 <= value <= 0x7fffffff
                    or (self.by_name[name][1] == 0 and value != 0)):
                raise ValueError(f"invalid Hi3861 raw state {name!r}")

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        pass

    def receive_report(self, device, flag, data):
        """Explicit synthetic serial input, not a LAN operation or measured hardware."""
        if flag not in device.state["_reports"] or not isinstance(data, bytes) or len(data) != 52:
            raise ValueError("expected a Hi3861 52-byte raw report")
        _project(device.state, device.mid, self.rows, flag, data)

    def advertise(self, device, outer):
        inner = {"t": "dev", "cid": "", "bc": "gree", "brand": "gree", "catalog": "gree",
                 "mac": device.mac, "mid": device.mid, "model": "gree", "name": device.name,
                 "lock": 0, "series": "gree", "vender": "1", "ver": "V3.0.0"}
        return [_reply(device, inner, 1, scan=True)]

    def handle(self, device, outer):
        if outer.get("t") != "pack" or outer.get("tcid") != device.mac:
            raise InvalidPacket("wrong Hi3861 target")
        index, uid, peer = outer.get("i"), outer.get("uid", 0), outer.get("cid", "")
        if type(index) is not int or index not in (0, 1):
            raise InvalidPacket("invalid Hi3861 key selector")
        if type(uid) is not int or not -0x80000000 <= uid <= 0x7fffffff:
            raise InvalidPacket("invalid Hi3861 uid")
        _text(peer, 63, empty=True)
        _text(outer.get("pack"), MAX_PACKET)
        inner = decode_pack(outer, GENERIC_KEY if index else device.key, CODEC,
                            number_parser=_Number)
        kind = _text(inner.get("t"), 15)
        mac = inner.get("mac", inner.get("sub", device.mac))
        _text(mac, 31)
        if "sub" in inner:
            _text(inner["sub"], 31)
        if kind == "bind":
            return [_reply(device, {"r": 200, "t": "bindok", "mac": mac,
                                    "key": device.key.decode("ascii")}, index, uid, peer)]
        if kind == "status":
            names = _names(inner.get("cols"))
            return [_reply(device, {"t": "dat", "uid": 0, "mac": mac, "cid": device.mac,
                                    "dat": [_get(device, device.state, name) for name in names],
                                    "cols": names, "r": 200}, index, uid, peer)]
        if kind != "cmd":
            return []
        names = _names(inner.get("opt"))
        local, normal = _prepare(names, inner.get("p"))
        candidate = deepcopy(device.state)
        for name, value in local:
            if name in ("lat", "lon"):
                candidate["_" + name] = value
            elif name == "host":
                candidate["_configured_host"] = value
            elif name == "time":
                fields = [int(part) for part in re.findall(r"[0-9]+", value)]
                year, month, day, hour, minute, second = fields
                candidate["_clock"] = year.to_bytes(2, "little") + bytes((second, minute, hour, 0, day, month))
            elif name == "ReportClientID":
                encoded = value.encode("ascii")
                candidate["_client_id_buffer"] = b"\x7e\x7e\x12\x6a" + encoded + bytes(26 - len(encoded))
                candidate["_client_id_pending"] = True
        for name, value in normal:
            if name in self.by_name:
                _write(candidate, device.mid, self.by_name[name], value)
        options = [name for name, _ in local if name != "ReportClientID"] + [name for name, _ in normal]
        values = [_get(device, candidate, name) for name, _ in local if name not in ("ReportClientID", "AppTimer")]
        values.extend(value for _, value in normal)
        reply = _reply(device, {"t": "res", "mac": mac, "p": values, "opt": options, "r": 200}, index, uid, peer)
        _echo(candidate, device.mid, self.rows)
        device.state.clear()
        device.state.update(candidate)
        return [reply]


def _initial(schema):
    return {**{row[0]: 0 for row in SCHEMAS[schema]},
            "_controls": {flag: bytearray(52) for flag in (0x91, 0x92, 0x93, 0x95)},
            "_reports": {flag: bytearray(52) for flag in (0x92, 0x93, 0x94, 0x95)},
            "_clock": bytes.fromhex("ea07000000000101"), "_rssi": 206,
            "_midtype": 0, "_error_flags": (0, 0), "_host": "dis.gree.com",
            "_configured_host": "dis.gree.com", "_lat": "", "_lon": "",
            "_client_id_buffer": bytes(30), "_client_id_pending": False}


PROFILES = (
    Profile(id='sim-hi3861-v113-fan', mids=('828202', '828203', '828204', '828205', '828208', '828209', '828210', '828211', '828213'),
            hid=HID, source_sha256=SOURCE_SHA256,
            initial_state=_initial(0), handler=Hi3861(0)),
    Profile(id='sim-hi3861-v113-heater', mids=('828a00', '828a01', '828a02', '828a03', '828a04', '828a05'),
            hid=HID, source_sha256=SOURCE_SHA256,
            initial_state=_initial(3), handler=Hi3861(3)),
    Profile(id='sim-hi3861-v113-purifier', mids=('828301', '828306', '828307', '828308', '828309', '828310'),
            hid=HID, source_sha256=SOURCE_SHA256,
            initial_state=_initial(7), handler=Hi3861(7)),
    Profile(id='sim-hi3861-v113-softener', mids=('829000',),
            hid=HID, source_sha256=SOURCE_SHA256,
            initial_state=_initial(8), handler=Hi3861(8)),
    Profile(id='sim-hi3861-v113-air', mids=('828100', '828103', '828105'),
            hid=HID, source_sha256=SOURCE_SHA256,
            initial_state=_initial(9), handler=Hi3861(9)),
)
