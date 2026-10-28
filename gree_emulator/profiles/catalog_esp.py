"""ESP32 CAN raw RAM semantics; mainboard bytes are deliberately synthetic."""

from copy import deepcopy
from datetime import datetime, timedelta
import math
import re
from time import monotonic

from ..wire import InvalidPacket, Reply, _json, decode_pack, encode_reply
from . import Profile

SCHEMAS = (
    {
        "GetEr": (0, 0, 5, 255, 0, 0),
        "AllErr": (1, 0, 5, 255, 0, 0),
        "Pow": (2, 0, 6, 255, 0, 0),
        "MasSub": (3, 0, 7, 255, 0, 0),
        "SvSt": (4, 0, 8, 255, 0, 0),
        "Blo": (5, 0, 9, 255, 0, 0),
        "Air": (6, 0, 10, 255, 0, 0),
        "Mod": (7, 0, 11, 255, 0, 0x40187f9c),
        "WdSpd": (8, 0, 15, 255, 0x40187f7c, 0x400db61c),
        "SwhSlp": (9, 0, 13, 255, 0, 0x40187f58),
        "Tur": (10, 0, 14, 255, 0, 0),
        "Quiet": (11, 0, 12, 255, 0x400db5b8, 0x400db5e8),
        "SetTem": (12, 0, 16, 65535, 0x400db414, 0x400db43c),
        "SetDeciTem": (13, 0, 16, 65535, 0, 0),
        "CoolSvStTemMin": (14, 0, 18, 65535, 0x400db414, 0x400db43c),
        "HeatSvStTemMax": (15, 0, 20, 65535, 0x400db414, 0x400db43c),
        "HumiSvStTemMin": (16, 0, 22, 65535, 0x400db414, 0x400db43c),
        "MasIDUMod": (17, 0, 28, 255, 0, 0),
        "GoOut": (18, 0, 29, 255, 0, 0),
        "OutHome": (19, 0, 29, 255, 0, 0),
        "AidHeat": (20, 0, 31, 255, 0, 0),
        "AssHt": (21, 0, 31, 255, 0x40188090, 0x401880b0),
        "SetCoolHumi": (22, 0, 32, 255, 0, 0),
        "TemBody": (23, 0, 34, 1, 0, 0),
        "HumiEnable": (24, 0, 34, 2, 0, 0),
        "SwUpDn": (25, 0, 35, 255, 0x40187fd4, 0x40187ff4),
        "SwingLfRig": (26, 0, 36, 255, 0x40188008, 0x40188050),
        "Add0.1": (27, 0, 37, 255, 0x400db488, 0x400db4b4),
        "Add0.5": (28, 0, 37, 255, 0x400db510, 0x400db544),
        "ErrType1": (29, 0, 50, 65535, 0, 0),
        "ErrType2": (30, 0, 52, 65535, 0, 0),
        "Heat3DSvStTemMax": (31, 0, 24, 65535, 0x400db414, 0x400db43c),
        "Heat2SvStTemMax": (32, 0, 26, 65535, 0x400db414, 0x400db43c),
        "LowDeHumi": (33, 0, 38, 255, 0, 0),
        "CleanTime": (34, 1, 6, 255, 0, 0),
        "CleanState": (35, 1, 7, 255, 0, 0),
        "AutoClean": (36, 1, 8, 255, 0x401880e8, 0x401880f8),
        "SysSta": (37, 1, 9, 255, 0, 0),
        "MidType": (38, 0, -1, 0, 0x40188114, 0),
    },
    {
        "GetEr": (0, 0, 0, 255, 0x401880cc, 0),
        "Pow": (1, 0, 5, 255, 0, 0),
        "Tur": (2, 0, 6, 255, 0, 0),
        "ModS": (3, 0, 7, 255, 0, 0),
        "FanMod": (4, 0, 8, 255, 0, 0),
        "WdSpd": (5, 0, 9, 255, 0x400db65c, 0x400db6d4),
        "RunMod": (6, 0, 10, 255, 0, 0),
        "IDUAirQu": (7, 0, 11, 255, 0, 0),
        "ODUViti": (8, 0, 12, 255, 0, 0),
        "Inloop": (9, 0, 13, 255, 0, 0),
        "InVitiGr": (10, 0, 15, 255, 0, 0),
        "InVitiGrCg": (11, 0, 16, 255, 0, 0),
        "IFDtiGr": (12, 0, 17, 255, 0, 0),
        "VitiGr": (13, 0, 18, 255, 0, 0),
        "TemSor": (14, 0, 19, 255, 0x400db740, 0),
        "HumSor": (15, 0, 24, 255, 0x400db740, 0),
        "InEffClRes": (16, 0, 29, 255, 0, 0),
        "InEffReRes": (17, 0, 30, 255, 0, 0),
        "AirQu": (18, 0, 31, 255, 0x400db740, 0),
        "PM2P5": (19, 0, 36, 65535, 0x400db740, 0),
        "VOC": (20, 0, 46, 65535, 0x400db740, 0),
        "CO2": (21, 0, 56, 65535, 0x400db740, 0),
        "PctCle": (22, 0, 66, 255, 0, 0),
        "PctRe": (23, 0, 67, 255, 0, 0),
        "IFDClRes": (24, 0, 68, 255, 0, 0),
        "EffReRes": (25, 0, 69, 255, 0, 0),
        "GasQ": (26, 0, 70, 31, 0, 0),
        "GasAvail": (27, 0, 71, 31, 0x400db740, 0),
        "GasLED": (28, 0, 72, 31, 0x400db740, 0),
        "GasMod": (29, 0, 73, 31, 0x400db740, 0),
        "GasMas": (30, 0, 74, 31, 0x400db740, 0),
        "PM2P5Sta": (31, 0, 75, 31, 0x400db740, 0),
        "SorErr": (32, 0, 76, 31, 0x400db740, 0),
        "CommErr": (33, 0, 77, 31, 0x400db740, 0),
        "ErrType": (34, 0, 83, 65535, 0, 0),
        "MIdType": (35, 0, -1, 65535, 0, 0),
        "MidType": (36, 0, -1, 0, 0x40188114, 0),
    },
)


def _schema(physical_type):
    delta = (physical_type - 0x6079) & 65535
    return int(physical_type in (0x605d, 0x60a0)
               or physical_type & 0xfff7 == 0x6091
               or delta < 22 and (0x00300801 >> delta) & 1)


def _emitted_mid(physical_type):
    return "6079" if _schema(physical_type) else f"{physical_type:04x}"


def _format_time(value):
    text = value.strftime("%Y-%m-%d %H:%M:%S")
    # Native tm_mon is zero-based, so its <10 zero-fill also overwrites October.
    return text[:5] + "00" + text[7:] if value.month == 10 else text


_EPOCH = datetime(1970, 1, 1)


def _clock32(seconds):
    # The original mktime result and timeval seconds are stored in one32-bit word.
    seconds = (seconds + (1 << 31)) % (1 << 32) - (1 << 31)
    return _EPOCH + timedelta(seconds=seconds + 8 * 3600)


def _u16(frame, offset):
    return frame[offset] | frame[offset + 1] << 8


def _put16(frame, offset, value):
    frame[offset], frame[offset + 1] = value & 255, value >> 8 & 255


def _store(frame, offset, mask, value):
    if mask == 65535:
        _put16(frame, offset, value)
    elif mask == 255:
        frame[offset] = value & 255
    else:
        # The source uses XOR, not a conventional cleared-bit masked store.
        shift = (mask & -mask).bit_length() - 1
        frame[offset] = ((frame[offset] ^ mask) | value << shift) & 255


def _raw(frame, offset, mask):
    if mask == 65535:
        return _u16(frame, offset)
    shift = (mask & -mask).bit_length() - 1
    return (frame[offset] & mask) >> shift


class CanCache:
    """One gateway's descriptor scratch and source-shaped synthetic board banks.

    Descriptor caches are shared across children, as in the original firmware;
    decimal setters can consequently depend on the preceding getter sequence.
    """

    def __init__(self, schemas=SCHEMAS, quiet_base=0xffff9fbb,
                 fan_one_types=(0x605d, 0x6079, 0x608d)):
        self.schemas = schemas
        self.quiet_base = quiet_base
        self.fan_one_types = fan_one_types
        self.values = [[0] * len(schema) for schema in schemas]
        self.system = [0] * 112

    def copy(self):
        result = CanCache(self.schemas, self.quiet_base, self.fan_one_types)
        result.values = [list(values) for values in self.values]
        result.system = list(self.system)
        return result

    def read(self, schema, board, name, channel=0):
        if not 0 <= channel <= 7:
            raise InvalidPacket("CAN raw sensor channel must fit three bits")
        names = self.schemas[schema]
        if name not in names:
            return 0
        index, owner, offset, mask, getter, _ = names[name]
        frame = self.system if owner else board
        offset += 12
        value = _raw(frame, offset, mask) if mask else 0
        if getter == 0x400db414:
            value = _u16(frame, offset) // 10
        elif getter == 0x400db488:
            value = _u16(frame, 28) % 10
        elif getter == 0x400db510:
            value = int(_u16(frame, 28) % 10 != 0)
        elif getter == 0x400db5b8:
            value = frame[offset]
            if ((_u16(frame, 2) + self.quiet_base) & 65535) < 2 and value:
                value = 1
        elif getter == 0x40187f7c:
            value = 1 if frame[24] == 2 else frame[offset]
        elif getter == 0x400db65c:
            value = frame[offset]
            if frame[offset - 3] == 1:
                value = 6
            elif 2 <= value <= 6:
                value -= 1
            elif value == 1:
                physical = _u16(frame, 2)
                value = 1 if physical in self.fan_one_types or physical & 0xfff7 == 0x6091 else 7
        elif getter == 0x400db740:
            if mask == 65535:
                value = _u16(frame, offset + channel * 2)
            elif mask == 255:
                value = frame[offset + channel]
            else:
                value = frame[offset] >> channel & 1
        elif getter == 0x40187fd4:
            value = max(0, frame[offset] - 1)
        elif getter == 0x40188008:
            raw = frame[offset]
            value = raw - 1 if 1 <= raw <= 7 else raw + 1 if 8 <= raw <= 12 else raw - 6 if 13 <= raw <= 14 else 0
        elif getter == 0x40188090:
            value = int(frame[offset] == 0)
        elif getter == 0x401880cc:
            value = int(bool(frame[95] or frame[96] or frame[12]))
        elif getter == 0x401880e8:
            value = frame[19]
        elif getter == 0x40188114:
            value = _u16(frame, 2)
        self.values[schema][index] = value & 65535
        return value & 65535

    def write(self, schema, board, name, requested):
        if type(requested) is not int or not -(1 << 31) <= requested <= 0xffffffff:
            raise InvalidPacket("CAN raw control requires integer32")
        names = self.schemas[schema]
        if name not in names:
            return
        index, owner, offset, mask, _, setter = names[name]
        if not mask:
            raise InvalidPacket("CAN zero-mask native loop is not a bounded control")
        frame = self.system if owner else board
        values = self.values[schema]
        value = requested & 65535
        values[index] = value
        offset += 12
        _store(frame, offset, mask, value)
        if setter == 0x400db43c:
            value = value * 10 & 65535
            if name == "SetTem":
                fraction_offset = names["Add0.1"][2] + 12
                value = value + frame[fraction_offset] & 65535
            values[index] = value
            _put16(frame, offset, value)
        elif setter in (0x400db4b4, 0x400db544):
            # Identical relative offsets refer to different sibling descriptors.
            target_name = "SetDeciTem" if setter == 0x400db544 else "SetTem"
            target = names[target_name][0]
            raw = values[target]
            remainder = raw % 10
            if not value and not remainder:
                return
            if setter == 0x400db544:
                frame[names["Add0.1"][2] + 12] = value * 5 & 255
                if value and remainder:
                    return
                raw = raw + 5 if value else raw - remainder
            else:
                if value and remainder:
                    return
                raw = raw + value if value else raw - remainder
            values[target] = raw & 65535
            _put16(frame, names[target_name][2] + 12, raw)
        elif setter == 0x400db5e8:
            values[index] = {0: 1, 1: 3, 2: 2}.get(value, 0)
        elif setter == 0x400db61c:
            values[index] = 0 if value == 8 else value + 1 & 65535
            if value != 8:
                values[index + 2] = int(values[index] == 7)
        elif setter == 0x400db6d4:
            if 1 <= value <= 5:
                values[index], values[index - 3] = value + 1, 0
                frame[names["Tur"][2] + 12] = 0
            elif value == 6:
                values[index - 3] = 1
                frame[names["Tur"][2] + 12] = 1
            elif value == 7:
                values[index], values[index - 3] = 1, 0
                frame[names["Tur"][2] + 12] = 0
            else:
                values[index] = 0
        elif setter == 0x40187f58:
            values[index] = {0: 1, 1: 4}.get(value, 0)
        elif setter == 0x40187f9c:
            raw = value & 255
            values[index] = 5 if raw == 0 else raw if raw <= 4 else raw + 1 if raw <= 11 else 0
        elif setter == 0x40187ff4:
            values[index] = value + 1 & 65535
        elif setter == 0x40188050:
            raw = value & 255
            values[index] = raw + 1 if raw < 7 else raw + 6 if raw < 9 else raw - 1 if raw < 14 else 0
        elif setter == 0x401880b0:
            values[index] = int(value & 255 != 1)
        elif setter == 0x401880f8:
            frame[19] = value & 255
            values[index] = 0x66 if value == 1 else 0x67


GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
ROOT_PROFILE = "sim-esp32-gr-can-v2.01"
_CONTEXTS = {
    "wlan": 2, "scan": 2, "subDev": 0, "subBDev": 0, "bind": 1,
    "status": 0, "cmd": 0, "upgrade": 0, "hbok": 2, "loginRes": 1,
    "tm": 2, "queryT": 0, "setT": 0, "updateT": 0, "deleteT": 0, "espLog": 2,
}
_INT_PREFIX = re.compile(r"^[\t\n\v\f\r ]*([+-]?[0-9]+)")


def _integer(value):
    if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
        raise InvalidPacket("CAN requires signed32 integers")
    return value


def _text(value, maximum):
    if (not isinstance(value, str) or len(value.encode()) > maximum
            or any(ord(char) < 32 for char in value)):
        raise InvalidPacket("CAN string exceeds its bounded native buffer")
    return value


def _scalar(value):
    if type(value) in (int, float):
        if type(value) is float and not math.isfinite(value):
            raise InvalidPacket("CAN requires finite scalar controls")
        text = str(_integer(int(value)))
    else:
        text = _text(value, 63)
        if text.startswith(("[", "{")):
            raise InvalidPacket("CAN scalar control cannot contain native JSON injection")
    match = _INT_PREFIX.match(text)
    return text, _integer(int(match[1]) if match else 0)


def _names(value):
    # Safe batch bound replaces unchecked native allocations and string copies.
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise InvalidPacket("CAN requires1..64 property names; empty native buffers are unsafe")
    for name in value:
        if not _text(name, 19):
            raise InvalidPacket("CAN property names cannot be empty")
    return value


class CanGateway:
    """One source gateway or one explicitly selected physical mainboard type."""

    plaintext_types = ("hbok", "tm", "espLog")

    def __init__(self, physical_type=None):
        self.physical_type = physical_type

    def validate_state(self, state):
        if state:
            raise ValueError("CAN starts with chosen zero raw banks; identity overrides are not controls")

    def validate_topology(self, root):
        if self.physical_type is not None:
            return
        for child in root.children:
            if (not isinstance(child.profile.handler, CanGateway)
                    or child.profile.handler.physical_type is None
                    or not child.mac.endswith("00")):
                raise ValueError("CAN children require an exact physical profile and seven-byte ID ending00")
            if child.mid != _emitted_mid(child.profile.handler.physical_type):
                raise ValueError("CAN child MID must be its actually emitted normalized identity")

    @staticmethod
    def _initialize(device, state=None):
        state = device.state if state is None else state
        if "_can_cache" not in state:
            state["_can_cache"] = CanCache()
            state["_can_boards"] = {}
            for child in device.children:
                board = [0] * 112
                _put16(board, 2, child.profile.handler.physical_type)
                board[5:12] = bytes.fromhex(child.mac)
                state["_can_boards"][child.mac] = board
            state["_can_clock"] = datetime(2000, 1, 1)
            state["_can_clock_at"] = monotonic()
            state["_can_timers"] = [None] * 10
            state["_can_timer_total"] = 0
        return state

    @staticmethod
    def _clock(state, now):
        seconds = int((state["_can_clock"] - _EPOCH).total_seconds()) - 8 * 3600
        return _clock32(seconds + int(max(0, now - state["_can_clock_at"])))

    @staticmethod
    def _set_clock(state, text, now, hours=0):
        if not isinstance(text, str) or not re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}", text):
            raise InvalidPacket("CAN time requires YYYY-MM-DD HH:MM:SS")
        try:
            value = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
        except ValueError as exc:
            raise InvalidPacket("CAN time is not a calendar timestamp") from exc
        value = _clock32(int((value - _EPOCH).total_seconds()) - 8 * 3600 + hours * 3600)
        state["_can_clock"], state["_can_clock_at"] = value, now
        return _format_time(value)

    @staticmethod
    def _target(device, state, identity):
        if identity == device.mac:
            return None
        for child in device.children:
            if bytes(state["_can_boards"][child.mac][5:12]).hex() == identity:
                return child
        raise InvalidPacket("CAN request selects an unknown child")

    @staticmethod
    def _reply(device, inner, index=0, uid=0, peer=""):
        if index == 2:
            reply = Reply(inner)
        else:
            reply = Reply({"t": "pack", "i": index, "uid": uid,
                           "cid": device.mac, "tcid": peer}, inner,
                          GENERIC_KEY if index else device.key, CODEC)
        if len(encode_reply(reply)) >= 1024:
            raise InvalidPacket("CAN reply exceeds native1024-byte work buffer")
        return [reply]

    def advertise(self, device, outer):
        if self.physical_type is not None:
            return []
        self._initialize(device)
        return self._reply(device, {
            "t": "dev", "cid": device.mac, "bc": "gree", "brand": "gree",
            "catalog": "gree", "mac": device.mac, "mid": "60", "model": "gree",
            "series": "gree", "name": device.name, "vender": "1", "ver": "V1.0",
            "lock": 0, "subCnt": len(device.children),
        }, 1)

    def encode_room(self, device):
        return None

    def thermal_target(self, device):
        if self.physical_type is None and "_can_cache" in device.state:
            self._tick(device, device.state, monotonic())
        return None

    def _read(self, device, state, child, name, now):
        board = state["_can_boards"].get(child.mac) if child else None
        physical = child.profile.handler.physical_type if child else (
            device.children[0].profile.handler.physical_type if device.children else 0)
        metadata = {
            "host": "dis.gree.com", "name": device.name, "hid": device.profile.hid,
            "rssi": 0, "MIdType": f"{physical:04x}", "bc": "",
            "ElcEn": 0, "time": _format_time(self._clock(state, now)),
        }
        if name in metadata:
            return metadata[name]
        if board is None:
            return 0
        return state["_can_cache"].read(_schema(physical), board, name, state.get("_can_channel", 0))

    def _command(self, device, state, inner, now):
        names = _names(inner.get("opt"))
        values = inner.get("p")
        if not isinstance(values, list) or len(values) != len(names):
            raise InvalidPacket("CAN opt/p arrays must have equal lengths")
        values = [_scalar(value) for value in values]
        child = self._target(device, state, inner.get("sub", device.mac))
        ack = []
        for name, (text, number) in zip(names, values):
            if name == "time":
                ack.append(self._set_clock(state, text, now))
            elif child:
                physical = child.profile.handler.physical_type
                state["_can_cache"].write(_schema(physical), state["_can_boards"][child.mac], name, number)
                ack.append(number)
            else:
                ack.append(text)
        return {"t": "res", "r": 200, "mac": inner.get("sub", device.mac),
                "opt": names, "p": ack, "val": list(ack)}

    def _timer(self, device, state, inner, now):
        kind = inner["t"]
        timers = state["_can_timers"]
        if kind == "queryT":
            start = _integer(inner.get("index", 0)) & 255
            count = _integer(inner.get("count", 0)) & 255
            if start > 10 or not 1 <= count <= 10 - start:
                raise InvalidPacket("CAN timer page requires1..10 safe native records")
            if state["_can_timer_total"] == 255:
                state["_can_timer_total"] = 0
            records = []
            for record in timers[start:start + count]:
                if record is None:
                    records = []
                    break
                first = record["cmd"][0] if record["cmd"] else ""
                value = _json(('{"value":' + first + '}').encode())["value"] if first.startswith(("{", "[")) else first
                records.append({**{key: record[key] for key in (
                    "id", "name", "enable", "hr", "min", "sec", "week", "tz")},
                    "cmd": [value]})
            return {"t": "listT", "total": state["_can_timer_total"], "index": start,
                    "list": records if records else []}
        identity = _integer(inner.get("id"))
        if not 0 <= identity < 10:
            raise InvalidPacket("CAN timer id exceeds ten native records")
        if kind == "deleteT":
            timers[identity] = None
            state["_can_timer_total"] = (state["_can_timer_total"] - 1) & 255
        else:
            record = {"id": identity, "name": _text(inner.get("name", ""), 19)}
            for key in ("enable", "hr", "min", "sec", "tz"):
                record[key] = _integer(inner.get(key, 0))
            week, commands = inner.get("week"), inner.get("cmd")
            if not isinstance(week, list) or len(week) != 7:
                raise InvalidPacket("CAN safe timer requires seven week entries")
            record["week"] = [_integer(value) for value in week]
            if not isinstance(commands, list) or len(commands) > 2:
                raise InvalidPacket("CAN timer command array exceeds two64-byte records")
            record["cmd"] = [_text(command, 63) for command in commands]
            for command in record["cmd"]:
                if command.startswith(("{", "[")):
                    _json(('{"value":' + command + '}').encode())
            if not 0 <= record["hr"] <= 23 or not 0 <= record["min"] <= 59 or not 0 <= record["sec"] <= 59:
                raise InvalidPacket("CAN safe timer requires a valid wall-clock time")
            if timers[identity] is None:
                state["_can_timer_total"] = (state["_can_timer_total"] + 1) & 255
            timers[identity] = record
        return {"t": "resT", "r": 200}

    def _tick(self, device, state, now):
        if state.get("_can_heartbeat_due", float("inf")) <= now:
            state["_can_heartbeat_period"] = 10
            state.pop("_can_heartbeat_due", None)
        armed = state.get("_can_armed")
        if armed:
            deadline, identities = armed
            if now < deadline:
                return
            state.pop("_can_armed")
            for identity in identities:
                record = state["_can_timers"][identity]
                if record is None:
                    continue
                if 1 not in record["week"]:
                    record["enable"] = 1
                for text in record["cmd"]:
                    try:
                        command = _json(text.encode())
                        targets = command.get("mac")
                        if not isinstance(targets, list) or len(targets) > 100:
                            continue
                        for target in targets:
                            self._command(device, state, {**command, "sub": target}, now)
                    except InvalidPacket:
                        # Native scheduled parse/route failures have no ACK.
                        continue
        clock = self._clock(state, now)
        minute = clock.hour * 60 + clock.minute
        weekday = (clock.weekday() + 1) % 7
        identities = [index for index, record in enumerate(state["_can_timers"])
                      if record is not None and record["enable"] == 0
                      and record["hr"] * 60 + record["min"] - minute == 1
                      and (1 not in record["week"] or record["week"][weekday] == 1)]
        if identities:
            state["_can_armed"] = (now + 60 - clock.second - clock.microsecond / 1e6, identities)

    def wlan(self, device, outer):
        return self.handle(device, outer)

    def handle(self, device, outer):
        if self.physical_type is not None:
            return []
        if outer.get("t") == "pack":
            if outer.get("tcid") != device.mac:
                raise InvalidPacket("CAN wrong outer target")
            index = _integer(outer.get("i")) & 255
            uid = _integer(outer.get("uid", 0))
            peer = _text(outer.get("cid", ""), 15)
            if index == 2:
                payload = outer.get("pack")
                if not isinstance(payload, str):
                    raise InvalidPacket("CAN plaintext pack must be a string")
                inner = _json(payload.encode())
            else:
                inner = decode_pack(outer, device.key if index == 0 else GENERIC_KEY, CODEC)
        else:
            inner, index, uid, peer = outer, 2, 0, ""
        kind = inner.get("t")
        if not isinstance(kind, str):
            raise InvalidPacket("CAN operation type must be a string")
        if _CONTEXTS.get(kind) != index:
            return []
        now = monotonic()
        state = self._initialize(device, deepcopy(device.state))
        self._tick(device, state, now)
        reply_index = 0
        if kind == "scan":
            replies = self.advertise(device, outer)
            # A packed plaintext scan retains its request peer and UID.
            replies = self._reply(device, replies[0].inner, 1, uid, peer)
            device.state = state
            return replies
        if kind == "bind":
            response = {"t": "bindok", "mac": device.mac,
                        "key": device.key.decode("ascii"), "r": 200}
            reply_index = 1
        elif kind == "wlan":
            state["_can_wlan"] = {name: _text(inner.get(name, ""), maximum)
                                  for name, maximum in (("ssid", 31), ("psw", 63), ("host", 31))}
            response, reply_index = {"t": "ret", "r": 200, "mac": device.mac}, 2
        elif kind == "status":
            names = _names(inner.get("cols"))
            child = self._target(device, state, inner.get("mac"))
            if child and _schema(child.profile.handler.physical_type) and "GasN" in inner:
                state["_can_channel"] = _integer(inner["GasN"]) & 7
            response = {"t": "dat", "r": 200, "mac": inner["mac"], "cols": names,
                        "dat": [self._read(device, state, child, name, now) for name in names]}
        elif kind == "cmd":
            response = self._command(device, state, inner, now)
        elif kind in ("subDev", "subBDev"):
            if inner.get("mac") != device.mac:
                raise InvalidPacket("CAN enumeration requires its root identity")
            start = _integer(inner.get("i")) & 255
            if kind == "subDev":
                children = device.children[start:start + 5]
                for child in children:
                    state["_can_boards"][child.mac][11] = 0
                response = {"t": "subList", "c": len(device.children), "i": start, "r": 200,
                            "list": [{"mac": child.mac, "mid": child.mid, "name": "ACUnit",
                                      "model": "gree", "lock": 0} for child in children] if children else [""]}
            else:
                # Source startup initializes this BLE-MTU-derived page count to0.
                response = {"t": "subBList", "i": start, "list": ""}
        elif kind in ("queryT", "setT", "updateT", "deleteT"):
            response = self._timer(device, state, inner, now)
        elif kind == "upgrade":
            state["_can_upgrade_url"] = _text(inner.get("url"), 64)
            # Native ACK follows successful asynchronous worker enqueue, not a completed flash.
            response = {"t": "ret", "r": 200, "mac": device.mac}
        else:
            if kind == "tm":
                self._set_clock(state, inner.get("time"), now, 8)
            elif kind == "hbok":
                state["_can_heartbeat_due"] = now + 130
                state["_can_heartbeat_period"] = 120
            elif kind == "loginRes":
                if _integer(inner.get("r")) == 200:
                    state["_can_login_ok"] = True
            elif kind == "espLog":
                state["_can_log_tag"] = _text(inner.get("tag"), 29)
                state["_can_log_level"] = min(5, max(0, _integer(inner.get("level"))))
            device.state = state
            return []
        replies = self._reply(device, response, reply_index, uid, peer)
        device.state = state
        return replies


_HID = "362001063222+U-ESP32_GR_CANV2.01.bin"
_SOURCE = "4daa8f69d8d742db1d8ef197cc9f04429bd7a62dcdd388a901d54f83a5cdb883"
PROFILES = (
    Profile(ROOT_PROFILE, ("60",), _HID, _SOURCE, {}, CanGateway(),
            max_children=100, max_request_bytes=1024),
    *(Profile(f"{ROOT_PROFILE}-{physical:04x}", (_emitted_mid(physical),),
              _HID, _SOURCE, {}, CanGateway(physical), identity_bytes=7,
              parent_profiles=(ROOT_PROFILE,), identity_suffix=b"\0")
      for physical in (0x6049, 0x604a, 0x604b, 0x604c, 0x605c,
                       0x605d, 0x6079, 0x6084, 0x608d, 0x608e, 0x6091, 0x6099, 0x60a0)),
)
