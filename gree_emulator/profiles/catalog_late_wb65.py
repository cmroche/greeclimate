"""Source-qualified WB65VR local runtime for V2.10, V2.11, and V1.05."""

from copy import deepcopy
import json
import math
import re

from Crypto.Cipher import AES

from ..wire import InvalidPacket, Reply, _json, encode_reply
from . import Profile
from .catalog_early_frvr import VR_NUMERIC


ECB_KEY = b"a3K8Bx%2r8Y7#xDh"
GCM_KEY = b"{yxAHAY_Lm6pbC/<"
NONCE = bytes.fromhex("5440784449675a516c5e6313")
AAD = b"qualcomm-test"
MAX_DATAGRAM = 1460
_INT_MIN, _INT_MAX = -(1 << 31), (1 << 31) - 1

# V1.05 retains the original tuple; the two later images replace these four slots.
V2_NUMERIC = (*VR_NUMERIC[:203], "OutEnvTem", "InEvaTem", "CompressorTem",
              "CompressorFqy", *VR_NUMERIC[207:])
V105_NUMERIC = VR_NUMERIC

_GETTERS = frozenset((
    "name", "lock", "AutoUpdate", "time", "host", "hid", "BtHid", "mid", "MOta",
    "bc", "DevID", "MafIdf", "AppTimer", "MidType", "BleON", "Mesh", "Meshota",
    "SubOnline", "Proaddr", "Random", "Unbind", "Subcount", "Meshid", "lat", "lon",
    "ReportClientID", "Onoff", "ModelType", "vender", "mac", "ver", "rssi",
))
_GETTERS_V2 = _GETTERS | {"FaultDisplay"}
_NO_VALUE = frozenset((
    "BtHid", "MOta", "DevID", "MafIdf", "MidType", "Meshota", "Subcount",
    "ReportClientID", "Onoff",
))
_SETTERS = frozenset((
    "time", "BleON", "Mesh", "Unbind", "Meshid", "host", "lat", "lon",
    "ReportClientID", "Onoff", "ModelType", "AppTimer",
))
_COMMAND_STRING_NAMES = frozenset((
    "time", "name", "lock", "AutoUpdate", "host", "hid", "mid", "bc", "DevID",
    "MafIdf", "AppTimer", "MidType", "BleON", "Mesh", "Unbind", "Meshid", "lat",
    "lon", "ReportClientID", "Onoff", "ModelType",
))

_OPERATION_TABLE = frozenset((
    "bind", "status", "cmd", "upgrade", "setT", "queryT", "deleteT", "updateT", "dump",
))
_V2_OPERATION_TABLE = _OPERATION_TABLE | {"binCmd"}


class _NumberToken:
    __slots__ = ("token",)

    def __init__(self, token):
        self.token = token


def _source_number(token):
    return _NumberToken(token)


def _decimal_prefix(token):
    match = re.match(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", token)
    if match is None:
        raise InvalidPacket("WB65 numeric parser found no decimal prefix")
    prefix = token[:match.end()]
    negative = prefix.startswith("-")
    digits = prefix[1:] if negative else prefix
    whole, _, fraction = digits.partition(".")
    value = 0.0
    for digit in whole:
        value = value * 10.0 + int(digit)
    place = 0.1
    for digit in fraction:
        value += int(digit) * place
        place *= 0.1
    return (-value if negative else value), match.end()




def _int32(value):
    if isinstance(value, _NumberToken):
        value, _ = _decimal_prefix(value.token)
    if type(value) not in (int, float):
        raise InvalidPacket("WB65 numeric field requires a JSON number")
    if isinstance(value, float):
        if math.isnan(value):
            raise InvalidPacket("WB65 numeric field is not finite")
        if value >= _INT_MAX:
            return _INT_MAX
        if value <= _INT_MIN:
            return _INT_MIN
        return int(value)
    return min(_INT_MAX, max(_INT_MIN, value))


def _raw_numbers(values, count):
    index, remainder = 0, None
    for _ in range(count):
        if remainder is None:
            if index >= len(values) or not isinstance(values[index], _NumberToken):
                raise InvalidPacket("WB65 raw command value is not a source number")
            token = values[index].token
            index += 1
        else:
            token = remainder[1:]
        value, consumed = _decimal_prefix(token)
        remainder = token[consumed:] if consumed < len(token) else None
        yield _int32(value)


def _b64(value, capacity, *, text_capacity=1024, trim=True):
    if not isinstance(value, str):
        raise InvalidPacket("WB65 base64 field must be text")
    try:
        source = value.encode("utf-8").split(b"\0", 1)[0]
    except UnicodeEncodeError as exc:
        raise InvalidPacket("invalid WB65 base64 text") from exc
    if len(source) >= text_capacity:
        raise InvalidPacket("WB65 base64 text exceeds native input buffer")
    source = source.replace(b"\r", b" ").replace(b"\n", b" ")
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    values = {byte: index for index, byte in enumerate(alphabet)}
    output = bytearray()
    groups, remainder = divmod(len(source), 4)
    for index in range(groups):
        offset = index * 4
        a, b, c, d = (values.get(byte, 0) for byte in source[offset:offset + 4])
        output.extend((a << 2 | b >> 4, (b & 15) << 4 | c >> 2,
                       (c & 3) << 6 | d))
    if remainder == 3:
        offset = groups * 4
        a, b, c = (values.get(byte, 0) for byte in source[offset:])
        output.extend((a << 2 | b >> 4, (b & 15) << 4 | c >> 2, (c & 3) << 6))
    if len(output) > capacity:
        raise InvalidPacket("WB65 base64 output exceeds native destination")
    if trim:
        for _ in range(min(4, len(output))):
            if output[-1] != 0:
                break
            output.pop()
    return bytes(output)


def _unpack(device, outer, index):
    ciphertext = _b64(outer.get("pack"), 1024)
    tag_text = outer.get("tag")
    if not isinstance(tag_text, str):
        raise InvalidPacket("WB65 GCM envelope requires a tag")
    tag = _b64(tag_text, 64, text_capacity=64, trim=False)
    runtime = device.state.get("_wb65vr")
    # The native callback leaves this destination uncleared; GCM reads 16 bytes regardless of decode length.
    tag_buffer = bytearray(runtime["tag_buffer"] if runtime is not None else bytes(64))
    tag_buffer[:len(tag)] = tag
    cipher = AES.new(device.key if index == 0 else GCM_KEY, AES.MODE_GCM,
                     nonce=NONCE, mac_len=16)
    cipher.update(AAD)
    try:
        plain = cipher.decrypt_and_verify(ciphertext, bytes(tag_buffer[:16]))
    except ValueError as exc:
        raise InvalidPacket("invalid WB65 GCM tag") from exc
    return _json(plain, number_parser=_source_number), bytes(tag_buffer)


def _reply(device, inner, index, uid, *, discovery=False):
    if discovery:
        codec, key, index = "aes-ecb-pkcs7", ECB_KEY, 1
    else:
        codec, key = "aes-gcm", (device.key if index == 0 else GCM_KEY)
    reply = Reply({"t": "pack", "i": index, "uid": uid,
                   "cid": device.mac, "tcid": ""}, inner, key, codec,
                  trailing_newline=False)
    if len(encode_reply(reply)) > MAX_DATAGRAM:
        raise InvalidPacket("WB65 reply exceeds UDP receive capacity")
    return reply


def _runtime(device, state):
    if "_wb65vr" not in state:
        state["_wb65vr"] = {
            # These reproducible metadata and hook-state values are emulator choices, not constructor facts.
            "clock": (2026, 1, 1, 0, 0, 0), "host": "", "lat": "", "lon": "",
            "mid": "", "bc": "", "ver": "", "vender": "", "model_type": "",
            "fault_display": "", "lock": 0, "auto_update": 0, "app_timer": 0,
            "rssi": 0, "mesh": 0, "ble_address": bytes(6), "unbind_address": bytes(6),
            "ble_helper_address": bytes(6), "mesh_helper_address": bytes(6),
            "mesh_id": 0, "pro_address": bytes(2), "random": bytes(4), "children": {},
            "timers": {}, "heartbeat_seen": False, "heartbeat_cleared": False,
            "heartbeat_pending": 0, "heartbeat_status": 0, "heartbeat_companion": 0,
            "tag_buffer": bytes(64), "binary_frames": [], "onoff_calls": [],
            "report_client_frame": None, "report_client_pending": False,
            "report_frequency": None, "report_frequency_neighbor": None,
            "dump_request": None, "upgrade_url": None,
            "network": {"host": "", "ssid": "", "psw": ""},
        }
    return state["_wb65vr"]


def _names(value, maximum):
    if (not isinstance(value, list) or len(value) > maximum
            or any(not isinstance(name, str) or not name or "\0" in name for name in value)
            or sum(len(name.encode("utf-8")) + 1 for name in value) > 512):
        raise InvalidPacket("WB65 property list exceeds native bounds")
    return value


def _text(value, maximum, *, empty=True):
    if (not isinstance(value, str) or "\0" in value or not empty and not value
            or len(value.encode("utf-8")) > maximum):
        raise InvalidPacket("WB65 string exceeds native destination")
    return value


def _clock_string(runtime):
    return "%04d-%02d-%02d %02d:%02d:%02d" % runtime["clock"]


def _scan_time(value, previous, *, maximum=1023):
    if not isinstance(value, str) or "\0" in value:
        return None, 0
    try:
        data = value.encode("utf-8")
    except UnicodeEncodeError:
        return None, 0
    if len(data) > maximum:
        return None, 0
    fields, converted = list(previous), 0
    widths, whitespace, cursor = (4, 2, 2, 2, 2, 2), b" \t\n\r\v\f", 0
    for index, width in enumerate(widths):
        while cursor < len(data) and data[cursor] in whitespace:
            cursor += 1
        start, limit = cursor, cursor + width
        if cursor < limit and data[cursor] in b"+-":
            cursor += 1
        digits = cursor
        while cursor < limit and data[cursor] in b"0123456789":
            cursor += 1
        if cursor == digits:
            break
        fields[index] = int(data[start:cursor], 10)
        converted += 1
        if index == 5:
            break
        if index == 2:
            while cursor < len(data) and data[cursor] in whitespace:
                cursor += 1
        else:
            separator = 45 if index < 2 else 58
            if cursor >= len(data) or data[cursor] != separator:
                break
            cursor += 1
    return tuple(fields), converted


def _address_bytes(value, count, previous):
    if not isinstance(value, str) or "\0" in value:
        raise InvalidPacket("WB65 address setter requires text")
    # sscanf("%2X...") accepts a parsed prefix and leaves later bytes untouched.
    result = bytearray(previous)
    cursor = 0
    for index in range(count):
        while cursor < len(value) and value[cursor].isspace():
            cursor += 1
        start = cursor
        if cursor < len(value) and value[cursor] in "+-":
            cursor += 1
        digits = cursor
        while cursor < len(value) and cursor - digits < 2 and value[cursor] in "0123456789abcdefABCDEF":
            cursor += 1
        if cursor == digits:
            break
        result[index] = int(value[start:cursor], 16) & 255
    return bytes(result)


def _get(device, state, runtime, name):
    if name not in _GETTERS and name != "FaultDisplay":
        return [state[name]]
    if name in _NO_VALUE:
        return []
    if name == "hid":
        return [device.profile.hid]
    if name == "mac":
        return [device.mac]
    if name == "name":
        return [device.name]
    if name == "time":
        return [_clock_string(runtime)]
    if name == "host" or name == "lat" or name == "lon":
        return [runtime[name]]
    if name in ("mid", "bc", "ver", "vender"):
        return [runtime[name]]
    if name == "ModelType":
        return [runtime["model_type"]]
    if name == "FaultDisplay":
        return [runtime["fault_display"]]
    if name == "Mesh":
        return [runtime["mesh"]]
    if name == "BleON":
        return [runtime["ble_address"].hex().upper()]
    if name == "Unbind":
        return [runtime["unbind_address"].hex().upper()]
    if name == "Meshid":
        return [f"{runtime['mesh_id']:04X}"]
    if name == "SubOnline":
        children = [address for address, online in runtime["children"].items() if online]
        return [json.dumps(children, separators=(",", ":")) if children else ""]
    if name == "Proaddr":
        return [runtime["pro_address"].hex().upper()]
    if name == "Random":
        return [runtime["random"].hex().upper()]
    if name == "AppTimer":
        return [runtime["app_timer"]]
    if name == "lock":
        return [runtime["lock"]]
    if name == "AutoUpdate":
        return [runtime["auto_update"]]
    if name == "rssi":
        return [runtime["rssi"]]
    raise InvalidPacket("WB65 metadata getter is not source-qualified")


def _hex_byte(data, cursor):
    while cursor < len(data) and data[cursor] in b" \t\n\r\v\f":
        cursor += 1
    start = cursor
    if cursor < len(data) and data[cursor] in b"+-":
        cursor += 1
    first_digit = cursor
    while (cursor < len(data) and cursor - start < 2
           and data[cursor] in b"0123456789abcdefABCDEF"):
        cursor += 1
    if cursor == first_digit:
        return 0, cursor, False
    return int(data[start:cursor], 16) & 255, cursor, True


def _onoff_records(value):
    data = _text(value, 1023).encode("utf-8")
    record_count = data.count(b",") + 1
    cursor = 2
    records = []
    for record_index in range(record_count):
        if record_index:
            comma = data.find(b",", cursor)
            cursor = (len(data) if comma < 0 else comma) + 2
        first, next_cursor, parsed = _hex_byte(data, cursor)
        second = 0
        if parsed:
            second, _, _ = _hex_byte(data, next_cursor)
        converted = []
        for offset in (4, 5, 6):
            char = data[cursor + offset] if cursor + offset < len(data) else 0
            if char >= 128:
                char -= 256
            converted.append((char - (0x30 if char < ord("A") else 0x57)) & 255)
        # The helper's first four payload bytes are unresolved; retain only qualified sink fields.
        records.append({
            "header_byte0": 0, "control_byte": (converted[2] + 2) & 255,
            "address": first << 8 | second, "payload_length": 6,
            "payload_suffix": bytes(converted[:2]),
        })
    return records


def _set(device, runtime, name, value):
    if name == "time":
        fields, _ = _scan_time(value, runtime["clock"])
        if fields is not None:
            runtime["clock"] = fields
    elif name in ("host", "lat", "lon"):
        limit = 20 if name == "host" else 10
        if isinstance(value, str) and "\0" not in value and 0 < len(value.encode("utf-8")) <= limit:
            runtime[name] = value
    elif name == "BleON":
        runtime["ble_address"] = _address_bytes(value, 6, runtime["ble_address"])
        runtime["ble_helper_address"] = runtime["ble_address"]
    elif name == "Unbind":
        address = _address_bytes(value, 6, runtime["unbind_address"])
        runtime["unbind_address"] = address
        runtime["children"].pop(address.hex().upper(), None)
    elif name == "Meshid":
        parsed = _address_bytes(value, 2, runtime["mesh_id"].to_bytes(2, "big"))
        runtime["mesh_id"] = int.from_bytes(parsed, "big")
    elif name == "Mesh":
        runtime["mesh_helper_address"] = runtime["ble_address"]
    elif name == "ReportClientID":
        value = _text(value, 26)
        frame = bytearray(30)
        frame[:4] = b"~~\x12\x6a"
        frame[4:4 + len(value.encode("utf-8"))] = value.encode("utf-8")
        runtime["report_client_frame"] = bytes(frame)
        runtime["report_client_pending"] = True
    elif name == "Onoff":
        runtime["onoff_calls"].extend(_onoff_records(value))


def _timer(device, runtime, kind, inner):
    timers = runtime["timers"]
    if kind == "queryT":
        index, count = _int32(inner.get("index")), _int32(inner.get("count"))
        ordered = list(timers.items())
        records = []
        start = max(0, index)
        stop = min(len(ordered), start + max(0, count), start + 10)
        for timer_id, timer in ordered[start:stop]:
            records.append({
                "id": timer_id, "name": timer["name"], "enable": int(timer["enabled"] == 0),
                "week": [(timer["week"] >> bit) & 1 for bit in range(7)],
                "hr": timer["hr"], "min": timer["min"], "sec": timer["sec"],
                "cmd": [{"mac": device.mac, "opt": ["Pow"], "p": [timer["power"]]}],
            })
        return {"t": "listT", "total": len(timers), "index": index, "list": records}
    timer_id = _int32(inner.get("id")) & 255
    if kind == "deleteT":
        timers.pop(timer_id, None)
        return {"t": "resT", "r": 200}
    if kind == "setT" and len(timers) >= 10:
        raise InvalidPacket("WB65 timer table is full")
    name = _text(inner.get("name"), 31)
    week = inner.get("week")
    command = inner.get("cmd")
    if (not isinstance(week, list) or len(week) != 7 or not isinstance(command, list)
            or len(command) != 1 or not isinstance(command[0], dict)):
        raise InvalidPacket("WB65 timer requires bounded week and command arrays")
    enabled, _, hour, minute, _ = (
        _int32(inner.get(field)) for field in ("enable", "tz", "hr", "min", "sec"))
    packed_week = 0
    for bit, day in enumerate(week):
        packed_week |= _int32(day) << bit
    options = _names(command[0].get("opt"), 32)
    values = command[0].get("p")
    if not isinstance(values, list) or len(options) != len(values):
        raise InvalidPacket("WB65 timer requires matching command arrays")
    power = 0
    for option, value in zip(options, values):
        parsed = _int32(value)
        if option == "Pow":
            power = parsed
    record = {"name": name, "enabled": int(enabled != 1), "week": packed_week & 127,
              "hr": hour & 255, "min": minute & 255, "sec": 0, "power": power}
    if kind == "setT" or timer_id in timers:
        timers[timer_id] = record
    return {"t": "resT", "r": 200}


def _bin_command(runtime, inner):
    if "hex01" not in inner:
        raise InvalidPacket("WB65 binCmd requires hex01")
    encoded = inner["hex01"]
    raw = _b64(encoded, 60)
    if len(raw) < 3 or raw[:2] != b"~~":
        raise InvalidPacket("WB65 binCmd frame marker is invalid")
    length = raw[2] + 2
    if length > len(raw) or length > 60:
        raise InvalidPacket("WB65 binCmd frame exceeds native 60-byte buffer")
    report_client = inner.get("ReportClientID")
    if "ReportClientID" in inner:
        report_client = _text(report_client, 26)
        report = bytearray(30)
        report[:4] = b"~~\x12\x6a"
        report[4:4 + len(report_client.encode("utf-8"))] = report_client.encode("utf-8")
        runtime["report_client_frame"] = bytes(report)
        runtime["report_client_pending"] = True
    report_frequency = inner.get("ReportFreq")
    frame = bytearray(60)
    frame[:length] = raw[:length]
    frame[7] = 0 if "ReportClientID" in inner else 0xaf
    frame[43] |= 0x02
    runtime["binary_frames"].append(bytes(frame[:length]))
    if "ReportFreq" in inner:
        frequency = _int32(report_frequency) & 255
        runtime["report_frequency"] = 60 if frequency == 255 else 0x4000 + frequency
        runtime["report_frequency_neighbor"] = 0x405a
    return {"t": "res", "r": 200}




class WB65VR:
    plaintext_types = ("tm", "hbok")

    def __init__(self, *, v2):
        self.v2 = v2
        self.numeric_slots = V2_NUMERIC if v2 else V105_NUMERIC
        self.numeric = frozenset(name for name in self.numeric_slots if name)
        self.special = _GETTERS_V2 if v2 else _GETTERS
        self.fields = self.numeric | self.special
        self.write_only = frozenset(("ReportClientID", "Onoff"))
        self.operations = _V2_OPERATION_TABLE if v2 else _OPERATION_TABLE

    def validate_state(self, state):
        for name, value in state.items():
            if name == "_uid" and type(value) is int and _INT_MIN <= value <= _INT_MAX:
                continue
            if (name not in self.numeric or type(value) is not int or not 0 <= value <= 65535):
                raise ValueError("WB65 state requires named uint16 cache fields")

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        """The WB65 raw-property table is a cache, not a source of room physics."""

    def advertise(self, device, outer):
        if outer.get("t") != "scan":
            return []
        inner = {
            "t": "dev", "cid": "", "bc": "", "brand": "", "catalog": "",
            "mac": device.mac, "mid": "10001", "model": "", "name": device.name,
            "lock": 0, "series": "", "vender": "", "ver": "", "hid": device.profile.hid,
        }
        if self.v2:
            inner["ModelType"] = ""
        return [_reply(device, inner, 1, 0, discovery=True)]

    def _get(self, device, state, runtime, name):
        if name == "FaultDisplay" and not self.v2:
            return [state[name]]
        return _get(device, state, runtime, name)

    def _command(self, device, outer, inner, index, uid):
        options = _names(inner.get("opt"), 32)
        values = inner.get("p")
        if not isinstance(values, list) or len(options) != len(values):
            raise InvalidPacket("WB65 command requires matching bounded arrays")
        state = device.state
        runtime = _runtime(device, state)
        command_strings = [name for name in options if name in _COMMAND_STRING_NAMES]
        raw_names = [name for name in options if name not in _COMMAND_STRING_NAMES]
        writer_failed = False
        for name, value in zip(options, values):
            if name not in _COMMAND_STRING_NAMES:
                continue
            if name not in _SETTERS:
                writer_failed = True
                break
            parsed = _int32(value) if name == "AppTimer" else _text(value, 1023)
            _set(device, runtime, name, parsed)
        numeric = []
        # The native raw-number pass starts at p[0]; it does not skip local strings.
        # The raw helper reuses an unconsumed exponent suffix for the next value.
        try:
            for name, parsed in zip(raw_names, _raw_numbers(values, len(raw_names))):
                if not writer_failed and name in self.numeric:
                    state[name] = parsed & 65535
                numeric.append((name, parsed))
        except InvalidPacket:
            # The wrapper builds its acknowledgement even after writer failure.
            pass
        state["_uid"] = uid
        selected, applied = [], []
        for name in command_strings:
            if name not in _NO_VALUE:
                selected.append(name)
                applied.extend(self._get(device, state, runtime, name))
        for name, value in numeric:
            selected.append(name)
            applied.append(value)
        return _reply(device, {"t": "res", "mac": "", "opt": selected,
                               "p": applied, "r": 200}, index, uid)

    def _status(self, device, inner, index, uid):
        names = _names(inner.get("cols"), 64)
        state = device.state
        runtime = _runtime(device, state)
        selected, data = [], []
        for name in names:
            if name in self.fields:
                selected.append(name)
                data.extend(self._get(device, state, runtime, name))
        target = inner.get("mac", device.mac)
        if not isinstance(target, str) or "\0" in target:
            raise InvalidPacket("WB65 status target is invalid")
        return _reply(device, {"t": "dat", "uid": uid, "mac": target,
                               "cid": device.mac, "dat": data, "cols": selected,
                               "r": 200}, index, uid)

    def _plain_target(self, device, outer):
        return outer.get("tcid", device.mac) == device.mac

    def handle_plaintext_from(self, device, outer, data, addr):
        if (not isinstance(data, bytes) or len(data) > MAX_DATAGRAM
                or not self._plain_target(device, outer)):
            return []
        kind = outer.get("t")
        if kind == "wlan":
            return self.wlan(device, outer)
        if kind not in ("tm", "hbok"):
            return []
        if kind == "tm":
            pending = deepcopy(device.state)
            runtime = _runtime(device, pending)
            # The six-field virtual RTC is explicit backing for sscanf's
            # in-place updates; an empty scratch tuple is not a calendar.
            fields, converted = _scan_time(outer.get("time"), runtime["clock"], maximum=32)
            if fields is None or converted != 6:
                return []
            runtime["clock"] = fields
            device.state.clear()
            device.state.update(pending)
        else:
            runtime = _runtime(device, device.state)
            runtime["heartbeat_cleared"] = True
            if runtime["heartbeat_pending"] == 0:
                runtime["heartbeat_seen"] = True
                runtime["heartbeat_status"] = 2
            runtime["heartbeat_companion"] = 0
        port = addr[1] if isinstance(addr, tuple) and len(addr) > 1 else None
        return [Reply({}, destination_port=port, raw_payload=data)]

    def wlan(self, device, outer):
        if not self._plain_target(device, outer):
            return []
        parsed = {}
        for name, maximum in (("host", 19), ("ssid", 32), ("psw", 64)):
            value = outer.get(name)
            encoded = None
            if isinstance(value, str) and "\0" not in value:
                try:
                    encoded = value.encode("utf-8")
                except UnicodeEncodeError:
                    encoded = None
            parsed[name] = value if encoded is not None and len(encoded) <= maximum else ""
        runtime = _runtime(device, device.state)
        runtime["network"] = parsed
        runtime["network_host_matches_source_default"] = parsed["host"] == "dis.gree.com"
        return [Reply({"t": "ret", "r": 200, "mac": device.mac})]

    def handle(self, device, outer):
        kind = outer.get("t")
        if kind != "pack" or outer.get("tcid") != device.mac:
            raise InvalidPacket("wrong WB65 root target")
        index, uid = outer.get("i"), outer.get("uid")
        if (type(index) is not int or index not in (0, 1)
                or type(uid) is not int or not _INT_MIN <= uid <= _INT_MAX
                or not isinstance(outer.get("cid", ""), str)):
            raise InvalidPacket("invalid WB65 session selector")
        inner, tag_buffer = _unpack(device, outer, index)
        kind = inner.get("t")
        if not isinstance(kind, str) or not kind or "\0" in kind:
            raise InvalidPacket("invalid WB65 operation")
        if kind not in self.operations:
            return []
        if kind == "bind":
            mac = _text(inner.get("mac"), 31)
            reply = _reply(device, {"t": "bindok", "r": 200, "mac": mac,
                                   "key": device.key.decode("ascii")}, index, uid)
        elif kind == "status":
            reply = self._status(device, inner, index, uid)
        elif kind == "cmd":
            reply = self._command(device, outer, inner, index, uid)
        elif kind in ("setT", "updateT", "deleteT", "queryT"):
            runtime = _runtime(device, device.state)
            reply = _reply(device, _timer(device, runtime, kind, inner), index, uid)
        elif kind == "dump":
            period, count = _int32(inner.get("period")), _int32(inner.get("cnt"))
            _runtime(device, device.state)["dump_request"] = (period, count)
            reply = _reply(device, {"t": "ret", "r": 200}, index, uid)
        elif kind == "upgrade":
            url = _text(inner.get("url"), 119)
            _runtime(device, device.state)["upgrade_url"] = url
            reply = _reply(device, {"t": "ret", "r": 200}, index, uid)
        elif kind == "binCmd":
            response = _bin_command(_runtime(device, device.state), inner)
            reply = _reply(device, response, index, uid)
        else:
            return []
        device.state["_uid"] = uid
        _runtime(device, device.state)["tag_buffer"] = tag_buffer
        return [reply]



def _profile(profile_id, hid, source_sha256, *, v2):
    handler = WB65VR(v2=v2)
    return Profile(profile_id, ("10001",), hid, source_sha256,
                   {**dict.fromkeys((name for name in handler.numeric_slots if name), 0),
                    "_uid": 0}, handler, max_request_bytes=MAX_DATAGRAM)


PROFILES = (
    _profile("sim-wb65vr-v2.10-10001", "362001068254+U-4MWB65VRV2.10.bin",
             "c1dc1448cc0441c4cd8da8262b90c93b3ce181a0de5ca739f41aa07ba0f921df", v2=True),
    _profile("sim-wb65vr-v2.11-10001", "362001068254+U-4MWB65VRV2.11.bin",
             "40f85264c8f450acd9e329a25fb9731b89940aa20cc38bd085c764495b5edf27", v2=True),
    _profile("sim-wb65vr-v1.05-10001", "362001067419+U-WB65VRV1.05.bin",
             "107efeb2ab0cc8b32ffbe796ef711eb904d8b8c1d25f92b3095e0fca805739ac", v2=False),
)
