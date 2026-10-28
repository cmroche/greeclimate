"""Source24/35 native Gnet UDP controllers, not ordinary Gree AC profiles.

The actual UDP registries contain nine/seven callbacks, not their larger cloud
registries. Factory-key bytes, UART0x44 MID, raw MCU banks, erased scene flash,
clock and previously uninitialized stack bytes are explicit virtual inputs.
No physical UART/flash/network completion or calibrated appliance is inferred.
Original contracts: RealtekMiddle/custom-bincmd-integration.json and
wb-new-remaining-operation-contracts.json, plus native-key/socket/HID exports.

The source accepts unchecked strings, pointer-table arrays, out-of-bounds frame
lengths and NULL fragment banks. This bounded model rejects those unsafe paths
atomically, rather than reproducing memory corruption. It preserves in-bounds
old-cJSON coercion, first case-insensitive duplicate lookup, permissive Base64,
shared scratch carryover, ordered fragments and exact source-specific flags.
"""

import base64
import binascii
from copy import deepcopy
from datetime import datetime, timedelta
import json
import math
import re

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from ..wire import InvalidPacket, Reply, _validate_outer
from . import Profile

CODEC = "aes-ecb-pkcs7-lf"
_SOURCE_DATA = {
    24: {"sha256": "faa49ed7a0ca7612b9e1ce6024a11f6fada63679d7e16e7970e357545faee6e7",
         "hid": "362001065867+U-WB01AV2.93.bin", "scene_bytes": 172,
         "scene_frame_bytes": 55, "scene_id_offset": 168},
    35: {"sha256": "449974949ee0720813a603c8276049c5ce420dcd854aa96c2e9a94b94b76d571",
         "hid": "362001067088+U-WB05IRV1.15.bin", "scene_bytes": 200,
         "scene_frame_bytes": 65, "scene_id_offset": 196},
}
_UDP_FLAGS = {"scan": 1, "ubindok": 0, "ret": 0, "bincmd": 0,
              "reset": 0, "hbok": 1, "utm": 0}
_MISSING = object()
_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_BASE64_LOOKUP = {byte: index for index, byte in enumerate(_ALPHABET + b"\0")}
_ASCII_FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def _fold(value):
    return value.translate(_ASCII_FOLD)


class _Object(dict):
    """Keep native linked-member print order as well as first-key lookup."""


def _first_object(pairs):
    result, found = _Object(), set()
    result.pairs = tuple(pairs)
    for key, value in pairs:
        folded = _fold(key)
        if folded not in found:
            found.add(folded)
            result[key] = value
    return result


def _field(obj, name, default=_MISSING):
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str) and _fold(key) == _fold(name):
                return value
    return default


def _json_object(data):
    def reject_constant(_):
        raise ValueError("nonfinite number")
    try:
        result = json.loads(data.decode("utf-8"), object_pairs_hook=_first_object,
                            parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvalidPacket("invalid legacy WB JSON object") from exc
    if not isinstance(result, dict):
        raise InvalidPacket("legacy WB requires an object")
    return result


def _signed(value):
    value &= 0xffffffff
    return value - 0x100000000 if value & 0x80000000 else value


def _valueint(value):
    """Old cJSON valueint, including the SDK's array-child-count override."""
    if isinstance(value, list):
        return len(value)
    if type(value) is bool:
        return int(value)
    if type(value) in (int, float):
        try:
            number = float(value)
        except OverflowError:
            number = math.inf if value > 0 else -math.inf
        if not math.isfinite(number):
            raise InvalidPacket("legacy WB numeric conversion exceeds finite virtual ABI")
        return max(-0x80000000, min(0x7fffffff, math.trunc(number)))
    return 0


def _native_json_text(value):
    """Original cJSON unformatted printer, including its six-digit fractions."""
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is str:
        return json.dumps(value.split("\0", 1)[0], ensure_ascii=False)
    if type(value) in (int, float):
        integer = _valueint(value)
        number = float(value)
        if abs(number - integer) <= 2.220446049250313e-16 and -2147483648 <= number <= 2147483647:
            return str(integer)
        if abs(number - math.floor(number)) <= 2.220446049250313e-16 and abs(number) < 1e60:
            return format(number, ".0f")
        return format(number, ".6e" if abs(number) < 1e-6 or abs(number) > 1e9 else ".6f")
    if isinstance(value, list):
        return "[" + ",".join(_native_json_text(item) for item in value) + "]"
    pairs = value.pairs if isinstance(value, _Object) else value.items()
    return "{" + ",".join(_native_json_text(key) + ":" + _native_json_text(item)
                           for key, item in pairs) + "}"


def _default_copy(buffer, value):
    """SDK flag0/100000: type dispatch, NOT a universal string-type gate."""
    if value is _MISSING:
        return False
    if type(value) is str or isinstance(value, dict):
        text = value.split("\0", 1)[0] if type(value) is str else _native_json_text(value)
        try:
            raw = text.encode("utf-8") + b"\0"
        except UnicodeError as exc:
            raise InvalidPacket("legacy WB bounded string requires valid UTF-8") from exc
        if len(raw) > len(buffer):
            raise InvalidPacket("legacy WB unchecked string would overflow its destination")
        buffer[:len(raw)] = raw
    elif type(value) in (int, float, bool):
        buffer[0] = _valueint(value) & 255
    elif isinstance(value, list):
        cursor = 0
        for item in value:
            if type(item) in (int, float):
                raw = str(_valueint(item)).encode("ascii") + b"\0"
                if cursor + len(raw) > len(buffer):
                    raise InvalidPacket("legacy WB numeric-array sprintf would overflow its destination")
                buffer[cursor:cursor + len(raw)] = raw
                cursor += 4
            elif type(item) is str or isinstance(item, dict):
                raise InvalidPacket("legacy WB string-array heap-pointer bytes are outside the bounded text ABI")
    # cJSON null follows the successful no-write branch.
    return True


def _cstring(buffer):
    return bytes(buffer).split(b"\0", 1)[0]


def _string_field(obj, name, capacity):
    scratch = bytearray(capacity)
    found = _default_copy(scratch, _field(obj, name))
    try:
        return found, _cstring(scratch).decode("utf-8")
    except UnicodeError as exc:
        raise InvalidPacket("legacy WB native C string is not valid UTF-8") from exc


def _decode_base64_into(text, destination):
    """Actual lookup/quarter loop, including padding writes and invalid bytes."""
    text = _cstring(text)
    groups = len(text) // 4
    length = 3 * groups - (2 if b"==" in text else 1 if b"=" in text else 0)
    if length < 0 or length >= len(destination) or 3 * groups > len(destination):
        raise InvalidPacket("legacy WB Base64 would write outside its native buffer")
    destination[length] = 0
    for group in range(groups):
        a, b, c, d = (_BASE64_LOOKUP.get(byte, 0) for byte in text[group * 4:group * 4 + 4])
        start = group * 3
        destination[start:start + 3] = bytes((((a << 2) | (b >> 4)) & 255,
                                             ((b << 4) | (c >> 2)) & 255,
                                             ((c << 6) | d) & 255))


def _bounded_index(index, length):
    if not 0 <= index < length:
        raise InvalidPacket("legacy WB fragment would access outside its bank")
    return index


def _patch(bank, command):
    offset, mask = command[1], command[2]
    index = _bounded_index(offset + 3, len(bank))
    value = int.from_bytes(command[4:8], "little")
    shift = (mask & -mask).bit_length() - 1 if mask else 16
    signed_mask = mask - 256 if mask & 128 else mask
    bank[index] = ((bank[index] & ~signed_mask) +
                   (((value << shift) & 0xffffffff) & signed_mask)) & 255


def _remember(state, arena):
    """Native pointer advancement: compare shifted input, copy ORIGINAL16B."""
    for index, stored in enumerate(state["fragment_initializers"]):
        shifted = index * 16
        if stored[0] == 0 or stored[:3] == bytes(arena[shifted:shifted + 3]):
            state["fragment_initializers"][index] = bytes(arena[:16])
            return


def _scan_clock(text):
    """Declared scanf ABI; source35 malformed lexing still needs ROM10110ffc."""
    values, position = [0] * 6, 0
    for index, width in enumerate((4, 2, 2, 2, 2, 2)):
        if index:
            separator = "-" if index in (1, 2) else " " if index == 3 else ":"
            if separator == " ":
                while position < len(text) and text[position] in " \t\r\n\v\f":
                    position += 1
            elif text[position:position + 1] == separator:
                position += 1
            else:
                break
        while position < len(text) and text[position] in " \t\r\n\v\f":
            position += 1
        match = re.match(r"[+-]?[0-9]+", text[position:position + width])
        if match is None:
            break
        values[index] = int(match.group())
        position += len(match.group())
    return values


def _set_clock(runtime, text, timezone):
    fields = _scan_clock(text)
    year, month, day, hour, minute, second = fields
    year, month = divmod(year * 12 + month - 1, 12)
    cycles = (year - 1) // 400
    canonical_year = year - cycles * 400
    days = ((datetime(canonical_year, month + 1, 1) - datetime(1970, 1, 1)).days
            + cycles * 146097 + day - 1)
    epoch = (days * 86400 + hour * 3600 + minute * 60 + second - timezone * 3600) & 0xffffffff
    runtime["clock_fields"] = fields
    runtime["clock_timezone"] = timezone
    runtime["clock_epoch_u32"] = epoch
    runtime["time"] = (datetime(1970, 1, 1) + timedelta(seconds=epoch + timezone * 3600)).strftime("%Y-%m-%d %H:%M:%S")
    runtime["clock_updates"] += 1
    runtime["uart_events"].append(0x82)


def _initial_state(index):
    size = _SOURCE_DATA[index]["scene_bytes"]
    return {"raw_banks": {name: bytes(65) for name in ("91", "92", "93", "6A")},
            "scene_flash": [b"\xff" * size for _ in range(20)],
            "fragment_initializers": [bytes(16) for _ in range(5)],
            "stack_work_readout": bytes(55), "legacy_reference_readout": bytes(65),
            "synthetic_readouts": True,
            "_runtime": {"sdk_version": "V3.5.M", "lock": 0, "online": 0,
                         "activity": 0, "host_mac": "", "room_id": 0,
                         "gnet_id": 0, "protocol_mode": 1, "login_flag": 0,
                         "host_managed": 0, "network_reinitializations": 0,
                         "reset_flags": 0, "raw91_refresh": 0,
                         "link_dirty": 0, "report_requests": 0,
                         "status_check": 0, "pending_words": {}, "status_bytes": [0] * 8,
                         "raw_pending_bits": 0, "uart_events": [], "reserved82": 0,
                         "frequency": 60, "frequency_frame": bytes(55),
                         "city": "", "data_curve_frame": bytes(55), "data_curve": {},
                         "flash_writes": [], "persist": {},
                         "time": "2000-01-01 00:00:00", "clock_fields": [2000, 1, 1, 0, 0, 0],
                         "clock_timezone": 0, "clock_epoch_u32": 946684800,
                         "clock_updates": 0, "clock_abi": "declared scanf/calendar virtual primitive; not ROM execution",
                         "heartbeat_byte": 0, "heartbeat_timer": None,
                         "timer_commands": [], "tick_input": 0,
                         "heartbeat_period_ms": 0, "sync": 0, "report_builder_requests": 0}}


class LegacyWBController:
    source_port = 5001
    accept_any_target = True
    plaintext_types = ()

    def __init__(self, source_index, mid, factory_key):
        self.source_index = source_index
        self.mid = mid
        self.generic_key = factory_key
        self.source = _SOURCE_DATA[source_index]
        self.operations = dict(_UDP_FLAGS)
        if source_index == 24:
            self.operations.update(logininfores=0, statuscheck=0)

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        return None

    def validate_state(self, state):
        if state.get("synthetic_readouts") is not True:
            raise ValueError("legacy raw/flash/clock/stack readouts must be explicitly synthetic")
        if set(state.get("raw_banks", {})) != {"91", "92", "93", "6A"}:
            raise ValueError("legacy WB requires all four opaque MCU readouts")
        for raw in state["raw_banks"].values():
            if type(raw) is not bytes or len(raw) != 65:
                raise ValueError("legacy WB raw banks must each contain65 bytes")
        for name, count, size in (("scene_flash", 20, self.source["scene_bytes"]),
                                  ("fragment_initializers", 5, 16)):
            if (not isinstance(state.get(name), list) or len(state[name]) != count
                    or any(type(raw) is not bytes or len(raw) != size for raw in state[name])):
                raise ValueError("invalid legacy WB " + name)
        for name, size in (("stack_work_readout", 55), ("legacy_reference_readout", 65)):
            if type(state.get(name)) is not bytes or len(state[name]) != size:
                raise ValueError("invalid explicit legacy WB scratch readout")
        if not isinstance(state.get("_runtime"), dict):
            raise ValueError("legacy WB runtime state must be an object")

    def decode_outer(self, data):
        if len(data) > 1536:
            raise InvalidPacket("legacy WB UDP receive capacity is1536 bytes")
        outer = _json_object(data)
        # Only encrypted outer pack reaches a registered UDP channel. Plaintext
        # requests take native channel2, whose table row is the NULL sentinel.
        if _field(outer, "t") != "pack":
            return _validate_outer({"t": "pack", "i": 2, "uid": 0, "pack": {}})
        selector = _valueint(_field(outer, "i", 0)) & 255
        uid = _valueint(_field(outer, "uid", 0))
        return _validate_outer({"t": "pack", "i": selector, "uid": uid,
                                "cid": "", "tcid": "", "pack": _field(outer, "pack", "")})

    def advertise(self, device, outer=None):
        # This table's scan is INSIDE generic-key channel1, not plaintext scan.
        return []

    def _decrypt(self, outer, key):
        payload = _field(outer, "pack")
        if type(payload) is not str:
            raise InvalidPacket("legacy WB encrypted pack requires a string")
        try:
            encrypted = base64.b64decode(payload, validate=True)
            if not encrypted or len(encrypted) % 16:
                raise ValueError("block length")
            plain = unpad(AES.new(key, AES.MODE_ECB).decrypt(encrypted), 16)
        except (ValueError, TypeError, binascii.Error) as exc:
            raise InvalidPacket("invalid legacy WB encrypted pack") from exc
        return _json_object(plain.split(b"\0", 1)[0])

    def _reply(self, device, runtime, inner, uid, flag):
        if runtime["activity"] >= 65536:
            runtime["activity"] = 0
        return Reply({"t": "pack", "i": flag, "uid": _signed(uid),
                      "cid": device.mac, "msgId": _signed(runtime["activity"]),
                      "pack": "", "tcid": runtime["host_mac"]}, inner,
                     self.generic_key if flag else device.key, CODEC,
                     destination_port=5000)

    def _proactive(self, device, runtime, inner, *, increment=False, reset=False):
        """Immediate UBindok callees, not an authored periodic lifecycle."""
        if increment:
            self._activity(runtime)
        if reset and runtime["activity"] >= 65536:
            runtime["activity"] = 0
        return Reply({"t": "pack", "i": 0, "msgId": _signed(runtime["activity"]),
                      "cid": device.mac, "tcid": runtime["host_mac"]},
                     inner, device.key, CODEC, destination_port=5000)

    @staticmethod
    def _activity(runtime):
        runtime["activity"] = (runtime["activity"] + 1) & 0xffffffff

    def _heartbeat(self, runtime):
        self._activity(runtime)
        runtime["heartbeat_byte"] = 0
        if runtime["heartbeat_timer"] is None:
            runtime["heartbeat_timer"] = {"name": "heart_beat_response", "interval": 61000,
                                           "autoreload": 1, "id": 0}
            runtime["timer_commands"].append((1, runtime["tick_input"]))
        else:
            runtime["timer_commands"].append((2, runtime["tick_input"]))
        runtime["timer_commands"].append((1 if runtime["online"] else 3, runtime["tick_input"]))

    def _room(self, runtime, inner, *, reinitialize=False):
        room = _field(inner, "roomId")
        if room is _MISSING:
            return
        room = _valueint(room) & 255
        if self.source_index == 35 or runtime["room_id"] != room:
            runtime["room_id"] = room
            runtime["persist"]["GnetgroupID"] = room
        if (reinitialize and self.source_index == 24 and runtime["gnet_id"]
                and runtime["protocol_mode"] == 1 and not runtime["login_flag"]):
            runtime["login_flag"] = 1
            runtime["persist"]["Gnet"] = 1
            runtime["network_reinitializations"] += 1

    def _fragments(self, state, fragments, arena, banks, *, scene_id=None):
        runtime, mask, special_dirty = state["_runtime"], 0, False
        objects = scene_id is None and runtime["sdk_version"] == "V3.4.M"
        if not isinstance(fragments, list):
            raise InvalidPacket("legacy WB fragment requires an actual array")
        arena[:16] = bytes(16)
        for entry in fragments:
            if objects:
                if not isinstance(entry, dict):
                    raise InvalidPacket("legacy WB object fragment would dereference an invalid JSON pointer")
                for name, offset, width in (("cmd_type", 0, 1), ("byte", 1, 1),
                                            ("mask", 2, 1), ("value", 4, 4), ("initval", 8, 4)):
                    value = _field(entry, name)
                    if value is not _MISSING:
                        arena[offset:offset + width] = (_valueint(value) & ((1 << (8 * width)) - 1)).to_bytes(width, "little")
                remember = _field(entry, "initval") is not _MISSING
            else:
                if not isinstance(entry, list) or len(entry) < 4:
                    raise InvalidPacket("legacy WB tuple fragment would dereference a missing child")
                for offset in range(3):
                    arena[offset] = _valueint(entry[offset]) & 255
                value = _valueint(entry[3]) & 0xffffffff
                arena[4:8] = value.to_bytes(4, "little")
                remember = (len(entry) & 255) == 5
                if remember:
                    arena[8:12] = (_valueint(entry[4]) & 0xffffffff).to_bytes(4, "little")
            if scene_id == 2:
                arena[4:8] = (int(int.from_bytes(arena[4:8], "little") == 0)).to_bytes(4, "little")
            if remember:
                _remember(state, arena)
            if not objects and scene_id is None and arena[:3] == b"\x82\x03\x60":
                runtime["reserved82"] = int.from_bytes(arena[4:8], "little")
                if self.source_index == 24:
                    runtime["reserved82"] &= 255
                runtime["uart_events"].append(0x82)
                special_dirty |= self.source_index == 35
                continue
            command = f"{arena[0]:02X}"
            if command not in ("91", "92", "93"):
                raise InvalidPacket("legacy WB unknown fragment command would dereference NULL")
            _patch(banks[command], arena)
            if self.source_index == 35 and scene_id is None:
                mask |= {"91": 0x20, "92": 0x40, "93": 0x80}[command]
        return mask, special_dirty

    def _prepass(self, state, fragments, banks):
        if self.source_index != 24 or state["_runtime"]["sdk_version"] == "V3.4.M":
            return
        if not isinstance(fragments, list):
            raise InvalidPacket("legacy WB fragment would dereference a non-array")
        reference = state["legacy_reference_readout"]
        for entry in fragments:
            if not isinstance(entry, list):
                raise InvalidPacket("legacy WB prepass requires tuple arrays")
            for nested in entry[5:len(entry) & 255] if (len(entry) & 255) > 5 else ():
                if not isinstance(nested, list) or len(nested) > 4:
                    raise InvalidPacket("legacy WB nested prepass would overflow four-byte scratch")
                scratch = bytearray(4)
                for index, value in enumerate(nested):
                    scratch[index] = _valueint(value) & 255
                target = _bounded_index(scratch[0] + 3, 65)
                source = _bounded_index(scratch[2] + 3, 65)
                banks["91"][target] = ((banks["91"][target] & ~scratch[1]) +
                                       (reference[source] & scratch[3])) & 255

    def _scene_write(self, runtime):
        runtime["flash_writes"].append({"offset": 0x1f3000 if self.source_index == 24 else 0x201000,
                                        "erase_bytes": 4096,
                                        "write_bytes": 20 * self.source["scene_bytes"]})

    def _populate_scene(self, state, inner, slot, *, fragments=True):
        record = bytearray(state["scene_flash"][slot])
        size, id_offset = self.source["scene_frame_bytes"], self.source["scene_id_offset"]
        scene_id = int.from_bytes(record[id_offset:id_offset + 4], "little")
        ascii_buffer = bytearray(128)
        banks = {}
        for index, name in enumerate(("91", "92", "93")):
            bank = bytearray(record[index * size:(index + 1) * size])
            if _default_copy(ascii_buffer, _field(inner, "hex" + name)):
                bank[:] = bytes(size)
                _decode_base64_into(ascii_buffer, bank)
                ascii_buffer[:] = bytes(128)
            banks[name] = bank
        fragment = _field(inner, "fragment")
        if fragments and fragment is not _MISSING:
            # Populate's input scratch is SP+28, immediately followed by its
            # initialized128-byte ASCII scratch at SP+38.
            arena = bytearray(16) + ascii_buffer
            self._fragments(state, fragment, arena, banks, scene_id=scene_id)
        for index, name in enumerate(("91", "92", "93")):
            record[index * size:(index + 1) * size] = banks[name]
        state["scene_flash"][slot] = bytes(record)

    def _scene(self, state, inner, scene_id):
        runtime = state["_runtime"]
        if self.source_index == 24 and not runtime["gnet_id"]:
            return 501
        id_offset = self.source["scene_id_offset"]
        ids = [int.from_bytes(raw[id_offset:id_offset + 4], "little") for raw in state["scene_flash"]]
        operation = _valueint(_field(inner, "operType", 0)) & 255
        if self.source_index == 24 and scene_id == 1 and operation == 1:
            if 1 in ids:
                return None
            slot = next((i for i, value in enumerate(ids) if value in (0, 0xffffffff)), None)
            if slot is None:
                return None
        elif operation == 1:
            if self.source_index == 24 and (_valueint(_field(inner, "sence_enable", 0)) & 255) != 1:
                return None
            slot = next((i for i, value in enumerate(ids) if value == scene_id), None)
            if slot is None:
                slot = next((i for i, value in enumerate(ids) if value in (0, 0xffffffff)), None)
            if slot is None:
                return 501
        elif operation in (0, 2):
            for index, value in enumerate(ids):
                if value == scene_id:
                    if operation == 2:
                        state["scene_flash"][index] = bytes(self.source["scene_bytes"])
                    else:
                        self._populate_scene(state, inner, index, fragments=False)
                    self._scene_write(runtime)
            return None
        else:
            return None
        newly_created = ids[slot] != scene_id
        record = bytearray(state["scene_flash"][slot])
        record[id_offset:id_offset + 4] = scene_id.to_bytes(4, "little")
        state["scene_flash"][slot] = bytes(record)
        self._populate_scene(state, inner, slot)
        if newly_created and scene_id == 1:
            fallback = next((i for i, value in enumerate(ids) if i != slot and value == 0xffffffff), None)
            if fallback is not None:
                record = bytearray(state["scene_flash"][fallback])
                record[id_offset:id_offset + 4] = (2).to_bytes(4, "little")
                state["scene_flash"][fallback] = bytes(record)
                self._populate_scene(state, inner, fallback)
        self._scene_write(runtime)
        return None

    def _bin_cmd(self, device, state, inner):
        runtime = state["_runtime"]
        self._room(runtime, inner, reinitialize=True)
        scene = _field(inner, "sceneId")
        if scene is not _MISSING:
            code = self._scene(state, inner, _valueint(scene) & 0xffffffff)
            response = {"t": "res", "r": 200}
            if code is not None:
                response["code"] = code
            response["mac"] = device.mac
            return response
        banks = {name: bytearray(raw) for name, raw in state["raw_banks"].items()}
        fragment = _field(inner, "fragment")
        if fragment is not _MISSING:
            self._prepass(state, fragment, banks)
        # The one-byte gap at55 is never read by init-cache's three-byte tests.
        arena = bytearray(state["stack_work_readout"]) + bytearray(129)
        ascii_buffer = memoryview(arena)[56:184]
        dirty, mask = False, 0
        for name in ("91", "92", "93", "6A"):
            if not _default_copy(ascii_buffer, _field(inner, "hex" + name)):
                continue
            retain = name == "91" and banks[name][3] == 0x91 and (
                self.source_index == 35 or runtime["raw91_refresh"] != 1)
            if not retain:
                if name == "91" and self.source_index == 24:
                    runtime["raw91_refresh"] = 0
                    banks[name][:] = bytes(65)
                _decode_base64_into(ascii_buffer, banks[name])
            if self.source_index == 35 or name != "6A":
                dirty = True
            if self.source_index == 24 and name in ("91", "92", "93"):
                mask |= {"91": 0x20, "92": 0x40, "93": 0x80}[name]
            ascii_buffer[:] = bytes(128)
        if dirty:
            runtime["link_dirty"] = 1
        for name in ("6B", "6C", "6D", "6E"):
            if not _default_copy(ascii_buffer, _field(inner, "hex" + name)):
                continue
            if name == "6B":
                low = bytearray(32)
                arena[:32] = bytes(32)
                _decode_base64_into(ascii_buffer, low)
                count = low[2] + 3
                if count > 28:
                    raise InvalidPacket("legacy WB clock frame would overrun32-byte scratch")
                arena[:count] = low[4:4 + count]
                _set_clock(runtime, _cstring(arena[:32]).decode("ascii", errors="replace"), 0)
                ascii_buffer[:] = bytes(128)
                runtime["report_requests"] += 1
                runtime["report_builder_requests"] += 1
                dirty = True
            elif name == "6C":
                arena[:55] = bytes(55)
                _decode_base64_into(ascii_buffer, memoryview(arena)[:55])
                if arena[4]:
                    if runtime["frequency"] == 60:
                        runtime["pending_words"][6] = 0x4000 + arena[4]
                        runtime["report_requests"] += 1
                    length = arena[2] + 2
                    if length > 55:
                        raise InvalidPacket("legacy WB frequency cache copy would exceed55 bytes")
                    frequency = arena[4] if 1 <= arena[4] <= 59 else 60
                    old = runtime["frequency_frame"]
                    if frequency != runtime["frequency"] or bytes(arena[5:length]) != old[5:length]:
                        updated = bytearray(old)
                        updated[:length] = arena[:length]
                        runtime["frequency_frame"] = bytes(updated)
                        runtime["persist"]["RepotrFreq"] = bytes(updated)
                    runtime["frequency"] = frequency
                    runtime["pending_words"][8] = 0x405a
                dirty = True
            elif name == "6D":
                low = bytearray(55)
                arena[:55] = bytes(55)
                _decode_base64_into(ascii_buffer, low)
                count = max(0, low[2] - 2)
                if count > 51:
                    raise InvalidPacket("legacy WB city frame would read beyond55-byte scratch")
                arena[:count] = low[4:4 + count]
                city_bytes = _cstring(arena[:55])
                if len(city_bytes) >= 50:
                    raise InvalidPacket("legacy WB city strcpy would exceed50-byte storage")
                runtime["city"] = city_bytes.decode("latin1")
                runtime["persist"]["city_name"] = city_bytes + bytes(50 - len(city_bytes))
                runtime["pending_words"][24 if self.source_index == 24 else 16] = 0
            else:
                arena[:55] = bytes(55)
                _decode_base64_into(ascii_buffer, memoryview(arena)[:55])
                if arena[:2] == b"~~" and arena[3] == 0x6e:
                    length, count = arena[2] + 2, arena[21]
                    if length > 55 or 22 + count * 6 > 55:
                        raise InvalidPacket("legacy WB DataCurve would cross its55-byte source frame")
                    old = runtime["data_curve_frame"]
                    if bytes(arena[4:length]) != old[4:length]:
                        updated = bytearray(old)
                        updated[:length] = arena[:length]
                        runtime["data_curve_frame"] = bytes(updated)
                        runtime["persist"]["DataCurve"] = bytes(updated)
                    records = []
                    for index in range(count):
                        raw = arena[22 + index * 6:28 + index * 6]
                        records.append({"byte0": raw[1], "byte1": raw[2], "byte2": raw[3],
                                        "word4": int.from_bytes(raw[4:6], "big"), "byte6": raw[0]})
                    runtime["data_curve"] = {"bytes286_289": list(arena[4:8]),
                                             "bytes28b_28d": list(arena[8:11]),
                                             "words27c_284": [int.from_bytes(arena[i:i + 2], "big") for i in range(11, 21, 2)],
                                             "count": count, "records": records}
                    if arena[4] == 1 and arena[5] == 1 and arena[6]:
                        runtime["pending_words"][28 if self.source_index == 24 else 20] = 0x4000 + arena[6]
                dirty = True
        if fragment is not _MISSING:
            fragment_mask, special = self._fragments(state, fragment, arena, banks)
            mask |= fragment_mask
            dirty |= special
        state["raw_banks"] = {name: bytes(raw) for name, raw in banks.items()}
        if self.source_index == 24:
            for bit, status_index in ((0x20, 1), (0x40, 2), (0x80, 3)):
                if mask & bit:
                    runtime["pending_words"][18] = 0x4005
                    runtime["status_bytes"][status_index] = 0x42
            if mask & 0x20:
                runtime["raw_pending_bits"] |= 1
            if mask & 0x80:
                runtime["raw_pending_bits"] |= 4
        else:
            for bit, event in ((0x20, 0x91), (0x40, 0x92), (0x80, 0x93)):
                if mask & bit:
                    runtime["pending_words"][10] = 0x4008
                    runtime["uart_events"].append(event)
            if mask & 0x20:
                runtime["status_bytes"][1] = 0x42
        self._activity(runtime)
        if not dirty:
            runtime["report_requests"] += 1
        return {"t": "res", "r": 200, "mac": device.mac}

    def _operation(self, device, state, inner, operation, proactive):
        runtime = state["_runtime"]
        if operation == "scan":
            if runtime["online"] and _valueint(_field(inner, "allRange", 0)) != 1:
                return None
            result = {"t": "UBind", "mid": self.mid, "ver": runtime["sdk_version"],
                      "devkey": device.key.split(b"\0", 1)[0].decode("latin1"),
                      "hid": self.source["hid"], "lock": runtime["lock"]}
            if self.source_index == 24:
                result["scene"] = int(runtime["online"] == 0)
            self._activity(runtime)
            return result
        if operation == "bincmd":
            return self._bin_cmd(device, state, inner)
        if operation == "reset":
            found, target = _string_field(inner, "mac", 13)
            if not found or not device.mac.startswith(target):
                return None
            runtime["reset_flags"] |= 2
            return {"t": "res", "r": 200, "mac": device.mac}
        if operation == "ret":
            self._activity(runtime)
            if self.source_index == 24 and (_valueint(_field(inner, "r", 0)) & 255) == 200:
                runtime["status_bytes"][6] = 0
        elif operation == "hbok":
            self._heartbeat(runtime)
        elif operation == "utm":
            _, text = _string_field(inner, "time", 32)
            _set_clock(runtime, text, 8)
            self._activity(runtime)
            if self.source_index == 24:
                runtime["sync"] = 1
        elif operation == "ubindok":
            found, host_mac = _string_field(inner, "mac", 17)
            if found or self.source_index == 35:
                runtime["host_mac"] = host_mac
            if self.source_index == 24:
                self._room(runtime, inner)
                managed = _field(inner, "hostManaged")
                if managed is not _MISSING and _valueint(managed) == 0:
                    runtime["sdk_version"] = "V3.5.M"
                    runtime["host_managed"] = 1
                    runtime["persist"]["GREE_FLASH"] = 1
                    runtime["report_builder_requests"] += 1
                    return None
                runtime["host_managed"] = 0
            runtime["online"] = 1
            proactive.append(self._proactive(device, runtime, {"t": "Utm"}, reset=True))
            if self.source_index == 24:
                proactive.append(self._proactive(
                    device, runtime, {"t": "getLoginInfo", "loginInfo": ["GnetID"],
                                      "curGnetID": runtime["gnet_id"]}, increment=True))
            runtime["heartbeat_period_ms"] = 60000
            runtime["status_bytes"][7] = 0x4f
            self._heartbeat(runtime)
            runtime["report_requests"] += 1
            self._activity(runtime)
        elif operation == "logininfores":
            raw_result = _field(inner, "r")
            if raw_result is _MISSING:
                runtime["status_bytes"][7] = 0
                return None
            result = _valueint(raw_result)
            if result in (200, 406):
                info = _field(inner, "loginInfo")
                if type(info) is not str:
                    return None
                info = _json_object(info.encode())
                gnet = _field(info, "GnetID")
                if gnet is _MISSING:
                    return None
                gnet = _valueint(gnet) & 255
                if runtime["gnet_id"] != gnet:
                    runtime["gnet_id"] = gnet
                    runtime["persist"]["GnetID"] = gnet
                runtime["status_bytes"][7] = 0
                eligible = bool(gnet)
            elif result == 500:
                runtime["status_bytes"][7] = 0
                eligible = True
            else:
                return None
            if eligible and runtime["protocol_mode"] == 1 and not runtime["login_flag"]:
                runtime["login_flag"] = 1
                runtime["persist"]["Gnet"] = 1
                runtime["network_reinitializations"] += 1
        elif operation == "statuscheck":
            runtime["status_check"] = 1
            runtime["report_requests"] += 1
            runtime["status_check"] = 0
        return None

    def handle_from(self, device, outer, addr):
        if (not isinstance(addr, (tuple, list)) or len(addr) < 2
                or type(addr[1]) is not int or addr[1] != 5001):
            raise InvalidPacket("legacy WB UDP request source port must be5001")
        return self.handle(device, outer)

    def handle(self, device, outer):
        if not isinstance(outer, dict) or _field(outer, "t") != "pack":
            return []
        selector = _valueint(_field(outer, "i", 0)) & 255
        if selector not in (0, 1):
            return []
        uid = _valueint(_field(outer, "uid", 0))
        inner = self._decrypt(outer, device.key if selector == 0 else self.generic_key)
        _, kind = _string_field(inner, "t", 32)
        operation = _fold(kind)
        if self.operations.get(operation) != selector:
            return []
        state = deepcopy(device.state)
        self.validate_state(state)
        replies = []
        response = self._operation(device, state, inner, operation, replies)
        runtime = state["_runtime"]
        if response is not None:
            replies.append(self._reply(device, runtime, response, uid, 1 if operation == "scan" else 0))
        device.state.clear()
        device.state.update(state)
        return replies


def make_middle_wb_legacy_profile(source_index, mid, *, factory_key):
    """Bind one exact source to explicit MCU MID and8-u16 factory-key readout."""
    if source_index not in _SOURCE_DATA:
        raise ValueError("legacy WB source must be24 or35")
    if (type(mid) is not str or re.fullmatch(r"[0-9a-f]{1,8}", mid) is None
            or not int(mid, 16) or format(int(mid, 16), "x") != mid):
        raise ValueError("legacy WB MID must be its nonzero canonical UART0x44 %x output")
    if type(factory_key) is not bytes or len(factory_key) != 16:
        raise ValueError("legacy WB factory-key readout must be exactly16 bytes")
    source = _SOURCE_DATA[source_index]
    return Profile(id=f"sim-middle-wb-legacy-{source['sha256'][:8]}-{mid}", mids=(mid,),
                   hid=source["hid"], source_sha256=source["sha256"],
                   initial_state=_initial_state(source_index),
                   handler=LegacyWBController(source_index, mid, factory_key),
                   max_request_bytes=1536)


# Chosen virtual UART/factory inputs, NEVER physical or compiled fallback keys.
PROFILES = (make_middle_wb_legacy_profile(24, "10001", factory_key=b"WB24-key-preset1"),
            make_middle_wb_legacy_profile(35, "10001", factory_key=b"WB35-key-preset1"))
