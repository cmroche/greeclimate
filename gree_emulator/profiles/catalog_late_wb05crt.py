"""Raw Gnet UDP contract for WB05C(RT)V2.03.

Only the explicitly configured synthetic MID 10001 is admitted. Raw command
and status bytes are opaque controller data, not typed or calibrated physics.
"""

import base64
import binascii
from calendar import timegm
from copy import deepcopy
from datetime import datetime, timedelta
from time import monotonic

from ..wire import InvalidPacket, Reply, decode_pack
from . import Profile


GENERIC_KEY = b"en (otClceakve r"
CODEC = "aes-ecb-pkcs7-lf"
SOURCE_VERSION = "V3.5.M"
# Synthetic UTC+8 epoch; virtual time never depends on the host wall clock.
_VIRTUAL_CLOCK_START = "2026-01-01 08:00:00"
RAW_CAPACITIES = {"raw_hex91": 65, "raw_hex92": 65, "raw_hex93": 65, "raw_hex6A": 65}
SCENE_SLOTS = 20
SCENE_BYTES = 172
SCENE_FRAME_BYTES = 55
SCENE_FRAME_OFFSETS = {"hex91": 0, "hex93": 55, "hex92": 110}
SCENE_ID_OFFSET = 168
_TEMP_FRAME_FIELDS = ("hex6B", "hex6C", "hex6D", "hex6E")
_UDP_FLAGS = {"scan": 1, "UBindok": 0, "ret": 0, "binCmd": 0,
              "reset": 0, "hbok": 1, "Utm": 0, "loginInfoRes": 0,
              "statusCheck": 0}
_TIMER_SLOTS = {"timer_0x06": 3, "timer_0x08": 4, "report_timer": 9,
                "ubind_timer": 11, "timer_0x18": 12, "timer_0x1c": 14}


_RAW_STATUS_ROWS = (
    (0x002, 0x10016974, None),
    (0x004, 0x10016ab9, None),
    (0x008, 0x10016d03, None),
    (0x040, 0x100169b5, "raw_hex92"),
    (0x080, 0x10016bff, "raw_hex93"),
    (0x100, 0x100169f6, None),
    (0x200, 0x10016bbe, None),
    (0x800, 0x10016a78, "raw_hex6A"),
)
_RAW_STATUS_EMPTY_ADDRESSES = tuple(
    address for _mask, address, field in _RAW_STATUS_ROWS if field is None
)


def _integer(value, low=-(1 << 31), high=(1 << 31) - 1):
    if type(value) is not int or not low <= value <= high:
        raise InvalidPacket("WB05C(RT) requires a bounded integer")
    return value


def _string(value, maximum, *, empty=True):
    if (not isinstance(value, str) or (not empty and not value) or "\0" in value
            or len(value.encode("utf-8")) > maximum):
        raise InvalidPacket("WB05C(RT) string exceeds its source field")
    return value

def _set_clock(runtime, value, now=None):
    value = _string(value, 31)
    try:
        clock = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError as exc:
        raise InvalidPacket("WB05C(RT) clock must match its source date-time format") from exc
    runtime["time"] = runtime["virtual_clock_base"] = value
    runtime["raw_clock"] = bytes((clock.second, clock.minute, clock.hour,
                                  (clock.weekday() + 1) % 7, clock.day, clock.month))
    runtime["virtual_clock_started_at"] = now
    runtime["virtual_clock_elapsed_seconds"] = 0
    runtime["time_updates"] += 1
    runtime["save_count"] += 1
    runtime["status_save_pending"] = True


def _advance_virtual_clock(runtime, now):
    started = runtime["virtual_clock_started_at"]
    if started is None:
        runtime["virtual_clock_started_at"] = now
        return
    elapsed = max(0, int(now - started))
    if elapsed == runtime["virtual_clock_elapsed_seconds"]:
        return
    clock = datetime.strptime(runtime["virtual_clock_base"], "%Y-%m-%d %H:%M:%S")
    clock += timedelta(seconds=elapsed)
    runtime["time"] = clock.strftime("%Y-%m-%d %H:%M:%S")
    runtime["raw_clock"] = bytes((clock.second, clock.minute, clock.hour,
                                  (clock.weekday() + 1) % 7, clock.day, clock.month))
    runtime["virtual_clock_elapsed_seconds"] = elapsed



def _base64(value, maximum, name):
    if not isinstance(value, str):
        raise InvalidPacket(f"WB05C(RT) {name} must be base64 text")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise InvalidPacket(f"invalid WB05C(RT) {name} base64") from exc
    if len(raw) > maximum:
        raise InvalidPacket(f"WB05C(RT) {name} exceeds its source buffer")
    return raw


def _mac_bytes(device):
    value = device.mac.replace(":", "")
    if len(value) != 12:
        raise InvalidPacket("WB05C(RT) metadata requires a six-byte module MAC")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise InvalidPacket("WB05C(RT) metadata requires a hexadecimal module MAC") from exc


def _mid_number(device):
    try:
        value = int(device.mid, 16)
    except (TypeError, ValueError) as exc:
        raise InvalidPacket("WB05C(RT) metadata requires the configured hexadecimal MID") from exc
    if not 0 <= value <= 0xffffffff:
        raise InvalidPacket("WB05C(RT) MID exceeds its source uint32 field")
    return value


def build_raw_status_metadata(device, payload_length, *, clock=None):
    """Return the source's 39-byte status metadata prefix."""
    payload_length = _integer(payload_length, 0, 0x7fffffff)
    if clock is None:
        clock = device.state["_runtime"]["raw_clock"]
    if type(clock) is not bytes or len(clock) != 6:
        raise InvalidPacket("WB05C(RT) status clock must be six opaque bytes")
    mac = _mac_bytes(device)
    return (b"fg\0" + bytes((payload_length & 255,)) + mac + bytes(6) + mac
            + _mid_number(device).to_bytes(4, "big") + b"\0\0\0\0\x06\0"
            + clock + b"\x02")


def build_raw_status(device, payload):
    """Wrap opaque source bytes as a base64 ``binStatus`` report."""
    if type(payload) is not bytes:
        raise InvalidPacket("WB05C(RT) status payload must be opaque bytes")
    encoded_payload = base64.b64encode(payload)
    metadata = build_raw_status_metadata(device, len(encoded_payload))
    return {"t": "binStatus", "mac": device.mac,
            "binStatus": encoded_payload.decode("ascii"),
            "header": base64.b64encode(metadata).decode("ascii")}




def _runtime():
    return {
        "time": _VIRTUAL_CLOCK_START, "virtual_clock_base": _VIRTUAL_CLOCK_START,
        "virtual_clock_started_at": None, "virtual_clock_elapsed_seconds": 0,
        "raw_clock": bytes((0, 0, 8, 4, 1, 1)), "room_id": 0,
        "host_managed": 0, "host_mac": "", "host_addr": None,
        "msg_id": 0, "lock": 0,
        "gnet_key": b"", "dirty": 0, "pending": 0,
        "status_save_pending": False, "network_restart_pending": False,
        "cloud_platform": 0, "reset_requested": False,
        "ret_count": 0, "heartbeat_acks": 0,
        "heartbeat_timer_active": False, "heartbeat_timer_ms": 0,
        "heartbeat_watchdog_due": None, "heartbeat_period_due": None,
        "heartbeat_period_ms": 0, "heartbeat_miss_count": 0,
        "rssi": 0,
        "source_timer_0x3c_ms": 0,
        "countdown_next_at": None, "countdown_calls": 0,
        "virtual_boot_time": None,
        "countdown_bytes": [0] * 8, "countdown_extra_byte": 0,
        "countdown_halfwords": [0] * 20,
        "timer_0x08": 0, "source_mode_0x4ac": 0,
        "report_timer": 0,
        "report_ready": 0, "report_type": 0, "report_payload": b"",
        "report_marker": 0, "report_retry_count": 0,
        "report_retry_due": None,
        "raw_status_source_flag": 0,
        "raw_settings_hex6C": b"", "raw_settings_hex6E": b"",
        "save_count": 0, "time_updates": 0, "scene_save_count": 0,
        "timer_0x18": 0, "timer_0x1c": 0, "timer_0x06": 0,
        "metadata_gate": 0, "scene_flag": 0,
        "controller_id_available": 0, "source_state_7": 0,
        "ubind_gate_4ed": 0, "ubind_gate_4e5": 0,
        "ubind_retry_count": 0, "ubind_flag": 0, "ubind_timer": 0,
    }


def _heartbeat_ok(runtime, now):
    runtime["heartbeat_acks"] += 1
    runtime["msg_id"] = (runtime["msg_id"] + 1) & 0xffffffff
    runtime["heartbeat_miss_count"] = 0
    runtime["heartbeat_timer_ms"] = 61000
    if runtime["host_managed"]:
        runtime["heartbeat_timer_active"] = True
        runtime["heartbeat_watchdog_due"] = now + 61
    else:
        runtime["heartbeat_timer_active"] = False
        runtime["heartbeat_watchdog_due"] = None

def _set_timer(runtime, name, value):
    runtime[name] = value
    runtime["countdown_halfwords"][_TIMER_SLOTS[name]] = value


def _set_countdown_byte(runtime, index, value):
    runtime["countdown_bytes"][index] = value
    if index == 5:
        runtime["ubind_flag"] = value
    elif index == 7:
        runtime["source_state_7"] = value


def _count_down(value, active, expired, steps=1):
    if steps == 0 or not value & active:
        return value
    remaining = value & (active - 1)
    # Native code subtracts first, then replaces an exact active marker with
    # expired. An active marker with no count instead loses its active bit.
    if remaining == 0 or value & expired:
        return value - min(steps, remaining + 1)
    return expired if steps >= remaining else value - steps


def _advance_countdowns(runtime, now):
    deadline = runtime["countdown_next_at"]
    if deadline is None:
        runtime["countdown_next_at"] = now + 0.1
        return
    if now < deadline:
        return
    # A delayed event loop need not replay every 100 ms callback. No sender
    # runs inside this callback: only bounded countdowns and modulo-ten phase.
    steps = int((now - deadline) * 10) + 1
    if deadline + steps / 10 <= now:
        steps += 1
    countdown_bytes = runtime["countdown_bytes"]
    countdown_bytes[5] = runtime["ubind_flag"]
    countdown_bytes[7] = runtime["source_state_7"]
    for index, value in enumerate(countdown_bytes):
        _set_countdown_byte(
            runtime, index, _count_down(value, 0x40, 0x80, steps)
        )
    slow_steps, calls = divmod(runtime["countdown_calls"] + steps, 10)
    if slow_steps:
        runtime["countdown_extra_byte"] = _count_down(
            runtime["countdown_extra_byte"], 0x40, 0x80, slow_steps
        )
        halfwords = runtime["countdown_halfwords"]
        for name, index in _TIMER_SLOTS.items():
            halfwords[index] = runtime[name]
        for index, value in enumerate(halfwords):
            halfwords[index] = _count_down(value, 0x4000, 0x8000, slow_steps)
        for name, index in _TIMER_SLOTS.items():
            runtime[name] = halfwords[index]
    runtime["countdown_calls"] = calls
    runtime["countdown_next_at"] = deadline + steps / 10
def _virtual_tick_ms(runtime, now):
    epoch = runtime["virtual_boot_time"]
    if epoch is None:
        runtime["virtual_boot_time"] = now
        return 0
    return int(max(0.0, now - epoch) * 1000) & 0xffffffff


def _source_jitter(runtime, now):
    state = _virtual_tick_ms(runtime, now)
    state = (state * 0x5851f42d4c957f2d + 1) & 0xffffffffffffffff
    return (((state >> 32) & 0x7fffffff) % 10) * 0.3


def _declared(raw, capacity, extra=3):
    length = (raw[2] if len(raw) > 2 else 0) + extra
    if length > capacity:
        raise InvalidPacket("WB05C(RT) declared raw frame exceeds its source buffer")
    if len(raw) < length:
        raise InvalidPacket("WB05C(RT) raw frame is shorter than its declared length")
    return length


def _raw_status_frame(state, address, field):
    return state[field] if field is not None else state["raw_status_frames"][address]


def _aggregate_raw_status(state, runtime):
    frames = [
        _raw_status_frame(state, address, field)
        for _mask, address, field in _RAW_STATUS_ROWS
    ]
    raw_hex6a = state["raw_hex6A"]
    extended = (runtime["raw_status_source_flag"] == 1
                and len(raw_hex6a) > 3 and raw_hex6a[3] == 0x6a)
    mask = 0x0bce if extended else 0x03ce
    payload = bytearray()
    for (selector, _address, _field), frame in zip(_RAW_STATUS_ROWS, frames):
        if (not mask & selector or len(frame) < 3 or frame[:2] != b"~~"
                or frame[2] == 0):
            continue
        count = (frame[2] + 3) & 255
        if count > len(frame) or len(payload) + count > 512:
            raise InvalidPacket("WB05C(RT) aggregate exceeds its bounded raw source")
        payload.extend(frame[:count])
    return bytes(payload)


def _queue_source_report(state):
    runtime = state["_runtime"]
    report_type = 6 if state["status_check"] == 0 else 7
    runtime["report_type"] = report_type
    runtime["report_payload"] = _aggregate_raw_status(state, runtime)
    runtime["report_marker"] = 0
    runtime["report_retry_due"] = None
    if report_type == 6:
        runtime["report_retry_count"] = 0
    if runtime["ubind_gate_4ed"] == 1:
        runtime["report_ready"] = 1


def _status_report_timestamp(runtime):
    clock = datetime.strptime(runtime["time"], "%Y-%m-%d %H:%M:%S")
    epoch = timegm(clock.timetuple()) if clock.year >= 1970 else 0
    value = epoch - 28800
    return ((value + 0x80000000) & 0xffffffff) - 0x80000000


_INITIAL_STATE = {
    **{name: bytes(size) for name, size in RAW_CAPACITIES.items()},
    "raw_scenes": [bytes(SCENE_BYTES) for _ in range(SCENE_SLOTS)],
    "raw_fragment_initializers": [bytes(16) for _ in range(5)],
    "raw_status_frames": {address: b"" for address in _RAW_STATUS_EMPTY_ADDRESSES},
    "raw_metadata_byte": 0,
    "status_check": 0,
    "raw_payloads_synthetic": True,
    "_runtime": _runtime(),
}


def _scene_id(record):
    return int.from_bytes(record[SCENE_ID_OFFSET:SCENE_BYTES], "little")


def _set_scene_id(record, scene_id):
    return (record[:SCENE_ID_OFFSET] + scene_id.to_bytes(4, "little"))


def _fixed_write(current, raw, *, clear=False):
    data = bytearray(bytes(len(current)) if clear else current)
    data[:len(raw)] = raw
    return bytes(data)




def _fragment_records(value):
    if not isinstance(value, list) or len(value) > 255:
        raise InvalidPacket("WB05C(RT) fragment must be a bounded positional array")
    parsed = []
    for record in value:
        if not isinstance(record, list) or not 4 <= len(record) <= 5:
            raise InvalidPacket("WB05C(RT) V3.5.M fragment records require four or five fields")
        command_type, byte_offset, mask, fragment_value = record[:4]
        initial = (_integer(record[4], -(1 << 31), 0xffffffff)
                   if len(record) == 5 else None)
        parsed.append((_integer(command_type, 0, 255), _integer(byte_offset, 0, 255),
                       _integer(mask, 0, 0xffff),
                       _integer(fragment_value, -(1 << 31), 0xffffffff), initial))
    return parsed


def _remember_fragment(state, command_type, byte_offset, mask, value, initial):
    table = state["raw_fragment_initializers"]
    key = bytes((command_type, byte_offset)) + mask.to_bytes(2, "little")
    index = next((i for i, record in enumerate(table) if record[:4] == key), None)
    if index is None:
        index = next((i for i, record in enumerate(table) if record == bytes(16)), None)
    if index is not None:
        table[index] = (
            key + (value & 0xffffffff).to_bytes(4, "little")
            + (initial & 0xffffffff).to_bytes(4, "little") + bytes(4)
        )




def _apply_fragment(state, runtime, command_type, byte_offset, mask, value):
    if (command_type, byte_offset, mask) == (0x82, 3, 0x60):
        state["raw_metadata_byte"] = value & 255
        runtime["status_save_pending"] = True
        return
    name = {0x91: "raw_hex91", 0x92: "raw_hex92", 0x93: "raw_hex93"}.get(command_type)
    if name is None:
        raise InvalidPacket("WB05C(RT) fragment selects no evidenced raw cache")
    offset = byte_offset + 3
    if offset >= RAW_CAPACITIES[name]:
        raise InvalidPacket("WB05C(RT) fragment offset exceeds its raw cache")
    shift = 16 if mask == 0 else (mask & -mask).bit_length() - 1
    old = state[name][offset]
    data = bytearray(state[name])
    data[offset] = ((old & (~mask & 255)) + (mask & ((value << shift) & 255))) & 255
    state[name] = bytes(data)


def _scene_payloads(inner, record, state, runtime, scene_id):
    result = bytearray(record)
    for name, offset in SCENE_FRAME_OFFSETS.items():
        if name in inner:
            raw = _base64(inner[name], SCENE_FRAME_BYTES, name)
            result[offset:offset + SCENE_FRAME_BYTES] = raw + bytes(SCENE_FRAME_BYTES - len(raw))
    if "fragment" in inner:
        for command_type, byte_offset, mask, value, initial in _fragment_records(inner["fragment"]):
            if scene_id == 2:
                value = int(value == 0)
            if (command_type, byte_offset, mask) == (0x82, 3, 0x60):
                _apply_fragment(state, runtime, command_type, byte_offset, mask, value)
                if initial is not None:
                    _remember_fragment(state, command_type, byte_offset, mask, value, initial)
                continue
            name = {0x91: "hex91", 0x92: "hex92", 0x93: "hex93"}.get(command_type)
            offset = byte_offset + 3
            if name is None or offset >= SCENE_FRAME_BYTES:
                raise InvalidPacket("WB05C(RT) scene fragment exceeds its source frame")
            position = SCENE_FRAME_OFFSETS[name] + offset
            shift = 16 if mask == 0 else (mask & -mask).bit_length() - 1
            result[position] = ((result[position] & (~mask & 255))
                                + (mask & ((value << shift) & 255))) & 255
            if initial is not None:
                _remember_fragment(state, command_type, byte_offset, mask, value, initial)
    return bytes(result)




def _scene(state, inner, runtime):
    if "sceneId" not in inner:
        return 0
    scene_id = _integer(inner["sceneId"], 0, 0xffffffff)
    if runtime["controller_id_available"] == 0:
        return 501
    operation = _integer(inner.get("operType", 0), 0, 255) & 255
    enabled = _integer(inner.get("sence_enable", 0), 0, 255) & 255
    if operation not in (0, 1, 2):
        return 0
    records = state["raw_scenes"]
    matches = [index for index, record in enumerate(records)
               if _scene_id(record) == scene_id]
    if operation == 2:
        for index in matches:
            records[index] = bytes(SCENE_BYTES)
            runtime["scene_save_count"] += 1
        return 0
    if operation == 0:
        for index in matches:
            records[index] = _set_scene_id(
                _scene_payloads(inner, records[index], state, runtime, scene_id), scene_id
            )
            runtime["scene_save_count"] += 1
        return 0
    if scene_id != 1 and enabled != 1:
        return 0
    slot = matches[0] if matches else next(
        (index for index, record in enumerate(records)
         if _scene_id(record) in (0, 0xffffffff)), None
    )
    if slot is None:
        return 0 if scene_id == 1 else 501
    payload = _scene_payloads(inner, records[slot], state, runtime, scene_id)
    records[slot] = _set_scene_id(payload, scene_id)
    runtime["scene_save_count"] += 1
    if scene_id == 1:
        second = next((index for index, record in enumerate(records)
                       if index != slot and _scene_id(record) == 0xffffffff), None)
        if second is not None:
            payload = _scene_payloads(inner, records[second], state, runtime, 2)
            records[second] = _set_scene_id(payload, 2)
            runtime["scene_save_count"] += 1
    return 0




class CrtController:
    """One source-qualified UDP5001 host-controller; no cloud/local facade."""

    source_port = 5001
    accept_any_target = True
    plaintext_types = ()
    tick_interval = 0.1

    def thermal_target(self, device):
        # This build exposes opaque raw frames; no calibrated physical mapping is evidenced.
        return None

    def encode_room(self, device):
        return None

    def validate_state(self, state):
        for name, capacity in RAW_CAPACITIES.items():
            value = state.get(name)
            if type(value) is not bytes or len(value) != capacity:
                raise ValueError(f"{name} must be a {capacity}-byte opaque buffer")
        frames = state.get("raw_status_frames")
        if (not isinstance(frames, dict)
                or set(frames) != set(_RAW_STATUS_EMPTY_ADDRESSES)
                or any(type(frame) is not bytes or len(frame) > 255
                       for frame in frames.values())):
            raise ValueError("raw_status_frames must preserve the five bounded opaque source buffers")
        scenes = state.get("raw_scenes")
        if (not isinstance(scenes, list) or len(scenes) != SCENE_SLOTS
                or any(type(scene) is not bytes or len(scene) != SCENE_BYTES for scene in scenes)):
            raise ValueError("raw_scenes must contain twenty 172-byte source records")
        fragments = state.get("raw_fragment_initializers")
        if (not isinstance(fragments, list) or len(fragments) != 5
                or any(type(record) is not bytes or len(record) != 16 for record in fragments)):
            raise ValueError("raw_fragment_initializers must contain five 16-byte source records")
        runtime = state.get("_runtime")
        if not isinstance(runtime, dict) or set(runtime) != set(_runtime()):
            raise ValueError("WB05C(RT) runtime state is incomplete")
        if type(runtime.get("gnet_key")) is not bytes or len(runtime["gnet_key"]) > 0x32:
            raise ValueError("gnet_key must preserve its bounded opaque source bytes")
        if any(type(runtime.get(name)) is not int or not 0 <= runtime[name] <= 255
               for name in ("room_id", "dirty", "pending", "cloud_platform")):
            raise ValueError("WB05C(RT) byte fields must preserve their source uint8 values")
        for name in ("status_save_pending", "network_restart_pending", "reset_requested"):
            if type(runtime.get(name)) is not bool:
                raise ValueError(f"{name} must preserve its source boolean state")
        try:
            clock = datetime.strptime(runtime["time"], "%Y-%m-%d %H:%M:%S")
            datetime.strptime(runtime["virtual_clock_base"], "%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError) as exc:
            raise ValueError("WB05C(RT) virtual clock must use the source date-time format") from exc
        if (type(runtime.get("raw_clock")) is not bytes or runtime["raw_clock"] != bytes(
                (clock.second, clock.minute, clock.hour, (clock.weekday() + 1) % 7,
                 clock.day, clock.month))):
            raise ValueError("raw_clock must preserve the virtual source-local calendar")
        elapsed = runtime.get("virtual_clock_elapsed_seconds")
        if type(elapsed) is not int or elapsed < 0:
            raise ValueError("virtual_clock_elapsed_seconds must be a nonnegative integer")
        if type(runtime.get("controller_id_available")) is not int or not 0 <= runtime["controller_id_available"] <= 255:
            raise ValueError("controller_id_available must preserve the source uint8 GnetID")
        if type(runtime.get("rssi")) is not int or not 0 <= runtime["rssi"] <= 0xffffffff:
            raise ValueError("rssi must preserve the source uint32 field")
        if type(runtime.get("source_state_7")) is not int or not 0 <= runtime["source_state_7"] <= 255:
            raise ValueError("source_state_7 must preserve the source uint8 field")
        if type(runtime.get("report_ready")) is not int or runtime["report_ready"] not in (0, 1):
            raise ValueError("report_ready must preserve the source uint8 status-ready flag")
        if type(runtime.get("report_type")) is not int or runtime["report_type"] not in (0, 6, 7):
            raise ValueError("report_type must preserve the source type-6/type-7 context")
        if type(runtime.get("report_payload")) is not bytes or len(runtime["report_payload"]) > 512:
            raise ValueError("report_payload must remain a bounded opaque frame aggregate")
        if type(runtime.get("report_marker")) is not int or not 0 <= runtime["report_marker"] <= 255:
            raise ValueError("report_marker must preserve the source uint8 retry marker")
        if type(runtime.get("report_retry_count")) is not int or not -1 <= runtime["report_retry_count"] <= 4:
            raise ValueError("report_retry_count must preserve the source retry state")
        if type(runtime.get("raw_status_source_flag")) is not int or runtime["raw_status_source_flag"] not in (0, 1):
            raise ValueError("raw_status_source_flag must preserve the source boolean")
        for name in ("raw_settings_hex6C", "raw_settings_hex6E"):
            if type(runtime.get(name)) is not bytes or len(runtime[name]) > SCENE_FRAME_BYTES:
                raise ValueError(f"{name} must remain a bounded opaque settings frame")
        byte_timers = runtime.get("countdown_bytes")
        halfword_timers = runtime.get("countdown_halfwords")
        if (not isinstance(byte_timers, list) or len(byte_timers) != 8
                or any(type(value) is not int or not 0 <= value <= 255
                       for value in byte_timers)):
            raise ValueError("countdown_bytes must preserve eight source uint8 timers")
        if (not isinstance(halfword_timers, list) or len(halfword_timers) != 20
                or any(type(value) is not int or not 0 <= value <= 0xffff
                       for value in halfword_timers)):
            raise ValueError("countdown_halfwords must preserve twenty source uint16 timers")
        if type(runtime.get("countdown_calls")) is not int or not 0 <= runtime["countdown_calls"] < 10:
            raise ValueError("countdown_calls must be the source 100ms modulo-ten counter")
        if type(runtime.get("countdown_extra_byte")) is not int or not 0 <= runtime["countdown_extra_byte"] <= 255:
            raise ValueError("countdown_extra_byte must preserve the source uint8 timer")
        for name in ("countdown_next_at", "virtual_boot_time",
                     "virtual_clock_started_at", "report_retry_due"):
            value = runtime.get(name)
            if value is not None and type(value) not in (int, float):
                raise ValueError(f"{name} must use the monotonic-seconds clock")
        metadata_byte = state.get("raw_metadata_byte")
        if type(metadata_byte) is not int or not 0 <= metadata_byte <= 255:
            raise ValueError("raw_metadata_byte must preserve its source uint8 field")
        if type(state.get("status_check")) is not int or state["status_check"] not in (0, 1):
            raise ValueError("status_check must be the source uint8 flag")
        if state.get("raw_payloads_synthetic") is not True:
            raise ValueError("WB05C(RT) raw buffers must remain explicitly synthetic")

    def advertise(self, device, outer):
        # Plain Gree LAN scan is not registered in the native UDP operation table.
        return []

    @staticmethod
    def _reply(device, state, inner, selector, uid):
        runtime = state["_runtime"]
        message_id = runtime["msg_id"]
        if message_id > 0xffff:
            message_id = 0
        runtime["msg_id"] = message_id + 1
        return Reply({"t": "pack", "i": selector, "uid": uid,
                      "cid": device.mac, "tcid": runtime["host_mac"],
                      "msgId": message_id}, inner,
                     GENERIC_KEY if selector else device.key, CODEC,
                     destination_port=5000)

    @staticmethod
    def _lifecycle_reply(device, state, inner, selector, *, increment=False):
        runtime = state["_runtime"]
        if increment:
            runtime["msg_id"] = (runtime["msg_id"] + 1) & 0xffffffff
        if not increment and runtime["msg_id"] > 0xffff:
            runtime["msg_id"] = 0
        outer = {"t": "pack", "i": selector, "msgId": runtime["msg_id"],
                 "cid": device.mac, "tcid": runtime["host_mac"]}
        return Reply(outer, inner, GENERIC_KEY if selector else device.key, CODEC,
                     destination_port=5000)

    @staticmethod
    def _heartbeat_reply(device, state):
        runtime = state["_runtime"]
        message_id = runtime["msg_id"]
        if message_id > 0xffff:
            message_id = 0
            runtime["msg_id"] = 0
        outer = {"t": "pack", "i": 1, "uid": 0, "cid": device.mac,
                 "tcid": runtime["host_mac"], "msgId": message_id}
        inner = {"t": "hb", "cid": device.mac, "RSSI": runtime["rssi"]}
        return Reply(outer, inner, GENERIC_KEY, CODEC, destination_port=5000)


    @staticmethod
    def _raw_report_reply(device, state, inner):
        runtime = state["_runtime"]
        message_id = runtime["msg_id"]
        if message_id > 0xffff:
            message_id = 0
            runtime["msg_id"] = 0
        outer = {"t": "pack", "i": 0, "msgId": message_id,
                 "cid": device.mac, "tcid": runtime["host_mac"]}
        return Reply(outer, inner, device.key, CODEC, destination_port=5000)

    def queue_source_report(self, device):
        """Build the source's next raw UDP report from opaque cached frames."""
        _queue_source_report(device.state)

    def _report_tick(self, device, state, host, now):
        runtime = state["_runtime"]
        if (runtime["report_ready"] != 1 or not runtime["host_managed"]
                or not isinstance(host, (tuple, list)) or not host):
            return []
        replies = []
        report_type = runtime["report_type"]
        if report_type == 6:
            due = runtime["report_retry_due"]
            if (runtime["report_marker"] != 0 and due is not None and now >= due):
                runtime["report_marker"] |= 0x80
            if runtime["report_marker"] & 0x80 or runtime["report_retry_count"] == 0:
                body = build_raw_status(device, runtime["report_payload"])
                replies.append((self._raw_report_reply(device, state, body),
                                (host[0], 5000)))
                runtime["report_marker"] = 0x4a
                runtime["report_retry_count"] += 1
                runtime["report_retry_due"] = now + 1
            if runtime["report_retry_count"] > 3:
                runtime["report_retry_count"] = -1
                runtime["report_marker"] = 0
                runtime["report_retry_due"] = None
            if runtime["report_marker"] != 0:
                return replies
        elif report_type == 7:
            body = {"t": "statusCheckRes",
                    "timestamp": _status_report_timestamp(runtime),
                    "binStatus": base64.b64encode(
                        runtime["report_payload"]
                    ).decode("ascii")}
            replies.append((self._raw_report_reply(device, state, body),
                            (host[0], 5000)))
        else:
            return replies
        runtime["report_ready"] = 0
        runtime["report_type"] = 0
        runtime["report_payload"] = b""
        runtime["report_marker"] = 0
        runtime["report_retry_due"] = None
        return replies

    @staticmethod
    def _ubind_reply(device, state):
        runtime = state["_runtime"]
        if runtime["msg_id"] > 0xffff:
            runtime["msg_id"] = 0
        inner = {"t": "UBind", "mid": device.mid, "ver": SOURCE_VERSION,
                 "lock": runtime["lock"], "devkey": device.key.decode("ascii"),
                 "scene": int(runtime["scene_flag"] == 0), "hid": device.profile.hid}
        outer = {"t": "pack", "i": 1, "msgId": runtime["msg_id"],
                 "cid": device.mac, "tcid": ""}
        return Reply(outer, inner, GENERIC_KEY, CODEC, destination_port=5000,
                     destination_host="255.255.255.255")

    def _bin_cmd(self, device, state, inner, now):
        runtime = state["_runtime"]
        source_mutated = False
        if "roomId" in inner:
            room_id = _integer(inner["roomId"], 0, 0xffffffff) & 255
            runtime["room_id"] = room_id
            if (runtime["controller_id_available"] != 0
                    and runtime["ubind_gate_4e5"] == 1
                    and runtime["ubind_gate_4ed"] == 0):
                runtime["ubind_gate_4ed"] = 1
                runtime["network_restart_pending"] = True
        scene_code = _scene(state, inner, runtime)
        if "sceneId" in inner:
            response = {"t": "res", "r": 200, "mac": device.mac}
            if scene_code:
                response["code"] = scene_code
            return response
        for name in ("hex91", "hex92", "hex93", "hex6A"):
            if name not in inner:
                continue
            field = "raw_" + name
            if name in ("hex91", "hex92", "hex93"):
                source_mutated = True
            raw = _base64(inner[name], RAW_CAPACITIES[field], name)
            _declared(raw, RAW_CAPACITIES[field])
            if name == "hex91" and state[field][3] == 0x91 and runtime["metadata_gate"] != 1:
                pass
            else:
                state[field] = _fixed_write(state[field], raw, clear=name == "hex91")
                if name == "hex91":
                    runtime["metadata_gate"] = 0
            if name == "hex91":
                runtime["dirty"] |= 0x20
                _set_timer(runtime, "report_timer", 0x4005)
                _set_countdown_byte(runtime, 1, 0x42)
            elif name == "hex92":
                runtime["dirty"] |= 0x40
                _set_timer(runtime, "report_timer", 0x4005)
                _set_countdown_byte(runtime, 2, 0x42)
                runtime["pending"] |= 1
            elif name == "hex93":
                runtime["dirty"] |= 0x80
                _set_timer(runtime, "report_timer", 0x4005)
                _set_countdown_byte(runtime, 3, 0x42)
                runtime["pending"] |= 4

        for name in _TEMP_FRAME_FIELDS:
            if name not in inner:
                continue
            raw = _base64(inner[name], SCENE_FRAME_BYTES, name)
            frame_length = _declared(
                raw, SCENE_FRAME_BYTES, 2 if name in ("hex6C", "hex6D", "hex6E") else 3
            )
            frame = raw + bytes(SCENE_FRAME_BYTES - len(raw))
            if name in ("hex6B", "hex6C", "hex6E"):
                source_mutated = True
            if name == "hex6B":
                if frame_length > 31 or 4 + frame_length > len(frame):
                    raise InvalidPacket("WB05C(RT) source clock exceeds its bounded frame")
                text = frame[4:4 + frame_length].split(b"\0", 1)[0]
                try:
                    clock_text = text.decode("ascii")
                except UnicodeDecodeError as exc:
                    raise InvalidPacket("WB05C(RT) source clock is not ASCII") from exc
                _set_clock(runtime, clock_text, now)
                _queue_source_report(state)
            elif name == "hex6C":
                if frame[4]:
                    runtime["raw_settings_hex6C"] = raw[:frame_length]
                    if runtime["source_mode_0x4ac"] == 0x3c:
                        _set_timer(runtime, "timer_0x06", frame[4] + 0x4000)
                        _queue_source_report(state)
                        runtime["status_save_pending"] = True
                        runtime["save_count"] += 1
                    runtime["source_mode_0x4ac"] = min(frame[4], 0x3c)
                    _set_timer(runtime, "timer_0x08", 0x405a)
            elif name == "hex6D":
                runtime["gnet_key"] = frame[4:frame_length].split(b"\0", 1)[0][:0x32]
                _set_timer(runtime, "timer_0x18", 0)
            elif name == "hex6E":
                if frame[:2] == b"~~" and frame[3] == 0x6e:
                    runtime["raw_settings_hex6E"] = raw[:frame_length]
                    if frame[4] == 1 and frame[5] == 1 and frame[6] != 0:
                        _set_timer(runtime, "timer_0x1c", frame[6] + 0x4000)

        if "fragment" in inner:
            for command_type, byte_offset, mask, value, initial in _fragment_records(inner["fragment"]):
                _apply_fragment(state, runtime, command_type, byte_offset, mask, value)
                if initial is not None:
                    _remember_fragment(state, command_type, byte_offset, mask, value, initial)
        if not source_mutated:
            _queue_source_report(state)
        return {"t": "res", "r": 200, "mac": device.mac}

    @staticmethod
    def _ubindok(device, state, inner, addr, now):
        runtime = state["_runtime"]
        host_managed = int(_integer(inner.get("hostManaged", 1), 0, 0xffffffff) != 0)
        if "roomId" in inner:
            runtime["room_id"] = _integer(inner["roomId"], 0, 0xffffffff) & 255
        if "host" in inner:
            runtime["host_mac"] = _string(inner["host"], 17)
        runtime["host_managed"] = host_managed
        if host_managed:
            runtime["host_addr"] = addr
            runtime["lock"] = 1
            _set_countdown_byte(runtime, 7, 0x4f)
            runtime["source_timer_0x3c_ms"] = 60000
            runtime["heartbeat_period_due"] = now + 60
            runtime["heartbeat_period_ms"] = 60000
        else:
            runtime["host_addr"] = None

    @staticmethod
    def _reset(device, state, inner):
        # shortcut: ROM0x80c is modeled as bounded comparison from caller ABI; requalify with matching SDK/ROM.
        requested = inner.get("mac")
        if (not isinstance(requested, str)
                or not device.mac.startswith(requested.split("\0", 1)[0])):
            return None
        state["_runtime"]["reset_requested"] = True
        return {"t": "ret", "r": 200, "mac": device.mac}

    def handle_from(self, device, outer, addr):
        if (not isinstance(addr, (tuple, list)) or len(addr) < 2
                or type(addr[1]) is not int or addr[1] != self.source_port):
            raise InvalidPacket("WB05C(RT) UDP source port must be 5001")
        if not isinstance(outer, dict):
            raise InvalidPacket("WB05C(RT) requires an object envelope")
        if outer.get("t") != "pack":
            raise InvalidPacket("WB05C(RT) requires the native encrypted pack envelope")
        selector = outer.get("i", 0)
        if type(selector) is not int:
            raise InvalidPacket("WB05C(RT) key selector must be uint8")
        selector &= 255
        if selector == 2:
            # Native slot two can parse an object pack, but no source callback has flag two.
            return []
        expected_uid = outer.get("uid", 0)
        uid = _integer(expected_uid, 0, 0xffffffff)
        inner = decode_pack(outer, device.key if selector == 0 else GENERIC_KEY, CODEC)
        kind = inner.get("t")
        if not isinstance(kind, str) or kind not in _UDP_FLAGS or _UDP_FLAGS[kind] != selector:
            return []
        now = monotonic()
        state = deepcopy(device.state)
        runtime = state["_runtime"]
        _virtual_tick_ms(runtime, now)
        _advance_virtual_clock(runtime, now)
        if runtime["countdown_next_at"] is None:
            runtime["countdown_next_at"] = now + 0.1
        response = None
        replies = []
        if kind == "scan":
            scene = _integer(inner.get("i", 0), 0, 255)
            if runtime["host_managed"] and scene != 1:
                return []
            response = {"t": "UBind", "scene": int(runtime["scene_flag"] == 0),
                        "mid": device.mid, "ver": SOURCE_VERSION, "lock": runtime["lock"],
                        "devkey": device.key.decode("ascii"), "hid": device.profile.hid}
        elif kind == "UBindok":
            self._ubindok(device, state, inner, addr, now)
            if runtime["host_managed"]:
                replies.append(self._lifecycle_reply(device, state, {"t": "Utm"}, 0))
                login_info = {"t": "getLoginInfo", "loginInfo": ["GnetID"],
                              "curGnetID": runtime["controller_id_available"]}
                replies.append(self._lifecycle_reply(
                    device, state, login_info, 0, increment=True
                ))
                _heartbeat_ok(runtime, now)
                _queue_source_report(state)
        elif kind == "ret":
            result = _integer(inner.get("r", 0)) & 255
            runtime["ret_count"] += 1
            if result == 200:
                runtime["report_marker"] = 0
        elif kind == "hbok":
            _heartbeat_ok(runtime, now)
        elif kind == "Utm":
            if "time" in inner:
                _set_clock(runtime, inner["time"], now)
        elif kind == "loginInfoRes":
            if "r" not in inner:
                _set_countdown_byte(runtime, 7, 0)
            result = _integer(inner.get("r", 0), 0, 0xffffffff)
            restart = False
            if result in (200, 406):
                nested = inner.get("result")
                if isinstance(nested, dict) and "platform" in nested:
                    runtime["cloud_platform"] = _integer(
                        nested["platform"], 0, 0xffffffff
                    ) & 255
                    _set_countdown_byte(runtime, 7, 0)
                    restart = runtime["controller_id_available"] != 0
            elif result == 500:
                _set_countdown_byte(runtime, 7, 0)
                restart = True
            if (restart and runtime["ubind_gate_4e5"] == 1
                    and runtime["ubind_gate_4ed"] == 0):
                runtime["ubind_gate_4ed"] = 1
                runtime["network_restart_pending"] = True
        elif kind == "statusCheck":
            state["status_check"] = 1
            _queue_source_report(state)
            state["status_check"] = 0
        elif kind == "reset":
            response = self._reset(device, state, inner)
        elif kind == "binCmd":
            response = self._bin_cmd(device, state, inner, now)

        if response is not None:
            replies.append(self._reply(device, state, response, selector, uid))
        device.state = state
        return replies

    def tick(self, device, now):
        state = device.state
        runtime = state["_runtime"]
        _virtual_tick_ms(runtime, now)
        _advance_virtual_clock(runtime, now)
        _advance_countdowns(runtime, now)
        replies = []
        host = runtime["host_addr"]

        if runtime["heartbeat_timer_active"]:
            watchdog = runtime["heartbeat_watchdog_due"]
            if watchdog is not None and now >= watchdog:
                runtime["heartbeat_watchdog_due"] = now + 61
                runtime["heartbeat_period_due"] = now + _source_jitter(runtime, now) + 1
                runtime["heartbeat_period_ms"] = 1000
        period = runtime["heartbeat_period_due"]
        if period is not None and now >= period:
            if runtime["host_managed"] and isinstance(host, (tuple, list)) and host:
                reply = self._heartbeat_reply(device, state)
                replies.append((reply, (host[0], 5000)))
            if runtime["heartbeat_period_ms"] == 1000:
                runtime["heartbeat_miss_count"] += 1
                if runtime["heartbeat_miss_count"] > 2:
                    runtime["host_managed"] = 0
                    runtime["lock"] = 0
                    _heartbeat_ok(runtime, now)
            runtime["heartbeat_period_due"] = now + 60
            runtime["heartbeat_period_ms"] = 60000

        eligible = (not runtime["host_managed"]
                    and (runtime["ubind_gate_4ed"] != 0 or runtime["ubind_gate_4e5"] == 1))
        if not eligible:
            runtime["ubind_retry_count"] = 0
            _set_countdown_byte(runtime, 5, 0)
            _set_timer(runtime, "ubind_timer", 0)
        else:
            if runtime["ubind_flag"] & 0x80 or runtime["ubind_retry_count"] == 0:
                replies.append((self._ubind_reply(device, state),
                                ("255.255.255.255", 5000)))
                _set_countdown_byte(runtime, 5, 0x43)
                runtime["ubind_retry_count"] += 1
            if runtime["ubind_retry_count"] > 2:
                runtime["ubind_retry_count"] = -1
                _set_countdown_byte(runtime, 5, 0)
                _set_timer(runtime, "ubind_timer", 0x401e)
            if runtime["ubind_timer"] & 0x8000:
                _set_timer(runtime, "ubind_timer", 0)
                runtime["ubind_retry_count"] = 0

        replies.extend(self._report_tick(device, state, host, now))

        if runtime["source_state_7"] & 0x80:
            _set_countdown_byte(runtime, 7, 0x4f)
            if runtime["host_managed"] and isinstance(host, (tuple, list)) and host:
                login_info = {"t": "getLoginInfo", "loginInfo": ["GnetID"],
                              "curGnetID": runtime["controller_id_available"]}
                reply = self._lifecycle_reply(
                    device, state, login_info, 0, increment=True
                )
                replies.append((reply, (host[0], 5000)))
        return replies


HANDLER = CrtController()
PROFILES = (
    Profile(
        id="sim-wb05crt-v2.03-10001", mids=("10001",),
        hid="362001066012+U-WB05C(RT)V2.03.bin",
        source_sha256="f53d5f238b092a1bda4b95ee84d8f1dd5eadfb8ad15f65de1186005f255d0275",
        initial_state=_INITIAL_STATE, handler=HANDLER, max_request_bytes=1536,
    ),
)
