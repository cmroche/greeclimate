"""Exact-source local LAN models for Realtek WB AR assessments 0, 1, and 7.

Only the original UDP listener and its own callback table are modeled.  MCU
identity is an explicit virtual producer input; opaque local byte caches are not
interpreted as climate controls, and platform, radio, cloud, OTA, and reset
completion are not claimed.
"""

from copy import deepcopy
from datetime import datetime, timedelta
import json
import math
import re

from ..wire import InvalidPacket, Reply, _json, _validate_outer, decode_pack, encode_reply
from . import Profile


SOURCE_SHA256 = {
    0: "a36e365040799152a2d54dba9d670cf0f8f714511e265395a5a9b28f9bc5c8ea",
    1: "8057d9189659f99bd711ba71de5786a2b30c4f164b050cc9190a39ec66e37d2b",
    7: "e8ce6d7aea077c0b183e06526f3b1601e41306a8f3ce5aff4a16807b0e79fd20",
}
_HID = {
    0: "362001066428+U-WB06ARV1.03.bin",
    1: "362001066428+U-WB06ARV1.73.bin",
    7: "362001066481+U-WB05C1RV1.72.bin",
}
LAN_BIND_PORTS = {0: 7000, 1: 5001, 7: 5001}
_CHANNEL1_AR0 = b"a3K8Bx%2r8Y7#xDh"  # Exact source-0 literal.
_CHANNEL_FLAGS = {
    0: {"scan": 2, "bind": 1, "status": 0, "cmd": 0, "binCmd": 0,
        "upgrade": 0, "queryT": 0, "wlan": 2, "tm": 2},
    1: {"scan": 1, "hbok": 1, "UBindok": 0, "ret": 0, "binCmd": 0,
        "reset": 0, "Utm": 0, "loginInfoRes": 0, "statusCheck": 0},
    7: {"scan": 1, "hbok": 1, "UBindok": 0, "ret": 0, "binCmd": 0,
        "reset": 0, "Utm": 0, "loginInfoRes": 0, "statusCheck": 0},
}
_METADATA_FIELDS = ("host", "ver", "name", "hid", "rssi", "mid", "bc", "time")
_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
_INT32_MIN = -(1 << 31)
_INT32_MAX = (1 << 31) - 1
_UINT32_MAX = (1 << 32) - 1


def _text(value, maximum, *, empty=True):
    if (not isinstance(value, str) or (not empty and not value)
            or "\x00" in value or len(value.encode("utf-8")) > maximum):
        raise InvalidPacket("invalid bounded source text")
    return value


def _cjson_int(value):
    """This source helper reads cJSON valueint (arrays contribute child count)."""
    if isinstance(value, list):
        number = len(value)
    elif type(value) is bool:
        number = int(value)
    elif type(value) is int:
        number = value
    elif type(value) is float and math.isfinite(value):
        number = math.trunc(value)
    else:
        raise InvalidPacket("source numeric field requires a cJSON valueint-compatible value")
    return min(_INT32_MAX, max(_INT32_MIN, number))


def _outer_valueint(value):
    """Match the original outer cJSON valueint reads without inner-array policy."""
    if type(value) is bool:
        number = int(value)
    elif type(value) is int:
        number = value
    elif type(value) is float and math.isfinite(value):
        number = math.trunc(value)
    else:
        number = 0
    return min(_INT32_MAX, max(_INT32_MIN, number))


def _uint(value, maximum, name):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"AR {name} must be an integer in 0..{maximum}")
    return value


def _parse_time(value):
    value = _text(value, 31, empty=False)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", value):
        raise InvalidPacket("AR time must use YYYY-MM-DD HH:MM:SS")
    try:
        return datetime.strptime(value, _TIME_FORMAT)
    except ValueError as exc:
        raise InvalidPacket("AR time is outside the safe calendar range") from exc


def _format_time(value):
    return value.strftime(_TIME_FORMAT)


def _raw_bytes(value, maximum=127):
    if isinstance(value, str):
        try:
            result = value.encode("utf-8")
        except UnicodeError as exc:
            raise InvalidPacket("invalid raw source bytes") from exc
    elif isinstance(value, list):
        if len(value) > maximum:
            raise InvalidPacket("raw source array exceeds its bounded scratch space")
        result = bytes(_byte(item) for item in value)
    else:
        raise InvalidPacket("raw source field must be text or a byte array")
    if len(result) > maximum:
        raise InvalidPacket("raw source field exceeds its bounded scratch space")
    return result


def _byte(value):
    value = _cjson_int(value)
    if not 0 <= value <= 255:
        raise InvalidPacket("source byte must be in 0..255")
    return value


def _json_value(value):
    """Match the source metadata string-or-raw-container serializer safely."""
    if value.startswith(("{", "[")):
        try:
            parsed = json.loads(value)
        except (ValueError, RecursionError) as exc:
            raise InvalidPacket("source raw metadata container is invalid JSON") from exc
        if not isinstance(parsed, (dict, list)):
            raise InvalidPacket("source raw metadata must be an object or array")
        return parsed
    return value


def _metadata_defaults(index, udp_key1):
    result = {
        "host": "synthetic.invalid",
        "name": "Synthetic module",
        "time": "2026-01-01 00:00:00",
        "ver": "V3.5.M",
        "bc": "gree",
        "rssi": -55,
        "tdev_brand": "gree",
        "tdev_catalog": "gree",
        "tdev_model": "gree",
        "tdev_series": "gree",
        "lock": 0,
        "lock_word": 0,
        "scene_enable": 0,
        "gnet_ready": 0,
        "no_host_managed": 0,
        "host_mac": "",
        "group_id": 0,
        "gnet_id": 0,
        "gnet_config": 0,
        "gnet_restart_marker": 0,
        "report_transport_ready": 0,
        "report_mode": 0,
        "report_active": 0,
        "report_interval": 0,
        "active_time": 0,
        "active_timer": 0,
        "report_timer": 0,
        "report_state": 0,
        "report_selector": 0,
        "raw_global_6a": b"",
        "raw_report_records": [{"mask": 0, "frame_hex": ""} for _ in range(8)],
        "local_uid": 0,
        "local_msg_id": 0,
        "saved_gnet_config": 0,
    }
    if index in (1, 7):
        # Explicit configured virtual 16-byte cache, not a firmware default.
        result["udp_key1"] = udp_key1
    return result


def _valid_state(index, state):
    allowed = set(_metadata_defaults(index, state.get("udp_key1"))) | {
        "wlan_config", "_wb_ar_runtime",
    }
    for name, value in state.items():
        if name not in allowed:
            raise ValueError(f"unsupported exact AR source state field: {name}")
        if name == "udp_key1":
            if type(value) is not bytes or len(value) != 16:
                raise ValueError("AR channel-1 key must be an explicit 16-byte virtual input")
        elif name in ("host", "name", "time", "ver", "bc", "host_mac"):
            maximum = 31 if name == "time" else (16 if name == "host_mac" else 255)
            if not isinstance(value, str) or "\x00" in value or len(value.encode("utf-8")) > maximum:
                raise ValueError(f"invalid AR {name} readout")
            if name == "time":
                _parse_time(value)
        elif name in ("tdev_brand", "tdev_catalog", "tdev_model", "tdev_series"):
            if not isinstance(value, str) or "\x00" in value or len(value.encode("utf-8")) > 255:
                raise ValueError(f"invalid AR {name} readout")
        elif name == "rssi":
            if type(value) is not int or not -128 <= value <= 127:
                raise ValueError("AR RSSI must be a signed byte")
        elif name == "report_state":
            if type(value) is not int or not -128 <= value <= 127:
                raise ValueError("AR report-state cache must be a signed byte")
        elif name == "lock_word":
            if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
                raise ValueError("AR UBind lock readout must be a signed int32")
        elif name in ("lock", "scene_enable", "group_id", "gnet_id",
                      "report_transport_ready", "report_mode", "report_active",
                      "report_interval", "active_time", "active_timer", "report_timer",
                      "report_selector", "local_uid", "local_msg_id",
                      "gnet_config", "gnet_restart_marker", "saved_gnet_config",
                      "gnet_ready", "no_host_managed"):
            maximum = 0xffff if name in ("active_timer", "report_timer", "group_id") else _UINT32_MAX
            if type(value) is not int or not 0 <= value <= maximum:
                raise ValueError(f"AR {name} is outside its source storage width")
            if name in ("report_transport_ready", "report_active", "report_selector",
                        "gnet_config", "gnet_restart_marker", "saved_gnet_config",
                        "gnet_ready", "no_host_managed") and value not in (0, 1):
                raise ValueError(f"AR {name} must be a source byte value 0 or 1")
            if name == "report_mode" and value > 3:
                raise ValueError("AR report mode must be 0..3")
        elif name == "raw_global_6a":
            if type(value) is not bytes or len(value) > 127:
                raise ValueError("AR raw 0x6a cache must fit its 0x80-byte source area")
        elif name == "raw_report_records":
            if not isinstance(value, list) or len(value) != 8:
                raise ValueError("AR raw report cache requires eight ordered records")
            for record in value:
                if (not isinstance(record, dict) or set(record) != {"mask", "frame_hex"}
                        or type(record["mask"]) is not int or not 0 <= record["mask"] <= 0xffff
                        or not isinstance(record["frame_hex"], str)
                        or len(record["frame_hex"]) > 516):
                    raise ValueError("invalid bounded AR raw report record")
                try:
                    bytes.fromhex(record["frame_hex"])
                except ValueError as exc:
                    raise ValueError("AR raw report frame must be hexadecimal") from exc
        elif name == "wlan_config":
            if not isinstance(value, dict) or set(value) != {"ssid", "psw", "host", "mode"}:
                raise ValueError("invalid AR virtual WLAN cache")
            for key, maximum in (("ssid", 32), ("psw", 64), ("host", 32)):
                _text(value[key], maximum)
            if value["mode"] != 3:
                raise ValueError("AR source WLAN mode is 3")
        elif name == "_wb_ar_runtime":
            if not isinstance(value, dict):
                raise ValueError("invalid private AR callback state")

    if index in (1, 7) and "udp_key1" not in state:
        raise ValueError("AR1/7 require an explicit virtual channel-1 key input")

def _runtime(state):
    runtime = state.get("_wb_ar_runtime")
    if runtime is None:
        runtime = {
            "callback_count": 0,
            "message_id": state["local_msg_id"],
            "heartbeat_timer_created": False,
            "response_timer_running": False,
            "response_timer_period_ms": 0,
            "heartbeat_running": False,
            "heartbeat_period_ms": 0,
            "heartbeat_remaining_ms": None,
            "heartbeat_failure": 0,
            "response_timeout_ms": None,
            "queued_report": None,
            "report_pending": False,
            "control_refresh_pending": False,
            "control_opcode": None,
            "reset_requested": False,
            "ota_url": None,
            "ota_pending": False,
            "host_mac": state["host_mac"],
            "login_restart_requested": False,
            "login_saved_gnet_id": state["gnet_id"],
            "task_requests": [],
            "outbound_requests": [],
            "global_frames": {0x91: bytes(0x37), 0x92: bytes(0x37), 0x93: bytes(0x37)},
            "scene_rows": [
                {"scene_id": 0, "hex91": bytes(0x37), "hex92": bytes(0x37),
                 "hex93": bytes(0x37)}
                for _ in range(20)
            ],
            "bin_cache": {},
            "bin_cmd_flags": 0,
            "product_fragments": [],
            "report_completion": 0,
            "city_bytes": b"",
            "data_curve_value": None,
            "response_marker": 0,
            "login_marker": 0,
            "clock_tick": None,
            "timer_tick": None,
        }
        state["_wb_ar_runtime"] = runtime
    return runtime

def _key(device, state, channel):
    if channel == 0:
        key = device.key
    elif device.profile.handler.source_index == 0:
        key = _CHANNEL1_AR0
    else:
        key = state.get("udp_key1")
    if (type(key) is not bytes or len(key) != 16
            or any(byte < 0x21 or byte > 0x7e for byte in key)):
        raise InvalidPacket("required exact-source printable 16-byte AES key is unavailable")
    return key


def _reply(device, state, inner, channel, request):
    source = device.profile.handler.source_index
    if channel == 2:
        return Reply({"t": "pack", "i": 2, "uid": state["local_uid"],
                      "cid": device.mac, "pack": inner, "tcid": "app"})
    if source == 0:
        outer = {"t": "pack", "i": channel, "uid": state["local_uid"],
                 "cid": device.mac, "pack": "", "tcid": "asvr"}
        key = _key(device, state, channel)
        destination_port = None
    else:
        request_outer = state["_wb_ar_runtime"].get("request_outer", {})
        outer = {"t": "pack", "i": channel, "uid": request_outer.get("uid", 0),
                 "cid": device.mac, "tcid": request_outer.get("cid", ""), "pack": ""}
        key = _key(device, state, channel)
        destination_port = 5000
    return Reply(outer, inner, key, "aes-ecb-pkcs7-lf", destination_port=destination_port)


def _increment(runtime):
    runtime["callback_count"] = (runtime["callback_count"] + 1) & _UINT32_MAX


def _time_update(state, runtime, value):
    clock = _parse_time(value)
    state["time"] = _format_time(clock)
    runtime["clock_tick"] = None
    runtime["control_opcode"] = 0x82
    runtime["control_refresh_pending"] = True
    runtime["task_requests"].append(0x82)
    del runtime["task_requests"][:-16]




def _hbok(state, runtime):
    _increment(runtime)
    runtime["heartbeat_failure"] = 0
    if not runtime["heartbeat_timer_created"]:
        runtime["heartbeat_timer_created"] = True
        runtime["response_timer_period_ms"] = 61000
        runtime["response_timeout_ms"] = None
        runtime["response_timeout_bounds_ms"] = (0, 2700)
    runtime["response_timer_running"] = state["gnet_ready"] == 1
    return []


def _outbound_request(device, state, runtime, inner):
    msg_id = runtime["message_id"]
    runtime["message_id"] = (msg_id + 1) & _UINT32_MAX
    outer = {"t": "pack", "i": 0, "uid": state["local_uid"], "cid": device.mac,
             "tcid": runtime["host_mac"], "msgId": msg_id, "pack": ""}
    packet = encode_reply(Reply(outer, inner, _key(device, state, 0),
                                "aes-ecb-pkcs7-lf", destination_port=5000))
    runtime["outbound_requests"].append({
        "msgId": msg_id, "inner": deepcopy(inner), "packet": packet,
        "destination_port": 5000,
    })
    del runtime["outbound_requests"][:-16]


def _report_body(state, runtime):
    if state["gnet_ready"] != 1:
        return None
    if not state["no_host_managed"]:
        mode = state["report_mode"]
        active = state["report_active"]
        if mode == 3:
            state["report_mode"] = 0
            return None
        if mode == 1 and not active:
            state["active_timer"] = (0x4000 + 60 * state["active_time"]) & 0xffff
            state["report_active"] = 1
        elif mode == 2 and not active:
            if state["report_timer"] != 0:
                return None
            state["report_timer"] = (0x4000 + 60 * state["report_interval"]) & 0xffff
    special = (state["report_selector"] == 1 and len(state["raw_global_6a"]) > 3
               and state["raw_global_6a"][3] == 0x6a)
    selection = 0xbce if special else 0x3ce
    output = bytearray()
    for record in state["raw_report_records"]:
        frame = bytes.fromhex(record["frame_hex"])
        if (len(frame) < 3 or frame[:2] != b"~~" or frame[2] == 0
                or record["mask"] & selection == 0 or len(output) >= 512):
            continue
        size = frame[2] + 3
        if size > len(frame) or len(output) + size > 512:
            raise InvalidPacket("AR raw report would exceed its source cache or 512-byte frame")
        output.extend(frame[:size])
    if special:
        runtime["report_completion"] = 0x4b
        if state["report_timer"]:
            state["report_timer"] = 0x4005
    elif state["report_timer"] and state["report_state"] >= 0:
        runtime["report_completion"] = 1
    if state["no_host_managed"] or state["report_transport_ready"] == 1:
        body = bytes(output)
        runtime["queued_report"] = {"body": body, "kind": 7 if state.get("_report_kind7") else 6}
        runtime["report_pending"] = True
        return body
    return None


def _status0(device, state, request, channel, mid):
    columns = request.get("cols")
    if not isinstance(columns, list) or len(columns) > 255:
        raise InvalidPacket("AR0 status cols must fit its uint8 source count")
    names = [_text(name, 255, empty=False) for name in columns]
    if sum(len(name.encode("utf-8")) + 1 for name in names) > 512:
        raise InvalidPacket("AR0 status cols exceed its bounded selector storage")
    values = {
        "host": _json_value(state["host"]),
        "ver": _json_value(state["ver"]),
        "name": _json_value(state["name"]),
        "hid": _HID[0],
        "rssi": state["rssi"],
        "mid": mid,
        "bc": _json_value(state["bc"]),
        "time": _json_value(state["time"]),
    }
    response = {"t": "dat", "r": 200, "mac": device.mac,
                "cols": names, "dat": [values[name] for name in names if name in _METADATA_FIELDS]}
    return [_reply(device, state, response, channel, request)]


def _atoi(value):
    value = _text(value, 255)
    match = re.match(r"^[\t\n\v\f\r ]*([+-]?\d+)", value)
    if not match:
        return 0
    result = int(match.group(1), 10)
    if not _INT32_MIN <= result <= _INT32_MAX:
        raise InvalidPacket("AR0 atoi input exceeds the safe signed-int range")
    return result


def _command0(device, state, runtime, request, channel):
    options, params = request.get("opt"), request.get("p")
    if (not isinstance(options, list) or not isinstance(params, list)
            or len(options) != len(params) or len(options) > 255):
        raise InvalidPacket("AR0 cmd requires bounded parallel opt and p arrays")
    options = [_text(name, 255, empty=False) for name in options]
    if any(not isinstance(value, str) for value in params):
        raise InvalidPacket("AR0 cmd p values must follow the native textual helper path")
    parsed = []
    for name, value in zip(options, params):
        if name == "time":
            parsed.append((name, _text(value, 31, empty=False)))
            _parse_time(value)
        elif name == "ReportClientID":
            parsed.append((name, _text(value, 255)))
        else:
            parsed.append((name, _atoi(value)))
    response = {"t": "res", "r": 200, "mac": device.mac, "opt": options,
                "p": [value for _, value in parsed]}
    response["val"] = list(response["p"])
    reply = _reply(device, state, response, channel, request)
    for name, value in parsed:
        if name == "time":
            _time_update(state, runtime, value)
        elif name == "ReportClientID":
            runtime["report_client_id"] = value
            runtime["report_client_pending"] = True
    return [reply]


def _raw_cache(runtime, name, data):
    runtime["bin_cache"][name] = data
    return data


def _store_product_fragment(records, cmd_type, offset, mask, value, initval):
    key = (cmd_type, offset, mask)
    record = {"cmd_type": cmd_type, "byte": offset, "mask": mask,
              "value": value, "initval": initval}
    for index, current in enumerate(records):
        if (current["cmd_type"], current["byte"], current["mask"]) == key:
            records[index] = record
            return
    if len(records) >= 5:
        # Native callers ignore the full-table helper's -1 and continue.
        return
    records.append(record)


def _fragment_update(runtime, records, source_index):
    if not isinstance(records, list) or len(records) > 32:
        raise InvalidPacket("AR fragment count exceeds its bounded source parser")
    frames = dict(runtime["global_frames"])
    product_fragments = list(runtime["product_fragments"])
    flags = runtime["bin_cmd_flags"]
    for record in records:
        if not isinstance(record, dict):
            raise InvalidPacket("AR fragment entry must be an object")
        required = {"cmd_type", "byte", "mask", "value"}
        if not required <= set(record):
            raise InvalidPacket("AR fragment is missing a source byte-update field")
        cmd_type = _byte(record["cmd_type"])
        offset = _byte(record["byte"])
        mask = _byte(record["mask"])
        value = _cjson_int(record["value"])
        if cmd_type not in frames or offset >= 0x34:
            raise InvalidPacket("AR fragment selector or byte offset is outside source storage")
        shift = (mask & -mask).bit_length() - 1 if mask else 16
        buffer = bytearray(frames[cmd_type])
        buffer[offset + 3] = (buffer[offset + 3] & ~mask) | ((value << shift) & mask)
        frames[cmd_type] = bytes(buffer)
        if source_index == 0:
            flags |= {0x91: 0x20, 0x92: 0x40, 0x93: 0x80}[cmd_type]
        if "initval" in record:
            _store_product_fragment(product_fragments, cmd_type, offset, mask, value,
                                    _cjson_int(record["initval"]))
    runtime["global_frames"] = frames
    runtime["product_fragments"] = product_fragments
    runtime["bin_cmd_flags"] = flags


def _bin_cmd0(device, state, runtime, request, channel):
    runtime["bin_cmd_flags"] = 0
    parsed = {}
    for name in ("hex91", "hex92", "hex93", "hex6A", "hex6B", "hex6C"):
        if name in request:
            parsed[name] = _raw_bytes(request[name])
    if "hex91" in parsed and len(parsed["hex91"]) < 4:
        raise InvalidPacket("AR0 hex91 must contain its source opcode byte")
    records = request.get("fragment")
    if records is not None and not isinstance(records, list):
        raise InvalidPacket("AR0 fragment must be an array")
    if "hex6B" in parsed:
        try:
            parsed["time"] = parsed["hex6B"].decode("ascii")
        except UnicodeError as exc:
            raise InvalidPacket("AR0 hex6B time must be ASCII") from exc
        _parse_time(parsed["time"])
    for name, data in parsed.items():
        _raw_cache(runtime, name, data)
    if "hex6A" in parsed:
        state["raw_global_6a"] = parsed["hex6A"]
    if "hex6B" in parsed:
        _time_update(state, runtime, parsed["time"])
    if "hex6C" in parsed:
        # The source helper transforms the input before applying its 60-byte condition.
        runtime["hex6c_input"] = parsed["hex6C"]
    if records is not None:
        runtime["product_fragments"] = []
        _fragment_update(runtime, records, 0)
    if "hex91" in parsed and len(parsed["hex91"]) > 3 and parsed["hex91"][3] == 0x91:
        runtime["bin_cmd_flags"] |= 0x20
    if "hex92" in parsed:
        runtime["bin_cmd_flags"] |= 0x40
    if "hex93" in parsed:
        runtime["bin_cmd_flags"] |= 0x80
    if runtime["bin_cmd_flags"] & 0x20:
        runtime["fragment_marker"] = 0x4005
        runtime["fragment_tag"] = 0x42
        runtime["control_opcode"] = 0x91
        runtime["control_refresh_pending"] = True
    if runtime["bin_cmd_flags"] & 0x40:
        runtime["control_opcode"] = 0x92
        runtime["control_refresh_pending"] = True
    if runtime["bin_cmd_flags"] & 0x80:
        runtime["control_opcode"] = 0x93
        runtime["control_refresh_pending"] = True
    response = {"t": "res", "r": 200, "mac": device.mac}
    return [_reply(device, state, response, channel, request)]




def _add_scene_payload(row, request):
    for name in ("hex91", "hex92", "hex93"):
        if name in request:
            data = _raw_bytes(request[name])
            if len(data) != 0x37:
                raise InvalidPacket("AR1/7 scene frame must contain exactly 0x37 bytes")
            row[name] = data


def _scene_response(device, state, request, channel, *, code=False):
    response = {"t": "res", "r": 200}
    if code:
        response["code"] = 501
    response["mac"] = device.mac
    return _reply(device, state, response, channel, request)


def _scene_bin_cmd(device, state, runtime, request, channel):
    operation = _cjson_int(request.get("operType", 0)) & 0xff
    scene_id = _cjson_int(request.get("sceneId", 0))
    enabled = _cjson_int(request.get("sence_enable", 0)) & 0xff
    if not 0 <= scene_id <= _UINT32_MAX:
        raise InvalidPacket("AR sceneId is outside its source uint32 field")
    rows = deepcopy(runtime["scene_rows"])
    matches = [row for row in rows if row["scene_id"] == scene_id and scene_id != 0]
    empty = [row for row in rows if row["scene_id"] == 0]
    targets = []
    code = False
    if operation == 0:
        if matches:
            _add_scene_payload(matches[0], request)
            targets.append(matches[0])
    elif operation == 1 and scene_id == 1:
        if not matches and len(empty) >= 2:
            empty[0]["scene_id"] = 1
            empty[1]["scene_id"] = 2
            _add_scene_payload(empty[0], request)
            _add_scene_payload(empty[1], request)
            targets.extend((empty[0], empty[1]))
    elif operation == 1 and enabled == 1:
        row = matches[0] if matches else (empty[0] if empty else None)
        if row is None:
            code = True
        else:
            if not matches:
                row["scene_id"] = scene_id
            _add_scene_payload(row, request)
            targets.append(row)
    elif operation == 2:
        for row in matches:
            row.update(scene_id=0, hex91=bytes(0x37), hex92=bytes(0x37), hex93=bytes(0x37))
    fragment = request.get("fragment")
    if fragment is not None:
        if not isinstance(fragment, list) or len(fragment) > 32:
            raise InvalidPacket("AR scene fragment count exceeds its bounded source parser")
        product_fragments = list(runtime["product_fragments"])
        for row in targets:
            for item in fragment:
                values = list(item.values()) if isinstance(item, dict) else item
                if not isinstance(values, list) or len(values) not in (4, 5):
                    raise InvalidPacket("AR scene fragment requires four ordered fields and optional initval")
                cmd_type, offset, mask = (_byte(values[0]), _byte(values[1]), _byte(values[2]))
                value = _cjson_int(values[3])
                if cmd_type not in (0x91, 0x92, 0x93) or offset >= 0x34:
                    raise InvalidPacket("AR scene fragment selector or byte offset is out of range")
                current = bytearray(row[f"hex{cmd_type:02X}"])
                shift = (mask & -mask).bit_length() - 1 if mask else 16
                current[offset + 3] = (current[offset + 3] & ~mask) | ((value << shift) & mask)
                row[f"hex{cmd_type:02X}"] = bytes(current)
                if len(values) == 5 and row["scene_id"] == 2:
                    _store_product_fragment(
                        product_fragments, cmd_type, offset, mask, value,
                        _cjson_int(values[4]))
        runtime["product_fragments"] = product_fragments
    runtime["scene_rows"] = rows
    return [_scene_response(device, state, request, channel, code=code)]


def _bin_cmd_c1r(device, state, runtime, request, channel):
    runtime["bin_cmd_flags"] = 0
    raw_fields = {}
    for name in ("hex91", "hex92", "hex93", "hex6A", "hex6B", "hex6C", "hex6D", "hex6E"):
        if name in request:
            raw_fields[name] = _raw_bytes(request[name])
    if "hex91" in raw_fields and len(raw_fields["hex91"]) < 4:
        raise InvalidPacket("AR1/7 hex91 must contain its source opcode byte")
    if "hex6E" in raw_fields and len(raw_fields["hex6E"]) < 7:
        raise InvalidPacket("AR1/7 hex6E must contain all source selector bytes")
    if "hex6D" in raw_fields and len(raw_fields["hex6D"]) > 0x36:
        raise InvalidPacket("AR1/7 city text exceeds its 0x37-byte source buffer")
    if "hex6B" in raw_fields:
        try:
            clock_text = raw_fields["hex6B"].decode("ascii")
        except UnicodeError as exc:
            raise InvalidPacket("AR1/7 hex6B time must be ASCII") from exc
        _parse_time(clock_text)
    fragments = request.get("fragment")
    if fragments is not None and not isinstance(fragments, list):
        raise InvalidPacket("AR1/7 fragment must be an array")
    if "roomId" in request:
        new_group_id = _cjson_int(request["roomId"]) & 0xff
        if state["group_id"] != new_group_id:
            runtime["group_save_requested"] = True
            state["group_id"] = new_group_id
    runtime["bin_cache"].update(raw_fields)
    if "hex6A" in raw_fields:
        state["raw_global_6a"] = raw_fields["hex6A"]
    if "hex6B" in raw_fields:
        _time_update(state, runtime, clock_text)
    if "hex6D" in raw_fields:
        runtime["city_bytes"] = raw_fields["hex6D"]
        runtime["city_set_pending"] = True
    if "hex6E" in raw_fields:
        frame = raw_fields["hex6E"]
        if frame[:2] == b"~~" and frame[3] == 0x6e:
            if frame[4:6] == b"\x01\x01" and frame[6] != 0:
                runtime["data_curve_value"] = 0x4000 + frame[6]
    if "hex6C" in raw_fields:
        # The source helper transforms the input before applying its 60-byte condition.
        runtime["hex6c_input"] = raw_fields["hex6C"]
    scene_replies = None
    if "sceneId" in request:
        scene_replies = _scene_bin_cmd(device, state, runtime, request, channel)
    if fragments and state["ver"] == "V3.4.M":
        _fragment_update(runtime, fragments, device.profile.handler.source_index)
    if "hex91" in raw_fields and raw_fields["hex91"][3] == 0x91:
        runtime["bin_cmd_flags"] |= 0x20
    if "hex92" in raw_fields:
        runtime["bin_cmd_flags"] |= 0x40
    if "hex93" in raw_fields:
        runtime["bin_cmd_flags"] |= 0x80
    if scene_replies is not None:
        return scene_replies
    return [_scene_response(device, state, request, channel)]


def _mid(handler):
    return f"{handler.mcu_mid_input:x}"


class ARHandler:
    def __init__(self, source_index, mcu_mid_input):
        self.source_index = source_index
        self.mcu_mid_input = mcu_mid_input
        if source_index in (1, 7):
            self.source_port = 5001

    def _normalize_outer(self, outer):
        if not isinstance(outer, dict):
            raise InvalidPacket("AR outer envelope must be an object")
        kind = outer.get("t")
        maximum = 1024 if self.source_index == 0 else 1536
        if kind == "scan":
            target = outer.get("tcid", "")
            if not isinstance(target, str):
                target = ""
            return {"t": "scan", "tcid": _text(target, maximum)}
        if kind != "pack":
            raise InvalidPacket("AR UDP accepts only its source pack envelope")
        if self.source_index == 0 and "i" not in outer:
            raise InvalidPacket("AR0 source channel is not established without its outer i field")
        channel = _outer_valueint(outer.get("i", 0)) & 0xff
        uid = _outer_valueint(outer.get("uid", 0))
        cid = outer.get("cid", "")
        tcid = outer.get("tcid", "")
        if not isinstance(cid, str):
            cid = ""
        if not isinstance(tcid, str):
            tcid = ""
        pack = outer.get("pack")
        if isinstance(pack, str):
            pack = _text(pack, maximum)
        return {"t": "pack", "i": channel, "uid": uid,
                "cid": _text(cid, maximum), "tcid": _text(tcid, maximum),
                "pack": pack}

    def decode_outer(self, data):
        """Normalize exact cJSON outer valueint fields before shared validation."""
        maximum = 1024 if self.source_index == 0 else 1536
        if type(data) is not bytes or len(data) > maximum:
            raise InvalidPacket("AR datagram exceeds its original receive buffer")
        return _validate_outer(self._normalize_outer(_json(data)))

    def validate_state(self, state):
        _valid_state(self.source_index, state)

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        return None

    def advertise(self, device, outer):
        # The outer broadcast t=scan route is not this firmware's registered pack callback.
        return []

    def _scan(self, device, state, runtime, request, channel):
        if self.source_index == 0:
            response = {
                "t": "dev", "mac": device.mac, "mid": _mid(self),
                "name": state["name"], "ver": state["ver"], "lock": state["lock"],
                "bc": state["bc"], "brand": state["tdev_brand"],
                "catalog": state["tdev_catalog"], "model": state["tdev_model"],
                "series": state["tdev_series"], "vender": "gree",
            }
            return [_reply(device, state, response, channel, request)]
        if state["gnet_ready"] and _cjson_int(request.get("allRange", 0)) != 1:
            return []
        try:
            device_key = _key(device, state, 0).decode("ascii")
        except UnicodeError as exc:
            raise InvalidPacket("AR1/7 devkey readout must be its source text bytes") from exc
        response = {"t": "UBind"}
        if self.source_index == 1:
            response["scene"] = int(state["scene_enable"] == 0)
        # AR7's mode-100 scene writer appends to the parser's decrypted input
        # buffer, not this output object; the outer frame allocation has room.
        response.update({
            "mid": _mid(self), "ver": state["ver"], "lock": state["lock_word"],
            "devkey": device_key, "hid": _HID[self.source_index],
        })
        return [_reply(device, state, response, channel, request)]

    def _wlan(self, device, state, request, channel):
        values = {
            "ssid": _text(request.get("ssid", ""), 32),
            "psw": _text(request.get("psw", ""), 64),
            "host": _text(request.get("host", ""), 32),
        }
        state["wlan_config"] = {**values, "mode": 3}
        return [_reply(device, state, {"t": "ret", "r": 200, "mac": device.mac}, channel, request)]

    def _upgrade(self, device, state, runtime, request, channel):
        mac = _text(request.get("mac", ""), 12)
        url = _text(request.get("url", ""), 255, empty=False)
        if not device.mac.startswith(mac):
            return []
        runtime["ota_url"] = url
        runtime["ota_pending"] = True
        return [_reply(device, state, {"t": "ret", "r": 200, "mac": device.mac}, channel, request)]

    def _reset(self, device, state, runtime, request, channel):
        mac = _text(request.get("mac", ""), 12)
        if not device.mac.startswith(mac):
            return []
        runtime["reset_requested"] = True
        return [_reply(device, state, {"t": "res", "r": 200, "mac": device.mac}, channel, request)]

    def _ubindok(self, device, state, runtime, request, channel):
        host = _text(request.get("mac", ""), 16)
        room_id = (_cjson_int(request["roomId"]) & 0xff) if "roomId" in request else state["group_id"]
        host_managed = (_cjson_int(request["hostManaged"]) & 0xff) if (
            self.source_index == 1 and "hostManaged" in request) else None
        if host:
            state["host_mac"] = host
            runtime["host_mac"] = host
        if room_id != state["group_id"]:
            runtime["group_save_requested"] = True
            state["group_id"] = room_id
        if self.source_index == 1 and host_managed == 0:
            state["ver"] = "V3.5.M"
            state["no_host_managed"] = 1
            runtime["report_json_status_pending"] = True
            return []
        state["no_host_managed"] = 0
        state["gnet_ready"] = 1
        state["lock_word"] = 1
        runtime["device_time_request_pending"] = True
        runtime["login_request_pending"] = True
        runtime["timer_id_byte"] = 0x4f
        runtime["heartbeat_running"] = True
        runtime["heartbeat_period_ms"] = 60000
        runtime["heartbeat_remaining_ms"] = 60000
        _hbok(state, runtime)
        _increment(runtime)
        _outbound_request(device, state, runtime, {"t": "Utm"})
        _outbound_request(device, state, runtime,
                          {"t": "getLoginInfo", "loginInfo": ["GnetID"],
                           "curGnetID": state["gnet_id"]})
        _report_body(state, runtime)
        return []

    def _login_info(self, state, runtime, request):
        if "r" not in request:
            runtime["login_marker"] = 0
            return []
        result = _cjson_int(request["r"])
        if result in (200, 406):
            info = request.get("loginInfo")
            if not isinstance(info, dict) or "GnetID" not in info:
                raise InvalidPacket("AR loginInfoRes requires its bounded nested GnetID readout")
            gnet_id = _cjson_int(info["GnetID"]) & 0xff
            previous = state["gnet_id"]
            state["gnet_id"] = gnet_id
            runtime["login_saved_gnet_id"] = gnet_id
            runtime["login_marker"] = 0
            if (state["gnet_config"] == 1 and state["gnet_restart_marker"] == 0
                    and gnet_id != 0):
                state["gnet_restart_marker"] = 1
                runtime["login_restart_requested"] = True
                runtime["restart_delay_ms"] = 1000
            if previous != gnet_id:
                runtime["gnet_id_persist_requested"] = True
        elif result == 500:
            runtime["login_marker"] = 0
            if state["gnet_config"] == 1 and state["gnet_restart_marker"] == 0:
                state["gnet_restart_marker"] = 1
                runtime["login_restart_requested"] = True
                runtime["restart_delay_ms"] = 1000
        return []

    def _status_check(self, state, runtime):
        state["_report_kind7"] = 1
        try:
            _report_body(state, runtime)
        finally:
            state.pop("_report_kind7", None)
        return []

    def _dispatch(self, device, state, runtime, request, channel, outer):
        kind = request.get("t")
        if not isinstance(kind, str):
            raise InvalidPacket("missing AR request type")
        required_channel = _CHANNEL_FLAGS[self.source_index].get(kind)
        if required_channel is None:
            return []
        if required_channel != channel:
            raise InvalidPacket("AR operation arrived on a channel rejected by its source table")
        if kind == "scan":
            return self._scan(device, state, runtime, request, channel)
        if self.source_index == 0:
            if kind == "bind":
                key = _key(device, state, 0).decode("ascii")
                response = {"t": "bindok", "r": 200, "mac": device.mac, "key": key}
                return [_reply(device, state, response, channel, request)]
            if kind == "status":
                return _status0(device, state, request, channel, _mid(self))
            if kind == "cmd":
                return _command0(device, state, runtime, request, channel)
            if kind == "binCmd":
                return _bin_cmd0(device, state, runtime, request, channel)
            if kind == "upgrade":
                return self._upgrade(device, state, runtime, request, channel)
            if kind == "queryT":
                index = _cjson_int(request.get("index", 0)) & 0xff
                _cjson_int(request.get("count", 0))
                return [_reply(device, state, {"t": "listT", "total": 0, "index": index},
                               channel, request)]
            if kind == "wlan":
                return self._wlan(device, state, request, channel)
            if kind == "tm":
                _time_update(state, runtime, _text(request.get("time", ""), 31, empty=False))
                return []
        else:
            if kind == "UBindok":
                return self._ubindok(device, state, runtime, request, channel)
            if kind == "hbok":
                return _hbok(state, runtime)
            if kind == "ret":
                result = _cjson_int(request.get("r", 0)) & 0xff
                if result == 200:
                    runtime["response_marker"] = 0
                runtime["context_length"] = 0
                _increment(runtime)
                return []
            if kind == "reset":
                return self._reset(device, state, runtime, request, channel)
            if kind == "Utm":
                _time_update(state, runtime, _text(request.get("time", ""), 31, empty=False))
                _increment(runtime)
                return []
            if kind == "loginInfoRes":
                return self._login_info(state, runtime, request)
            if kind == "statusCheck":
                return self._status_check(state, runtime)
            if kind == "binCmd":
                return _bin_cmd_c1r(device, state, runtime, request, channel)
        return []

    def handle(self, device, outer):
        outer = _validate_outer(self._normalize_outer(outer))
        if outer["t"] != "pack":
            raise InvalidPacket("AR request requires its original pack envelope")
        channel = outer["i"]
        if channel not in (0, 1, 2):
            return []
        if channel == 2:
            if self.source_index != 0:
                return []
            if not isinstance(outer.get("pack"), dict):
                raise InvalidPacket("AR0 channel 2 requires its plaintext object pack")
            request = outer["pack"]
        else:
            request = decode_pack(outer, _key(device, device.state, channel), "aes-ecb-pkcs7")
        kind = request.get("t")
        if not isinstance(kind, str):
            raise InvalidPacket("missing AR request type")
        required_channel = _CHANNEL_FLAGS[self.source_index].get(kind)
        if required_channel is None:
            return []
        if required_channel != channel:
            raise InvalidPacket("AR operation arrived on a channel rejected by its source table")
        state = deepcopy(device.state)
        runtime = _runtime(state)
        self.validate_state(state)
        runtime["request_outer"] = {key: outer.get(key) for key in ("cid", "tcid", "uid")}
        replies = self._dispatch(device, state, runtime, request, channel, outer)
        if state != device.state:
            device.state.clear()
            device.state.update(state)
        return replies

    def tick(self, device, now):
        state = device.state
        runtime = state.get("_wb_ar_runtime")
        if runtime is None:
            return []
        last_clock = runtime["clock_tick"]
        runtime["clock_tick"] = now
        if last_clock is not None and now > last_clock:
            seconds = int(now - last_clock)
            if seconds:
                clock = _parse_time(state["time"]) + timedelta(seconds=seconds)
                state["time"] = _format_time(clock)
        last_timer = runtime["timer_tick"]
        runtime["timer_tick"] = now
        if last_timer is None or now <= last_timer or not runtime["heartbeat_running"]:
            return []
        elapsed_ms = int((now - last_timer) * 1000)
        remaining = runtime["heartbeat_remaining_ms"]
        if elapsed_ms < remaining:
            runtime["heartbeat_remaining_ms"] = remaining - elapsed_ms
            return []
        overdue = elapsed_ms - remaining
        if runtime["heartbeat_period_ms"] == 1000:
            runtime["heartbeat_failure"] += 1
            if runtime["heartbeat_failure"] > 2:
                state["gnet_ready"] = 0
                state["lock_word"] = 0
                _hbok(state, runtime)
        runtime["heartbeat_period_ms"] = 60000
        runtime["heartbeat_remaining_ms"] = 60000 - overdue % 60000
        return []


def profile_for_mcu_input(index, mcu_mid_input, *, channel1_key=None, saved_gnet_config=0):
    """Build one source-disjoint model from its explicit uint32 SetMID input."""
    if type(index) is not int or index not in (0, 1, 7):
        raise ValueError("AR profile index must be one exact assessment index: 0, 1, or 7")
    if type(mcu_mid_input) is not int or not 1 <= mcu_mid_input <= _UINT32_MAX:
        raise ValueError("AR requires an explicit nonzero uint32 MCU SetMID input")
    if type(saved_gnet_config) is not int or saved_gnet_config not in (0, 1):
        raise ValueError("AR saved Gnet config must be an explicit source byte 0 or 1")
    if index == 0:
        if channel1_key is not None or saved_gnet_config:
            raise ValueError("AR0 has no configurable channel-1 key or saved-Gnet version branch")
        udp_key1 = None
    else:
        if (type(channel1_key) is not bytes or len(channel1_key) != 16
                or any(byte < 0x21 or byte > 0x7e for byte in channel1_key)):
            raise ValueError("AR1/7 require an explicit printable 16-byte channel-1 key readout")
        udp_key1 = channel1_key
    state = _metadata_defaults(index, udp_key1)
    state["saved_gnet_config"] = saved_gnet_config
    if index in (1, 7) and saved_gnet_config:
        state["ver"] = "V3.5.MF4"
    handler = ARHandler(index, mcu_mid_input)
    return Profile(
        id=f"sim-realtek-middle-ar{index}", mids=(f"{mcu_mid_input:x}",), hid=_HID[index],
        source_sha256=SOURCE_SHA256[index], initial_state=state, handler=handler,
        max_request_bytes=1024 if index == 0 else 1536,
    )


# Configured virtual inputs only; these channel-1 readouts are not firmware defaults.
PROFILES = (
    profile_for_mcu_input(0, 0x10001),
    profile_for_mcu_input(1, 0x10001, channel1_key=b"AR1-udp-key-0001"),
    profile_for_mcu_input(7, 0x10001, channel1_key=b"AR7-udp-key-0007"),
)
