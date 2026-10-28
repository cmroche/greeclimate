"""APJ Joylink UDP, configured UART44 product0x10001/protocol0/table5 only.

This is a pre-activated synthetic session, not ordinary Gree JSON UDP or a cloud
provisioner. The source-selected MID is configured, not emitted by discovery.
Source ACKs read the old report cache. A chosen synthetic mainboard applies each
command frame before the next script request; sensor calibration is unknown.
Strict JSON/padding, bounded values and atomic validation replace unsafe native
parser/padding paths. Native input CRC omission and pointer/MID bugs are retained.
"""

import binascii
from copy import deepcopy
import ipaddress
import json
import math
import re
import struct
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from ..wire import InvalidPacket, Reply, _json
from . import Profile


MAGIC = b"\xbb\x55\x34\x12"
MAX_BYTES = 1400
# Chosen persisted session's second16 ASCII bytes; key is each device's own key.
INITIAL_IV = b"fedcba9876543210"
FIELDS = ("Power", "Mode", "Wind", "TemperatureSet", "CurrentTemperature",
          "HorizontalDivision", "VerticalDivision", "Mute", "PtcHeat", "Powerful",
          "Sleep", "ScreenDisplay", "Dry")
INITIAL_STATE = dict.fromkeys(FIELDS, 0)
INITIAL_STATE.update(TemperatureSet=16, CurrentTemperature=-40)
_INT_PREFIX = re.compile(r"^[\t\n\v\f\r ]*([+-]?[0-9]+)")
_WIND = (1, 3, 5, 0, 0, 0, 2, 4)


def _number(value):
    if isinstance(value, str):
        if len(value.encode()) > 64 or "\0" in value:
            raise InvalidPacket("Joylink scalar string exceeds the safe bound")
        match = _INT_PREFIX.match(value)
        value = int(match[1]) if match else 0
    elif type(value) is float:
        if not math.isfinite(value):
            raise InvalidPacket("Joylink number must be finite")
        value = int(value)
    if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
        raise InvalidPacket("Joylink value must fit signed32")
    return value


def _write(frame, name, value):
    if name in ("Power", "Powerful", "ScreenDisplay"):
        index, mask = {"Power": (8, 0x80), "Powerful": (10, 1),
                       "ScreenDisplay": (10, 2)}[name]
        frame[index] = (frame[index] & ~mask) | (mask if value & 1 else 0)
    elif name == "Mode":
        frame[8] = (frame[8] & 0x8f) + {0: 0, 1: 0x10, 2: 0x40,
                                      3: 0x20, 4: 0x30, 5: 0x50}.get(value, 0)
    elif name == "Wind":
        speed = _WIND[value - 2] if 2 <= value <= 9 else 0
        advanced = (frame[11] >> 4 & 3) == 1
        mode = frame[8] & 0x70
        # ProductGetMid returns a string pointer, never a numeric product code.
        low = 1 if mode == 0x20 else min(speed, 3) if speed < 2 else 2 if speed < 4 else 3
        frame[8] = (frame[8] & 0xfc) + low
        if advanced and frame[8] < 128:
            frame[8] = (frame[8] & 0xfc) + (speed if speed < 2 else 2 if speed < 4 else 3)
        low = 1 if mode == 0x20 else speed
        if advanced and frame[8] < 128:
            low = speed
        frame[22] = (frame[22] & 0xf8) | low
    elif name == "TemperatureSet":
        frame[14] &= 0xf7
        if 16 <= value <= 30:
            frame[9] = (frame[9] & 15) + ((value - 16) << 4)
            frame[47] &= 15
        elif 8 <= value <= 15:
            frame[9] &= 15
            frame[47] = (frame[47] & 15) + ((value - 7) << 4)
        elif value in (31, 32):
            frame[9] = (frame[9] & 15) + 0xe0
            frame[47] = (frame[47] & 15) + (0x90 if value == 31 else 0xa0)
    elif name == "HorizontalDivision":
        raw = {0: 0, 2: 3, 3: 4, 4: 5, 5: 6, 6: 1}.get(value, 2)
        frame[12] = (frame[12] & 0xf0) + raw
    elif name == "VerticalDivision":
        raw = {0: 0, 1: 0x20, 2: 0x30, 3: 0x40, 4: 0x50, 6: 0x10}.get(value, 0x60)
        frame[12] = (frame[12] & 15) + raw
    elif name == "Mute":
        frame[20] = (frame[20] & 0xf3) + (8 if value == 1 else 0)
    elif name == "PtcHeat":
        raw = 8 if (frame[8] & 0x70) == 0x40 and not value & 1 else 0
        frame[10] = (frame[10] & 0xf7) + raw
    elif name == "Sleep":
        allowed = (frame[8] & 0x70) in (0x10, 0x20, 0x40, 0x50)
        frame[8] &= 0xf7
        frame[20] = (frame[20] & 0x6f) | (((value & 1) << 4) if allowed else 0)
    elif name == "Dry":
        mode = frame[8] & 0x70
        if mode != 0x40:
            frame[10] = (frame[10] & 0xf7) | ((value & 1) << 3 if mode in (0x10, 0x20) else 0)


def _read(frame):
    mode_raw = frame[8] & 0x70
    mode = {0: 0, 0x10: 1, 0x20: 3, 0x30: 4, 0x40: 2, 0x50: 5}.get(mode_raw, 0)
    low = {0: 0, 1: 1, 2: 3, 3: 5}[frame[8] & 3]
    extension = frame[22] & 7
    wind = 0 if extension and not low else {1: 2, 2: 8, 3: 3, 4: 9, 5: 4}.get(extension or low, 0)
    ext = frame[44] & 0xf0
    temperature = (frame[9] >> 4) + 16 if not ext else (ext >> 4) + 7 if ext <= 0x80 else 30
    horizontal = frame[12] & 15
    vertical = frame[12] >> 4
    sleep = mode_raw in (0x10, 0x20, 0x40, 0x50) and bool(frame[20] & 0x90 or frame[8] & 8)
    return dict(zip(FIELDS, (frame[8] >> 7, mode, wind, temperature, frame[46] - 40,
                            6 if horizontal == 1 else horizontal - 1 if 2 <= horizontal <= 6 else 0,
                            {1: 6, 2: 1, 3: 2, 4: 3, 5: 4, 6: 5}.get(vertical, 0),
                            int(bool(frame[20] & 12)),
                            int(not frame[10] & 8) if mode_raw == 0x40 else 0,
                            frame[10] & 1, int(sleep), frame[10] >> 1 & 1,
                            frame[10] >> 3 & 1 if mode_raw in (0x10, 0x20) else 0)))


def _state(device):
    candidate = deepcopy(device.state)
    if "_send" not in candidate:
        send = bytearray(b"\x7e\x7e\x60\x01" + b"\0" * 96)
        for name in FIELDS:
            _write(send, name, candidate[name])
        report = bytearray(send)
        report[3], report[44], report[46] = 0x31, send[47], candidate["CurrentTemperature"] + 40
        candidate.update(_send=send, _report=report, _slots=[])
    return candidate


def _streams(values):
    return [{"stream_id": name, "current_value": str(values[name])} for name in FIELDS]


def _frame(command, cipher, payload, key=None):
    if cipher == 3:
        payload = AES.new(key, AES.MODE_CBC, INITIAL_IV).encrypt(pad(payload, 16))
    header = bytearray(16)
    struct.pack_into("<IHH", header, 0, 0x123455bb, 0, len(payload))
    header[8], header[9], header[12] = 1, command, cipher
    struct.pack_into("<H", header, 14, binascii.crc_hqx(payload, 0xffff))
    result = bytes(header) + payload
    if len(result) > MAX_BYTES:
        raise InvalidPacket("Joylink reply exceeds native UDP capacity")
    return Reply({}, raw_payload=result)


def _peer_hash(address):
    try:
        host = str(ipaddress.IPv4Address(address[0]))
    except (ValueError, TypeError, IndexError) as exc:
        raise InvalidPacket("Joylink requires an IPv4 peer") from exc
    result, multiplier = 0, 0xf8c9
    for byte in host.encode():
        result = (multiplier * result + byte) & 0xffffffff
        multiplier = multiplier * 0x5c6b7 & 0xffffffff
    return result & 0x7fffffff


def _admit(slots, peer, timestamp, now):
    for slot in slots:
        if slot[0] == peer:
            if timestamp <= slot[1]:
                return False
            slot[1] = timestamp
            return True
    if len(slots) < 4:
        slots.append([peer, timestamp])
        return True
    cutoff = (now - 3600) & 0xffffffff
    for slot in slots:
        if slot[1] < cutoff:
            slot[:] = [peer, timestamp]
            return True
    return False


class Joylink:
    datagram_magic = MAGIC

    def validate_state(self, state):
        for name, value in state.items():
            if name not in FIELDS or type(value) is not int or not -(1 << 31) <= value < (1 << 31):
                raise ValueError("Joylink initial state requires its canonical signed32 fields")
            if name == "CurrentTemperature" and not -40 <= value <= 215:
                raise ValueError("Joylink synthetic sensor must fit its raw unsigned byte")

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        return None

    def advertise(self, device, outer):
        # Discovery belongs to the binary command1 path, never Gree JSON scan.
        return []

    def handle(self, device, outer):
        raise InvalidPacket("APJ ordinary Gree JSON is not a UDP carrier")

    def handle_datagram(self, device, raw):
        return self.handle_datagram_from(device, raw, ("127.0.0.1", 0))

    def handle_datagram_from(self, device, raw, address):
        if not isinstance(raw, bytes) or not 16 <= len(raw) <= MAX_BYTES or raw[:4] != MAGIC:
            raise InvalidPacket("invalid Joylink datagram size or magic")
        key_length, length = struct.unpack_from("<HH", raw, 4)
        command, cipher = raw[9], raw[12]
        if raw[8] != 1 or raw[10] > 1 or key_length + length + 16 != len(raw):
            raise InvalidPacket("invalid Joylink version, segment count, or lengths")
        if device.mid != "10001" or len(device.key) != 16:
            raise InvalidPacket("APJ requires configured product0x10001 and a16-byte session key")
        # Source emits a checksum but does not validate the incoming CRC.
        if command == 1 and cipher == 0 and key_length == 0:
            request = _json(raw[16:])
            d_idt = request.get("d_idt")
            if any(
                key in request and not isinstance(request[key], (str, int, dict))
                for key in ("uuid", "status", "d_idt")
            ):
                raise InvalidPacket("invalid Joylink scan fields")
            if isinstance(d_idt, dict) and d_idt.get("app_rand"):
                raise InvalidPacket("Joylink signed scan challenges require cloud activation")
            body = {
                "code": 0, "msg": "scan ok", "devkey": "", "mac": device.mac.upper(),
                "productuuid": "", "feedid": "synthetic-feed", "lancon": 1, "trantype": 1,
                "devtype": 0, "CID": "", "firmwareVersion": "",
                "modelCode": "CKVQUBBCKF5K8UK5Y9AIMC3QTVZP6KSD", "joySdkVersion": "2.1.23",
                "noSnapshot": 1, "batchBind": 0,
            }
            return [_frame(1, 0, json.dumps(body, separators=(",", ":")).encode())]
        if command not in (3, 4) or cipher != 3 or key_length != 0:
            raise InvalidPacket("Joylink provisioning requires external cloud-signed manufacturer data")
        if not length or length % 16:
            raise InvalidPacket("invalid Joylink AES block length")
        try:
            payload = unpad(AES.new(device.key, AES.MODE_CBC, INITIAL_IV).decrypt(raw[16:]), 16)
        except ValueError as exc:
            raise InvalidPacket("invalid Joylink key or padding") from exc
        if len(payload) < (4 if command == 3 else 12):
            raise InvalidPacket("truncated Joylink control payload")
        timestamp = struct.unpack_from("<I", payload)[0]
        peer, now = _peer_hash(address), int(time.time()) & 0xffffffff
        if command == 3:
            request = _json(payload[4:])
            feedid = request.get("feedid", "")
            if not isinstance(feedid, str) or len(feedid.encode()) > 32 or "\0" in feedid:
                raise InvalidPacket("invalid Joylink feedid")
            candidate = _state(device)
            if not _admit(candidate["_slots"], peer, timestamp, now):
                return []
            body = struct.pack("<I", now) + json.dumps(
                {"code": 0, "feedid": "synthetic-feed"}, separators=(", ", ":")
            ).encode()
            reply = _frame(4, 3, body, device.key)
            device.state = candidate
            return [reply]
        operation, serial = struct.unpack_from("<II", payload, 4)
        if operation not in (1002, 1004):
            candidate = _state(device)
            if _admit(candidate["_slots"], peer, timestamp, now):
                device.state = candidate
            return []
        request = _json(payload[12:])
        streams = request.get("streams", [])
        if not isinstance(streams, list) or len(streams) > 64:
            raise InvalidPacket("Joylink requires at most64 bounded streams")
        commands = []
        for stream in streams:
            if not isinstance(stream, dict):
                continue
            if "stream_id" not in stream:
                break
            name = stream["stream_id"]
            if not isinstance(name, str) or len(name.encode()) > 64:
                raise InvalidPacket("invalid Joylink stream name")
            value = stream.get("current_value")
            if type(value) not in (str, int, float):
                continue
            value = _number(value)
            if name in FIELDS and name != "CurrentTemperature":
                commands.append((name, value))
        candidate = _state(device)
        if not _admit(candidate["_slots"], peer, timestamp, now):
            return []
        if "_pending" in candidate:
            old = candidate["_report"]
            report = bytearray(candidate.pop("_pending"))
            report[3], report[44], report[46] = 0x31, report[47], old[46]
            candidate["_report"] = report
        values = _read(candidate["_report"])
        send = candidate["_send"]
        for name, value in commands:
            _write(send, name, value)
        body = struct.pack("<III", now, operation - 900, serial) + json.dumps(
            {"code": 0, "streams": _streams(values)}, separators=(",", ":")).encode()
        reply = _frame(4, 3, body, device.key)
        if commands:
            candidate["_pending"] = bytearray(send)
        candidate.update(values)
        device.state = candidate
        return [reply]


PROFILES = (Profile(
    id="sim-tg-apj-v1.14-joylink-raw-10001", mids=("10001",),
    hid="362001071953+U-WB05APJV1.14.bin",
    source_sha256="4671414a8c9d6fbaa69dd176f838666c32fe8b1412ed467e46735fd4392c5c7b",
    initial_state=INITIAL_STATE, handler=Joylink(), max_request_bytes=MAX_BYTES,
),)
