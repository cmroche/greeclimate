"""Shared source-derived framing and numeric conversion for legacy RT13 ECB builds."""

import json
import math
import re

from ..wire import InvalidPacket, Reply
from . import simulated, wb_raw


GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
SCAN_KEY = GENERIC_KEY
CODEC = "aes-ecb-pkcs7"
BUFFER_BYTES = 0x5B4
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?")



class LegacyRT13Handler:
    fields = wb_raw.RT13_110_FIELDS

    def validate_state(self, state):
        wb_raw.validate_state({name: value for name, value in state.items()
                               if not name.startswith("_")}, self.fields)

    def thermal_target(self, device):
        return simulated.thermal_target(device)

    def encode_room(self, device):
        # Synthetic sensor bias only; it is not source or hardware calibration.
        simulated.encode_room(device, 40, 255)


class _NumberToken(str):
    __slots__ = ()


def source_number(token):
    return _NumberToken(token)


def source_integer(value):
    # Native parser stops after an optional decimal fraction; d2iz truncates that binary64 prefix.
    if isinstance(value, _NumberToken):
        match = _NUMBER.match(value)
        if match is None:
            raise InvalidPacket("legacy RT13 numeric token has no numeric prefix")
        try:
            value = math.trunc(float(match.group()))
        except (OverflowError, ValueError) as exc:
            raise InvalidPacket("legacy RT13 numeric token is out of range") from exc
    elif type(value) is not int:
        raise InvalidPacket("legacy RT13 operation requires a numeric token")
    if not -(1 << 31) <= value < (1 << 31):
        raise InvalidPacket("legacy RT13 numeric token is outside signed int32")
    return value


def source_number_has_suffix(value):
    return (isinstance(value, _NumberToken)
            and (match := _NUMBER.match(value)) is not None
            and match.end() < len(value))

def source_values(values):
    if not isinstance(values, list):
        return values
    parsed = []
    previous_suffix = False
    for value in values:
        if previous_suffix:
            raise InvalidPacket("legacy RT13 numeric suffix prevents the next array value")
        parsed.append(source_integer(value) if isinstance(value, _NumberToken) else value)
        previous_suffix = source_number_has_suffix(value)
    return parsed


def _json_size(value):
    try:
        return len(json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                             allow_nan=False).encode("utf-8"))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise InvalidPacket("invalid legacy RT13 JSON value") from exc


def packed_reply(outer, inner, key):
    plain_size = _json_size(inner)
    ciphertext_size = ((plain_size // 16) + 1) * 16
    pack_size = 4 * ((ciphertext_size + 2) // 3)
    empty_pack_size = _json_size({**outer, "pack": ""})
    if empty_pack_size + pack_size >= BUFFER_BYTES:
        raise InvalidPacket("legacy RT13 reply exceeds the 0x5b4-byte source buffer")
    return Reply(outer, inner, key, CODEC)


def reply(device, inner, index, uid, peer):
    return packed_reply({"t": "pack", "i": index, "uid": uid,
                         "cid": device.mac, "tcid": peer}, inner,
                        GENERIC_KEY if index else device.key)
