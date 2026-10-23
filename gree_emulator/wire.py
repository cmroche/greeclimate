"""Strict JSON and evidenced AES framing, independent of the client library."""

import base64
import binascii
import json
import logging
import math
from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


_LOGGER = logging.getLogger(__name__)
_GCM_NONCE = bytes.fromhex("5440784449675a516c5e6313")
_GCM_AAD = b"qualcomm-test"


class InvalidPacket(ValueError):
    """Malformed or misaddressed peer input; safe to discard without replying."""


@dataclass(frozen=True)
class Reply:
    outer: dict
    inner: dict | None = None
    key: bytes | None = None
    codec: str | None = None


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidPacket("duplicate JSON key")
        result[key] = value
    return result


def _constant(value):
    raise InvalidPacket("nonfinite JSON number")


def _float(value):
    number = float(value)
    if not math.isfinite(number):
        raise InvalidPacket("nonfinite JSON number")
    return number


def _check_unicode(value):
    if isinstance(value, str):
        value.encode("utf-8")
    elif isinstance(value, dict):
        for key, item in value.items():
            key.encode("utf-8")
            _check_unicode(item)
    elif isinstance(value, list):
        for item in value:
            _check_unicode(item)


def _json(data: bytes) -> dict:
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_object,
                           parse_constant=_constant, parse_float=_float)
        _check_unicode(value)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvalidPacket("invalid JSON") from exc
    if not isinstance(value, dict):
        raise InvalidPacket("expected a JSON object")
    return value


def decode_outer(data: bytes) -> dict:
    outer = _json(data)
    if outer.get("t") not in ("scan", "pack", "subList"):
        raise InvalidPacket("unsupported envelope")
    for key in ("cid", "tcid"):
        if key in outer and not isinstance(outer[key], str):
            raise InvalidPacket(f"invalid {key}")
    for key in ("i", "uid"):
        if key in outer and type(outer[key]) is not int:
            raise InvalidPacket(f"invalid {key}")
    if outer["t"] == "pack" and not isinstance(outer.get("pack"), str):
        raise InvalidPacket("missing encrypted pack")
    return outer


def decode_pack(outer: dict, key: bytes, codec: str) -> dict:
    if codec not in ("aes-ecb-pkcs7", "aes-ecb-pkcs7-nul-input", "aes-gcm"):
        raise ValueError(f"unknown codec: {codec}")
    payload = outer.get("pack")
    if not isinstance(payload, str):
        raise InvalidPacket("missing encrypted pack")
    try:
        encrypted = base64.b64decode(payload, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise InvalidPacket("invalid base64") from exc
    if codec == "aes-gcm":
        tag = outer.get("tag")
        if not isinstance(tag, str):
            raise InvalidPacket("missing authentication tag")
        try:
            tag = base64.b64decode(tag, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise InvalidPacket("invalid tag base64") from exc
        if len(tag) != 16:
            raise InvalidPacket("invalid authentication tag length")
        cipher = AES.new(key, AES.MODE_GCM, nonce=_GCM_NONCE, mac_len=16)
        cipher.update(_GCM_AAD)
        try:
            plain = cipher.decrypt_and_verify(encrypted, tag)
        except ValueError as exc:
            raise InvalidPacket("invalid authentication tag") from exc
    else:
        if not encrypted or len(encrypted) % AES.block_size:
            raise InvalidPacket("invalid AES block length")
        plain = AES.new(key, AES.MODE_ECB).decrypt(encrypted)
        try:
            plain = unpad(plain, AES.block_size)
        except ValueError as exc:
            raise InvalidPacket("invalid padding") from exc
        if codec == "aes-ecb-pkcs7-nul-input" and plain.endswith(b"\0"):
            plain = plain[:-1]
    inner = _json(plain)
    _LOGGER.info("RX payload: %r", inner)
    return inner


def encode_reply(reply: Reply) -> bytes:
    outer = dict(reply.outer)
    if reply.inner is not None:
        if reply.codec not in ("aes-ecb-pkcs7", "aes-ecb-pkcs7-nul-input", "aes-gcm"):
            raise ValueError(f"unknown codec: {reply.codec}")
        plain = json.dumps(reply.inner, ensure_ascii=False, separators=(",", ":"),
                           allow_nan=False).encode("utf-8")
        if reply.codec == "aes-gcm":
            cipher = AES.new(reply.key, AES.MODE_GCM, nonce=_GCM_NONCE, mac_len=16)
            cipher.update(_GCM_AAD)
            encrypted, tag = cipher.encrypt_and_digest(plain)
            outer["tag"] = base64.b64encode(tag).decode("ascii")
        else:
            encrypted = AES.new(reply.key, AES.MODE_ECB).encrypt(pad(plain, AES.block_size))
        outer["pack"] = base64.b64encode(encrypted).decode("ascii")
    return json.dumps(outer, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")
