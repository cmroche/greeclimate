"""Independent authenticated framing vectors and strict wire regressions."""

import base64
import json

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from gree_emulator import wire
from gree_emulator.wire import InvalidPacket, Reply, decode_pack, encode_reply


KEY = b"{yxAHAY_Lm6pbC/<"
NONCE = bytes.fromhex("5440784449675a516c5e6313")
AAD = b"qualcomm-test"
# Generated directly with PyCryptodome and these literal parameters, not the wire codec.
PLAIN = b'{"t":"status","name":"B\xc3\xbcro"}'
CIPHERTEXT = bytes.fromhex("26da0a962c2dba84b2f289c478655759ce2cedc118c06505bc163b1fa7")
TAG = bytes.fromhex("1213204813fb0b1ffb6367b0d6d04195")


def authenticated(plain, *, key=KEY, nonce=NONCE, aad=AAD):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(aad)
    encrypted, tag = cipher.encrypt_and_digest(plain)
    return {"pack": base64.b64encode(encrypted).decode("ascii"),
            "tag": base64.b64encode(tag).decode("ascii")}


def fixed_packet():
    return {"pack": base64.b64encode(CIPHERTEXT).decode("ascii"),
            "tag": base64.b64encode(TAG).decode("ascii")}


def test_fixed_authenticated_ciphertext_and_reply_vector():
    expected = {"t": "status", "name": "Büro"}
    assert decode_pack(fixed_packet(), KEY, "aes-gcm") == expected
    outer = {"t": "pack", "i": 0}
    encoded = json.loads(encode_reply(Reply(outer, expected, KEY, "aes-gcm")))
    assert encoded == {**outer, **fixed_packet()}
    assert outer == {"t": "pack", "i": 0}


@pytest.mark.parametrize("plain,inner", [
    (b'{"t":"12345678"}', {"t": "12345678"}),
    (PLAIN, {"t": "status", "name": "Büro"}),
    (b'{}', {}),
])
def test_gcm_has_no_padding_and_preserves_utf8(plain, inner):
    packet = authenticated(plain)
    assert len(base64.b64decode(packet["pack"])) == len(plain)
    assert decode_pack(packet, KEY, "aes-gcm") == inner
    assert json.loads(encode_reply(Reply({}, inner, KEY, "aes-gcm"))) == packet


@pytest.mark.parametrize("part", ["pack", "tag"])
def test_tampering_is_rejected_before_json(part, monkeypatch):
    packet = fixed_packet()
    damaged = bytearray(base64.b64decode(packet[part]))
    damaged[0] ^= 1
    packet[part] = base64.b64encode(damaged).decode("ascii")

    def no_json(_):
        pytest.fail("unauthenticated plaintext reached the JSON parser")

    monkeypatch.setattr(wire, "_json", no_json)
    with pytest.raises(InvalidPacket, match="authentication"):
        decode_pack(packet, KEY, "aes-gcm")


@pytest.mark.parametrize("change", ["key", "nonce", "aad"])
def test_wrong_authenticated_parameters(change):
    parameters = {"key": KEY, "nonce": NONCE, "aad": AAD}
    parameters[change] = bytes([parameters[change][0] ^ 1]) + parameters[change][1:]
    with pytest.raises(InvalidPacket, match="authentication"):
        decode_pack(authenticated(PLAIN, **parameters), KEY, "aes-gcm")


def test_wrong_decode_key():
    with pytest.raises(InvalidPacket, match="authentication"):
        decode_pack(fixed_packet(), b"0123456789abcdef", "aes-gcm")


@pytest.mark.parametrize("tag", [None, True, 1, [], {}, "!", "é", "AA==\n", "AAAA=!"])
def test_missing_or_malformed_tag(tag):
    packet = fixed_packet()
    packet["tag"] = tag
    with pytest.raises(InvalidPacket):
        decode_pack(packet, KEY, "aes-gcm")


def test_absent_tag():
    with pytest.raises(InvalidPacket):
        decode_pack({"pack": fixed_packet()["pack"]}, KEY, "aes-gcm")


@pytest.mark.parametrize("length", [0, 1, 12, 15, 17, 32])
def test_tag_requires_exactly_sixteen_bytes(length):
    packet = fixed_packet()
    packet["tag"] = base64.b64encode(b"x" * length).decode("ascii")
    with pytest.raises(InvalidPacket, match="tag length"):
        decode_pack(packet, KEY, "aes-gcm")


@pytest.mark.parametrize("payload", [None, True, 1, [], {}, "!", "é", "AA==\n", "A", ""])
def test_missing_or_malformed_payload(payload):
    packet = fixed_packet()
    packet["pack"] = payload
    with pytest.raises(InvalidPacket):
        decode_pack(packet, KEY, "aes-gcm")


def test_absent_payload():
    with pytest.raises(InvalidPacket):
        decode_pack({"tag": fixed_packet()["tag"]}, KEY, "aes-gcm")


@pytest.mark.parametrize("payload", [CIPHERTEXT[:-1], CIPHERTEXT + b"\0", b"{}"])
def test_truncated_extended_or_plaintext_payload(payload):
    packet = fixed_packet()
    packet["pack"] = base64.b64encode(payload).decode("ascii")
    with pytest.raises(InvalidPacket, match="authentication"):
        decode_pack(packet, KEY, "aes-gcm")


@pytest.mark.parametrize("plain", [
    b"", b"\xff", b"[]", b"null", b'"status"', b'{"t":',
    b'{"t":"status"}{}', b'{"t":"status","t":"cmd"}',
    b'{"nested":{"x":1,"x":2}}', b'{"x":NaN}', b'{"x":Infinity}',
    b'{"x":-Infinity}', b'{"x":1e999}', b'{"x":"\\ud800"}',
    b'{"\\udfff":1}', b'{"x":["\\ud800"]}',
    b'{"t":"status"}\0', pad(b'{"t":"status"}', 16),
])
def test_authenticated_json_stays_strict(plain):
    with pytest.raises(InvalidPacket):
        decode_pack(authenticated(plain), KEY, "aes-gcm")


@pytest.mark.parametrize("codec", ["aes-ecb-pkcs7", "aes-ecb-pkcs7-nul-input"])
def test_mixed_codecs_are_not_auto_detected(codec):
    encrypted = AES.new(KEY, AES.MODE_ECB).encrypt(pad(PLAIN, 16))
    ecb_packet = {**fixed_packet(), "pack": base64.b64encode(encrypted).decode("ascii")}
    with pytest.raises(InvalidPacket):
        decode_pack(ecb_packet, KEY, "aes-gcm")
    with pytest.raises(InvalidPacket):
        decode_pack(fixed_packet(), KEY, codec)


@pytest.mark.parametrize("codec", ["aes-ecb-pkcs7", "aes-ecb-pkcs7-nul-input"])
def test_ecb_reply_bytes_remain_unchanged(codec):
    encrypted = AES.new(KEY, AES.MODE_ECB).encrypt(pad(PLAIN, 16))
    expected = {"pack": base64.b64encode(encrypted).decode("ascii")}
    assert json.loads(encode_reply(Reply({}, {"t": "status", "name": "Büro"}, KEY, codec))) == expected
    assert decode_pack(expected, KEY, codec) == {"t": "status", "name": "Büro"}


@pytest.mark.parametrize("codec", ["aes-ecb-pkcs7", "aes-ecb-pkcs7-nul-input"])
@pytest.mark.parametrize("suffix", [b"", b"\0", b"\0\0"])
def test_ecb_single_nul_policy_is_unchanged(codec, suffix):
    encrypted = AES.new(KEY, AES.MODE_ECB).encrypt(pad(PLAIN + suffix, 16))
    packet = {"pack": base64.b64encode(encrypted).decode("ascii")}
    if not suffix or (codec == "aes-ecb-pkcs7-nul-input" and suffix == b"\0"):
        assert decode_pack(packet, KEY, codec) == {"t": "status", "name": "Büro"}
    else:
        with pytest.raises(InvalidPacket):
            decode_pack(packet, KEY, codec)


@pytest.mark.parametrize("codec", ["aes-ecb-pkcs7", "aes-ecb-pkcs7-nul-input"])
def test_ecb_still_requires_pkcs7_padding(codec):
    encrypted = AES.new(KEY, AES.MODE_ECB).encrypt(b'{"t":"12345678"}')
    with pytest.raises(InvalidPacket, match="padding"):
        decode_pack({"pack": base64.b64encode(encrypted).decode("ascii")}, KEY, codec)


def test_unknown_codec_is_a_programming_error():
    with pytest.raises(ValueError, match="unknown codec") as error:
        decode_pack({}, KEY, "unknown")
    assert not isinstance(error.value, InvalidPacket)
    with pytest.raises(ValueError, match="unknown codec") as error:
        encode_reply(Reply({}, {}, KEY, "unknown"))
    assert not isinstance(error.value, InvalidPacket)
