"""JBL binary framing vectors captured from original constructor/CBC instructions."""
import json
from pathlib import Path

import pytest

from gree_emulator.profiles.controller import decode_mt2_frame, encode_mt2_frame
from gree_emulator.wire import InvalidPacket

FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/mt2-frame_research.json").read_text())


@pytest.mark.parametrize("row", FIXTURE["vectors"])
def test_native_constructor_literals_and_binary_decode(row):
    options = bytes.fromhex(row["options_hex"])
    payload = None if row["payload_hex"] is None else bytes.fromhex(row["payload_hex"])
    key, iv = bytes.fromhex(row["key_hex"]), bytes.fromhex(row["iv_hex"])
    expected = bytes.fromhex(row["expected_frame_hex"])
    assert encode_mt2_frame(row["opcode"], options, payload=payload,
                            sequence=row["sequence"], key=key, iv=iv) == expected
    assert decode_mt2_frame(expected, key=key, iv=iv) == (
        row["opcode"], options, None if payload is None else row["sequence"], payload)
    assert expected[:2] == b"\xaa\xbb" and not expected.startswith(b"{")


def test_mt2_options_checksum_covers_all_option_bytes_without_payload():
    assert encode_mt2_frame(8, b"\x02\x03") == bytes.fromhex("aabb08020500000203")
    with pytest.raises(InvalidPacket):
        decode_mt2_frame(bytes.fromhex("aabb08020200000203"))


@pytest.mark.parametrize("bad", [b"", b"{}", b"aabb", b"\xaa\xbb", b"\xaa\xbb\x01\x00",
                                  bytes.fromhex("aabb1100000010"),
                                  bytes.fromhex("aabb1101000000")])
def test_mt2_malformed_lengths_and_ordinary_json_are_not_admitted(bad):
    with pytest.raises(InvalidPacket):
        decode_mt2_frame(bad)


def test_mt2_safety_policy_rejects_wrong_keys_corrupt_padding_and_oversized_frames():
    row = next(row for row in FIXTURE["vectors"] if row["payload_hex"])
    packet = bytes.fromhex(row["expected_frame_hex"])
    key, iv = bytes.fromhex(row["key_hex"]), bytes.fromhex(row["iv_hex"])
    with pytest.raises(InvalidPacket):
        decode_mt2_frame(packet, key=b"wrong-key-1234567", iv=iv)
    with pytest.raises(InvalidPacket):
        decode_mt2_frame(packet[:-1] + bytes([packet[-1] ^ 255]), key=key, iv=iv)
    with pytest.raises(InvalidPacket):
        decode_mt2_frame(packet + b"\x00", key=key, iv=iv)
    with pytest.raises(InvalidPacket):
        encode_mt2_frame(17, payload=b"x" * 1024, key=key, iv=iv)
    with pytest.raises(InvalidPacket):
        encode_mt2_frame(1, payload=b"", key=key, iv=iv)
