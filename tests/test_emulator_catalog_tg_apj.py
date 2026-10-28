"""Source-qualified WB05APJ Joylink UDP emulator coverage."""

import asyncio
import json
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from gree_emulator.__main__ import load_config
from gree_emulator.profiles import PROFILES, catalog_tg_apj
from gree_emulator.server import start_server
from gree_emulator.wire import InvalidPacket
from tests.common import udp_peer


FIXTURE = Path(__file__).parent / "fixtures" / "emulator" / "catalog-tg-apj_research.json"


def _evidence():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _device(evidence):
    return load_config({"seed": "apj-source-vector", "devices": [{
        "id": "apj", "profile": evidence["profile"], "mid": evidence["configured_mid"],
        "mac": evidence["mac"],
    }]})[2][0]


def _scan_packet(payload):
    header = bytearray(16)
    struct.pack_into("<IHH", header, 0, 0x123455bb, 0, len(payload))
    header[8], header[9], header[12] = 1, 1, 0
    return bytes(header) + payload


def test_table_five_native_property_vectors():
    evidence = _evidence()
    callbacks = evidence["callbacks"]
    assert tuple(row["name"] for row in callbacks) == catalog_tg_apj.FIELDS

    for row in callbacks:
        for vector in row["writes"]:
            frame = bytearray(b"\x7e\x7e\x60\x01" + b"\x5a" * 96)
            catalog_tg_apj._write(frame, row["name"], vector["requested"])
            assert frame.hex() == vector["command01"], (row["name"], vector["requested"])
        for vector in row["reads"]:
            frame = bytearray(100)
            frame[row["read_byte_index"]] = vector["raw"]
            assert catalog_tg_apj._read(frame)[row["name"]] == vector["value"], row["name"]


@pytest.mark.asyncio
async def test_raw_script_transaction_matches_native_vector(monkeypatch):
    evidence = _evidence()
    monkeypatch.setattr(catalog_tg_apj, "time", SimpleNamespace(time=lambda: 1234))
    device = _device(evidence)
    device.key = evidence["key"].encode("ascii")
    transport, server = await start_server([device], "127.0.0.1", 0)
    address = transport.get_extra_info("sockname")
    try:
        async with udp_peer() as (peer, received):
            request = bytes.fromhex(evidence["first_request_hex"])
            peer.sendto(request, address)
            response, _ = await asyncio.wait_for(received.get(), 1)
            assert response == bytes.fromhex(evidence["first_response_hex"])
            assert device.state["_send"][8] & 0x80
            assert not device.state["_report"][8] & 0x80

            peer.sendto(request, address)
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(received.get(), 0.03)
    finally:
        transport.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_discovery_schema_and_signed_challenge_boundary():
    evidence = _evidence()
    device = _device(evidence)
    transport, server = await start_server([device], "127.0.0.1", 0)
    address = transport.get_extra_info("sockname")
    try:
        async with udp_peer() as (peer, received):
            peer.sendto(_scan_packet(b"{}"), address)
            reply, _ = await asyncio.wait_for(received.get(), 1)
            assert reply[:4] == bytes.fromhex(evidence["magic_hex"])
            assert json.loads(reply[16:]) == evidence["native_discovery_fields"]

            peer.sendto(_scan_packet(b'{"d_idt":{"app_rand":"challenge"}}'), address)
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(received.get(), 0.03)
    finally:
        transport.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_json_control_ack_matches_native_ciphertext(monkeypatch):
    evidence = _evidence()
    monkeypatch.setattr(catalog_tg_apj, "time", SimpleNamespace(time=lambda: 1234))
    device = _device(evidence)
    device.key = evidence["key"].encode("ascii")
    transport, server = await start_server([device], "127.0.0.1", 0)
    address = transport.get_extra_info("sockname")
    try:
        async with udp_peer() as (peer, received):
            peer.sendto(bytes.fromhex(evidence["json_control_request_hex"]), address)
            reply, _ = await asyncio.wait_for(received.get(), 1)
            assert reply == bytes.fromhex(evidence["json_control_response_hex"])
    finally:
        transport.close()
        await server.wait_closed()


def test_apj_is_not_a_gree_json_profile():
    profile = PROFILES["sim-tg-apj-v1.14-joylink-raw-10001"]
    with pytest.raises(InvalidPacket, match="not a UDP carrier"):
        profile.handler.handle(None, {"t": "status"})
