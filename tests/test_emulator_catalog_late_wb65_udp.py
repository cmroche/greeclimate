"""Actual WB65VR UDP routing preserves native plaintext echoes byte for byte."""

import asyncio
import base64
from datetime import datetime
import json
import socket

from Crypto.Cipher import AES
import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.catalog_late_wb65 import PROFILES
from gree_emulator.server import start_server


KEY = b"0123456789abcdef"
NONCE = bytes.fromhex("5440784449675a516c5e6313")
AAD = b"qualcomm-test"


def status_packet(device):
    plain = json.dumps({"t": "status", "cols": ["time"]}, separators=(",", ":")).encode()
    # The source base64 receiver trims decoded zero tails. Choose a source-valid
    # whitespace suffix here so this test isolates plaintext routing, not that
    # independent codec defect.
    while True:
        cipher = AES.new(KEY, AES.MODE_GCM, nonce=NONCE)
        cipher.update(AAD)
        encrypted, tag = cipher.encrypt_and_digest(plain)
        if encrypted[-1] and tag[-1]:
            break
        plain += b" "
    return json.dumps({"t": "pack", "i": 0, "uid": 42, "cid": "app",
                       "tcid": device.mac, "pack": base64.b64encode(encrypted).decode(),
                       "tag": base64.b64encode(tag).decode()}, separators=(",", ":")).encode()


def decode_status(raw):
    outer = json.loads(raw)
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=NONCE)
    cipher.update(AAD)
    return json.loads(cipher.decrypt_and_verify(base64.b64decode(outer["pack"], validate=True),
                                                base64.b64decode(outer["tag"], validate=True)))


@pytest.mark.parametrize("profile", PROFILES, ids=lambda profile: profile.id)
async def test_native_plaintext_echo_bytes_and_time_reach_real_udp_family(profile):
    device = EmulatedDevice("wb65", "020000000001", "Late WB65", "10001", KEY,
                            profile, dict(profile.initial_state), room_c=None, ambient_c=None,
                            last_step=1000)
    transport, server = await start_server([device], "127.0.0.1", 0)
    try:
        endpoint = transport.get_extra_info("sockname")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.settimeout(0.5)
            # Deliberate key order, whitespace, CR/LF and non-ASCII bytes. A
            # decoded/re-encoded JSON response is not the original source echo.
            heartbeat = b'{ "note" : "caf\xc3\xa9", "t" : "hbok" }\r\n'
            peer.sendto(heartbeat, endpoint)
            echoed, _ = await asyncio.to_thread(peer.recvfrom, 4096)
            assert echoed == heartbeat
            time_message = (b' \n{"time":"2026-01-02 03:04:05","t":"tm",'
                            b'"note":"\xe6\xb8\xa9\xe5\xba\xa6"}\t ')
            peer.sendto(time_message, endpoint)
            echoed, _ = await asyncio.to_thread(peer.recvfrom, 4096)
            assert echoed == time_message
            peer.sendto(status_packet(device), endpoint)
            raw, _ = await asyncio.to_thread(peer.recvfrom, 4096)
            status = decode_status(raw)
            assert status["t"] == "dat" and status["r"] == 200
            assert status["cols"] == ["time"]
            reported = datetime.strptime(status["dat"][0], "%Y-%m-%d %H:%M:%S")
            assert 0 <= (reported - datetime(2026, 1, 2, 3, 4, 5)).total_seconds() <= 2
    finally:
        server.close()
        await server.wait_closed()
