"""Public WB05RT13 wire/model vectors; no vendor image or client import required."""

import base64
import hashlib
import json
from pathlib import Path

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles import simulated
from gree_emulator.profiles.wb_rt13 import PROFILES
from gree_emulator.wire import InvalidPacket, encode_reply


FIXTURES = Path(__file__).parent / "fixtures" / "emulator"
VECTOR = json.loads((FIXTURES / "wb-rt13.json").read_text())
RESEARCH = json.loads((FIXTURES / "wb-rt13_research.json").read_text())
GENERIC = b"{yxAHAY_Lm6pbC/<"
NONCE = bytes.fromhex("5440784449675a516c5e6313")
AAD = b"qualcomm-test"


def device_for(profile, *, mac="020000000001", key=b"0123456789abcdef"):
    device = EmulatedDevice("office", mac, "Emulator Office", "10001", key,
                            profile, dict(profile.initial_state), last_step=1000)
    profile.handler.encode_room(device)
    return device


def packet(device, inner, *, index=0, key=None, plaintext=None):
    cipher = AES.new(key or (GENERIC if index else device.key), AES.MODE_GCM, nonce=NONCE)
    cipher.update(AAD)
    plain = plaintext if plaintext is not None else json.dumps(inner, separators=(",", ":")).encode()
    encrypted, tag = cipher.encrypt_and_digest(plain)
    return {"t": "pack", "i": index, "uid": 42, "cid": "app", "tcid": device.mac,
            "pack": base64.b64encode(encrypted).decode(), "tag": base64.b64encode(tag).decode()}


def peer_reply(reply, key):
    outer = json.loads(encode_reply(reply))
    encrypted = base64.b64decode(outer.pop("pack"), validate=True)
    tag = base64.b64decode(outer.pop("tag"), validate=True)
    cipher = AES.new(key, AES.MODE_GCM, nonce=NONCE)
    cipher.update(AAD)
    plain = cipher.decrypt_and_verify(encrypted, tag)
    assert len(plain) == len(encrypted)  # GCM uses neither block padding nor terminal NUL.
    return outer, json.loads(plain)


@pytest.mark.parametrize("profile", PROFILES, ids=lambda profile: profile.id)
def test_authenticated_bind_control_readback_vectors(profile, monkeypatch):
    monkeypatch.setattr(simulated, "monotonic", lambda: 1000)
    device = device_for(profile)
    for transaction in VECTOR["authenticated_transactions"]:
        index = transaction["selector"]
        replies = profile.handler.handle(device, packet(device, transaction["request"], index=index))
        assert len(replies) == 1
        outer, inner = peer_reply(replies[0], GENERIC if index else device.key)
        assert outer == {"t": "pack", "i": index, "uid": 42,
                         "cid": "020000000001", "tcid": "app"}
        assert inner == transaction["reply"]


@pytest.mark.parametrize("profile", PROFILES, ids=lambda profile: profile.id)
def test_discovery_uses_separate_ecb_wrapper(profile):
    device = device_for(profile)
    reply, = profile.handler.advertise(device, {"t": "scan"})
    outer = json.loads(encode_reply(reply))
    ciphertext = base64.b64decode(outer.pop("pack"), validate=True)
    inner = json.loads(unpad(AES.new(b"a3K8Bx%2r8Y7#xDh", AES.MODE_ECB).decrypt(ciphertext), 16))
    expected = dict(VECTOR["expected_replies"][0][0]["inner"], hid=profile.hid)
    assert inner == expected
    assert outer == {"t": "pack", "i": 1, "uid": 0, "cid": "", "tcid": ""}


@pytest.mark.parametrize("inner", [
    {"t": "cmd", "opt": ["Pow", "BuzzerCtrl"], "p": [1, 0]},
    {"t": "cmd", "opt": ["Pow", "unknown"], "p": [1, 0]},
    {"t": "cmd", "opt": ["Pow", "TemSen"], "p": [1, 60]},
    {"t": "cmd", "opt": ["Pow", "SetTem"], "p": [1, 31]},
    {"t": "cmd", "opt": ["Pow"], "p": [True]},
    {"t": "cmd", "opt": ["Pow"], "p": []},
    {"t": "cmd", "opt": [], "p": []},
    {"t": "cmd", "opt": ["Pow"], "p": "1"},
    {"t": "status", "cols": "Pow"},
    {"t": "status", "cols": [None]},
    {"t": "status", "cols": ["Pow\u0000ignored"]},
    {"t": "status", "cols": ["x" * 512]},
    {"t": "status", "cols": ["Pow"] * 65},
    {"t": "status", "cols": ["hid"] * 64},
])
@pytest.mark.parametrize("profile", PROFILES, ids=lambda profile: profile.id)
def test_bad_properties_are_atomic(profile, inner):
    device = device_for(profile)
    before = dict(device.state)
    with pytest.raises(InvalidPacket):
        profile.handler.handle(device, packet(device, inner))
    assert device.state == before
    assert device.last_step == 1000


@pytest.mark.parametrize("profile", PROFILES, ids=lambda profile: profile.id)
def test_status_reports_embedded_build_identity(profile):
    device = device_for(profile)
    reply, = profile.handler.handle(device, packet(
        device, {"t": "status", "cols": ["hid", "mid", "name", "hid"]}))
    assert peer_reply(reply, device.key)[1]["dat"] == [
        profile.hid, "10001", "Emulator Office", profile.hid]


@pytest.mark.parametrize("profile", PROFILES, ids=lambda profile: profile.id)
def test_unknown_empty_status_and_property_aliases(profile, monkeypatch):
    monkeypatch.setattr(simulated, "monotonic", lambda: 1000)
    device = device_for(profile)
    reply, = profile.handler.handle(device, packet(device, {"t": "status", "cols": ["unknown"]}))
    assert peer_reply(reply, device.key)[1] == {"t": "dat", "uid": 0, "mac": device.mac,
                                                "cid": device.mac, "dat": [], "cols": [], "r": 200}
    request = {"t": "cmd", "cols": ["Pow"], "opt": ["SetTem"], "p": [1]}
    reply, = profile.handler.handle(device, packet(device, request))
    assert peer_reply(reply, device.key)[1]["opt"] == ["Pow"]
    assert device.state["Pow"] == 1 and device.state["SetTem"] == 24
    reply, = profile.handler.handle(device, packet(device, {"t": "status", "opt": ["Pow", "Pow"]}))
    assert peer_reply(reply, device.key)[1]["dat"] == [1, 1]
    assert profile.handler.handle(device, packet(device, {"t": "subDev"})) == []


@pytest.mark.parametrize("profile", PROFILES, ids=lambda profile: profile.id)
def test_targets_devices_and_keys_are_isolated(profile, monkeypatch):
    monkeypatch.setattr(simulated, "monotonic", lambda: 1000)
    first = device_for(profile)
    second = device_for(profile, mac="020000000002", key=b"fedcba9876543210")
    command = {"t": "cmd", "opt": ["Pow", "Mod", "SetTem"], "p": [1, 1, 20]}
    profile.handler.handle(first, packet(first, command))
    assert second.state["Pow"] == 0 and second.state["SetTem"] == 24
    for selector in ("mac", "sub"):
        with pytest.raises(InvalidPacket):
            profile.handler.handle(first, packet(first, {**command, selector: second.mac}))
    wrong_outer = packet(first, command)
    wrong_outer["tcid"] = second.mac
    with pytest.raises(InvalidPacket):
        profile.handler.handle(first, wrong_outer)
    with pytest.raises(InvalidPacket):
        profile.handler.handle(second, packet(second, command, key=first.key))
    assert second.state["Pow"] == 0 and second.state["SetTem"] == 24
    bound_reply, = profile.handler.handle(second, packet(second, {"t": "bind"}, index=1))
    assert peer_reply(bound_reply, GENERIC)[1]["key"] == "fedcba9876543210"
    assert first.key != second.key


@pytest.mark.parametrize("profile", PROFILES, ids=lambda profile: profile.id)
def test_authentication_and_json_boundaries(profile):
    device = device_for(profile)
    inner = {"t": "cmd", "opt": ["Pow"], "p": [1]}
    valid = packet(device, inner)
    corrupted = []
    for tag in (None, "!", "AA==", base64.b64encode(bytes(16)).decode()):
        candidate = dict(valid)
        if tag is None:
            candidate.pop("tag")
        else:
            candidate["tag"] = tag
        corrupted.append(candidate)
    for index in (True, -1, 2, "0"):
        corrupted.append({**valid, "i": index})
    corrupted.append(packet(device, inner, index=1, key=device.key))
    encrypted = bytearray(base64.b64decode(valid["pack"]))
    encrypted[0] ^= 1
    corrupted.append({**valid, "pack": base64.b64encode(encrypted).decode()})
    for plaintext in (b'{"t":"cmd","t":"bind"}', b'{"t":"status"}\0', b'{"t":"status"}garbage'):
        corrupted.append(packet(device, None, plaintext=plaintext))
    before = dict(device.state)
    for candidate in corrupted:
        with pytest.raises(InvalidPacket):
            profile.handler.handle(device, candidate)
        assert device.state == before
        assert device.last_step == 1000


@pytest.mark.parametrize("profile", PROFILES, ids=lambda profile: profile.id)
def test_synthetic_temperature_step_is_not_native_calibration(profile, monkeypatch):
    monkeypatch.setattr(simulated, "monotonic", lambda: 1000)
    device = device_for(profile)
    profile.handler.handle(device, packet(device, {"t": "cmd", "opt": ["Pow", "Mod", "SetTem"],
                                                   "p": [1, 1, 20]}))
    device.advance(1060)
    assert device.room_c == 25 and device.state["TemSen"] == 65
    device.advance(1660)
    assert device.room_c == 20 and device.state["TemSen"] == 60


def test_source_constant_initializers_are_independent_of_emulator():
    """Bounded MOVS/STRB translation of public exact-source Thumb leaf bytes."""
    for leaf in RESEARCH["constant_initializers"]:
        registers = [0] * 8
        output = bytearray(32)
        code = bytes.fromhex(leaf["thumb_hex"])
        for offset in range(0, len(code), 2):
            instruction = int.from_bytes(code[offset:offset + 2], "little")
            if instruction & 0xF800 == 0x2000:  # MOVS low-register immediate
                registers[(instruction >> 8) & 7] = instruction & 255
            elif instruction & 0xF800 == 0x7000:  # STRB immediate through r0
                assert (instruction >> 3) & 7 == 0
                output[(instruction >> 6) & 31] = registers[instruction & 7]
            else:
                assert instruction == 0x4770 and offset == len(code) - 2  # BX LR
        assert output[:len(bytes.fromhex(leaf["expected_hex"]))].hex() == leaf["expected_hex"]


def probe_exact_firmware_constants(paths):
    """Research-only callable: native leaf replay; not imported/executed by tests.

    The caller supplies all three SHA-pinned vendor images and optional Unicorn.
    No hooks substitute key/nonce/AAD behavior; only scratch RAM and return LR.
    This does not claim native AES, LAN dispatch, board calibration or full boot.
    """
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB
    from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_R0

    results = []
    assert len(paths) == 3
    expected_images = {image["sha256"]: image for image in RESEARCH["images"]}
    for path in paths:
        image = Path(path).read_bytes()
        sha = hashlib.sha256(image).hexdigest()
        assert sha in expected_images
        expected_images.pop(sha)
        for leaf in RESEARCH["constant_initializers"]:
            code = bytes.fromhex(leaf["thumb_hex"])
            position = image.find(code)
            assert position >= 0 and image.find(code, position + 1) == -1
            native = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
            native.mem_map(0x100000, 0x1000)
            native.mem_map(0x200000, 0x1000)
            native.mem_write(0x100000, code)
            native.reg_write(UC_ARM_REG_R0, 0x200000)
            native.reg_write(UC_ARM_REG_LR, 0x100801)
            native.emu_start(0x100001, 0x100800, count=100)
            expected = bytes.fromhex(leaf["expected_hex"])
            assert bytes(native.mem_read(0x200000, len(expected))) == expected
            results.append({"sha256": sha, "leaf": leaf["name"], "source_offset": position,
                            "native_passed": True})
    assert not expected_images
    return results
