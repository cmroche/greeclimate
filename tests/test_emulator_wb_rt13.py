"""Public WB05RT13 wire/model vectors; no vendor image or client import required."""

import base64
import hashlib
import json
from pathlib import Path

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles import wb_rt13
from gree_emulator.profiles.wb_rt13 import PROFILES
from gree_emulator.wire import InvalidPacket, encode_reply


FIXTURES = Path(__file__).parent / "fixtures" / "emulator"
VECTOR = json.loads((FIXTURES / "wb-rt13-vectors_research.json").read_text())
RESEARCH = json.loads((FIXTURES / "wb-rt13_research.json").read_text())
GENERIC = b"{yxAHAY_Lm6pbC/<"
NONCE = bytes.fromhex("5440784449675a516c5e6313")
AAD = b"qualcomm-test"


def device_for(profile, *, mac="020000000001", key=b"0123456789abcdef"):
    device = EmulatedDevice("office", mac, "Emulator Office", VECTOR["mid"], key,
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
    monkeypatch.setattr(wb_rt13, "monotonic", lambda: 1000)
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
    if profile.source_sha256 == wb_rt13.BUILDS[0][1]:
        expected["mid"] = "10001"
    assert inner == expected
    assert outer == {"t": "pack", "i": 1, "uid": 0, "cid": "", "tcid": ""}


@pytest.mark.parametrize("inner", [
    {"t": "cmd", "opt": ["Pow", "BuzzerCtrl"], "p": [1, 0]},
    {"t": "cmd", "opt": ["Pow", "unknown"], "p": [1, 0]},
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
def test_status_reports_source_hid_and_configured_mid(profile):
    device = device_for(profile)
    reply, = profile.handler.handle(device, packet(
        device, {"t": "status", "cols": ["hid", "mid", "name", "hid"]}))
    expected_mid = "" if profile.source_sha256 == wb_rt13.BUILDS[0][1] else VECTOR["mid"]
    assert peer_reply(reply, device.key)[1]["dat"] == [
        profile.hid, expected_mid, "Emulator Office", profile.hid]


def test_v145_source_bound_profile():
    profile = next(profile for profile in PROFILES if profile.id == "sim-wb05rt13-v1.45")
    image = next(image for image in RESEARCH["images"] if image["version"] == "1.45")
    assert profile.source_sha256 == image["sha256"]
    assert image["sha256"] == (
        "2f12c03c97e4e7302acbc8ee72cda18e31e7d9843519d5a3fb1bdcb1a4f2ffec")
    assert profile.hid == image["hid"] == "362001065279+U-WB05RT13V1.45.bin"
    assert profile.max_request_bytes == image["receive_bytes"] == 1460
    assert profile.mids == ("10001",)
    assert profile.initial_state["_wb_dev_mid_raw"] == 0x10001
    assert profile.initial_state["_wb_dev_mid_buffer"] == "10001"
    assert profile.initial_state["_wb_dev_mid_retry_count"] == 6
    profile.handler.validate_state(dict(profile.initial_state))


def test_v145_discovery_mid_fallback_is_distinct_from_status_getter(monkeypatch):
    monkeypatch.setattr(wb_rt13, "monotonic", lambda: 1000)
    profile = next(profile for profile in PROFILES if profile.id == "sim-wb05rt13-v1.45")
    device = device_for(profile)

    def scan_mid():
        reply, = profile.handler.advertise(device, {"t": "scan"})
        outer = json.loads(encode_reply(reply))
        ciphertext = base64.b64decode(outer["pack"], validate=True)
        plain = unpad(AES.new(wb_rt13.SCAN_KEY, AES.MODE_ECB).decrypt(ciphertext), 16)
        return json.loads(plain)["mid"]

    assert scan_mid() == "10001"
    assert device.state["_wb_dev_mid_raw"] == 0x10001
    device.state["_wb_dev_mid_raw"] = 0
    device.state["_wb_dev_mid_retry_count"] = 5
    device.state["_wb_dev_mid_buffer"] = "previous"
    assert scan_mid() == "previous"
    device.state["_wb_dev_mid_retry_count"] = 6
    assert scan_mid() == "10001"
    assert device.state["_wb_dev_mid_raw"] == 0x10001
    device.state["_wb_dev_mid_raw"] = 0x12345
    assert scan_mid() == "12345"
    reply, = profile.handler.handle(device, packet(device, {"t": "status", "cols": ["mid"]}))
    assert peer_reply(reply, device.key)[1]["dat"] == [""]
    reply, = profile.handler.handle(device, packet(device, {"t": "cmd", "cols": ["mid"]}))
    assert peer_reply(reply, device.key)[1]["p"] == [""]
    for kind, value in (("status", "status/client"), ("cmd", "cmd/client"),
                        ("freqCount", "freq/client")):
        request = {"t": kind, "opt": ["ReportClientID"], "p": [value]}
        replies = profile.handler.handle(device, packet(device, request))
        if kind == "freqCount":
            assert replies == []
        else:
            assert len(replies) == 1
            if kind == "cmd":
                assert peer_reply(replies[0], device.key)[1]["p"] == []
        assert device.state["_wb_report_client"] == value
        frame = bytearray(30)
        frame[:4] = b"~~\x12\x6a"
        encoded = value.encode()
        frame[4:4 + len(encoded)] = encoded
        assert device.state["_wb_report_client_frame"] == list(frame)
        assert device.state["_wb_report_client_set"] == 1


def test_v145_exact_operation_table_and_per_operation_state(monkeypatch):
    monkeypatch.setattr(wb_rt13, "monotonic", lambda: 1000)
    profile = next(profile for profile in PROFILES if profile.id == "sim-wb05rt13-v1.45")
    device = device_for(profile)

    def send(inner):
        return [peer_reply(reply, device.key)[1]
                for reply in profile.handler.handle(device, packet(device, inner))]

    assert send({"t": "bind"}) == [{
        "r": 200, "t": "bindok", "mac": device.mac, "key": device.key.decode("ascii")}]
    assert send({"t": "bind", "mac": None}) == [{
        "r": 200, "t": "bindok", "mac": device.mac, "key": device.key.decode("ascii")}]
    assert send({"t": "status", "cols": ["Pow"]})[0]["dat"] == [0]
    assert send({"t": "freqCount", "opt": ["SendFreq", "FreqTime", "DRTime"],
                 "p": [1, 30, 60]}) == []
    assert [device.state[f"_wb_{name}"] for name in ("SendFreq", "FreqTime", "DRTime")] == [1, 30, 60]
    assert send({"t": "cmd", "opt": ["Pow"], "p": [1]})[0]["p"] == [1]
    plain = b'{\"t\":\"cmd\",\"opt\":[\"Pow\"],\"p\":[1.9]}'
    reply, = profile.handler.handle(device, packet(device, {}, plaintext=plain))
    assert peer_reply(reply, device.key)[1]["p"] == [1]
    plain = b'{\"t\":\"cmd\",\"opt\":[\"Pow\"],\"p\":[1e3]}'
    reply, = profile.handler.handle(device, packet(device, {}, plaintext=plain))
    assert peer_reply(reply, device.key)[1]["p"] == [1]
    before = dict(device.state)
    for plain in (b'{\"t\":\"cmd\",\"opt\":[\"Pow\"],\"p\":[true]}',
                  b'{\"t\":\"cmd\",\"opt\":[\"Pow\",\"SetTem\"],\"p\":[1e3,2]}'):
        with pytest.raises(InvalidPacket):
            profile.handler.handle(device, packet(device, {}, plaintext=plain))
    assert device.state == before
    assert send({"t": "upgrade", "url": "https://example.invalid/fw"}) == [
        {"t": "ret", "r": 200}]
    assert device.state["_wb_ota_queue"] == {"url": "https://example.invalid/fw"}

    timer = {"id": 3, "name": "night", "enable": 1, "tz": 0, "hr": 19,
             "min": 30, "sec": 45, "week": [1, 0, 1, 0, 0, 0, 0],
             "cmd": [{"opt": ["Pow"], "p": [1]}]}
    before = dict(device.state)
    with pytest.raises(InvalidPacket):
        send({"t": "setT", **{**timer, "id": 5, "week": [True] * 7}})
    assert device.state == before
    assert send({"t": "setT", **timer}) == [{"t": "resT", "r": 200}]
    timer_default_sec = {**timer, "id": 4, "name": "default-sec", "week": [0] * 7}
    timer_default_sec.pop("sec")
    assert send({"t": "setT", **timer_default_sec}) == [{"t": "resT", "r": 200}]
    listed = send({"t": "queryT", "index": 0, "count": 10})[0]
    assert listed["total"] == 2 and listed["list"][0]["week"] == [1, 0, 1, 0, 0, 0, 0]
    assert listed["list"][0]["sec"] == 45 and listed["list"][1]["sec"] == 0
    assert send({"t": "updateT", **{**timer, "name": "evening", "sec": 12}}) == [
        {"t": "resT", "r": 200}]
    assert send({"t": "queryT", "index": 0, "count": 1})[0]["list"] == []
    assert send({"t": "queryT", "index": 3, "count": 1})[0]["list"][0]["name"] == "evening"
    assert send({"t": "deleteT", "id": 259}) == [{"t": "resT", "r": 200}]
    assert send({"t": "deleteT", "id": 4}) == [{"t": "resT", "r": 200}]
    assert send({"t": "queryT", "index": 0, "count": 10})[0]["list"] == []

    assert send({"t": "dump", "period": 3, "cnt": 0}) == [{"t": "ret", "r": 200}]
    assert device.state["_wb_dump"] == {"period": 5, "cnt": 1}
    assert send({"t": "ReportCtrl"}) == []
    assert device.state["_wb_report_active_word"] == 16684
    assert device.state["_wb_reporting"]["request"] == {"ReportInterval": 10, "ActiveTime": 5}
    assert send({"t": "ReportCtrl", "ActiveTime": 7, "ReportInterval": 13,
                 "reportAnyway": True}) == []
    assert device.state["_wb_report_active_word"] == 16804
    assert device.state["_wb_reporting"]["request"] == {"ReportInterval": 13, "ActiveTime": 7}
    assert device.state["_wb_report_state"] == 2
    assert send({"t": "ReportCtrl", "ActiveTime": "bad", "ReportInterval": None,
                 "reportAnyway": None}) == []
    assert device.state["_wb_report_active_word"] == 16804
    assert device.state["_wb_reporting"]["request"] == {"ReportInterval": 13, "ActiveTime": 7}
    assert device.state["_wb_report_state"] == 2
    raw_frame = bytes.fromhex("7e7e0601020304af")
    frame = base64.b64encode(raw_frame).decode("ascii")
    assert send({"t": "binCmd", "hex01": frame, "ReportClientID": "home/abc",
                 "ReportFreq": 255}) == [{"t": "res", "r": 200}]
    assert device.state["_wb_uart_frame"] == list(raw_frame)
    assert device.state["_wb_report_client"] == "home/abc"
    assert device.state["_wb_report_client_set"] == 1
    assert device.state["_wb_report_frequency"] == 300
    client_frame = bytearray(30)
    client_frame[:4] = b"~~\x12\x6a"
    client_frame[4:12] = b"home/abc"
    assert device.state["_wb_report_client_frame"] == list(client_frame)
    for frequency, expected, word in ((0, 0, 16384), (17, 17, 16401),
                                      (65536, 0, 16384), (-1, 65535, 16383)):
        assert send({"t": "binCmd", "hex15": frame, "ReportFreq": frequency}) == [
            {"t": "res", "r": 200}]
        assert device.state["_wb_report_frequency"] == expected
        assert device.state["_wb_report_frequency_word"] == word
    _, unchanged = wb_rt13.wb_operations.operation(
        device, {"t": "binCmd", "hex01": frame, "ReportFreq": 65535})
    assert "_wb_report_frequency" not in unchanged
    long_client = "x" * 26
    assert send({"t": "binCmd", "hex15": frame, "ReportClientID": long_client}) == [
        {"t": "res", "r": 200}]
    assert device.state["_wb_report_client"] == long_client
    assert device.state["_wb_report_client_frame"][4:] == [ord("x")] * 26
    before = dict(device.state)
    with pytest.raises(InvalidPacket):
        send({"t": "binCmd", "hex15": frame, "ReportClientID": long_client + "x"})
    assert device.state == before
    before = dict(device.state)
    with pytest.raises(InvalidPacket):
        send({"t": "binCmd", "hex01": "not base64"})
    assert device.state == before
    assert send({"t": "reset", "mac": "020000000099"}) == [{}]
    assert device.state["_wb_reset_flag"] == 1
    device.state["_wb_reset_flag"] = 0
    before = dict(device.state)
    assert send({"t": "reset", "mac": device.mac}) == []
    assert device.state == {**before, "_wb_reset_flag": 1}
    assert send({"t": "Ackup"}) == []

@pytest.mark.parametrize("profile", PROFILES, ids=lambda profile: profile.id)
def test_unknown_status_and_unsupported_operation(profile, monkeypatch):
    monkeypatch.setattr(wb_rt13, "monotonic", lambda: 1000)
    device = device_for(profile)
    reply, = profile.handler.handle(device, packet(device, {"t": "status", "cols": ["unknown"]}))
    assert peer_reply(reply, device.key)[1] == {"t": "dat", "uid": 0, "mac": device.mac,
                                                "cid": device.mac, "dat": [], "cols": [], "r": 200}
    assert profile.handler.handle(device, packet(device, {"t": "subDev"})) == []


@pytest.mark.parametrize("profile", PROFILES, ids=lambda profile: profile.id)
def test_targets_devices_and_keys_are_isolated(profile, monkeypatch):
    monkeypatch.setattr(wb_rt13, "monotonic", lambda: 1000)
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
    monkeypatch.setattr(wb_rt13, "monotonic", lambda: 1000)
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
