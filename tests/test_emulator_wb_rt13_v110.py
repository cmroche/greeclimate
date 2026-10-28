"""Exact-source bounded WB05RT13 V1.10 wire and operation model."""

import base64
import json
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles import wb_rt13_v110 as wb
from gree_emulator.wire import InvalidPacket, encode_reply


SOURCE = json.loads((Path(__file__).parent / "fixtures" / "emulator"
                     / "wb-rt13-v110-source_research.json").read_text())
GENERIC = SOURCE["generic_key"].encode("ascii")
KEY = b"0123456789abcdef"
MAC = "020000000001"


def device_for(profile=None):
    profile = profile or wb.PROFILES[0]
    device = EmulatedDevice("office", MAC, "Emulator Office", SOURCE["mids"][0], KEY,
                            profile, dict(profile.initial_state), last_step=1000)
    profile.handler.encode_room(device)
    return device


def packet(device, inner, *, index=0, uid=42, peer="app", key=None, plaintext=None):
    plain = (plaintext if plaintext is not None else
             json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode())
    cipher = AES.new(key or (GENERIC if index else device.key), AES.MODE_ECB)
    return {"t": "pack", "i": index, "uid": uid, "cid": peer, "tcid": device.mac,
            "pack": base64.b64encode(cipher.encrypt(pad(plain, AES.block_size))).decode("ascii")}


def peer_reply(reply, key):
    outer = json.loads(encode_reply(reply))
    assert "tag" not in outer
    encrypted = base64.b64decode(outer["pack"], validate=True)
    plain = unpad(AES.new(key, AES.MODE_ECB).decrypt(encrypted), AES.block_size)
    return outer, json.loads(plain)


def exchange(device, inner, *, index=0, uid=42, peer="app"):
    return device.profile.handler.handle(device, packet(device, inner, index=index,
                                                         uid=uid, peer=peer))


def test_v110_fault_display_getter_does_not_admit_v104_mota():
    device = device_for()
    reply, = exchange(device, {"t": "status", "cols": ["FaultDisplay", "MOta"]})
    assert peer_reply(reply, KEY)[1]["dat"] == [""]
    assert peer_reply(reply, KEY)[1]["cols"] == ["FaultDisplay"]


@pytest.mark.parametrize("index", [0, 1])
def test_pack_and_reply_use_source_ecb_pkcs7_key_selector(index):
    device = device_for()
    replies = exchange(device, {"t": "bind"}, index=index)
    assert len(replies) == 1
    outer, inner = peer_reply(replies[0], GENERIC if index else KEY)
    assert outer == {"t": "pack", "i": index, "uid": 42, "cid": MAC, "tcid": "app",
                     "pack": outer["pack"]}
    assert inner == {"r": 200, "t": "bindok", "mac": MAC, "key": KEY.decode("ascii")}
    assert len(base64.b64decode(outer["pack"], validate=True)) % AES.block_size == 0
    assert not hasattr(replies[0], "tag")


def test_discovery_uses_ecb_wrapper_and_conditional_case4_mid():
    device = device_for()
    reply, = device.profile.handler.advertise(device, {"t": "scan"})
    outer, inner = peer_reply(reply, GENERIC)
    assert outer == {"t": "pack", "i": 1, "uid": 0, "cid": "", "tcid": "",
                     "pack": outer["pack"]}
    assert inner == {"t": "dev", "cid": MAC, "bc": "", "brand": "gree", "catalog": "gree",
                     "mac": MAC, "mid": "10001", "model": "gree",
                     "name": "Emulator Office", "lock": 0, "series": "gree",
                     "vender": "1", "ver": "V1.10"}
    assert set(inner) == set(SOURCE["scan_fields"]) | {"t"}
    assert "hid" not in inner

    device.mid = ""
    fallback, = device.profile.handler.advertise(device, {"t": "scan"})
    assert peer_reply(fallback, GENERIC)[1]["mid"] == "10001"


def test_status_getter_does_not_substitute_discovery_dev_mid():
    device = device_for()
    reply, = exchange(device, {"t": "status", "cols": ["mid", "Pow"]})
    outer, inner = peer_reply(reply, KEY)
    assert outer["tcid"] == "app" and outer["cid"] == MAC
    assert inner == {"t": "dat", "uid": 42, "mac": MAC, "cid": MAC,
                     "dat": ["", 0], "cols": ["mid", "Pow"], "r": 200}
    read, = exchange(device, {"t": "cmd", "cols": ["mid"]})
    assert peer_reply(read, KEY)[1] == {
        "t": "res", "mac": MAC, "p": [""], "opt": ["mid"], "r": 200}
    scan, = device.profile.handler.advertise(device, {"t": "scan"})
    assert peer_reply(scan, GENERIC)[1]["mid"] == "10001"
    assert SOURCE["metadata_mid_pointer"] != SOURCE["discovery_mid_buffer"]


def test_bind_command_and_status_ack_effects_are_bounded_and_atomic():
    device = device_for()
    before = dict(device.state)
    bind, = exchange(device, {"t": "bind", "mac": ["invalid"]})
    assert peer_reply(bind, KEY)[1]["mac"] == MAC
    bind, = exchange(device, {"t": "bind", "mac": "not-a-mac"})
    assert peer_reply(bind, KEY)[1]["mac"] == "not-a-mac"
    assert device.state == before

    command = {"t": "cmd", "opt": ["Pow", "SetTem"], "p": [1, 65537]}
    reply, = exchange(device, command, index=1, uid=9, peer="client")
    outer, inner = peer_reply(reply, GENERIC)
    assert outer == {"t": "pack", "i": 1, "uid": 9, "cid": MAC, "tcid": "client",
                     "pack": outer["pack"]}
    assert inner == {"t": "res", "mac": MAC, "p": [1, 65537],
                     "opt": ["Pow", "SetTem"], "r": 200}
    assert device.state["Pow"] == 1 and device.state["SetTem"] == 1

    status, = exchange(device, {"t": "status", "cols": ["Pow", "SetTem"]})
    assert peer_reply(status, KEY)[1]["dat"] == [1, 1]
    read, = exchange(device, {"t": "cmd", "cols": ["Pow", "SetTem"]})
    assert peer_reply(read, KEY)[1]["p"] == [1, 1]
    empty_status, = exchange(device, {"t": "status", "opt": [], "p": []})
    assert peer_reply(empty_status, KEY)[1]["dat"] == []
    empty_command, = exchange(device, {"t": "cmd", "opt": [], "p": []})
    assert peer_reply(empty_command, KEY)[1]["p"] == []
    before = dict(device.state)
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "cmd", "opt": ["Pow"], "p": [True]})
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "status", "opt": ["Pow"]})
    assert device.state == before


def test_native_numeric_tokens_use_decimal_prefix_and_reject_booleans():
    device = device_for()
    plain = b'{\"t\":\"cmd\",\"opt\":[\"Pow\"],\"p\":[1.9]}'
    reply, = device.profile.handler.handle(device, packet(device, {}, plaintext=plain))
    assert peer_reply(reply, KEY)[1]["p"] == [1]
    assert device.state["Pow"] == 1

    # The native decimal reader stops at e; a singleton numeric field consumes its prefix.
    plain = b'{\"t\":\"cmd\",\"opt\":[\"Pow\"],\"p\":[1e3]}'
    reply, = device.profile.handler.handle(device, packet(device, {}, plaintext=plain))
    assert peer_reply(reply, KEY)[1]["p"] == [1]
    assert device.state["Pow"] == 1

    before = dict(device.state)
    for plain in (b'{\"t\":\"cmd\",\"opt\":[\"Pow\"],\"p\":[true]}',
                  b'{\"t\":\"cmd\",\"opt\":[\"Pow\",\"SetTem\"],\"p\":[1e3,2]}'):
        with pytest.raises(InvalidPacket):
            device.profile.handler.handle(device, packet(device, {}, plaintext=plain))
    assert device.state == before


def test_timer_boolean_numeric_parse_failure_still_mutates_partial_record():
    device = device_for()
    timer = _timer(3)
    timer["week"] = [True, False, 1, 0, 0, 0, 0]
    reply, = exchange(device, timer)
    assert peer_reply(reply, KEY)[1] == {"t": "resT", "r": 200}
    row, = peer_reply(exchange(device, {"t": "queryT", "index": 3, "count": 1})[0], KEY)[1]["list"]
    assert row["week"] == [0] * 7 and row["hr"] == 1 and row["min"] == 2

def _timer(identifier, name="timer"):
    return {"t": "setT", "id": identifier, "name": name, "enable": 1, "tz": 0,
            "hr": 257, "min": 258, "sec": 59,
            "week": [1, 0, 1, 0, 0, 0, 0],
            "cmd": [{"opt": ["Pow"], "p": [257]}]}


def test_all_timer_operations_ack_effects_and_ignored_parser_failure():
    device = device_for()
    assert peer_reply(exchange(device, _timer(257))[0], KEY)[1] == {"t": "resT", "r": 200}
    before = dict(device.state)
    with pytest.raises(InvalidPacket):
        exchange(device, _timer(257))
    assert device.state == before
    assert peer_reply(exchange(device, {"t": "setT", "id": 2, "name": "partial"})[0], KEY)[1] == {
        "t": "resT", "r": 200}
    assert device.state["_wb_timer_count"] == 2

    listed = exchange(device, {"t": "queryT", "index": 0, "count": 10})[0]
    query = peer_reply(listed, KEY)[1]
    assert query == {"t": "listT", "total": 2, "index": 0, "list": [
        {"id": 1, "name": "timer", "enable": 1, "week": [1, 0, 1, 0, 0, 0, 0],
         "hr": 1, "min": 2, "sec": 59,
         "cmd": {"mac": [MAC], "opt": ["Pow"], "p": [1]}},
        {"id": 2, "name": "partial", "enable": 0, "week": [0] * 7,
         "hr": 0, "min": 0, "sec": 0,
         "cmd": {"mac": [MAC], "opt": ["Pow"], "p": [0]}}]}

    # V1.10 ignores the shared-parser error and still calls updateT's mutator.
    update, = exchange(device, {"t": "updateT", "id": 257, "name": "updated"})
    assert peer_reply(update, KEY)[1] == {"t": "resT", "r": 200}
    updated = peer_reply(exchange(device, {"t": "queryT", "index": 1, "count": 1})[0], KEY)[1]
    assert updated["list"][0]["name"] == "updated"
    assert updated["list"][0]["enable"] == 0

    deleted, = exchange(device, {"t": "deleteT", "id": 257})
    assert peer_reply(deleted, KEY)[1] == {"t": "resT", "r": 200}
    remaining = peer_reply(exchange(device, {"t": "queryT", "index": 0, "count": 10})[0], KEY)[1]
    assert remaining["total"] == 1 and [row["id"] for row in remaining["list"]] == [2]


def test_upgrade_dump_and_operation_error_paths():
    device = device_for()
    upgrade, = exchange(device, {"t": "upgrade", "url": "https://example.invalid/fw.bin"})
    assert peer_reply(upgrade, KEY)[1] == {"t": "ret", "r": 200}
    assert device.state["_wb_upgrade_url"] == "https://example.invalid/fw.bin"

    dump, = exchange(device, {"t": "dump", "period": 2, "cnt": 0})
    assert peer_reply(dump, KEY)[1] == {"t": "ret", "r": 200}
    assert device.state["_wb_dump"] == {"period": 5, "cnt": 1, "enabled": True}

    for operation in ({"t": "upgrade"}, {"t": "upgrade", "url": "x" * 120},
                      {"t": "queryT", "index": 0}, {"t": "deleteT"},
                      {"t": "setT", "name": "missing-id"}, {"t": "dump", "period": 1}):
        with pytest.raises(InvalidPacket):
            exchange(device, operation)

    for identifier in range(10):
        assert exchange(device, {"t": "setT", "id": identifier, "name": "timer"})
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "setT", "id": 11, "name": "full"})


def test_source_reply_buffer_limit_is_enforced():
    device = device_for()
    with pytest.raises(InvalidPacket, match="0x5b4-byte source buffer"):
        wb._reply(device, {"t": "res", "payload": "x" * 1400}, 0, 0, "app")


def test_opt_mode_mutates_exact_local_and_raw_selectors():
    device = device_for()
    status, = exchange(device, {"t": "status", "opt": ["time", "Pow"],
                                "p": ["2024-01-02 03:04:05", 8]})
    assert peer_reply(status, KEY)[1]["dat"] == ["2024-01-02 03:04:05", 8]
    assert device.state["_wb_time"] == "2024-01-02 03:04:05"
    assert device.state["Pow"] == 8

    client, = exchange(device, {"t": "cmd", "opt": ["ReportClientID"], "p": ["room-1"]})
    client_ack = peer_reply(client, KEY)[1]
    assert client_ack["opt"] == ["ReportClientID"] and client_ack["p"] == []
    assert device.state["_wb_report_client_target"] == (
        b"\x7e\x7e\x12\x6aroom-1" + bytes(20))
    assert device.state["_wb_report_client_enabled"] == 1
    client_status, = exchange(device, {"t": "status", "cols": ["ReportClientID"]})
    assert peer_reply(client_status, KEY)[1]["cols"] == []
    assert peer_reply(client_status, KEY)[1]["dat"] == []
    numeric_reply, = exchange(
        device, {"t": "cmd", "opt": ["FaultDisplay", "ver", "vender"], "p": [6, 7, 8]})
    assert peer_reply(numeric_reply, KEY)[1]["p"] == [6, 7, 8]
    text_reply, = exchange(
        device, {"t": "status", "cols": ["FaultDisplay", "ver", "vender"]})
    assert peer_reply(text_reply, KEY)[1]["dat"] == ["", "", ""]

    before = dict(device.state)
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "cmd", "opt": ["ReportClientID"], "p": ["x" * 27]})
    assert device.state == before
