"""Exact-source bounded WB05RT13 V1.04 wire and operation model."""

import base64
import json
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles import wb_rt13_v104 as wb
from gree_emulator.wire import InvalidPacket, encode_reply


SOURCE = json.loads((Path(__file__).parent / "fixtures" / "emulator"
                     / "wb-rt13-v104-source_research.json").read_text())
GENERIC = SOURCE["generic_key"].encode("ascii")
KEY = b"0123456789abcdef"
MAC = "020000000001"


def device_for():
    profile, = wb.PROFILES
    device = EmulatedDevice("office", MAC, "Emulator Office", SOURCE["mids"][0], KEY,
                            profile, dict(profile.initial_state), last_step=1000)
    profile.handler.encode_room(device)
    return device


def packet(device, inner, *, index=0, uid=42, peer="app", plaintext=None):
    plain = (plaintext if plaintext is not None else
             json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode())
    key = GENERIC if index else device.key
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(plain, AES.block_size))
    return {"t": "pack", "i": index, "uid": uid, "cid": peer, "tcid": device.mac,
            "pack": base64.b64encode(encrypted).decode("ascii")}


def peer_reply(reply, key):
    outer = json.loads(encode_reply(reply))
    assert "tag" not in outer
    cipher = base64.b64decode(outer["pack"], validate=True)
    plain = unpad(AES.new(key, AES.MODE_ECB).decrypt(cipher), AES.block_size)
    return outer, json.loads(plain)


def exchange(device, inner, *, index=0, uid=42, peer="app"):
    return device.profile.handler.handle(
        device, packet(device, inner, index=index, uid=uid, peer=peer))


def test_v104_gates_exact_source_fields_and_empty_mota_callback():
    v110_only = (
        "CpsTem", "DFPoint", "EnergyFlow", "EnvTem", "FaultDisplay", "TemsSenOut")
    device = device_for()
    status, = exchange(device, {"t": "status", "cols": sorted(v110_only)})
    assert peer_reply(status, KEY)[1]["cols"] == []
    assert peer_reply(status, KEY)[1]["dat"] == []
    for name in sorted(v110_only):
        for kind, member in (("cmd", "cols"), ("cmd", "opt"), ("status", "opt")):
            with pytest.raises(InvalidPacket):
                exchange(device, {"t": kind, member: [name], "p": [1]})

    status, = exchange(device, {"t": "status", "cols": ["MOta"]})
    assert peer_reply(status, KEY)[1]["cols"] == ["MOta"]
    assert peer_reply(status, KEY)[1]["dat"] == []
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "cmd", "cols": ["MOta"]})


def test_scan_and_metadata_getter_use_distinct_mid_storage():
    device = device_for()
    reply, = device.profile.handler.advertise(device, {"t": "scan"})
    outer, inner = peer_reply(reply, GENERIC)
    assert outer["i"] == 1 and outer["uid"] == 0 and outer["cid"] == ""
    assert inner["mid"] == "10001" and inner["ver"] == "V1.04"
    assert "hid" not in inner
    assert set(inner) == set(SOURCE["scan_fields"]) | {"t"}

    status, = exchange(device, {"t": "status", "cols": ["mid", "hid", "Pow"]})
    assert peer_reply(status, KEY)[1]["dat"] == ["", SOURCE["metadata_hid"], 0]
    command, = exchange(device, {"t": "cmd", "cols": ["mid"]})
    assert peer_reply(command, KEY)[1]["p"] == [""]
    command, = exchange(device, {"t": "cmd", "cols": ["hid"]})
    assert peer_reply(command, KEY)[1]["p"] == [SOURCE["metadata_hid"]]


def test_v104_operations_keep_source_schema_and_timer_records_have_no_name():
    device = device_for()
    bind, = exchange(device, {"t": "bind", "mac": ["invalid"]})
    assert peer_reply(bind, KEY)[1]["mac"] == MAC

    status, = exchange(device, {"t": "status", "opt": ["time", "Pow"],
                                "p": ["2024-01-02 03:04:05", 4]})
    assert peer_reply(status, KEY)[1]["dat"] == ["2024-01-02 03:04:05", 4]
    assert device.state["Pow"] == 4 and device.state["_wb_time"] == "2024-01-02 03:04:05"

    client, = exchange(device, {"t": "cmd", "opt": ["ReportClientID"], "p": ["room-1"]})
    client_ack = peer_reply(client, KEY)[1]
    assert client_ack["opt"] == ["ReportClientID"] and client_ack["p"] == []
    assert device.state["_wb_report_client_target"] == b"~~\x12\x6aroom-1" + bytes(20)
    assert device.state["_wb_report_client_enabled"] == 1
    client_status, = exchange(device, {"t": "status", "cols": ["ReportClientID"]})
    assert peer_reply(client_status, KEY)[1]["cols"] == []
    assert peer_reply(client_status, KEY)[1]["dat"] == []
    numeric_reply, = exchange(device, {"t": "cmd", "opt": ["ver", "vender"], "p": [7, 8]})
    assert peer_reply(numeric_reply, KEY)[1]["p"] == [7, 8]
    text_reply, = exchange(device, {"t": "status", "cols": ["ver", "vender"]})
    assert peer_reply(text_reply, KEY)[1]["dat"] == ["", ""]

    timer = {"t": "setT", "id": 257, "enable": 1, "tz": 0, "hr": 10, "min": 15,
             "sec": 0, "week": [1, 0, 1, 0, 0, 0, 0],
             "cmd": [{"opt": ["Pow"], "p": [1]}]}
    added, = exchange(device, timer)
    assert peer_reply(added, KEY)[1] == {"t": "resT", "r": 200}
    listed, = exchange(device, {"t": "queryT", "index": 0, "count": 10})
    query = peer_reply(listed, KEY)[1]
    assert query["index"] == 0 and query["total"] == 1
    row, = query["list"]
    assert row == {"id": 1, "enable": 1, "week": [1, 0, 1, 0, 0, 0, 0],
                   "hr": 10, "min": 15, "sec": 0,
                   "cmd": {"mac": [MAC], "opt": ["Pow"], "p": [1]}}
    assert "name" not in row

    update, = exchange(device, {"t": "updateT", "id": 1, "enable": 0,
                                "tz": 0, "hr": 11, "min": 12, "week": [0] * 7,
                                "cmd": [{"opt": ["Pow"], "p": [0]}]})
    assert peer_reply(update, KEY)[1] == {"t": "resT", "r": 200}
    delete, = exchange(device, {"t": "deleteT", "id": 1})
    assert peer_reply(delete, KEY)[1] == {"t": "resT", "r": 200}

    upgrade, = exchange(device, {"t": "upgrade", "url": "https://example.invalid/fw.bin"})
    assert peer_reply(upgrade, KEY)[1] == {"t": "ret", "r": 200}
    assert device.state["_wb_upgrade_url"] == "https://example.invalid/fw.bin"
    dump, = exchange(device, {"t": "dump", "period": 2, "cnt": 0})
    assert peer_reply(dump, KEY)[1] == {"t": "ret", "r": 200}
    assert device.state["_wb_dump"] == {"period": 5, "cnt": 1, "enabled": True}


def test_v104_numeric_tokens_use_decimal_prefix_and_reject_booleans():
    device = device_for()
    plain = b'{\"t\":\"cmd\",\"opt\":[\"Pow\"],\"p\":[1.9]}'
    reply, = device.profile.handler.handle(device, packet(device, {}, plaintext=plain))
    assert peer_reply(reply, KEY)[1]["p"] == [1]
    assert device.state["Pow"] == 1

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
