"""Independent raw-peer W06KV host transactions and deliberate model boundaries."""

import asyncio
import base64
from copy import deepcopy
import json
from pathlib import Path
import socket

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.catalog_realtek_late import PROFILES, SENSORS
from gree_emulator.profiles.hb import PROFILES as HB_PROFILES
from gree_emulator.server import start_server
from gree_emulator.wire import InvalidPacket, encode_reply
from greeclimate.device_factory import create_device
from greeclimate.deviceinfo import DeviceInfo

FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-realtek-late-w06k-vectors_research.json").read_text())
KEY = b"a3K8Bx%2r8Y7#xDh"


def device(mid="80241"):
    profile, = PROFILES
    return EmulatedDevice("host", FIXTURE["mac"], "", mid,
                          FIXTURE["session_key"].encode(), profile,
                          dict(profile.initial_state), room_c=None, ambient_c=None,
                          last_step=1000)


def request(unit, inner, *, index=0, uid=42, target=None):
    key = KEY if index & 255 else unit.key
    body = AES.new(key, AES.MODE_ECB).encrypt(pad(json.dumps(inner, separators=(",", ":")).encode(), 16))
    return {"t": "pack", "i": index, "uid": uid, "cid": "app", "tcid": target or unit.mac,
            "pack": base64.b64encode(body).decode()}


def decode(reply):
    raw = encode_reply(reply)
    assert not raw.endswith(b"\n")
    outer = json.loads(raw)
    key = KEY if outer["i"] else FIXTURE["session_key"].encode()
    inner = json.loads(unpad(AES.new(key, AES.MODE_ECB).decrypt(base64.b64decode(outer["pack"])), 16))
    return outer, inner


def exchange(unit, inner, **kwargs):
    reply, = unit.profile.handler.handle(unit, request(unit, inner, **kwargs))
    return decode(reply)


@pytest.mark.parametrize("mid", ["80241", "80242"])
def test_literal_full_wire_transactions_and_fresh_status(mid):
    unit = device(mid)
    for vector in FIXTURE["vectors"]:
        replies = unit.profile.handler.handle(unit, request(unit, vector["request"]))
        if vector["response"] is None:
            assert replies == []
        else:
            reply, = replies
            outer, inner = decode(reply)
            assert inner == vector["response"]
            assert outer["i"] == vector["reply_selector"]
            assert outer["cid"] == unit.mac and outer["tcid"] == "app" and outer["uid"] == 42


def test_every_known_raw_sensor_width_and_metadata_are_separate():
    unit = device()
    fields = list(SENSORS)
    _, ack = exchange(unit, {"t": "cmd", "opt": fields, "p": [-1] * len(fields)})
    assert ack == {"t": "res", "r": 200, "opt": fields,
                   "p": [-1] * len(fields), "val": [-1] * len(fields), "mac": unit.mac}
    _, status = exchange(unit, {"t": "status", "cols": fields})
    assert status["dat"] == [255, 255, 255, 255, 65535, 65535, 65535, 65535,
                             65535, 65535, 255, 255, 255]
    assert unit.room_c is None and unit.profile.handler.thermal_target(unit) is None


@pytest.mark.parametrize("inner", [
    {"t": "status", "cols": ["TemSen"]},
    {"t": "status", "cols": ["SwUpDn"]},
    {"t": "cmd", "opt": ["Pow", "Buzzer_ON_OFF"], "p": [1, 0]},
    {"t": "cmd", "opt": ["Pow", "TemSor"], "p": [1]},
    {"t": "cmd", "opt": ["Pow"], "p": [True]},
    {"t": "cmd", "opt": ["Pow"], "p": [1.0]},
    {"t": "status", "cols": ["Pow"], "sub": "020000000042"},
])
def test_invalid_batches_do_not_change_cache_clock_or_metadata(inner):
    unit = device()
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        unit.profile.handler.handle(unit, request(unit, inner))
    assert unit.state == before and unit.last_step == 1000


def test_root_identity_not_downstream_alias_and_wrong_key_is_rejected():
    unit = device()
    inner = {"t": "status", "cols": ["Pow"], "mac": "020000000042"}
    with pytest.raises(InvalidPacket):
        exchange(unit, inner)
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "bind", "mac": unit.mac}, target="020000000042")
    outer = request(unit, {"t": "status", "cols": ["Pow"]})
    outer["i"] = 1
    with pytest.raises(InvalidPacket):
        unit.profile.handler.handle(unit, outer)


def test_low_byte_session_selector_and_rebind_preserve_board_state():
    unit = device()
    exchange(unit, {"t": "cmd", "opt": ["Pow"], "p": [7]}, index=256)
    _, bound = exchange(unit, {"t": "bind", "mac": unit.mac}, index=-1)
    assert bound["key"] == FIXTURE["session_key"]
    _, status = exchange(unit, {"t": "status", "cols": ["Pow"]}, index=256)
    assert status["dat"] == [7]
    other = device()
    _, fresh = exchange(other, {"t": "status", "cols": ["Pow"]})
    assert fresh["dat"] == [0]


def test_timer_create_query_remove_with_native_window_and_shape():
    unit = device()
    record = {"t": "setT", "ManageType": 0, "id": 1, "enable": 1, "hr": 8,
              "min": 30, "sec": 0, "tz": 0, "week": [1, 0, 0, 0, 0, 0, 0],
              "cmd": [{"mac": [unit.mac], "BrdNum": 1, "BrdContent": [7]}]}
    _, ack = exchange(unit, record)
    assert ack == {"t": "resT", "r": 200}
    _, listed = exchange(unit, {"t": "queryT", "index": 0, "count": 3})
    assert listed["total"] == 1 and listed["list"][0]["cmd"][0]["BrdContent"] == [7]
    assert set(listed["list"][0]) == {"id", "enable", "hr", "min", "week", "cmd"}
    assert listed["list"][0]["cmd"][0]["mac"] == [unit.mac]
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "queryT", "index": 2, "count": 2})
    assert unit.state == before
    exchange(unit, {"t": "deleteT", "id": 1})
    _, listed = exchange(unit, {"t": "queryT", "index": 0, "count": 3})
    assert listed == {"t": "listT", "total": 0, "index": 0, "list": []}


def test_unqualified_timer_board_translation_never_invents_success():
    unit = device()
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "updateT", "id": 0, "name": "", "enable": 1, "hr": 8,
                        "min": 30, "sec": 0, "tz": 0, "week": [],
                        "cmd": [{"mac": [unit.mac], "opt": ["Mod"], "p": [1]}]})
    assert unit.state == before


def test_metadata_name_bug_is_distinct_from_scan_name_and_ack_value():
    unit = device()
    _, ack = exchange(unit, {"t": "cmd", "opt": ["name", "host", "lock"],
                            "p": ["renamed", "x" * 20, -1]})
    assert ack["p"] == [unit.mac, "x" * 20, -1]
    assert ack["val"] == ["renamed", "x" * 20, -1]
    _, status = exchange(unit, {"t": "status", "cols": ["name", "host", "lock", "rssi"]})
    assert status["dat"] == [unit.mac, "x" * 20, -1, -1]
    scan = unit.profile.handler.advertise(unit, {"t": "scan"})[0]
    assert scan.inner["name"] == "renamed"


def test_plaintext_network_acceptance_and_time_do_not_fake_a_radio_join():
    unit = device()
    replies = unit.profile.handler.wlan(unit, {
        "t": "wlan", "ssid": "test-network", "psw": "not-persisted", "host": "",
    })
    assert [json.loads(encode_reply(reply)) for reply in replies] == [
        {"t": "ret", "r": 200, "mac": unit.mac},
    ]
    assert "not-persisted" not in json.dumps(unit.state)
    assert unit.profile.handler.hbok(unit, {"t": "hbok"}) == []
    assert unit.profile.handler.tm(unit, {"t": "tm", "time": "2026-10-23 12:34:56"}) == []
    _, status = exchange(unit, {"t": "status", "cols": ["host", "time"]})
    assert status["dat"] == ["dis.gree.com", "2026-10-23 12:34:56"]


@pytest.mark.parametrize("name", (
    "Pow", "Blo", "SwhSlp", "Air", "SvSt", "Quiet", "Tur", "HeatCoolType",
    "Mod", "SetTem", "HeatSvStTemMax", "CoolSvStTemMin", "WdSpd", "SwUpDn",
    "SwingLfRig", "AllErr", "TemUn", "TemRec", "SlpMod", "TemRecH", "TemRecC",
    "WifiOff", "WifiRest", "AutoSetTem", "RemoteLock", "APPNotCtrl", "LowDeHumi",
    "Omod", "Demand", "Tcloud", "AppTimer", "ElcErg", "ElcGear", "Elc1Kwh",
    "AutoUpdate", "AutoComnCloud", "lock", "No",
))
def test_w04hb_every_literal_cache_control_uses_native_uint16_width(name):
    profile, = HB_PROFILES
    unit = EmulatedDevice("hb", FIXTURE["mac"], "", "302b",
                          FIXTURE["session_key"].encode(), profile,
                          dict(profile.initial_state), last_step=1000)
    _, ack = exchange(unit, {"t": "cmd", "opt": [name, name], "p": [65536, -1]})
    assert ack["opt"] == [name, name] and ack["p"] == [65536, -1]
    _, fresh = exchange(unit, {"t": "status", "cols": [name, name, "TemSen"]})
    assert fresh["cols"] == [name, name] and fresh["dat"] == [65535, 65535]
    before, clock = deepcopy(unit.state), unit.last_step
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "cmd", "opt": [name, name], "p": [1, True]})
    assert unit.state == before and unit.last_step == clock


def test_w06kv_native_full_name_window_clears_reply_columns():
    unit = device()
    _, status = exchange(unit, {"t": "status", "cols": ["hid"] * 50})
    assert status == {"t": "dat", "r": 200, "cols": [], "dat": [], "mac": unit.mac}
    _, ack = exchange(unit, {"t": "cmd", "opt": ["Pow"] * 50, "p": [1] * 50})
    assert ack == {"t": "res", "r": 200, "opt": [], "p": [], "val": [], "mac": unit.mac}
    _, fresh = exchange(unit, {"t": "status", "cols": ["Pow"]})
    assert fresh["dat"] == [1]


def test_w04hb_metadata_preserves_native_zero_item_columns_and_local_strings():
    profile, = HB_PROFILES
    unit = EmulatedDevice("hb", FIXTURE["mac"], "HB name", "302b",
                          FIXTURE["session_key"].encode(), profile,
                          dict(profile.initial_state), last_step=1000)
    _, metadata = exchange(unit, {"t": "status", "cols": [
        "apssid", "hid", "model", "mac", "name", "vender", "rssi",
    ]})
    assert metadata["cols"] == ["apssid", "hid", "model", "mac", "name", "vender", "rssi"]
    assert metadata["dat"] == ["362001063384+U-W04HBV1.20.bin", unit.mac, "HB name", "", 0]
    _, ack = exchange(unit, {"t": "cmd", "opt": ["host", "name", "lat", "lon"],
                            "p": ["dis.gree.com", "renamed", "12.5", "-8.25"]})
    assert ack["p"] == ["dis.gree.com", "renamed", "12.5", "-8.25"]
    _, metadata = exchange(unit, {"t": "status", "cols": ["host", "name", "lat", "lon", "InHid"]})
    assert metadata["cols"] == ["host", "name", "lat", "lon", "InHid"]
    assert metadata["dat"] == ["dis.gree.com", "renamed", "12.5", "-8.25"]


def test_w06kv_timer_list_uses_shared_board_content_without_mutating_records():
    unit = device()
    for timer_id, size, content in ((0, 2, [7, 8, 9]), (1, 3, [1, 2, 3])):
        exchange(unit, {"t": "setT", "ManageType": 0, "id": timer_id,
                        "enable": 1, "hr": 8, "min": 30, "sec": 0, "tz": 0,
                        "week": [], "cmd": [{"mac": [unit.mac], "BrdNum": size,
                                            "BrdContent": content}]})
    _, listed = exchange(unit, {"t": "queryT", "index": 0, "count": 2})
    assert [record["cmd"][0] for record in listed["list"]] == [
        {"mac": [unit.mac], "BrdNum": 2, "BrdContent": [7, 8]},
        {"mac": [unit.mac], "BrdNum": 3, "BrdContent": [7, 8, 9]},
    ]
    _, single = exchange(unit, {"t": "queryT", "index": 1, "count": 1})
    assert single["list"][0]["cmd"][0]["BrdContent"] == [1, 2, 3]


@pytest.mark.parametrize("mid", ["3018", "302b"])
def test_w04hb_mid_metadata_is_not_synthesized_from_discovery_mid(mid):
    profile, = HB_PROFILES
    unit = EmulatedDevice("hb", FIXTURE["mac"], "", mid,
                          FIXTURE["session_key"].encode(), profile,
                          dict(profile.initial_state), last_step=1000)
    _, metadata = exchange(unit, {"t": "status", "cols": ["mid", "model", "mid"]})
    assert metadata["cols"] == ["mid", "model", "mid"] and metadata["dat"] == ["", ""]
    assert unit.profile.handler.advertise(unit, {"t": "scan"})[0].inner["mid"] == mid


def test_w06kv_metadata_last_zeroes_scratch_without_zeroing_sensor_cache():
    unit = device()
    exchange(unit, {"t": "cmd", "opt": ["Pow", "TemSor"], "p": [7, 25]})
    _, mixed = exchange(unit, {"t": "status", "cols": ["Pow", "hid", "TemSor", "name"]})
    assert mixed["dat"] == [0, "362001061649+U-W06KV4.4.bin", 0, unit.mac]
    _, sensors = exchange(unit, {"t": "status", "cols": ["Pow", "TemSor"]})
    assert sensors["dat"] == [7, 25]
    _, mixed = exchange(unit, {"t": "status", "cols": ["hid", "Pow"]})
    assert mixed["dat"] == ["362001061649+U-W06KV4.4.bin", 7]


def test_w06kv_empty_status_has_no_native_getter_reply():
    unit = device()
    before = deepcopy(unit.state)
    assert unit.profile.handler.handle(unit, request(unit, {"t": "status", "cols": []})) == []
    assert unit.state == before and unit.last_step == 1000


def test_w04hb_every_metadata_column_retains_native_append_cardinality(monkeypatch):
    monkeypatch.setattr("gree_emulator.profiles.hb.monotonic", lambda: 42)
    profile, = HB_PROFILES
    unit = EmulatedDevice("hb", FIXTURE["mac"], "HB", "302b",
                          FIXTURE["session_key"].encode(), profile,
                          dict(profile.initial_state), last_step=42)
    columns = [
        "apssid", "appsw", "host", "name", "time", "lat", "lon", "rssi",
        "vender", "bc", "mid", "model", "series", "brand", "catalog", "country",
        "hid", "mac", "ver", "HidSvrVer", "InHid", "InHidSvrVer",
        "OEEPHid", "OEEPHidSvrVer",
    ]
    _, status = exchange(unit, {"t": "status", "cols": columns})
    assert status["cols"] == columns
    assert status["dat"] == [
        "", "HB", "2026-01-01 00:00:00", "", "", 0, "", "", "",
        "362001063384+U-W04HBV1.20.bin", unit.mac, "",
    ]


async def test_w06kv_plaintext_operations_reach_actual_udp_dispatch_without_tcid():
    unit = device()
    transport, server = await start_server([unit], "127.0.0.1", 0)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.settimeout(0.5)
            endpoint = transport.get_extra_info("sockname")
            peer.sendto(b'{"t":"wlan","ssid":"test","psw":"not-persisted","host":"lan.example"}', endpoint)
            raw, _ = await asyncio.to_thread(peer.recvfrom, 4096)
            assert json.loads(raw) == {"t": "ret", "r": 200, "mac": unit.mac}
            peer.sendto(b'{"t":"hbok"}', endpoint)
            peer.sendto(b'{"t":"tm","time":"2026-10-24 12:34:56"}', endpoint)
            peer.sendto(json.dumps(request(unit, {"t": "status", "cols": ["host", "time"]})).encode(), endpoint)
            raw, _ = await asyncio.to_thread(peer.recvfrom, 4096)
            outer = json.loads(raw)
            inner = json.loads(unpad(AES.new(unit.key, AES.MODE_ECB).decrypt(
                base64.b64decode(outer["pack"])), 16))
            assert inner == {"t": "dat", "r": 200, "cols": ["host", "time"],
                             "dat": ["lan.example", "2026-10-24 12:34:56"], "mac": unit.mac}
            assert "not-persisted" not in json.dumps(unit.state)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.parametrize("mid", ["80241", "80242"])
async def test_client_initial_sensor_poll_preserves_board_values(mid):
    unit = device(mid)
    fields = ["Pow", "TemSor", "CO2"]
    exchange(unit, {"t": "cmd", "opt": fields, "p": [1, 250, 1200]})
    transport, server = await start_server([unit], "127.0.0.1", 0)
    host, port = transport.get_extra_info("sockname")
    client = create_device(DeviceInfo(host, port, unit.mac, "Host", mid=mid), bind_timeout=1)
    try:
        await client.bind()
        await asyncio.wait_for(client._valid_state.wait(), 1)
        assert [client.get_property(name) for name in fields] == [1, 250, 1200]
        assert client.hid == "362001061649+U-W06KV4.4.bin"
        client._valid_state.clear()
        exchange(unit, {"t": "cmd", "opt": fields, "p": [0, 251, 1201]})
        await client.update_state()
        await asyncio.wait_for(client._valid_state.wait(), 1)
        assert [client.get_property(name) for name in fields] == [0, 251, 1201]
    finally:
        client.close()
        server.close()
        await server.wait_closed()
