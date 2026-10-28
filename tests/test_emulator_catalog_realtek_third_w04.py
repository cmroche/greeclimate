"""Independent literal original snapshots and explicit synthetic SDK9 policies."""
import asyncio
import base64
from copy import deepcopy
import json
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.catalog_realtek_third_w04 import KEY, PROFILES
from gree_emulator.wire import InvalidPacket, encode_reply
from gree_emulator.server import start_server
from greeclimate.device_factory import create_device
from greeclimate.deviceinfo import DeviceInfo

FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-realtek-third-w04_research.json").read_text())


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    monkeypatch.setattr("gree_emulator.profiles.catalog_realtek_third_w04.monotonic", lambda: 1000)


def device(profile=None):
    profile = profile or PROFILES[0]
    return EmulatedDevice("w04", FIXTURE["mac"], "Synthetic", profile.mids[0],
                          FIXTURE["session_key"].encode(), profile, {},
                          room_c=None, ambient_c=None, last_step=1000)


def packet(unit, inner, selector=0, key=None):
    key = (KEY if selector else unit.key) if key is None else key
    plain = json.dumps(inner, separators=(",", ":")).encode()
    return {"t": "pack", "i": selector, "uid": 42, "cid": "app", "tcid": unit.mac,
            "pack": base64.b64encode(AES.new(key, AES.MODE_ECB).encrypt(pad(plain, 16))).decode()}


def exchange(unit, inner, selector=0):
    reply, = unit.profile.handler.handle(unit, packet(unit, inner, selector))
    raw = encode_reply(reply)
    outer = json.loads(raw)
    plain = unpad(AES.new(KEY if outer["i"] else unit.key, AES.MODE_ECB)
                  .decrypt(base64.b64decode(outer["pack"])), 16)
    assert not raw.endswith(b"\n") and not plain.endswith(b"\n")
    assert outer["uid"] == 42 and outer["cid"] == unit.mac and outer["tcid"] == "app"
    return json.loads(plain)


@pytest.mark.parametrize("source", FIXTURE["sources"], ids=lambda row: row["sha256"][:12])
def test_every_original_nonempty_snapshot_and_exact_mid_branch(source):
    for vector in source["vectors"]:
        expected = vector["literal_snapshot"]
        profile, = [p for p in PROFILES if p.source_sha256 == source["sha256"] and vector["mid"] in p.mids]
        unit = device(profile)
        if expected is None:
            assert unit.profile.handler.handle(unit, packet(unit, {"t": "status", "cols": ["mid", "Pow"]})) == []
            status = exchange(unit, {"t": "status", "cols": ["mid", "hid"]})
            assert status["cols"] == ["mid", "hid"] and status["r"] == 200
            assert status["dat"] == [vector["mid"], profile.hid]
            assert profile.hid in ("V16.bin", "V8.bin", "V12.bin")
            assert exchange(unit, {"t": "cmd", "opt": ["Pow"], "p": [1]}) == {
                "t": "res", "mac": unit.mac, "val": [], "p": [], "opt": [], "r": 408}
            continue
        runtime = profile.handler._runtime(unit, unit.state)
        if bytes.fromhex(vector["serial_input"])[3] == 0x93 and vector["mid"] not in ("828401", "828402"):
            runtime["timer"] = list(bytes.fromhex(vector["serial_input"])[:7])
        response = exchange(unit, {"t": "status", "cols": list(expected)})
        assert response == {"t": "dat", "uid": 42, "mac": unit.mac, "cid": unit.mac,
                            "dat": list(expected.values()), "cols": list(expected), "r": 200}


@pytest.mark.parametrize("profile", [p for p in PROFILES if p.mids[0] in ("828140", "828401", "828402", "828a04")], ids=lambda p: p.id)
def test_discovery_binding_metadata_alias_lifecycle_and_isolation(profile):
    unit = device(profile)
    advertisement, = profile.handler.advertise(unit, {"t": "scan"})
    assert advertisement.inner == {"t": "dev", "cid": "", "bc": "", "brand": "", "catalog": "",
                                   "mac": unit.mac, "mid": unit.mid, "model": "", "name": "Synthetic",
                                   "lock": 0, "series": "", "vender": "", "ver": ""}
    assert exchange(unit, {"t": "bind", "mac": unit.mac}, 1) == {
        "r": 200, "t": "bindok", "mac": unit.mac, "key": FIXTURE["session_key"]}
    cols = ["hid", "mid", "rssi", "MafIdf", "DevID", "MidType", "AppTimer", "missing", "Pow", "Pow"]
    response = exchange(unit, {"t": "status", "cols": cols})
    assert response["cols"] == cols[:7]+["Pow", "Pow"]
    assert response["dat"] == [profile.hid, unit.mid, 0, 0, "", "", 0, 0, 0]
    alias = exchange(unit, {"t": "subDev", "i": 0})
    assert alias == {"r": 200, "t": "subList", "i": 0, "list": [
        {"mac": unit.mac+"01", "mid": unit.mid+"01", "name": "GreeHot", "model": "gree", "lock": 0}], "c": 1}
    assert exchange(unit, {"t": "subDev", "i": 1})["list"] == []
    ack = exchange(unit, {"t": "cmd", "opt": ["Pow"], "p": [3]})
    assert ack == {"t": "res", "mac": unit.mac, "val": [3], "p": [3], "opt": ["Pow"], "r": 200}
    assert exchange(unit, {"t": "status", "cols": ["Pow"]})["dat"] == [1]
    exchange(unit, {"t": "bind"}, 1)
    assert exchange(unit, {"t": "status", "cols": ["Pow"]})["dat"] == [1]
    assert exchange(device(profile), {"t": "status", "cols": ["Pow"]})["dat"] == [0]
    assert profile.handler.thermal_target(unit) is None and unit.room_c is None


def test_heater_setter_and_getter_are_distinct_storage():
    unit = device(next(p for p in PROFILES if p.id == "sim-w04a-v16-828a04"))
    assert exchange(unit, {"t": "cmd", "opt": ["HeatMod"], "p": [9]})["val"] == [9]
    assert exchange(unit, {"t": "status", "cols": ["HeatMod", "TimeWork"]})["dat"] == [7, 544]


@pytest.mark.parametrize("bad", [None, True, 1.5, "1", [], {}, 1 << 31])
def test_atomic_validation_isolation_and_no_fake_success(bad):
    unit = device()
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "cmd", "opt": ["Pow", "Wspd"], "p": [1, bad]})
    assert unit.state == before and unit.last_step == 1000
    for kind in ("startDist", "keyt", "missing", "newDev"):
        assert unit.profile.handler.handle(unit, packet(unit, {"t": kind})) == []
    assert unit.profile.handler.handle(unit, packet(unit, {"t": "bind"}, 2)) == []


def test_malformed_recovery_unknown_forwarding_and_metadata_mutation():
    unit = device()
    outer = packet(unit, {"t": "status", "cols": ["Pow"]})
    outer["tcid"] = "020000000099"
    with pytest.raises(InvalidPacket):
        unit.profile.handler.handle(unit, outer)
    with pytest.raises(InvalidPacket):
        unit.profile.handler.handle(unit, packet(unit, {"t": "bind"}, key=b"fedcba9876543210"))
    assert exchange(unit, {"t": "cmd", "opt": ["unmapped"], "p": [7]})["val"] == [7]
    assert exchange(unit, {"t": "status", "cols": ["unmapped", "Pow"]})["cols"] == ["Pow"]
    exchange(unit, {"t": "cmd", "opt": ["name"], "p": ["Renamed"]})
    assert exchange(unit, {"t": "status", "cols": ["name"]})["dat"] == ["Renamed"]
    assert exchange(unit, {"t": "cmd", "opt": ["dwRpt", "dwTsk", "Pow"], "p": [9, 2, 1]}) == {
        "t": "res", "mac": unit.mac, "val": [2, 9], "p": [2, 9], "opt": ["dwTsk", "dwRpt"], "r": 200}
    assert exchange(unit, {"t": "status", "cols": ["Pow"]})["dat"] == [0]


def test_synthetic_timer_store_and_serial_cache_execution():
    unit = device()
    timer = {"t": "setT", "id": 0, "name": "morning", "enable": 1, "tz": 8,
             "hr": 0, "min": 1, "sec": 27, "week": [0]*7,
             "cmd": [{"opt": ["Pow"], "p": [1]}]}
    assert exchange(unit, timer) == {"t": "resT", "r": 200}
    assert unit.profile.handler.handle(unit, packet(unit, timer)) == []
    listing = exchange(unit, {"t": "queryT", "index": 0, "count": 10})
    assert listing["total"] == 1 and listing["list"][0]["sec"] == 0
    exchange(unit, {"t": "cmd", "opt": ["time"], "p": ["1970-01-01 00:01:00"]})
    assert exchange(unit, {"t": "status", "cols": ["Pow", "AppTimer"]})["dat"] == [1, 0]
    assert exchange(unit, {"t": "deleteT", "id": 0}) == {"t": "resT", "r": 200}
    assert exchange(unit, {"t": "queryT", "index": 0, "count": 10})["list"] == []
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "deleteT", "id": 0})

def test_synthetic_timer_on_maximum_calendar_day_remains_serviceable(monkeypatch):
    unit = device()
    runtime = unit.profile.handler._runtime(unit, unit.state)
    runtime["time"] = "9999-12-31 23:58:59"
    timer = {"t": "setT", "id": 0, "name": "last-day", "enable": 1, "tz": 0,
             "hr": 23, "min": 59, "sec": 0, "week": [0]*7,
             "cmd": [{"opt": ["Pow"], "p": [1]}]}
    assert exchange(unit, timer) == {"t": "resT", "r": 200}

    maximum = "9999-12-31 23:59:59"
    assert exchange(unit, {"t": "cmd", "opt": ["time"], "p": [maximum]})["p"] == [maximum]
    monkeypatch.setattr("gree_emulator.profiles.catalog_realtek_third_w04.monotonic", lambda: 1001)
    assert exchange(unit, {"t": "status", "cols": ["Pow", "time", "AppTimer"]})["dat"] == [
        1, maximum, 0]
    listing = exchange(unit, {"t": "queryT", "index": 0, "count": 10})
    assert listing["list"][0]["enable"] == 0


def test_upgrade_receipt_and_dump_do_not_download_or_change_board():
    unit = device()
    assert exchange(unit, {"t": "upgrade", "url": "https://example.invalid/firmware"}) == {"t": "ret", "r": 200}
    assert exchange(unit, {"t": "dump"}) == {"t": "res", "mac": unit.mac, "r": 200}
    assert exchange(unit, {"t": "status", "cols": ["Pow"]})["dat"] == [0]


@pytest.mark.parametrize("mid,names,values,fresh", [
    ("828140", ["Mode", "Wspd", "Light", "SetHumidity"], [255, 256, -1, 55], [7, 0, 255, 55]),
    ("828a04", ["Pow", "AirChildLock", "SetTemp"], [2, 1, 300], [0, 1, 44]),
    ("828401", ["mode", "Rice", "Textre", "StTmr"], [31, 2, 3, 125], [31, 2, 3, 125]),
])
def test_literal_raw_width_and_minute_conversion(mid, names, values, fresh):
    unit = device(next(p for p in PROFILES if p.id == "sim-w04a-v16-"+mid))
    assert exchange(unit, {"t": "cmd", "opt": names, "p": values})["val"] == values
    assert exchange(unit, {"t": "status", "cols": names})["dat"] == fresh


def test_duplicate_first_json_value_and_readonly_ack_not_mutation():
    unit = device()
    ack = exchange(unit, {"t": "cmd", "opt": ["Pow", "Pow", "EnvHumidity"], "p": [2, 1, 99]})
    assert ack["p"] == ack["val"] == [2, 2, 99]
    assert exchange(unit, {"t": "status", "cols": ["Pow", "EnvHumidity"]})["dat"] == [0, 14]


def test_plain_network_settings_time_and_column_capacity_are_bounded():
    unit = device()
    reply, = unit.profile.handler.handle(unit, {"t": "wlan", "host": "example.invalid", "ssid": "synthetic", "psw": ""})
    assert reply.outer == {"t": "ret", "r": 200}
    assert exchange(unit, {"t": "status", "cols": ["host"]})["dat"] == ["example.invalid"]
    assert unit.profile.handler.handle(unit, {"t": "tm", "time": "1970-01-0100:00:05"}) == []
    assert exchange(unit, {"t": "status", "cols": ["time"]})["dat"] == ["1970-01-01 00:00:05"]
    assert exchange(unit, {"t": "status", "cols": ["Pow"]*32})["dat"] == [0]*32
    for columns in (["Pow"]*33, ["x"*511, "Pow"]):
        before = deepcopy(unit.state)
        with pytest.raises(InvalidPacket):
            exchange(unit, {"t": "status", "cols": columns})
        assert unit.state == before


def test_complete_metadata_serializers_and_mixed_batch_asymmetry():
    unit = device()
    columns = ["time", "name", "lock", "AutoUpdate", "host", "hid", "mid", "bc",
               "DevID", "MafIdf", "AppTimer", "MidType", "rssi"]
    assert exchange(unit, {"t": "status", "cols": columns})["dat"] == [
        "1970-01-01 00:00:00", "Synthetic", 0, 0, "", "362001061704+U-W04WV16.bin",
        "828140", "", "", 0, 0, "", 0]
    exchange(unit, {"t": "cmd", "opt": ["lock"], "p": [-2]})
    exchange(unit, {"t": "cmd", "opt": ["AutoUpdate"], "p": [258]})
    assert exchange(unit, {"t": "status", "cols": ["lock", "AutoUpdate"]})["dat"] == [1, 2]
    # Mixed board/metadata commands don't write metadata and consume board p from index zero.
    ack = exchange(unit, {"t": "cmd", "opt": ["lock", "Pow"], "p": [0, 1]})
    assert ack["opt"] == ["lock", "Pow"] and ack["val"] == [1, 0]
    assert exchange(unit, {"t": "status", "cols": ["lock", "Pow"]})["dat"] == [1, 0]


@pytest.mark.parametrize("vector", FIXTURE["surver_vectors"], ids=lambda row: row["source_sha256"][:12])
def test_original_complete_surver_udp_envelope(vector):
    profile, = [p for p in PROFILES if p.source_sha256 == vector["source_sha256"] and p.mids == (vector["mid"],)]
    unit = device(profile)
    reply, = profile.handler.handle(unit, vector["request_outer"])
    complete = encode_reply(reply)
    assert complete == bytes.fromhex(vector["literal_complete_reply_hex"])
    assert reply.raw_payload == complete and reply.inner is None
    outer = json.loads(complete)
    assert outer["i"] == 1 and not complete.endswith(b"\n")
    plain = unpad(AES.new(KEY, AES.MODE_ECB).decrypt(base64.b64decode(outer["pack"])), 16)
    assert plain == bytes.fromhex(vector["literal_decrypted_inner_hex"])
    assert plain.startswith(b"!!") and plain.endswith(b"\n")
    assert len(base64.b64decode(plain[2:-1])) == 39


def test_plain_tm_is_explicitly_admitted():
    assert device().profile.handler.plaintext_types == ("tm",)


async def test_client_cooker_poll_reads_source_case_and_effective_values(monkeypatch):
    monkeypatch.setattr("gree_emulator.profiles.catalog_realtek_third_w04.monotonic", asyncio.get_running_loop().time)
    profile = next(p for p in PROFILES if p.id == "sim-w04a-v16-828401")
    unit = device(profile)
    fields = ["Pow", "mode", "KpTpOnOFF"]
    exchange(unit, {"t": "cmd", "opt": fields, "p": [3, 31, 3]})
    transport, server = await start_server([unit], "127.0.0.1", 0)
    host, port = transport.get_extra_info("sockname")
    client = create_device(DeviceInfo(host, port, unit.mac, "Cooker", mid="828401"), bind_timeout=1)
    try:
        await client.bind()
        await asyncio.wait_for(client._valid_state.wait(), 1)
        assert [client.get_property(name) for name in fields] == [1, 31, 3]
        assert client.hid == profile.hid
        assert all(value is None for value in client.capabilities.values())
    finally:
        client.close()
        server.close()
        await server.wait_closed()
