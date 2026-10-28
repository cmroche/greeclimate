"""Literal source-ledger assertions and explicitly chosen safe-model policies."""
import base64
from copy import deepcopy
import json
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.catalog_realtek_third_numeric import PROFILES
from gree_emulator.wire import InvalidPacket, encode_reply

FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-realtek-third-numeric_research.json").read_text())


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    monkeypatch.setattr("gree_emulator.profiles.catalog_realtek_third_numeric.monotonic", lambda: 1000)
    monkeypatch.setattr("gree_emulator.profiles.catalog_realtek_third_tables.monotonic", lambda: 1000)


def device(build="w05p", mid=None):
    profile = next(profile for profile in PROFILES if profile.handler.build == build
                   and (mid is None or mid in profile.mids))
    return EmulatedDevice("numeric", FIXTURE["mac"], "", mid or profile.mids[0],
                          FIXTURE["key"].encode(), profile, deepcopy(dict(profile.initial_state)),
                          room_c=None, ambient_c=None, last_step=1000)


def send(unit, inner, index=0):
    key = b"a3K8Bx%2r8Y7#xDh" if index else unit.key
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(json.dumps(inner).encode(), 16))
    outer = {"t": "pack", "tcid": unit.mac, "i": index, "uid": -2147483648,
             "pack": base64.b64encode(encrypted).decode()}
    return unit.profile.handler.handle(unit, outer)


def status(unit, columns):
    reply, = send(unit, {"t": "status", "cols": columns})
    assert reply.outer["uid"] == -2147483648
    assert reply.outer["i"] == 0
    assert encode_reply(reply).endswith(b"\n")
    return reply.inner


@pytest.mark.parametrize("row", [row for row in FIXTURE["sources"] if row["build"] != "w05ac"], ids=lambda row: row["build"])
def test_every_unique_numeric_getter_from_both_banks(row):
    unit = device(row["build"])
    assert [bank["bank"] for bank in row["banks"]] == [0, 1]
    assert list(unit.profile.handler.fields) == row["fields"]
    assert unit.profile.source_sha256 == row["sha256"]
    for name, value in zip(row["fields"], row["initial"]):
        actual = status(unit, [name])
        assert actual["cols"] == [name] and actual["dat"] == [value]
    assert status(unit, row["status"]["request"])["dat"] == row["status"]["data"]
    assert status(unit, ["hid"])["dat"] == [row["hid"]]


@pytest.mark.parametrize("build", ["w05p", "afjme"])
def test_numeric_low16_mutation_fresh_status_and_ack_ownership(build):
    unit = device(build)
    replies = send(unit, {"t": "cmd", "opt": ["Pow", "Pow"], "p": [65537, -1]})
    if build == "w05p":
        assert replies == []  # The source NULL-tail boundary is not a successful ACK.
    else:
        assert replies[0].inner == {"t": "res", "mac": unit.mac, "r": 200}
    assert status(unit, ["Pow", "Pow"])["dat"] == [65535, 65535]
    assert status(device(build), ["Pow"])["dat"] == [0]


@pytest.mark.parametrize("build", ["w05p", "afjme"])
@pytest.mark.parametrize("bad", [True, None, "1", 1.1, [], {}, 1 << 31])
def test_atomic_safety_policy_for_invalid_scalar(build, bad):
    unit = device(build)
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        send(unit, {"t": "cmd", "opt": ["Pow", "Mod"], "p": [1, bad]})
    assert unit.state == before and unit.last_step == 1000


@pytest.mark.parametrize("build", ["w05p", "afjme"])
def test_source_first_hole_exact_capacity_unknown_and_metadata_shape(build):
    unit = device(build)
    assert status(unit, ["Pow", "", "TemSen"])["dat"] == [0]
    assert status(unit, ["Pow"]*30)["dat"] == []
    assert status(unit, ["apssid", "hid"])["cols"] == ["apssid", "hid"]
    assert len(status(unit, ["apssid", "hid"])["dat"]) == 1
    with pytest.raises(InvalidPacket):
        status(unit, ["Pow"]*31)
    with pytest.raises(InvalidPacket):
        status(unit, ["unqualified"])


@pytest.mark.parametrize("row", next(row["tables"] for row in FIXTURE["sources"] if row["build"] == "w05ac"))
def test_exact_w05ac_companion_tables_and_requested_effective_values(row):
    unit = device("w05ac", row["mid"])
    assert list(unit.profile.handler.fields) == row["fields"]
    for name in row["fields"]:
        assert status(unit, [name])["dat"] == [0]
    name = row["fields"][0]
    reply, = send(unit, {"t": "cmd", "opt": [name, name], "p": [65537, -1]})
    assert reply.inner == {"t": "res", "mac": unit.mac, "r": 200,
                           "opt": [name, name], "p": [65537, -1]}
    assert status(unit, [name])["dat"] == [-1]
    assert status(unit, ["apssid", "mac", "mid"])["dat"] == ["", "", ""]


def test_w05ac_array_byte_cache_requested_ack_and_position_bug():
    unit = device("w05ac", "70402")
    reply, = send(unit, {"t": "cmd", "opt": ["ArrCmd0x22"], "p": [[256, -1, 257]]})
    assert reply.inner["p"] == [[256, -1, 257]]
    assert status(unit, ["ArrCmd0x22"])["dat"] == [0]
    response = status(unit, ["AutoLeftLeg"]*8+["ArrCmd0x22"])
    assert response["dat"] == [0]*8+[[0, 255, 1]]
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        send(unit, {"t": "cmd", "opt": ["ArrCmd0x22"], "p": [[1, 2]]})
    assert unit.state == before
    assert len(status(unit, ["AutoLeftLeg"]*11)["dat"]) == 10
    with pytest.raises(InvalidPacket):
        status(unit, ["AutoLeftLeg"]*12)


def test_platform_rssi_is_not_numeric_cache_and_special_report_has_no_fake_ack():
    unit = device("afjme")
    send(unit, {"t": "cmd", "opt": ["rssi"], "p": [-1]})
    assert status(unit, ["rssi"])["dat"] == [0]
    assert unit.state["_tables"]["rssi_cache"] == 65535
    with pytest.raises(ValueError):
        unit.profile.handler.validate_state({"rssi": -1})
    assert send(unit, {"t": "cmd", "opt": ["ReportClientID"], "p": ["peer"]}) == []
    assert unit.state["_tables"]["report_client"] == "peer"


def test_timer_storage_query_and_synthetic_cache_execution():
    unit = device("w05p")
    send(unit, {"t": "cmd", "opt": ["time"], "p": ["2026-01-01 00:00:00"]})
    timer = {"t": "setT", "id": 257, "name": "synthetic", "enable": 0,
             "hr": 0, "min": 1, "sec": 0, "tz": 256, "week": [],
             "cmd": [{"mac": [unit.mac], "opt": ["Pow"], "p": [65537]}]}
    reply, = send(unit, timer)
    assert reply.inner == {"t": "resT", "r": 200}
    assert status(unit, ["AppTimer"])["dat"] == [1]
    reply, = send(unit, {"t": "queryT", "index": 0, "count": 10})
    assert reply.inner["total"] == 10 and reply.inner["list"][0]["id"] == 1
    send(unit, {"t": "cmd", "opt": ["time"], "p": ["2026-01-01 00:01:00"]})
    assert status(unit, ["Pow"])["dat"] == [1]
    send(unit, {"t": "deleteT", "id": 1})
    assert status(unit, ["AppTimer"])["dat"] == [0]


@pytest.mark.parametrize("build", ["w05p", "afjme", "w05ac"])
def test_every_metadata_column_literal_type_and_missing_datum_shape(build):
    metadata = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-realtek-third-numeric-metadata_research.json").read_text())
    response = status(device(build), metadata["columns"])
    assert response["cols"] == metadata["columns"]
    assert response["dat"] == metadata[build]


@pytest.mark.parametrize("build", ["w05p", "afjme", "w05ac"])
def test_rebinding_key_selector_and_synthetic_restart_isolation(build):
    unit = device(build)
    name = unit.profile.handler.fields[0]
    send(unit, {"t": "cmd", "opt": [name], "p": [7]}, index=256)
    reply, = send(unit, {"t": "bind", "mac": unit.mac}, index=-1)
    assert reply.inner == {"t": "bindok", "mac": unit.mac, "r": 200, "key": FIXTURE["key"]}
    assert reply.outer["i"] == 1 and status(unit, [name])["dat"] == [7]
    assert status(device(build), [name])["dat"] == [0]
    with pytest.raises(InvalidPacket):
        send(unit, {"t": "status", "mac": "wrong", "cols": [name]})
    with pytest.raises(InvalidPacket):
        send(unit, {"t": "status", "cols": [name], "sub": unit.mac+"01"})


@pytest.mark.parametrize("build", ["w05p", "afjme", "w05ac"])
def test_upgrade_wire_ack_policy_records_url_without_flashing(build):
    unit = device(build)
    replies = send(unit, {"t": "upgrade", "url": "http://example.invalid/source.bin"})
    if build == "afjme":
        assert replies[0].outer == {"t": "ret", "r": 200, "mac": unit.mac}
        assert encode_reply(replies[0]).endswith(b"\n")
    else:
        assert replies == []
    assert unit.state["_tables"]["upgrade_url"] == "http://example.invalid/source.bin"


@pytest.mark.parametrize("build,expected", [("w05p", "fg\u0001"), ("afjme", "!!")])
def test_source_server_version_preserves_miscalled_base64_effect_not_repaired_payload(build, expected):
    unit = device(build)
    reply, = send(unit, {"t": "surver", "mac": unit.mac})
    assert reply.inner is None
    assert reply.outer == {"t": "pack", "i": 1, "uid": -2147483648,
                           "cid": unit.mac, "tcid": "", "pack": expected}
    assert encode_reply(reply).endswith(b"\n")
    assert json.loads(encode_reply(reply))["pack"] == expected
    assert send(device("w05ac"), {"t": "surver"}) == []


def test_w05ac_time_ack_is_requested_string_not_the_prewrite_callback_clock():
    unit = device("w05ac")
    value = "2026-01-01 00:00:00"
    reply, = send(unit, {"t": "cmd", "opt": ["time"], "p": [value]})
    assert reply.inner["opt"] == ["time"] and reply.inner["p"] == [value]
    assert status(unit, ["time"])["dat"] == [value]


@pytest.mark.parametrize("build", ["w05p", "afjme", "w05ac"])
def test_source_discovery_metadata_and_safe_duplicate_lock_policy(build):
    unit = device(build)
    reply, = unit.profile.handler.advertise(unit, {"t": "scan"})
    assert reply.outer["i"] == 1
    assert reply.inner["mid"] == unit.mid and reply.inner["vender"] == ""
    assert reply.inner["bc"] == ("" if build == "afjme" else "gree")
    assert reply.inner["ver"] == {"w05p": "V1.2.1", "afjme": "V3.2.M", "w05ac": ""}[build]
    assert reply.inner.get("hid") == (unit.profile.hid if build == "afjme" else None)
    if build != "w05ac":
        send(unit, {"t": "cmd", "opt": ["lock"], "p": [7]})
        reply, = unit.profile.handler.advertise(unit, {"t": "scan"})
        assert reply.inner["lock"] == 7
