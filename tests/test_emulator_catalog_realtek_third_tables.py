"""Literal source-table contracts; no firmware or research runtime dependency."""
import base64
from copy import deepcopy
import json
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles import Profile
from gree_emulator.profiles.catalog_realtek_third_tables import (
    FiniteTables, PROFILES, W05_HID, W05_SHA, W06_HID, W06_SHA,
)
from gree_emulator.wire import InvalidPacket, encode_reply

FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-realtek-third-tables-vectors_research.json").read_text())
KEY = b"a3K8Bx%2r8Y7#xDh"


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch):
    monkeypatch.setattr("gree_emulator.profiles.catalog_realtek_third_tables.monotonic", lambda: 1000)


def device(table="w05-fan"):
    row = next(row for row in FIXTURE["tables"] if row["table"] == table)
    state = dict(zip(row["columns"], row["initial"]))
    matches = [profile for profile in PROFILES if profile.handler.table == table]
    if matches:
        profile, = matches
        assert dict(profile.initial_state) == state
        mid = row["mid"]
    else:
        # Unassociated source selectors are exercised without inventing an emitted MID.
        profile = Profile("test-source-selector", (), W06_HID, W06_SHA, state, FiniteTables(table))
        mid = ""
    return EmulatedDevice("finite", FIXTURE["mac"], "", mid,
                          FIXTURE["session_key"].encode(), profile, deepcopy(state),
                          room_c=None, ambient_c=None, last_step=1000)


def packet(unit, inner, *, index=0, uid=42, key=None):
    if key is None:
        key = KEY if index else unit.key
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(json.dumps(inner, separators=(",", ":")).encode(), 16))
    return {"t": "pack", "i": index, "uid": uid, "cid": "app", "tcid": unit.mac,
            "pack": base64.b64encode(encrypted).decode()}


def decode(reply):
    raw = encode_reply(reply)
    outer = json.loads(raw)
    inner = json.loads(unpad(AES.new(KEY if outer["i"] else FIXTURE["session_key"].encode(), AES.MODE_ECB)
                             .decrypt(base64.b64decode(outer["pack"])), 16))
    return raw, outer, inner


def exchange(unit, inner, **kwargs):
    reply, = unit.profile.handler.handle(unit, packet(unit, inner, **kwargs))
    return decode(reply)


def test_literal_wire_transactions_and_exact_lf():
    unit = device()
    for vector in FIXTURE["vectors"]:
        replies = unit.profile.handler.handle(unit, packet(unit, vector["request"]))
        if vector["response"] is None:
            assert replies == []
            continue
        raw, outer, inner = decode(replies[0])
        assert inner == vector["response"]
        assert raw.endswith(b"\n") == vector["newline"]
        assert not raw.endswith(b"\n\n")
        assert outer["i"] == vector["selector"]
        assert outer["uid"] == 42 and outer["cid"] == unit.mac and outer["tcid"] == ""


@pytest.mark.parametrize("row", FIXTURE["tables"], ids=lambda row: row["table"])
def test_all_nine_literal_selected_tables_and_every_scalar(row):
    unit = device(row["table"])
    assert list(unit.profile.handler.fields) == row["columns"]
    for name, initial in zip(row["columns"], row["initial"]):
        _, _, status = exchange(unit, {"t": "status", "cols": [name]})
        if len(name) >= 16:
            assert status["cols"] == status["dat"] == []
        else:
            assert status["cols"] == [name] and status["dat"] == [initial]
        _, _, ack = exchange(unit, {"t": "cmd", "opt": [name, name], "p": [256, -1]})
        assert ack["opt"] == [name, name] and ack["p"] == [256, -1]
        assert "val" not in ack and unit.state[name] == -1
        _, _, fresh = exchange(unit, {"t": "status", "cols": [name]})
        assert fresh["dat"] == ([] if len(name) >= 16 else [-1])
    assert unit.room_c is None and unit.profile.handler.thermal_target(unit) is None


@pytest.mark.parametrize("table", ["w05-fan", "w06-humidifier"])
def test_complete_metadata_getter_types_and_synthetic_policy(table):
    unit = device(table)
    columns = FIXTURE["metadata_columns"]
    _, _, status = exchange(unit, {"t": "status", "cols": columns})
    expected = [""] * 23
    expected[4] = "1970-01-01 00:00:00"
    expected[15] = FIXTURE["w05_hid"] if table.startswith("w05-") else FIXTURE["w06_hid"]
    assert status["cols"] == columns and status["dat"] == expected
    _, _, extra = exchange(unit, {"t": "status", "cols": ["rssi", "SvLine"]})
    if table.startswith("w05-"):
        assert extra["cols"] == ["SvLine"] and extra["dat"] == [[0]*24]
    else:
        assert extra["cols"] == ["rssi"] and extra["dat"] == [0]


@pytest.mark.parametrize("bad", [True, False, None, "1", 1.0, [], {}, 1 << 31, -(1 << 31)-1])
def test_strict_atomic_command_does_not_change_clock_or_cache(bad):
    unit = device()
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "cmd", "opt": ["Pow", "WdSpd"], "p": [1, bad]})
    assert unit.state == before and unit.last_step == 1000


def test_status_first_hole_duplicates_unknowns_and_exact_bound():
    unit = device()
    _, _, status = exchange(unit, {"t": "status", "cols": ["Pow", "missing", "Pow", "", "hid"]})
    assert status["cols"] == ["Pow", "Pow"] and status["dat"] == [0, 0]
    _, _, status = exchange(unit, {"t": "status", "cols": ["Pow", "x"*16, "hid"]})
    assert status["cols"] == ["Pow"] and status["dat"] == [0]
    _, _, status = exchange(unit, {"t": "status", "cols": ["Pow"]*34})
    assert status["cols"] == ["Pow"]*34 and status["dat"] == [0]*34
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "status", "cols": ["Pow"]*35})


def test_int32_key_selector_not_low_byte_and_rebind_is_not_reset():
    unit = device()
    exchange(unit, {"t": "cmd", "opt": ["Pow"], "p": [7]}, index=256)
    _, outer, bound = exchange(unit, {"t": "bind", "mac": unit.mac}, index=-1, uid=-(1 << 31))
    assert outer["i"] == 1 and outer["uid"] == -(1 << 31)
    assert bound["key"] == FIXTURE["session_key"]
    _, _, status = exchange(unit, {"t": "status", "cols": ["Pow"]})
    assert status["dat"] == [7]
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "status", "cols": ["Pow"]}, index=256, key=unit.key)
    other = device()
    _, _, status = exchange(other, {"t": "status", "cols": ["Pow"]})
    assert status["dat"] == [0]


def test_wrong_targets_and_oversized_reply_are_atomic():
    unit = device()
    for inner in ({"t": "bind", "mac": "020000000052"},
                  {"t": "status", "cols": ["Pow"], "sub": unit.mac},
                  {"t": "status", "cols": ["hid"]*34}):
        before = deepcopy(unit.state)
        with pytest.raises(InvalidPacket):
            exchange(unit, inner)
        assert unit.state == before
    outer = packet(unit, {"t": "bind", "mac": unit.mac})
    outer["tcid"] = "020000000052"
    with pytest.raises(InvalidPacket):
        unit.profile.handler.handle(unit, outer)


def test_timer_schema_create_update_query_delete_and_native_count_quirk():
    unit = device()
    record = {"t": "setT", "id": 257, "name": "morning", "enable": 1, "hr": 8,
              "min": 30, "sec": 1, "tz": 0, "week": [1],
              "cmd": [{"mac": [unit.mac], "opt": ["Pow", "WdSpd"], "p": [1, 255]}]}
    raw, _, ack = exchange(unit, record)
    assert ack == {"t": "resT", "r": 200} and not raw.endswith(b"\n")
    _, _, listed = exchange(unit, {"t": "queryT", "index": 0, "count": 0})
    assert listed == {"t": "listT", "total": 0, "index": 0, "list": [
        {"id": 1, "name": "morning", "enable": 1, "hr": 8, "min": 30, "sec": 1,
         "week": [1, 0, 0, 0, 0, 0, 0], "cmd": record["cmd"]}]}
    exchange(unit, {**record, "t": "updateT", "name": "renamed"})
    _, _, listed = exchange(unit, {"t": "queryT", "index": 0, "count": 9})
    assert listed["list"][0]["name"] == "renamed" and listed["total"] == 9
    exchange(unit, {"t": "deleteT", "id": 1})
    _, _, listed = exchange(unit, {"t": "queryT", "index": 0, "count": 3})
    assert listed == {"t": "listT", "total": 3, "index": 0}


def test_synthetic_clock_old_controls_timer_and_time_ack_order(monkeypatch):
    unit = device()
    _, _, ack = exchange(unit, {"t": "cmd", "opt": ["time"], "p": ["2026-10-25 00:00:00"]})
    assert ack["p"] == ["1970-01-01 00:00:00"]
    exchange(unit, {"t": "setT", "id": 0, "name": "one-shot", "enable": 0, "hr": 0,
                    "min": 0, "sec": 2, "tz": 0, "week": [],
                    "cmd": [{"mac": ["not-a-child-route"], "opt": ["Pow"], "p": [1]}]})
    monkeypatch.setattr("gree_emulator.profiles.catalog_realtek_third_tables.monotonic", lambda: 1003)
    _, _, status = exchange(unit, {"t": "status", "cols": ["Pow", "time"]})
    assert status["dat"] == [1, "2026-10-25 00:00:03"]
    _, _, timers = exchange(unit, {"t": "queryT", "index": 0, "count": 1})
    assert timers["list"][0]["enable"] == 1

def test_max_synthetic_clock_saturates_and_recovers(monkeypatch):
    unit = device()
    maximum = "9999-12-31 23:59:59"
    _, _, ack = exchange(unit, {"t": "cmd", "opt": ["time"], "p": [maximum]})
    assert ack["p"] == ["1970-01-01 00:00:00"]

    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "cmd", "opt": ["Pow", "time"],
                        "p": [1, "9999-12-31 23:59:60"]})
    assert unit.state == before and unit.last_step == 1000

    monkeypatch.setattr("gree_emulator.profiles.catalog_realtek_third_tables.monotonic", lambda: 1001)
    _, _, status = exchange(unit, {"t": "status", "cols": ["time"]})
    assert status["dat"] == [maximum]
    _, _, ack = exchange(unit, {"t": "cmd", "opt": ["time"], "p": ["2026-10-25 00:00:00"]})
    assert ack["p"] == [maximum]
    _, _, status = exchange(unit, {"t": "status", "cols": ["Pow", "time"]})
    assert status["dat"] == [0, "2026-10-25 00:00:00"]


def test_timer_scheduler_stops_after_maximum_calendar_day():
    unit = device()
    before_event = "9999-12-31 23:59:58"
    maximum = "9999-12-31 23:59:59"
    exchange(unit, {"t": "cmd", "opt": ["time"], "p": [before_event]})
    exchange(unit, {"t": "setT", "id": 0, "name": "last-second", "enable": 0,
                    "hr": 23, "min": 59, "sec": 59, "tz": 0, "week": [],
                    "cmd": [{"mac": [unit.mac], "opt": ["Pow"], "p": [1]}]})

    _, _, ack = exchange(unit, {"t": "cmd", "opt": ["time"], "p": [maximum]})
    assert ack["p"] == [before_event]
    _, _, status = exchange(unit, {"t": "status", "cols": ["Pow", "time"]})
    assert status["dat"] == [1, maximum]
    _, _, timers = exchange(unit, {"t": "queryT", "index": 0, "count": 1})
    assert timers["list"][0]["enable"] == 1

def test_plaintext_configuration_keeps_credentials_out_of_state():
    unit = device()
    reply, = unit.profile.handler.handle(unit, {"t": "wlan", "host": "dis.gree.com",
        "ssid": "synthetic", "psw": "not-retained", "lat": "0", "lon": "0"})
    assert encode_reply(reply) == b'{"t":"ret","r":0,"mac":"020000000051"}\n'
    assert "not-retained" not in json.dumps(unit.state)
    _, _, status = exchange(unit, {"t": "status", "cols": ["host"]})
    assert status["dat"] == ["dis.gree.com"]


@pytest.mark.parametrize("body", [
    b'{"t":"cmd","opt":["Pow"],"p":[1],"p":[0]}',
    b'{"t":"cmd","T":"status","opt":["Pow"],"p":[1]}',
    b'{"t":"status","cols":["Pow"],"x":NaN}',
])
def test_duplicate_json_members_and_nonfinite_values_never_mutate(body):
    unit = device()
    outer = packet(unit, {"t": "status", "cols": ["Pow"]})
    outer["pack"] = base64.b64encode(AES.new(unit.key, AES.MODE_ECB).encrypt(pad(body, 16))).decode()
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        unit.profile.handler.handle(unit, outer)
    assert unit.state == before and unit.last_step == 1000
