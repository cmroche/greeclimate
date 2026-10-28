"""Independent literal W05J source replay vectors; no research/runtime coupling."""
import base64
from copy import deepcopy
import json
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.catalog_early_w05j import PROFILES
from gree_emulator.wire import InvalidPacket, encode_reply

FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-early-w05j-vectors_research.json").read_text())
KEY = b"a3K8Bx%2r8Y7#xDh"


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch):
    monkeypatch.setattr("gree_emulator.profiles.catalog_early_w05j.monotonic", lambda: 1000)
    monkeypatch.setattr("gree_emulator.profiles.catalog_realtek_third_tables.monotonic", lambda: 1000)


def device(selector=1, mid=None):
    row = FIXTURE["schemas"][selector]
    profile = PROFILES[selector]
    return EmulatedDevice("raw-controller", FIXTURE["mac"], "", mid or row["synthetic_mid"],
                          FIXTURE["session_key"].encode(), profile,
                          deepcopy(dict(profile.initial_state)), room_c=None, ambient_c=None,
                          last_step=1000)


def packet(unit, inner, index=0, uid=-(1 << 31), key=None):
    key = key if key is not None else (KEY if index else unit.key)
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(json.dumps(inner, separators=(",", ":")).encode(), 16))
    return {"t": "pack", "i": index, "uid": uid, "tcid": unit.mac,
            "pack": base64.b64encode(encrypted).decode()}


def decode(reply):
    raw = encode_reply(reply)
    outer = json.loads(raw)
    plain = unpad(AES.new(KEY if outer["i"] else FIXTURE["session_key"].encode(), AES.MODE_ECB)
                  .decrypt(base64.b64decode(outer["pack"])), 16)
    return raw, outer, json.loads(plain), plain


def exchange(unit, inner, **kwargs):
    reply, = unit.profile.handler.handle(unit, packet(unit, inner, **kwargs))
    return decode(reply)


def assert_vector(unit, vector):
    if vector["request"]["t"] == "scan":
        replies = unit.profile.handler.advertise(unit, vector["request"])
    else:
        replies = unit.profile.handler.handle(unit, packet(unit, vector["request"], index=vector["index"]))
    assert len(replies) == len(vector["replies"])
    for reply, expected in zip(replies, vector["replies"]):
        raw, outer, inner, plain = decode(reply)
        assert inner == expected["inner"]
        assert raw.endswith(b"\n") == expected["outer_lf"]
        assert not plain.endswith(b"\n")
        assert {name: value for name, value in outer.items() if name != "pack"} == expected["outer"]


def test_original_encrypted_scan_bind_command_fresh_status():
    unit = device()
    for vector in FIXTURE["wire"]:
        assert_vector(unit, vector)
    assert unit.profile.handler.thermal_target(unit) is None
    assert unit.room_c is None


@pytest.mark.parametrize("row", FIXTURE["schemas"], ids=lambda row: row["profile_id"])
def test_every_selected_numeric_getter_and_cache_command(row):
    for field in row["fields"]:
        unit = device(row["selector"])
        _, _, initial, _ = exchange(unit, {"t": "status", "mac": unit.mac, "cols": [field["name"]]})
        assert [initial["cols"], initial["dat"]] == field["initial_status"]
        _, _, result, _ = exchange(unit, {"t": "cmd", "mac": unit.mac,
                                        "opt": [field["name"]], "p": [field["command"]]})
        assert [result["opt"], result["p"]] == field["fresh_status"]
        assert result["r"] == 200 and "val" not in result
        _, _, fresh, _ = exchange(unit, {"t": "status", "mac": unit.mac, "cols": [field["name"]]})
        assert [fresh["cols"], fresh["dat"]] == field["fresh_status"]


@pytest.mark.parametrize("vector", FIXTURE["writer_boundaries"], ids=lambda row: f"{row['selector']}-{row['name']}-{row['requested']}")
def test_native_custom_writer_signed_cache_boundaries(vector):
    unit = device(vector["selector"])
    exchange(unit, {"t": "cmd", "mac": unit.mac, "opt": [vector["name"]], "p": [vector["requested"]]})
    assert unit.state[vector["name"]] == vector["effective"]


@pytest.mark.parametrize("row", FIXTURE["branches"], ids=lambda row: row["mid"])
def test_mid_dependent_fan_and_water_branches(row):
    unit = device(row["selector"], row["mid"])
    for vector in row["transactions"]:
        assert_vector(unit, vector)


def test_literal_metadata_time_arrays_and_no_fake_ack():
    unit = device(0)
    for vector in FIXTURE["metadata_operations"]:
        assert_vector(unit, vector)
    assert unit.state["_tables"]["name"] == ""
    assert unit.state["_tables"]["report_client"] == "chosen-client"
    assert unit.state["_tables"]["upgrade"].startswith("http://example.invalid/")


def test_all_metadata_are_source_typed_not_inferred_sensor_fields():
    unit = device()
    names = FIXTURE["metadata_columns"]
    _, _, result, _ = exchange(unit, {"t": "status", "mac": unit.mac, "cols": names})
    assert result["cols"] == names
    assert result["dat"] == FIXTURE["metadata_initial"]
    assert "TemSen" not in unit.state


def test_native_timer_lifecycle_and_exact_no_lf():
    unit = device()
    for vector in FIXTURE["timers"]:
        assert_vector(unit, vector)
    assert unit.state["_tables"]["timers"] == {}


def test_status_holes_and_full_int32_key_selection():
    unit = device()
    for vector in FIXTURE["bounds"][:-1]:
        assert_vector(unit, vector)
    before = deepcopy(unit.state)
    # Native exact capacity returns empty arrays; the safe model rejects before copying.
    with pytest.raises(InvalidPacket):
        exchange(unit, FIXTURE["bounds"][-1]["request"], index=-1)
    assert unit.state == before
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "status", "mac": unit.mac, "cols": ["Pow"]}, index=256, key=unit.key)


@pytest.mark.parametrize("bad", [True, False, None, "1", 1.0, [], {}, 1 << 31, -(1 << 31) - 1])
def test_strict_atomic_command_preserves_cache_and_clock(bad):
    unit = device()
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "cmd", "opt": ["Pow", "WdSpd"], "p": [1, bad]})
    assert unit.state == before and unit.last_step == 1000


def test_read_only_metadata_unknowns_no_union_and_rebind_isolation():
    unit = device(11)
    _, _, result, _ = exchange(unit, {"t": "cmd", "opt": ["name", "Temperature", "Pow"], "p": ["ignored", 12, -1]})
    assert result["opt"] == ["name", "Pow"] and result["p"] == ["", -1]
    assert "Temperature" not in unit.state
    _, outer, bound, _ = exchange(unit, {"t": "bind", "mac": unit.mac}, index=256)
    assert outer["i"] == 1 and bound["r"] == 200
    assert unit.state["Pow"] == -1
    other = device(11)
    assert other.state["Pow"] == 0
    wrong = packet(unit, {"t": "status", "mac": unit.mac, "cols": ["Pow"]})
    wrong["tcid"] = "020000000002"
    reply, = unit.profile.handler.handle(unit, wrong)
    _, _, status, _ = decode(reply)
    assert status == {"t": "dat", "mac": unit.mac, "r": 200, "cols": ["Pow"], "dat": [-1]}


def test_native_command_and_status_channels_gate_separate_identities():
    unit = device()
    before = deepcopy(unit.state)
    wrong_target = packet(unit, {"t": "cmd", "mac": unit.mac, "opt": ["Pow"], "p": [1]})
    wrong_target["tcid"] = "020000000002"
    assert unit.profile.handler.handle(unit, wrong_target) == []
    assert unit.state == before

    _, outer, result, _ = exchange(
        unit, {"t": "cmd", "mac": "020000000002", "opt": ["Pow"], "p": [1]}
    )
    assert result == {"t": "res", "mac": unit.mac, "r": 200, "opt": ["Pow"], "p": [1]}
    assert {key: value for key, value in outer.items() if key != "pack"} == {
        "t": "pack", "i": 0, "uid": -(1 << 31), "cid": unit.mac, "tcid": ""
    }

    before = deepcopy(unit.state)
    wrong_identity = packet(unit, {"t": "status", "mac": "020000000002", "cols": ["Pow"]})
    assert unit.profile.handler.handle(unit, wrong_identity) == []
    assert unit.state == before


def test_synthetic_timer_executes_source_callback_not_physics():
    unit = device(2)
    exchange(unit, {"t": "cmd", "opt": ["time"], "p": ["2026-01-01 00:00:00"]})
    exchange(unit, {"t": "setT", "id": 1, "name": "synthetic", "enable": 0,
                    "hr": 0, "min": 1, "sec": 0, "tz": 0, "week": [],
                    "cmd": [{"mac": [unit.mac], "opt": ["StTmr"], "p": [1441]}]})
    exchange(unit, {"t": "cmd", "opt": ["time"], "p": ["2026-01-01 00:01:01"]})
    assert unit.state["StTmr"] == 1440
    assert unit.state["_tables"]["timers"][1]["enable"] == 1
    assert unit.room_c is None


def test_plaintext_wlan_native_ret200_and_safe_restart_boundary():
    unit = device()
    vector = FIXTURE["wlan"]
    reply, = unit.profile.handler.handle(unit, vector["request"])
    raw = encode_reply(reply)
    assert json.loads(raw) == vector["response"]
    assert raw.endswith(b"\n") == vector["outer_lf"]
    _, _, status, _ = exchange(unit, {"t": "status", "mac": unit.mac, "cols": ["host", "mid", "mac"]})
    assert status["dat"] == ["example.invalid", "", ""]
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        unit.profile.handler.handle(unit, {**vector["request"], "ssid": "x" * 32})
    assert unit.state == before


def test_known_status_requires_original_inner_identity():
    unit = device()
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "status", "cols": ["Pow"]})


def test_cloud_menu_array_is_outbound_bytes_not_a_numeric_cache_write():
    unit = device(7)
    exchange(unit, {"t": "cmd", "opt": ["CloudMenu"], "p": [7]})
    _, _, result, _ = exchange(unit, {"t": "cmd", "opt": ["CloudMenu"], "p": [[257, -1]]})
    assert result["opt"] == ["CloudMenu"] and result["p"] == [7]
    assert unit.state["_tables"]["cloud_menu"] == [1, 255] + [0] * 43
    _, _, status, _ = exchange(unit, {"t": "status", "mac": unit.mac, "cols": ["CloudMenu"]})
    assert status["dat"] == [7]


def test_array_client_id_and_response_capacity_boundaries_are_atomic():
    unit = device(0)
    exchange(unit, {"t": "cmd", "opt": ["ReportClientID"], "p": ["chosen-client"]})
    exchange(unit, {"t": "cmd", "opt": ["ReportClientID"], "p": [""]})
    assert unit.state["_tables"]["report_client"] == "chosen-client"
    before = deepcopy(unit.state)
    for names, values in [
        (["Pow", "SvLine"], [1, list(range(25))]),
        (["Pow", "ReportClientID"], [1, "x" * 17]),
    ]:
        with pytest.raises(InvalidPacket):
            exchange(unit, {"t": "cmd", "opt": names, "p": values})
        assert unit.state == before
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "status", "mac": unit.mac, "cols": ["hid"] * 34})
    assert unit.state == before
    cooker = device(7)
    before = deepcopy(cooker.state)
    with pytest.raises(InvalidPacket):
        exchange(cooker, {"t": "cmd", "opt": ["Pow", "CloudMenu"], "p": [1, list(range(46))]})
    assert cooker.state == before
