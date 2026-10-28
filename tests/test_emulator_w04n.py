"""Literal source-derived W04N callback, ordering and safe-boundary cases."""

import base64
import copy
import json
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import pytest

from gree_emulator.__main__ import load_config
from gree_emulator.wire import InvalidPacket

FIXTURES = Path(__file__).parent / "fixtures" / "emulator"
VECTORS = json.loads((FIXTURES / "w04n-raw_research.json").read_text())


def device(**overrides):
    return load_config({"seed": "n-callbacks", "devices": [
        {"id": "office", "profile": "sim-w04n-v17", "mid": "10001",
         "room_c": 26, "ambient_c": 26, **overrides},
    ]})[2][0]


def request(unit, operation, **fields):
    inner = {"t": operation, "mac": unit.mac, **fields}
    return request_raw(unit, json.dumps(inner, separators=(",", ":")).encode())


def request_raw(unit, plaintext):
    ciphertext = AES.new(unit.key, AES.MODE_ECB).encrypt(pad(plaintext, 16))
    outer = {"t": "pack", "i": 0, "uid": 23, "cid": "independent-peer",
             "tcid": unit.mac, "pack": base64.b64encode(ciphertext).decode()}
    return unit.profile.handler.handle(unit, outer)[0].inner


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda case: case["id"])
def test_source_callback_sequences_then_independent_fresh_status(case):
    unit = device()
    for name, value in case["commands"]:
        acknowledgement = request(unit, "cmd", opt=[name], p=[value])
        assert acknowledgement["p"] == acknowledgement["val"] == [value]
        assert acknowledgement["opt"] == [name]
        assert acknowledgement["r"] == 200
    fresh = request(unit, "status", cols=case["cols"])
    assert fresh["cols"] == case["cols"]
    assert fresh["dat"] == case["expected"]


@pytest.mark.parametrize("names,values", [
    (["Pow", "not-a-property"], [1, 1]),
    (["Pow", "BuzzerCtrl"], [1, 1]),
    (["Pow", "Null"], [1, 1]),
    (["Pow", "AllErr"], [1, 1]),
    (["Pow"], [True]), (["Pow"], ["1"]),
    (["Pow"], [None]), (["Pow"], []), (["Pow"], [[1]]), (["Pow"], [{"x": 1}]),
])
def test_safe_validation_is_atomic_without_claiming_native_parser_safety(names, values):
    unit = device()
    before = copy.deepcopy(unit.state), unit.room_c, unit.last_step
    with pytest.raises(InvalidPacket):
        request(unit, "cmd", opt=names, p=values)
    assert (unit.state, unit.room_c, unit.last_step) == before


def test_known_noop_is_not_unknown_and_every_getter_has_ordered_status():
    matrix = json.loads((FIXTURES / "w04n-coverage_research.json").read_text())
    unit = device()
    columns = matrix["v17_initial_columns"]
    expected = matrix["v17_initial_values"]
    for start in range(0, len(columns), 32):
        reply = request(unit, "status", cols=columns[start:start + 32])
        assert reply["cols"] == columns[start:start + 32]
        assert reply["dat"] == expected[start:start + 32]
    reply = request(unit, "status", cols=["Null", "unknown", "AirQ", "AirQ"])
    assert reply["cols"] == ["AirQ", "AirQ"]
    assert reply["dat"] == [0, 0]


def test_cache_is_per_device_and_restarts_from_declared_synthetic_defaults():
    first, second = device(), device()
    request(first, "cmd", opt=["Antifreeze", "WdSpd", "StSlp4C"], p=[1, 255, 4095])
    cols = ["AllErr", "LigSen", "SmartSlpMod", "StSlp4C"]
    assert request(first, "status", cols=cols)["dat"] == [1, 1, 7, 4095]
    assert request(second, "status", cols=cols)["dat"] == [0, 0, 0, 0]
    assert request(device(), "status", cols=cols)["dat"] == [0, 0, 0, 0]


def test_signed_raw_values_and_sensor_model_are_separate():
    unit = device()
    ack = request(unit, "cmd", opt=["SetTem", "TemSen", "RoomLen"], p=[-1, -1, -1])
    assert ack["p"] == [-1, -1, -1]
    assert ack["val"] == [-1, -1, -1]
    assert request(unit, "status", cols=["SetTem", "TemSen", "RoomLen"])["dat"] == [31, 26, 255]


@pytest.mark.parametrize("mid", ["10001", "10002", "10014", "10015", "10016", "10017",
                                  "11000", "11001", "11002", "11010", "11f00", "11f01",
                                  "11f02", "11f03", "13000"])
def test_preserved_runtime_mid_is_not_replaced_by_generic_fallback(mid):
    unit = device(mid=mid)
    assert request(unit, "status", cols=["mid", "hid"])["dat"] == [
        mid, "362001064973+U-W04NV17.bin"]


@pytest.mark.parametrize("requested,effective", [(2, 1), (4, 3), (5, 5), (255, 5)])
def test_actual_13000_fan_selector_is_not_generic_raw_fan(requested, effective):
    unit = device(mid="13000")
    ack = request(unit, "cmd", opt=["WdSpd"], p=[requested])
    assert ack["p"] == ack["val"] == [requested]
    assert request(unit, "status", cols=["WdSpd"])["dat"] == [effective]


def test_legacy_sleep_pair_uses_source_division_and_byte_readback():
    unit = device()
    ack = request(unit, "cmd", opt=["Slp1L1", "Slp1H1", "Slp1L2", "Slp1H2"],
                  p=[23, 23, 255, 255])
    assert ack["val"] == [23, 23, 255, 255]
    assert request(unit, "status", cols=["Slp1L1", "Slp1H1", "Slp1L2", "Slp1H2"])["dat"] == [44, 1, 250, 0]


def test_metadata_writes_use_source_effective_values_and_fresh_status():
    unit = device()
    ack = request(unit, "cmd", opt=["name", "host"], p=["A new name"])
    assert ack["opt"] == ["name", "host"]
    assert ack["p"] == ack["val"] == ["Anewname", "Anewname"]
    assert request(unit, "status", cols=["name", "host"])["dat"] == ["Anewname", "Anewname"]
    scan = unit.profile.handler.advertise(unit, {"t": "scan"})[0].inner
    assert scan["name"] == "Anewname"
    ack = request(unit, "cmd", opt=["AutoUpdate"], p=[257])
    assert ack["p"] == ack["val"] == [1]
    for value, effective in ((20, 0), (21, 1), (-10, 0), (-11, 1)):
        ack = request(unit, "cmd", opt=["lock"], p=[value])
        assert ack["p"] == ack["val"] == [effective]
        assert request(unit, "status", cols=["lock"])["dat"] == [effective]


def test_parser_metadata_precedes_numeric_controls_and_reuses_first_p():
    unit = device()
    ack = request(unit, "cmd", opt=["Pow", "AutoUpdate", "lock"], p=[1, 20])
    assert ack["opt"] == ["AutoUpdate", "lock", "Pow"]
    assert ack["p"] == ack["val"] == [1, 0, 1]
    assert request(unit, "status", cols=["Pow", "AutoUpdate", "lock"])["dat"] == [1, 1, 0]
    reply = request(unit, "status", opt=["name"], p=["Status with opt"])
    assert reply["cols"] == ["name"]
    assert reply["dat"] == ["Statuswithopt"]
    assert request(unit, "status", cols=["name"], opt=["name"], p=["Ignored"])["dat"] == ["Statuswithopt"]


def test_all_established_metadata_getters_and_native_no_output_case():
    unit = device()
    columns = ["time", "AppTimer", "rssi", "ReportClientID", "MOta", "mid"]
    reply = request(unit, "status", cols=columns)
    assert reply["cols"] == ["time", "AppTimer", "rssi", "MOta", "mid"]
    assert reply["dat"] == ["2000-01-01 00:00:00", 0, -50, "10001"]
    ack = request(unit, "cmd", opt=["ReportClientID"], p=["client-example"])
    assert ack["opt"] == ack["p"] == ack["val"] == []
    assert request(unit, "status", cols=["ReportClientID"])["cols"] == []


def test_synthetic_clock_preserves_established_string_wire_type():
    unit = device()
    text = "2026-10-24 12:34:56"
    ack = request(unit, "cmd", opt=["time"], p=[text])
    assert ack["p"] == ack["val"] == [text]
    assert request(unit, "status", cols=["time"])["dat"] == [text]
    before = copy.deepcopy(unit.state), unit.last_step
    with pytest.raises(InvalidPacket):
        request(unit, "cmd", opt=["time"], p=["2026-02-31 12:34:56"])
    assert (unit.state, unit.last_step) == before


def test_scheduler_prepass_reorders_duplicates_without_applying_other_controls():
    unit = device()
    ack = request(unit, "cmd", opt=["Pow", "dwRpt", "dwTsk", "dwRpt"], p=[1, 5, 3, 7])
    assert ack["opt"] == ["dwTsk", "dwRpt"]
    assert ack["p"] == ack["val"] == [3, 7]
    assert request(unit, "status", cols=["Pow"])["dat"] == [0]


@pytest.mark.parametrize("name,value", [("hid", "replacement"), ("mid", "10002"),
                                        ("rssi", -20), ("AppTimer", 1),
                                        ("name", "x" * 32), ("host", "x" * 32)])
def test_metadata_readonly_and_buffer_policy_reject_atomically(name, value):
    unit = device()
    before = copy.deepcopy(unit.state), unit.last_step
    with pytest.raises(InvalidPacket):
        request(unit, "cmd", opt=[name], p=[value])
    assert (unit.state, unit.last_step) == before


def test_original_json_integer_saturation_precedes_callback_masks_and_ack():
    unit = device()
    ack = request(unit, "cmd", opt=["SetTem", "RoomLen", "WdSpd"],
                  p=[2147483648, 4294967296, -2147483649])
    assert ack["p"] == ack["val"] == [2147483647, 2147483647, -2147483648]
    assert request(unit, "status", cols=["SetTem", "RoomLen", "WdSpd"])["dat"] == [31, 255, 0]


@pytest.mark.parametrize("profile", ["sim-w04n-v17", "sim-w04n-v19", "sim-w04n-jd-v12"])
@pytest.mark.parametrize("token,parsed,effective", [
    ("1.0", 1, 1),
    ("1.5", 1, 1), ("1e3", 1, 1), ("1e-3", 1, 1),
    ("-1.5", -1, 0), ("2.5", 2, 0),
    ("2147483648", (1 << 31) - 1, 0),
    ("-2147483649", -(1 << 31), 0), ("1e309", 1, 1),
])
def test_source_numeric_tokens_keep_integer_prefix_and_getter_readback(
        profile, token, parsed, effective):
    unit = device(profile=profile)
    plaintext = f'{{"t":"cmd","mac":"{unit.mac}","opt":["Pow"],"p":[{token}]}}'.encode()
    acknowledgement = request_raw(unit, plaintext)
    assert acknowledgement["p"] == [parsed]
    assert acknowledgement["val"] == [parsed]
    assert request(unit, "status", cols=["Pow"])["dat"] == [effective]


@pytest.mark.parametrize("profile,hid,scan_cid,scan_hid", [
    ("sim-w04n-v17", "362001064973+U-W04NV17.bin", True, True),
    ("sim-w04n-v19", "362001064973+U-W04NV19.bin", False, False),
    ("sim-w04n-jd-v12", "362001064270+U-BL3332_JDNEWV12.bin", True, True),
])
def test_exact_registered_build_identity_and_advertisement(profile, hid, scan_cid, scan_hid):
    unit = device(profile=profile)
    scan = unit.profile.handler.advertise(unit, {"t": "scan"})[0].inner
    assert scan["cid"] == (unit.mac if scan_cid else "")
    assert ("hid" in scan) is scan_hid
    if scan_hid:
        assert scan["hid"] == hid
    assert request(unit, "status", cols=["hid", "mid"])["dat"] == [hid, "10001"]
    ack = request(unit, "cmd", opt=["ACStupPos", "Air", "Buzzer_ON_OFF"], p=[255, 255, 1])
    assert ack["val"] == [255, 255, 1]
    assert request(unit, "status", cols=ack["opt"])["dat"] == [15, 3, 1]


@pytest.mark.parametrize("profile,temperature", [
    ("sim-w04n-v17", 26), ("sim-w04n-v19", 66), ("sim-w04n-jd-v12", 66),
])
def test_source_class_nine_changes_only_new_build_sensor_encoding(profile, temperature):
    unit = device(profile=profile)
    unit.state["_platform_class"] = 9
    assert request(unit, "status", cols=["TemSen"])["dat"] == [temperature]
    assert request(unit, "cmd", opt=["AssHt"], p=[2])["val"] == [2]


@pytest.mark.parametrize("profile", ["sim-w04n-v17", "sim-w04n-v19", "sim-w04n-jd-v12"])
def test_other_source_classes_do_not_authorize_auxiliary_auto_bit(profile):
    unit = device(profile=profile)
    unit.state["_platform_class"] = 3
    assert request(unit, "cmd", opt=["AssHt"], p=[2])["val"] == [2]
    assert request(unit, "status", cols=["AssHt", "TemSen"])["dat"] == [1, 26]


@pytest.mark.parametrize("text,effective", [
    ("a b", "ab"), ("a\tb", "a\tb"), ("a\\b", "a\\b"), ('a"b', 'a"b'), ("é", "é"),
])
def test_source_space_lexer_and_safe_valid_json_serialization(text, effective):
    unit = device()
    ack = request(unit, "cmd", opt=[" n a m e "], p=[text])
    assert ack["opt"] == ["name"]
    assert ack["p"] == ack["val"] == [effective]
    assert request(unit, "status", cols=[" n a m e "])["dat"] == [effective]


@pytest.mark.parametrize("profile", ["sim-w04n-v17", "sim-w04n-v19", "sim-w04n-jd-v12"])
@pytest.mark.parametrize("values,effective", [([1, 0], 1), ([0, 1], 0)])
def test_source_duplicate_names_use_first_value_for_wire_and_state(profile, values, effective):
    unit = device(profile=profile)
    request(unit, "cmd", opt=["Pow"], p=[1 - effective])
    ack = request(unit, "cmd", opt=["Pow", "Pow"], p=values)
    assert ack["p"] == values
    assert ack["val"] == [effective, effective]
    assert request(unit, "status", cols=["Pow"])["dat"] == [effective]


def test_escaped_space_survives_source_lexer_unlike_literal_ascii_space():
    unit = device()
    plain = b'{"t":"cmd","opt":["name"],"p":["a\\u0020b"]}'
    ciphertext = AES.new(unit.key, AES.MODE_ECB).encrypt(pad(plain, 16))
    outer = {"t": "pack", "i": 0, "uid": 23, "cid": "independent-peer",
             "tcid": unit.mac, "pack": base64.b64encode(ciphertext).decode()}
    ack = unit.profile.handler.handle(unit, outer)[0].inner
    assert ack["p"] == ack["val"] == ["a b"]
    assert request(unit, "status", cols=["name"])["dat"] == ["a b"]


@pytest.mark.parametrize("profile,effective", [
    ("sim-w04n-v17", 1), ("sim-w04n-v19", 0), ("sim-w04n-jd-v12", 1),
])
def test_heat_cool_getter_uses_exact_build_with_declared_feedback_input(profile, effective):
    unit = device(profile=profile)
    unit.state["_cache"][0x18f] = 2
    assert request(unit, "status", cols=["HeatCoolType"])["dat"] == [effective]
