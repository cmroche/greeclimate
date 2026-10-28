"""Independent source vectors and explicitly synthetic Hi3861 board/clock policies."""

import base64
from copy import deepcopy
import json
from pathlib import Path

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from gree_emulator.__main__ import load_config
from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles import PROFILES
from gree_emulator.profiles.hi3861 import GENERIC_KEY, _write
from gree_emulator.wire import InvalidPacket, decode_pack, encode_reply


FIXTURES = Path(__file__).parent / "fixtures" / "emulator"
RESEARCH = json.loads((FIXTURES / "session-hi3861_research.json").read_text())
VECTORS = [json.loads((FIXTURES / f"session-hi3861-{family}.json").read_text())
           for family in ("fan", "heater", "purifier", "softener", "air")]


def device_for(vector=VECTORS[0], *, mid=None, mac="020000000001", key=b"0123456789AbCdEf"):
    profile = PROFILES[vector["profile"]]
    return EmulatedDevice("hi3861", mac, "", mid or vector["mid"], key, profile,
                          deepcopy(dict(profile.initial_state)), room_c=None,
                          ambient_c=None, last_step=1000)


def packet(device, inner=None, *, index=0, key=None, plaintext=None):
    key = key if key is not None else GENERIC_KEY if index else device.key
    if plaintext is None:
        plaintext = json.dumps(inner, separators=(",", ":")).encode()
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(plaintext, 16))
    return {"t": "pack", "i": index, "uid": 9, "cid": "peer", "tcid": device.mac,
            "pack": base64.b64encode(encrypted).decode()}


def unpack(reply):
    raw = encode_reply(reply)
    assert not raw.endswith(b"\n")
    outer = json.loads(raw)
    ciphertext = base64.b64decode(outer.pop("pack"), validate=True)
    inner = json.loads(unpad(AES.new(reply.key, AES.MODE_ECB).decrypt(ciphertext), 16))
    return outer, inner


def exchange(device, inner, *, index=0):
    reply, = device.profile.handler.handle(device, packet(device, inner, index=index))
    outer, result = unpack(reply)
    assert outer == {"t": "pack", "i": index, "uid": 9,
                     "cid": device.mac, "tcid": "peer"}
    return result


def status(device, names):
    return exchange(device, {"t": "status", "cols": names})["dat"]


def command(device, names, values):
    return exchange(device, {"t": "cmd", "opt": names, "p": values})


@pytest.mark.parametrize("vector", VECTORS, ids=lambda row: row["profile"])
def test_independent_normal_wire_and_chosen_board_echo_vectors(vector):
    device = device_for(vector)
    assert status(device, vector["source_columns"]) == vector["startup_dat"]
    for request, expected in zip(vector["requests"], vector["expected_replies"], strict=True):
        if request["outer"]["t"] == "scan":
            replies = device.profile.handler.advertise(device, request["outer"])
        else:
            outer = packet(device, request["inner"], index=request["outer"]["i"],
                           key=request["key"].encode())
            outer.update(request["outer"])
            replies = device.profile.handler.handle(device, outer)
        decoded = [dict(zip(("outer", "inner"), unpack(reply))) for reply in replies]
        assert decoded == expected
    assert {name: value for name, value in device.state.items()
            if not name.startswith("_")} == vector["expected_state"]


@pytest.mark.parametrize("vector", VECTORS, ids=lambda row: row["profile"])
def test_every_source_getter_with_independent_raw_frame_projection(vector):
    device = device_for(vector)
    raw = vector["raw_report_vector"]
    device.state["_midtype"] = raw["midtype"]
    device.state["_error_flags"] = tuple(raw["error_flags"])
    for flag in raw["flags"]:
        device.profile.handler.receive_report(device, flag, bytes.fromhex(raw["bytes_hex"]))
    assert status(device, vector["source_columns"]) == raw["expected_dat"]
    before = deepcopy(device.state)
    device.advance(100000)
    assert device.state == before
    assert device.profile.handler.thermal_target(device) is None


@pytest.mark.parametrize("vector", VECTORS, ids=lambda row: row["profile"])
def test_every_descriptor_command_retains_requested_ack_and_exact_name(vector):
    device = device_for(vector)
    names = vector["source_columns"]
    result = command(device, names, [257] * len(names))
    assert result == {"t": "res", "mac": device.mac, "p": [257] * len(names),
                      "opt": names, "r": 200}
    assert len(status(device, names)) == len(names)
    assert status(device, ["NoSuch", "pow", "BuzzerCtrl", "_clock"]) == [0, 0, 0, 0]


@pytest.mark.parametrize("vector", VECTORS, ids=lambda row: row["profile"])
def test_all_conditional_mids_discover_without_hid_and_retain_raw_metadata(vector):
    for mid in vector["mids"]:
        device = device_for(vector, mid=mid)
        reply, = device.profile.handler.advertise(device, {"t": "scan"})
        outer, inner = unpack(reply)
        assert outer == {"t": "pack", "i": 1, "uid": 0, "cid": "", "tcid": ""}
        assert inner == {"t": "dev", "cid": "", "bc": "gree", "brand": "gree",
                         "catalog": "gree", "mac": device.mac, "mid": mid, "model": "gree",
                         "name": "", "lock": 0, "series": "gree", "vender": "1", "ver": "V3.0.0"}
        assert status(device, ["hid", "mid", "vender", "bc", "ver"]) == [
            RESEARCH["hid"], "", "", "67726565", "V3.0.0"]


def test_metadata_grouping_duplicates_host_split_name_noop_and_pending_byte_buffer():
    device = device_for()
    result = command(device, ["Pow", "lat", "Pow", "lat", "lon", "ReportClientID"],
                     [1, "23.123", 2, "final", "notnumeric", "client01"])
    assert result == {"t": "res", "mac": device.mac,
                      "p": ["final", "final", "notnumeric", 1, 2],
                      "opt": ["lat", "lat", "lon", "Pow", "Pow"], "r": 200}
    assert status(device, ["lat", "Pow", "lon", "ReportClientID"]) == ["final", 0, "notnumeric", 0]
    assert device.state["_client_id_pending"] is True
    assert device.state["_client_id_buffer"] == b"\x7e\x7e\x12\x6aclient01" + bytes(18)
    assert command(device, ["name", "host"], ["ignored", "example.test"])["p"] == ["", "dis.gree.com"]
    assert device.name == ""
    assert device.state["_configured_host"] == "example.test"
    assert status(device, ["name", "host"]) == ["", "dis.gree.com"]
    assert command(device, ["lock", "AutoUpdate", "hid", "mid", "bc", "DevID", "MafIdf"],
                   [9] * 7)["p"] == [0, 0, RESEARCH["hid"], "", "67726565", 0, 0]
    # Non-classifier metadata names follow ordinary requested ACK handling.
    assert command(device, ["rssi", "ver", "vender", "Subcount"], [1, 2, 3, 4])["p"] == [1, 2, 3, 4]
    assert status(device, ["rssi", "ver", "vender", "Subcount"]) == [-50, "V3.0.0", "", 0]


def test_apptimer_source_cardinality_irregularity_and_empty_batches():
    device = device_for()
    assert command(device, ["Pow", "AppTimer", "ReportClientID"], [1, 7, ""]) == {
        "t": "res", "mac": device.mac, "p": [1], "opt": ["AppTimer", "Pow"], "r": 200}
    assert status(device, ["AppTimer", "ReportClientID", "Pow"]) == [0, 0, 1]
    assert command(device, [], []) == {"t": "res", "mac": device.mac, "p": [], "opt": [], "r": 200}
    assert status(device, []) == []


def test_complete_calendar_time_raw_record_and_signed_rssi_provider():
    device = device_for()
    assert command(device, ["time"], ["2028-02-29 23:59:58"])["p"] == ["2028-02-29 23:59:58"]
    assert device.state["_clock"] == bytes.fromhex("ec073a3b17001d02")
    device.advance(999999)
    assert status(device, ["time"]) == ["2028-02-29 23:59:58"]
    for byte, expected in [(0, 0), (127, 127), (128, -128), (255, -1)]:
        device.state["_rssi"] = byte
        assert status(device, ["rssi"]) == [expected]


@pytest.mark.parametrize("value,ack,effective", [
    (4294967295, -1, 255), (2147483648, -2147483648, 0),
    (" -1suffix", -1, 255), ("4294967297", 1, 1),
    (257.9, 257, 1), ("257.9", 257, 1), ("nonnumeric", 0, 0),
])
def test_original_atoi_width_sign_and_requested_ack_versus_projected_byte(value, ack, effective):
    device = device_for()
    assert command(device, ["Temperature"], [value])["p"] == [ack]
    assert status(device, ["Temperature"]) == [effective]


@pytest.mark.parametrize("value,expected_cache,expected_byte", [
    (-1, -1, 128), (0, 0, 0), (1, 1, 128), (2, 2, 0),
    (255, 255, 128), (256, 256, 0), (2147483648, -2147483648, 0),
])
def test_native_scalar_cache_and_mask_before_synthetic_board_completion(value, expected_cache, expected_byte):
    device = device_for()
    row = device.profile.handler.by_name["Pow"]
    _write(device.state, device.mid, row, value)
    assert status(device, ["Pow"]) == [expected_cache]
    assert device.state["_controls"][0x91][4] == expected_byte


def test_native_fan_callback_guards_and_configured_mid_exception():
    for mid, expected_cache, expected_byte in [("828202", 0, 0xa0), ("828210", 7, 0xa7)]:
        device = device_for(mid=mid)
        frame = device.state["_controls"][0x91]
        frame[4], frame[5], frame[9] = 0xa0, 255, 1
        _write(device.state, mid, device.profile.handler.by_name["Mod"], 7)
        assert status(device, ["Mod"]) == [expected_cache]
        assert frame[4] == expected_byte
        assert frame[5] == (0 if mid == "828202" else 255)
    device = device_for()
    device.state["_controls"][0x91][9] = 1
    _write(device.state, device.mid, device.profile.handler.by_name["WdSpd"], 255)
    assert status(device, ["WdSpd"]) == [0]
    assert device.state["_controls"][0x91][5] == 1
    # Whole command uses a separately declared immediate board echo, not this native timing.
    assert command(device, ["WdSpd"], [255])["p"] == [255]
    assert status(device, ["WdSpd"]) == [1]


def test_timer_exact_one_clamping_signed_cache_and_fresh_report():
    device = device_for(VECTORS[4])
    frame = device.state["_controls"][0x93]
    frame[4:6] = bytes.fromhex("e0c0")
    _write(device.state, device.mid, device.profile.handler.by_name["StTmr"], 61)
    assert frame[4:6] == bytes.fromhex("e1c1")
    assert status(device, ["StTmr"]) == [61]
    assert command(device, ["StTmr", "TmrOn"], [1441, 1])["p"] == [1441, 1]
    assert status(device, ["StTmr", "TmrOn", "TmrOff"]) == [1440, 1, 0]
    command(device, ["TmrOff"], [2])
    assert status(device, ["TmrOn", "TmrOff"]) == [1, 0]
    assert command(device, ["StTmr"], ["-1"])["p"] == [-1]
    assert status(device, ["StTmr", "TmrOn", "TmrOff"]) == [0, 0, 0]
    raw = bytearray(52)
    raw[4:6] = bytes.fromhex("a101")
    device.profile.handler.receive_report(device, 0x93, bytes(raw))
    assert status(device, ["StTmr", "TmrOn", "TmrOff"]) == [61, 1, 0]


@pytest.mark.parametrize("family,flag,positions,names,expected", [
    (0, 0x94, {12: 128, 13: 255}, ["PM25"], [65408]),
    (4, 0x94, {15: 255, 16: 128, 10: 1, 11: 2, 12: 3, 13: 4},
     ["FiltUT", "wipm25", "wopm25"], [65408, 258, 772]),
    (2, 0x94, {12: 128, 13: 255, 30: 0, 31: 254},
     ["LifeFilterDays1", "TotalPureWater"], [65408, 65024]),
    (3, 0x94, {7: 255, 8: 128, 11: 18, 12: 52, 13: 86, 14: 120, 15: 154, 16: 188},
     ["RecycleTotalT", "InsFlowRate", "CycleFlowRate", "SaltTotalT"], [33023, 13330, 30806, 48282]),
    (2, 0x95, {4: 255, 5: 128}, ["ErrorCode1"], [33023]),
])
def test_independently_sourced_endian_report_vectors(family, flag, positions, names, expected):
    device = device_for(VECTORS[family])
    raw = bytearray(52)
    for offset, value in positions.items():
        raw[offset] = value
    device.profile.handler.receive_report(device, flag, bytes(raw))
    assert status(device, names) == expected


@pytest.mark.parametrize("names,values", [
    (["Pow", "Mod"], [1]), (["Pow"], [1, 2]), (["Pow"], "1"),
    (["Pow", "Mod"], [1, True]), (["Pow", "Mod"], [1, None]),
    (["Pow", "Mod"], [1, {}]), (["Pow", "Mod"], [1, []]),
    (["Pow", "Mod"], [1, -1]), (["Pow", "Mod"], [1, float("inf")]),
    (["Pow", "Mod"], [1, 2**64]), (["Pow", "Mod"], [1, "x" * 65]),
    (["Pow", ""], [1, 1]), (["Pow", "Bad\0Name"], [1, 1]),
    (["Pow", "x" * 20], [1, 1]), (["Pow", None], [1, 1]),
    (["Pow"] * 65, [1] * 65), (["Pow", "lat"], [1, ""]),
    (["Pow", "lat"], [1, "x" * 11]), (["Pow", "lon"], [1, 5]),
    (["Pow", "host"], [1, "x" * 21]), (["Pow", "time"], [1, "2026"]),
    (["Pow", "time"], [1, "2026-02-29 00:00:00"]),
    (["Pow", "ReportClientID"], [1, "x" * 17]),
    (["Pow", "ReportClientID"], [1, "é"]),
    (["lat", "time", "host"] * 20, ["1234567890", "2026-10-24 12:34:56", "example.test"] * 20),
])
def test_malformed_or_oversize_batches_are_atomic_and_recover(names, values):
    device = device_for()
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        command(device, names, values)
    assert device.state == before and device.last_step == 1000
    assert command(device, ["Pow"], [1])["p"] == [1]
    assert status(device, ["Pow"]) == [1]


@pytest.mark.parametrize("columns", ["Pow", [None], [""], ["a" * 20], ["Pow\0"], ["Pow"] * 65,
                                        ["hid"] * 50])
def test_invalid_or_oversize_status_does_not_mutate(columns):
    device = device_for()
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        status(device, columns)
    assert device.state == before and device.last_step == 1000


def test_both_key_slots_bind_persistence_identity_precedence_and_uid_routes():
    device = device_for()
    for index in (0, 1, 1, 0):
        assert exchange(device, {"t": "bind"}, index=index) == {
            "r": 200, "t": "bindok", "mac": device.mac, "key": device.key.decode()}
        assert exchange(device, {"t": "status", "cols": ["Pow"]}, index=index)["dat"] == [0]
    assert exchange(device, {"t": "bind", "mac": "supplied"}, index=1)["mac"] == "supplied"
    assert exchange(device, {"t": "status", "sub": "fallback", "cols": []})["mac"] == "fallback"
    assert exchange(device, {"t": "status", "mac": "preferred", "sub": "ignored", "cols": []})["mac"] == "preferred"
    assert status(device, ["mac"]) == [device.mac]
    for uid in (-2147483648, 2147483647):
        outer = {**packet(device, {"t": "status", "cols": []}), "uid": uid}
        reply, = device.profile.handler.handle(device, outer)
        metadata, inner = unpack(reply)
        assert metadata["uid"] == uid and inner["uid"] == 0


def test_wrong_targets_keys_selector_routes_and_duplicate_json_reject_without_mutation():
    device = device_for()
    bad = [
        {**packet(device, {"t": "cmd", "opt": ["Pow"], "p": [1]}), "tcid": "other"},
        packet(device, {"t": "cmd", "opt": ["Pow"], "p": [1]}, key=b"fedcba9876543210"),
        {**packet(device, {"t": "status", "cols": []}), "i": 2},
        {**packet(device, {"t": "status", "cols": []}), "i": True},
        {**packet(device, {"t": "status", "cols": []}), "uid": True},
        {**packet(device, {"t": "status", "cols": []}), "cid": "x" * 64},
        packet(device, {"t": "status", "mac": "x" * 32, "cols": []}),
        packet(device, plaintext=b'{"t":"cmd","opt":["Pow"],"p":[1],"p":[0]}'),
        {**packet(device, {"t": "status", "cols": []}), "pack": "!!!!"},
        {**packet(device, {"t": "status", "cols": []}), "pack": base64.b64encode(b"x").decode()},
    ]
    for outer in bad:
        before = deepcopy(device.state)
        with pytest.raises(InvalidPacket):
            device.profile.handler.handle(device, outer)
        assert device.state == before and device.last_step == 1000
    for kind in ("upgrade", "reset", "subDev", "mate", "unknown"):
        assert device.profile.handler.handle(device, packet(device, {"t": kind})) == []


def test_isolation_restart_and_config_seeded_key_stability():
    config = {"seed": "hi3861-independent", "devices": [
        {"id": "fan", "profile": VECTORS[0]["profile"], "mid": "828210", "name": "Synthetic fan"},
        {"id": "air", "profile": VECTORS[4]["profile"], "mid": "828105"}]}
    first, second = load_config(config)[2]
    before = deepcopy(second.state)
    command(first, ["Pow", "lat", "host"], [1, "synthetic", "example.test"])
    assert second.state == before
    assert command(first, ["name"], ["ignored"])["p"] == ["Synthetic fan"]
    first_key, second_key = first.key, second.key
    restarted_first, restarted_second = load_config(config)[2]
    assert (restarted_first.key, restarted_second.key) == (first_key, second_key)
    assert status(restarted_first, ["Pow", "lat", "host"]) == [0, "", "dis.gree.com"]
    assert status(first, ["Pow", "lat", "host"]) == [1, "synthetic", "dis.gree.com"]
    assert restarted_first.state["_controls"] is not first.state["_controls"]
    assert restarted_first.room_c is restarted_second.room_c is None


def test_reply_preflight_occurs_before_metadata_cache_or_clock_mutation():
    device = device_for()
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket, match="reply exceeds"):
        command(device, ["lat", "time"] + ["hid"] * 30,
                ["changed", "2028-02-29 23:59:58"] + [0] * 30)
    assert device.state == before and device.last_step == 1000


def test_complete_metadata_getters_precede_unknown_fallback():
    device = device_for()
    columns = ["hid", "ver", "bc", "mac", "BtHid", "MOta", "DevID", "MafIdf",
               "Proaddr", "Subcount", "lock", "AutoUpdate", "lat", "lon", "host",
               "time", "rssi", "mid", "vender", "name", "ReportClientID", "AppTimer"]
    assert status(device, columns) == [
        RESEARCH["hid"], "V3.0.0", "67726565", device.mac, 0, 0, 0, 0, 0, 0,
        0, 0, "", "", "dis.gree.com", "2026-01-01 00:00:00", -50, "", "", "", 0, 0]


def test_new_report_overrides_requested_cache_and_preserves_field_order():
    device = device_for()
    assert command(device, ["Pow", "Pow", "Mod", "Temperature"], [1, 2, 9, 257])["p"] == [1, 2, 9, 257]
    raw = bytearray(52)
    raw[4], raw[6] = 0x82, 0x80
    device.profile.handler.receive_report(device, 0x94, bytes(raw))
    assert status(device, ["Temperature", "Pow", "Mod", "Pow"]) == [128, 1, 2, 1]


@pytest.mark.parametrize("token,requested,effective", [
    (b"1e3", 1, 1), (b"1e-3", 1, 1), (b"1E+3", 1, 1),
    (b"-1.0e3", -1, 255), (b"4294967295e0", -1, 255),
    (b"4294967296e0", 0, 0), (b"4294967297", 1, 1),
    (b"\"-1e3\"", -1, 255), (b"\"1e999\"", 1, 1),
])
def test_raw_json_numeric_lexemes_reach_source_atoi_without_float_normalization(token, requested, effective):
    device = device_for()
    plain = b'{"t":"cmd","opt":["Temperature"],"p":[' + token + b']}'
    reply, = device.profile.handler.handle(device, packet(device, plaintext=plain))
    _, result = unpack(reply)
    assert result["p"] == [requested]
    assert status(device, ["Temperature"]) == [effective]
    assert command(device, ["Temperature"], [2])["p"] == [2]
    assert status(device, ["Temperature"]) == [2]


@pytest.mark.parametrize("token", [
    b"-1e3", b"-1e-3", b"-0", b"-0e3", b"1e999", b"-1.0e999",
    b"NaN", b"Infinity", b"-Infinity", b"18446744073709551616",
    b"1e9999999999999999999999",
    b"1" * 65,
])
def test_unsafe_or_nonfinite_raw_numeric_tokens_reject_entire_batch_and_recover(token):
    device = device_for()
    before = deepcopy(device.state)
    plain = b'{"t":"cmd","opt":["Pow","Temperature"],"p":[1,' + token + b']}'
    with pytest.raises(InvalidPacket):
        device.profile.handler.handle(device, packet(device, plaintext=plain))
    assert device.state == before and device.last_step == 1000
    assert command(device, ["Pow"], [1])["p"] == [1]
    assert status(device, ["Pow"]) == [1]


def test_lexical_number_parser_is_hi3861_only_and_does_not_turn_numbers_into_strings():
    device = device_for()
    outer = packet(device, plaintext=b'{"t":"cmd","opt":["Temperature"],"p":[1e3]}')
    assert decode_pack(outer, device.key, "aes-ecb-pkcs7")["p"] == [1000.0]
    reply, = device.profile.handler.handle(device, outer)
    assert unpack(reply)[1]["p"] == [1]
    before = deepcopy(device.state)
    for plain in (b'{"t":"cmd","opt":["lat"],"p":[1e3]}',
                  b'{"t":"cmd","opt":[1e3],"p":[1]}'):
        with pytest.raises(InvalidPacket):
            device.profile.handler.handle(device, packet(device, plaintext=plain))
        assert device.state == before
