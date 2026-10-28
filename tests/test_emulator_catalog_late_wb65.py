"""Exact-source late WB65VR presets; cached sensors are synthetic, not physics."""

import base64
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.profiles import catalog_late_wb65 as family
from gree_emulator.wire import InvalidPacket, decode_outer, encode_reply


FIXTURES = Path(__file__).parent / "fixtures" / "emulator"
MAC = "020000000001"
KEY = b"0123456789abcdef"
GENERIC = b"{yxAHAY_Lm6pbC/<"
NONCE = bytes.fromhex("5440784449675a516c5e6313")
VERSIONS = ("v210", "v211", "v105")


def evidence(version):
    return json.loads((FIXTURES / f"catalog-late-wb65-{version}_research.json").read_text())


def device(version):
    source = evidence(version)
    profile = next(profile for profile in family.PROFILES if profile.id == source["profile_id"])
    return SimpleNamespace(mac=MAC, mid="10001", name="Late WB65", key=KEY,
                           last_step=1000, profile=profile, state=dict(profile.initial_state))


def packet(inner=None, *, literal=None, index=0, uid=42, gcm=True):
    plain = literal if literal is not None else json.dumps(inner, separators=(",", ":")).encode()
    key = GENERIC if index else KEY
    outer = {"t": "pack", "i": index, "uid": uid, "cid": "app", "tcid": MAC}
    if gcm:
        cipher = AES.new(key, AES.MODE_GCM, nonce=NONCE)
        cipher.update(b"qualcomm-test")
        encrypted, tag = cipher.encrypt_and_digest(plain)
        outer["tag"] = base64.b64encode(tag).decode()
    else:
        encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(plain, 16))
    outer["pack"] = base64.b64encode(encrypted).decode()
    return outer


def encoded(reply):
    data = encode_reply(reply)
    if reply.raw_payload is None:
        assert b"\n" not in data and b"\r" not in data
    return data


def response(reply, *, discovery=False, index=None, uid=None):
    outer = json.loads(encoded(reply))
    assert outer["t"] == "pack"
    assert set(outer) == {"t", "i", "uid", "cid", "tcid", "pack"} | (
        set() if discovery else {"tag"})
    assert type(outer["i"]) is int and type(outer["uid"]) is int
    if index is not None:
        assert outer["i"] == index
    if uid is not None:
        assert outer["uid"] == uid
    ciphertext = base64.b64decode(outer["pack"], validate=True)
    if discovery:
        assert "tag" not in outer
        plain = unpad(AES.new(b"a3K8Bx%2r8Y7#xDh", AES.MODE_ECB).decrypt(ciphertext), 16)
    else:
        cipher = AES.new(GENERIC if outer["i"] else KEY, AES.MODE_GCM, nonce=NONCE)
        cipher.update(b"qualcomm-test")
        plain = cipher.decrypt_and_verify(ciphertext, base64.b64decode(outer["tag"], validate=True))
    assert outer["cid"] == MAC and outer["tcid"] == ""
    assert b"\n" not in plain and b"\r" not in plain
    return json.loads(plain)


def exchange(root, inner=None, **kwargs):
    reply, = root.profile.handler.handle(root, packet(inner, **kwargs))
    return response(reply, index=kwargs.get("index", 0), uid=kwargs.get("uid", 42))


@pytest.mark.parametrize("version", VERSIONS)
def test_exact_payload_namespace_and_native_admission_role(version):
    source, root = evidence(version), device(version)
    assert root.profile.source_sha256 == source["source_sha256"]
    assert root.profile.hid == source["hid"]
    assert root.profile.mids == ("10001",)
    assert list(root.profile.handler.numeric_slots) == source["numeric_slots"]
    assert len(root.profile.handler.numeric_slots) == 495
    assert source["native_admission"]["literal_mid_match"]
    assert all(stage["returned"] and stage["mid_word"] == 65537
               and stage["mid_string"] == "10001" for stage in source["native_admission"]["stages"])
    reply, = root.profile.handler.advertise(root, {"t": "scan"})
    advertised = response(reply, discovery=True)
    assert set(advertised) == set(source["wire_runtime"]["advertisement_fields"])
    assert advertised["t"] == "dev" and advertised["mid"] == "10001"
    assert advertised["hid"] == source["hid"] and advertised["mac"] == MAC
    assert advertised["cid"] == ""
    assert ("ModelType" in advertised) == (version != "v105")
    assert exchange(root, {"t": "status", "cols": ["mid", "hid"]})["dat"] == ["", source["hid"]]


@pytest.mark.parametrize("version", VERSIONS)
def test_every_finite_raw_cache_field_unsigned_fresh_readback(version):
    root = device(version)
    names = dict.fromkeys(name for name in evidence(version)["numeric_slots"]
                          if name and name not in root.profile.handler.special)
    for name in names:
        ack = exchange(root, {"t": "cmd", "opt": [name], "p": [65537]})
        assert ack["opt"] == [name] and ack["p"] == [65537]
        assert exchange(root, {"t": "status", "cols": [name]})["dat"] == [1]
        ack = exchange(root, {"t": "cmd", "opt": [name], "p": [-1]})
        assert ack["p"] == [-1]
        assert exchange(root, {"t": "status", "cols": [name]})["dat"] == [65535]


@pytest.mark.parametrize("version", VERSIONS)
def test_metadata_overrides_raw_slots_and_hid_is_initialized(version):
    root = device(version)
    root.state.update({"hid": 65535, "mid": 65535, "name": 65535, "ModelType": 65535})
    result = exchange(root, {"t": "status", "cols": ["hid", "mid", "name", "ModelType"]})
    assert result["dat"] == [root.profile.hid, "", root.name, ""]
    assert exchange(root, {"t": "status", "cols": ["not-a-property", "Pow"]})["cols"] == ["Pow"]


def test_v105_does_not_union_later_four_sensor_slots():
    old, later = device("v105"), device("v210")
    names = ["OutEnvTem", "InEvaTem", "CompressorTem", "CompressorFqy"]
    assert exchange(old, {"t": "status", "cols": names})["cols"] == []
    assert exchange(later, {"t": "status", "cols": names})["dat"] == [0, 0, 0, 0]


@pytest.mark.parametrize("version", VERSIONS)
def test_every_qualified_local_metadata_getter_overrides_numeric_cache(version):
    root = device(version)
    for name, kinds in evidence(version)["metadata_getter_argument_kinds"].items():
        root.state[name] = 65535
        result = exchange(root, {"t": "status", "cols": [name]})
        assert result["cols"] == [name]
        assert len(result["dat"]) == len(kinds)
        for value, kind in zip(result["dat"], kinds):
            assert type(value) is (str if kind == "string" else int)

@pytest.mark.parametrize("version", VERSIONS)
def test_duplicate_numeric_ack_is_distinct_from_final_cache(version):
    root = device(version)
    ack = exchange(root, {"t": "cmd", "opt": ["Pow", "Pow"], "p": [65537, -1]})
    assert ack["p"] == [65537, -1]
    assert exchange(root, {"t": "status", "cols": ["Pow", "Pow"]})["dat"] == [65535, 65535]


@pytest.mark.parametrize("version", VERSIONS)
def test_wrong_codec_does_not_mutate(version):
    root = device(version)
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        root.profile.handler.handle(root, packet({"t": "status", "cols": ["Pow"]}, gcm=False))
    assert root.state == before


@pytest.mark.parametrize("version", VERSIONS)
def test_native_unknown_cache_name_echoes_but_does_not_create_a_field(version):
    root = device(version)
    ack = exchange(root, {"t": "cmd", "opt": ["Pow", "not-a-property"], "p": [1, 2]})
    assert ack["opt"] == ["Pow", "not-a-property"] and ack["p"] == [1, 2]
    assert "not-a-property" not in root.state
    assert exchange(root, {"t": "status", "cols": ["Pow", "not-a-property"]})["dat"] == [1]


@pytest.mark.parametrize("version", VERSIONS)
def test_wire_contract_is_exact_and_source_evidence_is_scoped(version):
    source, root = evidence(version), device(version)
    wire = source["wire_runtime"]
    operations = ["bind", "status", "cmd", "upgrade", "setT", "queryT",
                  "deleteT", "updateT", "dump"]
    if version != "v105":
        operations.append("binCmd")
    assert wire["operation_table"] == operations
    assert wire["transport"]["udp_reply_appends_lf"] is False
    assert wire["transport"]["receive_buffer_bytes"] == 1460
    assert wire["codec"]["tag_length_bytes"] == 16
    assert wire["codec"]["tag_decoder_length_equality_check"] is False
    assert wire["codec"]["json_number_parser"] == (
        "WB65 token retention plus cmd decimal-prefix cursor: 1e3 and 1e309 -> 1; "
        "shared exponent suffix feeds the next p item (1e3,2 -> 1,3); "
        "fractions truncate toward zero before uint16 cache conversion")
    assert source["command_parse_native"]["artifact"] == (
        "CatalogQuirks/RealtekLate/WB65VR/command-parse-native-results.json")
    assert wire["plain_hooks"]["types"] == ["wlan", "hbok", "tm"]
    assert wire["timers"]["record_fields"] == [
        "id", "name", "enable", "week", "hr", "min", "sec", "cmd"]
    assert wire["completion_boundaries"]["registered_reset"] is False
    assert wire["timers"]["cache_capacity"] == 10
    assert wire["evidence_basis"]["callback_execution"] == "static-source-only"
    assert wire["evidence_basis"]["native_admission_scope"] == (
        "configured UART producer through dev builder only; not callback replay or a physical MID claim")
    if version == "v105":
        assert "binCmd_limits" not in wire
    else:
        assert wire["binCmd_limits"]["decoded_frame_bytes"] == 60
        assert wire["binCmd_limits"]["ReportClientID_max"] == 26
    assert root.profile.source_sha256 == source["source_sha256"]


@pytest.mark.parametrize("version", VERSIONS)
def test_all_local_operation_acknowledgements(version):
    root = device(version)
    assert exchange(root, {"t": "bind", "mac": MAC}) == {
        "t": "bindok", "r": 200, "mac": MAC, "key": KEY.decode("ascii")}
    assert exchange(root, {"t": "status", "cols": ["Pow"]}) == {
        "t": "dat", "uid": 42, "mac": MAC, "cid": MAC,
        "r": 200, "cols": ["Pow"], "dat": [0]}
    assert exchange(root, {"t": "cmd", "opt": ["Pow"], "p": [17]}) == {
        "t": "res", "r": 200, "mac": "", "opt": ["Pow"], "p": [17]}
    assert exchange(root, {"t": "upgrade", "url": "https://example.invalid/fw.bin"}) == {
        "t": "ret", "r": 200}
    assert exchange(root, {"t": "dump", "period": 30, "cnt": 2}) == {
        "t": "ret", "r": 200}
    before = deepcopy(root.state)
    assert root.profile.handler.handle(root, packet({"t": "reset"})) == []
    assert root.state == before

@pytest.mark.parametrize("version", VERSIONS)
def test_generic_gcm_selector_uses_source_global_key(version):
    root = device(version)
    assert exchange(root, {"t": "status", "cols": ["Pow"]}, index=1)["dat"] == [0]


@pytest.mark.parametrize("version", VERSIONS)
def test_upgrade_url_destination_is_bounded(version):
    root = device(version)
    url = "https://" + "x" * (119 - len("https://"))
    assert len(url) == 119
    assert exchange(root, {"t": "upgrade", "url": url}) == {"t": "ret", "r": 200}
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "upgrade", "url": url + "x"})
    assert root.state == before


@pytest.mark.parametrize("version", VERSIONS)
def test_timer_grammar_cache_projection_and_local_ack(version):
    root = device(version)
    timer = {
        "t": "setT", "id": 258, "name": "night", "enable": 1, "tz": 0,
        "hr": 6, "min": 45, "sec": 59, "week": [1, 0, 1, 0, 0, 1, 0],
        "cmd": [{"mac": MAC, "opt": ["Pow"], "p": [17]}],
    }
    assert exchange(root, timer) == {"t": "resT", "r": 200}
    listed = exchange(root, {"t": "queryT", "index": 0, "count": 10})
    assert listed["t"] == "listT"
    assert listed["total"] == 1 and listed["index"] == 0
    assert listed["list"] == [{
        "id": 2, "name": "night", "enable": 1, "week": [1, 0, 1, 0, 0, 1, 0],
        "hr": 6, "min": 45, "sec": 0,
        "cmd": [{"mac": MAC, "opt": ["Pow"], "p": [17]}],
    }]
    updated = dict(timer, t="updateT", name="later",
                   cmd=[{"mac": MAC, "opt": ["Pow"], "p": [23]}])
    assert exchange(root, updated) == {"t": "resT", "r": 200}
    listed = exchange(root, {"t": "queryT", "index": 0, "count": 10})
    assert listed["list"][0]["name"] == "later"
    assert listed["list"][0]["sec"] == 0
    assert listed["list"][0]["cmd"][0]["p"] == [23]
    assert exchange(root, {"t": "deleteT", "id": 258}) == {"t": "resT", "r": 200}
    assert exchange(root, {"t": "queryT", "index": 0, "count": 10}) == {
        "t": "listT", "total": 0, "index": 0, "list": []}


@pytest.mark.parametrize("version", ("v210", "v211"))
def test_bin_cmd_frame_report_client_and_frequency_effects(version):
    root = device(version)
    for client_id, frequency, byte7 in ((None, 0x123, 0xAF), ("Unit-7", 0xFF, 0)):
        frame = bytearray(44)
        frame[:3] = b"\x7e\x7e\x2a"
        frame[7], frame[43] = 0x7E, 0x01
        inner = {"t": "binCmd", "hex01": base64.b64encode(frame).decode("ascii"),
                 "ReportFreq": frequency}
        if client_id is not None:
            inner["ReportClientID"] = client_id
        assert exchange(root, inner) == {"t": "res", "r": 200}
        state = root.state["_wb65vr"]
        expected = bytearray(frame)
        expected[7], expected[43] = byte7, 0x03
        assert state["binary_frames"][-1] == bytes(expected)
        assert state["report_frequency"] == (60 if frequency == 0xFF else 0x4000 + (frequency & 0xFF))
        assert state["report_frequency_neighbor"] == 0x405A
    assert root.state["_wb65vr"]["report_client_frame"] == (
        b"\x7e\x7e\x12\x6aUnit-7" + bytes(30 - 4 - len("Unit-7")))
    before = deepcopy(root.state)
    oversized = bytearray(61)
    oversized[:3] = b"\x7e\x7e\x3b"
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "binCmd", "hex01": base64.b64encode(oversized).decode("ascii")})
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "binCmd", "hex01": base64.b64encode(bytes(frame)).decode("ascii"),
                        "ReportClientID": "x" * 27})
    assert root.state == before


def test_v105_has_no_later_bin_cmd_operation():
    root = device("v105")
    outer = packet({"t": "binCmd", "hex01": base64.b64encode(bytes(44)).decode("ascii")})
    assert root.profile.handler.handle(root, outer) == []


def test_plain_wlan_ack_and_raw_hbok_tm_echoes_are_unpacked_and_unterminated():
    root = device("v210")
    wlan_raw = b'{ "psw" : "secret", "t" : "wlan", "ssid" : "network", "host" : "dis.gree.com" }'
    wlan = decode_outer(wlan_raw, plaintext_types=root.profile.handler.plaintext_types)
    reply, = root.profile.handler.handle_plaintext_from(
        root, wlan, wlan_raw, ("192.0.2.10", 7351))
    assert json.loads(encoded(reply)) == {"t": "ret", "r": 200, "mac": MAC}
    local = root.state["_wb65vr"]
    assert local["network"] == {"host": "dis.gree.com", "ssid": "network", "psw": "secret"}
    assert local["network_host_matches_source_default"] is True
    for raw in (b'{ "extra" : 1, "t" : "hbok", "uid" : 42 }',
                b'{ "time" : "2026-06-19 10:20:30", "t" : "tm", "tcid" : "020000000001" }'):
        outer = decode_outer(raw, plaintext_types=root.profile.handler.plaintext_types)
        reply, = root.profile.handler.handle_plaintext_from(
            root, outer, raw, ("192.0.2.10", 7351))
        assert encoded(reply) == raw
    assert root.state["_wb65vr"]["heartbeat_seen"] is True
    assert root.state["_wb65vr"]["clock"] == (2026, 6, 19, 10, 20, 30)
    overlong_time = json.dumps({"t": "tm", "time": "x" * 33}).encode()
    parsed = decode_outer(overlong_time, plaintext_types=root.profile.handler.plaintext_types)
    before = deepcopy(root.state)
    assert root.profile.handler.handle_plaintext_from(
        root, parsed, overlong_time, ("192.0.2.10", 7351)) == []
    assert root.state == before
    overlong_wlan = {"t": "wlan", "host": "h" * 20, "ssid": "s" * 33, "psw": "p" * 65}
    raw = json.dumps(overlong_wlan, separators=(",", ":")).encode()
    parsed = decode_outer(raw, plaintext_types=root.profile.handler.plaintext_types)
    reply, = root.profile.handler.handle_plaintext_from(
        root, parsed, raw, ("192.0.2.10", 7351))
    assert json.loads(encoded(reply)) == {"t": "ret", "r": 200, "mac": MAC}
    assert root.state["_wb65vr"]["network"] == {"host": "", "ssid": "", "psw": ""}


def test_source_base64_zero_sextets_and_plaintext_space_lexemes():
    root = device("v210")
    request = packet(literal=b'{"t":"status", "cols":["Pow "]}')
    assert "A" in request["tag"]
    extended_tag = dict(request, tag=request["tag"] + "A")
    parsed = decode_outer(json.dumps(extended_tag, separators=(",", ":")).encode())
    reply, = root.profile.handler.handle(root, parsed)
    assert response(reply)["cols"] == []
    for replacement in ("?", "\n", "\r"):
        outer = dict(request)
        outer["tag"] = request["tag"].replace("A", replacement, 1)
        parsed = decode_outer(json.dumps(outer, separators=(",", ":")).encode())
        reply, = root.profile.handler.handle(root, parsed)
        assert response(reply)["cols"] == []


def test_command_integer_precision_and_int32_clamps():
    root = device("v210")
    exact = exchange(root, literal=b'{"t":"cmd","opt":["Pow"],"p":[16777217]}')
    assert exact["p"] == [16777217]
    high = exchange(root, literal=b'{"t":"cmd","opt":["Pow"],"p":[2147483648]}')
    assert high["p"] == [2147483647]
    low = exchange(root, literal=b'{"t":"cmd","opt":["Pow"],"p":[-2147483649]}')
    assert low["p"] == [-2147483648]


@pytest.mark.parametrize("version", VERSIONS)
def test_native_command_parse_literals_and_exponent_cursor(version):
    source = evidence(version)["command_parse_native"]
    assert source["parser_return_r0"] == 0
    vectors = source["vectors"]
    assert [vector["name"] for vector in vectors] == [
        "exponent", "large-exponent", "positive-fraction",
        "negative-fraction", "shared-exponent-cursor"]
    for vector in vectors:
        root = device(version)
        ack = exchange(root, literal=vector["request"].encode("ascii"))
        assert ack["t"] == "res"
        for name, value in vector["cache"].items():
            assert exchange(root, {"t": "status", "cols": [name]})["dat"] == [value]
