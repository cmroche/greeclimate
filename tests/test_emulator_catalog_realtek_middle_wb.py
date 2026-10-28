"""Original-source WB namespace/ABI contracts and explicitly safe virtual state.

Tests are authored against separately pinned source fixtures; worker agents do
not execute them. Source proof does not assert physical UART/BLE/RTC/flash.
"""
import asyncio
import base64
from copy import deepcopy
import json
from pathlib import Path
import socket

import pytest

from gree_emulator.__main__ import load_config
from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.catalog_realtek_middle_wb import (
    ECB, GCM, PROFILES, make_middle_wb_profile,
)
from gree_emulator.server import start_server
from gree_emulator.wire import InvalidPacket, decode_pack, encode_reply
from tests.test_emulator_catalog_early_scalar import packet_raw_json as ecb_packet
from tests.test_emulator_wb_rt13 import packet as gcm_packet


FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-realtek-middle-wb_research.json").read_text())
SOURCES = FIXTURE["sources"]
GETTERS = [(source, name, values) for source in SOURCES for name, values in source["initial_getters"]]
KEY = b"0123456789abcdef"


def controller(source, mac="020000000001", mid="12345"):
    index = source["assessment_index"] if isinstance(source, dict) else source
    profile = make_middle_wb_profile(index, mid)
    return EmulatedDevice("root", mac, "", mid, KEY, profile, dict(profile.initial_state),
                          room_c=None, ambient_c=None, last_step=1000)


def packet(root, inner=None, *, raw=None, index=0):
    handler = root.profile.handler
    key = root.key if index == 0 else handler.generic_key
    if raw is None:
        raw = json.dumps(inner, separators=(",", ":"), ensure_ascii=False)
    if handler.codec == GCM:
        result = gcm_packet(root, {}, index=index, key=key, plaintext=raw.encode())
    else:
        result = ecb_packet(raw, index=index, target=root.mac, key=key)
    result["cid"] = "client"
    return result


def replies(root, inner=None, *, raw=None, index=0):
    return root.profile.handler.handle(root, packet(root, inner, raw=raw, index=index))


def exchange(root, inner=None, *, raw=None, index=0):
    reply, = replies(root, inner, raw=raw, index=index)
    serialized = encode_reply(reply)
    assert not serialized.endswith(b"\n")
    outer = json.loads(serialized)
    assert outer["cid"] == root.mac and outer["tcid"] == "client"
    assert outer["i"] == index and outer["uid"] == 42
    assert ("tag" in outer) == (reply.codec == GCM)
    return decode_pack(outer, reply.key, reply.codec)


def status(root, names):
    return exchange(root, {"t": "status", "cols": names})


@pytest.mark.parametrize("source,name,expected", GETTERS,
                         ids=[f"{source['assessment_index']}-{name}" for source, name, _ in GETTERS])
def test_every_finite_source_getter_has_explicit_typed_synthetic_readout(source, name, expected):
    root = controller(source)
    assert status(root, [name]) == {"t": "dat", "uid": 42, "mac": root.mac, "cid": root.mac,
                                   "dat": expected, "cols": [name], "r": 200}
    assert root.profile.handler.thermal_target(root) is None
    assert root.profile.source_sha256 == source["source_sha256"]


@pytest.mark.parametrize("source", SOURCES, ids=lambda s: str(s["assessment_index"]))
def test_outer_identity_is_reply_metadata_not_an_unimplemented_mac_filter(source):
    root = controller(source)
    outer = packet(root, {"t": "status", "cols": ["Pow"]})
    outer["tcid"] = "different-target"
    reply, = root.profile.handler.handle(root, outer)
    encoded = json.loads(encode_reply(reply))
    assert root.profile.handler.accept_any_target
    assert encoded["cid"] == "different-target" and encoded["tcid"] == "client"
    assert decode_pack(encoded, reply.key, reply.codec)["dat"] == [0]


@pytest.mark.parametrize("source", SOURCES, ids=lambda s: str(s["assessment_index"]))
@pytest.mark.parametrize("i_token,uid_token,channel,uid", [
    ("1e3", "3.9", 1, 3), ("1.9", "true", 1, 0),
    ("-0.9", "-3.9", 0, -3), ("0", '"wrong"', 0, 0), ("0", "null", 0, 0),
])
def test_source_outer_num_abi_precedes_generic_integer_header_validation(
        source, i_token, uid_token, channel, uid):
    root = controller(source)
    outer = packet(root, {"t": "status", "cols": ["Pow"]}, index=channel)
    raw = json.dumps(outer, separators=(",", ":"))
    raw = raw.replace(f'"i":{channel}', f'"i":{i_token}', 1)
    raw = raw.replace('"uid":42', f'"uid":{uid_token}', 1).encode()
    decoded = root.profile.handler.decode_outer(raw)
    assert decoded["i"] == channel and decoded["uid"] == uid
    reply, = root.profile.handler.handle(root, decoded)
    result = json.loads(encode_reply(reply))
    assert result["uid"] == uid
    assert decode_pack(result, reply.key, reply.codec)["uid"] == uid


@pytest.mark.parametrize("source", SOURCES, ids=lambda s: str(s["assessment_index"]))
@pytest.mark.parametrize("cid,tcid,expected_cid,expected_tcid", [
    (True, None, "true", "null"), (13, ["x"], "", ""),
    ("x" * 64, "x" * 32, "", ""), ("a\0suffix", False, "a", "false"),
])
def test_source_optional_outer_str_abi_is_not_a_strict_identity_gate(
        source, cid, tcid, expected_cid, expected_tcid):
    root = controller(source)
    outer = packet(root, {"t": "status", "cols": ["Pow"]})
    outer.update(cid=cid, tcid=tcid)
    decoded = root.profile.handler.decode_outer(json.dumps(outer).encode())
    reply, = root.profile.handler.handle(root, decoded)
    assert reply.outer["cid"] == expected_tcid
    assert reply.outer["tcid"] == expected_cid


@pytest.mark.parametrize("source", SOURCES, ids=lambda s: str(s["assessment_index"]))
def test_discovery_actual_mid_and_initialized_hid_are_not_filename_or_zeroed_fixture(source):
    root = controller(source)
    reply, = root.profile.handler.advertise(root, {"t": "scan"})
    wire = json.loads(encode_reply(reply))
    assert wire["i"] == 1 and wire["uid"] == 0 and wire["cid"] == wire["tcid"] == ""
    assert "tag" not in wire and reply.codec == ECB
    inner = decode_pack(wire, reply.key, ECB)
    assert inner["mid"] == "12345" and inner["mac"] == root.mac
    assert inner["ver"] == source["sdk_ver"]
    assert ("hid" in inner) == source["dev_hid_present"]
    if source["dev_hid_present"]:
        assert inner["hid"] == source["constructed_hid"]
    assert status(root, ["hid", "ver", "mid"])["dat"] == [source["constructed_hid"], source["sdk_ver"], ""]
    assert root.profile.hid == source["constructed_hid"]


@pytest.mark.parametrize("source_index", [34, 38])
@pytest.mark.parametrize("i_token,uid_token,channel,uid", [
    ("0.9", "3.9", 0, 3), ("0", "true", 0, 0),
    ("1e3", "-3.9", 1, -3), ("0", '"wrong"', 0, 0),
])
async def test_source_outer_decoder_real_udp_does_not_relax_standard_family(
        source_index, i_token, uid_token, channel, uid):
    native = controller(source_index)
    standard = load_config({"devices": [
        {"id": "ordinary", "profile": "sim-w04h-v3.55", "mid": "10001"},
    ]})[2][0]
    standard.key = KEY
    unchanged = deepcopy(standard.state)
    outer = packet(native, {"t": "cmd", "opt": ["Pow"], "p": [1]}, index=channel)
    # Deliberately target the STANDARD root with a shared test key. The native
    # source has no TCID equality gate; the strict standard decoder must reject
    # this header before its command can mutate state.
    outer["tcid"] = standard.mac
    raw = json.dumps(outer, separators=(",", ":"))
    raw = raw.replace(f'"i":{channel}', f'"i":{i_token}', 1)
    raw = raw.replace('"uid":42', f'"uid":{uid_token}', 1).encode()
    transport, server = await start_server([standard, native], "127.0.0.1", 0)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.settimeout(0.15)
            endpoint = transport.get_extra_info("sockname")
            peer.sendto(raw, endpoint)
            received, _ = await asyncio.to_thread(peer.recvfrom, 65535)
            reply = json.loads(received)
            key = native.key if channel == 0 else native.profile.handler.generic_key
            result = decode_pack(reply, key, native.profile.handler.codec)
            assert reply["i"] == channel and reply["uid"] == uid
            assert result["mac"] == native.mac and result["p"] == [1]
            assert standard.state == unchanged
            with pytest.raises(socket.timeout):
                await asyncio.to_thread(peer.recvfrom, 65535)
            peer.sendto(json.dumps(packet(native, {"t": "status", "cols": ["Pow"]})).encode(),
                        endpoint)
            received, _ = await asyncio.to_thread(peer.recvfrom, 65535)
            assert decode_pack(json.loads(received), native.key,
                               native.profile.handler.codec)["dat"] == [1]
            assert standard.state == unchanged
    finally:
        server.close()
        await server.wait_closed()




@pytest.mark.parametrize("source_index", [34, 38])
async def test_source_scan_ignores_unused_target_and_scalar_headers_over_real_udp(source_index):
    native = controller(source_index)
    standard = load_config({"devices": [
        {"id": "ordinary", "profile": "sim-w04h-v3.55", "mid": "10001"},
    ]})[2][0]
    unchanged = deepcopy(standard.state)
    transport, server = await start_server([standard, native], "127.0.0.1", 0)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.settimeout(0.15)
            peer.sendto(b'{"t":"scan","tcid":"unrelated","cid":false,"i":[],"uid":"ignored"}',
                        transport.get_extra_info("sockname"))
            received, _ = await asyncio.to_thread(peer.recvfrom, 65535)
            outer = json.loads(received)
            result = decode_pack(outer, b"a3K8Bx%2r8Y7#xDh", ECB)
            assert result["t"] == "dev" and result["mid"] == native.mid
            assert result["mac"] == native.mac and outer["i"] == 1
            assert standard.state == unchanged
            with pytest.raises(socket.timeout):
                await asyncio.to_thread(peer.recvfrom, 65535)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.parametrize("source", SOURCES, ids=lambda s: str(s["assessment_index"]))
@pytest.mark.parametrize("fields,expected", [
    ({"sub": "request-sub", "mac": "other"}, "request-sub"),
    ({"sub": True, "mac": "other"}, "true"),
    ({"sub": None, "mac": "other"}, "null"),
    ({"sub": 13, "mac": "fallback"}, "fallback"),
    ({"sub": "x" * 32, "mac": "fallback"}, "fallback"),
    ({"sub": "", "mac": "other"}, ""),
    ({"mac": None}, "null"),
    ({"sub": [], "mac": {}}, None),
])
def test_status_inner_alias_str_abi_is_separate_from_outer_reply_identity(source, fields, expected):
    root = controller(source)
    result = exchange(root, {"t": "status", "cols": ["Pow"], **fields})
    assert result["mac"] == (root.mac if expected is None else expected)
    assert result["cid"] == root.mac and result["dat"] == [0]


@pytest.mark.parametrize("source", SOURCES, ids=lambda s: str(s["assessment_index"]))
@pytest.mark.parametrize("supplied,expected", [
    ("not-the-module", "not-the-module"), ("", ""), (True, "true"),
    (None, "null"), (13, None), ("x" * 32, None),
])
def test_bind_echoes_source_str_result_without_invented_mac_equality(source, supplied, expected):
    root = controller(source)
    result = exchange(root, {"t": "bind", "mac": supplied})
    assert result == {"t": "bindok", "r": 200,
                      "mac": root.mac if expected is None else expected,
                      "key": KEY.decode("ascii")}


def test_factory_requires_real_producer_domain_but_never_guesses_physical_mid():
    assert len(PROFILES) == 5
    assert {profile.mids for profile in PROFILES} == {("10001",)}
    assert len({profile.id for profile in PROFILES}) == 5
    assert {profile.source_sha256 for profile in PROFILES} == {source["source_sha256"] for source in SOURCES}
    for profile in PROFILES:
        root = controller(profile.handler.source_index, mid="10001")
        reply, = root.profile.handler.advertise(root, {"t": "scan"})
        assert decode_pack(json.loads(encode_reply(reply)), reply.key, ECB)["mid"] == "10001"
    for mid in ("", "0", "00012345", "ABCDEF", "100000000", "not-a-mid"):
        with pytest.raises(ValueError):
            make_middle_wb_profile(38, mid)
    for index in (24, 35, 37):
        with pytest.raises(ValueError):
            make_middle_wb_profile(index, "12345")
    assert controller(38, mid="abcdef").profile.mids == ("abcdef",)


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("selector", (0, 1))
def test_exact_paired_and_generic_crypto_selector_routes_and_bind_ack(source, selector):
    root = controller(source)
    assert exchange(root, {"t": "bind", "mac": "provided-prefix"}, index=selector) == {
        "t": "bindok", "r": 200, "mac": "provided-prefix", "key": KEY.decode(),
    }
    assert exchange(root, {"t": "bind"}, index=selector)["mac"] == root.mac
    packet0 = packet(root, {"t": "status", "cols": ["Pow"]}, index=selector)
    packet0["i"] = 2
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        root.profile.handler.handle(root, packet0)
    assert root.state == before


@pytest.mark.parametrize("source", SOURCES)
def test_raw32_ack_low16_cache_duplicates_and_first_nod_alias_are_separate(source):
    root, other = controller(source), controller(source, "020000000002")
    ack = exchange(root, {"t": "cmd", "opt": ["Pow", "Pow", "NoD"], "p": [-1, 65536, 65537]})
    assert ack == {"t": "res", "mac": root.mac, "p": [-1, 65536, 65537],
                   "opt": ["Pow", "Pow", "NoD"], "r": 200}
    assert status(root, ["Pow", "NoD", "Pow"])["dat"] == [0, 1, 0]
    assert status(other, ["Pow", "NoD"])["dat"] == [0, 0]
    assert source["first_match_slots"]["NoD"] == (176 if source["assessment_index"] == 34 else 57)
    ack = exchange(root, {"t": "cmd", "opt": ["Pow"], "p": [4294967295]})
    assert ack["p"] == [2147483647]
    assert status(root, ["Pow"])["dat"] == [65535]


@pytest.mark.parametrize("source", SOURCES)
def test_decimal_prefix_parser_retains_exponent_cursor_not_json_float_normalization(source):
    root = controller(source)
    ack = exchange(root, raw='{"t":"cmd","opt":["Pow"],"p":[1e3]}')
    assert ack["p"] == [1]
    ack = exchange(root, raw='{"t":"cmd","opt":["Pow","SetTem"],"p":[1e3,2]}')
    assert ack["p"] == [1, 3]
    assert status(root, ["Pow", "SetTem"])["dat"] == [1, 3]
    ack = exchange(root, raw='{"t":"cmd","opt":["Pow","SetTem"],"p":[1e-3,2]}')
    assert ack["p"] == [1, -3]
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        exchange(root, raw='{"t":"cmd","opt":["Pow","SetTem"],"p":[1e+3,2]}')
    assert root.state == before  # Intentional safe rollback of native partial writes.
    for raw in ('true', 'null', '"7"'):
        with pytest.raises(InvalidPacket):
            exchange(root, raw='{"t":"cmd","opt":["Pow"],"p":[' + raw + ']}')
    assert root.state == before


@pytest.mark.parametrize("source", SOURCES)
def test_source_specific_binary64_infinity_cast_from_long_decimal_integer(source):
    root = controller(source)
    ack = exchange(root, raw='{"t":"cmd","opt":["Pow"],"p":[' + '9' * 400 + ']}')
    expected = 2147483647 if source["assessment_index"] == 38 else 0
    assert ack["p"] == [expected]
    assert status(root, ["Pow"])["dat"] == [expected & 65535]


@pytest.mark.parametrize("source", SOURCES)
def test_source_grouping_primary_quoted_values_numeric_cursor_and_ack_order(source):
    root = controller(source)
    ack = exchange(root, {"t": "cmd", "opt": ["Pow", "time"], "p": [7, "2026-02-03 04:05:06"]})
    assert ack["opt"] == ["time", "Pow"]
    assert ack["p"] == ["2026-02-03 04:05:06", 7]
    assert status(root, ["Pow", "time"])["dat"] == [7, "2026-02-03 04:05:06"]
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "cmd", "opt": ["Pow", "hid"], "p": [8, "not-a-hid"]})
    assert root.state == before
    assert status(root, ["Pow", "hid"])["dat"] == [7, source["constructed_hid"]]


@pytest.mark.parametrize("source", SOURCES)
def test_primary_store_survives_later_readonly_failure_before_numeric_phase(source):
    root = controller(source)
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "cmd", "opt": ["lat", "lock", "Pow"],
                        "p": ["1234567890", "0", 7]})
    # Original mode0 calls commit in primary order; the readonly negative stops
    # parsing before numeric stores, but does not undo the earlier latitude.
    assert status(root, ["lat", "Pow"])["dat"] == ["1234567890", 0]


@pytest.mark.parametrize("source", SOURCES)
def test_cols_wins_over_opt_and_status_opt_can_write_but_cmd_cols_cannot(source):
    root = controller(source)
    assert exchange(root, {"t": "status", "opt": ["Pow"], "p": [7]})["dat"] == [7]
    ack = exchange(root, {"t": "cmd", "cols": ["Pow"], "opt": ["Pow"], "p": [9]})
    assert ack["p"] == [0]  # Cleared numeric scratch, not a fresh cache readback.
    assert status(root, ["Pow"])["dat"] == [7]
    assert exchange(root, {"t": "status", "cols": ["Pow"], "sub": "any-source-substring"})["mac"] == "any-source-substring"


@pytest.mark.parametrize("source", SOURCES)
def test_unknown_getter_omission_known_no_scalar_and_unknown_raw_ack_are_distinct(source):
    root = controller(source)
    result = status(root, ["Pow", "BtHid", "__unknown__", "Pow"])
    assert result["cols"] == ["Pow", "BtHid", "Pow"] and result["dat"] == [0, 0]
    ack = exchange(root, {"t": "cmd", "opt": ["__unknown__"], "p": [17]})
    assert ack["opt"] == ["__unknown__"] and ack["p"] == [17]
    assert status(root, ["__unknown__"])["dat"] == []
    ack = exchange(root, {"t": "cmd", "opt": ["name", "ModelType", "AppTimer"], "p": ["new", "new-model", "7"]})
    assert ack["p"] == ["", "", 0]  # Original success-noop cases, not fake mutations.


@pytest.mark.parametrize("source", SOURCES)
def test_ble_mesh_pending_mac_unbind_alias_and_signed_meshid_are_source_qualified(source):
    root = controller(source)
    exchange(root, {"t": "cmd", "opt": ["Mesh"], "p": ["123456789abc"]})
    assert status(root, ["BleON", "Mesh"])["dat"] == ["123456789abc", 0]
    assert root.state["_middle_wb"]["sdk_events"] == [[0x14, 3]]
    exchange(root, {"t": "cmd", "opt": ["Unbind"], "p": ["001122334455"]})
    expected = "123456789abc" if source["assessment_index"] == 38 else "003456789abc"
    assert status(root, ["Unbind", "BleON"])["dat"] == ["001122334455", expected]
    exchange(root, {"t": "cmd", "opt": ["Meshid"], "p": ["ff80"]})
    assert status(root, ["Meshid"])["dat"] == ["ff80" if source["assessment_index"] == 38 else "fe80"]


@pytest.mark.parametrize("source", SOURCES)
def test_write_only_packet_actions_are_not_boolean_controls_or_getter_values(source):
    root = controller(source)
    ack = exchange(root, {"t": "cmd", "opt": ["ReportClientID"], "p": ["literal-client"]})
    assert ack["opt"] == ack["p"] == []
    assert root.state["_middle_wb"]["report_client_packet"].startswith("7e7e126a" + b"literal-client".hex())
    ack = exchange(root, {"t": "cmd", "opt": ["Onoff"], "p": ["0x0000000"]})
    assert ack["opt"] == ack["p"] == []
    assert root.state["_middle_wb"]["mesh_queue"] == ["000200000600010530020000"]
    before = deepcopy(root.state)
    for value in (True, 1, "1"):
        with pytest.raises(InvalidPacket):
            exchange(root, {"t": "cmd", "opt": ["Onoff"], "p": [value]})
    assert root.state == before


@pytest.mark.parametrize("source", SOURCES)
def test_host_pending_write_and_lat_lon_byte_limits_do_not_fabricate_readback(source):
    root = controller(source)
    exchange(root, {"t": "cmd", "opt": ["host", "lat", "lon"], "p": ["host.example", "1234567890", "12345678901"]})
    assert status(root, ["host", "lat", "lon"])["dat"] == ["", "1234567890", ""]
    assert root.state["_middle_wb"]["host_requested"] == "host.example"
    exchange(root, {"t": "cmd", "opt": ["lat"], "p": [""]})
    assert status(root, ["lat"])["dat"] == ["1234567890"]


def timer(kind="setT", identifier=257, **changes):
    return {"t": kind, "id": identifier, "name": "source", "enable": 1, "tz": -1,
            "hr": 258, "min": 259, "sec": 40, "week": [2, 0, 0, 0, 0, 0, 0],
            "cmd": [{"mac": ["ignored"], "opt": ["Pow"], "p": [259]},
                    {"opt": ["Pow"], "p": [0]}], **changes}


@pytest.mark.parametrize("index", (36, 38, 39, 40))
def test_timer_local_record_schema_query_ids_source_counter_underflow_and_duplicate_rule(index):
    root = controller(index)
    assert exchange(root, timer()) == {"t": "resT", "r": 200}
    result = exchange(root, {"t": "queryT", "index": 0, "count": 10})
    assert result == {"t": "listT", "total": 1, "index": 0, "list": [{
        "id": 1, "name": "source", "enable": 1, "week": [0, 1, 0, 0, 0, 0, 0],
        "hr": 2, "min": 3, "sec": 0,
        "cmd": [{"mac": [root.mac], "opt": ["Pow"], "p": [3]}],
    }]}
    changed = timer(name="changed")
    if index == 36:
        assert replies(root, changed) == []
    else:
        assert exchange(root, changed) == {"t": "resT", "r": 200}
    assert exchange(root, {"t": "deleteT", "id": 42}) == {"t": "resT", "r": 200}
    assert exchange(root, {"t": "queryT", "index": 0, "count": 10})["total"] == 0
    exchange(root, {"t": "deleteT", "id": 1})
    assert exchange(root, {"t": "queryT", "index": 0, "count": 10}) == {
        "t": "listT", "total": 255, "index": 0, "list": [],
    }
    assert replies(root, timer(identifier=2)) == []
    assert exchange(root, timer("updateT", 42)) == {"t": "resT", "r": 200}
    assert root.state["_middle_wb"]["timers"] == {}


@pytest.mark.parametrize("source", SOURCES)
def test_local_dump_is_ack_only_and_ota_virtual_buffer_preserves_source_suffix(source):
    root = controller(source)
    status(root, ["Pow"])
    before = deepcopy(root.state)
    assert exchange(root, {"t": "dump"}) == {"t": "ret", "r": 200}
    assert root.state == before
    assert exchange(root, {"t": "upgrade", "url": "abcdef"}) == {"t": "ret", "r": 200}
    exchange(root, {"t": "upgrade", "url": "xy"})
    assert bytes.fromhex(root.state["_middle_wb"]["ota_buffer"]).split(b"\0", 1)[0] == b"xycdef"
    assert root.state["_middle_wb"]["ota_task_requested"] is True
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "upgrade", "url": "x" * 120})
    assert root.state == before
    if source["assessment_index"] == 34:
        with pytest.raises(InvalidPacket):
            exchange(root, timer())


def test_df13_binary_envelope_is_opaque_preserved_bytes_with_exact_local_flags():
    root = controller(38)
    payload = bytes.fromhex("7e7e0801020304050607")
    assert exchange(root, {"t": "binCmd", "hex01": base64.b64encode(payload).decode()}) == {"t": "res", "r": 200}
    buffer = bytes.fromhex(root.state["_middle_wb"]["binary_frame"])
    assert buffer[:7] == payload[:7] and buffer[7] == 0xaf
    assert buffer[0x2b] == 2 and len(buffer) == 60
    exchange(root, {"t": "binCmd", "hex01": base64.b64encode(payload).decode(), "ReportFreq": 255})
    assert root.state["_middle_wb"]["binary_report_frequency"] == 60
    assert bytes.fromhex(root.state["_middle_wb"]["binary_frame"])[7] == 0
    before = deepcopy(root.state)
    for value in ("!not-base64!", base64.b64encode(b"\x7e\x7e\xff").decode()):
        with pytest.raises(InvalidPacket):
            exchange(root, {"t": "binCmd", "hex01": value})
    assert root.state == before
    for index in (34, 36, 39, 40):
        with pytest.raises(InvalidPacket):
            exchange(controller(index), {"t": "binCmd", "hex01": base64.b64encode(payload).decode()})
