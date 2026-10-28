"""Literal original-instruction vectors; full ingress uses an explicit safe policy."""
import base64
from copy import deepcopy
import json
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.catalog_legacy_direct import PROFILES
from gree_emulator.wire import InvalidPacket, encode_reply

FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/legacy-direct_research.json").read_text())
DEVICE_KEY = b"a3K8Bx%2r8Y7GREE"
GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
MAC = "020000000001"


def device(mac=MAC):
    profile, = PROFILES
    unit = EmulatedDevice("legacy", mac, "legacy", "0", DEVICE_KEY, profile,
                          deepcopy(dict(profile.initial_state)), room_c=None,
                          ambient_c=None, last_step=0)
    profile.handler.encode_room(unit)
    return unit


def packet(inner, index=0, *, uid=42, target=MAC, key=None):
    key = key if key is not None else (GENERIC_KEY if index & 255 else DEVICE_KEY)
    payload = json.dumps(inner, separators=(",", ":")).encode()
    return {"t": "pack", "i": index, "uid": uid, "cid": "app", "tcid": target,
            "pack": base64.b64encode(AES.new(key, AES.MODE_ECB).encrypt(pad(payload, 16))).decode()}


def exchange(unit, inner, index=0, **kwargs):
    reply, = unit.profile.handler.handle(unit, packet(inner, index, **kwargs))
    raw = encode_reply(reply)
    outer = json.loads(raw)
    key = GENERIC_KEY if outer["i"] & 255 else DEVICE_KEY
    plaintext = unpad(AES.new(key, AES.MODE_ECB).decrypt(base64.b64decode(outer["pack"])), 16)
    assert not raw.endswith(b"\n") and not plaintext.endswith(b"\n")
    assert reply.destination_port is None  # ordinary UDP echoes the sender port
    assert outer["uid"] == 0 and outer["cid"] == unit.mac and outer["tcid"] == "app"
    return outer, json.loads(plaintext)


def test_exact_source_profile_identity_and_roomless_cache():
    unit = device()
    assert len(PROFILES) == 1 and unit.profile.id == "sim-w06m-v1.03"
    assert unit.profile.mids == ("0",)
    assert unit.profile.hid == FIXTURE["hid"]
    assert unit.profile.source_sha256 == FIXTURE["source_sha256"]
    assert unit.profile.max_request_bytes == 1024
    assert unit.profile.handler.thermal_target(unit) is None
    assert unit.profile.handler.encode_room(unit) is None
    assert unit.room_c is None
    assert FIXTURE["origin"]["native_cases"] == 644
    assert FIXTURE["origin"]["failures"] == 0


NUMERIC = [row for row in FIXTURE["native_vectors"]
           if isinstance(row["request"], str) and row["operation"] == "status"
           and type(row["response"].get("dat")) in (int, float)]



def test_every_literal_table_slot_and_supplied_native_metadata_getter():
    from gree_emulator.profiles.catalog_legacy_direct import NAMES, RAW_SLOTS

    assert tuple(FIXTURE["ordered_table"]) == NAMES
    first = {}
    for index, name in enumerate(FIXTURE["ordered_table"]):
        first.setdefault(name, index)
    assert RAW_SLOTS == {name: index for name, index in first.items() if index < 445}
    assert RAW_SLOTS["HeatCoolType"] == 17
    unit = device()
    unit.profile.handler.advertise(unit, {"t": "scan"})
    metadata = unit.state["_legacy_direct"]["metadata"]
    for row in FIXTURE["native_vectors"]:
        if row["operation"] == "status" and isinstance(row["request"], str):
            value = row["response"].get("dat")
            if isinstance(value, str) and row["request"] != "mac":
                metadata[row["request"]] = value
    for row in FIXTURE["native_vectors"]:
        if row["operation"] != "status":
            continue
        _, actual = exchange(unit, {"t": "status", "cols": row["request"]})
        assert actual == row["response"]


def test_source_initialized_metadata_and_default_key_not_config_seed():
    unit = device()
    unit.key = b"0123456789abcdef"
    unit.profile.handler.encode_room(unit)
    assert unit.key == DEVICE_KEY
    expected = {"apssid": "", "appsw": "", "host": "", "name": "legacy",
                "time": "2016-12-22 00:00:00", "vender": "1", "bc": "",
                "mid": "0", "model": "", "series": "", "brand": "",
                "catalog": "", "hid": "362001062071+U-W06MV1.03.bin",
                "mac": MAC, "ver": "V1.0"}
    for name, value in expected.items():
        _, status = exchange(unit, {"t": "status", "cols": name})
        assert status == {"t": "dat", "mac": MAC, "r": 200, "cols": name, "dat": value}


def test_scalar_metadata_readback_array_string_setter_and_atomic_invalid():
    unit = device()
    _, scalar = exchange(unit, {"t": "cmd", "mac": MAC, "opt": "name", "p": "ignored"})
    assert scalar == {"t": "res", "mac": MAC, "r": 200,
                      "opt": "name", "p": "legacy", "val": "legacy"}
    _, changed = exchange(unit, {"t": "cmd", "mac": MAC,
                                 "opt": ["name"], "p": ["changed"]})
    assert changed == {"t": "res", "mac": MAC, "r": 200,
                       "opt": ["name"], "p": ["changed"], "val": ["changed"]}
    _, fresh = exchange(unit, {"t": "status", "cols": ["name", "country", "Pow"]})
    assert fresh["cols"] == ["name", "country", "Pow"] and fresh["dat"] == ["changed", 0]
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "cmd", "mac": MAC, "opt": ["name", "Pow"],
                        "p": ["not-committed", None]})
    assert unit.state == before


@pytest.mark.parametrize("row", NUMERIC, ids=lambda row: row["request"])
def test_every_native_numeric_first_match_scalar_and_array(row):
    unit = device()
    name = row["request"]
    _, scalar = exchange(unit, {"t": "status", "cols": name})
    assert scalar == row["response"]
    if name in ("ElcDatHor", "ElcDatDte", "ElcDatMth", "WatLine"):
        return  # source binary array frames have separate literal coverage below
    _, array = exchange(unit, {"t": "status", "cols": [name]})
    assert array == {"t": "dat", "mac": MAC, "r": 200, "cols": [name], "dat": [0]}
    _, ack = exchange(unit, {"t": "cmd", "mac": MAC, "opt": [name], "p": [-1]})
    assert ack == {"t": "res", "mac": MAC, "r": 200, "opt": [name], "p": [65535], "val": [65535]}
    _, fresh = exchange(unit, {"t": "status", "cols": [name]})
    assert fresh["dat"] == [65535]


def test_literal_first_hole_unknown_duplicates_and_exact_thirty_cliff():
    unit = device()
    for row in FIXTURE["native_vectors"]:
        if row["operation"] != "status" or not isinstance(row["request"], list):
            continue
        if "hid" in row["request"] and "country" in row["request"]:
            continue  # supplied native metadata probe state is tested separately
        _, reply = exchange(unit, {"t": "status", "cols": row["request"]})
        assert reply == row["response"]
    _, unknown = exchange(unit, {"t": "status", "cols": ["not-a-property", "Pow", "Pow"]})
    assert unknown["cols"] == ["Pow", "Pow"] and unknown["dat"] == [0, 0]
    _, short = exchange(unit, {"t": "status", "cols": ["Pow"] * 29})
    assert short["dat"] == [0] * 29
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "status", "cols": ["Pow"] * 31})


def test_country_is_recognized_without_value_and_numeric_duplicate_uses_final_cache():
    unit = device()
    _, scalar = exchange(unit, {"t": "status", "cols": "country"})
    assert scalar == {"t": "dat", "mac": MAC, "r": 200, "cols": "country"}
    _, ragged = exchange(unit, {"t": "status", "cols": ["country", "Pow", "Pow"]})
    assert ragged == {"t": "dat", "mac": MAC, "r": 200,
                      "cols": ["country", "Pow", "Pow"], "dat": [0, 0]}
    _, ack = exchange(unit, {"t": "cmd", "mac": MAC, "opt": ["Pow", "Pow"], "p": [-1, 65537]})
    assert ack == {"t": "res", "mac": MAC, "r": 200,
                   "opt": ["Pow", "Pow"], "p": [1, 1], "val": [1, 1]}
    _, fresh = exchange(unit, {"t": "status", "cols": "Pow"})
    assert fresh["dat"] == 1


@pytest.mark.parametrize("bad", [True, None, 1.5, "1", {}, [], 1 << 31, -(1 << 31) - 1])
def test_safe_invalid_batch_has_no_partial_mutation(bad):
    unit = device()
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "cmd", "mac": MAC, "opt": ["Pow", "Mod"], "p": [7, bad]})
    assert unit.state == before and unit.last_step == 0


def test_source_key_width_full_index_gate_and_sticky_index():
    unit = device()
    assert unit.profile.handler.handle(unit, packet({"t": "status", "cols": ["Pow"]}, 256)) == []
    outer = packet({"t": "status", "cols": ["Pow"]}, 256)
    del outer["i"]
    assert unit.profile.handler.handle(unit, outer) == []
    _, status = exchange(unit, {"t": "status", "cols": ["Pow"]}, 0, uid=-123)
    assert status["dat"] == [0]
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "status", "cols": ["Pow"]}, key=GENERIC_KEY)
    with pytest.raises(InvalidPacket):
        unit.profile.handler.handle(unit, {"t": "pack", "i": 2, "pack": {"t": "status", "cols": ["Pow"]}})


def test_status_ignores_targets_command_rejects_wrong_route_and_devices_reset():
    unit = device()
    _, status = exchange(unit, {"t": "status", "mac": "020000000099", "cols": ["Pow"]}, target="wrong")
    assert status["dat"] == [0]
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "cmd", "mac": "020000000099", "opt": ["Pow"], "p": [1]})
    assert unit.state == before
    exchange(unit, {"t": "cmd", "mac": MAC, "opt": ["Pow"], "p": [9]})
    for other in (device("020000000002"), device()):
        _, fresh = exchange(other, {"t": "status", "cols": ["Pow"]})
        assert fresh["dat"] == [0]


def test_nested_timer_mac_integration_and_independent_query():
    unit = device()
    request = {"t": "setT", "id": 3, "name": "first", "enable": 0,
               "hr": 6, "min": 8, "sec": 9, "week": [0, 0, 0, 0, 0, 0, 0],
               "cmd": [{"mac": [MAC], "opt": ["Pow"], "p": [-1]}]}
    _, ack = exchange(unit, request)
    assert ack == {"t": "resT", "r": 200}
    _, query = exchange(unit, {"t": "queryT", "index": 3, "count": 1})
    assert query == {"t": "listT", "total": 1, "index": 3, "list": [
        {"id": 3, "name": "first", "enable": 0, "hr": 6, "min": 8, "sec": 9,
         "week": [0, 0, 0, 0, 0, 0, 0],
         "cmd": [{"mac": [MAC], "opt": ["Pow"], "p": [255]}]}]}
    _, untouched = exchange(unit, {"t": "status", "cols": ["Pow"]})
    assert untouched["dat"] == [0]
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "setT", "id": 4, "mac": MAC})
    assert unit.state == before


@pytest.mark.parametrize("plaintext", [
    b'{"t":"cmd","mac":"020000000001","opt":["Pow"],"p":[1],"p":[2]}',
    b'{"t":"cmd","mac":"020000000001","opt":["Pow"],"p":[NaN]}',
    b'{"t":"status","cols":["Pow"]} trailing',
])
def test_strict_safe_parser_rejects_native_unsafe_inputs_atomically(plaintext):
    unit = device()
    outer = packet({"t": "status", "cols": ["Pow"]})
    outer["pack"] = base64.b64encode(
        AES.new(DEVICE_KEY, AES.MODE_ECB).encrypt(pad(plaintext, 16))).decode()
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        unit.profile.handler.handle(unit, outer)
    assert unit.state == before


def test_invalid_pkcs7_is_not_native_broken_unpadding_compatibility():
    unit = device()
    outer = packet({"t": "status", "cols": ["Pow"]})
    outer["pack"] = base64.b64encode(AES.new(DEVICE_KEY, AES.MODE_ECB).encrypt(
        b'{"t":"status"} ' + b"\x00")).decode()
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        unit.profile.handler.handle(unit, outer)
    assert unit.state == before


def test_literal_source_scan_bind_uid_and_full_reply_index():
    unit = device()
    outer, scan = exchange(unit, {"t": "scan"}, 1, uid=987654)
    assert outer["i"] == 1
    assert scan == {"t": "dev", "cid": MAC, "bc": "gree", "brand": "gree",
                    "catalog": "gree", "mac": MAC, "mid": "0", "model": "gree",
                    "name": "legacy", "series": "gree", "vender": "1",
                    "ver": "V1.0", "lock": 0, "endpoint_id": ""}
    outer, bound = exchange(unit, {"t": "bind", "mac": MAC}, 257, uid=-(1 << 31))
    assert outer["i"] == 257
    assert bound == {"t": "bindok", "mac": MAC, "key": "a3K8Bx%2r8Y7GREE", "r": 200}
    assert unit.key == DEVICE_KEY
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "bind", "mac": "020000000099"}, 1)
    _, fresh = exchange(unit, {"t": "status", "cols": ["Pow"]}, 0)
    assert fresh["dat"] == [0]


@pytest.mark.parametrize("vector", FIXTURE["binary_reports"]["vectors"],
                         ids=lambda row: row["names"][0])
def test_source_static_binary_array_report_bytes_not_json_dat(vector):
    for name in vector["names"]:
        unit = device()
        reply, = unit.profile.handler.handle(
            unit, packet({"t": "status", "cols": [name]}))
        raw = encode_reply(reply)
        assert raw == bytes.fromhex(vector["frame_hex"])
        assert len(raw) == vector["frame_length"]
        assert reply.raw_payload == raw and reply.inner is None
        assert reply.destination_port is None
        assert unpad(AES.new(GENERIC_KEY, AES.MODE_ECB).decrypt(raw[39:]), 16) == bytes.fromhex(
            vector["plaintext_hex"])
        assert not raw.startswith(b"{") and not raw.endswith(b"\n")


@pytest.mark.parametrize("names,vector_index", [
    (["ElcDatHor", "WatLine"], 1),
    (["WatLine", "Pow", "ElcDatMth"], 0),
    (["ElcDatDte", "unknown", "WatLine", "Pow"], 1),
])
def test_last_binary_stage_in_array_selects_exact_raw_frame(names, vector_index):
    unit = device()
    reply, = unit.profile.handler.handle(unit, packet({"t": "status", "cols": names}))
    assert encode_reply(reply) == bytes.fromhex(
        FIXTURE["binary_reports"]["vectors"][vector_index]["frame_hex"])


@pytest.mark.parametrize("row", NUMERIC, ids=lambda row: row["request"])
def test_every_numeric_scalar_command_and_fresh_scalar_status(row):
    unit = device()
    name = row["request"]
    _, ack = exchange(unit, {"t": "cmd", "mac": MAC, "opt": name, "p": -1})
    assert ack == {"t": "res", "mac": MAC, "r": 200,
                   "opt": name, "p": 65535, "val": 65535}
    _, fresh = exchange(unit, {"t": "status", "cols": name})
    assert fresh == {"t": "dat", "mac": MAC, "r": 200, "cols": name, "dat": 65535}


def test_config_state_boundary_rejects_identity_metadata_and_private_overrides():
    handler = device().profile.handler
    handler.validate_state({"Pow": 65535, "SetTem": 0})
    for state in ({"Pow": -1}, {"Pow": 65536}, {"Pow": True}, {"Pow": 1.0},
                  {"mid": "10001"}, {"hid": "other"}, {"name": "other"},
                  {"_legacy_direct": {}}, {"unknown": 0}):
        with pytest.raises(ValueError):
            handler.validate_state(state)


def test_upgrade_is_only_source_local_staging_not_network_completion():
    unit = device()
    _, response = exchange(unit, {"t": "upgrade", "url": "http://example.invalid/fw.bin"})
    assert response == {"t": "ret", "r": 200, "mac": MAC}
    assert unit.state["_legacy_direct"]["upgrade_url"] == "http://example.invalid/fw.bin"
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "upgrade", "url": "x" * 160})
    assert unit.state == before
    assert unit.profile.handler.handle(
        unit, packet({"t": "upgrade", "url": "http://example.invalid/other.bin"}, 256)) == []
    assert unit.state["_legacy_direct"]["upgrade_url"] == "http://example.invalid/fw.bin"


def test_exact_thirty_command_cliff_has_neither_ack_nor_mutation():
    unit = device()
    before = {name: value for name, value in unit.state.items() if not name.startswith("_")}
    last_step = unit.last_step
    assert unit.profile.handler.handle(unit, packet({
        "t": "cmd", "mac": MAC, "opt": ["Pow"] * 30, "p": [1] * 30})) == []
    # Lazy source bookkeeping is not an observable command-cache mutation.
    assert {name: value for name, value in unit.state.items() if not name.startswith("_")} == before
    assert unit.last_step == last_step
    for _ in range(2):
        _, fresh = exchange(unit, {"t": "status", "cols": ["Pow"]})
        assert fresh["dat"] == [0]


def test_actual_cli_ignores_outer_target_only_for_source_qualified_family():
    import socket
    from tests.test_emulator_firmware_cli import cli_server, packet as cli_packet, unpack

    ordinary_mac = "020000000002"
    records = [
        {"id": "legacy", "profile": "sim-w06m-v1.03", "mid": "0", "mac": MAC},
        {"id": "ordinary", "profile": "sim-w04h-v3.55", "mid": "10001",
         "mac": ordinary_mac},
    ]
    with cli_server(records) as (address, identities), socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(0.2)
        assert identities["legacy"]["mac"] == MAC
        assert identities["ordinary"]["mac"] == ordinary_mac
        peer.sendto(cli_packet(
            {"t": "pack", "i": 1, "uid": 17, "cid": "app", "tcid": ordinary_mac},
            {"t": "bind", "mac": ordinary_mac}, GENERIC_KEY), address)
        response, source = peer.recvfrom(8192)
        assert source == address
        _, bound = unpack(response, GENERIC_KEY)
        assert bound["t"] == "bindok" and bound["mac"] == ordinary_mac
        ordinary_key = bound["key"].encode("ascii")

        def send(request):
            peer.sendto(json.dumps(request, separators=(",", ":")).encode(), address)

        def receive(key):
            response, source = peer.recvfrom(8192)
            assert source == address
            return unpack(response, key)

        send(packet({"t": "cmd", "mac": MAC, "opt": "Pow", "p": 7},
                    target=ordinary_mac))
        assert receive(DEVICE_KEY)[1]["p"] == 7
        for target in (MAC, "020000000099", "", None, ordinary_mac):
            request = packet({"t": "status", "cols": "Pow"}, target=target)
            if target is None:
                request.pop("tcid")
            send(request)
            outer, fresh = receive(DEVICE_KEY)
            assert outer["cid"] == MAC
            assert fresh["t"] == "dat" and fresh["dat"] == 7
            with pytest.raises(socket.timeout):
                peer.recvfrom(8192)

        send(packet({"t": "cmd", "mac": ordinary_mac, "opt": "Pow", "p": 9}))
        with pytest.raises(socket.timeout):
            peer.recvfrom(8192)
        send(packet({"t": "status", "cols": "Pow"}))
        assert receive(DEVICE_KEY)[1]["dat"] == 7

        for target in ("020000000099", MAC, "", None):
            request = packet({"t": "cmd", "mac": ordinary_mac,
                              "opt": ["Pow"], "p": [1]},
                             target=target, key=ordinary_key)
            if target is None:
                request.pop("tcid")
            send(request)
            with pytest.raises(socket.timeout):
                peer.recvfrom(8192)
        send(packet({"t": "status", "mac": ordinary_mac, "cols": ["Pow"]},
                    target=ordinary_mac, key=ordinary_key))
        outer, fresh = receive(ordinary_key)
        assert outer["cid"] == ordinary_mac and fresh["dat"] == [0]
