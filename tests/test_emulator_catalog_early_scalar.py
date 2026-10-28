"""Literal native vectors for the active source-qualified WB05MR profile."""
import base64
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

from Crypto.Cipher import AES
import pytest

from gree_emulator.profiles import catalog_early_scalar as scalar
from gree_emulator.wire import InvalidPacket, encode_reply

EVIDENCE = json.loads((Path(__file__).parent / "fixtures" / "emulator" /
                       "catalog-early-scalar_research.json").read_text())
SOURCES = EVIDENCE["sources"]
EVIDENCE_HASHES = {row["id"]: row["sha256"] for row in EVIDENCE["evidence"]}
IDS = ["sim-wb05mr-v1.05-10001"]
SESSION_KEY = b"0123456789abcdef"
GENERIC_KEY = EVIDENCE["wire_contract"]["generic_key_ascii"].encode("ascii")
MAC = "020000000001"


def device(source):
    profile = next(profile for profile in scalar.PROFILES
                   if profile.source_sha256 == source["source_sha256"])
    return SimpleNamespace(profile=profile, mac=MAC, mid=profile.mids[0], name="Scalar",
                           key=SESSION_KEY, last_step=1000.0,
                           state=dict(profile.initial_state))


def _pad(data):
    count = AES.block_size - len(data) % AES.block_size
    return data + bytes((count,)) * count


def _unpad(data):
    assert data and len(data) % AES.block_size == 0
    count = data[-1]
    assert 1 <= count <= AES.block_size and data[-count:] == bytes((count,)) * count
    return data[:-count]


def packet(inner, *, index=0, uid=42, target=MAC, key=None):
    plaintext = json.dumps(inner, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    session_key = key or (GENERIC_KEY if index else SESSION_KEY)
    encrypted = AES.new(session_key, AES.MODE_ECB).encrypt(_pad(plaintext))
    return {"t": "pack", "i": index, "uid": uid, "cid": "peer", "tcid": target,
            "pack": base64.b64encode(encrypted).decode("ascii")}

def packet_raw_json(raw_json, *, index=0, uid=42, target=MAC, key=None):
    plaintext = raw_json.encode("utf-8")
    session_key = key or (GENERIC_KEY if index else SESSION_KEY)
    encrypted = AES.new(session_key, AES.MODE_ECB).encrypt(_pad(plaintext))
    return {"t": "pack", "i": index, "uid": uid, "cid": "peer", "tcid": target,
            "pack": base64.b64encode(encrypted).decode("ascii")}


def unpack(reply, root, *, index=0, uid=42, discovery=False):
    wire = encode_reply(reply)
    assert not wire.endswith(b"\n")
    outer = json.loads(wire)
    assert outer["t"] == "pack"
    assert outer["i"] == (1 if discovery else index)
    assert outer["uid"] == (0 if discovery else uid)
    assert outer["cid"] == ("" if discovery else root.mac)
    assert outer["tcid"] == ("" if discovery else "peer")
    assert "tag" not in outer
    assert reply.codec == "aes-ecb-pkcs7"
    key = GENERIC_KEY if discovery or outer["i"] else root.key
    plaintext = _unpad(AES.new(key, AES.MODE_ECB).decrypt(base64.b64decode(outer["pack"])))
    assert not plaintext.endswith(b"\n")
    return json.loads(plaintext)


def exchange(root, inner, *, index=0, uid=42):
    message = {"mac": root.mac, **inner}
    replies = root.profile.handler.handle(
        root, packet(message, index=index, uid=uid, target=root.mac))
    reply, = replies
    return unpack(reply, root, index=index, uid=uid)


def source_operation(source, operation):
    return next(row for row in source["protocol_operations"] if row["id"] == operation)


def expected_defaults(source):
    return {**source["metadata_defaults"], **source["metadata_safe_fallbacks"]}


def expected_status(source, names):
    fields = {field["name"]: field for field in source["fields"]}
    defaults = expected_defaults(source)
    available = set(source["numeric_names"]) | set(defaults)
    selected, values = [], []
    for name in names:
        if name in source["write_only_names"] or name not in available:
            continue
        selected.append(name)
        values.extend(defaults[name] if name in defaults else fields[name]["native_get"]["dat"])
    return selected, values


@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_exact_active_source_profile_and_all_495_ordered_slots(source):
    index = source["historical_index"]
    assert [row["historical_index"] for row in SOURCES] == [22]
    assert EVIDENCE["source_scope"].startswith("Active public profile: exact source index 22 only.")
    root = device(source)
    handler = root.profile.handler
    assert [profile.id for profile in scalar.PROFILES] == IDS
    assert set(scalar.ORDERED_NAMES) == {22}
    assert set(scalar.METADATA_DEFAULTS) == {22}
    assert root.profile.id == source["profile_id"]
    assert root.profile.source_sha256 == source["source_sha256"]
    assert handler.source_sha256 == source["source_sha256"]
    assert root.profile.hid == source["hid"]
    assert root.profile.mids == ("10001",)
    assert len(source["ordered_names"]) == source["slot_count"] == 495
    assert list(handler.ordered_names) == source["ordered_names"]
    assert list(scalar.ORDERED_NAMES[index]) == source["ordered_names"]
    assert handler.numeric == frozenset(source["numeric_names"])
    assert handler.local_names == frozenset(source["local_names"])
    assert handler.metadata_names == tuple(source["metadata_names"])
    assert handler.special == handler.local_names
    assert handler.write_only == frozenset(source["write_only_names"])
    assert handler.fields == handler.numeric | handler.local_names
    assert len(source["fields"]) == len(source["numeric_names"])
    assert all(field["write_class"] != "no_source_write_vector" for field in source["fields"])
    assert {field["name"] for field in source["fields"]} == set(source["numeric_names"])
    for field in source["fields"]:
        hashes = field["evidence_hashes"]
        assert hashes["source"] == source["source_sha256"]
        assert hashes["getter"] == EVIDENCE_HASHES[field["native_get_evidence"]]
        if field["write_class"] == "uint16_cache":
            native_write = field["native_write"]
            assert native_write["evidence_hashes"]["source"] == source["source_sha256"]
            assert native_write["evidence_hashes"]["ack"] == EVIDENCE_HASHES[
                native_write["evidence"]["ack"]]
            assert native_write["evidence_hashes"]["fresh"] == EVIDENCE_HASHES[
                native_write["evidence"]["fresh"]]
    for vectors in source["extended_protocols"].values():
        for vector in vectors:
            hashes = vector["evidence_hashes"]
            assert hashes["source"] == source["source_sha256"]
            assert hashes["results"] == EVIDENCE_HASHES["native_protocol_results"]
            assert hashes["vectors"] == EVIDENCE_HASHES["native_protocol_vectors"]
    lexical = source["lexical_number_run"]
    assert lexical["evidence_sha256"]["source"] == source["source_sha256"]
    assert lexical["evidence_sha256"]["results"] == EVIDENCE_HASHES["native_lexical_cpu"]
    assert lexical["evidence_sha256"]["vectors"] == EVIDENCE_HASHES["native_lexical_vectors"]
    timer = source["timer_record"]
    assert timer["source_sha256"] == source["source_sha256"]
    assert timer["constructor"]["evidence_sha256"]["results"] == EVIDENCE_HASHES[
        "native_timer_record"]
    assert all(query["evidence_sha256"]["source"] == source["source_sha256"]
               and query["evidence_sha256"]["results"] == EVIDENCE_HASHES["native_timer_record"]
               for query in timer["queries"])
    response_evidence = timer["setT_source_closed_response"]["evidence_sha256"]
    assert response_evidence["source"] == source["source_sha256"]
    assert response_evidence["decompiled_c"] == source["source_artifact_hashes"][
        "decompiled_c_sha256"]
    assert response_evidence["instructions_tsv"] == source["source_artifact_hashes"][
        "instructions_tsv_sha256"]
    for binding in source["binding_runs"]:
        assert binding["evidence_sha256"]["source"] == source["source_sha256"]
        assert binding["evidence_sha256"]["results"] == EVIDENCE_HASHES["native_bindings"]
    for operation in source["local_operations"].values():
        hashes = operation["evidence_sha256"]
        assert hashes["source"] == source["source_sha256"]
        assert hashes["result"] == EVIDENCE_HASHES[operation["evidence"]]
    for alias in source["alias_roles"]:
        name, slots = alias["name"], alias["slots"]
        assert [slot for slot, value in enumerate(handler.ordered_names) if value == name] == slots
        assert handler.ordered_names.index(name) == slots[0]
    assert scalar.CODEC == "aes-ecb-pkcs7"


def test_mr_native_udp_receive_and_bounded_router_evidence():
    udp = EVIDENCE["udp_ingress"]
    assert udp["source_sha256"] == "ac43e9ff82a55cb1719055eaa9ced115948814efbeb18086f818bb8ea9fedf9e"
    assert udp["artifact_sha256"] == EVIDENCE_HASHES["native_udp_receive"]
    assert udp["roots"] == {
        "receive": "0x9b032098", "router": "0x9b032764",
        "UDP_socket_producer": "0x9b033180"}
    assert "select/recvfrom receive a declared queued datagram" in udp["qualification"]
    for vector in udp["vectors"]:
        assert vector["MID_producer"]["completed"] is True
        assert vector["MID_producer"]["return_r0"] == 5
        assert vector["MID_producer"]["emitted_mid"] == "10001"
        assert vector["receive"]["completed"] is True
        assert vector["receive"]["return_r0"] == 1
        calls = vector["network_API_calls"]
        assert [call["API"] for call in calls] == ["select", "recvfrom"]
        assert calls[0]["return"] == 1
        assert calls[1]["packet_hex"] == vector["input_hex"]
        assert vector["router"]["entry"] == "0x9b032764"
        assert vector["router"]["completed"] is False
        assert vector["router"]["pc"] == "0x1000489e"
        assert vector["original_cipher_observations"][0]["observer_only"] is True
        expected_key = GENERIC_KEY.hex() if vector["name"] == "scan" else SESSION_KEY.hex()
        assert vector["original_cipher_observations"][0]["key_hex"] == expected_key


@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_every_finite_source_getter_including_footer_fields(source):
    root = device(source)
    for field in source["fields"]:
        name = field["name"]
        result = exchange(root, {"t": "status", "cols": [name]})
        assert result["cols"] == field["native_get"]["cols"], name
        assert result["dat"] == field["native_get"]["dat"], name


@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_mr_metadata_defaults_ragged_values_and_fault_safe_rejection(source):
    root = device(source)
    defaults = expected_defaults(source)
    assert root.profile.handler.metadata_defaults == defaults
    assert scalar.METADATA_DEFAULTS[source["historical_index"]] == defaults
    setter_scope = EVIDENCE["metadata_setter_scope"]
    assert setter_scope["source_sha256"] == source["source_sha256"]
    assert setter_scope["evidence_sha256"] == EVIDENCE_HASHES["native_metadata_setters"]
    names = set(setter_scope["names"])
    outcomes = (setter_scope["completed_with_json_reply"]
               + setter_scope["completed_without_json_reply"]
               + setter_scope["native_fault_names"])
    assert len(outcomes) == len(set(outcomes)) == len(names) == 17
    assert set(outcomes) == names
    assert setter_scope["request_template"]["p"] == [65537]
    assert setter_scope["native_fault_names"] == ["rssi"]
    for vector in source["metadata_getters"]:
        hashes = vector["evidence_hashes"]
        assert hashes["source"] == source["source_sha256"]
        assert hashes["result"] == EVIDENCE_HASHES["native_metadata_status"]
        if vector["native_outcome"] == "success":
            result = exchange(root, {"t": "status", "cols": [vector["name"]]})
            assert result["cols"] == vector["cols"], vector["name"]
            assert result["dat"] == vector["dat"], vector["name"]
        elif vector["safe_model"] == "reject getter atomically":
            assert vector["native_outcome"] == "fault"
            assert vector["native_fault"]["pc"] == "0x9b008b0c"
            before = deepcopy(root.state)
            with pytest.raises(InvalidPacket):
                exchange(root, {"t": "status", "cols": [vector["name"]]})
            assert root.state == before
        else:
            assert vector["native_outcome"] in ("fault", "no completed getter vector")
            result = exchange(root, {"t": "status", "cols": [vector["name"]]})
            assert result["cols"] == [] and result["dat"] == [], vector["name"]
    unknown = source["unknown"]
    assert unknown["request"]["cols"] == ["__unknown__"]
    assert unknown["native_status"] is None
    assert unknown["native_fault"]["pc"] == "0x9b008b0c"
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        exchange(root, unknown["request"])
    assert root.state == before
    names = ["Pow", "DevID", "MafIdf", "Pow", "hid"]
    result = exchange(root, {"t": "status", "cols": names})
    columns, data = expected_status(source, names)
    assert result["cols"] == columns
    assert result["dat"] == data
    assert any(not row["dat"] for row in source["metadata_getters"]
               if row["native_outcome"] == "success")


@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_every_numeric_source_setter_ack_fresh_and_cache_value(source):
    root = device(source)
    numeric_fields = [field for field in source["fields"]
                      if field["write_class"] == "uint16_cache"]
    assert numeric_fields
    assert all(field["native_write"] is not None for field in numeric_fields)
    for field in numeric_fields:
        vector = field["native_write"]
        assert vector is not None and vector["class"] == "uint16_cache", field["name"]
        assert vector["mask"] == field["write_mask"] == 65535
        result = exchange(root, vector["request"])
        assert result == vector["ack"], field["name"]
        fresh = exchange(root, {"t": "status", "cols": [field["name"]]})
        assert fresh["cols"] == vector["fresh"]["cols"], field["name"]
        assert fresh["dat"] == vector["fresh"]["dat"], field["name"]
        requested = vector["request"]["p"][0]
        stored = 0 if requested < 0 else requested & 65535
        assert root.state[field["name"]] == stored, field["name"]

@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_raw_exponent_number_uses_source_lexical_parser(source):
    vector = source["lexical_number_run"]
    assert vector["raw_request"] == (
        '{"t":"cmd","mac":"020000000001","opt":["Pow"],"p":[1e3]}')
    assert vector["native_completed"] is True and vector["native_fault"] is None
    assert vector["native_ack"]["p"] == [1]
    assert vector["fresh_completed"] is True
    assert vector["fresh_status"]["cols"] == ["Pow"]
    assert vector["fresh_status"]["dat"] == [1]
    root = device(source)
    replies = root.profile.handler.handle(
        root, packet_raw_json(vector["raw_request"], target=root.mac))
    reply, = replies
    assert unpack(reply, root) == vector["native_ack"]
    fresh = exchange(root, {"t": "status", "cols": ["Pow"]})
    assert fresh["dat"] == vector["fresh_status"]["dat"]



def test_mr_literal_overflow_exponent_and_negative_zero_vectors():
    source = SOURCES[0]
    run = source["lexical_edge_run"]
    assert run["source_sha256"] == source["source_sha256"]
    assert run["evidence_sha256"]["results"] == EVIDENCE_HASHES["native_lexical_edge"]
    assert run["qualification"].startswith(
        "Original MR whole command/status callbacks with literal JSON numeric spellings.")
    assert [vector["name"] for vector in run["vectors"]] == [
        "overflow-exponent", "negative-zero-compaction"]
    for vector in run["vectors"]:
        assert vector["native_completed"] and vector["native_fault"] is None
        assert vector["fresh_completed"]
        if vector["name"] == "overflow-exponent":
            assert vector["raw_request"] == (
                '{"t":"cmd","mac":"020000000001","opt":["Pow"],"p":[1e309]}')
        else:
            assert vector["raw_request"] == (
                '{"t":"cmd","mac":"020000000001","opt":["Pow","Mod"],"p":[-0,7]}')
        root = device(source)
        reply, = root.profile.handler.handle(
            root, packet_raw_json(vector["raw_request"], uid=0, target=root.mac))
        assert unpack(reply, root, uid=0) == vector["native_ack"]
        fresh_request = {
            "t": "status", "mac": root.mac,
            "cols": vector["native_fresh_status"]["cols"],
        }
        fresh_reply, = root.profile.handler.handle(
            root, packet(fresh_request, uid=0, target=root.mac))
        assert unpack(fresh_reply, root, uid=0) == vector["native_fresh_status"]


@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_mr_plaintext_callbacks_preserve_source_closed_behavior(source):
    contract = source["plaintext_callbacks"]
    assert contract["qualification"].startswith(
        "Static source closure only; no completed whole-callback native vector")
    assert contract["source_sha256"] == source["source_sha256"]
    assert contract["evidence_sha256"]["source"] == source["source_sha256"]
    assert contract["handler_roots"] == {
        "hbok": "0x9b032a28", "tm": "0x9b032ce4",
        "wlan": "0x9b032ce0", "calendar_set": "0x9b0379f8",
    }
    hashes = contract["evidence_sha256"]
    assert hashes["router_decompiled_c"] == source["source_artifact_hashes"][
        "decompiled_c_sha256"]
    assert hashes["router_instructions_tsv"] == source["source_artifact_hashes"][
        "instructions_tsv_sha256"]
    assert hashes["final_source_decompiled_c"] == EVIDENCE_HASHES[
        "mr_final_source_decompiled_c"]
    assert hashes["final_source_instructions_tsv"] == EVIDENCE_HASHES[
        "mr_final_source_instructions"]
    assert hashes["final_source_qualification"] == EVIDENCE_HASHES[
        "mr_final_source_qualification"]
    root = device(source)
    handler = root.profile.handler
    assert handler.plaintext_types == ("hbok", "tm", "wlan")

    heartbeat = contract["handlers"]["hbok"]
    exchange(root, {"t": "status", "cols": ["Pow"]})
    runtime = root.state["_runtime"]
    runtime["heartbeat_retries"] = heartbeat["precondition"]["heartbeat_retries"]
    runtime["heartbeat_pending"] = heartbeat["precondition"]["heartbeat_pending"]
    assert handler.handle(root, heartbeat["request"]) == heartbeat["expected_replies"]
    assert root.state["_runtime"]["heartbeat_retries"] == 0
    assert root.state["_runtime"]["heartbeat_pending"] is False

    clock = contract["handlers"]["tm"]
    root.last_step = 0.0
    assert handler.handle(root, clock["request"]) == clock["expected_replies"]
    assert root.state["_runtime"]["clock_epoch"] == clock["effective_epoch"]
    assert exchange(root, {"t": "status", "cols": ["time"]})["dat"] == [
        clock["effective_time"]]

    wlan = contract["handlers"]["wlan"]
    request = wlan["request"]
    replies = handler.handle(root, request)
    reply, = replies
    assert json.loads(encode_reply(reply)) == wlan["expected_plaintext_reply"]
    assert root.state["_runtime"]["network"] == wlan["expected_virtual_network"]
    assert root.state["_runtime"]["restart_requested"] is True

    for field, maximum in wlan["byte_limits"].items():
        invalid = {**request, field: "x" * (maximum + 1)}
        before = deepcopy(root.state)
        with pytest.raises(InvalidPacket):
            handler.handle(root, invalid)
        assert root.state == before
    bounds = EVIDENCE["string_bound_scope"]
    assert bounds["source_sha256"] == source["source_sha256"]
    assert bounds["evidence_sha256"] == EVIDENCE_HASHES["native_string_bounds"]
    assert bounds["primitive"] == {
        "address": "0x9b008b48", "name": "strnlen",
        "veneer_hex": "014b5b6a184700bf00080000", "caller_abi": "(str, max)"}
    assert bounds["reader"]["GetString"] == "0x9b037304"
    assert bounds["reader"]["reject_when_return_equals_max"] is True
    assert {field: value["maximum_payload_bytes"]
            for field, value in bounds["caller_capacities"].items()
            if field in ("host", "ssid", "psw")} == wlan["byte_limits"]


def test_mr_corrected_source_string_bounds_cover_upgrade_and_timer_name():
    source = SOURCES[0]
    bounds = EVIDENCE["string_bound_scope"]
    assert bounds["source_sha256"] == source["source_sha256"]
    root = device(source)

    url_limit = bounds["caller_capacities"]["url"]["maximum_payload_bytes"]
    url = "u" * url_limit
    assert exchange(root, {"t": "upgrade", "url": url}) == {"t": "ret", "r": 200}
    assert root.state["_runtime"]["upgrade_url"] == url
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "upgrade", "url": url + "u"})
    assert root.state == before

    name_limit = bounds["caller_capacities"]["name"]["maximum_payload_bytes"]
    timer = deepcopy(EVIDENCE["timer_record_scope"]["input"])
    timer["name"] = "n" * name_limit
    assert exchange(root, timer) == {"t": "resT", "r": 200}
    assert root.state["_runtime"]["timers"][timer["id"] & 255]["name"] == timer["name"]
    before = deepcopy(root.state)
    timer["name"] += "n"
    with pytest.raises(InvalidPacket):
        exchange(root, timer)
    assert root.state == before

@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_signed_boundaries_duplicates_and_name_noop_mixed_order(source):
    root = device(source)
    for vector in source["signed_boundaries"]:
        result = exchange(root, vector["request"])
        assert result == vector["ack"], vector["id"]
        fresh = exchange(root, {"t": "status", "cols": ["Pow"]})
        assert fresh["dat"] == vector["fresh"]["dat"], vector["id"]
    duplicate = source["duplicates"]
    assert exchange(root, duplicate["request"]) == duplicate["ack"]
    duplicate_fresh = exchange(
        root, {"t": "status", "cols": duplicate["fresh"]["cols"]})
    assert duplicate_fresh["dat"] == duplicate["fresh"]["dat"]
    mixed = source["mixed"]
    result = exchange(root, mixed["request"])
    assert result == mixed["ack"]
    assert result["opt"] == ["name", "Pow"]
    assert result["p"] == ["", 1]
    fresh = exchange(root, {"t": "status", "cols": mixed["request"]["opt"]})
    assert fresh["dat"] == mixed["fresh"]["dat"] == [1, ""]
    assert root.name == "Scalar"


@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_mr_mixed_reportclientid_and_numeric_bindings(source):
    runs = {run["id"]: run for run in source["binding_runs"]}
    for run_id in ("mr-negative-first", "mr-negative-last",
                   "mr-local-first", "mr-numeric-first"):
        vector = runs[run_id]
        assert vector["native_completed"] is True
        root = device(source)
        assert exchange(root, vector["request"]) == vector["native_ack"]
        fresh = exchange(root, {
            "t": "status", "cols": vector["native_fresh_status"]["cols"]})
        assert fresh["dat"] == vector["native_fresh_status"]["dat"]
        if run_id in ("mr-local-first", "mr-numeric-first"):
            assert root.state["_runtime"]["frames"]["ReportClientID"].hex() == (
                source["binary_vectors"]["ReportClientID"]["frame_hex"])
    for run_id in ("mr-negative-first", "mr-negative-last"):
        assert runs[run_id]["native_ack"]["p"] == [7, 0]
        assert runs[run_id]["native_fresh_status"]["dat"] == [7, 0]
    for run_id in ("mr-local-first", "mr-numeric-first"):
        assert runs[run_id]["native_ack"]["opt"] == ["Pow"]
        assert runs[run_id]["native_ack"]["p"] == [7]

@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_numeric_shadow_writes_do_not_replace_actual_getter_values(source):
    root = device(source)
    overrides = set(source["raw_getter_override_names"])
    for field in source["fields"]:
        name = field["name"]
        if name not in overrides or field["write_class"] != "uint16_cache":
            continue
        vector = field["native_write"]
        exchange(root, vector["request"])
        requested = vector["request"]["p"][0]
        expected_cache = 0 if requested < 0 else requested & 65535
        assert root.state[name] == expected_cache
        fresh = exchange(root, {"t": "status", "cols": [name]})
        assert fresh["dat"] == vector["fresh"]["dat"]
        assert fresh["dat"] == field["native_get"]["dat"]


@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_mr_local_readonly_noop_and_host_roles(source):
    root = device(source)
    for name in source["read_only_names"]:
        before = deepcopy(root.state)
        with pytest.raises(InvalidPacket):
            exchange(root, {"t": "cmd", "opt": ["Pow", name], "p": [1, "ignored"]})
        assert root.state == before
    for name in source["noop_names"]:
        operation = source["local_operations"][name]
        assert exchange(root, operation["request"]) == operation["native_ack"], name
    assert root.name == "Scalar"
    for name in source["noop_names"]:
        assert exchange(root, {"t": "status", "cols": [name]})["dat"] == expected_defaults(source)[name]

    host = source["local_operations"]["host"]
    qualification = source["native_host_write_qualification"]
    assert qualification["setter_root"] == "0x9b030f40"
    assert "host" not in qualification["source_supported_literals"]
    assert qualification["source_supported_literals"] == [
        "name", "time", "AppTimer", "ReportCID", "ModelType"]
    assert qualification["evidence_sha256"]["source"] == source["source_sha256"]
    assert qualification["evidence_sha256"]["decompiled_c"] == source[
        "source_artifact_hashes"]["decompiled_c_sha256"]
    assert qualification["evidence_sha256"]["instructions_tsv"] == source[
        "source_artifact_hashes"]["instructions_tsv_sha256"]
    assert qualification["native_return_r0"] == -1
    assert qualification["native_json_reply"] is None
    assert host["native_ack"] is None and host["native_return_r0"] == -1
    field = next(field for field in source["fields"] if field["name"] == "host")
    assert field["write_class"] == "native_no_reply_safe_reject"
    assert field["native_write"]["native_return_r0"] == -1
    assert field["native_write"]["native_ack"] is None
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        exchange(root, host["request"])
    assert root.state == before
    assert exchange(root, {"t": "status", "cols": ["host"]})["dat"] == [
        host["native_fresh"]["dat"][0]]

@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_mr_time_uses_native_timer_api_result(source):
    root = device(source)
    operation = source["local_operations"]["time"]
    assert operation["native_completed"] is True
    assert operation["native_fault"] is None
    assert exchange(root, operation["request"]) == operation["native_ack"]
    fresh = exchange(root, {"t": "status", "cols": ["time"]})
    assert fresh["dat"] == operation["native_fresh"]["dat"] == ["2036-03-09 06:28:16"]
    assert source["clock_sdk_api_context"] is None
    assert root.state["_runtime"]["time_sync_pending"] is True


@pytest.mark.parametrize("timer_id", ("active_logical_enable_zero", "inactive_logical_enable_one"))
def test_mr_timer_worker_replays_virtual_schedule_without_changing_pow(timer_id):
    source = SOURCES[0]
    worker = source["timer_worker_runs"][timer_id]
    hashes = worker["evidence_sha256"]
    assert hashes["source"] == source["source_sha256"]
    assert hashes["results"] == EVIDENCE_HASHES[worker["id"]]
    assert worker["qualification"].startswith("Original MR record constructor")
    assert worker["clock_scope"].startswith("Explicit virtual source clock")
    assert len(bytes.fromhex(worker["original_record_hex"])) == 52
    assert worker["constructor"]["completed"] is True
    assert worker["constructor"]["return_r0"] == 0
    assert "sec" not in worker["input"] and worker["input"]["min"] == 28
    root = device(source)
    root.last_step = 0.0
    handler = root.profile.handler
    clock = source["plaintext_callbacks"]["handlers"]["tm"]
    assert handler.handle(root, clock["request"]) == []
    assert root.state["_runtime"]["clock_epoch"] == worker["clock_epoch"]
    assert exchange(root, worker["input"]) == source[
        "timer_record"]["setT_source_closed_response"]["json"]
    timer = root.state["_runtime"]["timers"][worker["input"]["id"]]
    assert timer["enable"] == worker["logical_enable_before"]
    assert timer["remaining"] == worker["remaining_before"]
    assert root.state["Pow"] == 0

    for step in worker["steps"]:
        now = float(step["index"])
        root.last_step = now
        assert handler.tick(root, now) == []
        assert step["worker"]["completed"] is True
        timer = root.state["_runtime"]["timers"][worker["input"]["id"]]
        assert timer["remaining"] == step["countdown_signed"]
        assert root.state["_runtime"]["timer_projection"].hex() == (
            step["timer_projection_hex"])
        assert root.state["Pow"] == step["raw_Pow"]

    assert timer["enable"] == worker["logical_enable_after"]
    assert timer["remaining"] == worker["steps"][-1]["countdown_signed"]
    query = exchange(root, {"t": "queryT", "index": 0, "count": 10})
    assert query["list"][0]["enable"] == worker["logical_enable_after"]
    assert root.state["Pow"] == 0



@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_native_timer_record_construction_and_query_vectors(source):
    timer = source["timer_record"]
    constructor = timer["constructor"]
    assert constructor["native_completed"] is True and constructor["native_return_r0"] == 0
    assert len(bytes.fromhex(constructor["record_hex"])) == 52
    assert timer["input"] == EVIDENCE["timer_record_scope"]["input"]
    assert timer["setT_source_closed_response"]["json"] == {"t": "resT", "r": 200}
    root = device(source)
    assert exchange(root, timer["input"]) == timer["setT_source_closed_response"]["json"]
    for vector in timer["queries"]:
        assert vector["native_completed"] is True
        assert exchange(root, vector["request"]) == vector["native_response"]


@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_mr_timer_missing_seconds_uses_min_byte(source):
    optional = source["timer_optional_seconds"]
    assert EVIDENCE["timer_optional_seconds_scope"]["evidence_sha256"] == (
        EVIDENCE_HASHES["native_timer_optional_seconds"])
    assert optional["constructor"]["evidence_sha256"]["results"] == (
        EVIDENCE_HASHES["native_timer_optional_seconds"])
    assert optional["source_sha256"] == source["source_sha256"]
    assert "sec" not in optional["input"]
    constructor = optional["constructor"]
    assert constructor["native_completed"] is True
    assert len(bytes.fromhex(constructor["record_hex"])) == 52
    root = device(source)
    assert exchange(root, optional["input"]) == source[
        "timer_record"]["setT_source_closed_response"]["json"]
    for vector in optional["queries"]:
        assert vector["native_completed"] is True
        result = exchange(root, vector["request"])
        assert result == vector["native_response"]
    missing = optional["queries"][0]["native_response"]["list"][0]
    explicit = source["timer_record"]["queries"][0]["native_response"]["list"][0]
    assert missing["sec"] == 9
    assert explicit["sec"] == 0


@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_mr_unmatched_timer_update_uses_source_closed_noop(source):
    vector = source["timer_update_missing_id_static"]
    evidence = vector["evidence_sha256"]
    assert evidence["source"] == source["source_sha256"]
    assert evidence["decompiled_c"] == source["source_artifact_hashes"][
        "decompiled_c_sha256"]
    assert evidence["instructions_tsv"] == source["source_artifact_hashes"][
        "instructions_tsv_sha256"]
    assert vector["qualification"].startswith(
        "Static source-business closure only; no native whole updateT replay")
    assert vector["request"]["t"] == "updateT" and vector["request"]["id"] == 257
    assert vector["source_closed_ack"] == {"t": "resT", "r": 200}
    root = device(source)
    query = {"t": "queryT", "index": 0, "count": 10}
    before = exchange(root, query)
    assert before["list"] == []
    assert exchange(root, vector["request"]) == vector["source_closed_ack"]
    assert exchange(root, query) == before

@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_mr_write_only_report_frames_and_utf8_boundary(source):
    root = device(source)
    vector = source["binary_vectors"]["ReportClientID"]
    evidence = vector["evidence_sha256"]
    assert evidence["source"] == source["source_sha256"]
    assert evidence["result"] == EVIDENCE_HASHES["native_final_fields"]
    assert evidence["decompiled_c"] == source["source_artifact_hashes"][
        "decompiled_c_sha256"]
    assert vector["max_utf8_payload_bytes"] == 26
    assert vector["frame_bytes"] == 30
    assert vector["source_write_root"] == "0x9b030d14"
    assert vector["evidence_sha256"]["final_source_decompiled_c"] == (
        EVIDENCE_HASHES["mr_final_source_decompiled_c"])
    assert vector["evidence_sha256"]["final_source_instructions_tsv"] == (
        EVIDENCE_HASHES["mr_final_source_instructions"])
    assert vector["frame_qualification"].startswith(
        "Original setter clears a 30-byte buffer")
    assert exchange(root, vector["request"]) == vector["native_ack"]
    assert root.state["_runtime"]["frames"]["ReportClientID"].hex() == vector["frame_hex"]
    assert len(root.state["_runtime"]["frames"]["ReportClientID"]) == vector["frame_bytes"]
    assert len(vector["frame_hex"]) == 2 * vector["frame_bytes"]
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "status", "cols": ["ReportClientID"]})
    assert root.state == before
    maximum = "é" * 13
    exchange(root, {"t": "cmd", "opt": ["ReportClientID"], "p": [maximum]})
    payload = maximum.encode("utf-8")
    expected_frame = (bytes.fromhex("7e7e126a") + payload
                      + b"\0" * (vector["frame_bytes"] - 4 - len(payload)))
    assert len(expected_frame) == vector["frame_bytes"] == 30
    assert root.state["_runtime"]["frames"]["ReportClientID"] == expected_frame
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "cmd", "opt": ["ReportClientID"], "p": ["é" * 14]})
    assert root.state == before


@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_unknown_and_invalid_numeric_commands_are_strict_and_atomic(source):
    root = device(source)
    unknown = source["unknown"]
    assert unknown["native_status"] is None
    assert unknown["native_fault"]["pc"] == "0x9b008b0c"
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        exchange(root, unknown["request"])
    assert root.state == before
    for value in EVIDENCE["numeric_policy_vectors"]["invalid_model_inputs"]:
        before = deepcopy(root.state)
        with pytest.raises(InvalidPacket):
            exchange(root, {"t": "cmd", "opt": ["Pow"], "p": [value]})
        assert root.state == before
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "cmd", "opt": ["Pow", "__unknown__"],
                        "p": [1, "ignored"]})
    assert root.state == before
    names = ["Pow", "name", "host"]
    result = exchange(root, {"t": "status", "cols": names})
    columns, values = expected_status(source, names)
    assert result["cols"] == columns
    assert result["dat"] == values





@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_mr_buzzer_on_off_native_word_values(source):
    assert "Buzzer_ON_OFF" in source["numeric_names"]
    assert "BuzzerCtrl" not in source["numeric_names"]
    assert "BuzzerCtrl" not in source["local_names"]
    evidence = EVIDENCE["buzzer_state_scope"]["evidence_sha256"]
    assert evidence["state"] == EVIDENCE_HASHES["native_buzzer_state"]
    assert evidence["state_vectors"] == EVIDENCE_HASHES["native_buzzer_state_vectors"]
    for vector in source["buzzer_state_runs"]:
        root = device(source)
        assert vector["native_ack"] is not None
        assert exchange(root, vector["request"]) == vector["native_ack"]
        fresh = exchange(root, {"t": "status", "cols": ["Buzzer_ON_OFF"]})
        assert fresh["cols"] == vector["native_fresh_status"]["cols"]
        assert fresh["dat"] == vector["native_fresh_status"]["dat"]
    word_two = next(row for row in source["buzzer_state_runs"] if row["id"] == "buzzer-word-2")
    negative = next(row for row in source["buzzer_state_runs"] if row["id"] == "buzzer-word--1")
    assert word_two["native_ack"]["p"] == [2]
    assert word_two["native_fresh_status"]["dat"] == [2]
    assert negative["native_ack"]["p"] == [0]
    assert negative["native_fresh_status"]["dat"] == [0]

def test_mr_session_packet_discovery_headers_and_raw_mid_are_separate():
    source = SOURCES[0]
    discovery_evidence = source["native_discovery"]["evidence_sha256"]
    assert discovery_evidence["source"] == source["source_sha256"]
    assert discovery_evidence["result"] == EVIDENCE_HASHES["native_discovery"]
    vector = next(row for row in source["binding_runs"]
                  if row["id"] == "mr-negative-first")
    root = device(source)
    replies = root.profile.handler.handle(
        root, packet(vector["request"], index=0, uid=73, target=root.mac))
    reply, = replies
    assert unpack(reply, root, index=0, uid=73) == vector["native_ack"]
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        root.profile.handler.handle(
            root, packet(vector["request"], index=0, target=root.mac, key=GENERIC_KEY))
    with pytest.raises(InvalidPacket):
        root.profile.handler.handle(
            root, packet(vector["request"], index=0, target="000000000000"))
    assert root.state == before

    reply, = root.profile.handler.advertise(root, {"i": 73, "uid": 12})
    discovery = unpack(reply, root, discovery=True)
    assert discovery == source["native_discovery"]["json_output"]
    assert discovery["mid"] == root.profile.mids[0] == root.mid == "10001"
    assert discovery["mid"] == EVIDENCE["udp_ingress"]["vectors"][0][
        "MID_producer"]["emitted_mid"]
    assert exchange(root, {"t": "status", "cols": ["mid", "name"]})["dat"] == ["", ""]



@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_mr_upgrade_keeps_native_fault_and_no_ack_distinct(source):
    upgrade = source_operation(source, "upgrade")
    assert upgrade["native_ack"] is None
    if upgrade["native_fault"] is None:
        assert upgrade["native_completed"] is True
    else:
        assert upgrade["native_completed"] is False
    root = device(source)
    assert exchange(root, upgrade["request"]) == {"t": "ret", "r": 200}
    assert root.state["_runtime"]["upgrade_url"] == upgrade["request"]["url"]
    assert root.state["_runtime"]["upgrade_pending"] is True
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "upgrade", "url": "x" * 120})
    assert root.state == before

@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_mr_bin_cmd_native_fault_and_source_closed_response(source):
    offsets = EVIDENCE["reportfreq_offset_scope"]
    assert offsets["source_index"] == source["historical_index"] == 22
    assert source["reportfreq_byte_offsets_hex"] == offsets["byte_offsets_hex"] == [
        "0x22", "0x24"]
    assert "not decimal offsets 22 and 24" in offsets["qualification"]
    assert offsets["evidence_sha256"]["source"] == source["source_sha256"]
    assert offsets["evidence_sha256"]["decompiled_c"] == source[
        "source_artifact_hashes"]["decompiled_c_sha256"]
    assert offsets["evidence_sha256"]["instructions_tsv"] == source[
        "source_artifact_hashes"]["instructions_tsv_sha256"]
    assert any(vector["request"].get("ReportFreq") == 255
               for vector in source["extended_protocols"]["binCmd"])
    for vector in source["extended_protocols"]["binCmd"]:
        assert vector["registered"] is True
        assert vector["native_completed"] is False
        assert vector["native_ack"] is None
        assert vector["native_fault"]["pc"] == "0x1000489e"
        closure = vector["source_closure_expected"]
        assert closure["normal_cpu_register_value"] == 0
        assert closure["ack"] == {"t": "res", "r": 200}
        assert closure["evidence_sha256"]["source"] == source["source_sha256"]
        assert closure["evidence_sha256"]["decompiled_c"] == source[
            "source_artifact_hashes"]["decompiled_c_sha256"]
        assert closure["evidence_sha256"]["instructions_tsv"] == source[
            "source_artifact_hashes"]["instructions_tsv_sha256"]
        root = device(source)
        replies = root.profile.handler.handle(
            root, packet(vector["request"], target=root.mac))
        reply, = replies
        assert unpack(reply, root) == closure["ack"]

@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_mr_frequency_callback_silent_modes_and_unknown_fault_safety(source):
    vectors = source["extended_protocols"]["freqCount"]
    assert all(vector["registered"] is True and vector["native_completed"] is True
               and vector["native_fault"] is None and vector["native_ack"] is None
               for vector in vectors)
    for vector in vectors:
        root = device(source)
        before_pow = root.state["Pow"]
        before_frequency = deepcopy(root.state.get("_runtime", {}).get("frequency", {}))
        assert root.profile.handler.handle(
            root, packet(vector["request"], target=root.mac)) == []
        if vector["id"] == "freq-known-write":
            fresh = exchange(root, {"t": "status", "cols": vector["native_fresh"]["cols"]})
            assert fresh["dat"] == vector["native_fresh"]["dat"] == [77]
            assert root.state["Pow"] == 77
        else:
            assert root.state["Pow"] == before_pow
            assert root.state.get("_runtime", {}).get("frequency", {}) == before_frequency

    unsafe = source_operation(source, "freqCount")
    assert unsafe["native_ack"] is None
    assert unsafe["native_fault"]["pc"] == "0x9b008b0c"
    known = set(source["numeric_names"]) | set(source["local_names"])
    assert all(name not in known for name in unsafe["request"]["opt"])
    root = device(source)
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        root.profile.handler.handle(root, packet(unsafe["request"], target=root.mac))
    assert root.state == before




@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
@pytest.mark.parametrize("decoded", [b"~~", b"~~\x05A"])
def test_mr_bin_cmd_uses_original_zeroed_decode_buffer(source, decoded):
    root = device(source)
    request = {"t": "binCmd", "hex01": base64.b64encode(decoded).decode("ascii")}
    assert exchange(root, request) == {"t": "res", "r": 200}
    expected = bytearray(60)
    expected[:len(decoded)] = decoded
    expected[7], expected[43] = 0xaf, 2
    assert root.state["_runtime"]["frames"]["hex01"] == bytes(expected)


@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
@pytest.mark.parametrize("frequency, expected_frequency, word", [
    (255, 60, b"\x00\x00"), (511, 255, b"\xff\x40"), (-1, 255, b"\xff\x40")])
def test_mr_reportfreq_sentinel_compares_full_cjson_integer(source, frequency,
                                                           expected_frequency, word):
    root = device(source)
    request = {"t": "binCmd", "hex01": "fn4A", "ReportFreq": frequency}
    assert exchange(root, request) == {"t": "res", "r": 200}
    runtime = root.state["_runtime"]
    assert runtime["report_frequency"] == expected_frequency
    assert runtime["frames"]["ReportFreq"][0x22:0x26] == word + b"\x5a\x40"


@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_mr_request_target_matches_literal_native_key_precedence(source):
    for vector in EVIDENCE["target_precedence_native"]["vectors"]:
        root = device(source)
        replies = root.profile.handler.handle(root, packet(vector["request"]))
        expected = deepcopy(vector["native_ack"])
        if expected["t"] == "dat":
            expected["uid"] = 42
        assert vector["completed"] is True
        assert unpack(replies[0], root) == expected


@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_mr_wlan_limits_match_corrected_native_string_reader(source):
    root = device(source)
    accepted = {"t": "wlan", "host": "X" * 19, "ssid": "X" * 32, "psw": "X" * 64}
    reply, = root.profile.handler.handle(root, accepted)
    assert json.loads(encode_reply(reply)) == {"t": "ret", "r": 200, "mac": ""}
    for field, length in (("host", 20), ("ssid", 33), ("psw", 65)):
        before = deepcopy(root.state)
        with pytest.raises(InvalidPacket):
            root.profile.handler.handle(root, {**accepted, field: "X" * length})
        assert root.state == before


@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_mr_source_header_cstring_bound_is_atomic(source):
    root = device(source)
    outer = packet({"t": "status", "cols": ["Pow"]})
    for peer in ("X" * 64, "peer\0tail"):
        before = deepcopy(root.state)
        with pytest.raises(InvalidPacket):
            root.profile.handler.handle(root, {**outer, "cid": peer})
        assert root.state == before
