"""Original-source nine/seven UDP callbacks and explicit virtual raw readouts.

Authored only: no worker test/native execution. Physical MCU data/calibration,
actual flash contents and source35 malformed-clock ROM are not fabricated.
"""

import asyncio
import base64
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.catalog_realtek_middle_wb_legacy import (
    CODEC, PROFILES, _native_json_text, make_middle_wb_legacy_profile,
)
from gree_emulator.server import EmulatorServer
from gree_emulator.wire import InvalidPacket, encode_reply


FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-realtek-middle-wb-legacy_research.json").read_text())
SOURCES = FIXTURE["sources"]
KEY = bytes.fromhex(FIXTURE["paired_key_hex"])
ADDR = ("192.0.2.10", 5001)
MAC = "020000000001"


def controller(source, mac=MAC):
    if isinstance(source, int):
        source = next(row for row in SOURCES if row["assessment_index"] == source)
    profile = make_middle_wb_legacy_profile(
        source["assessment_index"], FIXTURE["initial_mid"],
        factory_key=bytes.fromhex(source["factory_key_hex"]))
    return EmulatedDevice("legacy-root", mac, "", "10001", KEY, profile,
                          deepcopy(dict(profile.initial_state)), room_c=None,
                          ambient_c=None, last_step=1000)


def request(root, inner=None, *, selector=0, uid=42, raw=None, **metadata):
    plain = (raw if raw is not None else json.dumps(inner, separators=(",", ":"))).encode() + b"\n"
    key = root.key if selector == 0 else root.profile.handler.generic_key
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(plain, 16))
    outer = {"t": "pack", "i": selector, "uid": uid, "cid": "request-client",
             "tcid": "not-the-module", "pack": base64.b64encode(encrypted).decode()}
    outer.update(metadata)
    return outer


def send(root, inner=None, *, selector=0, uid=42, raw=None, **metadata):
    packet = request(root, inner, selector=selector, uid=uid, raw=raw, **metadata)
    packet = root.profile.handler.decode_outer(json.dumps(packet).encode())
    return root.profile.handler.handle_from(root, packet, ADDR)


def response(reply):
    encoded = encode_reply(reply)
    assert not encoded.endswith(b"\n")
    outer = json.loads(encoded)
    plain = unpad(AES.new(reply.key, AES.MODE_ECB).decrypt(base64.b64decode(outer["pack"])), 16)
    assert plain.endswith(b"\n")
    return outer, json.loads(plain)


def command(root, **fields):
    reply, = send(root, {"t": "binCmd", **fields})
    outer, inner = response(reply)
    assert outer["i"] == 0 and reply.key == KEY and reply.codec == CODEC
    assert reply.destination_port == 5000
    return outer, inner


def encoded(raw):
    return base64.b64encode(raw).decode()


def scene_id(root, index):
    offset = root.profile.handler.source["scene_id_offset"]
    return int.from_bytes(root.state["scene_flash"][index][offset:offset + 4], "little")


def set_scene_id(root, index, value):
    offset = root.profile.handler.source["scene_id_offset"]
    record = bytearray(root.state["scene_flash"][index])
    record[offset:offset + 4] = value.to_bytes(4, "little")
    root.state["scene_flash"][index] = bytes(record)


@pytest.mark.parametrize("source", SOURCES)
def test_exact_source_identity_factory_inputs_and_explicit_unknown_readouts(source):
    root = controller(source)
    assert root.profile.id == source["profile_id"]
    assert root.profile.source_sha256 == source["source_sha256"]
    assert root.profile.hid == source["hid"]
    assert root.profile.mids == ("10001",)
    assert root.profile.max_request_bytes == 1536
    assert root.profile.handler.generic_key == bytes.fromhex(source["factory_key_hex"])
    assert root.profile.handler.source_port == 5001
    assert root.profile.handler.thermal_target(root) is None
    assert root.state["synthetic_readouts"] is True
    assert set(root.state["raw_banks"].values()) == {bytes(65)}
    assert root.state["scene_flash"] == [b"\xff" * source["scene_stride"]] * 20
    assert root.state["stack_work_readout"] == bytes(55)
    root.profile.handler.validate_state(root.state)
    assert {name.lower(): flag for name, flag in source["operations"].items()} == root.profile.handler.operations


def test_profile_registration_and_factory_never_guess_or_zero_a_mid():
    assert {profile.id for profile in PROFILES} == {source["profile_id"] for source in SOURCES}
    for mid in ("", "0", "00010001", "100000000", "route-guessed", "ABCDEF"):
        with pytest.raises(ValueError):
            make_middle_wb_legacy_profile(24, mid, factory_key=b"0123456789abcdef")
    with pytest.raises(ValueError):
        make_middle_wb_legacy_profile(34, "10001", factory_key=KEY)
    with pytest.raises(ValueError):
        make_middle_wb_legacy_profile(24, "10001", factory_key=b"short")


OPERATIONS = [(source, operation, channel) for source in SOURCES
              for operation, channel in source["operations"].items()]


@pytest.mark.parametrize("source,operation,channel", OPERATIONS)
def test_every_actual_udp_table_callback_is_reachable_on_its_independent_channel(source, operation, channel):
    root = controller(source)
    fields = {"t": operation}
    if operation == "reset":
        fields["mac"] = ""
    elif operation == "loginInfoRes":
        fields["r"] = 404
    elif operation == "Utm":
        fields["time"] = "2024-02-03 04:05:06"
    replies = send(root, fields, selector=channel)
    if operation == "scan":
        _, inner = response(replies[0])
        assert inner["t"] == "UBind" and inner["mid"] == "10001"
    elif operation in ("reset", "binCmd"):
        assert response(replies[0])[1] == FIXTURE["ordinary_ack"]
    elif operation == "UBindok":
        assert [response(reply)[1]["t"] for reply in replies] == source["ubind_immediate_packets"]
    else:
        assert replies == []
    before = deepcopy(root.state)
    assert send(root, fields, selector=1 - channel) == []
    assert root.state == before


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("kind", ("status", "cmd", "bind", "wlan", "tm", "unknown"))
def test_cloud_registry_and_metadata_getters_do_not_become_udp_operations(source, kind):
    root = controller(source)
    before = deepcopy(root.state)
    assert send(root, {"t": kind, "cols": ["mid", "ver", "hid", "Pow"]}) == []
    assert root.state == before


@pytest.mark.parametrize("source", SOURCES)
def test_native_discovery_is_encrypted_ubind_not_plaintext_dev_or_blank_mid(source):
    root = controller(source)
    reply, = send(root, {"t": "scan"}, selector=1)
    outer, inner = response(reply)
    assert outer == {"t": "pack", "i": 1, "uid": 42, "cid": MAC, "msgId": 1,
                     "pack": outer["pack"], "tcid": ""}
    assert inner == {"t": "UBind", "mid": "10001", "ver": source["sdk_ver"],
                     "devkey": KEY.decode(), "hid": source["hid"], "lock": 0,
                     **({"scene": 1} if source["scan_scene_output"] else {})}
    assert root.profile.handler.advertise(root, {"t": "scan"}) == []
    plain = root.profile.handler.decode_outer(b'{"t":"scan","i":false,"tcid":99}')
    assert root.profile.handler.handle_from(root, plain, ADDR) == []
    root.state["_runtime"]["online"] = 1
    assert send(root, {"t": "scan"}, selector=1) == []
    assert len(send(root, {"t": "scan", "allRange": True}, selector=1)) == 1


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("i,selector,uid,expected_uid", [(256, 0, "42", 0), (257, 1, True, 1), (0.9, 0, -3.9, -3)])
def test_old_cjson_byte_selector_and_valueint_metadata_are_not_new_core_num_rules(source, i, selector, uid, expected_uid):
    root = controller(source)
    inner = {"t": "scan"} if selector else {"t": "binCmd"}
    outer = request(root, inner, selector=selector, uid=uid)
    outer["i"] = i
    outer["cid"], outer["tcid"] = ["ignored"], {"ignored": True}
    normalized = root.profile.handler.decode_outer(json.dumps(outer).encode())
    assert normalized["i"] == selector and normalized["uid"] == expected_uid
    assert normalized["cid"] == normalized["tcid"] == ""
    reply, = root.profile.handler.handle_from(root, normalized, ADDR)
    assert response(reply)[0]["uid"] == expected_uid


@pytest.mark.parametrize("source", SOURCES)
def test_first_case_insensitive_fields_and_operation_values_preserve_actual_sdk_semantics(source):
    root = controller(source)
    reply, = send(root, raw='{"T":"BINCMD","t":"status","HEX92":null,"hex92":"ignored-second"}')
    assert response(reply)[1] == FIXTURE["ordinary_ack"]
    assert root.state["raw_banks"]["92"] == bytes(65)
    before = deepcopy(root.state)
    outer = request(root, {"t": "binCmd"})
    del outer["i"]
    normalized = root.profile.handler.decode_outer(json.dumps(outer).encode())
    assert normalized["i"] == 0
    assert len(root.profile.handler.handle_from(root, normalized, ADDR)) == 1
    with pytest.raises(InvalidPacket):
        root.profile.handler.handle_from(root, outer, (ADDR[0], 5000))
    assert root.state != before


@pytest.mark.parametrize("source", SOURCES)
def test_all_four_raw_banks_are_separate_local_base64_readouts_not_effective_dat(source):
    root = controller(source)
    frame = bytes.fromhex(FIXTURE["raw_bank_frame_hex"])
    _, ack = command(root, **{name: encoded(frame) for name in ("hex91", "hex92", "hex93", "hex6A")})
    assert ack == FIXTURE["ordinary_ack"]
    assert set(root.state["raw_banks"].values()) == {frame + bytes(65 - len(frame))}
    runtime = root.state["_runtime"]
    if source["assessment_index"] == 24:
        assert runtime["pending_words"][18] == 0x4005
        assert runtime["status_bytes"][1:4] == [0x42] * 3
        assert runtime["raw_pending_bits"] == 5
    else:
        assert runtime["pending_words"] == {}
        assert runtime["uart_events"] == []


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("refresh", (0, 1, 2, 255))
def test_raw91_cache_guard_uses_exact_one_only_in_source24(source, refresh):
    root = controller(source)
    old = bytearray(b"X" * 65)
    old[3] = 0x91
    root.state["raw_banks"]["91"] = bytes(old)
    root.state["_runtime"]["raw91_refresh"] = refresh
    fresh = bytes.fromhex("7e7e03910708")
    command(root, hex91=encoded(fresh))
    actual = root.state["raw_banks"]["91"]
    if source["assessment_index"] == 24 and refresh == 1:
        assert actual == fresh + bytes(65 - len(fresh))
        assert root.state["_runtime"]["raw91_refresh"] == 0
    else:
        assert actual == bytes(old)


@pytest.mark.parametrize("source", SOURCES)
def test_loose_base64_unknown_characters_and_padding_writes_are_not_strict_decoder(source):
    root = controller(source)
    command(root, hex92="!!!!")
    assert root.state["raw_banks"]["92"][:4] == bytes(4)
    command(root, hex92="Af==")
    assert root.state["raw_banks"]["92"][:3] == b"\x01\xf0\0"
    command(root, hex92=[1234, 9])
    assert root.state["raw_banks"]["92"][:3] == b"\xd7\x6d\xf8"
    assert _native_json_text({"X": 1.5, "Y": 1.0}) == '{"X":1.500000,"Y":1}'
    command(root, hex92={"X": 1.5})


@pytest.mark.parametrize("source", SOURCES)
def test_raw_clock_frequency_city_datacurve_and_shared_scratch_are_finite_local_transforms(source):
    root = controller(source)
    clock = b"2024-02-03 04:05:06"
    b_frame = b"~~" + bytes((len(clock) - 3, 0x6b)) + clock
    c_frame = bytes.fromhex("7e7e046c2a55")
    city = b"Boston"
    d_frame = b"~~" + bytes((len(city) + 2, 0x6d)) + city
    e_frame = bytearray(22)
    e_frame[:7] = bytes.fromhex("7e7e146e010107")
    e_frame[11:21] = bytes.fromhex("00010002000300040005")
    command(root, hex6B=encoded(b_frame), hex6C=encoded(c_frame),
            hex6D=encoded(d_frame), hex6E=encoded(e_frame))
    runtime = root.state["_runtime"]
    assert runtime["clock_fields"] == [2024, 2, 3, 4, 5, 6]
    assert runtime["clock_timezone"] == 0 and runtime["uart_events"] == [0x82]
    assert runtime["frequency"] == 42 and runtime["pending_words"][8] == 0x405a
    assert runtime["city"] == "Boston" and len(runtime["persist"]["city_name"]) == 50
    assert runtime["data_curve"]["words27c_284"] == [1, 2, 3, 4, 5]
    assert runtime["data_curve"]["records"] == []
    assert runtime["pending_words"][28 if source["assessment_index"] == 24 else 20] == 0x4007
    # A null D field does NOT clear the C Base64 text. Native D decodes C again.
    c_frame = b"~~\x07lAXYZ12"
    command(root, hex6C=encoded(c_frame), hex6D=None)
    assert root.state["_runtime"]["city"] == "AXYZ1"


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("object_mode", (False, True))
def test_both_fragment_wire_shapes_share_native_widths_masks_and_original16_cache(source, object_mode):
    root = controller(source)
    if object_mode:
        root.state["_runtime"]["sdk_version"] = "V3.4.M"
    fragment = [FIXTURE["fragment_object"] if object_mode else FIXTURE["fragment_legacy"]]
    command(root, fragment=fragment)
    assert root.state["raw_banks"]["91"][4] == 5
    cached = root.state["fragment_initializers"][0]
    assert cached[:3] == b"\x91\x01\x0f"
    assert int.from_bytes(cached[4:8], "little") == 5
    assert int.from_bytes(cached[8:12], "little") == 0x12345678
    runtime = root.state["_runtime"]
    assert runtime["report_requests"] == 1
    if source["normal_fragment_mask"]:
        assert runtime["uart_events"] == [0x91]
        assert runtime["pending_words"][10] == 0x4008
    else:
        assert runtime["uart_events"] == [] and runtime["pending_words"] == {}


@pytest.mark.parametrize("source", SOURCES)
def test_init_cache_compares_shifted_workarea_but_copies_original_fragment(source):
    root = controller(source)
    root.state["fragment_initializers"] = [b"\x93\x09\x09" + bytes(13)] * 5
    root.state["fragment_initializers"][1] = b"\x91\x01\xff" + bytes(13)
    work = bytearray(24)
    work[16:19] = b"\x91\x01\xff"
    command(root, hex6C=encoded(work), fragment=[[0x92, 2, 0xf0, 5, 7]])
    assert root.state["fragment_initializers"][1][:3] == b"\x92\x02\xf0"
    assert root.state["fragment_initializers"][0][:3] == b"\x93\x09\x09"
    assert root.state["raw_banks"]["92"][5] == 0x50


@pytest.mark.parametrize("source", SOURCES)
def test_object_fragment_missing_fields_reuse_scratch_and_legacy_reserved_width_is_source_specific(source):
    root = controller(source)
    root.state["_runtime"]["sdk_version"] = "V3.4.M"
    command(root, fragment=[{"cmd_type": 0x91, "byte": 0, "mask": 0xff, "value": 3},
                            {"byte": 1}])
    assert root.state["raw_banks"]["91"][3:5] == b"\x03\x03"
    root.state["_runtime"]["sdk_version"] = "V3.5.M"
    command(root, fragment=[[0x82, 3, 0x60, 0x12345678]])
    expected = 0x78 if source["reserved82_width"] == 8 else 0x12345678
    assert root.state["_runtime"]["reserved82"] == expected
    assert root.state["_runtime"]["uart_events"][-1] == 0x82


def test_source24_extra_legacy_prepass_is_distinct_from_normal_patch_and_precedes_explicit91():
    root = controller(24)
    reference = bytearray(65)
    reference[3] = 0xa0
    root.state["legacy_reference_readout"] = bytes(reference)
    fragment = [[0x91, 1, 0, 0, 0, [0, 0xf0, 0, 0xf0]]]
    command(root, fragment=fragment)
    assert root.state["raw_banks"]["91"][3] == 0xa0
    root.state["_runtime"]["raw91_refresh"] = 1
    command(root, fragment=fragment, hex91=encoded(bytes.fromhex("7e7e03910102")))
    assert root.state["raw_banks"]["91"][3] == 0x91


@pytest.mark.parametrize("source", SOURCES)
def test_scenes_have_exact_native_stride_flash_gate_and_no_automatic_effective_status(source):
    root = controller(source)
    _, ack = command(root, sceneId=3, operType=1, sence_enable=1)
    if source["assessment_index"] == 24:
        assert ack["code"] == 501 and scene_id(root, 0) == 0xffffffff
        root.state["_runtime"]["gnet_id"] = 1
    command(root, sceneId=3, operType=1, sence_enable=1,
            hex91=encoded(b"abcdef"), fragment=[[0x92, 0, 0xff, 7]])
    assert scene_id(root, 0) == 3
    record = root.state["scene_flash"][0]
    assert record[:6] == b"abcdef"
    assert record[source["scene_frame_bytes"] + 3] == 7
    assert root.state["_runtime"]["activity"] == 0
    assert root.state["_runtime"]["flash_writes"][-1] == {
        "offset": source["scene_flash_offset"], "erase_bytes": 4096,
        "write_bytes": source["scene_stride"] * 20}
    assert root.state["raw_banks"]["91"] == bytes(65)
    assert send(root, {"t": "status", "cols": ["sceneId"]}) == []


@pytest.mark.parametrize("source", SOURCES)
def test_scene1_special_creation_fallback_scene2_and_source24_enable_gate(source):
    root = controller(source)
    root.state["_runtime"]["gnet_id"] = 1
    command(root, sceneId=3, operType=1)
    if source["assessment_index"] == 24:
        assert scene_id(root, 0) == 0xffffffff
    else:
        assert scene_id(root, 0) == 3
    root = controller(source)
    root.state["_runtime"]["gnet_id"] = 1
    command(root, sceneId=1, operType=1, fragment=[[0x91, 0, 0xff, 0]])
    assert [scene_id(root, i) for i in range(2)] == [1, 2]
    assert root.state["scene_flash"][0][3] == 0
    assert root.state["scene_flash"][1][3] == 1
    before = deepcopy(root.state)
    command(root, sceneId=1, operType=1, hex91=encoded(b"xxxxxx"))
    if source["assessment_index"] == 24:
        assert root.state == before
    else:
        assert root.state["scene_flash"][0][:6] == b"xxxxxx"


@pytest.mark.parametrize("source", SOURCES)
def test_full_scene_table_and_delete_all_duplicate_ids_keep_native_error_branches(source):
    root = controller(source)
    root.state["_runtime"]["gnet_id"] = 1
    for index in range(20):
        set_scene_id(root, index, 100 + index)
    _, ack = command(root, sceneId=9, operType=1, sence_enable=1)
    assert ack["r"] == 200 and ack["code"] == 501
    _, special = command(root, sceneId=1, operType=1)
    assert ("code" not in special) if source["assessment_index"] == 24 else special["code"] == 501
    set_scene_id(root, 0, 7)
    set_scene_id(root, 1, 7)
    count = len(root.state["_runtime"]["flash_writes"])
    command(root, sceneId=7, operType=2)
    assert root.state["scene_flash"][:2] == [bytes(source["scene_stride"])] * 2
    assert len(root.state["_runtime"]["flash_writes"]) == count + 2


@pytest.mark.parametrize("source", SOURCES)
def test_ubindok_immediate_packets_actual_host_cache_counter_and_no_invented_uid(source):
    root = controller(source)
    host = "0200000000a5"
    replies = send(root, {"t": "UBindok", "mac": host, "roomId": 258})
    decoded = [response(reply) for reply in replies]
    assert [inner["t"] for _, inner in decoded] == source["ubind_immediate_packets"]
    assert [outer["msgId"] for outer, _ in decoded] == list(range(len(decoded)))
    assert all("uid" not in outer and outer["cid"] == MAC and outer["tcid"] == host for outer, _ in decoded)
    assert root.state["_runtime"]["activity"] == source["ubind_activity_increments"]
    assert root.state["_runtime"]["heartbeat_period_ms"] == 60000
    assert root.state["_runtime"]["heartbeat_timer"]["interval"] == 61000
    outer, ack = command(root)
    assert outer["tcid"] == host and ack["mac"] == MAC
    assert outer["msgId"] == source["ubind_activity_increments"] + 1


def test_source24_hostmanaged_zero_early_path_has_no_online_activity_or_network_reinit():
    root = controller(24)
    root.state["_runtime"]["gnet_id"] = 1
    assert send(root, {"t": "UBindok", "hostManaged": 0, "roomId": 2}) == []
    runtime = root.state["_runtime"]
    assert runtime["online"] == runtime["activity"] == runtime["network_reinitializations"] == 0
    assert runtime["sdk_version"] == "V3.5.M" and runtime["persist"]["GREE_FLASH"] == 1
    assert runtime["room_id"] == 2


@pytest.mark.parametrize("source", SOURCES)
def test_reset_prefix_null_and_missing_are_actual_default_parser_branches(source):
    root = controller(source)
    assert send(root, {"t": "reset"}) == []
    assert send(root, {"t": "reset", "mac": "ffffffffffff"}) == []
    assert response(send(root, {"t": "reset", "mac": MAC[:4]})[0])[1] == FIXTURE["ordinary_ack"]
    assert root.state["_runtime"]["reset_flags"] == 2
    assert response(send(root, {"t": "reset", "mac": None})[0])[1] == FIXTURE["ordinary_ack"]


@pytest.mark.parametrize("source", SOURCES)
def test_ret_heartbeat_utm_and_counter_rollover_are_not_blanket_noops(source):
    root = controller(source)
    root.state["_runtime"]["status_bytes"][6] = 9
    assert send(root, {"t": "ret", "r": 456}) == []
    assert root.state["_runtime"]["status_bytes"][6] == (0 if source["assessment_index"] == 24 else 9)
    assert send(root, {"t": "hbok"}, selector=1) == []
    assert root.state["_runtime"]["timer_commands"] == [(1, 0), (3, 0)]
    assert send(root, {"t": "hbok"}, selector=1) == []
    assert root.state["_runtime"]["timer_commands"][-2:] == [(2, 0), (3, 0)]
    assert send(root, {"t": "Utm", "time": "2024-02-03 04:05:06"}) == []
    assert root.state["_runtime"]["clock_timezone"] == 8
    assert root.state["_runtime"]["clock_fields"] == [2024, 2, 3, 4, 5, 6]
    root.state["_runtime"]["activity"] = 65535
    outer, _ = command(root)
    assert outer["msgId"] == 0 and root.state["_runtime"]["activity"] == 0


def test_source24_login_info_and_status_check_have_real_local_transitions_without_fake_ack():
    root = controller(24)
    assert send(root, {"t": "loginInfoRes", "r": 200,
                       "loginInfo": '{"GnetID":258}'}) == []
    runtime = root.state["_runtime"]
    assert runtime["gnet_id"] == 2 and runtime["persist"]["GnetID"] == 2
    assert runtime["login_flag"] == 1 and runtime["network_reinitializations"] == 1
    before = runtime["report_requests"]
    assert send(root, {"t": "statusCheck"}) == []
    assert root.state["_runtime"]["report_requests"] == before + 1
    assert root.state["_runtime"]["status_check"] == 0
    other = controller(35)
    assert send(other, {"t": "loginInfoRes", "r": 200, "loginInfo": "{}"}) == []


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("fields", [
    {"hex91": "A" * 128}, {"hex92": "="},
    {"fragment": [[0x94, 0, 255, 1]]}, {"fragment": [[0x91, 255, 255, 1]]},
    {"fragment": [[0x91, 0]]}, {"hex92": ["pointer-table"]},
])
def test_explicit_unsafe_memory_boundaries_reject_atomically_not_silently_accept(source, fields):
    root = controller(source)
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        command(root, **fields)
    assert root.state == before


@pytest.mark.parametrize("source", SOURCES)
def test_native_server_decoder_group_preserves_source_port_fixed_reply_and_rejects_oversize(source):
    root = controller(source)

    async def scenario():
        server = EmulatorServer([root])
        sent = []
        server.transport = SimpleNamespace(sendto=lambda data, addr: sent.append((data, addr)),
                                           close=lambda: server.connection_lost(None))
        outer = request(root, {"T": "SCAn"}, selector=1, uid=True, cid=["ignored"], tcid={"ignored": True})
        data = json.dumps(outer).encode()
        server.datagram_received(data, ("127.0.0.1", 5001))
        assert len(sent) == 1 and sent[0][1] == ("127.0.0.1", 5000)
        result = json.loads(sent[0][0])
        assert result["uid"] == 1 and result["msgId"] == 1 and result["cid"] == MAC
        before = deepcopy(root.state)
        server.datagram_received(data, ("127.0.0.1", 5000))
        server.datagram_received(data + b" " * 1536, ("127.0.0.1", 5001))
        assert len(sent) == 1 and root.state == before
        server.close()

    asyncio.run(scenario())
