"""Independent source transactions and explicit safe Realtek root policies."""

import base64
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from gree_emulator.__main__ import load_config
from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles import PROFILES
from gree_emulator.profiles.realtek_controller import W05G_FIELDS, W05R_CONTROLS, W05R_FIELDS
from gree_emulator.server import EmulatorServer
from gree_emulator.wire import InvalidPacket, encode_reply


FIXTURES = Path(__file__).parent / "fixtures" / "emulator"
IDS = ("sim-w05r-v2.35", "sim-w05g-v4.3")
GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
RESEARCH = {
    profile_id: json.loads((FIXTURES / f"session-realtek-{slug}_research.json").read_text())
    for profile_id, slug in zip(IDS, ("w05r", "w05g"), strict=True)
}
QUIRKS = {
    profile_id: json.loads((FIXTURES / f"session-realtek-{slug}-quirks_research.json").read_text())
    for profile_id, slug in zip(IDS, ("w05r", "w05g"), strict=True)
}


def device_for(profile_id, mac="020000000001", key=b"0123456789abcdef"):
    profile = PROFILES[profile_id]
    return EmulatedDevice("root", mac, "", profile.mids[0], key, profile,
                          dict(profile.initial_state), room_c=None, ambient_c=None,
                          last_step=1000)


def packet(device, inner=None, *, index=0, key=None, plaintext=None):
    if plaintext is None:
        plaintext = json.dumps(inner, separators=(",", ":")).encode()
    key = key if key is not None else GENERIC_KEY if index else device.key
    ciphertext = AES.new(key, AES.MODE_ECB).encrypt(pad(plaintext, 16))
    return {"t": "pack", "i": index, "uid": 42, "cid": "app", "tcid": device.mac,
            "pack": base64.b64encode(ciphertext).decode()}


def peer_reply(device, reply):
    raw = encode_reply(reply)
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    outer = json.loads(raw)
    ciphertext = base64.b64decode(outer.pop("pack"), validate=True)
    assert len(ciphertext) <= 1024
    assert 4 * ((len(ciphertext) + 2) // 3) + 1 <= 1024
    key = GENERIC_KEY if outer["i"] else device.key
    inner = json.loads(unpad(AES.new(key, AES.MODE_ECB).decrypt(ciphertext), 16))
    assert outer["cid"] == device.mac and outer["tcid"] == ""
    return outer, inner


def exchange(device, inner, **kwargs):
    reply, = device.profile.handler.handle(device, packet(device, inner, **kwargs))
    return peer_reply(device, reply)[1]


def status(device, names):
    return exchange(device, {"t": "status", "mac": device.mac, "cols": names})


def command(device, names, values, **kwargs):
    return exchange(device, {"t": "cmd", "opt": names, "p": values}, **kwargs)


@pytest.mark.parametrize("profile_id", IDS)
def test_native_valid_outer_ciphertext_vectors(profile_id):
    device = device_for(profile_id)
    research = RESEARCH[profile_id]
    for position, vector in enumerate(research["source_vectors"]["vectors"][:3]):
        outer = vector["request_outer"]
        replies = (device.profile.handler.advertise(device, outer) if outer["t"] == "scan"
                   else device.profile.handler.handle(device, outer))
        decoded = [peer_reply(device, reply) for reply in replies]
        assert [inner for _, inner in decoded] == vector["expected_inner"]
        assert [outer["i"] for outer, _ in decoded] == [1 if position < 2 else 0]
        assert [outer["uid"] for outer, _ in decoded] == [0 if position == 0 else 42]
    assert device.state["Pow"] == 0


@pytest.mark.parametrize("profile_id", IDS)
def test_original_native_conflicting_command_is_rejected_atomically(profile_id):
    device = device_for(profile_id)
    vector = RESEARCH[profile_id]["source_vectors"]["vectors"][3]
    outer = vector["request_outer"]
    plaintext = unpad(AES.new(device.key, AES.MODE_ECB).decrypt(
        base64.b64decode(outer["pack"], validate=True)), 16)
    inner = json.loads(plaintext)
    assert outer["tcid"] == device.mac
    assert inner["t"] == "cmd" and inner["mac"] == "020000000002"
    before = dict(device.state)
    with pytest.raises(InvalidPacket, match="conflicting Realtek inner identity"):
        device.profile.handler.handle(device, outer)
    assert device.state == before and device.last_step == 1000


@pytest.mark.parametrize("profile_id", IDS)
def test_native_wrong_target_and_key_vectors_are_rejected_atomically(profile_id):
    device = device_for(profile_id)
    for vector in RESEARCH[profile_id]["source_vectors"]["vectors"][4:]:
        before = dict(device.state)
        with pytest.raises(InvalidPacket):
            device.profile.handler.handle(device, vector["request_outer"])
        assert device.state == before and device.last_step == 1000


def test_w05g_identity_adapted_command_preserves_native_ack_and_empty_getters():
    device = device_for(IDS[1])
    vectors = RESEARCH[IDS[1]]["source_vectors"]["vectors"]
    request = {"t": "cmd", "mac": device.mac, "opt": ["Pow", "Pow"], "p": [7, 65537]}
    # Only the conflicting identity is adapted; the native ACK/cache path is unchanged.
    assert exchange(device, request) == vectors[3]["expected_inner"][0]
    assert device.state["Pow"] == 1
    assert status(device, ["Pow", "hid", "Pow"]) == vectors[2]["expected_inner"][0]


def test_all_w05r_independent_bounded_valid_element_vectors():
    for vector in RESEARCH[IDS[0]]["bounded_translation"]["vectors"]:
        device = device_for(IDS[0])
        device.state.update(vector["cache_before"])
        assert exchange(device, vector["request"]) == vector["expected"]
        fresh = vector["next_status"]
        assert status(device, fresh["cols"]) == fresh


def test_w05g_exact_empty_platform_callbacks_including_irregular_shapes():
    device = device_for(IDS[1])
    catalog = RESEARCH[IDS[1]]["contract"]["isolated_status_from_zero_synthetic_platform"]
    for name, expected in catalog.items():
        result = status(device, [name])
        assert result["cols"] == expected["cols"]
        assert result["dat"] == (["2026-01-01 00:00:00"] if name == "time" else expected["dat"])
    command(device, ["Pow", "Pow"], [7, 65537])
    assert status(device, ["Pow", "Unknown", "Pow"])["cols"] == ["Pow", "Pow"]
    assert status(device, ["Pow", "Unknown", "Pow"])["dat"] == []
    assert device.state["Pow"] == 1


@pytest.mark.parametrize("profile_id", IDS)
def test_duplicate_signed32_ack_and_fresh_status_distinction(profile_id):
    device = device_for(profile_id)
    result = command(device, ["Pow", "Unknown", "Pow", "Pow"], [7, 99, 65537, -1])
    assert result["opt"] == ["Pow", "Pow", "Pow"]
    assert result["p"] == ([7, 1, 65535] if profile_id == IDS[0] else [7, 65537, -1])
    assert "val" not in result
    result = status(device, ["Pow", "Unknown", "hid", "Pow"])
    assert result["cols"] == ["Pow", "hid", "Pow"]
    assert result["dat"] == ([65535, device.profile.hid, 65535] if profile_id == IDS[0]
                             else [device.profile.hid])
    assert command(device, [], [])["p"] == []
    assert status(device, [])["dat"] == []


@pytest.mark.parametrize("profile_id", IDS)
def test_source_key_selector_is_not_an_operation_permission(profile_id):
    device = device_for(profile_id)
    for index in (0, 1, 2, -1, 256):
        # Source dispatch selects key by zero/nonzero, but reply key is operation-derived.
        assert exchange(device, {"t": "bind", "mac": device.mac}, index=index)["key"] == device.key.decode()
        assert command(device, ["Pow"], [65537], index=index)["p"] == ([1] if profile_id == IDS[0] else [65537])
        reply = exchange(device, {"t": "status", "mac": device.mac, "cols": ["hid"]}, index=index)
        assert reply["dat"] == [device.profile.hid]


@pytest.mark.parametrize("profile_id", IDS)
@pytest.mark.parametrize("changes", [
    {"opt": ["Pow", "Pow"], "p": [1]}, {"opt": ["Pow"], "p": [1, 2]},
    {"opt": "Pow", "p": [1]}, {"opt": ["Pow"], "p": "1"},
    {"opt": ["Pow", "Pow"], "p": [1, True]},
    {"opt": ["Pow", "Pow"], "p": [1, 1.5]},
    {"opt": ["Pow", "Pow"], "p": [1, 1 << 31]},
    {"opt": ["Pow", "Pow"], "p": [1, -(1 << 31) - 1]},
    {"opt": ["Pow", None], "p": [1, 2]}, {"opt": ["Pow", ""], "p": [1, 2]},
    {"opt": ["Pow", "Pow\0ignored"], "p": [1, 2]},
    {"opt": ["Pow"] * 129, "p": [1] * 129},
    {"opt": ["Pow"] * 75, "p": [65535] * 75},
])
def test_invalid_and_reply_scratch_overflow_batches_are_atomic(profile_id, changes):
    device = device_for(profile_id)
    before = dict(device.state)
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "cmd", **changes})
    assert device.state == before and device.last_step == 1000


def test_unknown_and_unrelated_ac_names_remain_omitted():
    for profile_id in IDS:
        device = device_for(profile_id)
        assert command(device, ["Unknown"], [1])["opt"] == []
        assert status(device, ["TemSen", "BuzzerCtrl"])["cols"] == []
        assert device.room_c is None


@pytest.mark.parametrize("profile_id", IDS)
def test_wrong_identity_keys_and_invalid_inner_json_are_atomic(profile_id):
    device = device_for(profile_id)
    requests = []
    for kind in ("bind", "status", "cmd"):
        for selector in ("mac", "sub"):
            inner = {"t": kind, "mac": device.mac, "cols": ["Pow"], "opt": ["Pow"], "p": [1],
                     selector: "020000000002"}
            requests.append(packet(device, inner))
    valid = {"t": "cmd", "opt": ["Pow"], "p": [1]}
    requests.extend([
        {**packet(device, valid), "tcid": "020000000002"},
        packet(device, valid, key=b"fedcba9876543210"),
        packet(device, plaintext=b'{"t":"cmd","t":"status"}'),
        packet(device, plaintext=b'{"t":"cmd","opt":["Pow"],"p":[NaN]}'),
        packet(device, plaintext=b'{"t":"cmd","opt":["Pow"],"p":[1]}\x00'),
        packet(device, plaintext=b'[]'),
        packet(device, {"t": None}),
        packet(device, {"t": ["cmd"]}),
        {**packet(device, valid), "i": True},
        {**packet(device, valid), "uid": None},
        {**packet(device, valid), "pack": "not-base64"},
    ])
    for outer in requests:
        before = dict(device.state)
        with pytest.raises(InvalidPacket):
            device.profile.handler.handle(device, outer)
        assert device.state == before and device.last_step == 1000


@pytest.mark.parametrize("profile_id", IDS)
@pytest.mark.parametrize("cols", ["Pow", [None], [""], ["Pow\0ignored"], ["Pow"] * 129, ["hid"] * 25])
def test_invalid_and_oversize_getters_do_not_mutate(profile_id, cols):
    device = device_for(profile_id)
    before = dict(device.state)
    with pytest.raises(InvalidPacket):
        status(device, cols)
    assert device.state == before


@pytest.mark.parametrize("profile_id", IDS)
def test_seeded_independent_sensorless_state_and_rebind(profile_id):
    records = [{"id": name, "profile": profile_id, "mid": PROFILES[profile_id].mids[0]}
               for name in ("first", "second")]
    config = {"seed": "realtek", "devices": records}
    first, second = load_config(config)[2]
    restarted, = load_config({"seed": "realtek", "devices": records[:1]})[2]
    assert first.key == restarted.key and first.key != second.key
    assert first.mac == restarted.mac and first.mac != second.mac
    assert first.children == second.children == []
    assert first.room_c is first.ambient_c is None
    assert first.profile.max_request_bytes == 1024 and first.profile.max_children == 0
    assert first.profile.handler.thermal_target(first) is None
    assert first.profile.hid == RESEARCH[profile_id]["contract"]["hid"]
    assert first.profile.source_sha256 == RESEARCH[profile_id]["contract"]["source_sha256"]
    command(first, ["Pow"], [-1])
    assert second.state["Pow"] == restarted.state["Pow"] == 0
    key = first.key
    for _ in range(2):
        assert exchange(first, {"t": "bind", "mac": first.mac}, index=1)["key"] == key.decode()
        assert first.state["Pow"] == 65535 and first.key == key
    before = dict(first.state)
    first.advance(first.last_step + 100)
    assert first.state == before
    assert first.room_c is first.ambient_c is None
    for field, value in (("TemSen", 50), ("Pow", -1), ("Pow", 65536), ("Pow", True),
                         ("_uid", 1), ("hid", "wrong")):
        with pytest.raises(ValueError):
            load_config({"devices": [{**records[0], "state": {field: value}}]})
    for field in ("room_c", "ambient_c"):
        with pytest.raises(ValueError):
            load_config({"devices": [{**records[0], field: 26}]})


@pytest.mark.parametrize("profile_id", IDS)
async def test_original_receive_size_checked_before_decryption_and_mutation(profile_id):
    device = device_for(profile_id)
    server = EmulatorServer([device])
    sent = []
    server.transport = SimpleNamespace(sendto=lambda data, addr: sent.append(data))
    before = dict(device.state)
    raw = json.dumps(packet(device, {"t": "cmd", "opt": ["Pow"], "p": [1]})).encode()
    server.datagram_received(raw + b" " * (1025 - len(raw)), ("127.0.0.1", 7000))
    server.datagram_received(b'{"t":"scan"}' + b" " * 1013, ("127.0.0.1", 7000))
    assert sent == [] and device.state == before
    server.datagram_received(raw + b" " * (1024 - len(raw)), ("127.0.0.1", 7000))
    assert len(sent) == 1 and device.state["Pow"] == 1
    server.connection_lost(None)


@pytest.mark.parametrize("profile_id", IDS)
def test_complete_independent_getter_catalog(profile_id):
    fixture = QUIRKS[profile_id]
    namespace = W05G_FIELDS if profile_id == IDS[1] else W05R_FIELDS
    assert list(namespace) == fixture["namespace"]
    assert len(namespace) == (60 if profile_id == IDS[1] else 36)
    assert len(set(namespace)) == (44 if profile_id == IDS[1] else 36)
    for vector in fixture["native_status"]:
        device = device_for(profile_id)
        result = status(device, [vector["name"]])
        if vector["name"] == "time":
            assert result["dat"] == ["2026-01-01 00:00:00"]
        elif vector["name"] == "mac" and profile_id == IDS[1]:
            assert result["cols"] == vector["cols"]
            assert result["dat"] == fixture["synthetic_identity_readout"]["mac"]
        else:
            assert result["cols"] == vector["cols"]
            assert result["dat"] == vector["dat"]


@pytest.mark.parametrize("profile_id", IDS)
def test_complete_independent_numeric_callbacks_and_fresh_cache(profile_id):
    for vector in QUIRKS[profile_id]["numeric"]:
        device = device_for(profile_id)
        name, value = vector["name"], vector["value"]
        if profile_id == IDS[0] and (name == "ConBtnName" or name == "DelButton" and value == -1):
            before = deepcopy(device.state)
            with pytest.raises(InvalidPacket):
                command(device, [name], [value])
            assert device.state == before
            continue
        response = command(device, [name], [value])
        assert response["opt"] == [name]
        expected = ["2026-01-01 00:00:00"] if name == "time" and profile_id == IDS[0] else vector["p"]
        if name == "DelButton" and profile_id == IDS[0]:
            # Original flash read stopped before ACK; sentinel is explicit model input.
            expected = [26]
        effective_cache = vector["cache"]
        if name == "Electnumzero" and profile_id == IDS[0]:
            completion = QUIRKS[profile_id]["synthetic_numeric_completion"][name]
            expected = completion["ack"]
            if value & 65535 == completion["clear_when_cached"]:
                effective_cache = completion["effective_cache"]
        assert response["p"] == expected
        if name in device.state:
            assert device.state[name] == effective_cache
        fresh = status(device, [name])
        if profile_id == IDS[0] and name in W05R_CONTROLS:
            assert fresh["dat"] == [effective_cache]
        elif profile_id == IDS[1]:
            native = next(row for row in QUIRKS[profile_id]["native_status"] if row["name"] == name)
            expected = ["2026-01-01 00:00:00"] if name == "time" else [2] if name == "Mesh" else native["dat"]
            if name == "mac":
                expected = QUIRKS[profile_id]["synthetic_identity_readout"]["mac"]
            assert fresh["dat"] == expected


def test_r_button_registry_cardinality_occupied_delete_and_numeric_name_guard():
    device = device_for(IDS[0])
    result = command(device, ["ConBtnNum", "AddButton", "ConBtnName"], [1, 1, "first"])
    assert result["opt"] == ["ConBtnNum", "AddButton", "ConBtnName"]
    assert result["p"] == [1, 26, 1, "first"]
    assert status(device, ["RefBtnList", "ConBtnName", "RefBtnList"])["dat"] == [
        [1], ["first"], 0, [1], ["first"]]
    assert command(device, ["ConBtnName"], ["occupied"])["p"] == [26, "occupied"]
    assert status(device, ["RefBtnList"])["dat"] == [[1], ["first"]]
    for value in (1, None, [], "x" * 16, "é" * 8, "bad\0name"):
        before = deepcopy(device.state)
        with pytest.raises(InvalidPacket):
            command(device, ["Pow", "ConBtnName"], [7, value])
        assert device.state == before
    runtime = device.state["_runtime"]
    runtime["flash_word"] = 0
    assert command(device, ["DelButton"], [1])["p"] == [27]
    assert status(device, ["RefBtnList"])["dat"] == [[1], ["first"]]
    device.state["_runtime"]["flash_word"] = 0xffffffff
    assert command(device, ["DelButton"], [1])["p"] == [26]
    assert status(device, ["RefBtnList"])["dat"] == [[], []]
    for name, value in (("DelButton", 0), ("DelButton", 26)):
        before = deepcopy(device.state)
        with pytest.raises(InvalidPacket):
            command(device, ["Pow", name], [1, value])
        assert device.state == before


def test_r_source_actions_and_explicit_virtual_ir_timer_energy_policy():
    device = device_for(IDS[0])
    assert command(device, ["Studied", "AddButton", "Studied"], [2, 4, 2])["p"] == [2, 26, 2]
    assert status(device, ["Studied", "AddButton"])["dat"] == [0, 4]
    assert device.state["_runtime"]["learning"] == 2
    assert device.state["_runtime"]["learn_pending"] is True
    assert command(device, ["SendButton", "Pow"], [-1, 7])["p"] == [65535, 7]
    assert device.state["_runtime"]["send_pending"] is True
    command(device, ["ProTimeReminder", "ProTimeLen", "ProTimePow"], [19, 3, 1])
    assert status(device, ["ProTimeReminder", "ProTimeLen", "ProTimePow"])["dat"] == [0, 3, 1]
    assert device.state["_runtime"]["timer"] == {"requested_at": 1000, "duration": 3, "power": 1}
    device.advance(2000)
    # No unqualified timer expiry/physical IR is inferred from a timer receipt.
    assert status(device, ["Pow", "ProTimePow"])["dat"] == [7, 1]
    command(device, ["ProTimePow"], [0])
    assert device.state["_runtime"]["timer"] is None
    device.state["_runtime"]["energy"] = 12345
    assert command(device, ["Electnumzero"], [7])["p"] == [0]
    assert status(device, ["Electnumzero"])["dat"] == [7]
    assert device.state["_runtime"]["energy"] == 12345
    assert command(device, ["Electnumzero"], [1])["p"] == [0]
    assert status(device, ["Electnumzero"])["dat"] == [0]
    assert device.state["_runtime"]["energy"] == 0
    assert command(device, ["RefBtnList"], [-1])["p"] == [65535]
    assert status(device, ["RefBtnList"])["dat"] == [[], []]


@pytest.mark.parametrize("profile_id", IDS)
def test_clock_backing_elapsed_numeric_scratch_and_isolation(profile_id):
    first, second = device_for(profile_id), device_for(profile_id, "020000000002")
    assert status(first, ["time"])["dat"] == ["2026-01-01 00:00:00"]
    assert status(second, ["time"])["dat"] == ["2026-01-01 00:00:00"]
    first.advance(1061.9)
    assert status(first, ["time"])["dat"] == ["2026-01-01 00:01:01"]
    assert status(second, ["time"])["dat"] == ["2026-01-01 00:00:00"]
    result = command(first, ["time"], [65537])
    assert result["p"] == ([65537] if profile_id == IDS[1] else ["2026-01-01 00:01:01"])
    assert status(first, ["time"])["dat"] == ["2026-01-01 00:01:01"]
    if profile_id == IDS[1]:
        assert command(first, ["time"], ["2024-02-29 23:59:59"])["p"] == ["2024-02-29 23:59:59"]
        first.advance(1063)
        assert status(first, ["time"])["dat"] == ["2024-03-01 00:00:00"]
        for value in ("2025-02-29 00:00:00", "2026-1-1 00:00:00", "bad"):
            before = deepcopy(first.state)
            with pytest.raises(InvalidPacket):
                command(first, ["host", "time"], ["changed", value])
            assert first.state == before
    else:
        # R string time only invokes the unchanged calendar getter.
        assert command(first, ["time"], ["2024-02-29 23:59:59"])["p"] == ["2026-01-01 00:01:01"]


def test_g_strings_are_independent_of_numeric_scratch_and_invalid_lengths_retain():
    device = device_for(IDS[1])
    assert command(device, ["host", "lat", "lon", "Meshid"], [
        "host.local", "12.34", "-123.45", "ABCD"])["p"] == ["host.local", "12.34", "-123.45", "abcd"]
    assert command(device, ["host", "lat", "lon"], ["", "a" * 11, ""])["p"] == [
        "host.local", "12.34", "-123.45"]
    assert command(device, ["host", "lat", "Meshid"], [-1, 65537, 7])["p"] == [-1, 65537, 7]
    assert status(device, ["host", "lat", "Meshid"])["dat"] == ["host.local", "12.34", "abcd"]
    assert command(device, ["BleLink", "Mesh"], ["AABBCCDDEEFF", "010203040506"])["p"] == [
        "aabbccddeeff", "010203040506"]
    # Only original opt[0] selects the deferred action, using the LAST parsed
    # address in the batch; source readout aliases change, not physical pairing.
    assert status(device, ["BleLink", "Mesh", "BleStatus", "BleKey"])["dat"] == [
        "010203040506", 0, 253, "", 253]
    assert command(device, ["Unbind"], ["AABBCCDDEEFF"])["p"] == ["aabbccddeeff"]
    assert status(device, ["Unbind"])["dat"] == ["aabbccddeeff"]
    for name in ("BleLink", "Mesh", "Unbind", "Meshid"):
        before = deepcopy(device.state)
        with pytest.raises(InvalidPacket):
            command(device, ["Pow", name], [7, "not-hex"])
        assert device.state == before
    assert command(device, ["BleKey", "NoD", "Pow"], ["not-a-key", {}, None]) == {
        "t": "res", "mac": device.mac, "r": 200, "opt": ["BleKey", "NoD", "Pow"], "p": ["", 253]}


def test_g_unbind_descriptor_flag_does_not_invent_offline_transition():
    device = device_for(IDS[1])
    status(device, [])
    device.state["_runtime"]["children"] = {"aabbccddeeff": True}
    device.state["_runtime"]["descriptor_flags"] = {"aabbccddeeff": 255}
    assert command(device, ["Unbind"], ["AABBCCDDEEFF"])["p"] == ["aabbccddeeff"]
    assert status(device, ["Subcount", "SubOnline"])["dat"] == [1, '["aabbccddeeff"]']
    assert device.state["_runtime"]["descriptor_flags"] == {"aabbccddeeff": 0}
    assert device.children == []  # Synthetic descriptor readout, not attachable BLE children.


def test_g_scene_capacity_truthy_failure_and_match_only_control():
    device = device_for(IDS[1])
    for scene in range(1, 31):
        assert command(device, ["Sceneid"], [str(scene)])["p"] == [scene]
    assert command(device, ["Sceneid"], ["65537"])["p"] == [1]
    assert command(device, ["Sceneid"], ["31"])["p"] == [31]
    runtime = device.state["_runtime"]
    assert runtime["registry"] == list(range(1, 31))
    assert runtime["scene_result"] == -1 and runtime["selected"] == 1
    assert status(device, ["Sceneid", "Scenecontrol", "Scene"])["dat"] == [31, 31, "OK"]
    assert command(device, ["Scenecontrol"], ["65535"])["p"] == [65535]
    assert device.state["_runtime"]["control_header"] == [0, 0, 0, 0]
    for value in ("-1", "1x", "2147483648", ""):
        before = deepcopy(device.state)
        with pytest.raises(InvalidPacket):
            command(device, ["Sceneid"], [value])
        assert device.state == before


def test_g_coupled_ack_conversion_dedup_and_source_scene_offsets():
    device = device_for(IDS[1])
    command(device, ["Sceneid"], ["1"])
    assert command(device, ["Onoff", "Scenecontrol"], ['["01021af","01021af"]', "1"])["p"] == [1, "OK"]
    runtime = device.state["_runtime"]
    assert runtime["onoff_queue"][:3] == [1, 1, 0]
    assert bytes(runtime["onoff_queue"][3:23]).hex() == "aaaa000000000000000820010102010a0f000000"
    assert command(device, ["Onoff", "Scenecontrol"], ['["01021AF"]', "1"])["opt"] == [
        "Scenecontrol", "Onoff"]
    assert bytes(device.state["_runtime"]["onoff_queue"][23:43]).hex() == (
        "aaaa00000000000000082001010201eaef000000")
    assert device.state["_runtime"]["control_header"][0] == 1  # Duplicate companion suppressed.
    assert command(device, ["Scene"], ['["01021af"]'])["p"] == ["OK"]
    runtime = device.state["_runtime"]
    assert runtime["scene_queue"][:3] == [1, 1, 0]
    assert bytes(runtime["scene_queue"][12:20]).hex() == "0821010102010a0f"
    assert runtime["selected"] == 0 and runtime["pending"][18:20] == [3, 0x40]
    assert runtime["control_header"][0] == 2
    assert bytes(runtime["control_frames"][:15]).hex() == "aaaaffff0000000003060104340201"
    assert bytes(runtime["control_frames"][250:265]).hex() == "aaaaffff0000000003060104340301"


def test_g_separate_queue_capacities_overwrite_drop_and_first_option_selection():
    device = device_for(IDS[1])
    command(device, ["Sceneid"], ["1"])
    for value in range(31):
        command(device, ["Onoff", "Scenecontrol"], [json.dumps(["0102" + format(value, "03x")]), "1"])
    assert device.state["_runtime"]["onoff_queue"][:3] == [30, 1, 1]
    assert device.state["_runtime"]["control_header"][0] == 1
    for _ in range(6):
        command(device, ["Sceneid"], ["1"])
        command(device, ["Scene"], ['["01021af"]'])
    assert device.state["_runtime"]["scene_queue"][:3] == [5, 1, 1]
    other = device_for(IDS[1])
    for value in range(1, 7):
        command(other, ["Sceneid"], [str(value)])
    for value in range(1, 7):
        command(other, ["Scenecontrol"], [str(value)])
    assert other.state["_runtime"]["control_header"][0] == 5
    for value in range(11):
        command(other, ["Pow", "Lpn"], [value, 7])
    runtime = other.state["_runtime"]
    assert runtime["power_queue"][:3] == [10, 0, 0]
    assert runtime["power_queue"][3:7] == [0, 7, 0, 0]
    assert runtime["pending"][26] == 0x45 and other.state["Pow"] == 10
    empty = device_for(IDS[1])
    command(empty, ["Unknown", "Mesh"], [1, 2])
    assert empty.state["_runtime"]["scene_queue"][:3] == [0, 0, 0]
    for name, kind, length in (("Mesh", 4, 8), ("Meshota", 11, 2), ("Reota", 12, 2)):
        fresh = device_for(IDS[1])
        assert command(fresh, [name], [65537])["p"] == [65537]
        assert fresh.state["_runtime"]["scene_queue"][:3] == [1, 1, 0]
        assert fresh.state["_runtime"]["scene_queue"][12:14] == [length, kind]


@pytest.mark.parametrize("names,values", [
    (["Onoff"], ['["01021af"]']),
    (["Onoff", "Pow"], ['["01021af"]', "1"]),
    (["Onoff", "Scenecontrol"], ['["01021af"]', 1]),
    (["Onoff", "Scenecontrol"], ['["short"]', "1"]),
    (["Scene"], ["[]junk"]),
    (["Scene"], ["{}"]),
    (["Scene"], [json.dumps(["01021af"] * 38)]),
    (["Scene"], ['["01021ag"]']),
])
def test_g_scene_errors_reject_companion_and_prior_mutations_atomically(names, values):
    device = device_for(IDS[1])
    command(device, ["Sceneid"], ["1"])
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        command(device, ["host", *names], ["changed", *values])
    assert device.state == before


def test_g_empty_scene_result_and_empty_array_are_not_physical_success():
    device = device_for(IDS[1])
    assert command(device, ["Scene"], ["[]"])["p"] == ["FAIL"]
    runtime = device.state["_runtime"]
    assert runtime["scene_queue"][:3] == [0, 0, 0]
    assert runtime["scene_queue"][12:15] == [3, 0x21, 0]
    assert runtime["pending"][18:20] == [3, 0x40]
    command(device, ["Sceneid"], ["1"])
    assert command(device, ["Scene"], ["[]"])["p"] == ["OK"]
    assert device.state["_runtime"]["scene_queue"][:3] == [1, 1, 0]


@pytest.mark.parametrize("profile_id", IDS)
def test_full_reply_preflight_preserves_runtime_clock_queues_and_restart(profile_id):
    device = device_for(profile_id)
    status(device, ["time"])
    before = deepcopy(device.state)
    names = ["host"] if profile_id == IDS[1] else ["Pow"]
    values = ["changed"] if profile_id == IDS[1] else [7]
    with pytest.raises(InvalidPacket):
        command(device, [*names, *(["hid"] * 25)], [*values, *([""] * 25)])
    assert device.state == before
    with pytest.raises(InvalidPacket):
        status(device, ["hid"] * 25)
    assert device.state == before
    restarted = device_for(profile_id)
    assert status(restarted, ["time"])["dat"] == ["2026-01-01 00:00:00"]
    if profile_id == IDS[1]:
        command(device, ["Sceneid"], ["1"])
        assert status(restarted, ["Sceneid", "Scene"])["dat"] == [0, "FAIL"]
    else:
        command(device, ["ConBtnNum", "AddButton", "ConBtnName"], [1, 1, "first"])
        assert status(restarted, ["RefBtnList"])["dat"] == [[], []]
