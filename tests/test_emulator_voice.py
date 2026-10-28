"""Independent native voice vectors and explicit sensorless-controller policies."""

import asyncio
import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from gree_emulator.__main__ import load_config
from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles import PROFILES
from gree_emulator.profiles.voice import CACHE_FIELDS, CONTROLS, SELECTORS
from gree_emulator.server import EmulatorServer
from gree_emulator.wire import InvalidPacket, encode_reply


FIXTURES = Path(__file__).parent / "fixtures" / "emulator"
VECTOR = json.loads((FIXTURES / "session-voice.json").read_text())
RESEARCH = json.loads((FIXTURES / "session-voice_research.json").read_text())
QUIRKS = json.loads((FIXTURES / "session-voice-quirks_research.json").read_text())
PROFILE = PROFILES["sim-is-t3bbw03-v3.62"]
GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"


def device_for(mac=VECTOR["mac"], key=VECTOR["key"].encode()):
    return EmulatedDevice("voice", mac, "", "80222", key, PROFILE,
                          dict(PROFILE.initial_state), room_c=None, ambient_c=None,
                          last_step=1000)


def packet(device, inner=None, *, index=0, key=None, plaintext=None):
    if plaintext is None:
        plaintext = json.dumps(inner, separators=(",", ":")).encode()
    selected_key = key if key is not None else GENERIC_KEY if index else device.key
    ciphertext = AES.new(selected_key, AES.MODE_ECB).encrypt(pad(plaintext, 16))
    return {"t": "pack", "i": index, "uid": 7, "cid": "app", "tcid": device.mac,
            "pack": base64.b64encode(ciphertext).decode()}


def peer_reply(reply, key):
    raw = encode_reply(reply)
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    outer = json.loads(raw)
    ciphertext = base64.b64decode(outer.pop("pack"), validate=True)
    inner = json.loads(unpad(AES.new(key, AES.MODE_ECB).decrypt(ciphertext), 16))
    return outer, inner


def exchange(device, inner, *, index=0):
    reply, = PROFILE.handler.handle(device, packet(device, inner, index=index))
    outer, result = peer_reply(reply, GENERIC_KEY if index else device.key)
    assert outer == {"t": "pack", "i": index, "uid": 7, "cid": device.mac, "tcid": ""}
    return result


def status(device, names):
    return exchange(device, {"t": "status", "mac": device.mac, "cols": names})["dat"]


def command(device, names, values):
    return exchange(device, {"t": "cmd", "opt": names, "p": values})


def test_exact_native_transactions_including_raw_ciphertext_and_single_lf():
    device = device_for()
    device.state.update(VECTOR["initial_state"])
    for vector in VECTOR["native_vectors"]:
        outer = vector["input_outer"]
        if vector["label"] in ("wrong_key", "wrong_target"):
            before = dict(device.state)
            with pytest.raises(InvalidPacket):
                PROFILE.handler.handle(device, outer)
            assert device.state == before
            continue
        replies = (PROFILE.handler.advertise(device, outer) if outer["t"] == "scan"
                   else PROFILE.handler.handle(device, outer))
        assert [encode_reply(reply).decode() for reply in replies] == vector["datagrams"]
        assert [peer_reply(reply, GENERIC_KEY if reply.outer["i"] else device.key)[1]
                for reply in replies] == vector["independent_decrypted"]
    assert {name: device.state[name] for name in VECTOR["expected_state"]} == VECTOR["expected_state"]


def test_sensorless_metadata_literal_startup_and_explicit_synthetic_readouts():
    device = device_for()
    assert PROFILE.mids == ("80222",)
    assert PROFILE.hid == RESEARCH["hid"]
    assert PROFILE.source_sha256 == RESEARCH["source_sha256"]
    assert CACHE_FIELDS == frozenset(RESEARCH["model"]["writable_fields"])
    assert len(CACHE_FIELDS) == 41 and len(SELECTORS) == 45
    assert PROFILE.handler.thermal_target(device) is None
    PROFILE.handler.encode_room(device)
    before = dict(device.state)
    device.advance(100000)
    assert device.state == before
    assert device.room_c is device.ambient_c is None
    assert device.state["Quiet"] == device.state["Tur"] == 0
    assert status(device, ["TemSen", "hid", "RealTimePower", "VoiceVolume", "VoiceGate"]) == [
        "362001062573+IS-T3BBW03V3.62.img", 0, 0, 0]
    reply, = PROFILE.handler.advertise(device, {"t": "scan"})
    _, metadata = peer_reply(reply, GENERIC_KEY)
    assert "hid" not in metadata and "TemSen" not in metadata


def test_ack_precedes_normalization_and_fresh_status_has_effective_values():
    device = device_for()
    result = command(device, ["Quiet", "Tur", "SwhSw", "WdSpd", "SwUpDn"], [2, 4, 5, 6, 3])
    assert result["p"] == [2, 4, 5, 6, 3]
    assert "val" not in result
    assert status(device, ["Quiet", "Tur", "SwhSw", "WdSpd", "SwUpDn"]) == [0, 1, 1, 6, 3]
    command(device, ["WdSpd", "SwUpDn", "SwingLfRig"], [7, 0, 2])
    assert status(device, ["Quiet", "Tur", "SwhSw"]) == [1, 0, 1]
    command(device, ["WdSpd", "SwingLfRig"], [65535, 0])
    assert status(device, ["Quiet", "Tur", "SwhSw"]) == [0, 0, 0]


def test_sequential_sleep_economy_cross_fields_and_duplicates():
    device = device_for()
    result = command(device, ["SvSt", "SwhSlp", "SvSt", "SlpMod"], [1, 1, 1, 1])
    assert result["opt"] == ["SvSt", "SwhSlp", "SvSt", "SlpMod"]
    assert result["p"] == [1, 1, 1, 1]
    assert status(device, ["SwhSlp", "SlpMod", "SvSt", "SwhSlp"]) == [1, 1, 0, 1]
    command(device, ["SvSt"], [1])
    assert status(device, ["SwhSlp", "SlpMod", "SvSt"]) == [0, 0, 1]
    command(device, ["SwhSlp", "SlpMod"], [2, 3])
    assert status(device, ["SwhSlp", "SlpMod", "SvSt"]) == [2, 3, 1]


def test_unknowns_empty_arrays_and_explicit_side_effect_exclusions():
    device = device_for()
    assert command(device, ["Pow", "Unknown", "Pow"], [1, 99, 2])["p"] == [1, 2]
    assert status(device, ["Pow", "Unknown", "Pow", "TemSen", "BuzzerCtrl"]) == [2, 2]
    assert command(device, [], [])["opt"] == []
    assert status(device, []) == []
    for kind in ("subDev", "reset", "mate"):
        assert PROFILE.handler.handle(device, packet(device, {"t": kind})) == []


@pytest.mark.parametrize("changes", [
    {"opt": ["Pow", "Mod"], "p": [1]}, {"opt": ["Pow"], "p": [1, 2]},
    {"opt": "Pow", "p": [1]}, {"opt": ["Pow"], "p": "1"},
    {"opt": ["Pow", "Mod"], "p": [1, True]},
    {"opt": ["Pow", "Mod"], "p": [1, 1.5]},
    {"opt": ["Pow", "Mod"], "p": [1, -(2**31) - 1]},
    {"opt": ["Pow", "Mod"], "p": [1, 2**31]},
    {"opt": ["Pow", "Unknown"], "p": [1, None]},
    {"opt": ["Pow", ""], "p": [1, 1]},
    {"opt": ["Pow", "Mod\0ignored"], "p": [1, 1]},
    {"opt": ["Pow", None], "p": [1, 1]},
    {"opt": ["Pow"] * 129, "p": [1] * 129},
    {"opt": ["Pow"] * 100, "p": [1] * 100},
])
def test_malformed_or_oversize_command_is_atomic(changes):
    device = device_for()
    before = dict(device.state)
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "cmd", **changes})
    assert device.state == before and device.last_step == 1000


@pytest.mark.parametrize("cols", ["Pow", [None], [""], ["Pow\0ignored"],
                                  ["Pow"] * 129, ["Pow"] * 100])
def test_invalid_or_oversize_status_is_atomic(cols):
    device = device_for()
    before = dict(device.state)
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "status", "mac": device.mac, "cols": cols})
    assert device.state == before


def test_identity_key_slots_isolation_and_repeat_binding():
    first, second = device_for(), device_for("020000000002", b"fedcba9876543210")
    command(first, ["Pow"], [1])
    assert second.state == dict(PROFILE.initial_state)
    assert exchange(first, {"t": "cmd", "mac": first.mac, "sub": first.mac,
                            "opt": ["Pow"], "p": [2]})["p"] == [2]
    invalid = [
        {**packet(first, {"t": "cmd", "opt": ["Pow"], "p": [1]}), "tcid": second.mac},
        packet(first, {"t": "cmd", "opt": ["Pow"], "p": [1]}, key=second.key),
        packet(first, {"t": "cmd", "opt": ["Pow"], "p": [1]}, index=1),
        packet(first, {"t": "status", "mac": second.mac, "cols": ["Pow"]}),
        packet(first, {"t": "status", "mac": first.mac, "cols": ["Pow"]}, index=1),
        packet(first, {"t": "bind", "mac": first.mac}),
        packet(first, {"t": "bind", "mac": second.mac}, index=1),
        packet(first, {"t": "bind"}, index=1),
        packet(first, {"t": "bind", "mac": first.mac}, index=1, key=first.key),
    ]
    for outer in invalid:
        before = dict(first.state)
        with pytest.raises(InvalidPacket):
            PROFILE.handler.handle(first, outer)
        assert first.state == before
    for device in (first, second, first):
        before = dict(device.state)
        assert exchange(device, {"t": "bind", "mac": device.mac}, index=1) == {
            "t": "bindok", "mac": device.mac, "r": 200, "key": device.key.decode()}
        assert device.state == {**before, "_uid": 7}


@pytest.mark.parametrize("selector", ["mac", "sub"])
@pytest.mark.parametrize("kind", ["cmd", "status", "bind", "reset"])
def test_conflicting_inner_identity_rejects_before_cache_uid_or_time_mutation(selector, kind):
    first, second = device_for(), device_for("020000000002", b"fedcba9876543210")
    first.state["_uid"], second.state["_uid"] = 123, 456
    before = [(dict(device.state), device.last_step) for device in (first, second)]
    inner = {"t": kind, "mac": first.mac, "opt": ["Pow"], "p": [1], "cols": ["Pow"],
             selector: second.mac}
    with pytest.raises(InvalidPacket, match="conflicting voice inner identity"):
        PROFILE.handler.handle(first, packet(first, inner, index=int(kind == "bind")))
    assert [(device.state, device.last_step) for device in (first, second)] == before


def test_scan_echoes_saved_uid_without_resetting_or_sharing_it():
    first, second = device_for(), device_for("020000000002")
    outer = packet(first, {"t": "status", "mac": first.mac, "cols": []})
    PROFILE.handler.handle(first, {**outer, "uid": 123})
    for device, uid in ((first, 123), (second, 0)):
        reply, = PROFILE.handler.advertise(device, {"t": "scan", "uid": 999})
        assert peer_reply(reply, GENERIC_KEY)[0]["uid"] == uid


@pytest.mark.parametrize("changes", [{"i": True}, {"i": -1}, {"i": 2}, {"i": "0"},
                                     {"uid": True}, {"uid": None}, {"uid": 2**31},
                                     {"cid": None}, {"pack": "!"}, {"pack": "AA=="}])
def test_invalid_envelopes_do_not_mutate(changes):
    device = device_for()
    with pytest.raises(InvalidPacket):
        PROFILE.handler.handle(device, {**packet(device, {"t": "cmd", "opt": ["Pow"], "p": [1]}),
                                        **changes})
    assert device.state == dict(PROFILE.initial_state)


@pytest.mark.parametrize("plaintext", [b'{"t":"cmd","t":"bind"}', b'{"t":"status"}\0',
                                       b'{"t":"status"}garbage', b'[]', b'{"t":NaN}'])
def test_strict_json_deviations_are_atomic(plaintext):
    device = device_for()
    with pytest.raises(InvalidPacket):
        PROFILE.handler.handle(device, packet(device, plaintext=plaintext))
    assert device.state == dict(PROFILE.initial_state)


def test_missing_uid_and_invalid_pkcs7_padding_are_rejected_atomically():
    device = device_for()
    inner = {"t": "cmd", "opt": ["Pow"], "p": [1]}
    missing_uid = packet(device, inner)
    missing_uid.pop("uid")
    invalid_padding = packet(device, inner)
    # Independently encrypt a complete AES block stream with an illegal zero pad.
    plaintext = json.dumps(inner, separators=(",", ":")).encode()
    plaintext += b"\0" * (16 - len(plaintext) % 16)
    invalid_padding["pack"] = base64.b64encode(
        AES.new(device.key, AES.MODE_ECB).encrypt(plaintext)).decode()
    for outer in (missing_uid, invalid_padding):
        with pytest.raises(InvalidPacket):
            PROFILE.handler.handle(device, outer)
        assert device.state == dict(PROFILE.initial_state)


@pytest.mark.parametrize("state", [{"Pow": True}, {"Pow": -1}, {"Pow": 65536},
                                   {"TemSen": 26}, {"hid": "spoof"}, {"VoiceGate": True},
                                   {"_power": float("inf")}, {"_power": True}])
def test_configured_cache_rejects_nonmodeled_or_non_uint16_state(state):
    with pytest.raises(ValueError):
        PROFILE.handler.validate_state(state)


def test_seeded_restart_preserves_identity_key_but_resets_literal_cache():
    config = {"seed": "voice-restart", "devices": [
        {"id": "voice", "profile": PROFILE.id, "mid": "80222"}]}
    first = load_config(config)[2][0]
    command(first, ["Pow", "SetTem"], [1, 20])
    restarted = load_config(config)[2][0]
    assert (restarted.mac, restarted.key) == (first.mac, first.key)
    assert restarted.state == dict(PROFILE.initial_state)
    assert restarted.room_c is restarted.ambient_c is None
    with pytest.raises(ValueError, match="room_c"):
        load_config({"devices": [{**config["devices"][0], "room_c": 26}]})


def test_raw_original_receive_limit_and_single_lf_response():
    async def scenario():
        device = device_for()
        server = EmulatorServer([device])
        sent = []
        server.transport = SimpleNamespace(sendto=lambda data, addr: sent.append((data, addr)))
        raw = json.dumps(packet(device, {"t": "cmd", "opt": ["Pow"], "p": [1]})).encode()
        server.datagram_received(raw + b" " * (1025 - len(raw)), ("127.0.0.1", 12345))
        assert not sent and device.state == dict(PROFILE.initial_state)
        server.datagram_received(raw + b" " * (1024 - len(raw)), ("127.0.0.1", 12345))
        assert len(sent) == 1 and device.state["Pow"] == 1
        assert sent[0][0].endswith(b"\n") and not sent[0][0].endswith(b"\n\n")
    asyncio.run(scenario())


@pytest.mark.parametrize("vector", RESEARCH["native_property_evidence"]["uint16_max_writes"],
                         ids=lambda vector: vector["field"])
def test_all_cache_fields_match_independent_native_uint16_max_writes(vector):
    device = device_for()
    initial = RESEARCH["native_property_evidence"]["initial_cache"]
    device.state.update(initial)
    result = command(device, [vector["field"]], [vector["value"]])
    assert [result["opt"], result["p"]] == vector["response_arrays"]
    expected = dict(initial)
    for stage in ("cache_deltas_after_dispatch", "cache_deltas_after_normalization"):
        expected.update({name: values[1] for name, values in vector[stage].items()
                         if name in CONTROLS})
    assert {name: device.state[name] for name in CONTROLS} == expected


@pytest.mark.parametrize("vector", RESEARCH["native_property_evidence"]["cross_field_vectors"],
                         ids=lambda vector: vector["label"])
def test_cross_fields_match_independent_native_cache_outputs(vector):
    device = device_for()
    device.state.update(RESEARCH["native_property_evidence"]["initial_cache"])
    result = command(device, vector["opt"], vector["p"])
    assert [result["opt"], result["p"]] == vector["response_arrays"]
    assert {name: device.state[name] for name in CONTROLS} == vector["cache_after_normalization"]


@pytest.mark.parametrize("vector", QUIRKS["getter_vectors"], ids=lambda row: row["name"])
def test_complete_native_getter_matrix_order_duplicates_and_cardinality(vector):
    device = device_for()
    device.state.update(QUIRKS["initial_state"])
    response = exchange(device, {"t": "status", "mac": device.mac,
                                 "cols": [vector["name"], "Unknown", vector["name"]]})
    assert response["cols"] == vector["cols"]
    assert response["dat"] == vector["dat"]


@pytest.mark.parametrize("vector", QUIRKS["special_vectors"], ids=lambda row: row["label"])
def test_corrected_native_full_ingress_callback_vectors(vector):
    device = device_for()
    device.state.update(QUIRKS["initial_state"])
    assert exchange(device, vector["request"]) == vector["expected"]
    if vector["expected_fresh"]:
        expected = vector["expected_fresh"]
        assert exchange(device, {"t": "status", "mac": device.mac,
                                 "cols": expected["cols"]}) == expected


@pytest.mark.parametrize("name", SELECTORS)
def test_complete_action_matrix_recognizes_every_selector_without_fake_balanced_ack(name):
    device = device_for()
    value = "2026-10-24 12:34:56" if name == "time" else 1
    result = command(device, [name], [value])
    assert result["opt"] == [name]
    if name in CONTROLS or name in ("ProTimePow", "ProTimeLen", "ProTimeReminder",
                                    "SendButton", "Studied"):
        assert result["p"] == [1]
    elif name == "hid":
        assert result["p"] == ["362001062573+IS-T3BBW03V3.62.img"]
    elif name == "time":
        assert result["p"] == [value]
    elif name == "DelButton":
        assert result["p"] == [26]
    else:
        assert result["p"] == []


def test_signed_requests_store_low16_but_callbacks_ack_original_and_guards_skip_ir():
    device = device_for()
    device.state.update(Tur=300, Quiet=18, ProTimeReminder=9)
    result = command(device, ["Pow", "ProTimeLen", "ProTimeReminder", "ProTimePow"],
                     [-1, 65536, -2, 65537])
    assert result["p"] == [65535, 65536, -2, 65537]
    assert status(device, ["Pow", "ProTimeLen", "ProTimeReminder", "ProTimePow",
                           "Tur", "Quiet"]) == [65535, 0, 0, 1, 300, 18]
    device.state.update(SvSt=1, SwhSlp=0, SlpMod=0)
    command(device, ["SwhSlp"], [65537])
    assert status(device, ["SwhSlp", "SlpMod", "SvSt"]) == [1, 0, 1]
    command(device, ["ProTimePow", "ProTimeReminder"], [1, 2])
    assert status(device, ["ProTimeReminder"]) == [2]


def test_last_special_flag_order_controls_whether_cache_normalizes():
    device = device_for()
    device.state.update(Tur=300, Quiet=18)
    command(device, ["ACCntlrShape", "ProTimePow"], [7, 1])
    assert status(device, ["Tur", "Quiet"]) == [300, 18]
    command(device, ["ProTimePow", "ACCntlrShape"], [1, 7])
    assert status(device, ["Tur", "Quiet"]) == [0, 0]


def test_audio_total_batch_size_persistent_counter_and_single_gate_reset():
    device = device_for()
    assert command(device, ["VoiceGate", "Unknown"], [-1, 0])["p"] == [-1]
    assert device.state["_audio_count"] == 1
    assert command(device, ["VoiceVolume", "Unknown"], [65537, 0])["p"] == [65537]
    assert device.state["_audio_count"] == 0
    assert (device.state["_saved_gate"], device.state["_saved_volume"]) == (65535, 1)
    assert command(device, ["VoiceGate", "VoiceVolume", "Pow"], [2, 3, 1])["p"] == [1]
    assert status(device, ["VoiceGate", "VoiceVolume"]) == [2, 3]
    assert command(device, ["VoiceVolume"], [9])["p"] == []
    assert status(device, ["VoiceVolume", "VoiceGate"]) == [9, 0]
    assert device.state["_saved_gate"] == 2
    assert command(device, ["VoiceGate"], [1])["p"] == []
    assert status(device, ["VoiceGate"]) == [0]


def test_virtual_ir_actions_do_not_fabricate_received_buttons_or_physical_success():
    device = device_for()
    assert command(device, ["AddButton"], [28])["p"] == [26]
    assert status(device, ["AddButton", "RefBtnList", "RefBtnList"]) == [0, [], [], [], []]
    assert command(device, ["ConBtnNum", "ConBtnName"], [42, "Bedroom"])["p"] == []
    assert command(device, ["Studied"], [2])["p"] == [2]
    assert status(device, ["Studied"]) == [0]
    assert command(device, ["DelButton"], [[42, -1, 2**31 - 1]])["p"] == [26]
    assert command(device, ["SendButton"], [-1])["p"] == [-1]
    assert status(device, ["SendButton", "RefBtnList"]) == [65535, [], []]


@pytest.mark.parametrize(("power", "expected"), [
    (123.75, 123), (-1.25, 0), (0.99, 0), (65536.75, 65536),
    (4294967296, 4294967295), (16777217, 16777216),
])
def test_power_is_float32_unsigned_integer_readout_not_written_numeric_slot(power, expected):
    device = device_for()
    PROFILE.handler.validate_state({"_power": power})
    device.state["_power"] = power
    assert command(device, ["RealTimePower"], [7])["p"] == []
    assert status(device, ["RealTimePower", "RealTimePower"]) == [expected, expected]


def test_virtual_clock_advances_independently_and_never_changes_on_rejected_batch(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr("gree_emulator.profiles.voice.time.monotonic", lambda: now[0])
    first, second = device_for(), device_for("020000000002")
    assert status(first, ["time"]) == ["1970-01-01 00:00:00"]
    assert status(second, ["time"]) == ["1970-01-01 00:00:00"]
    assert command(first, ["time"], ["2024-02-29 23:59:59"])["p"] == ["2024-02-29 23:59:59"]
    now[0] += 2
    assert status(first, ["time"]) == ["2024-03-01 00:00:01"]
    assert status(second, ["time"]) == ["1970-01-01 00:00:02"]
    before = dict(first.state)
    now[0] += 1
    with pytest.raises(InvalidPacket):
        command(first, ["time", "Pow"], ["2023-02-29 00:00:00", 1])
    assert first.state == before


def test_guard_elapsed_counter_threshold_hold_and_reminder_reset(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr("gree_emulator.profiles.voice.time.monotonic", lambda: now[0])
    device = device_for()
    device.state["_power"] = 6
    command(device, ["ProTimePow", "ProTimeLen"], [1, 1])
    now[0] += 3599
    assert status(device, ["ProTimeReminder"]) == [0]
    device.state["_power"] = 5
    now[0] += 1
    assert status(device, ["ProTimeReminder"]) == [1]
    now[0] += 1
    assert status(device, ["ProTimeReminder"]) == [1]
    device.state["_power"] = 4.99
    now[0] += 1
    assert status(device, ["ProTimeReminder"]) == [0]
    device.state["_power"] = 6
    now[0] += 2
    status(device, [])
    command(device, ["ProTimePow"], [1])
    assert device.state["_guard_ticks"] == 2
    assert status(device, ["ProTimeReminder"]) == [0]


@pytest.mark.parametrize(("name", "value"), [
    ("time", "2024-13-01 00:00:00"), ("time", 0),
    ("ConBtnName", "x" * 20), ("ConBtnName", "bad\0name"),
    ("DelButton", [True]), ("DelButton", [2**31]), ("VoiceGate", False),
])
def test_special_schema_failure_is_atomic_for_clock_counter_cache_and_uid(name, value):
    device = device_for()
    before = dict(device.state)
    with pytest.raises(InvalidPacket):
        command(device, ["Pow", name], [1, value])
    assert device.state == before


def test_reply_size_preflight_covers_cardinality_and_prevents_special_mutation():
    device = device_for()
    before = dict(device.state)
    with pytest.raises(InvalidPacket):
        command(device, ["time"] * 40, ["2026-10-24 12:34:56"] * 40)
    assert device.state == before
    with pytest.raises(InvalidPacket):
        status(device, ["RefBtnList"] * 80)
    assert device.state == before


def test_full_hid_and_final_voicegate_are_reachable_in_one_status_transaction():
    device = device_for()
    result = exchange(device, {"t": "status", "mac": device.mac,
                               "cols": ["hid", "VoiceGate"]})
    assert result == {"t": "dat", "mac": device.mac, "r": 200,
                      "cols": ["hid", "VoiceGate"],
                      "dat": ["362001062573+IS-T3BBW03V3.62.img", 0]}


def test_guard_uses_float32_comparison_and_unsigned_tick_equality(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr("gree_emulator.profiles.voice.time.monotonic", lambda: now[0])
    device = device_for()
    command(device, ["ProTimePow", "ProTimeLen"], [1, 0])
    device.state.update(_power=5.0000001, _guard_active=0)
    now[0] += 1
    assert status(device, ["ProTimeReminder"]) == [0]
    assert device.state["_guard_ticks"] == 0
    device.state.update(_power=6, _guard_ticks=0xffffffff)
    now[0] += 1
    assert status(device, ["ProTimeReminder"]) == [1]


@pytest.mark.parametrize("vector", QUIRKS["guard_boundary_vectors"])
def test_instruction_derived_guard_four_five_six_boundaries(vector, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr("gree_emulator.profiles.voice.time.monotonic", lambda: now[0])
    device = device_for()
    command(device, ["ProTimePow", "ProTimeLen"], [1, 1])
    device.state.update(_power=vector["power"], _guard_active=vector["active"],
                        _guard_ticks=vector["ticks"], ProTimeReminder=vector["reminder"])
    now[0] += 1
    assert status(device, ["ProTimeReminder"]) == [vector["expected_reminder"]]
    assert device.state["_guard_active"] == vector["expected_active"]
    assert device.state["_guard_ticks"] == vector["expected_ticks"]


@pytest.mark.parametrize("vector", QUIRKS["native_delete_vectors"])
def test_qualified_native_numeric_and_array_delete_ack_and_fresh_cache(vector):
    device = device_for()
    assert command(device, ["DelButton"], [vector["input"]])["p"] == [vector["ack"]]
    assert status(device, ["DelButton"]) == [vector["fresh"]]


@pytest.mark.parametrize(("value", "expected_count"), [
    (1, 7), ([], 7), ([1], 0), ([1, 2], 0),
])
def test_delete_refreshes_catalog_count_only_when_deleting_array_items(value, expected_count):
    device = device_for()
    device.state["AddButton"] = 7
    assert command(device, ["DelButton"], [value])["p"] == [26]
    assert status(device, ["AddButton"]) == [expected_count]
