"""Exact-source bounded models for Realtek WB rows 5, 6, and 16."""

import base64
import copy
import json
from pathlib import Path

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles import catalog_realtek_middle_wb_mf4 as mf4
from gree_emulator.wire import InvalidPacket, encode_reply


FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "emulator" /
                      "catalog-realtek-middle-wb-mf4_research.json").read_text())
GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
PRIVATE_KEY = b"0123456789abcdef"


def device_for(profile, *, mac="020000000001", mid="object-mid", key=PRIVATE_KEY):
    return EmulatedDevice("virtual", mac, "Synthetic module", mid, key, profile,
                          copy.deepcopy(dict(profile.initial_state)), last_step=1000)


def packet(device, inner, *, index=0, plaintext=None):
    key = GENERIC_KEY if index else device.key
    plain = (plaintext if plaintext is not None else
             json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode())
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(plain, AES.block_size))
    return {"t": "pack", "i": index, "uid": 42, "cid": "controller",
            "tcid": "a-different-target", "pack": base64.b64encode(encrypted).decode()}


def decode_reply(reply, key):
    outer = json.loads(encode_reply(reply))
    encrypted = base64.b64decode(outer["pack"], validate=True)
    plain = unpad(AES.new(key, AES.MODE_ECB).decrypt(encrypted), AES.block_size)
    return outer, json.loads(plain)


def send(device, inner, *, index=0, plaintext=None):
    return device.profile.handler.handle(device, packet(device, inner, index=index,
                                                        plaintext=plaintext))


def schedule(timer_id, *, enable=1, name="timer", sec=41, tz=9, cmd=None):
    return {"t": "setT", "id": timer_id, "name": name, "enable": enable,
            "week": [0, 1, 0, 1, 0, 1, 0], "hr": 7, "min": 8, "sec": sec,
            "tz": tz, "cmd": cmd or [{"opt": ["Pow"], "p": [7]}]}


def test_profile_sources_and_finite_names_match_research_fixture():
    assert len(mf4.PROFILES) == len(FIXTURE["profiles"]) == 3
    assert [profile.id for profile in mf4.PROFILES] == [row["id"] for row in FIXTURE["profiles"]]
    for profile, row in zip(mf4.PROFILES, FIXTURE["profiles"]):
        assert profile.source_sha256 == row["source_sha256"]
        assert profile.hid == row["hid"]
        assert profile.mids == ("10001",)
        assert profile.max_request_bytes == 1460
        profile.handler.validate_state(copy.deepcopy(dict(profile.initial_state)))
    assert len(mf4._MA_NAMES) == 301
    assert len(mf4._HR_NAMES) == 305

    assert [profile.initial_state["dev_ver"] for profile in mf4.PROFILES] == [
        "V3.4.M", "V3.4.M", "V3.0.0"]
    assert mf4.PROFILES[0].initial_state["companion_ver"] == "V3.4.MF4"
    assert mf4.PROFILES[1].initial_state["companion_ver"] == "V3.4.MF4"
    assert [profile.initial_state["gnet_id"] for profile in mf4.PROFILES[:2]] == [0, 0]
    assert [profile.initial_state["mcu_mode"] for profile in mf4.PROFILES[:2]] == [0, 0]
    assert all("ver" not in profile.initial_state for profile in mf4.PROFILES[:2])
    assert FIXTURE["row_17"]["source_sha256"] not in {
        profile.source_sha256 for profile in mf4.PROFILES}
    assert "no UDP bind/recvfrom/registered UDP receiver exists" in FIXTURE["row_17"]["admission"]

@pytest.mark.parametrize("profile", mf4.PROFILES, ids=lambda profile: profile.id)
def test_advertised_mcu_mid_is_not_the_property_mid_or_device_object_mid(profile):
    device = device_for(profile)
    device.state.update(mcu_mid_raw=0x1234abcd, mid="status-property-mid", name="status-name",
                        bc="context-bc", vender="context-vender",
                        tdev_brand="virtual-brand", lock=5)
    reply, = profile.handler.advertise(device, {"t": "scan"})
    _, tdev = decode_reply(reply, GENERIC_KEY)
    assert tdev["mid"] == "1234abcd"
    assert tdev["mid"] != device.mid
    assert tdev["hid"] == profile.hid
    assert tdev["name"] == "status-name"
    assert tdev["brand"] == "virtual-brand"
    assert tdev["bc"] == "context-bc"
    assert tdev["vender"] == "context-vender"
    assert tdev["lock"] == 0
    assert tdev["ver"] == profile.initial_state["dev_ver"]

    reply, = send(device, {"t": "status", "cols": ["mid", "hid", "ver", "name", "bc", "vender"]})
    _, status = decode_reply(reply, device.key)
    expected_ver = profile.initial_state["dev_ver"]
    assert status["dat"] == ["status-property-mid", profile.hid, expected_ver, "status-name",
                             "context-bc", "context-vender"]

@pytest.mark.parametrize("profile", mf4.PROFILES, ids=lambda profile: profile.id)
def test_source_retry_fallback_and_public_key_route(profile):
    device = device_for(profile)
    reply, = profile.handler.advertise(device, {"t": "scan"})
    outer = json.loads(encode_reply(reply))
    ciphertext = base64.b64decode(outer["pack"], validate=True)
    plaintext = unpad(AES.new(GENERIC_KEY, AES.MODE_ECB).decrypt(ciphertext), AES.block_size)
    assert outer["i"] == 1
    assert plaintext.endswith(b"}") and not plaintext.endswith(b"}\n")
    expected_route = profile is mf4.PROFILES[1]
    assert reply.destination_host == ("255.255.255.255" if expected_route else None)
    assert reply.destination_port == (5000 if expected_route else None)
    _, tdev = decode_reply(reply, GENERIC_KEY)
    assert tdev["mid"] == "10001"
    assert device.state["_wb_dev_mid_raw"] == 0x10001
    assert tdev["name"] == "Synthetic module"
    assert tdev["brand"] == tdev["catalog"] == tdev["model"] == tdev["series"] == "gree"
    assert tdev["ver"] == profile.initial_state["dev_ver"]
    assert tdev["bc"] == tdev["vender"] == ""
    reply, = send(device, {"t": "status", "cols": ["bc", "vender"]})
    assert decode_reply(reply, device.key)[1]["dat"] == ["", ""]

    replies = send(device, {"t": "bind", "mac": "not-this-device"}, index=1)
    assert len(replies) == 1
    assert replies[0].destination_host == ("255.255.255.255" if expected_route else None)
    assert replies[0].destination_port == (5000 if expected_route else None)
    outer, inner = decode_reply(replies[0], GENERIC_KEY)
    assert inner == {"r": 200, "t": "bindok", "mac": "not-this-device",
                     "key": device.key.decode("ascii")}
    assert {key: value for key, value in outer.items() if key != "pack"} == {
        "t": "pack", "i": 1, "uid": 42, "cid": device.mac, "tcid": "controller"}


def test_status_preserves_ordered_columns_duplicate_matches_and_ragged_no_data():
    profile = mf4.PROFILES[0]
    device = device_for(profile)
    device.state.update(mid="property-mid", Pow=0x1234, SetTem=24, NoD=3,
                        rssi=-55, AppTimer=8, AutoUpdate=1, lock=7, MidType=0x80)
    columns = ["Pow", "mid", "DevID", "SetTem", "Pow", "MafIdf", "NoD",
               "lock", "AutoUpdate", "AppTimer", "MidType", "rssi", "unlisted"]
    reply, = send(device, {"t": "status", "cols": columns})
    _, response = decode_reply(reply, device.key)
    assert response["cols"] == columns
    assert response["dat"] == ["property-mid", 7, 1, 8, 1, -55,
                                0x1234, 24, 0x1234, 3]
    assert "val" not in response


def test_command_ack_uses_parsed_words_and_metadata_readback_not_cache_echo():
    device = device_for(mf4.PROFILES[0])
    request = {"t": "cmd", "opt": ["Pow", "Pow", "SetTem"], "p": [65537, 2, 1000]}
    reply, = send(device, request)
    _, response = decode_reply(reply, device.key)
    assert response["opt"] == request["opt"]
    assert response["p"] == request["p"]
    assert device.state["Pow"] == 2
    assert device.state["SetTem"] == 1000

    name = device.state["name"]
    reply, = send(device, {"t": "cmd", "opt": ["name"], "p": ["ignored"]})
    _, response = decode_reply(reply, device.key)
    assert response["p"] == [name]
    assert device.state["name"] == name

    reply, = send(device, {"t": "cmd", "opt": ["ReportClientID"],
                           "p": ["status/client"]})
    _, response = decode_reply(reply, device.key)
    assert response["p"] == []
    runtime = device.state["_wb_mf4_runtime"]
    assert runtime["report_client_frame"][:4] == b"~~\x12\x6a"
    assert runtime["report_client_pending"] is True


def test_special_numeric_writes_keep_getter_buffers_separate():
    device = device_for(mf4.PROFILES[0])
    columns = ["rssi", "AppTimer", "AutoUpdate", "lock", "MidType"]
    values = [255, 1, 2, 3, 255]
    reply, = send(device, {"t": "cmd", "opt": columns, "p": values})
    assert decode_reply(reply, device.key)[1]["p"] == values
    assert [device.state["_wb_mf4_cache"][name] for name in columns] == [255, 1, 2, 3, 255]
    reply, = send(device, {"t": "status", "cols": columns})
    assert decode_reply(reply, device.key)[1]["dat"] == [-55, 0, 0, 0, 0]


@pytest.mark.parametrize("profile", mf4.PROFILES[:2])
@pytest.mark.parametrize("raw_mid, expected_flags", [(0, [0, 6]), (0x11002, [0, 4, 6])])
def test_ma_time_command_ignores_text_and_acknowledges_current_clock(
        profile, raw_mid, expected_flags):
    device = device_for(profile)
    if raw_mid:
        device.state["mcu_mid_raw"] = raw_mid
    current = device.state["time"]
    reply, = send(device, {"t": "cmd", "opt": ["time"], "p": ["not a timestamp"]})
    _, response = decode_reply(reply, device.key)
    assert response["p"] == [current]
    assert device.state["time"] == current

    runtime = device.state["_wb_mf4_runtime"]
    assert runtime["time_config_persist_requested"] is True
    assert runtime["time_flag_bytes_set"] == expected_flags
    assert runtime["time_status_bit_0x80_set"] is True
    assert runtime["clock_time"] == current


def test_hr_time_command_updates_virtual_rtc_and_recomputes_source_timers():
    device = device_for(mf4.PROFILES[2])
    send(device, schedule(1))
    send(device, schedule(2, enable=0))
    runtime = device.state["_wb_mf4_runtime"]
    assert {row["id"]: row["time_delta"] for row in runtime["timers"]} == {
        1: 25680, 2: 25680,
    }
    value = "2026-06-01 12:34:56"
    reply, = send(device, {"t": "cmd", "opt": ["time"], "p": [value]})
    _, response = decode_reply(reply, device.key)
    assert response["p"] == [value]
    assert device.state["time"] == value
    assert runtime["clock_time"] == value
    assert {row["id"]: row["time_delta"] for row in runtime["timers"]} == {
        1: 25680, 2: -19616,
    }
    assert runtime["time_persist_requested"] is False

    reply, = send(device, {"t": "status", "cols": ["time"]})
    assert decode_reply(reply, device.key)[1]["dat"] == response["p"]
    before = copy.deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        send(device, {"t": "cmd", "opt": ["time"], "p": ["2026-02-30 12:34:56"]})
    assert device.state == before
@pytest.mark.parametrize("gate, expected_persist", [
    (0x5b03b45b, False), (0x5b03b45c, True),
])
def test_hr_time_offset_persist_uses_source_gate_word(gate, expected_persist):
    device = device_for(mf4.PROFILES[2])
    device.state["hr_persist_gate_word"] = gate
    device.state["hr_clock_offset_word"] = 0xfffffff0
    send(device, {"t": "cmd", "opt": ["time"], "p": ["2026-01-02 00:00:00"]})
    runtime = device.state["_wb_mf4_runtime"]
    assert runtime["time_persist_requested"] is expected_persist
    expected_offset = 0x15170 if expected_persist else 0xfffffff0
    assert device.state["hr_clock_offset_word"] == expected_offset


@pytest.mark.parametrize("profile", mf4.PROFILES)
def test_numeric_abi_uses_source_tag_gate_and_wrapping_decimal_prefix(profile):
    device = device_for(profile)
    plain = (b'{"t":"cmd","opt":["Pow","Mod","SetTem"],'
             b'"p":[2147483648,1e3,4294967295]}')
    reply, = send(device, {}, plaintext=plain)
    _, response = decode_reply(reply, device.key)
    assert response["p"] == [-2147483648, 1, -1]
    assert device.state["Pow"] == 0
    assert device.state["Mod"] == 1
    assert device.state["SetTem"] == 65535

    for token in (b"-1", b"12.9", b'"1"', b"true", b"null"):
        invalid = b'{"t":"cmd","opt":["Pow"],"p":[' + token + b']}'
        before = copy.deepcopy(device.state)
        with pytest.raises(InvalidPacket):
            send(device, {}, plaintext=invalid)
        assert device.state == before


def test_source_specific_modeltype_string_and_numeric_paths_are_distinct():
    ma = device_for(mf4.PROFILES[0])
    reply, = send(ma, {"t": "cmd", "opt": ["ModelType"], "p": [257]})
    _, response = decode_reply(reply, ma.key)
    assert response["p"] == [257]
    reply, = send(ma, {"t": "status", "cols": ["ModelType"]})
    assert decode_reply(reply, ma.key)[1]["dat"] == [257]

    hr = device_for(mf4.PROFILES[2])
    reply, = send(hr, {"t": "cmd", "opt": ["ModelType"], "p": ["requested"]})
    assert decode_reply(reply, hr.key)[1]["p"] == [""]
    assert hr.state["ModelType"] == ""


@pytest.mark.parametrize("inner", [
    {"t": "cmd", "opt": ["host"], "p": ["not-a-setter"]},
    {"t": "cmd", "opt": ["Pow"], "p": [True]},
    {"t": "cmd", "opt": ["Pow", "SetTem"], "p": [1]},
    {"t": "cmd", "opt": ["ReportClientID"], "p": ["x" * 27]},
    {"t": "reset"},
])
def test_unsafe_or_bad_commands_are_rejected_atomically(inner):
    device = device_for(mf4.PROFILES[0])
    before = copy.deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        send(device, inner)
    assert device.state == before


def test_timer_list_state_enable_seconds_timezone_and_first_nested_command():
    device = device_for(mf4.PROFILES[0])
    first = schedule(2, enable=1, cmd=[{"opt": ["Pow", "Pow"], "p": [7, 8]},
                                       {"opt": ["Mod"], "p": [9]}])
    second = schedule(7, enable=2)
    assert [decode_reply(reply, device.key)[1] for reply in send(device, first)] == [
        {"t": "resT", "r": 200}]
    send(device, second)
    runtime = device.state["_wb_mf4_runtime"]
    assert [record["id"] for record in runtime["timers"]] == [7, 2]

    reply, = send(device, {"t": "queryT", "index": 0, "count": 10})
    item = decode_reply(reply, device.key)[1]["list"]
    assert [entry["id"] for entry in item] == [2, 7]
    assert list(item[0]) == ["id", "name", "enable", "week", "hr", "min", "sec",
                             "cmd", "mac", "opt", "Pow", "p"]
    assert item[0]["enable"] == 1
    assert item[0]["sec"] == 0
    assert item[0]["week"] == [0, 1, 0, 1, 0, 1, 0]
    assert item[0]["cmd"] == [{"opt": ["Pow", "Pow"], "p": [7, 8]}]
    assert item[0]["Pow"] == 7
    assert "tz" not in item[0] and "time_delta" not in item[0]
    assert item[1]["enable"] == 0

    missing = schedule(9, name="missing")
    missing["t"] = "updateT"
    reply, = send(device, missing)
    assert decode_reply(reply, device.key)[1] == {"t": "resT", "r": 200}
    assert runtime["schedule_count"] == 2
    reply, = send(device, {"t": "deleteT", "id": 99})
    assert decode_reply(reply, device.key)[1] == {"t": "resT", "r": 200}
    assert runtime["schedule_count"] == 1
    send(device, {"t": "deleteT", "id": 2})
    assert runtime["timers"] == []  # Non-head deletion assigns root.head=matched.next.
    assert runtime["schedule_count"] == 0


def test_schedule_numeric_lexer_preserves_scalar_prefix_and_array_cursor_quirks():
    device = device_for(mf4.PROFILES[0])
    plaintext = (
        b'{"t":"setT","id":1e3,"name":"lexer","enable":1.2,'
        b'"week":[1e3,0,0,0,0,0],"hr":7.5,"min":8,"sec":41.9,"tz":11.2,'
        b'"cmd":[{"opt":["Pow","Mod"],"p":[1e3,99]}]}'
    )
    send(device, {}, plaintext=plaintext)
    reply, = send(device, {"t": "queryT", "index": 0, "count": 10})
    [item] = decode_reply(reply, device.key)[1]["list"]
    assert item["id"] == 1
    assert item["enable"] == 1
    assert item["week"] == [1, 1, 1, 0, 0, 0, 0]
    assert item["hr"] == 7
    assert item["sec"] == 0
    assert item["cmd"] == [{"opt": ["Pow", "Mod"], "p": [1, 3]}]
    assert item["Pow"] == 1


def test_schedule_bounds_and_invalid_record_are_atomic():
    device = device_for(mf4.PROFILES[0])
    before = copy.deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        send(device, schedule(1, sec="invalid"))
    assert device.state == before
    with pytest.raises(InvalidPacket):
        send(device, {"t": "queryT", "index": -1, "count": 1})
    assert device.state == before


def test_schedule_capacity_rejects_even_replacement_at_ten_records():
    device = device_for(mf4.PROFILES[0])
    for timer_id in range(10):
        send(device, schedule(timer_id, name=f"timer-{timer_id}"))
    before = copy.deepcopy(device.state)
    assert send(device, schedule(0, name="replacement")) == []
    assert device.state == before


def test_report_frequency_control_and_unsafe_routes_are_source_local():
    device = device_for(mf4.PROFILES[0])
    device.state["freq_secondary_ready"] = True
    assert send(device, {"t": "freqCount", "cols": ["SendFreq", "FreqTime", "Pow"],
                         "p": [1, 30, 4]}) == []
    runtime = device.state["_wb_mf4_runtime"]
    assert runtime["request_ready"] is True
    assert runtime["report_timer"] == 0x400a
    assert runtime["freq_time"] == 30
    assert runtime["freq_secondary_timer"] == 0x4001
    assert device.state["Pow"] == 4

    device.state["report_context"] = "topic/prefix"
    assert send(device, {"t": "ReportCtrl", "ActiveTime": 2, "ReportInterval": 3,
                         "reportAnyway": True}) == []
    assert runtime["report_context_prefix"] == "topic"
    assert runtime["report_state"] == 2
    assert runtime["report_active_timer"] == 60 * 2 + 0x4000
    assert runtime["report_interval_timer"] == 60 * 3 + 0x4000
    assert send(device, {"t": "ReportCtrl", "reportAnyway": "not-a-boolean"}) == []
    assert runtime["report_state"] == 1

    device.state["report_route_word"] = 255
    before = copy.deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        send(device, {"t": "ReportLimit", "CtrlFunc": "unsafe"})
    assert device.state == before
    assert send(device, {"t": "ReportLimit", "NRA": [[1, 2, 3], [4, 5, 6]]}) == []
    assert runtime["nra"] == [[1, 2, 3, 2], [4, 5, 6, 2]]

    device6 = device_for(mf4.PROFILES[1])
    before = copy.deepcopy(device6.state)
    with pytest.raises(InvalidPacket):
        send(device6, {"t": "statusCheck"})
    assert device6.state == before

def test_local_callback_gates_and_state_only_setup_paths():
    ma170 = device_for(mf4.PROFILES[0])
    assert send(ma170, {"t": "scan"}) == []
    assert "_wb_mf4_runtime" not in ma170.state
    ma170.state["gnet_id"] = 1
    ma170.state["ubind_lock"] = 255
    reply, = send(ma170, {"t": "scan"})
    _, ubind = decode_reply(reply, ma170.key)
    tdev_reply, = ma170.profile.handler.advertise(ma170, {"t": "scan"})
    assert decode_reply(tdev_reply, GENERIC_KEY)[1]["ver"] == "V3.4.MF4"
    assert ubind["t"] == "UBind"
    assert ubind["ver"] == "V3.4.MF4"
    assert ubind["lock"] == -1
    assert ma170.state["_wb_mf4_runtime"]["bound"] is True
    status_reply, = send(ma170, {"t": "status", "cols": ["ver"]})
    assert decode_reply(status_reply, ma170.key)[1]["dat"] == ["V3.4.MF4"]

    ma183 = device_for(mf4.PROFILES[1])
    ma183.state["mcu_mode"] = 1
    assert send(ma183, {"t": "scan"}) == []
    assert "_wb_mf4_runtime" not in ma183.state
    ma183.state["mcu_mode"] = 2
    ma183.state["ubind_lock"] = 128
    _, ubind = decode_reply(send(ma183, {"t": "scan"})[0], ma183.key)
    assert ubind["t"] == "UBind"
    assert ubind["ver"] == "V3.4.MF4"
    assert ubind["lock"] == -128
    tdev_reply, = ma183.profile.handler.advertise(ma183, {"t": "scan"})
    assert decode_reply(tdev_reply, GENERIC_KEY)[1]["ver"] == "V3.4.MF4"
    status_reply, = send(ma183, {"t": "status", "cols": ["ver"]})
    assert decode_reply(status_reply, ma183.key)[1]["dat"] == ["V3.4.MF4"]

    before = copy.deepcopy(ma183.state)
    with pytest.raises(InvalidPacket):
        send(ma183, {"t": "networkInfo", "gnetkey": "seven77"})
    assert ma183.state == before
    assert send(ma183, {"t": "networkInfo", "gnetkey": "ABCDEFGH", "homemac": "ignored"}) == []
    runtime = ma183.state["_wb_mf4_runtime"]
    assert runtime["gnet_key"] == b"ABCDEFGH"
    assert runtime["network_ready"] is True
    assert runtime["mode"] == 2

    assert send(ma183, {"t": "lifeCycle", "LifeCycleFlag": 0x101,
                        "LifeCycleSwitch": 2}) == []
    assert runtime["lifecycle"] == {"LifeCycleFlag": 1, "LifeCycleSwitch": 2}
    assert runtime["lifecycle_status"] & 0x80
    assert send(ma183, {"t": "hbok"}) == []
    assert runtime["heartbeat_ready"] is True
    assert runtime["heartbeat_failed"] is False
    assert runtime["heartbeat_timer"] == 0x403c
    assert send(ma183, {"t": "loginInfoRes", "r": 200, "loginInfo": {"GnetID": 0}}) == []
    assert runtime["login_result"] == 0
    before = copy.deepcopy(ma183.state)
    with pytest.raises(InvalidPacket):
        send(ma183, {"t": "loginInfoRes", "loginInfo": {"GnetID": 1}})
    assert ma183.state == before


def test_bin_cmd_stages_only_bounded_virtual_frames():
    device = device_for(mf4.PROFILES[0])
    device.state["report_route_word"] = 0x13800
    frame = b"~~" + bytes([45]) + bytes(range(44))
    encoded = base64.b64encode(frame).decode()
    reply, = send(device, {"t": "binCmd", "hex01": encoded,
                           "ReportFreq": 255, "ReportClientID": "frame-client"})
    assert decode_reply(reply, device.key)[1] == {"t": "res", "r": 200}
    runtime = device.state["_wb_mf4_runtime"]
    stage = runtime["binary_frames"][0]
    expected_stage = bytearray(frame)
    expected_stage[0x2b] |= 2
    expected_stage[7] = 0
    assert stage[:len(frame)] == expected_stage
    assert runtime["report_freq"] == 44
    assert runtime["report_client_pending"] is True

    before = copy.deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        send(device, {"t": "binCmd", "hex01": "not-base64"})
    assert device.state == before
    with pytest.raises(InvalidPacket):
        send(device, {"t": "binCmd", "hex01": encoded, "sceneId": 4})
    assert device.state == before


def test_ubind_requires_configured_virtual_identities_and_consumes_pending_client():
    device = device_for(mf4.PROFILES[0])
    before = copy.deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        send(device, {"t": "UBindok"})
    assert device.state == before

    device.state.update(ubind_identity1="010203040506", ubind_identity2="111213141516",
                        ubind_identity3="a1a2a3a4a5a6", report_route_word=0x12345678,
                        ubind_word2=0x87654321, ubind_readouts=[0x101, 0x202, 0x303, 0x404, 0x505])
    send(device, {"t": "cmd", "opt": ["ReportClientID"], "p": ["pending"]})
    reply, = send(device, {"t": "UBindok"})
    _, response = decode_reply(reply, device.key)
    header = base64.b64decode(response["header"], validate=True)
    assert header[:2] == b"fg"
    assert header[4:10] == bytes.fromhex("010203040506")
    assert header[10:16] == bytes.fromhex("111213141516")
    assert header[16:22] == bytes.fromhex("a1a2a3a4a5a6")
    assert header[22:30] == bytes.fromhex("1234567887654321")
    assert header[33:38] == bytes((1, 2, 3, 4, 5))
    runtime = device.state["_wb_mf4_runtime"]
    assert runtime["report_client_pending"] is False
    assert runtime["report_client_frame"] is None


def test_dump_ranges_are_per_source_and_upgrade_is_only_local_intent():
    ma170 = device_for(mf4.PROFILES[0])
    before = copy.deepcopy(ma170.state)
    assert send(ma170, {"t": "dump", "period": 20, "cnt": 2}) == []
    assert ma170.state == before

    ma183 = device_for(mf4.PROFILES[1])
    reply, = send(ma183, {"t": "dump", "period": 1, "cnt": 40000})
    assert decode_reply(reply, ma183.key)[1] == {"t": "ret", "r": 200}
    assert ma183.state["_wb_mf4_runtime"]["dump_period"] == 5
    assert ma183.state["_wb_mf4_runtime"]["dump_count"] == 36000

    hr = device_for(mf4.PROFILES[2])
    send(hr, {"t": "dump", "period": 10000, "cnt": 40000})
    assert hr.state["_wb_mf4_runtime"]["dump_period"] == 4096
    assert hr.state["_wb_mf4_runtime"]["dump_count"] == 40000
    reply, = send(hr, {"t": "upgrade", "url": "https://example.invalid/fw"})
    assert decode_reply(reply, hr.key)[1] == {"t": "ret", "r": 200}
    assert hr.state["_wb_mf4_runtime"]["upgrade_url"] == "https://example.invalid/fw"
    reply, = send(hr, {"t": "upgrade", "url": None})
    assert decode_reply(reply, hr.key)[1] == {"t": "ret", "r": 200}
    assert hr.state["_wb_mf4_runtime"]["upgrade_url"] == "null"
    before = copy.deepcopy(hr.state)
    with pytest.raises(InvalidPacket):
        send(hr, {"t": "upgrade"})
    assert hr.state == before
