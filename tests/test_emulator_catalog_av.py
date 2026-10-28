"""Old AV raw caches: exact wire contracts, not synthetic Celsius controls."""
import copy
import json
from base64 import b64encode
from pathlib import Path

import pytest

from gree_emulator.__main__ import load_config
from gree_emulator.wire import InvalidPacket
from gree_emulator.wire import decode_outer, encode_reply
from tests.test_emulator import peer_packet, peer_reply
from tests.test_emulator_session_qca import raw_devices, raw_request, raw_status


MATRIX = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-av_research.json").read_text())
VERSIONS = MATRIX["versions"]


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("vector", MATRIX["ordinary"], ids=lambda vector: vector["name"])
def test_every_old_ordinary_raw_setter_ack_and_fresh_getter(version, vector):
    root, child = raw_devices("sim-w06av-" + version)
    name = vector["name"]
    packet = {"t": "cmd", "sub": child.mac, "opt": [name], "p": [vector["requested"]]}
    if version == "v7" and vector["selector"] >= 38:
        with pytest.raises(InvalidPacket):
            raw_request(root, packet)
        assert raw_status(root, child, [name])["dat"] == [""]
        return
    assert raw_request(root, packet) == {
        "t": "res", "mac": child.mac, "r": 200,
        "opt": [name], "p": [vector["requested"]], "val": [vector["requested"]],
    }
    assert raw_status(root, child, [name])["dat"] == [vector["expected"]]


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("vector", MATRIX["alternate"], ids=lambda vector: vector["name"])
def test_every_old_alternate_raw_setter_and_report(version, vector):
    root, child = raw_devices("sim-w06av-" + version, alternate=True)
    raw_request(root, {"t": "cmd", "sub": child.mac,
                       "opt": [vector["name"]], "p": [vector["requested"]]})
    assert raw_status(root, child, [vector["name"]])["dat"] == [vector["expected"]]


@pytest.mark.parametrize("profile", (
    "sim-w06av-v7", "sim-w06av-v16", "sim-w06av-v16-eu", "sim-w06av-v16-kf",
    "sim-w06av-v20", "sim-w06av-v30", "sim-w06bv-v9", "sim-w06bv-v16",
    "sim-w06bv-v20", "sim-w06bv-v30",
))
def test_alternate_control_only_descriptor_keeps_source_network_serializer_scope(profile):
    root, child = raw_devices(profile, alternate=True)
    names = ["Pow", "ExWdSpd", "WdSpd", "ExWdSpd"]
    packet = {"t": "cmd", "sub": child.mac, "opt": names, "p": [1, 65537, 2, 65538]}
    omitted = profile in ("sim-w06av-v7", "sim-w06bv-v9")
    values = [1, 2] if omitted else [1, "", 2, ""]
    assert raw_request(root, packet) == {
        "t": "res", "r": 200, "mac": child.mac,
        "opt": ["Pow", "WdSpd"] if omitted else names, "p": values, "val": values,
    }
    assert raw_status(root, child, names)["dat"] == [1, "", 2, ""]


@pytest.mark.parametrize("version", VERSIONS)
def test_old_discovery_does_not_invent_hid_and_requested_metadata_keeps_source_scope(version):
    root, child = raw_devices("sim-w06av-" + version)
    assert "hid" not in root.profile.handler.advertise(root, {"t": "scan"})[0].inner
    expected = [root.profile.hid if version == "v7" else "", root.mac, *MATRIX["metadata_common"][1:]]
    for target in (root, child):
        assert raw_status(root, target, MATRIX["metadata_columns"])["dat"] == expected
    assert raw_status(root, root, ["Pow", "SetTem", "TemBody", "notAField"])["dat"] == [0, 0, 0, ""]


@pytest.mark.parametrize("version", VERSIONS)
def test_raw_temperature_masks_aliases_order_and_no_room_projection(version):
    root, child = raw_devices("sim-w06av-" + version)
    raw_request(root, {"t": "cmd", "sub": child.mac,
                       "opt": ["SetDeciTem", "Quiet", "TemBody", "ErrType1"],
                       "p": [183, -1, 255, -1]})
    assert raw_status(root, child, ["SetTem", "SetDeciTem", "Add0.1", "Add0.5", "Quiet", "TemBody", "ErrType1"])["dat"] == [18, 183, 3, 1, 255, 255, 65535]
    child.room_c = 9
    child.profile.handler.encode_room(child)
    assert raw_status(root, child, ["TemBody"])["dat"] == [255]
    assert child.profile.handler.thermal_target(child) is None
    before = copy.deepcopy(child.state)
    with pytest.raises(InvalidPacket):
        raw_request(root, {"t": "cmd", "sub": child.mac,
                           "opt": ["Quiet", "Pow"], "p": [42, True]})
    assert child.state == before


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("stored,emitted,suffix", [
    ("6099", "6079", "fan"), ("608d", "6079", "fan"), ("6091", "6079", "fan"),
    ("6035", "6036", "water"), ("6036", "6036", "water"),
])
def test_old_stored_mid_aliases_are_normalized_only_in_enumeration(version, stored, emitted, suffix):
    config = {"devices": [
        {"id": "root", "profile": "sim-w06av-" + version, "mid": "60", "mac": "020000000001"},
        {"id": "child", "profile": "sim-w06av-" + version + "-" + suffix,
         "mid": stored, "mac": "02000000000201", "parent": "root"},
    ]}
    if version == "v7" and suffix == "water":
        with pytest.raises(ValueError):
            load_config(config)
        return
    root, child = load_config(config)[2]
    result = raw_request(root, {"t": "subDev", "mac": root.mac, "i": 0})
    assert result["list"][0]["mid"] == emitted
    assert result["list"][0]["mac"] == child.mac
    assert child.mid == stored
    raw_request(root, {"t": "cmd", "sub": child.mac, "opt": ["Pow"], "p": [1]})
    assert raw_status(root, child, ["Pow"])["dat"] == [1]


@pytest.mark.parametrize("version", VERSIONS)
def test_old_root_metadata_setters_are_atomic_and_distinct_from_child_raw_cache(version):
    root, child = raw_devices("sim-w06av-" + version)
    original_name = root.name
    command = {"t": "cmd", "sub": root.mac, "opt": ["name", "lock", "time"],
               "p": ["Renamed", 1, "2026-10-24 12:34:56"]}
    assert raw_request(root, command)["val"] == command["p"]
    assert raw_status(root, root, ["name", "lock", "time"])["dat"] == [root.mac, 1, "2026-10-24 12:34:56"]
    advertisement = root.profile.handler.advertise(root, {"t": "scan"})[0].inner
    assert advertisement["name"] == original_name and advertisement["lock"] == 1
    before = copy.deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        raw_request(root, {"t": "cmd", "sub": root.mac,
                           "opt": ["name", "lock"], "p": ["Rejected", True]})
    assert root.state == before and root.name == original_name
    assert raw_status(root, child, ["Pow", "SetTem"])["dat"] == [0, 24]


@pytest.mark.parametrize("profile", ["sim-w06av-" + version for version in VERSIONS] + [
    "sim-w06bv-v9", "sim-w06bv-v16", "sim-w06bv-v30",
])
def test_indexed_alternate_readouts_and_readonly_gas_count(profile):
    root, child = raw_devices(profile, alternate=True)
    raw_request(root, {"t": "cmd", "sub": child.mac,
                       "opt": ["GasAvail", "TemSor", "PM2P5"], "p": [5, 42, 65537]})
    for index, expected in ((0, [1, 42, 1, 0]), (1, [0, 0, 0, 0]), (2, [1, 0, 0, 0])):
        reply = raw_request(root, {"t": "status", "mac": child.mac, "GasN": index,
                                   "cols": ["GasAvail", "TemSor", "PM2P5", "GasQ"]})
        assert reply["GasN"] == index and reply["dat"] == expected
    before = copy.deepcopy(child.state)
    with pytest.raises(InvalidPacket):
        raw_request(root, {"t": "cmd", "sub": child.mac, "opt": ["GasQ"], "p": [4]})
    with pytest.raises(InvalidPacket):
        raw_request(root, {"t": "status", "mac": child.mac, "GasN": 5, "cols": ["TemSor"]})
    assert child.state == before


@pytest.mark.parametrize("profile", ["sim-w06bv-v9", "sim-w06bv-v16", "sim-w06bv-v30"])
@pytest.mark.parametrize("vector", MATRIX["ordinary"], ids=lambda vector: vector["name"])
def test_additional_bv_builds_keep_raw_descriptor_widths_and_namespace(profile, vector):
    root, child = raw_devices(profile)
    request = {"t": "cmd", "sub": child.mac,
               "opt": [vector["name"]], "p": [vector["requested"]]}
    if profile == "sim-w06bv-v9" and vector["selector"] >= 38:
        with pytest.raises(InvalidPacket):
            raw_request(root, request)
        return
    assert raw_request(root, request)["val"] == request["p"]
    assert raw_status(root, child, [vector["name"]])["dat"] == [vector["expected"]]


@pytest.mark.parametrize("profile,advertises_hid,status_hid", [
    ("sim-w06bv-v9", False, "362001061437+U-W06BV9.bin"),
    ("sim-w06bv-v16", False, ""),
    ("sim-w06bv-v30", True, "362001067524+U-W06BV30.bin"),
])
def test_bv_identity_lifecycle_is_qualified_per_build(profile, advertises_hid, status_hid):
    root, child = raw_devices(profile)
    advert = root.profile.handler.advertise(root, {"t": "scan"})[0].inner
    assert ("hid" in advert) is advertises_hid
    assert raw_status(root, root, ["hid"])["dat"] == [status_hid]
    assert raw_status(root, child, ["hid"])["dat"] == [status_hid]


SCHEDULES = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-av-schedules_research.json").read_text())
ROOT_MAC = "020000000001"
SCHEDULE_CHILD = "02000000000201"


def schedule_devices(profile):
    return load_config({"devices": [
        {"id": "root", "profile": profile, "mid": "60", "mac": ROOT_MAC},
        {"id": "child", "profile": profile + "-ac", "mid": "604a",
         "parent": "root", "mac": SCHEDULE_CHILD},
    ]})[2]


def schedule_exchange(root, inner):
    packet = peer_packet({"t": "pack", "i": 0, "uid": -17,
                          "cid": "app", "tcid": root.mac}, inner, root.key)
    replies = root.profile.handler.handle(root, decode_outer(packet))
    result = []
    for reply in replies:
        encoded = encode_reply(reply)
        index = json.loads(encoded)["i"]
        decoded = peer_reply(encoded, b"a3K8Bx%2r8Y7#xDh" if index else root.key)
        result.append((index, decoded["inner"]))
    return result


@pytest.mark.parametrize("profile", SCHEDULES["timer_profiles"])
def test_source_timer_set_update_report_query_delete_and_board_isolation(profile):
    root, child = schedule_devices(profile)
    timer = copy.deepcopy(SCHEDULES["timer"])
    assert schedule_exchange(root, {"t": "setT", **timer}) == [(0, SCHEDULES["resT"])]
    query = {"t": "queryT", "index": 2, "count": 2}
    assert schedule_exchange(root, query) == [
        (0, {"t": "listT", "total": 1, "index": 2, "list": [SCHEDULES["timer_report"]]}),
        (0, {"t": "listT", "total": 1, "index": 2, "list": []}),
    ]
    other, _ = schedule_devices(profile)
    assert schedule_exchange(other, {**query, "count": 1}) == [
        (0, {"t": "listT", "total": 0, "index": 2, "list": []})]
    timer.update(name="updated", enable=258, hr=262, min=-1, sec=264,
                 cmd=[{"mac": [SCHEDULE_CHILD], "opt": ["Pow"], "p": [257]}])
    assert schedule_exchange(root, {"t": "updateT", **timer}) == [(0, SCHEDULES["resT"])]
    expected = {**SCHEDULES["timer_report"], "name": "updated", "enable": 0,
                "hr": 6, "min": 255, "sec": 8,
                "cmd": [{"mac": [SCHEDULE_CHILD], "opt": ["Pow"], "p": [1]}]}
    assert schedule_exchange(root, {**query, "count": 1}) == [
        (0, {"t": "listT", "total": 1, "index": 2, "list": [expected]})]
    assert schedule_exchange(root, {"t": "updateT", **timer, "week": []}) == [(0, SCHEDULES["resT"])]
    assert schedule_exchange(root, {**query, "count": 1})[0][1]["list"] == [expected]
    assert raw_status(root, child, ["Pow", "SetTem"])["dat"] == [0, 24]
    assert schedule_exchange(root, {"t": "deleteT", "id": 2}) == [(0, SCHEDULES["resT"])]
    assert schedule_exchange(root, {**query, "count": 1}) == [
        (0, {"t": "listT", "total": 0, "index": 2, "list": []})]
    assert schedule_exchange(root, {"t": "deleteT", "id": 9}) == [(0, SCHEDULES["resT"])]
    other, _ = schedule_devices(profile)
    assert schedule_exchange(other, {**query, "count": 1})[0][1]["total"] == 0


@pytest.mark.parametrize("profile", SCHEDULES["timer_profiles"])
def test_timer_native_bounds_and_safe_atomic_overflow_rejection(profile):
    root, child = schedule_devices(profile)
    timer = copy.deepcopy(SCHEDULES["timer"])
    schedule_exchange(root, {"t": "setT", **timer})
    before = copy.deepcopy((root.state, child.state))
    invalid = [
        {**timer, "id": 10}, {**timer, "id": -1}, {**timer, "enable": True},
        {**timer, "name": "x" * 20}, {**timer, "week": [0] * 8},
        {**timer, "cmd": []},
        {**timer, "cmd": [{"mac": [ROOT_MAC], "opt": ["Pow"], "p": [1]}]},
        {**timer, "cmd": [{"mac": [SCHEDULE_CHILD], "opt": ["TemSen"], "p": [1]}]},
        {**timer, "cmd": [{"mac": [SCHEDULE_CHILD], "opt": ["Pow"], "p": []}]},
    ]
    for record in invalid:
        with pytest.raises(InvalidPacket):
            schedule_exchange(root, {"t": "updateT", **record})
        assert (root.state, child.state) == before
    for index, count in ((-1, 1), (10, 1), (9, 2), (0, 0), (0, 11), (0, True)):
        with pytest.raises(InvalidPacket):
            schedule_exchange(root, {"t": "queryT", "index": index, "count": count})
        assert (root.state, child.state) == before
    assert schedule_exchange(root, {"t": "queryT", "index": 9, "count": 1}) == [
        (0, {"t": "listT", "total": 1, "index": 9, "list": []})]


@pytest.mark.parametrize("profile", SCHEDULES["rule_profiles"])
def test_ifttt_safe_owned_records_preserve_native_id_and_single_report_semantics(profile):
    root, child = schedule_devices(profile)
    rule = copy.deepcopy(SCHEDULES["rule"])
    report = {**rule, "week": [1, 0, 1, 0, 0, 0, 0]}
    assert schedule_exchange(root, {"t": "setIFTTT", **rule}) == [(2, SCHEDULES["resT"])]
    query = {"t": "queryIFTTT", "index": 0, "count": 2}
    assert schedule_exchange(root, query) == [
        (0, {"t": "listIFTTT", "total": 1, "index": 0, "list": [report]})]
    other, _ = schedule_devices(profile)
    assert schedule_exchange(other, query) == [
        (0, {"t": "listIFTTT", "total": 0, "index": 0, "list": []})]
    second = {**rule, "id": 99, "name": "second"}
    assert schedule_exchange(root, {"t": "setIFTTT", **second}) == [(2, SCHEDULES["resT"])]
    second_report = {**report, "id": 0, "name": "second"}
    assert schedule_exchange(root, {**query, "index": 1, "count": 1}) == [
        (0, {"t": "listIFTTT", "total": 2, "index": 1, "list": [second_report]})]
    updated = {**rule, "name": "updated-rule", "week": [], "start": [], "end": []}
    assert schedule_exchange(root, {"t": "updateIFTTT", **updated}) == [(2, SCHEDULES["resT"])]
    assert schedule_exchange(root, {**query, "count": 260}) == [
        (0, {"t": "listIFTTT", "total": 2, "index": 0,
             "list": [{**report, "name": "updated-rule", "week": [0] * 7,
                       "start": [0, 0, 0], "end": [0, 0, 0]}]})]
    assert schedule_exchange(root, {"t": "deleteIFTTT", "id": 7}) == [(2, SCHEDULES["resT"])]
    assert schedule_exchange(root, query) == [
        (0, {"t": "listIFTTT", "total": 1, "index": 0, "list": [second_report]})]
    assert schedule_exchange(root, {"t": "deleteIFTTT", "id": 0}) == [(2, SCHEDULES["resT"])]
    assert schedule_exchange(root, {**query, "index": 15, "count": 1}) == [
        (0, {"t": "listIFTTT", "total": 0, "index": 0, "list": []})]
    assert raw_status(root, child, ["Pow", "WdSpd", "SetTem"])["dat"] == [0, 0, 24]
    other, _ = schedule_devices(profile)
    assert schedule_exchange(other, query)[0][1]["total"] == 0


@pytest.mark.parametrize("profile", SCHEDULES["rule_profiles"])
def test_ifttt_full_list_unknown_ids_and_malformed_records_do_not_mutate(profile):
    root, child = schedule_devices(profile)
    rule = copy.deepcopy(SCHEDULES["rule"])
    for number in range(16):
        schedule_exchange(root, {"t": "setIFTTT", **rule, "name": str(number)})
    assert schedule_exchange(root, {"t": "queryIFTTT", "index": 15, "count": 1})[0][1] == {
        "t": "listIFTTT", "total": 16, "index": 15,
        "list": [{**rule, "id": 15, "name": "15", "week": [1, 0, 1, 0, 0, 0, 0]}],
    }
    before = copy.deepcopy((root.state, child.state))
    bad_rules = [
        {**rule, "cmd": "not base64"}, {**rule, "mac": SCHEDULE_CHILD},
        {**rule, "name": "x" * 32}, {**rule, "week": [0] * 8},
        {**rule, "condit": [[1, 2]]}, {**rule, "condit": [[1, 2, 3]] * 6},
        {**rule, "enable": True}, {**rule, "id": 99},
    ]
    for record in bad_rules:
        with pytest.raises(InvalidPacket):
            schedule_exchange(root, {"t": "updateIFTTT", **record})
        assert (root.state, child.state) == before
    for packet in ({"t": "setIFTTT", **rule},
                   {"t": "deleteIFTTT", "id": 99},
                   {"t": "queryIFTTT", "index": 0, "count": 256},
                   {"t": "queryIFTTT", "index": 15, "count": 2}):
        with pytest.raises(InvalidPacket):
            schedule_exchange(root, packet)
        assert (root.state, child.state) == before


@pytest.mark.parametrize("profile", SCHEDULES["rule_profiles"])
@pytest.mark.parametrize("payload", (
    b"[]", b'{"i":1,"i":0,"pack":""}', b'{"i":true,"pack":""}',
    b'{"i":1}', b'{"i":1,"pack":null}', b'{"i":1,"pack":7}',
    b'{"i":1,"pack":{}}', b'{"i":NaN,"pack":""}',
    b'{"i":1,"pack":"\\ud800"}', b'{"i":1,"pack":"/w=="}',
))
def test_nested_ifttt_json_and_pack_validation_is_atomic(profile, payload):
    root, child = schedule_devices(profile)
    before = copy.deepcopy((root.state, child.state))
    rule = {**SCHEDULES["rule"], "cmd": b64encode(payload).decode("ascii")}
    with pytest.raises(InvalidPacket):
        schedule_exchange(root, {"t": "setIFTTT", **rule})
    assert (root.state, child.state) == before


def test_rule_json_shape_does_not_relax_the_lan_envelope():
    with pytest.raises(InvalidPacket, match="unsupported envelope"):
        decode_outer(b'{"i":1,"pack":"AAAA"}')


@pytest.mark.parametrize("profile", SCHEDULES["no_schedule_profiles"])
@pytest.mark.parametrize("kind", ("setT", "updateT", "queryT", "deleteT",
                                   "setIFTTT", "updateIFTTT", "queryIFTTT", "deleteIFTTT"))
def test_v30_closed_dispatch_has_no_schedule_ack(profile, kind):
    root, _ = schedule_devices(profile)
    before = copy.deepcopy(root.state)
    assert schedule_exchange(root, {"t": kind, **SCHEDULES["rule"]}) == []
    assert root.state == before


@pytest.mark.parametrize("profile", ("sim-w06av-v20", "sim-w06bv-v20"))
@pytest.mark.parametrize("kind", ("setIFTTT", "updateIFTTT", "queryIFTTT", "deleteIFTTT"))
def test_v20_timer_dispatch_does_not_invent_ifttt(profile, kind):
    root, _ = schedule_devices(profile)
    assert schedule_exchange(root, {"t": kind, **SCHEDULES["rule"]}) == []


@pytest.mark.parametrize("profile", SCHEDULES["timer_profiles"] + SCHEDULES["no_schedule_profiles"])
@pytest.mark.parametrize("kind", ("listT", "listIFTTT", "resT", "upgrade"))
def test_reporters_are_outputs_and_no_flash_contract_never_fakes_upgrade_ack(profile, kind):
    root, _ = schedule_devices(profile)
    before = copy.deepcopy(root.state)
    assert schedule_exchange(root, {"t": kind, "url": "http://invalid.example/firmware"}) == []
    assert root.state == before


@pytest.mark.parametrize("profile", SCHEDULES["rule_profiles"])
def test_old_network_metadata_owned_cache_and_host_setter_boundaries(profile):
    root, child = schedule_devices(profile)
    wifi_writable = profile in ("sim-w06av-v7", "sim-w06bv-v9")
    packet = {"t": "cmd", "sub": root.mac, "opt": ["host"], "p": ["synthetic.example"]}
    if wifi_writable:
        packet.update(opt=["apssid", "appsw", "host"],
                      p=["synthetic-ap", "", "synthetic.example"])
    expected = ["synthetic-ap", "", "dis.gree.com"] if wifi_writable else ["dis.gree.com"]
    reply = raw_request(root, packet)
    assert reply["p"] == reply["val"] == expected
    assert raw_status(root, root, packet["opt"])["dat"] == expected
    assert raw_status(root, child, packet["opt"])["dat"] == expected
    before = copy.deepcopy(root.state)
    for name, value in (("apssid", ""), ("apssid", "x" * 33),
                        ("appsw", "x" * 33), ("host", "x" * 21), ("host", "")):
        with pytest.raises(InvalidPacket):
            raw_request(root, {"t": "cmd", "sub": root.mac, "opt": [name], "p": [value]})
        assert root.state == before
    if not wifi_writable:
        for name in ("apssid", "appsw"):
            expected = "12345678" if name == "appsw" else ""
            reply = raw_request(root, {"t": "cmd", "sub": root.mac, "opt": [name], "p": ["new"]})
            assert reply["p"] == reply["val"] == [expected]
            assert root.state == before


@pytest.mark.parametrize("profile", ("sim-w06av-v20", "sim-w06av-v30",
                                     "sim-w06bv-v20", "sim-w06bv-v30"))
def test_later_network_metadata_echoes_ignored_fields_without_faking_stored_changes(profile):
    root, _ = schedule_devices(profile)
    assert raw_request(root, {"t": "cmd", "sub": root.mac,
                              "opt": ["name", "lock", "time"],
                              "p": ["later-name", -1, "2026-10-24 12:34:56"]})["r"] == 200
    assert root.profile.handler.advertise(root, {"t": "scan"})[0].inner["hid"] == root.profile.hid
    time = "" if profile in SCHEDULES["stale_clock_profiles"] else "2026-10-24 12:34:56"
    assert raw_status(root, root, ["hid", "name", "lock", "time"])["dat"] == [
        root.profile.hid, root.mac, -1, time]
    before = copy.deepcopy(root.state)
    for name in ("apssid", "appsw", "host"):
        reply = raw_request(root, {"t": "cmd", "sub": root.mac, "opt": [name], "p": ["new"]})
        assert reply["p"] == reply["val"] == [""]
        assert root.state == before
        assert raw_status(root, root, [name])["dat"] == [""]


@pytest.mark.parametrize("profile", SCHEDULES["rule_profiles"])
def test_old_child_rename_is_separate_from_root_metadata_and_suppresses_controls(profile):
    root, child, other = raw_devices(profile, count=2)
    other_name = other.name
    packet = {"t": "cmd", "sub": child.mac, "opt": ["name", "Pow"],
              "p": ["renamed-child", 1]}
    assert raw_request(root, packet)["val"] == ["renamed-child", 1]
    page = raw_request(root, {"t": "subDev", "mac": root.mac, "i": 0})
    assert [entry["name"] for entry in page["list"]] == ["renamed-child", other_name]
    assert raw_status(root, child, ["name", "Pow"])["dat"] == [root.mac, 0]
    assert raw_status(root, other, ["Pow"])["dat"] == [0]
    before = copy.deepcopy((root.state, child.state))
    with pytest.raises(InvalidPacket):
        raw_request(root, {**packet, "p": ["rejected-name", True]})
    assert child.name == "renamed-child" and (root.state, child.state) == before


@pytest.mark.parametrize("profile", SCHEDULES["timer_profiles"] + SCHEDULES["no_schedule_profiles"])
def test_clock_metadata_path_takes_precedence_without_applying_requested_child_controls(profile):
    root, child = schedule_devices(profile)
    name = child.name
    packet = {"t": "cmd", "sub": child.mac, "opt": ["Pow", "name", "time"],
              "p": [1, "ignored-name", "2026-10-24 12:34:56"]}
    time = "" if profile in SCHEDULES["stale_clock_profiles"] else "2026-10-24 12:34:56"
    expected_name = "ignored-name" if profile in SCHEDULES["rule_profiles"] else ""
    reply = raw_request(root, packet)
    assert reply["p"] == [1, ROOT_MAC, time]
    assert reply["val"] == [1, expected_name, time]
    assert child.name == name
    assert raw_status(root, child, ["Pow", "time"])["dat"] == [0, time]
    before = copy.deepcopy((root.state, child.state))
    with pytest.raises(InvalidPacket):
        raw_request(root, {**packet, "p": [1, "rejected-name", "2026-13-24 12:34:56"]})
    assert (root.state, child.state) == before and child.name == name


@pytest.mark.parametrize("profile", SCHEDULES["timer_profiles"] + SCHEDULES["no_schedule_profiles"])
def test_network_metadata_acknowledges_effective_values_not_requested_strings(profile):
    root, _ = schedule_devices(profile)
    initial_name = root.name
    proposed = "source-name"
    expected_name = proposed if profile in SCHEDULES["rule_profiles"] else ""
    assert raw_request(root, {"t": "cmd", "sub": ROOT_MAC, "opt": ["name"], "p": [proposed]}) == {
        "t": "res", "mac": ROOT_MAC, "r": 200, "opt": ["name"],
        "p": [ROOT_MAC], "val": [expected_name],
    }
    assert raw_status(root, root, ["Pow", "SetTem", "TemBody", "name"])["dat"] == [
        0, 0, 0, ROOT_MAC]
    assert root.name == initial_name
    duplicate = raw_request(root, {"t": "cmd", "sub": ROOT_MAC,
                                   "opt": ["name", "name", "lock", "lock"],
                                   "p": ["first", "last", 0, 1]})
    final_name = "last" if profile in SCHEDULES["rule_profiles"] else ""
    assert duplicate["p"] == [ROOT_MAC, ROOT_MAC, 1, 1]
    assert duplicate["val"] == [final_name, final_name, 1, 1]
    assert raw_status(root, root, ["name", "lock"])["dat"] == [ROOT_MAC, 1]


@pytest.mark.parametrize("profile", ("sim-w06av-v20", "sim-w06av-v30",
                                     "sim-w06bv-v20", "sim-w06bv-v30"))
def test_later_child_name_write_is_not_false_success(profile):
    root, child = schedule_devices(profile)
    before = copy.deepcopy((root.state, child.state))
    with pytest.raises(InvalidPacket):
        raw_request(root, {"t": "cmd", "sub": child.mac,
                           "opt": ["name", "Pow"], "p": ["not-applied", 1]})
    assert (root.state, child.state) == before
