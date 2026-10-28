"""Literal exact-source descriptor closure, not emulator-generated expectations."""
import copy
import json
from pathlib import Path

import pytest

from gree_emulator.wire import InvalidPacket
from tests.test_emulator import vector_device
from tests.test_emulator_atw import GENERIC_KEY, MAC, handle, status

EVIDENCE = json.loads((Path(__file__).parent / "fixtures/emulator/atw-closure_research.json").read_text())
NAMESPACE = json.loads((Path(__file__).parent / "fixtures/emulator/atw-namespace_research.json").read_text())


@pytest.mark.parametrize("source", EVIDENCE["firmwares"], ids=lambda row: row["source_sha256"][:12])
@pytest.mark.parametrize("mid", ["9300", "9301", "9302"])
def test_exact_source_raw_namespace_is_not_a_same_mid_union(source, mid):
    device = vector_device({
        "profile": source["profile_prefix"] + mid, "mid": mid, "initial_state": {},
        "device": {"room_c": 26, "ambient_c": 26},
    })
    assert device.profile.source_sha256 == source["source_sha256"]
    controls = source["controls"]
    requested = list(range(256, 256 + len(controls)))
    reply, = handle(device, {"t": "cmd", "opt": controls, "p": requested})
    assert reply.inner == {"t": "res", "r": 200, "opt": controls, "p": requested, "val": requested}
    assert status(device, controls)["dat"] == source["staged_status_vector"]
    assert status(device, ["EVU"])["cols"] == (["EVU"] if source["has_evu"] else [])
    if not source["has_evu"]:
        with pytest.raises(InvalidPacket):
            handle(device, {"t": "cmd", "opt": ["Pow", "EVU"], "p": [0, 1]})
    device.profile.handler.receive_report(device, bytes.fromhex(EVIDENCE["report_vector"]["frame_hex"]))
    assert status(device, EVIDENCE["sensors"])["dat"] == EVIDENCE["report_vector"]["dat"]
    assert status(device, EVIDENCE["empty_metadata"])["dat"] == []
    assert status(device, EVIDENCE["empty_metadata"])["cols"] == EVIDENCE["empty_metadata"]
    assert status(device, ["hid", "ModelType", "mid"])["dat"] == [source["hid"], "", mid]
    discovery, = device.profile.handler.advertise(device, {"t": "scan"})
    assert ("hid" in discovery.inner) is source["discovery_hid"]
    assert discovery.inner["ModelType"] == ""
    assert discovery.inner["ver"] == source["runtime_ver"]
    assert status(device, ["ver", "host", "bc", "model", "series", "brand", "catalog"])["dat"] == [
        source["runtime_ver"], "dis.gree.com", "", "", "", "", "",
    ]


def test_v604_evu_duplicate_requests_stage_low_byte_and_do_not_touch_report():
    source = next(row for row in EVIDENCE["firmwares"] if row["source_sha256"].startswith("37ab39b7"))
    device = vector_device({
        "profile": source["profile_prefix"] + "9300", "mid": "9300", "initial_state": {},
    })
    result, = handle(device, {"t": "cmd", "opt": ["EVU", "Emegcy", "EVU"], "p": [255, 255, 256]})
    assert result.inner["val"] == [255, 255, 256]
    assert status(device, ["EVU", "Emegcy", "EVU"])["dat"] == [0, 0, 0]
    assert device.state["Emegcy"] == 255


def source_device(source, alternate=False):
    suffix = "raw-806004" if alternate else "9300"
    return vector_device({"profile": source["profile_prefix"] + suffix,
                          "mid": "806004" if alternate else "9300", "initial_state": {}})


@pytest.mark.parametrize("source", EVIDENCE["firmwares"], ids=lambda row: row["source_sha256"][:12])
@pytest.mark.parametrize("alternate", [False, True])
def test_every_original_network_record_retains_getter_cardinality(source, alternate):
    device = source_device(source, alternate)
    expected = {
        "vender": "1", "bc": "", "mid": device.mid, "model": "", "series": "",
        "apssid": "", "appsw": "", "brand": "", "catalog": "", "hid": source["hid"],
        "host": "dis.gree.com", "mac": MAC, "name": "Emulator Office",
        "time": "1970-01-01 00:00:00", "ver": source["runtime_ver"], "ModelType": "", "rssi": -1,
    }
    if not alternate:
        expected.update(Mod=1, CoWatOutTemSet=18, HeWatOutTemSet=35, WatBoxTemSet=50,
                        CoHomTemSet=24, HeHomTemSet=24, RmoHomTemHi=126)
    names = NAMESPACE["network_records"] + (["EVU"] if source["has_evu"] else [])
    for start in range(0, len(names), 12):
        cols = names[start:start + 12]
        assert status(device, cols) == {
            "t": "dat", "r": 200, "mac": MAC, "cols": cols,
            "dat": [expected.get(name, 0) for name in cols if name not in EVIDENCE["empty_metadata"]],
        }
    assert status(device, [" ModTmr5", "ModTmr5"])["cols"] == [" ModTmr5"]


@pytest.mark.parametrize("source", EVIDENCE["firmwares"], ids=lambda row: row["source_sha256"][:12])
def test_alternate_mid_has_separate_raw_controls_unsigned16_reports_and_no_room(source):
    device = source_device(source, True)
    assert device.profile.handler.thermal_target(device) is None
    assert device.room_c is None and device.ambient_c is None
    names = NAMESPACE["alternate_controls"]
    requested = list(range(256, 266))
    assert handle(device, {"t": "cmd", "opt": names, "p": requested})[0].inner["val"] == requested
    assert status(device, names)["dat"] == list(range(10))
    report = NAMESPACE["alternate_report"]
    device.profile.handler.receive_report(device, bytes.fromhex(report["frame_hex"]))
    assert status(device, NAMESPACE["alternate_sensors"])["dat"] == report["dat"]
    assert status(device, ["AllInWatTemHi", "AllInWatTem", "TemUn", "AllErr"])["dat"] == [0, 65535, 1, 0]
    with pytest.raises(InvalidPacket):
        handle(device, {"t": "cmd", "opt": ["Pow", "TemUn"], "p": [0, 1]})
    handle(device, {"t": "cmd", "opt": ["Pow"], "p": [0]})
    assert status(device, NAMESPACE["alternate_sensors"])["dat"] == report["dat"]
    assert status(source_device(source, True), NAMESPACE["alternate_sensors"])["dat"] == [0] * 15


@pytest.mark.parametrize("source", EVIDENCE["firmwares"], ids=lambda row: row["source_sha256"][:12])
@pytest.mark.parametrize("alternate", [False, True])
def test_native_timer_local_schema_mutation_and_single_index_query(source, alternate):
    device = source_device(source, alternate)
    assert handle(device, {"t": "queryT", "index": 2, "count": 3})[0].inner == NAMESPACE["timer_empty"]
    request = copy.deepcopy(NAMESPACE["timer_request"])
    reply, = handle(device, request, selector=1, key=GENERIC_KEY)
    assert reply.inner == NAMESPACE["timer_ack"]
    assert reply.outer["i"] == 0 and reply.key == device.key
    reply, = handle(device, {"t": "queryT", "index": 2, "count": 3})
    assert reply.inner == NAMESPACE["timer_query"]
    assert handle(device, {"t": "queryT", "index": 3, "count": 2})[0].inner == {
        "t": "listT", "total": 10, "index": 3, "list": [],
    }
    request.update(t="updateT", name="changed")
    assert handle(device, request)[0].inner == NAMESPACE["timer_ack"]
    assert handle(device, {"t": "queryT", "index": 2, "count": 1})[0].inner["list"][0]["name"] == "changed"
    assert handle(device, {"t": "deleteT", "id": 2})[0].inner == NAMESPACE["timer_ack"]
    assert handle(device, {"t": "queryT", "index": 2, "count": 1})[0].inner == NAMESPACE["timer_empty"]


@pytest.mark.parametrize("field,value", [
    ("id", 10), ("enable", 2), ("hr", 24), ("min", 60), ("sec", 61),
    ("week", [0] * 6), ("name", "x" * 32), ("tz", True), ("cmd", []),
])
def test_invalid_timer_batch_is_atomic(field, value):
    source = EVIDENCE["firmwares"][0]
    device = source_device(source)
    before = copy.deepcopy(device.state)
    request = copy.deepcopy(NAMESPACE["timer_request"])
    request[field] = value
    with pytest.raises(InvalidPacket):
        handle(device, request)
    assert device.state == before


@pytest.mark.parametrize("source", EVIDENCE["firmwares"], ids=lambda row: row["source_sha256"][:12])
def test_metadata_ack_uses_final_cache_and_refreshes_discovery(source):
    device = source_device(source)
    names = ["name", "lock", "name", "time", "lock", "Pow"]
    values = ["first", 1, "last", "2026-10-24 06:07:08", -1, 0]
    expected = ["last", -1, "last", "2026-10-24 06:07:08", -1, 0]
    reply, = handle(device, {"t": "cmd", "opt": names, "p": values})
    assert reply.inner == {"t": "res", "r": 200, "opt": names, "p": expected, "val": expected}
    assert status(device, ["name", "time", "lock"])["dat"] == ["last", "2026-10-24 06:07:08", -1]
    scan, = device.profile.handler.advertise(device, {"t": "scan"})
    assert scan.inner["name"] == "last" and scan.inner["lock"] == -1


@pytest.mark.parametrize("source", EVIDENCE["firmwares"], ids=lambda row: row["source_sha256"][:12])
def test_upgrade_ack_is_only_original_url_acceptance_and_isolated_staging(source):
    device = source_device(source)
    other = source_device(source)
    reply, = handle(device, NAMESPACE["upgrade_request"])
    assert reply.inner == NAMESPACE["upgrade_ack"]
    assert reply.outer["i"] == 1 and reply.key == GENERIC_KEY
    assert device.state["_atw_upgrade_pending"] is True
    assert device.state["_atw_upgrade_url"] == NAMESPACE["upgrade_request"]["url"]
    assert "_atw_upgrade_url" not in other.state
    assert "_atw_upgrade_url" not in source_device(source).state
    before = copy.deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        handle(device, {"t": "upgrade", "url": "x" * 160})
    assert device.state == before


@pytest.mark.parametrize("source", EVIDENCE["firmwares"], ids=lambda row: row["source_sha256"][:12])
@pytest.mark.parametrize("alternate", [False, True])
def test_source_specific_ap_metadata_mutation_is_not_a_version_or_mid_union(source, alternate):
    device = source_device(source, alternate)
    request = {"t": "cmd", "opt": ["apssid", "appsw", "apssid"],
               "p": ["first", "synthetic-password", "last"]}
    if source["metadata_credentials_writable"]:
        reply, = handle(device, request)
        expected = ["last", "synthetic-password", "last"]
        assert reply.inner == {"t": "res", "r": 200, "opt": request["opt"],
                               "p": expected, "val": expected}
        assert status(device, ["apssid", "appsw"])["dat"] == expected[:2]
        handle(device, {"t": "cmd", "opt": ["appsw"], "p": [""]})
        assert status(device, ["appsw"])["dat"] == [""]
    else:
        before = copy.deepcopy(device.state)
        with pytest.raises(InvalidPacket):
            handle(device, request)
        assert device.state == before
        assert status(device, ["apssid", "appsw"])["dat"] == ["", ""]


@pytest.mark.parametrize("name,value", [
    ("name", ""), ("name", "x" * 80), ("lock", True), ("lock", 2147483648),
    ("time", "2026-02-30 06:07:08"), ("time", "2026- 1-01 06:07:08"),
    ("apssid", ""), ("apssid", "x" * 32), ("appsw", "x" * 32),
])
def test_invalid_metadata_batch_does_not_advance_or_partially_change_cache(name, value):
    device = source_device(EVIDENCE["firmwares"][0])
    before = (copy.deepcopy(device.state), device.name, device.room_c, device.last_step)
    with pytest.raises(InvalidPacket):
        handle(device, {"t": "cmd", "opt": ["Pow", "name", name], "p": [1, "changed", value]})
    assert (device.state, device.name, device.room_c, device.last_step) == before


@pytest.mark.parametrize("envelope", [
    {"uid": -2147483649}, {"uid": 2147483648}, {"i": 2147483648},
])
def test_envelope_rejects_integers_outside_original_signed32_parser_storage(envelope):
    device = source_device(EVIDENCE["firmwares"][0])
    with pytest.raises(InvalidPacket):
        handle(device, {"t": "status", "mac": MAC, "cols": ["Pow"]}, **envelope)
