"""Independent original-source literal expectations; no physical board claims."""
import base64
from copy import deepcopy
import json
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.catalog_early_m26s import PROFILES
from gree_emulator.wire import InvalidPacket, encode_reply

FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-early-m26s_research.json").read_text())
OPERATIONS = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-early-m26s-operations_research.json").read_text())


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    monkeypatch.setattr("gree_emulator.profiles.catalog_early_m26s.monotonic", lambda: 1000)


def device(selector=1, mid=None):
    profile = next(item for item in PROFILES if item.handler.selector == selector)
    return EmulatedDevice("m26s", FIXTURE["mac"], "", mid or profile.mids[0], FIXTURE["key"].encode(),
                          profile, deepcopy(dict(profile.initial_state)), room_c=None,
                          ambient_c=None, last_step=1000)


def send(unit, inner, index=0, uid=-2147483648):
    key = b"a3K8Bx%2r8Y7#xDh" if index else unit.key
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(json.dumps(inner).encode(), 16))
    return unit.profile.handler.handle(unit, {"t": "pack", "i": index, "uid": uid,
        "tcid": unit.mac, "pack": base64.b64encode(encrypted).decode()})


def status(unit, names):
    reply, = send(unit, {"t": "status", "cols": names})
    assert reply.outer == {"t": "pack", "i": 0, "uid": -2147483648, "cid": unit.mac, "tcid": ""}
    assert reply.inner["t"] == "dat" and reply.inner["r"] == 200
    assert encode_reply(reply).endswith(b"\n")
    return [reply.inner["cols"], reply.inner["dat"]]


@pytest.mark.parametrize("row", FIXTURE["tables"], ids=lambda row: str(row["selector"]))
def test_every_source_table_and_exact_mid_route(row):
    unit = device(row["selector"])
    assert list(unit.profile.handler.fields) == row["fields"]
    assert list(unit.profile.mids) == row["mids"]
    assert unit.profile.source_sha256 == FIXTURE["source_sha256"]
    assert unit.profile.hid == FIXTURE["hid"]
    assert unit.profile.max_request_bytes == 1024
    assert dict(unit.profile.initial_state) == dict.fromkeys(row["fields"], 0)


@pytest.mark.parametrize("row", FIXTURE["selected"], ids=lambda row: row["mid"])
def test_every_selected_getter_and_special_array_native_readback(row):
    unit = device(row["selector"], row["mid"])
    for field in row["fields"]:
        assert status(unit, [field["name"]]) == field["output"]
    for vector in row["commands"]:
        reply, = send(unit, {"t": "cmd", "opt": vector["names"], "p": vector["values"]})
        assert [reply.inner["opt"], reply.inner["p"]] == vector["status"]
        assert status(unit, vector["names"]) == vector["status"]


@pytest.mark.parametrize("field", FIXTURE["metadata"], ids=lambda field: field["name"])
def test_every_metadata_getter_and_literal_wire_type(field):
    assert status(device(), [field["name"]]) == field["output"]


@pytest.mark.parametrize("row", FIXTURE["scalar_boundaries"], ids=lambda row: f'{row["selector"]}-{row["name"]}')
def test_all_custom_scalar_callback_cache_boundaries(row):
    for value in row["values"]:
        unit = device(row["selector"])
        reply, = send(unit, {"t": "cmd", "opt": [row["name"]], "p": [value["input"]]})
        assert reply.inner["p"] == [value["cached"]]
        assert status(unit, [row["name"]]) == [[row["name"]], [value["cached"]]]


def test_native_encrypted_scan_bind_command_and_fresh_status():
    unit = device(1, "828211")
    for vector in FIXTURE["wire"]:
        if vector["index"] is None:
            reply, = unit.profile.handler.advertise(unit, vector["request"])
        else:
            reply, = send(unit, vector["request"], vector["index"])
        assert reply.inner == vector["expected"]
        assert reply.outer["i"] == vector["outer_index"]
        encoded = encode_reply(reply)
        assert encoded.endswith(b"\n") is vector["outer_lf"]
        outer = json.loads(encoded)
        key = b"a3K8Bx%2r8Y7#xDh" if outer["i"] else unit.key
        plain = unpad(AES.new(key, AES.MODE_ECB).decrypt(base64.b64decode(outer["pack"])), 16)
        assert not plain.endswith(b"\n") and json.loads(plain) == vector["expected"]


def test_all_native_timer_operations_literal_storage_and_framing():
    unit = device(0)
    for vector in FIXTURE["timers"]:
        reply, = send(unit, vector["request"])
        assert reply.inner == vector["expected"]
        assert encode_reply(reply).endswith(b"\n") is vector["outer_lf"]


def test_synthetic_timer_executes_source_scalar_cache_and_disables_one_shot():
    unit = device(0, "828c02")
    timer = {"t": "setT", "id": 1, "name": "synthetic", "enable": 0,
             "hr": 0, "min": 1, "sec": 0, "tz": 0, "week": [],
             "cmd": [{"mac": [unit.mac], "opt": ["WsetTmpC", "Pow"], "p": [10, 257]}]}
    send(unit, timer)
    send(unit, {"t": "cmd", "opt": ["time"], "p": ["2026-01-01 00:01:00"]})
    assert status(unit, ["Pow", "WsetTmpC", "time"])[1] == [257, 0, "2026-01-01 00:01:00"]
    reply, = send(unit, {"t": "queryT", "index": 0, "count": 10})
    assert reply.inner["list"][0]["enable"] == 1


def test_unknown_readonly_duplicate_and_first_hole_status_rules():
    unit = device()
    reply, = send(unit, {"t": "cmd", "opt": ["Temperature", "unknown", "Temperature", "name"],
                         "p": [257, 9, -1, "ignored"]})
    assert reply.inner["opt"] == ["Temperature", "Temperature", "name"]
    assert reply.inner["p"] == [-1, -1, ""]
    assert status(unit, ["Temperature", "unknown", "Temperature"])[1] == [-1, -1]
    assert status(unit, ["Pow", "", "Temperature"])[0] == ["Pow"]
    assert status(unit, ["Pow", "0123456789abcdef", "Temperature"])[0] == ["Pow"]
    assert status(unit, ["Pow"]*45) == [[], []]
    assert status(unit, ["BuzzerCtrl", "Buzz", "Beep"]) == [[], []]
    assert unit.profile.handler.thermal_target(unit) is None


@pytest.mark.parametrize("bad", [True, None, "1", 1.1, [], {}, 1 << 31])
def test_atomic_safety_policy_and_malformed_recovery(bad):
    unit = device()
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        send(unit, {"t": "cmd", "opt": ["Pow", "Temperature"], "p": [1, bad]})
    assert unit.state == before and unit.last_step == 1000
    send(unit, {"t": "cmd", "opt": ["Pow"], "p": [257]})
    assert status(unit, ["Pow"])[1] == [257]


def test_unavailable_native_long_names_are_not_silently_reclassified_unsupported():
    unit = device(4)
    reply, = send(unit, {"t": "cmd", "opt": ["WaterValueSelect", "WaterFlow"], "p": [257, 12]})
    assert reply.inner["opt"] == [] and reply.inner["p"] == []
    assert unit.state["WaterValueSelect"] == 257
    assert status(unit, ["WaterFlow"])[1] == [12]


def test_report_client_and_array_limits_are_local_synthetic_backing():
    unit = device(8)
    reply, = send(unit, {"t": "cmd", "opt": ["ReportClientID"], "p": ["synthetic-peer"]})
    assert reply.inner["p"] == ["synthetic-peer"]
    assert status(unit, ["ReportClientID"])[1] == ["synthetic-peer"]
    send(unit, {"t": "cmd", "opt": ["CloudMenu"], "p": [[256, -1, 257]]})
    assert unit.state["_tables"]["cloud_menu"] == [0, 255, 1]+[0]*42
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        send(unit, {"t": "cmd", "opt": ["CloudMenu"], "p": [[0]*46]})
    assert unit.state == before


def test_keys_targets_rebind_isolation_and_restart():
    unit, other = device(), device()
    send(unit, {"t": "cmd", "opt": ["Pow"], "p": [7]}, index=-1)
    reply, = send(unit, {"t": "bind", "mac": unit.mac}, index=256)
    assert reply.outer["i"] == 1 and reply.inner["key"] == FIXTURE["key"]
    assert status(unit, ["Pow"])[1] == [7]
    assert status(other, ["Pow"])[1] == [0]
    assert status(device(), ["Pow"])[1] == [0]
    for inner in ({"t": "status", "mac": "wrong", "cols": ["Pow"]},
                  {"t": "status", "sub": unit.mac+"01", "cols": ["Pow"]}):
        with pytest.raises(InvalidPacket):
            send(unit, inner)
    with pytest.raises(InvalidPacket):
        unit.profile.handler.handle(unit, {"t": "pack", "tcid": "wrong", "i": 0, "pack": ""})
    with pytest.raises(InvalidPacket):
        unit.profile.handler.handle(unit, {"t": "pack", "tcid": unit.mac, "i": 2, "pack": {"t": "bind"}})


def test_upgrade_and_surver_do_not_fabricate_completion_acknowledgements():
    unit = device()
    assert send(unit, {"t": "surver", "mac": unit.mac}) == []
    assert send(unit, {"t": "upgrade", "url": "http://example.invalid/m26s.bin"}) == []
    assert unit.state["_tables"]["upgrade_url"] == "http://example.invalid/m26s.bin"


@pytest.mark.parametrize("row", OPERATIONS["bank2_selected"], ids=lambda row: row["mid"])
def test_independent_bank_two_selected_getters_and_arrays(row):
    unit = device(row["selector"], row["mid"])
    for field in row["fields"]:
        assert status(unit, [field["name"]]) == field["output"]
    for vector in row["commands"]:
        reply, = send(unit, {"t": "cmd", "opt": vector["names"], "p": vector["values"]})
        assert [reply.inner["opt"], reply.inner["p"]] == vector["status"]


def test_independent_bank_two_all_metadata_and_timer_operations():
    unit = device(0)
    for field in OPERATIONS["bank2_metadata"]:
        assert status(unit, [field["name"]]) == field["output"]
    for vector in OPERATIONS["bank2_timers"]:
        reply, = send(unit, vector["request"])
        assert reply.inner == vector["expected"]
        assert encode_reply(reply).endswith(b"\n") is vector["outer_lf"]


@pytest.mark.parametrize("bank", ("bank1_peripheral", "bank2_peripheral"))
def test_both_original_banks_wlan_upgrade_surver_and_report_client(bank):
    unit = device(1, "828211")
    for vector in OPERATIONS[bank]["report_client"]:
        reply, = send(unit, {"t": "cmd", "opt": ["ReportClientID"], "p": [vector["input"]]})
        assert [reply.inner["opt"], reply.inner["p"]] == vector["status"]
    for vector in OPERATIONS[bank]["operations"]:
        if vector["request"]["t"] == "wlan":
            replies = unit.profile.handler.handle(unit, vector["request"])
            assert [reply.outer for reply in replies] == vector["expected"]
            assert encode_reply(replies[0]).endswith(b"\n")
            assert status(unit, ["host"])[1] == [""]
        else:
            assert send(unit, vector["request"]) == vector["expected"]
