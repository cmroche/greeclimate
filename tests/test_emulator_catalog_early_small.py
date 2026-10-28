"""Independent literal Small source tables and safe bounded wire contracts."""
import base64
from copy import deepcopy
import json
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.catalog_early_small import PROFILES
from gree_emulator.wire import InvalidPacket, encode_reply

FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-early-small_research.json").read_text())
DESCRIPTOR_FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-early-small-descriptors_research.json").read_text())
KEY = b"a3K8Bx%2r8Y7#xDh"


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch):
    monkeypatch.setattr("gree_emulator.profiles.catalog_early_small.monotonic", lambda: 1000)


def device(profile_id="sim-w05n-v103"):
    profile = next(profile for profile in PROFILES if profile.id == profile_id)
    return EmulatedDevice("small", FIXTURE["mac"], FIXTURE["name"], profile.mids[0],
                          FIXTURE["session_key"].encode(), profile,
                          deepcopy(dict(profile.initial_state)), room_c=None,
                          ambient_c=None, last_step=1000)


def packet(unit, inner, *, index=0, uid=42, key=None, cid="app", tcid=None):
    if key is None:
        key = KEY if index else unit.key
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(json.dumps(inner, separators=(",", ":")).encode(), 16))
    return {"t": "pack", "i": index, "uid": uid, "cid": cid,
            "tcid": unit.mac if tcid is None else tcid,
            "pack": base64.b64encode(encrypted).decode()}


def decode(reply):
    raw = encode_reply(reply)
    outer = json.loads(raw)
    key = KEY if outer["i"] else FIXTURE["session_key"].encode()
    inner = json.loads(unpad(AES.new(key, AES.MODE_ECB).decrypt(base64.b64decode(outer["pack"])), 16))
    return raw, outer, inner


def exchange(unit, inner, **kwargs):
    replies = unit.profile.handler.handle(unit, packet(unit, inner, **kwargs))
    if not replies:
        assert inner["t"] == "cmd"
        return None, None, None
    reply, = replies
    return decode(reply)


@pytest.mark.parametrize("profile_id", ["sim-w05n-v103", "sim-w05w-v12"])
def test_literal_no_command_ack_and_independent_fresh_status(profile_id):
    unit = device(profile_id)
    for vector in FIXTURE["vectors"]:
        raw, outer, inner = exchange(unit, vector["request"])
        assert inner == vector["response"]
        if inner is None:
            assert raw is outer is None
            continue
        assert outer["i"] == vector["selector"] and outer["uid"] == 42
        assert outer["cid"] == unit.mac and outer["tcid"] == ""
        assert raw.endswith(b"\n") == vector["newline"]
        assert not raw.endswith(b"\n\n")


@pytest.mark.parametrize("row", FIXTURE["sources"], ids=lambda row: row["profile"])
def test_every_source_qualified_scalar_and_exact_identity(row):
    unit = device(row["profile"])
    handler = unit.profile.handler
    assert unit.profile.source_sha256 == row["source_sha256"]
    assert unit.profile.hid == row["hid"] and unit.mid == row["mid"]
    assert set(handler.fields) == set(row["scalar_names"])
    assert set(unit.state) == set(row["scalar_names"])
    assert set(handler.names) == set(row["scalar_names"] + row["metadata_names"])
    for name in row["scalar_names"]:
        _, _, before = exchange(unit, {"t": "status", "cols": [name]})
        assert before["cols"] == [name] and before["dat"] == [0]
        assert exchange(unit, {"t": "cmd", "opt": [name, name], "p": [65536, -1]}) == (None, None, None)
        _, _, fresh = exchange(unit, {"t": "status", "cols": [name]})
        assert fresh["dat"] == [65535]
    assert unit.profile.handler.thermal_target(unit) is None and unit.room_c is None


@pytest.mark.parametrize("row", FIXTURE["sources"], ids=lambda row: row["profile"])
def test_complete_metadata_names_keep_native_missing_value_distinction(row):
    unit = device(row["profile"])
    expected = {"host": "", "name": "small", "time": "1970-01-01 00:00:00",
                "lat": "", "lon": "", "vender": "0", "bc": "0" * 32,
                "mid": "910001" if row["mid"] == "9100" else row["mid"],
                "hid": row["hid"], "mac": "020000000061", "ver": "",
                "InHid": "", "OEEPHid": "", "rssi": 0}
    for name in row["metadata_names"]:
        _, _, status = exchange(unit, {"t": "status", "cols": [name]})
        assert status["cols"] == [name]
        assert status["dat"] == ([expected[name]] if name in row["metadata_readable"] else [])
    _, _, status = exchange(unit, {"t": "status", "cols": ["BuzzerCtrl", "Buzzer_ON_OFF"]})
    assert status["cols"] == status["dat"] == []


def test_status_first_hole_unknowns_duplicates_and_exact_capacity_bug():
    unit = device()
    _, _, status = exchange(unit, {"t": "status", "cols": ["Pow", "unknown", "Pow", "", "hid"]})
    assert status["cols"] == ["Pow", "Pow"] and status["dat"] == [0, 0]
    _, _, status = exchange(unit, {"t": "status", "cols": ["Pow", "x" * 16, "hid"]})
    assert status["cols"] == ["Pow"] and status["dat"] == [0]
    _, _, status = exchange(unit, {"t": "status", "cols": ["Pow"] * 29})
    assert status["dat"] == [0] * 29
    _, _, status = exchange(unit, {"t": "status", "cols": ["Pow"] * 30})
    assert status["cols"] == status["dat"] == []
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "status", "cols": ["Pow"] * 31})


@pytest.mark.parametrize("bad", [True, False, None, [], {}, 1.0, 1 << 31, -(1 << 31) - 1])
def test_command_validation_and_reply_preflight_are_atomic(bad):
    unit = device()
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "cmd", "opt": ["Pow", "Mod"], "p": [1, bad]})
    assert unit.state == before and unit.last_step == 1000
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "status", "cols": ["hid"] * 29})
    assert unit.state == before


def test_n_enumeration_and_deliberately_shared_alias_cache():
    unit = device()
    _, _, listing = exchange(unit, {"t": "subDev", "mac": unit.mac, "i": 0})
    assert listing == {"t": "subList", "c": 1, "i": 0, "r": 200, "list": [
        {"mac": "02000000006101", "mid": "910001", "name": "GreeHot", "model": "gree", "lock": 0}]}
    _, _, listing = exchange(unit, {"t": "subDev", "mac": unit.mac, "i": 1})
    assert listing == {"t": "subList", "c": 1, "i": 1, "r": 200, "list": []}
    assert exchange(unit, {"t": "cmd", "mac": unit.mac, "sub": unit.mac + "01", "opt": ["Pow"], "p": [7]}) == (None, None, None)
    _, _, status = exchange(unit, {"t": "status", "mac": "02000000006201", "cols": ["Pow"]})
    assert status["mac"] == "02000000006201" and status["dat"] == [7]
    _, _, root = exchange(unit, {"t": "status", "mac": unit.mac, "cols": ["Pow"]})
    assert root["dat"] == [7]


def test_rebind_key_width_wrong_target_isolation_and_restart():
    unit = device("sim-w05w-v12")
    exchange(unit, {"t": "cmd", "opt": ["Pow"], "p": [7]}, index=256)
    _, outer, bound = exchange(unit, {"t": "bind", "mac": unit.mac}, index=-1, uid=-(1 << 31))
    assert outer["i"] == 1 and outer["uid"] == -(1 << 31) and bound["key"] == FIXTURE["session_key"]
    _, _, status = exchange(unit, {"t": "status", "cols": ["Pow"]})
    assert status["dat"] == [7]
    for inner in ({"t": "bind", "mac": "020000000062"},
                  {"t": "status", "mac": "020000000062", "cols": ["Pow"]},
                  {"t": "cmd", "sub": unit.mac, "opt": ["Pow"], "p": [1]}):
        before = deepcopy(unit.state)
        with pytest.raises(InvalidPacket):
            exchange(unit, inner)
        assert unit.state == before
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "status", "cols": ["Pow"]}, index=256, key=unit.key)
    other = device("sim-w05w-v12")
    _, _, status = exchange(other, {"t": "status", "cols": ["Pow"]})
    assert status["dat"] == [0]


def test_metadata_command_type_distinction_and_pending_name():
    for profile_id in ("sim-w05n-v103", "sim-w05w-v12"):
        unit = device(profile_id)
        assert exchange(unit, {"t": "cmd", "opt": ["time"], "p": ["2026-01-01 00:00:00"]}) == (None, None, None)
        _, _, fresh = exchange(unit, {"t": "status", "cols": ["time"]})
        assert fresh["dat"] == ["2026-01-01 00:00:00"]
    unit = device("sim-w05w-v12")
    assert exchange(unit, {"t": "cmd", "opt": ["name", "host"], "p": ["pending", "local"]}) == (None, None, None)
    _, _, fresh = exchange(unit, {"t": "status", "cols": ["name", "host"]})
    assert fresh["dat"] == ["small", "local"]


def test_timer_create_query_update_execute_delete_and_upgrade_boundary(monkeypatch):
    unit = device()
    exchange(unit, {"t": "cmd", "opt": ["time"], "p": ["2026-01-01 07:59:59"]})
    timer = {"t": "setT", "id": 257, "name": "morning", "enable": 0, "hr": 8,
             "min": 0, "sec": 0, "tz": 0, "week": [],
             "cmd": [{"mac": [unit.mac], "opt": ["Pow"], "p": [1]}]}
    raw, _, ack = exchange(unit, timer)
    assert ack == {"t": "resT", "r": 200} and not raw.endswith(b"\n")
    _, _, listing = exchange(unit, {"t": "queryT", "index": 0, "count": 0})
    assert listing == {"t": "listT", "total": 0, "index": 0, "list": [
        {"id": 1, "name": "morning", "enable": 0, "hr": 8, "min": 0, "sec": 0,
         "week": [0] * 7, "cmd": timer["cmd"]}]}
    monkeypatch.setattr("gree_emulator.profiles.catalog_early_small.monotonic", lambda: 1002)
    _, _, fresh = exchange(unit, {"t": "status", "cols": ["Pow"]})
    assert fresh["dat"] == [1]
    exchange(unit, {**timer, "t": "updateT", "name": "renamed"})
    exchange(unit, {"t": "deleteT", "id": 1})
    _, _, listing = exchange(unit, {"t": "queryT", "index": 0, "count": 3})
    assert listing == {"t": "listT", "total": 3, "index": 0}
    replies = unit.profile.handler.handle(unit, packet(unit, {"t": "upgrade", "url": "https://example.invalid/firmware.bin"}))
    assert replies == [] and unit.state["_small"]["upgrade"] == "https://example.invalid/firmware.bin"


@pytest.mark.parametrize("profile_id", ["sim-w05w-v12", "sim-w05xf-v11"])
def test_plain_upgrade_and_survey_reply_selectors(profile_id):
    unit = device(profile_id)
    for inner in ({"t": "surver", "mac": unit.mac},
                  {"t": "upgrade", "url": "https://example.invalid/image.bin"}):
        reply, = unit.profile.handler.handle(unit, packet(unit, inner))
        assert reply.inner is None
        assert encode_reply(reply) == b'{"t":"ret","r":200,"mac":"020000000061"}\n'


@pytest.mark.parametrize("profile_id", ["sim-w05n-v103", "sim-w05w-v12", "sim-w05xf-v11"])
def test_scalar_timer_records_store_only_first_source_option(profile_id):
    unit = device(profile_id)
    command = {"mac": [unit.mac], "opt": ["Pow", "Mod"], "p": [1, 2]}
    exchange(unit, {"t": "setT", "id": 1, "name": "bounded", "enable": 1,
                    "hr": 8, "min": 0, "sec": 0, "tz": 0, "week": [], "cmd": [command]})
    _, _, listing = exchange(unit, {"t": "queryT", "index": 0, "count": 0})
    assert listing["list"][0]["cmd"] == [{"mac": [unit.mac], "opt": ["Pow"], "p": [1]}]


@pytest.mark.parametrize("profile_id", [profile.id for profile in PROFILES])
def test_clock_uses_source_unpadded_year_and_survives_next_tick(profile_id, monkeypatch):
    unit = device(profile_id)
    exchange(unit, {"t": "cmd", "opt": ["time"], "p": ["0001-01-02 03:04:05"]})
    _, _, status = exchange(unit, {"t": "status", "cols": ["time"]})
    assert status["dat"] == ["1-01-02 03:04:05"]
    monkeypatch.setattr("gree_emulator.profiles.catalog_early_small.monotonic", lambda: 1001)
    _, _, status = exchange(unit, {"t": "status", "cols": ["time"]})
    assert status["dat"] == ["1-01-02 03:04:06"]


@pytest.mark.parametrize("row", DESCRIPTOR_FIXTURE["tables"], ids=lambda row: row["table"])
def test_every_selected_descriptor_source_table_and_mutation_prefix(row):
    unit = device(row["profile"])
    assert unit.profile.source_sha256 == row["source_sha256"]
    assert unit.profile.hid == row["hid"] and list(unit.profile.mids) == row["mids"]
    assert list(unit.profile.handler.fields) == [item["name"] for item in row["properties"]]
    for item in row["properties"]:
        unit = device(row["profile"])
        name = item["name"]
        _, _, before = exchange(unit, {"t": "status", "cols": [name]})
        assert before["cols"] == [name] and before["dat"] == [item["initial"]]
        assert exchange(unit, {"t": "cmd", "opt": [name], "p": [1]}) == (None, None, None)
        _, _, after = exchange(unit, {"t": "status", "cols": [name]})
        assert after["cols"] == [name] and after["dat"] == [item["command_one"]]
    assert unit.room_c is None and unit.profile.handler.thermal_target(unit) is None


@pytest.mark.parametrize("row", DESCRIPTOR_FIXTURE["tables"], ids=lambda row: row["table"])
def test_descriptor_metadata_has_no_invented_values_or_namespace_union(row):
    unit = device(row["profile"])
    values = {"host": "", "name": "small", "time": "1970-01-01 00:00:00", "hid": row["hid"], "rssi": 0}
    for name in row["metadata_names"]:
        _, _, status = exchange(unit, {"t": "status", "cols": [name]})
        assert status["cols"] == [name]
        assert status["dat"] == ([values[name]] if name in row["metadata_readable"] else [])
    _, _, status = exchange(unit, {"t": "status", "cols": ["TemSen", "BuzzerCtrl", "Buzzer_ON_OFF"]})
    assert status["cols"] == status["dat"] == []


def test_descriptor_int32_cache_is_not_a_mask_clamped_polling_preset():
    unit = device("sim-w04r-v203-fan")
    for value in (256, 65536, -1, -(1 << 31), (1 << 31) - 1):
        assert exchange(unit, {"t": "cmd", "opt": ["Pow", "WdSpd"], "p": [value, value]}) == (None, None, None)
        _, _, fresh = exchange(unit, {"t": "status", "cols": ["Pow", "WdSpd"]})
        assert fresh["dat"] == [value, value]
    _, _, status = exchange(unit, DESCRIPTOR_FIXTURE["default_vector"]["request"])
    expected = deepcopy(DESCRIPTOR_FIXTURE["default_vector"]["response"])
    expected["dat"][0] = (1 << 31) - 1
    assert status == expected


@pytest.mark.parametrize(("selector", "matches"), ((0, True), (0, False), (1, True)))
def test_w04r_native_bind_key_selection_and_reply_framing(selector, matches, monkeypatch):
    unit = device("sim-w04r-v203-air")
    assert unit.profile.handler.accept_any_target
    unit.mac, unit.key = "020000000061", b"W04RProbeKey0001"
    generic_key = b"W04RProbeKey0002"
    monkeypatch.setattr("gree_emulator.profiles.catalog_early_small.KEY", generic_key)
    packs = {
        (0, True): "8oPXDTShsS03Y7IUBsRuNIbLU2gZgodId/0Hb5cZG4pCDUP5OTDlpJZnhvpl+5TH",
        (0, False): "8oPXDTShsS03Y7IUBsRuNPbNHZYiEN+sCqZO70nwai9CDUP5OTDlpJZnhvpl+5TH",
        (1, True): "QE+CJe8w+EltqPLQkzBBSL4FzdZVS/29DUZPaXK+a054mn18T48Td+CoajBLaWiD",
    }
    request = {"t": "pack", "i": selector, "tcid": "0123456789ab", "uid": 4660,
               "cid": "TEST_CID", "pack": packs[selector, matches]}
    if not matches:
        with pytest.raises(InvalidPacket):
            unit.profile.handler.handle(unit, request)
        return
    reply = unit.profile.handler.handle(unit, request)[0]
    outer = json.loads(encode_reply(reply))
    inner = json.loads(unpad(
        AES.new(generic_key, AES.MODE_ECB).decrypt(base64.b64decode(outer["pack"])), 16,
    ))
    assert outer["t"] == "pack" and outer["i"] == 1 and outer["uid"] == 4660
    assert outer["cid"] == unit.mac and outer["cid"] != "TEST_CID"
    assert outer["tcid"] == ""
    assert outer["pack"] == (
        "x9IsfTZFVBzOBw9YSpkLX83pBZNs2KAC7o7e+XYHKBCO2ZgS0C7pwr+0337q8n"
        "Os2RxZvXaz4GFC77ZPCYMfFAJopyUYKnWYbkF7GvOw61s="
    )
    assert inner == {"t": "bindok", "mac": unit.mac, "r": 200,
                     "key": unit.key.decode("ascii")}


def test_descriptor_tx_getters_are_not_frozen_rx_readouts():
    unit = device("sim-w04w-v125-sdk-gas")
    for value, stored in ((245, 245), (246, 246), (890, 890), (999, 890), (39, 39)):
        assert exchange(unit, {"t": "cmd", "opt": ["mode"], "p": [value]}) == (None, None, None)
        _, _, fresh = exchange(unit, {"t": "status", "cols": ["mode"]})
        assert fresh["dat"] == [stored]
    unit = device("sim-w04w-v125-sdk-fan")
    for value, stored in ((60, 60), (999, 60), (80, 80), (100, 100)):
        exchange(unit, {"t": "cmd", "opt": ["angleLR"], "p": [value]})
        _, _, fresh = exchange(unit, {"t": "status", "cols": ["angleLR"]})
        assert fresh["dat"] == [stored]
    exchange(unit, {"t": "cmd", "opt": ["angleAutoLROnOff"], "p": [1]})
    exchange(unit, {"t": "cmd", "opt": ["angleLR"], "p": [999]})
    _, _, fresh = exchange(unit, {"t": "status", "cols": ["angleLR"]})
    assert fresh["dat"] == [60]


@pytest.mark.parametrize("vector", DESCRIPTOR_FIXTURE["boundary_vectors"])
def test_independent_descriptor_boundary_vectors(vector):
    unit = device(vector["profile"])
    assert exchange(unit, {"t": "cmd", "opt": [vector["name"]], "p": [vector["input"]]}) == (None, None, None)
    _, _, fresh = exchange(unit, {"t": "status", "cols": vector["fresh_cols"]})
    assert fresh["cols"] == vector["fresh_cols"] and fresh["dat"] == vector["fresh_dat"]


def test_descriptor_long_names_exact_capacity_and_atomic_recovery():
    unit = device("sim-w04w-v125-sdk-fridge")
    name = "freezerTargetTemperature"
    _, _, status = exchange(unit, {"t": "status", "cols": [name]})
    assert status["cols"] == [name] and status["dat"] == [0]
    exchange(unit, {"t": "cmd", "opt": [name], "p": [22]})
    _, _, fresh = exchange(unit, {"t": "status", "cols": [name]})
    assert fresh["dat"] == [-50]
    _, _, status = exchange(unit, {"t": "status", "cols": [name] * 30})
    assert status["cols"] == status["dat"] == []
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        exchange(unit, {"t": "cmd", "opt": ["fridgeSwitch", name], "p": [0, True]})
    assert unit.state == before
    _, _, fresh = exchange(unit, {"t": "status", "cols": [name]})
    assert fresh["dat"] == [-50]


def test_exact_five_source_payloads_and_unique_registered_contracts():
    expected = {row["source_sha256"] for row in FIXTURE["sources"]}
    expected.update(row["source_sha256"] for row in DESCRIPTOR_FIXTURE["tables"])
    assert len(expected) == 5 and {profile.source_sha256 for profile in PROFILES} == expected
    assert len({profile.id for profile in PROFILES}) == len(PROFILES)
    assert len(DESCRIPTOR_FIXTURE["tables"]) == 18
