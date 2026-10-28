"""Independent WB source vectors and chosen synthetic-IO wire regressions."""

import base64
from copy import deepcopy
import json
from pathlib import Path

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.wb_adr import PROFILES as ADR_PROFILES, raw_value, stage_command
from gree_emulator.profiles.wb_gateway import PROFILES as BR_PROFILES
from gree_emulator.wire import InvalidPacket, decode_outer, encode_reply


DIRECTORY = Path(__file__).parent / "fixtures/emulator"
FIXTURES = {build: json.loads((DIRECTORY / f"session-wb-{label}.json").read_text())
            for build, label in (("BR", "br131"), ("ADR", "adr"))}
RESEARCH = {build: json.loads((DIRECTORY / f"session-wb-{label}_research.json").read_text())
            for build, label in (("BR", "br131"), ("ADR", "adr"))}
KEY = b"0123456789abcdef"
GENERIC = b"a3K8Bx%2r8Y7#xDh"


def devices(build, category="ac", mid=None, count=1):
    profiles = ADR_PROFILES if build == "ADR" else BR_PROFILES
    identifier = "sim-wb05adr-v1.16" if build == "ADR" else "sim-wb05br-v1.31"
    root_profile = next(p for p in profiles if p.id == identifier)
    suffix = "water" if category == "water_floor" else category
    profile = next(p for p in profiles if p.id == identifier + "-" + suffix)
    root = EmulatedDevice(id="root", mac="020000000001", name="WB Gateway", mid=root_profile.mids[0],
                          key=KEY, profile=root_profile, state={})
    root.children = [EmulatedDevice(id=f"child-{i}", mac=f"0244668800{i:04x}", name=f"Child {i}",
                                    mid=mid or profile.mids[0], key=KEY, profile=profile,
                                    state=deepcopy(dict(profile.initial_state))) for i in range(count)]
    root.profile.handler.validate_topology(root)
    return root


def exchange(root, inner, index=0, direct=False, **overrides):
    outer = {"t": "subList" if direct else "pack", "cid": "app", "tcid": root.mac,
             "uid": 7, "i": index, **overrides}
    if direct:
        outer.update(inner)
    else:
        key = GENERIC if index == 1 else KEY
        plaintext = json.dumps(inner, separators=(",", ":")).encode()
        outer["pack"] = base64.b64encode(AES.new(key, AES.MODE_ECB).encrypt(pad(plaintext, 16))).decode()
    replies = root.profile.handler.handle(root, decode_outer(json.dumps(outer).encode()))
    result = []
    for reply in replies:
        packet = json.loads(encode_reply(reply))
        key = GENERIC if packet["i"] == 1 else KEY
        plaintext = unpad(AES.new(key, AES.MODE_ECB).decrypt(base64.b64decode(packet["pack"])), 16)
        result.append(json.loads(plaintext))
    return result


def status(root, child, cols):
    return exchange(root, {"t": "status", "mac": child.mac, "cols": cols})[0]["dat"]


def command(root, child, names, values, **extra):
    return exchange(root, {"t": "cmd", "mac": root.mac, "sub": child.mac,
                           "opt": names, "p": values, **extra})[0]


@pytest.mark.parametrize("build", ("BR", "ADR"))
def test_every_finite_category_getter_has_an_independent_initial_report(build):
    for vector in FIXTURES[build]["default_status"]:
        root = devices(build, vector["category"], vector["mid"])
        child = root.children[0]
        assert status(root, child, vector["cols"]) == vector["dat"]
        assert status(root, child, ["TemSen", "missing", "mac", "mid", "hid"]) == [
            "", "", root.mac, root.mid, root.profile.hid]
        assert root.profile.handler.thermal_target(child) is None


READ_CASES = [(build, case) for build, fixture in RESEARCH.items()
              for case in fixture["observations"]
              if "field" in case and "supplied_raw" in case and isinstance(case.get("expected"), dict)]


@pytest.mark.parametrize("build,case", READ_CASES)
def test_original_callback_read_vectors(build, case):
    root = devices(build, case.get("category", "ac"))
    child = root.children[0]
    descriptors = RESEARCH[build]["fields"][case.get("category", "ac")]
    field = next(row for row in descriptors if row["name"] == case["field"])
    if field["read_tuple"]:
        child.state["reported"][field["read_tuple"]["bytes"]] = case["supplied_raw"]
    if case["field"] in ("GasAvail", "GasLED", "GasMod", "GasMas", "PM2P5Sta"):
        child.state["reported"]["00410a"] = 3
    assert {case["field"]: raw_value(child, case["field"])} == case["expected"]


CONVERTERS = [(build, case) for build, fixture in RESEARCH.items()
              for case in fixture["observations"]
              if case.get("case") in ("mode_write", "setpoint_write", "6098_unit_conversion")]


@pytest.mark.parametrize("build,case", CONVERTERS)
def test_original_mode_setpoint_and_unit_writer_vectors(build, case):
    unit = case["case"] == "6098_unit_conversion"
    root = devices(build, "filter" if unit else "ac", "6098" if unit else None)
    child = root.children[0]
    context = case["requested"] if isinstance(case["requested"], dict) else {"Mod": case["requested"]}
    expected = case.get("expected_uart_uint16", case.get("expected_uart_byte"))
    if expected is None:
        with pytest.raises(InvalidPacket):
            stage_command(child, list(context), list(context.values()))
    else:
        staged = stage_command(child, list(context), list(context.values()))
        assert staged["outbound"][0][1] == expected
        assert child.state["outbound"] == []


@pytest.mark.parametrize("build,raw,expected", [(build, raw, expected) for build in ("BR", "ADR")
                                              for raw, expected in ((0, ""), (1, 1), (5, 0), (12, 11),
                                                                     (13, ""), (257, 1), (65535, ""))])
def test_source_mode_low_byte_getter_boundaries(build, raw, expected):
    root = devices(build)
    root.children[0].state["reported"]["007100"] = raw
    assert status(root, root.children[0], ["Mod", "Mod"]) == [expected, expected]


@pytest.mark.parametrize("build,expected", (("BR", [22, 5, 1]), ("ADR", [0, 5, 1])))
def test_requested_ack_outbound_and_fresh_report_are_separate(build, expected):
    root = devices(build, count=2)
    one, two = root.children
    ack = command(root, one, ["SetTem", "Add0.5"], [22, 1])
    assert ack["p"] == ack["val"] == [22, 1]
    assert one.state["requested"] == [("SetTem", 22), ("Add0.5", 1)]
    assert one.state["outbound"] == [("007300", 225 if build == "BR" else 5)]
    assert status(root, one, ["SetTem", "Add0.1", "Add0.5"]) == expected
    assert status(root, two, ["SetTem", "Add0.1", "Add0.5"]) == [24, 0, 0]
    assert status(devices(build), devices(build).children[0], ["SetTem"]) == [24]


@pytest.mark.parametrize("build", ("BR", "ADR"))
def test_named_duplicates_unknown_readonly_and_noop_cardinality(build):
    root = devices(build, "water_floor")
    child = root.children[0]
    ack = command(root, child, ["SetTem", "SetTem", "missing", "WtmrHr", "WCurTem"], [19, 25, 3, 7, 99])
    assert ack["p"] == [19, 25, 3, 7, 99]
    assert ack["val"] == [19, 25, None, 7, 99]
    assert child.state["outbound"] == [("007300", 190), ("007300", 190)]
    assert status(root, child, ["SetTem", "SetDeciTem", "WtmrHr", "WCurTem", "missing"]) == [19, "", 0, 0, ""]
    command(root, child, ["WUTHTmrHr"], [12])
    assert child.state["outbound"] == []
    assert status(root, child, ["WUTHTmrHr"]) == [0]


@pytest.mark.parametrize("build", ("BR", "ADR"))
def test_water_timer_combined_tuple_cycle_and_low_byte_mode(build):
    root = devices(build, "water_floor")
    child = root.children[0]
    command(root, child, ["WtmrMin", "WtmrHr", "WUTHCycle", "Wmod"], [300, 258, 255, 257])
    assert child.state["outbound"] == [("007120", (44, 2)), ("006f1b", 1),
                                       ("007119", 0), ("007118", 1), ("002115", None)]
    assert status(root, child, ["WtmrMin", "WtmrHr", "WUTHCycle", "Wmod"]) == [44, 2, 0, 1]
    command(root, child, ["WUTHTmrMin", "WUTHTmrHr"], [-1, 257])
    assert child.state["outbound"] == [("00711a", (255, 1))]


@pytest.mark.parametrize("build", ("BR", "ADR"))
def test_filter_arrays_packed_flags_auxiliary_rows_and_no_emission(build):
    root = devices(build, "filter", "6098")
    child = root.children[0]
    child.state["reported"].update({"00410a": 3, "004007": 80, "004008": 81,
                                    "004d06": 65535, "004d08": 258,
                                    "003f0f": 1, "003f16": 1, "003f10": 0, "003f17": 1,
                                    "00410b": 3, "003d1d": 1, "003d09": 1})
    assert status(root, child, ["TemSor", "PM2P5", "GasAvail", "PctCle", "PctRe", "ErrType", "GasN", "ReportFreq"]) == [
        [80, 81], [65535, 258], [1, 1], 3, 2, 3, "", ""]
    command(root, child, ["GasLED", "ReportFreq"], [258, 1])
    assert child.state["outbound"] == [("007d0b", 2)]
    assert status(root, child, ["GasLED", "ReportFreq"]) == [[0, 1], ""]
    assert child.state["report_requested"] is True
    child.state["reported"]["00410a"] = 0
    assert status(root, child, ["TemSor", "GasLED"]) == ["", ""]


@pytest.mark.parametrize("build", ("BR", "ADR"))
def test_unit_fraction_is_gateway_shared_but_raw_reports_are_child_local(build):
    root = devices(build, "filter", "6098", 2)
    one, two = root.children
    command(root, one, ["SetTem", "TemUn", "TemRec"], [22, 1, 1])
    assert one.state["outbound"] == [("007300", 222)]
    assert status(root, one, ["SetTem", "TemUn", "TemRec"]) == [22, 1, 1]
    assert status(root, two, ["TemUn", "SetTem", "TemRec"]) == [1, 24, 0]
    assert status(root, one, ["SetTem", "TemRec"]) == [22, 1]
    independent = devices(build, "filter", "6098")
    assert status(independent, independent.children[0], ["TemUn", "TemRec"]) == [0, 0]


@pytest.mark.parametrize("build", ("BR", "ADR"))
def test_error_bit_masks_widths_and_missing_slots(build):
    root = devices(build)
    child = root.children[0]
    child.state["reported"].update({"001e03": 3, "001e05": 1, "002205": 255, "00220d": 1})
    assert status(root, child, ["ErrType1", "ErrType2"]) == [32771, 24]
    del child.state["reported"]["001e05"]
    assert status(root, child, ["ErrType1"]) == [32769]


def test_br_energy_read_side_lifecycle_and_power_bias_without_physics():
    root = devices("BR", "energy", "6083")
    child = root.children[0]
    child.state["reported"].update({"00585a": 65535, "005858": 0, "005880": 1234, "081410": 0x01020304})
    assert status(root, child, ["PVGenedPwr", "PSSGoCPwr", "OldGridTotEngy", "NewGridTotEngy", "OldGridTotEngy", "OldGridTotEngy", "TotalEle"]) == [
        65535000, -32768000, 0, 1234, 0, 1234, 169090600]
    child.state["reported"]["005858"] = 32768
    assert status(root, child, ["PSSGoCPwr"]) == [0]


@pytest.mark.parametrize("build", ("BR", "ADR"))
@pytest.mark.parametrize("names,values", ((["Pow", "Mod"], [1, 12]), (["Pow"], [True]),
                                         (["Pow"], [1.0]), (["SetTem"], ["22"]),
                                         (["Pow", "hid"], [1, "other"]),
                                         (["SetTem"], [2**31]), (["Pow"], [])))
def test_safe_whole_batch_failure_preserves_controls_shared_cache_and_clocks(build, names, values):
    root = devices(build)
    child = root.children[0]
    before, root_before, clock = deepcopy(child.state), deepcopy(root.state), child.last_step
    with pytest.raises(InvalidPacket):
        command(root, child, names, values)
    assert child.state == before
    assert root.state == root_before
    assert child.last_step == clock


@pytest.mark.parametrize("build", ("BR", "ADR"))
def test_reply_size_preflight_preserves_read_side_accumulators_and_command_state(build):
    root = devices(build)
    child = root.children[0]
    before = deepcopy(child.state)
    with pytest.raises(InvalidPacket, match="UDP payload"):
        command(root, child, ["Pow"] * 7000, [1] * 7000)
    assert child.state == before and root.state == {}


@pytest.mark.parametrize("build", ("BR", "ADR"))
def test_bind_casing_alias_pagination_and_root_metadata(build):
    root = devices(build, "filter", "6091", 7)
    assert exchange(root, {"t": "bind", "mac": root.mac}, 1)[0]["t"] == "bindOk"
    for offset, identities in ((0, root.children[:5]), (1, root.children[1:6]), (5, root.children[5:]), (7, [])):
        for kind in ("subDev", "subList"):
            assert exchange(root, {"t": kind, "mac": root.mac, "i": offset}) == [{
                "t": "subList", "i": offset, "c": 7, "r": 200,
                "list": [{"mac": c.mac, "mid": "6079"} for c in identities]}]
    child = root.children[0]
    assert status(root, child, ["MIdType", "mid", "mac", "hid"]) == ["6091", root.mid, root.mac, root.profile.hid]
    root.children = []
    assert exchange(root, {"t": "bind", "mac": root.mac}, 1)[0]["t"] == "bindok"


@pytest.mark.parametrize("changes", ({"i": 2}, {"i": True}, {"uid": True}, {"uid": 2**31},
                                      {"tcid": "020000000009"}, {"cid": "x" * 15}))
def test_adr_does_not_accept_other_key_routes_or_malformed_envelopes(changes):
    root = devices("ADR")
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "subList", "i": 0}, **changes)


def test_adr_identity_and_opaque_modes_are_not_rt13_ble_or_success_stubs():
    root = devices("ADR")
    assert root.mid == "6400"
    assert root.profile.hid == "362001069264+U-WB05ADRV1.16.bin"
    assert root.profile.source_sha256 == "58f46141990b02939b909f01117a8a855a315e4be0047f6b983104b7882e9c4a"
    for kind in ("binCmd", "binStatus", "gbinstatus", "hex6A", "hex6B", "res_200"):
        assert exchange(root, {"t": kind, "mac": root.mac, "hex6A": "010203"}) == []
    assert root.children[0].state["outbound"] == []
    advertised = root.profile.handler.advertise(root, {"t": "scan"})[0]
    assert advertised.codec == "aes-ecb-pkcs7"
    assert advertised.inner == {"t": "dev", "bc": "", "catalog": "gree", "series": "gree", "model": "gree",
                                "lock": 0, "vender": "1", "mid": "6400", "name": "WB Gateway",
                                "ver": "V3.2.M", "mac": root.mac, "subCnt": 1}


@pytest.mark.parametrize("build", ("BR", "ADR"))
def test_turbo_quiet_order_sleep_swing_and_generic_widths(build):
    root = devices(build)
    child = root.children[0]
    command(root, child, ["WdSpd", "Quiet", "SwhSlp", "SwUpDn", "Pow", "SetCoolHumi"],
            [6, 0, 1, 1, -2, 257])
    assert child.state["outbound"] == [
        ("006f01", 1), ("00710c", 0), ("00710d", 4), ("007102", 2),
        ("006f00", 1), ("007115", 1)]
    assert status(root, child, ["WdSpd", "Quiet", "SwhSlp", "SwUpDn", "Pow", "SetCoolHumi"]) == [6, 0, 1, 1, 1, 1]
    command(root, child, ["WdSpd", "Quiet", "AutoClean"], [8, 0, 1])
    assert status(root, child, ["WdSpd", "Tur", "Quiet", "AutoClean"]) == [8, 0, 0, 1]
    command(root, child, ["SwingLfRig", "CoolSvStTemMin", "SetDeciTem"], [258, -1, 65537])
    assert status(root, child, ["SwingLfRig", "CoolSvStTemMin", "SetTem", "SetDeciTem", "Add0.1"]) == [1, 6552, 0, 1, 1]


@pytest.mark.parametrize("build", ("BR", "ADR"))
@pytest.mark.parametrize("mid", ("605d", "6098"))
def test_filter_speed_has_its_own_selector_and_605d_turbo_tuple(build, mid):
    root = devices(build, "filter", mid)
    child = root.children[0]
    command(root, child, ["WdSpd"], [7])
    assert child.state["outbound"] == [("007b01", 0), ("007d01", 1)]
    assert status(root, child, ["WdSpd", "Tur"]) == [7, 0]
    command(root, child, ["WdSpd"], [6])
    assert child.state["outbound"] == ([("007d01", 6)] if mid == "605d" else []) + [("007b01", 1)]
    assert status(root, child, ["WdSpd", "Tur"]) == [6, 1]
    before = deepcopy(child.state)
    with pytest.raises(InvalidPacket):
        command(root, child, ["WdSpd"], [0])
    assert child.state == before


def test_br_price_chunks_ai_selector_and_raw_unavailable_getters():
    root = devices("BR", "water_floor")
    child = root.children[0]
    command(root, child, ["ElecPrice", "AISvst"], [list(range(24)), 3])
    assert child.state["outbound"] == [
        ("7e1830", tuple(range(7))), ("7e1837", tuple(range(7, 14))),
        ("7e183e", tuple(range(14, 21))), ("7e1845", (21, 22, 23)), ("0871b5", 0x6f)]
    assert status(root, child, ["ElecPrice", "AISvst"]) == ["", 0x6f]
    before = deepcopy(child.state)
    with pytest.raises(InvalidPacket):
        command(root, child, ["ElecPrice"], [[1] * 23])
    assert child.state == before


@pytest.mark.parametrize("build", ("BR", "ADR"))
def test_direct_list_key_index_differs_from_encrypted_child_offset_and_aliases_are_source_local(build):
    root = devices(build, "filter", "608d", 7)
    direct = exchange(root, {"t": "subList", "i": 1}, index=1, direct=True)
    packed = exchange(root, {"t": "subList", "i": 5}, index=1)
    assert [entry["mac"] for entry in direct[0]["list"]] == [child.mac for child in root.children[1:6]]
    assert [entry["mac"] for entry in packed[0]["list"]] == [child.mac for child in root.children[5:]]
    assert all(entry["mid"] == "6079" for entry in direct[0]["list"])
    assert root.children[0].mid == "608d"
    for mid in ("608d", "6091", "6099", "60a9"):
        root.children[0].mid = mid
        assert exchange(root, {"t": "subList", "i": 0})[0]["list"][0]["mid"] == "6079"
    root.children[0].mid = "6098"
    assert exchange(root, {"t": "subList", "i": 0})[0]["list"][0]["mid"] == "6098"


@pytest.mark.parametrize("build", ("BR", "ADR"))
def test_factory_default_state_validation_accepts_only_chosen_report_initialization(build):
    root = devices(build)
    child = root.children[0]
    root.profile.handler.validate_state({})
    child.profile.handler.validate_state(deepcopy(dict(child.profile.initial_state)))
    altered = deepcopy(dict(child.profile.initial_state))
    altered["reported"]["007300"] = 220
    with pytest.raises(ValueError):
        child.profile.handler.validate_state(altered)


@pytest.mark.parametrize("build", ("BR", "ADR"))
def test_read_reply_size_preflight_does_not_advance_shared_accumulators(build):
    root = devices(build, "energy" if build == "BR" else "filter")
    child = root.children[0]
    before, root_before = deepcopy(child.state), deepcopy(root.state)
    cols = ["OldGridTotEngy"] * 7000 if build == "BR" else ["TemUn"] * 12000
    with pytest.raises(InvalidPacket, match="UDP payload"):
        status(root, child, cols)
    assert child.state == before
    assert root.state == root_before


@pytest.mark.parametrize("build", ("BR", "ADR"))
def test_named_opt_values_are_authoritative_over_conflicting_packet_extras(build):
    root = devices(build)
    child = root.children[0]
    ack = command(root, child, ["Pow", "Mod", "SetTem"], [0, 1, 22],
                  Pow=1, Mod="untrusted", SetTem={"invalid": "extra"},
                  **{"Add0.1": "invalid", "Add0.5": 1})
    assert ack["p"] == ack["val"] == [0, 1, 22]
    assert child.state["outbound"] == [("006f00", 0), ("007100", 1), ("007300", 220)]
    assert status(root, child, ["Pow", "Mod", "SetTem", "Add0.1"]) == [0, 1, 22, 0]
    ack = command(root, child, ["SetTem", "SetTem", "Add0.1"], [21, 25, 7],
                  SetTem="untrusted", **{"Add0.1": {"invalid": "extra"}})
    assert ack["p"] == ack["val"] == [21, 25, 7]
    assert child.state["outbound"] == [("007300", 217), ("007300", 217)]
    assert status(root, child, ["SetTem", "Add0.1"]) == [21, 7]


@pytest.mark.parametrize("build", ("BR", "ADR"))
@pytest.mark.parametrize("invalid", ("bad", True, {}, [1]))
def test_invalid_named_context_is_atomic_despite_valid_packet_extras_and_recovers(build, invalid):
    root = devices(build)
    child = root.children[0]
    before, root_before, clock = deepcopy(child.state), deepcopy(root.state), child.last_step
    with pytest.raises(InvalidPacket):
        command(root, child, ["Pow", "SetTem", "Add0.1"], [1, 22, invalid],
                Pow=0, SetTem=24, **{"Add0.1": 7})
    assert child.state == before
    assert root.state == root_before
    assert child.last_step == clock
    command(root, child, ["Pow", "Mod", "SetTem"], [1, 4, 23], Mod="still ignored")
    assert status(root, child, ["Pow", "Mod", "SetTem"]) == [1, 4, 23]
