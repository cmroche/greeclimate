"""Exact historical raw-controller contracts and explicit safe-model policies."""
from copy import deepcopy
import base64
import json
from pathlib import Path

import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.catalog_realtek_middle import PROFILES
from gree_emulator.wire import InvalidPacket, encode_reply
from tests.test_emulator_realtek_controller import exchange, packet, status


MATRIX = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-realtek-middle-r241_research.json").read_text())
G44 = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-realtek-middle-g44_research.json").read_text())


def controller(mac="020000000001", profile_id="sim-w05r-v2.41"):
    profile = next(profile for profile in PROFILES if profile.id == profile_id)
    return EmulatedDevice("root", mac, "", profile.mids[0], b"0123456789abcdef", profile,
                          dict(profile.initial_state), room_c=None, ambient_c=None,
                          last_step=1000)


@pytest.mark.parametrize("name,expected", MATRIX["initial_getters"])
def test_every_source_getter_has_an_explicit_synthetic_readout(name, expected):
    device = controller()
    assert status(device, [name]) == {
        "t": "dat", "mac": "020000000001", "r": 200, "cols": [name], "dat": expected,
    }
    assert device.profile.handler.thermal_target(device) is None


@pytest.mark.parametrize("name", MATRIX["scalar_controls"])
@pytest.mark.parametrize("vector", MATRIX["scalar_vectors"])
def test_native_low_halfword_prefix_gets_safe_atomic_ack_and_fresh_cache(name, vector):
    device = controller()
    assert exchange(device, {"t": "cmd", "opt": [name], "p": [vector["requested"]]}) == {
        "t": "res", "mac": "020000000001", "r": 200,
        "opt": [name], "p": [vector["ack"]],
    }
    assert status(device, [name])["dat"] == [vector["fresh"]]
    assert "val" not in exchange(device, {"t": "cmd", "opt": [], "p": []})


def test_finite_native_namespace_preserves_duplicates_and_omits_unknowns():
    device = controller()
    assert status(device, MATRIX["negative_getters"])["dat"] == []
    assert status(device, MATRIX["negative_getters"])["cols"] == []
    result = exchange(device, {"t": "cmd", "opt": ["Pow", "__unknown__", "Pow"],
                               "p": [7, 99, 65537]})
    assert result["opt"] == ["Pow", "Pow"] and result["p"] == [7, 1]
    assert status(device, ["Pow", "hid", "Pow"])["dat"] == [1, MATRIX["hid"], 1]


def test_invalid_last_action_cannot_apply_an_earlier_cache_write_or_uid():
    device = controller()
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "cmd", "opt": ["Pow", "ConBtnName"], "p": [1, 7]})
    assert device.state == before
    assert device.last_step == 1000


def test_virtual_ir_records_clock_and_caches_are_isolated_and_restart_empty():
    first, other = controller(), controller("020000000002")
    response = exchange(first, {"t": "cmd", "opt": ["ConBtnNum", "AddButton", "ConBtnName"],
                                "p": [1, 1, "bedroom"]})
    assert response["p"] == [1, 26, 1, "bedroom"]
    assert status(first, ["RefBtnList"])["dat"] == [[1], ["bedroom"]]
    assert status(other, ["RefBtnList"])["dat"] == [[], []]
    first.last_step += 61
    assert status(first, ["time"])["dat"] == ["2026-01-01 00:01:01"]
    restarted = controller()
    assert status(restarted, ["RefBtnList", "time"])["dat"] == [[], [], "2026-01-01 00:00:00"]


def timer_request(kind="setT", timer_id=7):
    return {
        "t": kind, "id": timer_id, "name": "literal", "enable": 0,
        "hr": 0, "min": 1, "sec": 0, "tz": -1, "week": [],
        "cmd": [{"mac": ["020000000001"], "opt": ["Pow"], "p": [65537, 99]}],
    }


def test_timer_parser_preserves_source_first_property_and_first_value_shape():
    device = controller()
    assert exchange(device, timer_request()) == {"t": "resT", "r": 200}
    assert exchange(device, {"t": "queryT", "index": 0, "count": 10}) == {
        "t": "listT", "total": 10, "index": 0,
        "list": [{
            "id": 7, "name": "literal", "enable": 0, "hr": 0, "min": 1, "sec": 0,
            "week": [0] * 7,
            "cmd": [{"mac": ["020000000001"], "opt": ["Pow"], "p": [65537]}],
        }],
    }
    assert device.state["_runtime"]["schedules"][7]["tz"] == 255
    device.last_step += 61
    assert status(device, ["Pow", "time"])["dat"] == [1, "2026-01-01 00:01:01"]
    assert device.state["_runtime"]["schedules"][7]["enable"] == 1
    assert device.state["_runtime"]["send_pending"] is True
    assert status(controller(), ["Pow"])["dat"] == [0]


def test_timer_update_delete_and_empty_query_are_native_distinct_shapes():
    device = controller()
    assert exchange(device, {"t": "queryT", "index": 0, "count": 10}) == {
        "t": "listT", "total": 10, "index": 0,
    }
    exchange(device, timer_request())
    replacement = timer_request("updateT")
    replacement["name"] = "changed"
    exchange(device, replacement)
    assert exchange(device, {"t": "queryT", "index": 0, "count": 10})["list"][0]["name"] == "changed"
    assert exchange(device, {"t": "deleteT", "id": 263}) == {"t": "resT", "r": 200}
    assert "list" not in exchange(device, {"t": "queryT", "index": 0, "count": 10})


def test_timer_capacity_and_update_failure_do_not_mutate_the_store():
    device = controller()
    for timer_id in range(10):
        assert exchange(device, timer_request(timer_id=timer_id))["r"] == 200
    before = deepcopy(device.state)
    assert exchange(device, timer_request(timer_id=10)) == {"t": "resT", "r": 500}
    assert device.state["_runtime"]["schedules"] == before["_runtime"]["schedules"]
    assert device.profile.handler.handle(device, packet(device, timer_request("updateT", 10))) == []
    assert device.state["_runtime"]["schedules"] == before["_runtime"]["schedules"]


def test_timer_invalid_final_record_is_atomic_even_after_a_synthetic_due_event():
    device = controller()
    exchange(device, timer_request())
    device.last_step += 61
    before = deepcopy(device.state)
    request = timer_request(timer_id=8)
    request["cmd"].append({"mac": [], "opt": ["Pow", "Mod"], "p": [1, 2]})
    with pytest.raises(InvalidPacket):
        exchange(device, request)
    assert device.state == before


def test_upgrade_records_only_bounded_virtual_request_not_firmware_execution():
    device = controller()
    assert exchange(device, {"t": "upgrade", "url": "http://example.invalid/fw.bin"}) == {
        "t": "ret", "r": 200, "mac": "020000000001",
    }
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "upgrade", "url": "a" * 160})
    assert device.state == before


def test_surver_preserves_original_malformed_base64_field_not_an_encrypted_ack():
    device = controller()
    reply, = device.profile.handler.handle(device, packet(device, {"t": "surver"}))
    raw = encode_reply(reply)
    assert raw.endswith(b"\n")
    assert json.loads(raw) == {
        "t": "pack", "i": 1, "uid": 42, "cid": "020000000001", "tcid": "", "pack": "fg\x01",
    }
    assert reply.inner is None and reply.key is None


@pytest.mark.parametrize("vector", G44["initial_getters"])
def test_g44_complete_ragged_namespace_has_explicit_readouts(vector):
    device = controller(profile_id="sim-w05g-v4.4")
    result = status(device, [vector["name"]])
    assert result["cols"] == vector["columns"]
    assert result["dat"] == vector["values"]


def test_g44_root_registry_metadata_and_upgrade_shapes_are_source_specific():
    device = controller(profile_id="sim-w05g-v4.4")
    assert exchange(device, {"t": "subDev", "i": 0}) == G44["operation_vectors"]["subDev"]
    assert exchange(device, {"t": "meshstatus", "meshmac": [], "len": []}) == G44["operation_vectors"]["meshstatus"]
    assert exchange(device, {"t": "onoffse", "meshid": "0000", "on": 1, "off": 0, "lpn": 0}) == G44["operation_vectors"]["onoffse"]
    assert exchange(device, {"t": "upgrade", "url": "http://example.invalid/fw.bin"}) == {
        "t": "ret", "r": 200, "mac": "020000000001",
    }


def test_g44_dump_enqueues_exact_local_frame_without_a_fake_ack_or_radio_action():
    device = controller(profile_id="sim-w05g-v4.4")
    request = {"t": "dump", "mac": "020000000002", "period": 258, "cnt": 259}
    assert device.profile.handler.handle_from(device, packet(device, request), ("127.0.0.1", 41000)) == []
    queued, = device.state["_runtime"]["binary_queue"]
    assert queued["frame"][:22] == G44["operation_vectors"]["dump_frame_prefix"]
    assert queued["frame"][22:] == [0] * 228
    assert queued["peer"] == ("127.0.0.1", 41000)
    assert "_runtime" not in controller(profile_id="sim-w05g-v4.4").state


def test_g44_binary_envelope_queue_counter_capacity_and_atomic_validation():
    device = controller(profile_id="sim-w05g-v4.4")
    request = {"t": "bin", "stm": 1, "sub": ["0001"],
               "bin": [base64.b64encode(b"\x01").decode()], "type": [2]}
    assert device.profile.handler.handle(device, packet(device, request)) == []
    assert device.state["_runtime"]["binary_queue"][0]["frame"][:12] == [
        170, 170, 0, 1, 0, 0, 0, 0, 2, 3, 31, 1,
    ]
    before = deepcopy(device.state)
    invalid = {"t": "bin", "stm": 1, "sub": ["0001", "bad"],
               "bin": ["AQ==", "AQ=="], "type": [2, 2]}
    with pytest.raises(InvalidPacket):
        device.profile.handler.handle(device, packet(device, invalid))
    assert device.state == before
    for _ in range(6):
        assert device.profile.handler.handle(device, packet(device, request)) == []
    assert len(device.state["_runtime"]["binary_queue"]) == 5
    assert device.state["_runtime"]["binary_sequence"] == 35
