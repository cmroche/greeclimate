"""Exact-source WB04AV1.49 operations across its qualified synthetic MID inputs."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles import wb
from gree_emulator.wire import InvalidPacket, Reply, encode_reply


VECTORS = json.loads((Path(__file__).parent / "fixtures/emulator/wb04a-operations_research.json").read_text())
MIDS = ("10f05", "10010", "10011", "11011", "11012")


@pytest.fixture(params=MIDS)
def device(request):
    profile = wb.PROFILES[0]
    return EmulatedDevice(id="wb04-operations", mac="020000000001", name="WB04",
                          mid=request.param, key=b"0123456789abcdef", profile=profile,
                          state=deepcopy(dict(profile.initial_state)))


def send(device, inner):
    envelope = {"t": "pack", "i": 0, "uid": 9, "cid": "peer", "tcid": device.mac}
    packet = json.loads(encode_reply(Reply(envelope, inner, device.key, wb.CODEC)))
    return [reply.inner for reply in device.profile.handler.handle(device, packet)]


def test_status_and_cmd_fall_back_to_opt_after_cols_lookup_fails(device):
    assert send(device, {"t": "status", "cols": None, "opt": ["Pow"], "p": [1]})[0]["t"] == "dat"
    assert device.state["Pow"] == 1
    assert send(device, {"t": "cmd", "cols": None, "opt": ["Pow"], "p": [0]})[0]["t"] == "res"
    assert device.state["Pow"] == 0


def test_timer_set_query_update_and_delete_follow_wb04_source_vectors(device):
    timer = VECTORS["timer"]
    assert send(device, timer["set_request"]) == [timer["response"]]
    assert send(device, timer["query_request"]) == [timer["query_response"]]
    assert send(device, timer["update_request"]) == [timer["response"]]
    assert send(device, timer["query_request"]) == [timer["update_query_response"]]
    assert send(device, timer["delete_request"]) == [timer["response"]]
    assert send(device, timer["query_request"]) == [timer["empty_query_response"]]


def test_timer_command_schema_and_bound_are_source_specific(device):
    request = VECTORS["timer"]["set_request"]
    before = deepcopy(device.state)
    invalid = [
        [{"opt": ["Pow"], "p": [1]}],
        {"opt": ["Pow"], "p": []},
        {"opt": ["Pow"] * 33, "p": [1] * 33},
    ]
    for command in invalid:
        with pytest.raises(InvalidPacket):
            send(device, {**request, "cmd": command})
        assert device.state == before


def test_timer_query_uses_native_linked_list_slot_order_and_ten_entry_bound(device):
    template = VECTORS["timer"]["set_request"]
    identifiers = (9, 2, 7, 4, 1, 8, 0, 6, 5, 3)
    for identifier in identifiers:
        request = deepcopy(template)
        request.update(id=identifier, name=f"slot-{identifier}")
        assert send(device, request) == [VECTORS["timer"]["response"]]

    rejected = deepcopy(template)
    rejected.update(id=10, name="eleventh")
    assert send(device, rejected) == []
    assert send(device, {"t": "queryT", "index": 8, "count": 10}) == [{
        "t": "listT", "total": 10, "index": 8,
        "list": [
            {"id": 5, "name": "slot-5", "enable": 1, "week": [0, 1, 1, 0, 0, 0, 1],
             "hr": 6, "min": 30, "sec": 0,
             "cmd": {"mac": [device.mac], "opt": ["Pow"], "p": [2]}},
            {"id": 3, "name": "slot-3", "enable": 1, "week": [0, 1, 1, 0, 0, 0, 1],
             "hr": 6, "min": 30, "sec": 0,
             "cmd": {"mac": [device.mac], "opt": ["Pow"], "p": [2]}}
        ]
    }]
    assert send(device, {"t": "queryT", "index": 10, "count": 1}) == [{
        "t": "listT", "total": 10, "index": 10, "list": []
    }]


def test_update_missing_timer_and_unknown_delete_preserve_native_count_fault(device):
    timer = VECTORS["timer"]
    update = deepcopy(timer["update_request"])
    update["id"] = 3
    assert send(device, update) == [timer["response"]]
    assert send(device, timer["query_request"]) == [timer["empty_query_response"]]

    assert send(device, {"t": "deleteT", "id": 3}) == [timer["response"]]
    assert send(device, timer["query_request"]) == [{
        "t": "listT", "total": 255, "index": 0, "list": []
    }]
    assert send(device, timer["set_request"]) == []


def test_freq_count_projects_source_mode_and_controls_without_ack(device):
    assert send(device, {"t": "freqCount", "cols": ["FreqTime"],
                         "opt": ["SendFreq"], "p": [1]}) == []
    assert "_wb_send_freq_pending" not in device.state
    assert device.state["_wb_frequency_timer_word"] == 16384

    request = VECTORS["freqCount"]["request"]
    assert send(device, request) == VECTORS["freqCount"]["response"]
    assert {key: device.state[key] for key in VECTORS["freqCount"]["state"]} == VECTORS["freqCount"]["state"]
    assert send(device, {"t": "freqCount", "cols": None, "opt": ["FreqTime"], "p": [8]}) == []
    assert device.state["_wb_frequency_timer_word"] == 16392
    assert send(device, {"t": "freqCount", "opt": ["SendFreq"], "p": [0]}) == []
    assert device.state["_wb_send_freq_pending"] == 1
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        send(device, {"t": "freqCount", "opt": ["DRTime"], "p": [8]})
    with pytest.raises(InvalidPacket):
        send(device, {"t": "freqCount", "opt": [{}], "p": [1]})
    with pytest.raises(InvalidPacket):
        send(device, {"t": "freqCount", "opt": ["SendFreq"] * 129, "p": [1] * 129})
    assert device.state == before


def test_upgrade_uses_direct_url_schema_but_never_runs_native_network_task(device):
    vector = VECTORS["upgrade"]
    before = deepcopy(device.state)
    assert send(device, vector["request"]) == [vector["response"]]
    assert device.state == before
    with pytest.raises(InvalidPacket):
        send(device, {"t": "upgrade"})
    with pytest.raises(InvalidPacket):
        send(device, {"t": "upgrade", "url": "x" * 120})
    assert device.state == before
