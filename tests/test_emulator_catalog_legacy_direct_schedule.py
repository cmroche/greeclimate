"""Literal 65da timer expectations, not derived from CV or runtime output."""
from copy import deepcopy

import pytest

from gree_emulator.profiles.catalog_legacy_direct_schedule import due, schedule
from gree_emulator.wire import InvalidPacket

MAC = "020000000001"


def command(identifier=0, **changes):
    request = {"t": "setT", "id": identifier, "name": "wake", "enable": 0,
               "hr": 6, "min": 8, "sec": 9, "week": [0] * 7,
               "cmd": [{"mac": [MAC], "opt": ["Pow"], "p": [1]}]}
    request.update(changes)
    return request


def test_fixed_ids_global_total_and_partial_update_inserts():
    runtime = {}
    assert schedule(command(3), runtime, MAC, 0) == {"t": "resT", "r": 200}
    schedule(command(0, name="second"), runtime, MAC, 0)
    assert schedule({"t": "queryT", "index": 3, "count": 1}, runtime, MAC, 0) == {
        "t": "listT", "total": 2, "index": 3,
        "list": [{"id": 3, "name": "wake", "enable": 0, "hr": 6, "min": 8, "sec": 9,
                  "week": [0, 0, 0, 0, 0, 0, 0],
                  "cmd": [{"mac": [MAC], "opt": ["Pow"], "p": [1]}]}]}
    response = schedule({"t": "queryT", "index": 0, "count": 4}, runtime, MAC, 0)
    assert [item["id"] for item in response["list"]] == [0, 3]
    schedule({"t": "updateT", "id": 1, "cmd": [{"mac": [MAC], "opt": ["unknown"]}]},
             runtime, MAC, 0)
    assert runtime["timers"][1] == {
        "id": 1, "_valid": 1, "name": "", "enable": 0, "hr": 0,
        "min": 0, "sec": 0, "week": [0, 0, 0, 0, 0, 0, 0], "p": 0}
    assert schedule({"t": "deleteT", "id": 9}, runtime, MAC, 0) == {"t": "resT", "r": 200}
    schedule({"t": "deleteT", "id": 3}, runtime, MAC, 0)
    assert runtime["timers"][3]["_valid"] == 0
    assert runtime["timers"][3]["enable"] == 1
    assert runtime["timers"][3]["name"] == "wake"


def test_mutation_wraps_all_scalar_bytes_and_retains_other_fields():
    runtime = {}
    schedule(command(0, enable=256, hr=262, min=264, sec=265, week=[-1] * 7,
                     cmd=[{"mac": [MAC], "opt": ["Pow"], "p": [-1]}]), runtime, MAC, 0)
    schedule({"t": "updateT", "id": 0, "name": "renamed",
              "cmd": [{"mac": [MAC], "opt": ["unknown"], "p": [7]}]}, runtime, MAC, 0)
    assert runtime["timers"][0] == {
        "id": 0, "_valid": 1, "name": "renamed", "enable": 0,
        "hr": 6, "min": 8, "sec": 9, "week": [255] * 7, "p": 255}


@pytest.mark.parametrize("packet,index", [
    (command(10), 0), (command(), 256),
    ({"t": "setT", "id": 0, "mac": MAC}, 0),
    (command(week=[0] * 6), 0), (command(week=[True] * 7), 0),
    (command(name="x" * 32), 0), (command(hr=1.5), 0),
    (command(cmd=[{"mac": ["different"], "opt": ["Pow"]}]), 0),
    ({"t": "queryT", "index": 9, "count": 2}, 0),
])
def test_safe_rejection_is_atomic_and_has_no_fake_ack(packet, index):
    runtime = {}
    schedule(command(), runtime, MAC, 0)
    before = deepcopy(runtime)
    with pytest.raises(InvalidPacket):
        schedule(packet, runtime, MAC, index)
    assert runtime == before


def test_due_countdown_and_one_shot_disables_not_deletes():
    runtime = {}
    schedule(command(), runtime, MAC, 0)
    assert due(runtime, 6, 8, 0, 2) == {
        "flags": 128, "on": [0, 0, 9], "off": [0, 0, 0],
        "event": 0, "notify": 0, "trigger": False}
    assert due(runtime, 6, 8, 9, 2) == {
        "flags": 128, "on": [0, 0, 0], "off": [0, 0, 0],
        "event": 94, "notify": 128, "trigger": True}
    assert runtime["timers"][0]["_valid"] == 1
    assert runtime["timers"][0]["enable"] == 1


def test_due_weekday_exclusion_and_non_one_week_values():
    runtime = {}
    schedule(command(week=[0, 1, 0, 0, 0, 0, 0],
                     cmd=[{"mac": [MAC], "opt": ["Pow"], "p": [0]}]), runtime, MAC, 0)
    assert due(runtime, 6, 8, 0, 2) == {
        "flags": 64, "on": [0, 0, 0], "off": [23, 59, 59],
        "event": 0, "notify": 0, "trigger": False}
    runtime["timers"][0]["week"] = [255] * 7
    assert due(runtime, 6, 8, 0, 2)["off"] == [0, 0, 9]


def test_due_all_past_uses_fixed_maximum_and_nearest_opposite_polarity():
    runtime = {}
    schedule(command(), runtime, MAC, 0)
    assert due(runtime, 6, 8, 10, 2)["on"] == [23, 59, 59]
    schedule(command(0, min=9, sec=0), runtime, MAC, 0)
    schedule(command(1, sec=15, cmd=[{"mac": [MAC], "opt": ["Pow"], "p": [0]}]),
             runtime, MAC, 0)
    assert due(runtime, 6, 8, 0, 2) == {
        "flags": 192, "on": [23, 59, 59], "off": [0, 0, 15],
        "event": 0, "notify": 128, "trigger": False}
