"""Literal CV2/V7 local schedule contracts; no profile-generated expectations."""
from copy import deepcopy

import pytest

from gree_emulator.profiles.catalog_cv_schedule import due_queue, handle
from gree_emulator.wire import InvalidPacket


MAC = "020000000001"


def request(identifier=0, **changes):
    value = {"t": "setT", "id": identifier, "name": "wake", "enable": 0,
             "hr": 6, "min": 8, "sec": 59, "tz": 255,
             "week": [0, 0, 0, 0, 0, 0, 0],
             "cmd": [{"mac": ["020000000002"], "opt": ["Mod"], "p": [-1]}]}
    value.update(changes)
    return value


def test_mutation_ack_fresh_query_and_id_order():
    schedules = []
    assert handle(schedules, request(3), MAC) == {"t": "resT", "r": 200}
    handle(schedules, request(0), MAC)
    assert [item["id"] for item in schedules] == [3, 0]
    assert handle(schedules, {"t": "queryT", "index": 3, "count": 2}, MAC) == {
        "t": "listT", "total": 10, "index": 3, "list": [
            {"id": 3, "name": "wake", "enable": 0, "hr": 6, "min": 8, "sec": 59,
             "week": [0, 0, 0, 0, 0, 0, 0],
             "cmd": [{"mac": [MAC], "opt": ["Pow"], "p": [4294967295]}]}]}
    assert handle(schedules, {"t": "queryT", "index": 1, "count": 9}, MAC) == {
        "t": "listT", "total": 10, "index": 1, "list": []}
    assert handle(schedules, {"t": "deleteT", "id": 3}, MAC) == {"t": "resT", "r": 200}
    assert [item["id"] for item in schedules] == [0]
    with pytest.raises(InvalidPacket):
        handle(schedules, {"t": "deleteT", "id": 3}, MAC)


def test_update_wraps_bytes_and_set_replaces_at_capacity():
    schedules = []
    for identifier in range(10):
        handle(schedules, request(identifier), MAC)
    handle(schedules, request(3, t="updateT", enable=256, hr=262, min=264,
                              sec=511, tz=-1, week=[-1, 2, 3, 4, 5, 6, 7]), MAC)
    assert {key: schedules[3][key] for key in ("enable", "hr", "min", "sec", "tz", "week")} == {
        "enable": 0, "hr": 6, "min": 8, "sec": 255, "tz": 255,
        "week": [4294967295, 2, 3, 4, 5, 6, 7]}
    handle(schedules, request(3, name="replacement"), MAC)
    assert len(schedules) == 10
    assert [item["id"] for item in schedules] == list(range(10))
    handle(schedules, {"t": "deleteT", "id": 3}, MAC)
    with pytest.raises(InvalidPacket):
        handle(schedules, request(3, t="updateT"), MAC)


@pytest.mark.parametrize("changes", [
    {"id": 10}, {"enable": 2}, {"hr": 24}, {"min": 60}, {"sec": 60},
    {"name": None}, {"name": "x" * 32}, {"week": [0] * 6},
    {"week": [False] * 7}, {"id": 1.0}, {"cmd": []},
    {"cmd": [{"mac": ["x" * 16], "opt": ["Pow"], "p": [1]}]},
    {"cmd": [{"mac": [MAC], "opt": ["unknown"], "p": [1]}]},
])
def test_unsafe_requests_rejected_without_mutation(changes):
    schedules = []
    handle(schedules, request(), MAC)
    before = deepcopy(schedules)
    with pytest.raises(InvalidPacket):
        handle(schedules, request(**changes), MAC)
    assert schedules == before


def test_due_original_inversion_ignored_seconds_selector_and_queue():
    schedules = []
    handle(schedules, request(cmd=[{"mac": [MAC], "opt": ["Pow"], "p": [1]}]), MAC)
    assert due_queue(schedules, 6, 8, 0, 0xa0) == 0xa3
    assert due_queue(schedules, 6, 8, 1, 0xa0) == 0xa0
    assert due_queue(schedules, 6, 8, 0, 0xa0, inhibited=True) == 0xa0
    schedules[0]["enable"] = 1
    assert due_queue(schedules, 6, 8, 0, 0xa0) == 0xa0
    schedules[0]["enable"] = 0
    schedules[0]["week"] = [0, 0, 0, 0, 0, 0, 1]
    schedules[0]["_selector"] = 1
    schedules[0]["p"] = 2
    assert due_queue(schedules, 6, 8, 0, 0xa0) == 0xa1
    schedules[0]["_selector"] = 4
    assert due_queue(schedules, 6, 8, 0, 0xa0) == 0xa0


def test_due_week_carry_crosses_nodes_and_ordered_conflicts():
    schedules = []
    handle(schedules, request(0, week=[0, 0, 1, 0, 0, 0, 0],
                              cmd=[{"mac": [MAC], "opt": ["Pow"], "p": [1]}]), MAC)
    handle(schedules, request(1, cmd=[{"mac": [MAC], "opt": ["Pow"], "p": [0]}]), MAC)
    # Second node's all-zero week inherits carry and reads p==0: it cannot clear Pow.
    assert due_queue(schedules, 6, 8, 0, 0xa0) == 0xa3
    schedules.reverse()
    assert due_queue(schedules, 6, 8, 0, 0xa0) == 0xa3
    schedules[1]["p"] = 0
    assert due_queue(schedules, 6, 8, 0, 0xa0) == 0xa1


def test_independent_lists_casefold_members_and_upgrade_block():
    left, right = [], []
    command = request()
    command["ID"] = command.pop("id")
    handle(left, command, MAC)
    assert right == []
    assert handle(left, {"t": "not-schedule"}, MAC) is None
    with pytest.raises(InvalidPacket, match="upgrade"):
        handle(left, {"t": "upgrade", "url": "https://invalid.example/never-fetch"}, MAC)
