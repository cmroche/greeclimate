"""Literal original-instruction expectations; no source-probe dependency at runtime."""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from gree_emulator.profiles.catalog_xr_timers import advance, handle_timer, refresh_clock
from gree_emulator.wire import InvalidPacket


EVIDENCE = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-xr-timers_research.json").read_text())
DEVICE = SimpleNamespace(mac="020000000001")
CLOCK = 1780272010  # Monday 2026-06-01T00:00:10Z, supplied virtual RTC.


def record(identifier=1, **values):
    result = deepcopy(EVIDENCE["base_record"])
    result.update(id=identifier, **values)
    return result


def store(state, identifier=1, operation="setT", **values):
    return handle_timer(DEVICE, state, dict(t=operation, **record(identifier, **values)))


def query(state, index=0, count=10):
    return handle_timer(DEVICE, state, dict(t="queryT", index=index, count=count))


def test_original_parser_and_int32_array_fixture():
    state = {}
    assert handle_timer(DEVICE, state, deepcopy(EVIDENCE["parser_request"])) == EVIDENCE["responses"]["stored"]
    assert handle_timer(DEVICE, state, EVIDENCE["parser_query_request"]) == EVIDENCE["parser_query_response"]
    assert state["_timers"][0]["tz"] == 255
    assert "tz" not in query(state)["list"][0]


def test_empty_query_omits_list_and_nonempty_out_of_range_includes_it():
    vector = EVIDENCE["empty_query"]
    state = {}
    assert handle_timer(DEVICE, state, vector["request"]) == vector["response"]
    assert state == {}
    store(state)
    assert handle_timer(DEVICE, state, vector["request"]) == {**vector["response"], "list": []}


def test_query_uses_original_ordinal_count_plus_one_and_insertion_order():
    state = {}
    vector = EVIDENCE["pagination"]
    for identifier in vector["insertion_ids"]:
        store(state, identifier)
    response = handle_timer(DEVICE, state, vector["request"])
    assert [item["id"] for item in response["list"]] == vector["expected_ids"]
    assert response["total"] == 1
    assert [item["id"] for item in query(state, 256, 256)["list"]] == [50]
    assert query(state, -1, -1) == {"t": "listT", "total": 255, "index": 255, "list": []}


def test_replacement_preserves_position_and_native_one_byte_value_merge():
    state = {}
    vector = EVIDENCE["replacement"]
    store(state, 7, cmd=[{"mac": ["a"], "opt": ["Pow"], "p": [vector["old_p"]]}])
    store(state, 2)
    store(state, 263, operation="updateT", cmd=[{"mac": ["b"], "opt": ["Mod"], "p": [vector["new_p"]]}])
    result = query(state)["list"]
    assert [item["id"] for item in result] == [7, 2]
    assert result[0]["cmd"] == [{"mac": ["b"], "opt": ["Mod"], "p": [vector["expected_p"]]}]


def test_set_and_update_share_insert_path_and_distinct_full_responses():
    state = {}
    for identifier in range(10):
        assert store(state, identifier, operation="updateT") == {"t": "resT", "r": 200}
    before = deepcopy(state)
    assert store(state, 10) == {"t": "resT", "r": 500}
    assert state == before
    assert store(state, 10, operation="updateT") is None
    assert state == before
    assert store(state, 256, name="replace") == {"t": "resT", "r": 200}
    assert len(state["_timers"]) == 10
    assert query(state)["list"][0]["name"] == "replace"


def test_original_delete_unknown_is_success_not_inferred_silence():
    state = {}
    request = {"t": "deleteT", "id": 256}
    assert handle_timer(DEVICE, state, request) == EVIDENCE["responses"]["delete_unknown"]
    store(state, 0)
    store(state, 2)
    assert handle_timer(DEVICE, state, request) == EVIDENCE["responses"]["delete_known"]
    assert [item["id"] for item in query(state)["list"]] == [2]
    assert handle_timer(DEVICE, state, request) == EVIDENCE["responses"]["delete_unknown"]


def test_unsigned_seconds_numeric_enable_and_short_week():
    state = {}
    store(state, sec=-1, enable=-2, week=[-2147483648, 256])
    item = query(state)["list"][0]
    assert (item["hr"], item["min"], item["sec"], item["enable"]) == (1193046, 28, 15, 1)
    assert item["week"] == [-2147483648, 256, 0, 0, 0, 0, 0]


def test_empty_mac_and_p_zero_fill_only_first_option():
    state = {}
    store(state, cmd=[{"mac": [], "opt": ["Pow", None], "p": []}])
    assert query(state)["list"][0]["cmd"] == [{"mac": [], "opt": ["Pow"], "p": [0]}]


def test_original_case_insensitive_json_member_lookup():
    request = {key.upper(): value for key, value in dict(t="setT", **record()).items()}
    state = {}
    assert handle_timer(DEVICE, state, request) == {"t": "resT", "r": 200}
    assert query(state)["list"][0]["id"] == 1
    assert handle_timer(DEVICE, state, {"t": []}) is None


@pytest.mark.parametrize("values", [
    {"name": "x" * 20}, {"name": "\0"}, {"name": "é" * 10},
    {"week": [0] * 8}, {"week": [True]}, {"week": [1 << 31]},
    {"cmd": []}, {"cmd": [{"opt": [], "p": [1]}]},
    {"cmd": [{"opt": ["Pow"], "mac": ["a"] * 11, "p": [1]}]},
    {"cmd": [{"opt": ["Pow"], "p": [1] * 31}]},
    {"cmd": [{"opt": ["Pow"], "p": [True]}]},
    {"cmd": [{"opt": ["Pow"], "mac": [5], "p": [1]}]},
    {"cmd": [{"opt": ["Pow"], "p": [1]}] * 11},
    {"enable": True}, {"hr": 1.5}, {"tz": "0"},
])
def test_unsafe_parser_shapes_reject_atomically(values):
    state = {"_clock": CLOCK}
    store(state)
    before = deepcopy(state)
    with pytest.raises(InvalidPacket):
        store(state, 2, **values)
    assert state == before


@pytest.mark.parametrize("command", [
    [{"mac": ["a", "b"], "opt": ["Pow"], "p": [1]}],
    [{"mac": ["longer"], "opt": ["Pow"], "p": [1]}],
    [{"mac": ["a"], "opt": ["SetTem"], "p": [1]}],
    [{"mac": ["a"], "opt": ["Pow"], "p": [1]}] * 2,
])
def test_native_replacement_allocation_growth_rejects_before_mutation(command):
    state = {}
    store(state, cmd=[{"mac": ["a"], "opt": ["Pow"], "p": [0x12345678]}])
    before = deepcopy(state)
    with pytest.raises(InvalidPacket):
        store(state, operation="updateT", cmd=command)
    assert state == before


def test_serialized_persistence_window_is_atomic_and_per_device():
    state = {}
    huge = [{"mac": ["a" * 1023] * 10, "opt": ["Pow"], "p": [1]}]
    assert store(state, cmd=huge) == {"t": "resT", "r": 500}
    assert state == {}
    assert store(state, operation="updateT", cmd=huge) is None
    assert state == {}
    store(state)
    other = {}
    store(other, 9)
    handle_timer(DEVICE, state, {"t": "deleteT", "id": 1})
    assert query(state) == {"t": "listT", "total": 10, "index": 0}
    assert query(other)["list"][0]["id"] == 9


def test_clock_threshold_and_explicit_time_refresh():
    state = {"_clock": 0}
    store(state, sec=12)
    assert state["_timers"][0]["_remaining"] == 0
    assert advance(DEVICE, state, 0, 1000) == []
    assert state["_timers"][0]["enable"] == 0
    refresh_clock(state, 0x5b03b45b)
    assert state["_timers"][0]["_remaining"] == 0
    assert not state["_timer_clock_valid"]
    refresh_clock(state, CLOCK)
    assert state["_timers"][0]["_remaining"] == 2
    assert state["_timer_clock_valid"]


def test_one_shot_due_disables_without_fabricated_root_command():
    state = {"_clock": CLOCK, "_cache": [7] * 495}
    store(state, sec=12)
    assert advance(DEVICE, state, CLOCK, CLOCK + 0.9) == []
    assert state["_timers"][0]["_remaining"] == 2
    assert advance(DEVICE, state, CLOCK + 0.9, CLOCK + 2) == []
    assert state["_timers"][0]["_remaining"] == 0
    assert state["_timers"][0]["enable"] == 0
    assert advance(DEVICE, state, CLOCK + 2, CLOCK + 3) == []
    assert state["_timers"][0]["enable"] == 1
    assert state["_timers"][0]["_remaining"] == -(CLOCK + 3)
    assert state["_timer_dirty"]
    assert state["_timer_output"] == [0] * 6
    assert state["_cache"] == [7] * 495
    assert query(state)["list"][0]["enable"] == 1


def test_repeat_uses_sunday_first_week_and_fires_at_remaining_one():
    state = {"_clock": CLOCK}
    store(state, sec=12, week=[0, -1, 0, 0, 0, 0, 0], tz=255)
    advance(DEVICE, state, CLOCK, CLOCK + 1)
    assert state["_timers"][0]["_remaining"] == 1
    assert state["_timers"][0]["enable"] == 0
    assert state["_timer_dirty"]
    advance(DEVICE, state, CLOCK + 1, CLOCK + 3)
    assert state["_timers"][0]["_remaining"] == -(CLOCK + 3)
    assert state["_timers"][0]["enable"] == 0
    other = {"_clock": CLOCK}
    store(other, sec=12, week=[0, 0, 1, 0, 0, 0, 0])
    advance(DEVICE, other, CLOCK, CLOCK + 300)
    assert other["_timers"][0]["_remaining"] == 2
    assert "_timer_dirty" not in other


def test_midnight_refresh_and_disabled_record_lifecycle():
    # Last second of Sunday before the qualified source-probe Monday.
    state = {"_clock": CLOCK - 11}
    store(state, sec=5, week=[0, 1, 0, 0, 0, 0, 0])
    advance(DEVICE, state, CLOCK - 11, CLOCK - 10)
    assert state["_timers"][0]["_remaining"] == 4
    disabled = {"_clock": CLOCK}
    store(disabled, sec=12, enable=1)
    advance(DEVICE, disabled, CLOCK, CLOCK + 100)
    assert disabled["_timers"][0]["_remaining"] == 2
    assert "_timer_dirty" not in disabled


def test_past_active_timer_uses_original_uart_sentinel_without_execution():
    state = {"_clock": CLOCK}
    store(state, sec=5)
    assert state["_timer_output"] == [23, 59, 59, 23, 59, 59]
    advance(DEVICE, state, CLOCK, CLOCK + 100)
    assert state["_timers"][0]["enable"] == 0
    assert state["_timers"][0]["_remaining"] == -5
    assert "_timer_dirty" not in state


def test_batched_advance_preserves_one_shot_across_days_and_fresh_state():
    state = {"_clock": CLOCK}
    store(state, sec=12)
    advance(DEVICE, state, CLOCK, CLOCK + 86400 * 20)
    assert state["_timers"][0]["enable"] == 1
    # Every source midnight refreshes even disabled records; no repeat execution.
    assert state["_timers"][0]["_remaining"] == 12
    assert state["_timer_dirty"]
    assert query({}) == {"t": "listT", "total": 10, "index": 0}


def test_native_midnight_refresh_repeats_for_every_node_in_order():
    vector = EVIDENCE["scheduler"]["midnight_order"]
    state = {"_clock": vector["clock"] - 1}
    for identifier, seconds in enumerate(vector["stored_seconds"]):
        store(state, identifier, sec=seconds, week=[0, 1, 0, 0, 0, 0, 0])
    advance(DEVICE, state, vector["clock"] - 1, vector["clock"])
    assert [item["_remaining"] for item in state["_timers"]] == vector["expected_remaining"]
