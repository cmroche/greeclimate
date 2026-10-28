"""Complete finite DV namespaces, source/raw versus synthetic readout boundaries."""
import json
from pathlib import Path

import pytest

from gree_emulator.profiles import controller as controller_profile
from gree_emulator.wire import InvalidPacket
from tests.test_emulator_dv302 import controller, exchange, poll

VECTORS = json.loads((Path(__file__).parent / "fixtures" / "emulator"
                      / "controller-closure_research.json").read_text())
PROFILES = tuple(VECTORS["sources"])


@pytest.mark.parametrize("profile", PROFILES)
def test_complete_source_getter_table(profile):
    device = controller(profile)
    expected = {**VECTORS["string_metadata"], **VECTORS["numeric_metadata"],
                **VECTORS["scalar_initial"], "mac": device.mac, "mid": "3018",
                "hid": device.profile.hid, "name": device.name,
                **{name: 0 for name in VECTORS["raw_readouts"]}}
    assert len(expected) + len(VECTORS["empty_metadata"]) == 103
    for name, value in expected.items():
        assert poll(device, [name, name]) == {
            "t": "dat", "r": 200, "mac": device.mac,
            "cols": [name, name], "dat": [value, value]}
    for name in VECTORS["empty_metadata"]:
        assert poll(device, [name, "Pow", name]) == {
            "t": "dat", "r": 200, "mac": device.mac,
            "cols": [name, "Pow", name], "dat": [0]}
    assert poll(device, VECTORS["unknown"])["cols"] == []


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("name,limit", VECTORS["scalar_limits"].items())
def test_complete_scalar_commands_keep_requested_ack_and_byte_storage(profile, name, limit):
    device = controller(profile)
    values = [0, limit]
    reply = exchange(device, {"t": "cmd", "opt": [name, name], "p": values})
    assert reply == {"t": "res", "r": 200, "opt": [name, name],
                     "p": values, "val": values}
    stored = VECTORS["scalar_initial"][name] if name in VECTORS["no_store"] else limit & 255
    assert poll(device, [name, name])["dat"] == [stored, stored]
    assert poll(controller(profile), [name])["dat"] == [VECTORS["scalar_initial"][name]]
    before = dict(device.state), device.name, device.last_step
    for invalid in (limit + 1, -1, True, None, "1", 1.5, [], {}):
        with pytest.raises(InvalidPacket):
            exchange(device, {"t": "cmd", "opt": ["Pow", name], "p": [1, invalid]})
        assert (device.state, device.name, device.last_step) == before


@pytest.mark.parametrize("profile", PROFILES)
def test_raw_readouts_never_gain_setters_or_climate_calibration(profile, monkeypatch):
    device = controller(profile)
    clock = [device.last_step]
    monkeypatch.setattr(controller_profile, "monotonic", lambda: clock[0])
    for name in VECTORS["raw_readouts"] + VECTORS["source_excluded_commands"]:
        before = dict(device.state), device.name, device.last_step
        with pytest.raises(InvalidPacket):
            exchange(device, {"t": "cmd", "opt": ["Pow", name], "p": [1, 1]})
        assert (device.state, device.name, device.last_step) == before
    exchange(device, {"t": "cmd", "opt": ["Pow", "SetTem"], "p": [1, 257]})
    clock[0] += 120
    assert poll(device, ["TemSor", "Health", "Lig", "SetTem"])["dat"] == [0, 0, 0, 1]


def test_v401_metadata_final_text_and_source_host_no_store():
    vector = VECTORS["v401_metadata"]
    device = controller("sim-w06dv-v4.01")
    reply = exchange(device, vector["command"])
    assert reply["opt"] == vector["command"]["opt"]
    assert reply["p"] == reply["val"] == vector["ack"]
    assert poll(device, vector["fresh_columns"])["dat"] == vector["fresh_dat"]
    assert device.profile.handler.advertise(device, {"t": "scan"})[0].inner["name"] == "Last"
    fresh = controller("sim-w06dv-v4.01")
    assert poll(fresh, ["host", "time"])["dat"] == ["", "1970-01-01 00:00:00"]


@pytest.mark.parametrize("profile", PROFILES)
def test_exact_capacity_count_precedes_whitelist_filtering(profile):
    device = controller(profile)
    assert poll(device, ["Pow"] * 49)["dat"] == [0] * 49
    assert poll(device, ["Pow"] * 49 + ["Unknown"]) == {
        "t": "dat", "r": 200, "mac": device.mac, "cols": [], "dat": []}
    reply = exchange(device, {"t": "cmd", "opt": ["Pow"] * 50, "p": [1] * 50})
    assert reply == {"t": "res", "r": 200, "opt": [], "p": [], "val": []}
    assert poll(device, ["Pow"])["dat"] == [1]
    before = dict(device.state), device.last_step
    for inner in ({"t": "status", "mac": device.mac, "cols": ["Pow"] * 51},
                  {"t": "cmd", "opt": ["Pow"] * 51, "p": [0] * 51}):
        with pytest.raises(InvalidPacket):
            exchange(device, inner)
        assert (device.state, device.last_step) == before


def test_v401_metadata_amplification_is_preflighted_before_any_mutation():
    device = controller("sim-w06dv-v4.01")
    before = dict(device.state), device.name, device.last_step
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "cmd", "opt": ["name"] * 10, "p": ["x"] * 9 + ["x" * 90]})
    assert (device.state, device.name, device.last_step) == before
