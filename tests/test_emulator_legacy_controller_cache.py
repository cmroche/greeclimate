"""Independent original setter->getter vectors for both exact legacy70 sources."""
import json
from pathlib import Path

import pytest

from gree_emulator.profiles.controller import (
    LEGACY_CLOUD_COLUMNS, LEGACY_CONTROLLER_FIELDS, LEGACY_CONTROLLER_HID,
    LEGACY_CONTROLLER_SOURCES, LegacyControllerCache,
)
from gree_emulator.wire import InvalidPacket

FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator"
                      / "legacy-controller-readback_research.json").read_text())


@pytest.mark.parametrize("source", FIXTURE["sources"], ids=lambda s: s["source_sha256"][:12])
def test_every_original_callback_mutation_and_independent_fresh_getter(source):
    assert len(LEGACY_CONTROLLER_FIELDS) == 70
    assert {row["name"] for row in source["vectors"]} == LEGACY_CONTROLLER_FIELDS
    for row in source["vectors"]:
        cache = LegacyControllerCache(source["source_sha256"],
                                      bytes([row["uniform_initial_byte"]]) * 87)
        reply = cache.command([row["name"]], [row["requested"]])
        assert cache.raw.hex() == row["raw_after_hex"], (row["name"], row["requested"])
        assert reply == {"t": "res", "opt": [row["name"]],
                         "val": [row["fresh_value"]]}, (row["name"], row["requested"])
        assert cache.dat([row["name"]])["dat"] == [row["fresh_value"]]


@pytest.mark.parametrize("source", LEGACY_CONTROLLER_SOURCES)
def test_source_unknown_getters_keep_null_and_invalid_commands_are_atomic(source):
    cache = LegacyControllerCache(source)
    assert cache.dat(["Pow", "unknown", "Pow"]) == {
        "t": "dat", "cols": ["Pow", "unknown", "Pow"], "dat": [0, None, 0]}
    before = bytes(cache.raw)
    for name, value in (("unknown", 1), ("Pow", True), ("Pow", None),
                        ("Pow", 2147483648), ("Pow", -2147483649), ("Pow", "1")):
        with pytest.raises(InvalidPacket):
            cache.command(["Pow", name], [1, value])
        assert bytes(cache.raw) == before
    with pytest.raises(InvalidPacket):
        cache.command(["Pow"], [])
    assert bytes(cache.raw) == before


@pytest.mark.parametrize("source", LEGACY_CONTROLLER_SOURCES)
def test_duplicate_final_readback_crossfield_aliases_and_isolation(source):
    cache = LegacyControllerCache(source)
    assert cache.command(["Pow", "Pow"], [1, 0]) == {
        "t": "res", "opt": ["Pow", "Pow"], "val": [0, 0]}
    cache.command(["EnvArea1St", "EnvArea4St"], [1, 1])
    assert cache.dat(["EnvArea1St", "EnvArea4St"])["dat"] == [0, 1]
    cache.command(["SvSt", "Mod"], [1, 4])
    assert cache.read("SvSt") == 0
    cache.command(["AssHt", "Blo"], [1, 1])
    assert cache.dat(["AssHt", "Blo"])["dat"] == [0, 0]  # shared bit; heat-mode Blo gate
    cache.command(["TemSen"], [255])
    assert cache.read("TemSen") == 50
    assert LegacyControllerCache(source).read("TemSen") == 0


def test_exact_qcom_cloud_adapter_has_fifteen_source_columns_and_string_values():
    cache = LegacyControllerCache(LEGACY_CONTROLLER_SOURCES[1])
    report = cache.cloud_command({"Pow": 1, "SetTem": 22, "Mod": 1})
    assert tuple(report) == LEGACY_CLOUD_COLUMNS
    assert report == {"Lig": "0", "AssHt": "0", "SwhSlp": "0", "SlpMod": "0",
                      "WdSpd": "0", "SetTem": "22", "TemSen": "0", "Pow": "1",
                      "Blo": "0", "Emod": "0", "Mod": "1", "Quiet": "0",
                      "SwingLfRig": "0", "SwUpDn": "0", "Tur": "0"}
    assert LEGACY_CONTROLLER_HID == "362001000968+U-CS532BJ(MTK)V0.0.bin"
    assert "t" not in report and "mac" not in report and "r" not in report
    with pytest.raises(InvalidPacket):
        LegacyControllerCache(LEGACY_CONTROLLER_SOURCES[0]).cloud_command({"Pow": 1})
    with pytest.raises(ValueError):
        LegacyControllerCache("guessed-same-MID")
