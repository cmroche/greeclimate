"""NR compiled SDK coverage must not become a fabricated UDP appliance."""
import json
from pathlib import Path

from gree_emulator.profiles import PROFILES

RESEARCH = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-early-nr_research.json").read_text())


def test_nr_source_has_no_udp_emulator_registration():
    assert RESEARCH["source_sha256"] == "f95499f24635d8d4cb3059facdbaed33b82f9d86be3a4879fbb4df0870496603"
    assert RESEARCH["classification"] == "non_lan_tcp_mqtt_only_in_closed_compiled_sdk_namespace"
    assert RESEARCH["emulator_profiles"] == []
    assert not any(profile.source_sha256 == RESEARCH["source_sha256"] for profile in PROFILES.values())


def test_nr_preserves_every_compiled_descriptor_and_metadata_initializer():
    assert RESEARCH["table_counts"] == [41, 46, 34, 8]
    assert RESEARCH["named_counts"] == [41, 44, 33, 8]
    rows = RESEARCH["properties"]
    assert len(rows) == 129
    assert sum(row["name"] is not None for row in rows) == 126
    assert sum(row["role"] == "internal_tuple_dependency" for row in rows) == 3
    assert len(RESEARCH["sdk_metadata"]) == 54
    assert RESEARCH["metadata_override_count"] == 11
    defaults = {row["name"]: row["initializer"] for row in RESEARCH["sdk_metadata"]}
    assert defaults["productName"] == "Gcloud"
    assert defaults["mid"] == "60"
    assert defaults["hid"] == "362001068561+U-WB05NR11V1.24.bin"
    assert defaults["subList"] is None
    assert defaults["gfTotEngy"] == 0
    assert all(row["writable"] for row in RESEARCH["sdk_metadata"])
    for category in ("ac", "filter", "water", "energy"):
        names = [row["name"] for row in rows if row["category"] == category]
        assert "TotEngy" in names
        assert "TotalEle" not in names and "ADRTotalEle" not in names


def test_nr_mid_roles_and_energy_getters_remain_source_distinct():
    roles = RESEARCH["mid_roles"]
    assert roles["root_default"] == "60"
    assert roles["filter_configured"] == ["605d", "6079", "6084", "608d", "6091", "6098", "6099", "60a0", "60a4", "60a9"]
    assert roles["energy_configured"] == ["6083", "6094"]
    assert roles["emitted_aliases"] == {"608d": "6079", "6091": "6079", "6099": "6079", "60a9": "6079"}
    rows = RESEARCH["properties"]
    assert next(row for row in rows if row["category"] == "energy" and row["name"] == "TotEngy")["get_tuple"] == "001410"
    assert next(row for row in rows if row["category"] == "ac" and row["name"] == "TotEngy")["get_tuple"] is None
    assert RESEARCH["getter_vectors"][2]["dat"] == ["gf001", 65535000, -32768000, 4294967295, 1]
