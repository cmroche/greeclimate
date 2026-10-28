"""Do not expose cloud/provisioning callbacks as an ordinary LAN appliance."""

import json
from pathlib import Path

from gree_emulator.profiles import PROFILES


FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures/emulator/catalog-early-crj_research.json").read_text()
)


def test_crj_cloud_source_is_not_registered_as_udp_appliance():
    assert all(profile.source_sha256 != FIXTURE["source_sha256"] for profile in PROFILES.values())
