"""Do not turn cloud/controller source identities into ordinary UDP appliances."""

import json
from pathlib import Path

from gree_emulator.profiles import PROFILES


FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-early-opaque_research.json").read_text())


def test_opaque_controller_sources_do_not_gain_an_unqualified_udp_facade():
    sources = FIXTURE["sources"] + FIXTURE["unregistered_sources"]
    # These are independently inventoried payloads, not aliases from the registry.
    expected_hashes = {
        "b808c5a0a0f147f399b42a5b007f93c001a5a7c93986e3997c15aa404bac3a49",
        "d4508fefa2cfc8029643dc40d270b8fbeefcf83f2fc59275eb8f415ae13ee5c1",
        "efbd09c92362e8da6adccf6c7c2e291e94ceb90bcf7b7467549d8ac1b2eaa4dc",
        "431d28f24075accf3f44cb875680ef52cf323f72be8def330195ab173bb1ba0c",
    }
    assert {source["source_sha256"] for source in sources} == expected_hashes
    assert sum(len(source["source_associations"]) for source in sources) == 5
    assert expected_hashes.isdisjoint(profile.source_sha256 for profile in PROFILES.values())
