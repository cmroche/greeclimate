import pytest

from greeclimate.mid_profile import FALLBACK_MID_PROFILE, KNOWN_MID_PROFILES, match_mid_profile


@pytest.mark.parametrize("mid", ["0001", "10f01"])
def test_exact_mid_matches_registry_object(mid):
    expected = next(profile for profile in KNOWN_MID_PROFILES if profile.mid == mid)
    assert match_mid_profile(mid) is expected


@pytest.mark.parametrize("mid", [
    1, "1", "10F01", " 0001", "unrecorded", None, "", [], {},
])
def test_unknown_or_malformed_mid_uses_fallback(mid):
    assert match_mid_profile(mid) is FALLBACK_MID_PROFILE
