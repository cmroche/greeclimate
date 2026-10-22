import pytest

from greeclimate.mid_profile import (
    FALLBACK_MID_PROFILE,
    KNOWN_MID_PROFILES,
    MidProfile,
    match_mid_profile,
)


@pytest.mark.parametrize("mid", ["0001", "10f01"])
def test_exact_mid_matches_registry_object(mid):
    expected = next(profile for profile in KNOWN_MID_PROFILES if profile.mid == mid)
    assert match_mid_profile(mid) is expected


@pytest.mark.parametrize("mid", [
    1, "1", "10F01", " 0001", "unrecorded", None, "", [], {},
])
def test_unknown_or_malformed_mid_uses_fallback(mid):
    assert match_mid_profile(mid) is FALLBACK_MID_PROFILE


@pytest.mark.parametrize("name,columns", [
    ("target_temperature", ("SetTem", "TemRec", "TemUn")),
    ("sleep", ("SwhSlp", "SlpMod")),
])
def test_composite_evidence_requires_every_exact_case_column(name, columns):
    for omitted in columns:
        incomplete = tuple(column for column in columns if column != omitted)
        assert name not in MidProfile("composite", incomplete, "air_conditioner").capabilities
    for renamed in columns:
        wrong_case = tuple(column.lower() if column == renamed else column for column in columns)
        assert name not in MidProfile("composite", wrong_case, "air_conditioner").capabilities
    assert MidProfile("composite", columns, "air_conditioner").capabilities[name] is True


def test_omitted_and_similarly_named_fields_do_not_declare_negative_or_alias_evidence():
    profile = MidProfile("partial", ("Pow", "SetTem", "TemUn", "HumSen", "Lamp", "Quier"),
                         "air_conditioner")
    assert profile.capabilities == {"power": True, "temperature_units": True}
    assert "target_temperature" not in profile.capabilities
    assert "lan_buzzer_control" not in profile.capabilities


@pytest.mark.parametrize("profile", [
    FALLBACK_MID_PROFILE,
    MidProfile(None, ("Pow", "Mod"), "air_conditioner"),
    MidProfile("untyped", ("Pow", "Mod")),
])
def test_missing_mid_or_untyped_profile_has_no_capability_evidence(profile):
    assert profile.capabilities == {}
