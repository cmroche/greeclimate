import pytest

from greeclimate.mid_profile import match_mid_profile


@pytest.mark.parametrize("mid", [
    1, "1", "10F01", " 0001", "unrecorded", None, "", [], {},
])
def test_unknown_or_malformed_mid_uses_fallback(mid):
    assert match_mid_profile(mid).status_columns == ("hid",)
