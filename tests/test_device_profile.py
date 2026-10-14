"""Ordered conjunctive firmware-trait matching, independent of device classes."""
import pytest

from greeclimate import device_profile
from greeclimate.device_profile import DeviceProfile, match_device_profile

KNOWN_HID = "362001066763+U-W06A(P3)V6.04.bin"


@pytest.mark.parametrize("criteria", [
    {"mid": "9300"},
    {"firmware_code": "362001066763"},
    {"module": "W06A"},
    {"version": "6.04"},
    {"module": "W06A", "version": "6.04"},
    {"mid": "9300", "firmware_code": "362001066763",
     "module": "W06A", "version": "6.04"},
])
def test_every_specified_criterion_is_required(monkeypatch, criteria):
    profile = DeviceProfile(**criteria)
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (profile,))
    assert match_device_profile("9300", KNOWN_HID) is profile
    for name in criteria:
        mismatched = DeviceProfile(**dict(criteria, **{name: "different"}))
        monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (mismatched,))
        assert match_device_profile("9300", KNOWN_HID) is None


@pytest.mark.parametrize("hid", [None, "", "malformed", 9300, [], {}])
def test_mid_only_matches_without_firmware(monkeypatch, hid):
    profile = DeviceProfile(mid="9300")
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (profile,))
    assert match_device_profile("9300", hid) is profile


@pytest.mark.parametrize("mid", [None, "", "9300 ", 9300, [], {}])
def test_mid_is_exact_and_not_coerced(monkeypatch, mid):
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (DeviceProfile(mid="9300"),))
    assert match_device_profile(mid, KNOWN_HID) is None


@pytest.mark.parametrize("criterion", ["firmware_code", "module", "version"])
@pytest.mark.parametrize("hid", [
    None, "", "malformed", 9300, [], {},
    "362001066763", "362001066763+",
    KNOWN_HID.replace("6.04", "6..04"),
    "extra" + KNOWN_HID, KNOWN_HID + "extra", KNOWN_HID + "\n",
])
def test_missing_firmware_cannot_satisfy_criterion(monkeypatch, criterion, hid):
    value = {"firmware_code": "362001066763", "module": "W06A", "version": "6.04"}[criterion]
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (
        DeviceProfile(mid="9300", **{criterion: value}),
    ))
    assert match_device_profile("9300", hid) is None


@pytest.mark.parametrize("hid", [
    "362001066763+U-W06A(P3)V6.04.bin",
    "362001066763+W06A(LT)V6.04.bin",
    "362001066763+W06AV6.04.bin",
])
def test_module_excludes_prefix_and_qualifier(monkeypatch, hid):
    profile = DeviceProfile(module="W06A", version="6.04")
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (profile,))
    assert match_device_profile(None, hid) is profile
    for module in ("U-W06A", "W06A(P3)", "W06A(LT)"):
        monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (
            DeviceProfile(module=module),
        ))
        assert match_device_profile(None, hid) is None


def test_version_is_literal_firmware_version(monkeypatch):
    profile = DeviceProfile(version="6.04")
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (profile,))
    assert match_device_profile(None, None) is None
    assert match_device_profile(None, KNOWN_HID.replace("6.04", "6.4")) is None
    assert match_device_profile(None, KNOWN_HID) is profile


@pytest.mark.parametrize("mid,hid", [(None, None), ("9300", KNOWN_HID)])
def test_unconstrained_profile_does_not_match(monkeypatch, mid, hid):
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (DeviceProfile(),))
    assert match_device_profile(mid, hid) is None


def test_first_matching_profile_wins_without_hid_precedence_or_merging(monkeypatch):
    first = DeviceProfile(mid="9300", settings={"cooling_mode_value": 0})
    second = DeviceProfile(firmware_code="362001066763",
                           settings={"cooling_mode_value": 5, "other": "second"})
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (first, second))
    assert match_device_profile("9300", None) is first
    selected = match_device_profile("9300", KNOWN_HID)
    assert selected is first
    assert selected.settings == {"cooling_mode_value": 0}
    assert match_device_profile(None, KNOWN_HID) is second
    assert match_device_profile("unknown", KNOWN_HID) is second
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (second, first))
    assert match_device_profile("9300", KNOWN_HID) is second
