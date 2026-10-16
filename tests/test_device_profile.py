"""Firmware-code matching with numeric minimum-version precedence."""
from itertools import permutations

import pytest

from greeclimate import device_profile
from greeclimate.device import Device, DeviceInfo
from greeclimate.device_profile import DeviceProfile, match_device_profile
from tests.test_device import get_mock_info

KNOWN_HID = "362001000762+U-CS532AE(LT)V3.33.bin"
CODE = "362001000762"


@pytest.mark.parametrize("hid", [
    None, "", "malformed", 9300, [], {},
    CODE, CODE + "+", KNOWN_HID.replace("3.33", "3..33"),
    "extra" + KNOWN_HID, KNOWN_HID + "extra", KNOWN_HID + "\n",
])
def test_complete_hid_is_required(hid):
    assert match_device_profile(hid) is None


@pytest.mark.parametrize("hid", [
    "362001000762+U-CS532AE(LT)V3.33.bin",
    "362001000762+CS532AE(MTK)V3.33.bin",
    "362001000762+CS532AEV3.33.bin",
    "362001000762+U-DIFFERENTV99.bin",
])
def test_module_and_qualifier_do_not_constrain_matching(monkeypatch, hid):
    profile = DeviceProfile(CODE, 40)
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (profile,))
    assert match_device_profile(hid) is profile


@pytest.mark.parametrize("order", list(permutations(range(3))))
def test_greatest_eligible_minimum_wins(monkeypatch, order):
    profiles = (
        DeviceProfile(CODE, 0),
        DeviceProfile(CODE, 40, min_version="3.10", relearn_temperature_offset=True),
        DeviceProfile(CODE, 0, min_version="4"),
    )
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", tuple(profiles[i] for i in order))
    for version, index in [("3.9", 0), ("3.10", 1), ("3.11", 1), ("4", 2), ("4.0.0", 2)]:
        assert match_device_profile(KNOWN_HID.replace("3.33", version)) is profiles[index]


def test_no_eligible_minimum_or_other_code_returns_none(monkeypatch):
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (
        DeviceProfile(CODE, 40, min_version="4"),
        DeviceProfile("999999999999", 0),
    ))
    assert match_device_profile(KNOWN_HID) is None
    assert match_device_profile(KNOWN_HID.replace(CODE, "888888888888")) is None


@pytest.mark.parametrize("first_floor,second_floor,reported", [
    ("1.2", "1.2.0", "1.2.0.0"),
    ("1.05", "1.5", "1.5"),
    ("0", "0.0", "0.0.0"),
    (None, None, "3.33"),
])
def test_equivalent_minima_and_fallback_ties_keep_first(monkeypatch, first_floor, second_floor, reported):
    first = DeviceProfile(CODE, 0, min_version=first_floor)
    second = DeviceProfile(CODE, 40, min_version=second_floor, relearn_temperature_offset=True)
    for profiles in [(first, second), (second, first)]:
        monkeypatch.setattr(device_profile, "KNOWN_PROFILES", profiles)
        assert match_device_profile(KNOWN_HID.replace("3.33", reported)) is profiles[0]


def test_zero_floor_overrides_fallback(monkeypatch):
    floor = DeviceProfile(CODE, 40, min_version="0")
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (DeviceProfile(CODE, 0), floor))
    assert match_device_profile(KNOWN_HID.replace("3.33", "0.0")) is floor


@pytest.mark.asyncio
async def test_only_reported_hid_selects_versioned_quirks(monkeypatch):
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (
        DeviceProfile(CODE, 0), DeviceProfile(CODE, 40, min_version="3.10"),
    ))
    info = list(get_mock_info())
    info[-1] = "99.0"
    device = Device(DeviceInfo(*info))
    hid = KNOWN_HID.replace("3.33", "3.09")
    device.handle_state_update(hid=hid, TemSen=45, TemUn=0)
    assert device.current_temperature == 45
    assert device.hid == hid
    assert device.version == "3.09"
    device.version = "99.0"
    assert device.current_temperature == 45
    hid = KNOWN_HID.replace("3.33", "3.10.0")
    device.handle_state_update(hid=hid)
    assert device.current_temperature == 5
    assert device.version == "3.10.0"
    assert device.hid == hid
    device.version = "0"
    assert device.current_temperature == 5
