"""Firmware-code policy regressions, backed by inspected-build observations."""

import pytest

from greeclimate import device_profile
from greeclimate.air_conditioner import AirConditionerDevice
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.device_profile import DeviceProfile, match_device_profile
from tests.test_device import get_mock_info

KNOWN_HID = "362001000762+U-CS532AE(LT)V3.33.bin"
CODE = "362001000762"


@pytest.mark.parametrize("hid", [
    None, "", "malformed", 9300, [], {},
    "extra" + KNOWN_HID, CODE + "extra", CODE + "0+suffix",
    CODE + " ", " " + CODE, "999999999999+U-UNKNOWNV1.bin",
])
def test_unknown_or_nonstring_code_has_no_profile(hid):
    assert match_device_profile(hid) is None


@pytest.mark.asyncio
async def test_reported_code_selects_traits_independently_of_display_version(monkeypatch):
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (DeviceProfile(CODE, 40),))
    info = list(get_mock_info())
    info[-1] = "99.0"
    device = AirConditionerDevice(DeviceInfo(*info))
    assert device.current_temperature is None
    for hid, version in [(CODE, None), (CODE + "+incomplete", None),
                         (KNOWN_HID, "3.33"),
                         (KNOWN_HID.replace("3.33", "99"), "99")]:
        device.handle_state_update(hid=hid, TemSen=45, TemUn=0)
        assert device.current_temperature == 5
        assert device.hid == hid
        assert device.version == version
        device.version = "0"
        assert device.current_temperature == 5


@pytest.mark.asyncio
@pytest.mark.parametrize("hid,expected", [
    ("362001064973+U-W04NV17.bin", [5, 25, 25]),
    ("362001064973+U-W04NV19.bin", [5, 25, 25]),
    ("362001065016+U-W04HMV1.05.bin", [5, 25, -15]),
])
async def test_code_buzzer_profile_keeps_existing_temperature_calibration(hid, expected):
    device = AirConditionerDevice(DeviceInfo(*get_mock_info()))
    device.handle_state_update(hid=hid, TemUn=0, TemRec=0)
    for raw, temperature in zip([45, 65, 25], expected):
        device.handle_state_update(TemSen=raw)
        assert device.current_temperature == temperature
        assert device.raw_properties["TemSen"] == raw


@pytest.mark.asyncio
@pytest.mark.parametrize("hid", [
    "362001065634+U-WB04BRT13V1.50.bin",
    "362001066763+U-W06A(P3)V6.04.bin",
])
@pytest.mark.parametrize("samples,expected", [
    ([35, 45], [35, 45]),
    ([45, 35], [5, -5]),
    ([65, 25], [25, -15]),
])
async def test_profile_without_temperature_default_preserves_guessed_and_learned_temperature(hid, samples, expected):
    device = AirConditionerDevice(DeviceInfo(*get_mock_info()))
    device.handle_state_update(hid=hid, TemUn=0, TemRec=0)
    for raw, temperature in zip(samples, expected):
        device.handle_state_update(TemSen=raw)
        assert device.current_temperature == temperature
