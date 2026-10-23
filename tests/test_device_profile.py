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
                         (CODE + "+U-CS532AE.bin", None),
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
    ("362001065279+U-WB05RT13V1.45.bin", [5, 25, -15]),
    ("362001065279+U-WB05RT13V1.54.bin", [5, 25, -15]),
    ("362001065279+U-WB05RT13V1.64.bin", [5, 25, -15]),
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
    "362001061433+U-W06AV7.bin",
    "362001067012+U-W06AV16.bin",
    "362001066326+U-WB05BRV1.18.bin",
    "362001066380+U-WB05BRV1.38.bin",
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


@pytest.mark.parametrize("code,buzzer,offset,relearn,dialect", [
    ("362001000762", (), 40, False, None),
    ("362001060499", ("Buzzer_ON_OFF",), 0, False, None),
    ("362001061383", ("Buzzer_ON_OFF",), 40, True, None),
    ("362001064973", ("Buzzer_ON_OFF",), 40, True, None),
    ("362001065016", ("Buzzer_ON_OFF",), 40, False, None),
    ("362001065279", ("Buzzer_ON_OFF",), 40, False, None),
    ("362001065634", ("Buzzer_ON_OFF",), None, False, "commercial"),
    ("362001066763", (), None, False, None),
    ("362001061649", (), None, False, None),
    ("362001000968", None, 0, False, None),
    ("362001063525", None, 40, False, None),
    ("362001061433", (), None, False, "w06"),
    ("362001067012", (), None, False, "w06"),
    ("362001066326", None, None, False, "wb"),
    ("362001066380", None, None, False, "wb"),
])
@pytest.mark.parametrize("suffix", [
    "", "+", "+incomplete", "+U-W04NV17.bin", "+OTHER(MTK)V999.0.bin",
])
def test_code_traits_apply_independently_of_module_and_version(code, buzzer, offset, relearn, dialect, suffix):
    profile = match_device_profile(code + suffix)
    assert profile is not None
    assert profile.firmware_code == code
    assert profile.buzzer_properties == buzzer
    assert profile.temperature_offset == offset
    assert profile.relearn_temperature_offset is relearn
    assert profile.gateway_dialect == dialect


def test_firmware_codes_have_one_consolidated_record():
    codes = [profile.firmware_code for profile in device_profile.KNOWN_PROFILES]
    assert len(codes) == len(set(codes))


@pytest.mark.parametrize("hid,code", [
    ("362001061433+U-W06AV7.bin", "362001061433"),
    ("362001067012+U-W06AV16.bin", "362001067012"),
    ("362001066326+U-WB05BRV1.16.bin", "362001066326"),
    ("362001066326+U-WB05BRV1.18.bin", "362001066326"),
    ("362001066380+U-WB05BRV1.13.bin", "362001066380"),
    ("362001066380+U-WB05BRV1.22.bin", "362001066380"),
    ("362001066380+U-WB05BRV1.31.bin", "362001066380"),
    ("362001066380+U-WB05BRV1.38.bin", "362001066380"),
])
def test_embedded_gateway_identity_matches_code_not_ota_label(hid, code):
    profile = match_device_profile(hid)
    assert profile is not None
    assert profile.firmware_code == code
    assert profile is match_device_profile(code)
    assert profile is match_device_profile(code + "+arbitrary-module-V999.bin")
    assert match_device_profile("0" + hid) is None
    assert match_device_profile(hid.replace("+", " +", 1)) is None


def test_w06_ota_lookup_alias_is_not_registered_as_embedded_firmware():
    assert match_device_profile("362001060168+U-W06AV30.bin") is None
