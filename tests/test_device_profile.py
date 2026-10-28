"""Firmware-code policy regressions, backed by inspected-build observations."""

import json
from pathlib import Path

import pytest

from greeclimate import device_profile
from greeclimate.air_conditioner import AirConditionerDevice
from greeclimate.cipher import CipherV1
from greeclimate.device import Device
from greeclimate.device_factory import create_device
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.device_profile import DeviceProfile, match_device_profile
from tests.test_device import get_mock_info

KNOWN_HID = "362001000762+U-CS532AE(LT)V3.33.bin"
CODE = "362001000762"

RESEARCH_IDENTITIES = json.loads(
    (Path(__file__).parent / "fixtures" / "device_profiles_research.json").read_text()
)["identities"]


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
    "362001063300+U-W05ZV2.28.bin",
    "362001062573+IS-T3BBW03V3.62.img",
    "362001066224+G01BV1.2.bin",
    "362001071823+ZTS31B3V1.092.bin",
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
    ("362001064270", ("Buzzer_ON_OFF",), 40, True, None),
    ("362001064973", ("Buzzer_ON_OFF",), 40, True, None),
    ("362001065016", ("Buzzer_ON_OFF",), 40, False, None),
    ("362001065279", ("Buzzer_ON_OFF",), 40, False, None),
    ("362001065634", ("Buzzer_ON_OFF",), None, False, "commercial"),
    ("362001067427", (), 40, False, None),
    ("362001066763", (), None, False, None),
    ("362001061649", (), None, False, None),
    ("362001000968", (), 0, False, None),
    ("362001061394", (), None, False, None),
    ("362001061895", (), None, False, None),
    ("362001062992", (), None, False, None),
    ("362001061329", (), None, False, None),
    ("362001061704", (), None, False, None),
    ("362001063222", (), None, False, None),
    ("362001063525", (), 40, False, None),
    ("362001061433", (), None, False, "w06"),
    ("362001061437", (), None, False, "w06"),
    ("362001067012", (), None, False, "w06"),
    ("362001066326", (), None, False, "wb"),
    ("362001066380", (), None, False, "wb"),
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
    ("362001061437+U-W06BV9.bin", "362001061437"),
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


def test_cellular_report_matches_embedded_code_not_ota_alias_without_trait_inference():
    profile = match_device_profile("362001066224+G01BV1.2.bin")
    assert profile is match_device_profile("362001066224")
    assert profile is not None
    assert profile.temperature_offset is None
    assert profile.buzzer_properties == ()
    assert profile.cooling_mode_value is None
    assert profile.capabilities == ()
    assert profile.gateway_dialect is None
    assert match_device_profile("362001066221+G01BV1.2.bin") is None


@pytest.mark.asyncio
@pytest.mark.parametrize("hid", [
    "362001061331+U-W05JV2.74.bin",
    "362001063147+U-M26SV3.05.bin",
    "362001061917+W05RV2.35.bin",
    "362001061996+U-W05G(RELT)V4.3.bin",
    "362001063300+U-W05ZV2.28.bin",
    "362001064475+W05BAV1.11.bin",
    "362001062573+IS-T3BBW03V3.62.img",
    "362001066380+U-WB05BRV1.13.bin",
    "362001066380+U-WB05BRV1.22.bin",
    "362001066380+U-WB05BRV1.31.bin",
    "362001066380+U-WB05BRV1.38.bin",
    "362001064231+U-WF-T710-RPGV1.43.bin",
    "362001065909+U-WB05_TGV1.30.bin",
    "362001063856+U-Hi3861-OldV1.13.bin",
    "362001061890+U-ESP32_GRV1.1.bin",
    "362001061898+U-ESP32_GRV2.5.bin",
    "362001062978+U-MSTWB801AV1.01.bin",
    "362001061394+U-W05NV1.03.bin",
    "362001061895+U-W05WV1.2.bin",
    "362001062992+U-W05XFV1.1.bin",
    "362001063222+U-ESP32_GR_CANV2.01.bin",
    "362001061329+U-W04RV2.03.bin",
    "362001061704+U-W04WV1.25.bin",
])
@pytest.mark.parametrize("suffix", [None, "+different-module-V999.bin"])
async def test_closed_named_namespaces_never_append_automatic_buzzer(hid, suffix, cipher, send):
    # Explicit AC construction exercises its buzzer consumer, not MID classification.
    device = AirConditionerDevice(DeviceInfo(*get_mock_info()))
    await device.bind(key="0123456789abcdef", cipher=CipherV1())
    if suffix is not None:
        hid = hid.partition("+")[0] + suffix
    device.handle_state_update(hid=hid)
    assert device.capabilities["lan_buzzer_control"] is False
    for enabled, value in [(False, 1), (True, 0)]:
        device.buzzer = enabled
        device.set_property("Pow", value)
        await device.push_state_update()
        assert send.call_args.args[0]["pack"]["opt"] == ["Pow"]
        assert send.call_args.args[0]["pack"]["p"] == [value]


@pytest.mark.asyncio
@pytest.mark.parametrize("hid,mid", [
    ("362001061331+U-W05JV2.74.bin", None),
    ("362001063147+U-M26SV3.05.bin", None),
    ("362001061917+W05RV2.35.bin", "80221"),
    ("362001061996+U-W05G(RELT)V4.3.bin", "80300"),
    ("362001063300+U-W05ZV2.28.bin", "80801"),
    ("362001064475+W05BAV1.11.bin", "80801"),
    ("362001062573+IS-T3BBW03V3.62.img", "80222"),
    ("362001064231+U-WF-T710-RPGV1.43.bin", None),
    ("362001065909+U-WB05_TGV1.30.bin", None),
    ("362001063856+U-Hi3861-OldV1.13.bin", "828202"),
    ("362001061890+U-ESP32_GRV1.1.bin", "80261"),
    ("362001061898+U-ESP32_GRV2.5.bin", "80261"),
    ("362001062978+U-MSTWB801AV1.01.bin", "80260"),
    ("362001061649+U-W06KV4.4.bin", "80241"),
    ("362001061649+U-W06KV4.4.bin", "80242"),
    ("362001060629", "809030"),
    ("362001060200", "13801"),
])
async def test_raw_identity_keeps_raw_consumer_commands(hid, mid, cipher, send):
    device = create_device(DeviceInfo(*get_mock_info(), mid=mid))
    assert type(device) is Device
    await device.bind(key="0123456789abcdef", cipher=CipherV1())
    device.handle_state_update(hid=hid, Pow=0)
    device.set_property("Pow", 1)
    await device.push_state_update()
    assert send.call_args.args[0]["pack"]["opt"] == ["Pow"]
    assert send.call_args.args[0]["pack"]["p"] == [1]
    assert device.capabilities["mode"] is None
    assert device.capabilities["current_temperature"] is None


@pytest.mark.asyncio
async def test_b20_report_qualifies_w06_inventory_and_child_raw_command():
    from tests.test_gateway import ROOT, gateway_peer

    async with gateway_peer("362001067524+U-W06BV20.bin") as (gateway, peer):
        child_id = "ab123456000001"
        child, = await peer.enumerate([{"mac": child_id, "mid": "604a"}])
        child.set_property("Pow", 1)
        await child.push_state_update()
        request = await peer.receive()
        assert request["inner"] == {
            "t": "cmd", "mac": ROOT, "sub": child_id,
            "opt": ["Pow"], "p": [1],
        }
        assert request["outer"]["tcid"] == ROOT


@pytest.mark.asyncio
@pytest.mark.parametrize("hid", [
    "362001000968+U-CS532BJ(MTK)V0.0.bin",
    "362001000968+different-module-V999.bin",
])
async def test_legacy_embedded_code_preserves_already_normalized_temperature(hid):
    device = AirConditionerDevice(DeviceInfo(*get_mock_info()))
    device.handle_state_update(hid=hid, TemSen=45, TemUn=0)
    assert device.current_temperature == 45
    device.handle_state_update(TemSen=22)
    assert device.current_temperature == 22


@pytest.mark.parametrize("hid", [
    "362001060009+U-CS532BJ(MTK)V0.0.bin",
    "362001060185+U-CS532BJ(MTK)V0.0.bin",
    "362001060705+U-W06DV3.02.bin",
    "362001060896+W06A(P3)V5.08.bin",
    "362001063084",
])
def test_ota_lookup_aliases_do_not_select_embedded_traits(hid):
    assert match_device_profile(hid) is None


@pytest.mark.parametrize(
    "identity", RESEARCH_IDENTITIES, ids=lambda identity: identity["firmware_code"],
)
def test_researched_identities_match_reported_hid_and_bare_code(identity):
    profile = match_device_profile(identity["hid"])
    assert profile is not None
    assert profile.firmware_code == identity["firmware_code"]
    assert profile is match_device_profile(identity["firmware_code"])


def test_compound_hid_uses_first_code_and_suffix_is_not_an_identity():
    identity = next(
        identity for identity in RESEARCH_IDENTITIES
        if identity["firmware_code"] == "362001062353"
    )
    code = identity["firmware_code"]
    profile = match_device_profile(identity["hid"])
    assert profile is not None
    assert profile.firmware_code == code
    assert profile is match_device_profile(code + "+unrelated-module-V999.bin")
    assert match_device_profile("362001063014+N-W05ACV0.00.bin") is None


def test_eleven_digit_identity_is_not_zero_padded():
    profile = match_device_profile("36300000257")
    assert profile is not None
    assert profile.firmware_code == "36300000257"
    assert match_device_profile("036300000257") is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "identity", RESEARCH_IDENTITIES, ids=lambda identity: identity["firmware_code"],
)
async def test_identity_only_profiles_report_buzzer_unsupported_and_out_of_commands(identity, cipher, send):
    device = AirConditionerDevice(DeviceInfo(*get_mock_info()))
    await device.bind(key="0123456789abcdef", cipher=CipherV1())
    device.handle_state_update(hid=identity["hid"])
    assert device.capabilities["lan_buzzer_control"] is False

    device.buzzer = False
    device.set_property("Pow", 1)
    await device.push_state_update()
    assert send.call_args.args[0]["pack"]["opt"] == ["Pow"]
    assert send.call_args.args[0]["pack"]["p"] == [1]


@pytest.mark.parametrize("hid", [
    "362001061894+U-W05WV1.1.bin",
    "362001066515+U-WB05FRV1.40.bin",
    "362001068561+U-WB05NR11V1.24.bin",
    "362001068811+U-WB06DRV1.03.bin",
    "362001068811+U-WB06DRV1.22.bin",
    "362001068811+U-WB06DRV1.30.bin",
    "362001068811+U-WB06DRV2.02.bin",
    "362001061446+U-W05SV1.30.bin",
    "362001062033+M16223SBV1.2.bin",
    "362001064696+U-WFR710RTG1(F11)V1.02.bin",
    "362001065567+U-WB05ART11V1.48.bin",
    "362001067522+U-WB05SRV1.08.bin",
    "362001068796+U-WB05DRAV2.05.bin",
    "362001068839+U-WB05DRBV1.30.bin",
    "362001063228+U-Hi3861V1.24.bin",
    "362001063534+U-Hi3861_JDV1.07.bin",
    "362001063534+U-Hi3861_JDV1.21.bin",
    "362001065437+G04V1.1.bin",
    "362001065586+U-G06AV1.05.bin",
    "362001067274+MC-VTSBH02V1.0.bin",
    "362001062870+U-G03AV1.0.bin",
    "362001068872+U-WB05AARV1.02.bin",
    "362001062030+U-W05MV1.18.bin",
    "362001063012+U-W06TV1.10.bin",
])
def test_embedded_identity_alone_does_not_invent_appliance_traits(hid):
    code = hid.partition("+")[0]
    profile = match_device_profile(hid)
    assert profile is not None
    assert profile is match_device_profile(code)
    assert profile.temperature_offset is None
    assert profile.relearn_temperature_offset is False
    assert profile.buzzer_properties == ()
    assert profile.cooling_mode_value is None
    assert profile.capabilities == ()
    assert profile.gateway_dialect is None


@pytest.mark.parametrize("hid", [
    "362001061329+U-W04RV2.03.bin",
    "362001061704+U-W04WV1.25.bin",
    "362001063222+U-ESP32_GR_CANV2.01.bin",
])
def test_named_buzzer_without_opt_in_keeps_other_traits_unknown(hid):
    profile = match_device_profile(hid)
    assert profile.buzzer_properties == ()
    assert profile.temperature_offset is None
    assert profile.relearn_temperature_offset is False
    assert profile.cooling_mode_value is None
    assert profile.capabilities == ()
    assert profile.gateway_dialect is None


@pytest.mark.asyncio
@pytest.mark.parametrize("hid", [
    "362001000748+U-CS532Z(LT)V3.73.bin",
    "362001000748+U-CS532Z(LT)V3.75.bin",
])
async def test_conflicting_buzzer_aliases_stay_unsupported_without_version_admission(hid, cipher, send):
    device = AirConditionerDevice(DeviceInfo(*get_mock_info()))
    await device.bind(key="0123456789abcdef", cipher=CipherV1())
    device.handle_state_update(hid=hid, TemSen=65, TemUn=0)
    assert device.current_temperature == 25
    assert device.capabilities["lan_buzzer_control"] is False
    device.buzzer = False
    device.set_property("Pow", 1)
    await device.push_state_update()
    assert send.call_args.args[0]["pack"]["opt"] == ["Pow"]
    assert send.call_args.args[0]["pack"]["p"] == [1]
