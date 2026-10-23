from unittest.mock import AsyncMock

import pytest

from greeclimate.cipher import CipherV1
from greeclimate.device import Device
from greeclimate.device_factory import create_device
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.gateway import GatewayDevice

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


@pytest.mark.asyncio
@pytest.mark.parametrize("mid", ["6049", "604a", "604b", "604c", "605c", "608f", "6092"])
async def test_ordinary_gateway_child_poll_remains_raw_after_parent_hid(mid):
    unit = create_device(DeviceInfo("127.0.0.1", 7000, "001122334455", "Child", mid=mid))
    assert type(unit) is Device
    await unit.bind(key="0123456789abcdef", cipher=CipherV1())
    unit.send = AsyncMock()
    await unit.update_state()
    assert unit.send.call_args.args[0]["pack"]["cols"] == ["Pow", "Mod", "SetTem", "TemBody", "hid"]
    unit.handle_state_update(hid="362001061433+U-W06AV7.bin", TemBody=85)
    await unit.update_state()
    assert unit.send.call_args.args[0]["pack"]["cols"] == ["Pow", "Mod", "SetTem", "TemBody"]
    assert type(unit) is Device
    assert all(value is None for value in unit.capabilities.values())
    assert unit.get_property("TemBody") == 85
    unit.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mid", ["6079", "6084", "608d", "608e", "6091", "6099",
                                 "60a0", "60a4", "60a9", "06049", "604A"])
async def test_routing_comparisons_and_mid_aliases_do_not_borrow_ordinary_child_poll(mid):
    unit = create_device(DeviceInfo("127.0.0.1", 7000, "001122334455", "Unqualified route", mid=mid))
    await unit.bind(key="0123456789abcdef", cipher=CipherV1())
    unit.send = AsyncMock()
    unit.handle_state_update(hid="362001067012+U-W06AV30.bin", Pow=1, TemBody=85)
    await unit.update_state()
    assert unit.send.call_args.args[0]["pack"]["cols"] == ["hid"]
    assert type(unit) is Device
    assert all(value is None for value in unit.capabilities.values())
    unit.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mid,hid", [
    ("60", "362001061433+U-W06AV7.bin"),
    ("60", "362001066326+U-WB05BRV1.18.bin"),
    ("60", "362001066380+U-WB05BRV1.38.bin"),
    (None, "362001065279+U-WB05RT13V1.64.bin"),
])
async def test_gateway_or_missing_mid_stays_identity_only_despite_known_firmware(mid, hid):
    unit = create_device(DeviceInfo("127.0.0.1", 7000, "001122334455", "Parent", mid=mid))
    await unit.bind(key="0123456789abcdef", cipher=CipherV1())
    unit.send = AsyncMock()
    unit.handle_state_update(hid=hid, Pow=1, TemSen=65)
    await unit.update_state()
    assert unit.send.call_args.args[0]["pack"]["cols"] == ["hid"]
    assert type(unit) is (GatewayDevice if mid == "60" else Device)
    assert all(value is None for value in unit.capabilities.values())
    unit.close()
