"""MID-only family selection and reported firmware traits."""
import asyncio
from unittest.mock import AsyncMock

import pytest

from greeclimate import device_profile
from greeclimate.atw import AirToWaterDevice, AirToWaterMode
from greeclimate.cipher import CipherV1
from greeclimate.device import Device
from greeclimate.device_factory import create_device
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.discovery import Discovery, Listener

pytestmark = pytest.mark.asyncio

KNOWN_HID = "362001066763+U-W06A(P3)V6.04.bin"


def info(mid=None):
    return DeviceInfo("127.0.0.1", 7000, "001122334455", "SMH-100IRB",
                      "gree", "gree", mid=mid)


async def capture(unit):
    await unit.bind(key="0123456789abcdef", cipher=CipherV1())
    unit.send = AsyncMock()
    return unit


def receive(unit, properties):
    unit.packet_received({"t": "pack", "pack": {
        "t": "dat", "cols": list(properties), "dat": list(properties.values()),
    }}, ("127.0.0.1", 7000))


def command(unit):
    pack = unit.send.await_args.args[0]["pack"]
    assert pack["t"] == "cmd"
    return dict(zip(pack["opt"], pack["p"]))


async def test_discovery_mid_selects_atw_before_reported_firmware():
    delivered = asyncio.Queue()

    class Receiver(Listener):
        async def device_found(self, device_info):
            delivered.put_nowait(device_info)

    discovery = Discovery()
    discovery.add_listener(Receiver())
    discovery.packet_received({"t": "pack", "pack": {
        "t": "dev", "mac": "001122334455", "mid": "9300",
        "name": "Synthetic", "brand": "gree", "model": "gree",
    }}, ("127.0.0.1", 7000))
    await asyncio.gather(*discovery.tasks)
    unit = create_device(delivered.get_nowait())
    assert isinstance(unit, AirToWaterDevice)
    assert unit.hid is None and unit.cooling_mode_value is None
    await capture(unit)
    receive(unit, {"Pow": 0, "Mod": 2, "TemUn": 0,
                   "AllInWatTemHi": 132, "AllInWatTemLo": 4,
                   "HeWatOutTemSet": 35})
    assert unit.inlet_water_temperature_c == 32.4
    unit.heating_water_target_temperature_c = 36
    await unit.push_state_update()
    assert command(unit) == {"HeWatOutTemSet": 36}
    unit.mode = AirToWaterMode.Heat
    await unit.push_state_update()
    assert command(unit) == {"Mod": 1}
    with pytest.raises(ValueError):
        unit.mode = AirToWaterMode.Cool
    receive(unit, {"hid": KNOWN_HID})
    assert unit.inlet_water_temperature_c == 32.4
    assert unit.heating_water_target_temperature_c == 36
    unit.mode = AirToWaterMode.Cool
    await unit.push_state_update()
    assert command(unit) == {"Mod": 5}


@pytest.mark.parametrize("hid", [
    KNOWN_HID,
    "362001066763+W06A(P3)V6.0.bin",
    "362001066763+U-OTHER(LT)V7.12.bin",
])
async def test_sinclair_ignores_module_and_version(hid):
    unit = await capture(create_device(info("9300")))
    receive(unit, {"Pow": 0, "Mod": 1, "hid": hid})
    unit.mode = AirToWaterMode.Cool
    await unit.push_state_update()
    assert command(unit) == {"Mod": 5}


@pytest.mark.parametrize("mid", [None, "", "unknown", 9300, "9300 ", [], {}])
async def test_unmatched_mid_retains_ac_commands_and_temperature_learning_after_sinclair_hid(mid):
    unit = await capture(create_device(info(mid)))
    assert type(unit) is Device
    receive(unit, {"Pow": 0, "Mod": 1, "TemUn": 0, "hid": KNOWN_HID,
                   "TemRec": 0, "SetTem": 20, "TemSen": 20})
    assert unit.current_temperature == 20
    for sensor, expected in [(65, 25), (19, -21)]:
        receive(unit, {"TemSen": sensor})
        assert unit.current_temperature == expected
    unit.target_temperature = 23
    await unit.push_state_update()
    assert command(unit) == {"SetTem": 23, "TemRec": 0, "TemUn": 0, "BuzzerCtrl": 1}


@pytest.mark.parametrize("hid", [
    None, "", 9300, "unknown", "362001066763", "362001066763+",
    KNOWN_HID.replace("362001066763", "3620010667630"),
    KNOWN_HID.replace("6.04", "6..04"), KNOWN_HID + "extra",
])
async def test_sinclair_mid_without_matching_hid_retains_atw_without_cooling(hid):
    unit = await capture(create_device(info("9300")))
    assert isinstance(unit, AirToWaterDevice)
    assert unit.cooling_mode_value is None
    receive(unit, {"Pow": 0, "Mod": 1, "hid": hid, "TemUn": 0,
                   "HeWatOutTemSet": 35})
    assert unit.cooling_mode_value is None
    with pytest.raises(ValueError):
        unit.mode = AirToWaterMode.Cool
    unit.heating_water_target_temperature_c = 36
    await unit.push_state_update()
    assert command(unit) == {"HeWatOutTemSet": 36}


@pytest.mark.parametrize("mid", ["9300", None, "unknown"])
async def test_cooling_uses_numeric_firmware_floor_not_discovery_version_or_mid(monkeypatch, mid):
    profile = device_profile.DeviceProfile(
        firmware_code="362001066763", min_version="6.10", cooling_mode_value=5)
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (profile,))
    metadata = info(mid)
    metadata.version = "99.0"
    unit = await capture(AirToWaterDevice(metadata))
    assert unit.cooling_mode_value is None
    receive(unit, {"Pow": 0, "Mod": 1,
                   "hid": "362001066763+U-OTHERV6.9.bin"})
    assert unit.cooling_mode_value is None
    with pytest.raises(ValueError):
        unit.mode = AirToWaterMode.Cool
    unit.version = "0"
    receive(unit, {"hid": "362001066763+U-OTHERV6.10.0.bin"})
    assert unit.cooling_mode_value == 5
    unit.version = "0"
    unit.mode = AirToWaterMode.Cool
    await unit.push_state_update()
    assert command(unit) == {"Mod": 5}


@pytest.mark.parametrize("options,expected", [
    ({}, 5), ({"cooling_mode_value": 0}, 0),
    ({"cooling_mode_value": 5}, 5), ({"cooling_mode_value": None}, None),
])
async def test_explicit_cooling_override_is_independent(options, expected):
    unit = await capture(create_device(info("9300"), **options))
    receive(unit, {"Pow": 0, "Mod": 1, "hid": KNOWN_HID})
    assert unit.cooling_mode_value == expected
    if expected is None:
        with pytest.raises(ValueError):
            unit.mode = AirToWaterMode.Cool
        await unit.push_state_update()
        unit.send.assert_not_awaited()
    else:
        unit.mode = AirToWaterMode.Cool
        await unit.push_state_update()
        assert command(unit) == {"Mod": expected}
    for hid in (KNOWN_HID, "unrecognized", KNOWN_HID):
        receive(unit, {"hid": hid})
        assert unit.cooling_mode_value == (expected if options or hid == KNOWN_HID else None)
    separate = create_device(info("9300"))
    receive(separate, {"hid": KNOWN_HID})
    assert separate.cooling_mode_value == 5


@pytest.mark.parametrize("value", [True, 3])
async def test_selected_constructor_rejects_invalid_cooling(value):
    with pytest.raises(ValueError, match="cooling_mode_value must be None, 0 or 5"):
        create_device(info("9300"), cooling_mode_value=value)


async def test_fallback_rejects_family_only_settings():
    with pytest.raises(TypeError):
        create_device(info("unknown"), cooling_mode_value=0)


async def test_selected_constructor_rejects_unsupported_settings():
    with pytest.raises(TypeError):
        create_device(info("9300"), unsupported_setting=True)


async def test_profile_instances_have_independent_staged_state():
    first = await capture(create_device(info("9300")))
    second = await capture(create_device(info("9300")))
    for unit in (first, second):
        receive(unit, {"Pow": 0, "Mod": 1, "hid": KNOWN_HID,
                       "TemUn": 0, "HeWatOutTemSet": 35})
    first.heating_water_target_temperature_c = 36
    await first.push_state_update()
    await second.push_state_update()
    assert command(first) == {"HeWatOutTemSet": 36}
    assert second.heating_water_target_temperature_c == 35
    second.send.assert_not_awaited()
