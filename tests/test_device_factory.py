"""Exact identity dispatch, safe defaults and family-specific wire behavior."""
import asyncio
from unittest.mock import AsyncMock

import pytest

from greeclimate import device_factory
from greeclimate.atw import AirToWaterDevice, AirToWaterMode
from greeclimate.cipher import CipherV1
from greeclimate.device import Device
from greeclimate.device_factory import DeviceProfile, create_device
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


async def test_discovery_mid_selects_atw_wire_behavior():
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
    unit = await capture(create_device(delivered.get_nowait()))
    assert isinstance(unit, AirToWaterDevice)
    receive(unit, {"Pow": 0, "Mod": 1, "TemUn": 0,
                   "AllInWatTemHi": 132, "AllInWatTemLo": 4,
                   "HeWatOutTemSet": 35})
    assert unit.inlet_water_temperature_c == 32.4
    unit.heating_water_target_temperature_c = 36
    await unit.push_state_update()
    assert command(unit) == {"HeWatOutTemSet": 36}
    with pytest.raises(ValueError):
        unit.mode = AirToWaterMode.Cool


@pytest.mark.parametrize("mid,hid", [
    (None, KNOWN_HID), ("unknown", KNOWN_HID), ("9300", "unknown"),
])
async def test_exact_hid_or_mid_selects_atw(mid, hid):
    unit = await capture(create_device(info(mid), hid=hid))
    receive(unit, {"Pow": 0, "Mod": 1, "TemUn": 0, "HeWatOutTemSet": 35})
    unit.heating_water_target_temperature_c = 36
    await unit.push_state_update()
    assert command(unit) == {"HeWatOutTemSet": 36}
    assert unit.hid is None  # Lookup metadata is not reported state.
    with pytest.raises(ValueError):
        unit.mode = AirToWaterMode.Cool


@pytest.mark.parametrize("mid,hid", [
    (None, None), ("", None), ("unknown", None), (9300, None),
    (None, KNOWN_HID.replace("6.04", "6.05")),
    (None, ""), (None, 9300), ("9300 ", None),
])
async def test_unmatched_identity_retains_ac_commands(mid, hid):
    unit = await capture(create_device(info(mid), hid=hid))
    assert type(unit) is Device
    receive(unit, {"Pow": 0, "Mod": 1, "TemUn": 0,
                   "TemRec": 0, "SetTem": 20, "TemSen": 65})
    assert unit.current_temperature == 25
    unit.target_temperature = 23
    await unit.push_state_update()
    assert command(unit) == {"SetTem": 23, "TemRec": 0, "TemUn": 0, "BuzzerCtrl": 1}


@pytest.mark.parametrize("hid,expected", [("test-hid", 5), ("unknown", 0)])
async def test_hid_precedes_mid(monkeypatch, hid, expected):
    monkeypatch.setattr(device_factory, "KNOWN_DEVICES", (
        DeviceProfile(AirToWaterDevice, mids=("test-mid",),
                      settings={"cooling_mode_value": 0}),
        DeviceProfile(AirToWaterDevice, hids=("test-hid",),
                      settings={"cooling_mode_value": 5}),
    ))
    unit = await capture(create_device(info("test-mid"), hid=hid))
    receive(unit, {"Pow": 0, "Mod": 1})
    unit.mode = AirToWaterMode.Cool
    await unit.push_state_update()
    assert command(unit) == {"Mod": expected}


@pytest.mark.parametrize("kind", ["mids", "hids"])
async def test_duplicate_identity_first_row_wins(monkeypatch, kind):
    monkeypatch.setattr(device_factory, "KNOWN_DEVICES", tuple(
        DeviceProfile(AirToWaterDevice, **{kind: ("duplicate",)},
                      settings={"cooling_mode_value": value})
        for value in (0, 5)
    ))
    unit = await capture(create_device(
        info("duplicate" if kind == "mids" else None),
        hid="duplicate" if kind == "hids" else None,
    ))
    receive(unit, {"Pow": 0, "Mod": 1})
    unit.mode = AirToWaterMode.Cool
    await unit.push_state_update()
    assert command(unit) == {"Mod": 0}


async def test_explicit_settings_override_without_mutating_profile(monkeypatch):
    monkeypatch.setattr(device_factory, "KNOWN_DEVICES", (
        DeviceProfile(AirToWaterDevice, mids=("test-mid",),
                      settings={"cooling_mode_value": 5}),
    ))
    for settings, expected in (({"cooling_mode_value": 0}, 0),
                               ({"cooling_mode_value": None}, None), ({}, 5)):
        unit = await capture(create_device(info("test-mid"), **settings))
        receive(unit, {"Pow": 0, "Mod": 1})
        if expected is None:
            with pytest.raises(ValueError):
                unit.mode = AirToWaterMode.Cool
            await unit.push_state_update()
            unit.send.assert_not_awaited()
        else:
            unit.mode = AirToWaterMode.Cool
            await unit.push_state_update()
            assert command(unit) == {"Mod": expected}


@pytest.mark.parametrize("value", [True, 3])
async def test_selected_constructor_rejects_invalid_cooling(value):
    with pytest.raises(ValueError):
        create_device(info("9300"), cooling_mode_value=value)


async def test_fallback_rejects_family_only_settings():
    with pytest.raises(TypeError):
        create_device(info("unknown"), cooling_mode_value=0)


async def test_profile_instances_have_independent_staged_state():
    first = await capture(create_device(info("9300")))
    second = await capture(create_device(info("9300")))
    for unit in (first, second):
        receive(unit, {"Pow": 0, "Mod": 1, "TemUn": 0, "HeWatOutTemSet": 35})
    first.heating_water_target_temperature_c = 36
    await first.push_state_update()
    await second.push_state_update()
    assert command(first) == {"HeWatOutTemSet": 36}
    assert second.heating_water_target_temperature_c == 35
    second.send.assert_not_awaited()
