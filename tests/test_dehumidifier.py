"""Dehumidifier controls and real encrypted command framing."""
import asyncio

import pytest

from greeclimate.cipher import CipherV1, CipherV2
from greeclimate.dehumidifier import DehumidifierDevice
from greeclimate.device import FanSpeed, TemperatureUnits, VerticalSwing
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.network import Response
from tests.common import udp_peer
from tests.test_device import (
    RECOVERY_MAC, generate_device_mock_async, get_mock_info,
    recovery_negotiate, recovery_packet, recovery_receive,
)

pytestmark = pytest.mark.asyncio


async def test_missing_dehumidifier_properties():
    device = DehumidifierDevice(DeviceInfo(*get_mock_info()))
    for name in ("power", "target_humidity", "dehumidifier_mode", "current_humidity",
                 "clean_filter", "water_full", "current_temperature", "temperature_units",
                 "fan_speed", "light", "vertical_swing", "anion", "quiet"):
        assert getattr(device, name) is None
    for name in ("mode", "target_temperature", "horizontal_swing", "fresh_air", "xfan",
                 "sleep", "turbo", "steady_heat", "power_save", "buzzer"):
        assert not hasattr(device, name)


@pytest.mark.parametrize("raw,humidity", [(3, 30), (6, 45), (12, 75)])
async def test_target_humidity_conversion(raw, humidity, cipher, send):
    device = await generate_device_mock_async(DehumidifierDevice)
    device.handle_state_update(Dwet=raw)
    assert device.target_humidity == humidity
    device.target_humidity = humidity + 5
    await device.push_state_update()
    pack = send.call_args.args[0]["pack"]
    assert dict(zip(pack["opt"], pack["p"])) == {"Dwet": raw + 1}


@pytest.mark.parametrize("humidity,raw", [(46, 6)])
async def test_humidity_preserves_existing_floor_conversion(humidity, raw):
    device = DehumidifierDevice(DeviceInfo(*get_mock_info()))
    device.target_humidity = humidity
    assert device.get_property("Dwet") == raw


@pytest.mark.parametrize("value", [0, 1, 9])
async def test_reported_humidity_status(value):
    device = DehumidifierDevice(DeviceInfo(*get_mock_info()))
    device.handle_state_update(Dmod=value, DwatSen=value, Dfltr=value, DwatFul=value)
    assert device.dehumidifier_mode == value
    assert device.current_humidity == value
    assert device.clean_filter is bool(value)
    assert device.water_full is bool(value)
    with pytest.raises(AttributeError):
        device.dehumidifier_mode = 0
    with pytest.raises(AttributeError):
        device.temperature_units = TemperatureUnits.F


async def test_optional_controls_have_only_dehumidifier_wire_fields(cipher, send):
    device = await generate_device_mock_async(DehumidifierDevice)
    device.handle_state_update(hid="362001064973+U-W04NV17.bin")
    device.power = True
    device.fan_speed = FanSpeed.High
    device.light = True
    device.vertical_swing = VerticalSwing.FullSwing
    device.anion = True
    device.quiet = True
    device.target_humidity = 45
    await device.push_state_update()
    pack = send.call_args.args[0]["pack"]
    assert dict(zip(pack["opt"], pack["p"])) == {
        "Pow": 1, "WdSpd": 5, "Lig": 1, "SwUpDn": 1, "Health": 1,
        "Quiet": 2, "Dwet": 6,
    }
    assert device.quiet == 2
    device.quiet = False
    await device.push_state_update()
    pack = send.call_args.args[0]["pack"]
    assert dict(zip(pack["opt"], pack["p"])) == {"Quiet": 0}


@pytest.mark.parametrize("cipher_type", [CipherV1, CipherV2])
async def test_encrypted_dehumidifier_dwet_command(cipher_type):
    async with udp_peer() as (peer, queue):
        host, port = peer.get_extra_info("sockname")
        device = DehumidifierDevice(
            DeviceInfo(host, port, RECOVERY_MAC, "dehumidifier", mid="13805"),
            bind_timeout=0.1,
        )
        data, results = asyncio.Queue(), asyncio.Queue()
        device.add_handler(Response.DATA, data.put_nowait)
        device.add_handler(Response.RESULT, results.put_nowait)
        try:
            addr = await recovery_negotiate(device, peer, queue, cipher_type())
            status, _ = await recovery_receive(queue, device.device_cipher)
            assert status["t"] == "status"
            peer.sendto(recovery_packet({
                "t": "dat", "cols": ["Dwet", "Dmod", "DwatSen", "Dfltr", "DwatFul"],
                "dat": [0, 9, 0, 0, 1],
            }, device.device_cipher), addr)
            await asyncio.wait_for(data.get(), 2)
            assert device.target_humidity == 15
            assert device.dehumidifier_mode == 9
            assert device.current_humidity == 0
            assert device.clean_filter is False and device.water_full is True
            device.target_humidity = 45
            await device.push_state_update()
            command, _ = await recovery_receive(queue, device.device_cipher)
            assert command["t"] == "cmd"
            assert command["opt"] == ["Dwet"] and command["p"] == [6]
            peer.sendto(recovery_packet({
                "t": "res", "opt": ["Dwet"], "p": [6],
            }, device.device_cipher), addr)
            assert await asyncio.wait_for(results.get(), 2) == {"Dwet": 6}
            assert device.target_humidity == 45
        finally:
            device.close()
            if hasattr(device, "_transport_closed"):
                await asyncio.wait_for(device._transport_closed.wait(), 2)
            await asyncio.gather(*device.tasks, return_exceptions=True)
