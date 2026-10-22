"""Exact-MID family selection without binding or firmware inference."""
from unittest.mock import AsyncMock, Mock

import pytest

from greeclimate.air_conditioner import AirConditionerDevice
from greeclimate.cipher import CipherV1
from greeclimate.dehumidifier import DehumidifierDevice
from greeclimate.device import Device, TemperatureUnits
from greeclimate.device_factory import create_device
from greeclimate.deviceinfo import DeviceInfo

pytestmark = pytest.mark.asyncio

KNOWN_HID = "362001066763+U-W06A(P3)V6.04.bin"


def info(mid=None):
    return DeviceInfo("127.0.0.1", 7000, "001122334455", "SMH-100IRB",
                      "gree", "gree", mid=mid)



async def capture(unit):
    await unit.bind(key="0123456789abcdef", cipher=CipherV1())
    unit.connection_made(Mock(get_extra_info=Mock(return_value=("127.0.0.1", 7000))))
    unit.ready.set()
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



@pytest.mark.parametrize("mid,device_type", [
    *((mid, AirConditionerDevice) for mid in (
        "0001", "10f01", "10f02", "10001", "10002", "10007", "11001", "11002",
        "12000", "12001", "12002", "12003", "13000", "15000", "809032", "3018",
        "3019", "302b", "3062", "4005",
    )),
    *((mid, DehumidifierDevice) for mid in (
        "13800", "13802", "13803", "13804", "13805", "13806",
    )),
])
async def test_factory_selects_exact_implemented_family_without_binding(monkeypatch, mid, device_type):
    bind = AsyncMock()
    send = AsyncMock()
    monkeypatch.setattr(Device, "bind", bind)
    monkeypatch.setattr(Device, "send", send)
    metadata = info(mid)
    unit = create_device(metadata)
    assert type(unit) is device_type
    assert unit.device_info is metadata
    assert unit.device_info.mid == mid
    assert unit.hid is None
    bind.assert_not_awaited()
    send.assert_not_awaited()



async def test_ac_factory_result_encodes_typed_temperature_command():
    unit = await capture(create_device(info("10001")))
    assert type(unit) is AirConditionerDevice
    receive(unit, {"TemUn": 0, "TemRec": 0, "SetTem": 20,
                   "hid": "362001064973+U-W04NV17.bin"})
    unit.temperature_units = TemperatureUnits.C
    unit.target_temperature = 23
    await unit.push_state_update()
    assert command(unit) == {"SetTem": 23, "TemRec": 0, "TemUn": 0}
    assert unit.target_temperature == 23



async def test_dehumidifier_factory_result_encodes_only_humidity_command():
    unit = await capture(create_device(info("13805")))
    assert type(unit) is DehumidifierDevice
    receive(unit, {"Dwet": 0, "TemUn": 0, "TemRec": 0, "SetTem": 20,
                   "hid": "362001064973+U-W04NV17.bin"})
    unit.target_humidity = 45
    await unit.push_state_update()
    assert command(unit) == {"Dwet": 6}
    assert unit.target_humidity == 45
    for name in ("mode", "target_temperature", "buzzer"):
        assert not hasattr(unit, name)



@pytest.mark.parametrize("mid", [
    None, "", "unknown", 9300, 10001, "9300 ", " 10001", "10001 ", "10F01",
    "302B", "010001", "100010", [], {}, "13801", "11000", "11005", "11010",
    "3027", "6000", "6400", "807002", "9300", "9301", "9302", "60", "82000", "82002",
    "5000", "5001", "605d", "6098", "828100", "828214", "910001",
])
@pytest.mark.parametrize("hid", [KNOWN_HID, "362001064973+U-W04NV17.bin"])
async def test_unmatched_mid_remains_raw_only_after_known_hid_and_model(mid, hid):
    metadata = info(mid)
    metadata.model = "10001"
    unit = await capture(create_device(metadata))
    assert type(unit) is Device
    receive(unit, {"Pow": 0, "Mod": 1, "TemUn": 0, "hid": hid,
                   "TemRec": 0, "SetTem": 20, "TemSen": 20})
    metadata.model = "9300"
    assert unit.device_info.mid == mid
    assert unit.get_property("TemSen") == 20
    for name in ("power", "mode", "current_temperature", "target_temperature",
                 "target_humidity", "buzzer"):
        assert not hasattr(unit, name)
    unit.set_property("SetTem", 23)
    await unit.push_state_update()
    assert command(unit) == {"SetTem": 23}
    assert type(unit) is Device



@pytest.mark.parametrize("mid", [None, "10001", "13805"])
async def test_factory_forwards_timeouts_and_loop(mid):
    import asyncio

    loop = asyncio.get_running_loop()
    unit = create_device(info(mid), timeout=23, bind_timeout=7, loop=loop)
    try:
        assert unit._timeout == 23
        assert unit._bind_timeout == 7
        assert unit._loop is loop
    finally:
        unit.close()


@pytest.mark.parametrize("mid", [None, "10001", "13805"])
async def test_selected_constructor_rejects_unsupported_settings(mid):
    with pytest.raises(TypeError):
        create_device(info(mid), unsupported_setting=True)
