"""Optional outdoor, coil and compressor temperatures and the fault bit field."""

import pytest

from greeclimate.air_conditioner import AirConditionerDevice
from greeclimate.cipher import CipherV1
from greeclimate.deviceinfo import DeviceInfo

# WB05RT13 firmware: raw temperatures carry a +40 offset.
WB05RT13_HID = "362001065279+U-WB05RT13V1.23.bin"
EXTENDED = ["OutEnvTem", "CompressorTem", "InEvaTem", "FaultDisplay"]


async def make_device():
    device = AirConditionerDevice(
        DeviceInfo("1.1.1.1", 7000, "f4911e7aca59", "1e7aca59", mid="10001")
    )
    await device.bind(key="0123456789abcdef", cipher=CipherV1())
    return device


@pytest.mark.asyncio
async def test_extended_properties_are_none_until_reported(cipher, send):
    device = await make_device()
    assert device.outdoor_temperature is None
    assert device.compressor_temperature is None
    assert device.evaporator_temperature is None
    assert device.fault_display is None


@pytest.mark.asyncio
async def test_extended_poll_is_separate_from_regular_poll(cipher, send):
    device = await make_device()
    device.handle_state_update(hid=WB05RT13_HID)

    await device.update_state()
    regular = send.call_args.args[0]["pack"]["cols"]
    await device.update_extended_state()

    assert send.call_args.args[0]["pack"]["cols"] == EXTENDED
    assert not set(EXTENDED) & set(regular)


@pytest.mark.asyncio
async def test_extended_values_decode_with_the_unit_offset(cipher, send):
    device = await make_device()
    device.handle_state_update(hid=WB05RT13_HID, TemSen=66)
    device.handle_state_update(OutEnvTem=47, CompressorTem=114, InEvaTem=92, FaultDisplay=0)

    assert device.outdoor_temperature == 7
    assert device.compressor_temperature == 74
    assert device.evaporator_temperature == 52
    assert device.fault_display == 0


@pytest.mark.asyncio
async def test_offset_follows_the_ambient_sensor_not_a_constant(cipher, send):
    """A unit reporting plain Celsius must not be shifted by 40."""
    device = await make_device()
    device.handle_state_update(hid="362001000000+U-UNKNOWN.bin", TemSen=25)
    device.handle_state_update(OutEnvTem=7, CompressorTem=61, InEvaTem=45)

    assert device.outdoor_temperature == 7
    assert device.compressor_temperature == 61
    assert device.evaporator_temperature == 45


@pytest.mark.asyncio
async def test_unreported_columns_stay_none(cipher, send):
    """Firmware omits columns it does not know; the other values must still work."""
    device = await make_device()
    device.handle_state_update(hid=WB05RT13_HID, TemSen=66)
    device.handle_state_update(OutEnvTem=47)

    assert device.outdoor_temperature == 7
    assert device.compressor_temperature is None
    assert device.evaporator_temperature is None
    assert device.fault_display is None


@pytest.mark.asyncio
@pytest.mark.parametrize("raw", [0, 1, 131, 500, -100, "", None, 47.0, True])
async def test_implausible_or_malformed_sensor_values_are_rejected(raw, cipher, send):
    """A raw 0 behind the +40 offset (-40 C) means "no sensor", not a reading."""
    device = await make_device()
    device.handle_state_update(hid=WB05RT13_HID, TemSen=66)
    device.handle_state_update(CompressorTem=raw)

    assert device.compressor_temperature is None


@pytest.mark.asyncio
@pytest.mark.parametrize("raw,expected", [
    (4096, 4096), (0, 0),
    ("4096", 4096), ("0", 0),  # real WB05RT13 firmware reports a decimal string
    ("", None), (" 12", None), ("-1", None), ("0x10", None), ("abc", None),
    (None, None), (True, None), (1.0, None),
])
async def test_fault_display_is_the_raw_bit_field(raw, expected, cipher, send):
    device = await make_device()
    device.handle_state_update(FaultDisplay=raw)

    assert device.fault_display == expected


@pytest.mark.asyncio
async def test_no_offset_known_yields_no_temperature(cipher, send):
    """Without a profile offset or an ambient reading the raw value cannot be trusted."""
    device = await make_device()
    device.handle_state_update(hid="362001000000+U-UNKNOWN.bin")
    device.handle_state_update(OutEnvTem=47)

    assert device.outdoor_temperature is None
