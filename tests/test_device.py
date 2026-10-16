import asyncio
import enum

import pytest

from greeclimate.cipher import CipherV1
from greeclimate.device import Device, DeviceInfo, Props, TemperatureUnits
from greeclimate.exceptions import DeviceNotBoundError, DeviceTimeoutError


class FakeProps(enum.Enum):
    FAKE = "fake"


def get_mock_info():
    return (
        "1.1.1.0",
        "7000",
        "aabbcc001122",
        "MockDevice1",
        "MockBrand",
        "MockModel",
        "0.0.1-fake",
    )


def get_mock_state():
    return {
        "Pow": 1,
        "Mod": 3,
        "SetTem": 25,
        "TemSen": 29,
        "TemUn": 0,
        "WdSpd": 0,
        "Air": 0,
        "Blo": 0,
        "Health": 0,
        "SwhSlp": 0,
        "SlpMod": 0,
        "Lig": 1,
        "SwingLfRig": 1,
        "SwUpDn": 1,
        "Quiet": 0,
        "Tur": 0,
        "StHt": 0,
        "SvSt": 0,
        "TemRec": 0,
        "HeatCoolType": 0,
        "hid": "362001000762+U-CS532AE(LT)V3.31.bin",
        "Dmod": 0,
        "Dwet": 5,
        "DwatSen": 58,
        "Dfltr": 0,
        "DwatFul": 0,
    }


def get_mock_state_off():
    return {
        "Pow": 0,
        "Mod": 0,
        "SetTem": 0,
        "TemSen": 0,
        "TemUn": 0,
        "WdSpd": 0,
        "Air": 0,
        "Blo": 0,
        "Health": 0,
        "SwhSlp": 0,
        "SlpMod": 0,
        "Lig": 0,
        "SwingLfRig": 0,
        "SwUpDn": 0,
        "Quiet": 0,
        "Tur": 0,
        "StHt": 0,
        "SvSt": 0,
        "TemRec": 0,
        "HeatCoolType": 0,
        "Dmod": 0,
        "Dwet": 0,
        "DwatSen": 0,
        "Dfltr": 0,
        "DwatFul": 0,
    }


def get_mock_state_on():
    return {
        "Pow": 1,
        "Mod": 1,
        "SetTem": 1,
        "TemSen": 1,
        "TemUn": 1,
        "WdSpd": 1,
        "Air": 1,
        "Blo": 1,
        "Health": 1,
        "SwhSlp": 1,
        "SlpMod": 1,
        "Lig": 1,
        "SwingLfRig": 1,
        "SwUpDn": 1,
        "Quiet": 2,
        "Tur": 1,
        "StHt": 1,
        "SvSt": 1,
        "TemRec": 0,
        "HeatCoolType": 0,
        "Dmod": 0,
        "Dwet": 3,
        "DwatSen": 1,
        "Dfltr": 0,
        "DwatFul": 0,
    }


def get_mock_state_no_temperature():
    return {
        "Pow": 1,
        "Mod": 3,
        "SetTem": 25,
        "TemUn": 0,
        "WdSpd": 0,
        "Air": 0,
        "Blo": 0,
        "Health": 0,
        "SwhSlp": 0,
        "SlpMod": 0,
        "Lig": 1,
        "SwingLfRig": 1,
        "SwUpDn": 1,
        "Quiet": 0,
        "Tur": 0,
        "StHt": 0,
        "SvSt": 0,
        "TemRec": 0,
        "HeatCoolType": 0,
        "Dmod": 0,
        "Dwet": 1,
        "DwatSen": 1,
        "Dfltr": 0,
        "DwatFul": 0,
    }


def get_mock_state_bad_temp():
    return {"TemSen": 69, "hid": "362001060297+U-CS532AF(MTK).bin"}


async def generate_device_mock_async():
    d = Device(DeviceInfo("1.1.1.1", 7000, "f4911e7aca59", "1e7aca59"))
    await d.bind(key="St8Vw1Yz4Bc7Ef0H", cipher=CipherV1())
    return d


def test_device_info_equality(send):
    """The only way to get the key through binding is by scanning first"""

    props = [
        "1.1.1.0",
        "7000",
        "aabbcc001122",
        "MockDevice1",
        "MockBrand",
        "MockModel",
        "0.0.1-fake",
    ]

    # When all properties match the device info is the same
    assert DeviceInfo(*props) == DeviceInfo(*props)

    # When any property differs the device info is not the same
    for i in range(2, len(props)):
        new_props = props.copy()
        new_props[i] = "modified_prop"
        assert DeviceInfo(*new_props) != DeviceInfo(*props)


@pytest.mark.asyncio
async def test_get_device_info(cipher, send):
    """Initialize device, check properties."""

    info = DeviceInfo(*get_mock_info())
    device = Device(info)

    assert device.device_info == info

    fake_key = "abcdefgh12345678"
    await device.bind(key=fake_key, cipher=CipherV1())

    assert device.device_cipher is not None
    assert device.device_cipher.key == fake_key


@pytest.mark.asyncio
async def test_device_bind(cipher, send):
    """Check that the device returns a device key when binding."""

    info = DeviceInfo(*get_mock_info())
    device = Device(info, timeout=1, bind_timeout=1)
    fake_key = "abcdefgh12345678"
    
    def fake_send(*args, **kwargs):
        """Emulate a bind event"""
        if not device.ready.is_set():
            device.device_cipher = CipherV1(fake_key.encode())
            device.handle_device_bound(fake_key)
        else:
            device.handle_state_update(**get_mock_state())
    send.side_effect = fake_send

    assert device.device_info == info
    await device.bind()
    assert send.call_count == 2   # 1 for bind, 2 for update_state

    assert device.device_cipher is not None
    assert device.device_cipher.key == fake_key
    
    # Bind with cipher already set
    await device.bind()
    assert send.call_count == 3 


@pytest.mark.asyncio
async def test_device_bind_timeout(cipher, send):
    """Check that the device handles timeout errors when binding."""
    info = DeviceInfo(*get_mock_info())
    device = Device(info, timeout=1, bind_timeout=1)

    with pytest.raises(DeviceTimeoutError):
        await device.bind()
        assert send.call_count == 1

    assert device.device_cipher is None


@pytest.mark.asyncio
async def test_device_bind_none(cipher, send):
    """Check that the device handles bad binding sequences."""
    info = DeviceInfo(*get_mock_info())
    device = Device(info, timeout=1, bind_timeout=1)

    def fake_send(*args, **kwargs):
        device.ready.set()
    send.side_effect = fake_send

    with pytest.raises(DeviceNotBoundError):
        await device.bind()
        assert send.call_count == 1

    assert device.device_cipher is None


@pytest.mark.asyncio
async def test_device_late_bind_from_update(cipher, send):
    """Check that the device handles late binding sequences."""
    info = DeviceInfo(*get_mock_info())
    device = Device(info, timeout=1, bind_timeout=1)
    fake_key = "abcdefgh12345678"

    def fake_send(*args, **kwargs):
        if not device.ready.is_set():
            device.device_cipher = CipherV1(fake_key.encode())
            device.handle_device_bound(fake_key)
        else:
            device.handle_state_update(**get_mock_state())
    send.side_effect = fake_send

    await device.update_state()
    assert send.call_count == 3
    assert device.device_cipher.key == fake_key

    device.power = True

    send.side_effect = None
    await device.push_state_update()
    
    assert device.device_cipher is not None
    assert device.device_cipher.key == fake_key


@pytest.mark.asyncio
async def test_device_late_bind_from_request_version(cipher, send):
    """Check that the device handles late binding sequences."""
    info = DeviceInfo(*get_mock_info())
    device = Device(info, timeout=1, bind_timeout=1)
    fake_key = "abcdefgh12345678"

    def fake_send(*args, **kwargs):
        if not device.ready.is_set():
            device.device_cipher = CipherV1(fake_key.encode())
            device.handle_device_bound(fake_key)
        else:
            device.handle_state_update(**get_mock_state())
    send.side_effect = fake_send

    await device.request_version()
    assert send.call_count == 3
    assert device.device_cipher.key == fake_key
    
    
@pytest.mark.asyncio
async def test_device_bind_no_cipher(cipher, send):
    """Check that the device handles late binding sequences."""
    info = DeviceInfo(*get_mock_info())
    device = Device(info, timeout=1, bind_timeout=1)
    fake_key = "abcdefgh12345678"
    
    with pytest.raises(ValueError):
        await device.bind(fake_key)


@pytest.mark.asyncio
async def test_device_bind_no_device_info(cipher, send):
    """Check that the device handles late binding sequences."""
    device = Device(None, timeout=1, bind_timeout=1)
    
    with pytest.raises(DeviceNotBoundError):
        await device.bind()


@pytest.mark.asyncio
async def test_update_properties(cipher, send):
    """Check that properties can be updates."""
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    def fake_send(*args, **kwargs):
        state = get_mock_state()
        device.handle_state_update(**state)
    send.side_effect = fake_send

    await device.update_state()

    for p in Props:
        assert device.get_property(p) is not None
        assert device.get_property(p) == get_mock_state()[p.value]


@pytest.mark.asyncio
async def test_update_properties_timeout(cipher, send):
    """Check that timeouts are handled when properties are updates."""
    device = await generate_device_mock_async()

    send.side_effect = asyncio.TimeoutError
    with pytest.raises(DeviceTimeoutError):
        await device.update_state()


@pytest.mark.asyncio
async def test_set_properties_not_dirty(cipher, send):
    """Check that the state isn't pushed when properties unchanged."""
    device = await generate_device_mock_async()

    await device.push_state_update()
    assert send.call_count == 0


@pytest.mark.asyncio
async def test_set_properties(cipher, send):
    """Check that state is pushed when properties are updated."""
    device = await generate_device_mock_async()

    device.power = True
    device.mode = 1
    device.temperature_units = 1
    device.fan_speed = 1
    device.fresh_air = True
    device.xfan = True
    device.anion = True
    device.sleep = True
    device.light = True
    device.horizontal_swing = 1
    device.vertical_swing = 1
    device.quiet = True
    device.turbo = True
    device.steady_heat = True
    device.power_save = True
    device.target_humidity = 30

    await device.push_state_update()
    send.assert_called_once()

    for p in Props:
        if p not in (
            Props.TEMP_SENSOR,
            Props.TEMP_SET,
            Props.TEMP_BIT,
            Props.UNKNOWN_HEATCOOLTYPE,
            Props.HUM_SENSOR,
            Props.DEHUMIDIFIER_MODE,
            Props.WATER_FULL,
            Props.CLEAN_FILTER,
        ):
            assert device.get_property(p) is not None
            assert device.get_property(p) == get_mock_state_on()[p.value]


@pytest.mark.asyncio
async def test_set_properties_timeout(cipher, send):
    """Check timeout handling when pushing state changes."""
    device = await generate_device_mock_async()

    device.power = True
    device.mode = 1
    device.temperature_units = 1
    device.fan_speed = 1
    device.fresh_air = True
    device.xfan = True
    device.anion = True
    device.sleep = True
    device.light = True
    device.horizontal_swing = 1
    device.vertical_swing = 1
    device.quiet = True
    device.turbo = True
    device.steady_heat = True
    device.power_save = True
    
    assert len(device._dirty)

    send.reset_mock()
    send.side_effect = [asyncio.TimeoutError, asyncio.TimeoutError, asyncio.TimeoutError]
    with pytest.raises(DeviceTimeoutError):
        await device.push_state_update()

    assert len(device._dirty)


@pytest.mark.asyncio
async def test_uninitialized_properties(cipher, send):
    """Check uninitialized property handling."""
    device = await generate_device_mock_async()

    assert not device.power
    assert device.mode is None
    assert device.target_temperature is None
    assert device.current_temperature is None
    assert device.temperature_units is None
    assert device.fan_speed is None
    assert device.target_humidity is None
    assert not device.fresh_air
    assert not device.xfan
    assert not device.anion
    assert not device.sleep
    assert not device.light
    assert device.horizontal_swing is None
    assert device.vertical_swing is None
    assert not device.quiet
    assert not device.turbo
    assert not device.steady_heat
    assert not device.power_save


@pytest.mark.asyncio
async def test_update_current_temp_unsupported(cipher, send):
    """Check that properties can be updates."""
    device = await generate_device_mock_async()

    def fake_send(*args, **kwargs):
        state = get_mock_state_no_temperature()
        device.handle_state_update(**state)
    send.side_effect = fake_send

    await device.update_state()

    assert device.get_property(Props.TEMP_SENSOR) is None
    assert device.current_temperature is None
    assert device.target_temperature == 25


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "temsen,hid",
    [
        (69, "362001000762+U-CS532AE(LT)V3.31.bin"),
        (61, "362001061060+U-W04HV3.29.bin"),
        (62, "362001061147+U-ZX6045RV1.01.bin"),
    ],
)
async def test_update_current_temp_offset40(temsen, hid, cipher, send):
    """Check that properties can be updates."""
    device = await generate_device_mock_async()

    def fake_send(*args, **kwargs):
        device.handle_state_update(TemSen=temsen, hid=hid)
    send.side_effect = fake_send

    await device.update_state()
    
    assert device.get_property(Props.TEMP_SENSOR) is not None
    assert device.current_temperature == temsen - 40


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "temsen,hid",
    [
        (21, "362001060297+U-CS532AF(MTK)V4.bin"),
        (21, "362001060297+U-CS532AF(MTK)V2.bin"),
        (22, "362001061383+U-BL3332_JDV1.bin"),
        (23, "362001061217+U-W04NV7.bin"),
    ],
)
async def test_update_current_temp_offset0(temsen, hid, cipher, send):
    """Check that properties can be updates."""
    device = await generate_device_mock_async()

    def fake_send(*args, **kwargs):
        device.handle_state_update(TemSen=temsen, hid=hid)
    send.side_effect = fake_send

    await device.update_state()

    assert device.get_property(Props.TEMP_SENSOR) is not None
    assert device.current_temperature == temsen


@pytest.mark.asyncio
async def test_update_current_temp_bad(cipher, send):
    """Check that properties can be updates."""
    device = await generate_device_mock_async()

    def fake_send(*args, **kwargs):
        device.handle_state_update(**get_mock_state_bad_temp())
    send.side_effect = fake_send

    await device.update_state()

    assert device.current_temperature == get_mock_state_bad_temp()["TemSen"] - 40



@pytest.mark.asyncio
@pytest.mark.parametrize(
    "hid,sensor,expected,version",
    [
        ("362001060200+U-CS849AV10.bin", 45, 45, "10"),
        ("362001000762+U-CS532AE(LT)V3.33.bin", 25, -15, "3.33"),
        ("362001061665+U-W05TV2.07.bin", 25, -15, "2.07"),
        ("362001000748+U-CS532Z(LT)V3.75.bin", 25, -15, "3.75"),
        ("362001000748+U-CS532Z(LT)V3.74.bin", 25, -15, "3.74"),
        ("362001000748+U-DIFFERENTV99.bin", 25, -15, "99"),
        ("362001000835+U-CS532AX(MTK)V3.bin", 45, 45, "3"),
        ("362001000835+U-CS532AX(MTK)V2.bin", 45, 45, "2"),
        ("362001060297+U-CS532AF(MTK)V4.bin", 45, 45, "4"),
        ("362001060297+U-CS532AF(MTK)V4.0.bin", 45, 45, "4.0"),
        ("362001065736+U-QCOM4004CV3.76.bin", 25, -15, "3.76"),
        ("362001064307+U-QCOM4004CV3.76.bin", 25, 25, "3.76"),
        ("999999999999+U-UNKNOWNV4.bin", 25, 25, "4"),
        ("362001061383+U-BL3332_JDV18.bin", 25, 25, "18"),
        ("362001060498+U-CS845B(MTK2)V6.bin", 45, 45, "6"),
        ("362001061060+U-W04HV3.55.bin", 25, -15, "3.55"),
    ],
)
async def test_temperature_code_defaults_and_literal_identity(hid, sensor, expected, version):
    device = Device(DeviceInfo(*get_mock_info()))
    device.handle_state_update(hid=hid, TemSen=sensor, TemUn=0, TemRec=0)

    assert device.current_temperature == expected
    assert device.version == version
    assert device.hid == hid
    assert device.raw_properties["TemSen"] == sensor


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "samples,expected",
    [
        ([-20, 65], [-20, 65]),
        ([19, 65], [19, 65]),
        ([51, 19], [11, -21]),
        ([90, 19], [50, -21]),
        ([20, 65], [20, 25]),
        ([50, 19], [10, 19]),
        ([0, 28, 45, 65, 25], [None, 28, 45, 25, -15]),
        ([40, 35, 19, 65], [0, -5, 19, 65]),
        ([0, 28, 0, 65], [None, 28, 0, 25]),
        ([40, 0, 19, 65], [0, None, 19, 65]),
        ([19, 0, 65], [19, 0, 65]),
        ([65, 0, 19], [25, None, -21]),
    ],
)
async def test_temperature_guess_promotion_and_permanent_lock(samples, expected):
    device = Device(DeviceInfo(*get_mock_info()))
    device.handle_state_update(SetTem=25, TemUn=0, TemRec=0)
    assert device.current_temperature is None

    for sensor, temperature in zip(samples, expected):
        device.handle_state_update(TemSen=sensor)
        assert device.current_temperature == temperature
        assert device.raw_properties["TemSen"] == sensor
        assert device.target_temperature == 25


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", [None, "28", 28.5, True, False, "", -21, 91, 218])
async def test_invalid_temperature_defers_inference(invalid):
    device = Device(DeviceInfo(*get_mock_info()))
    device.handle_state_update(SetTem=25, TemUn=0, TemRec=0, TemSen=invalid)
    assert device.current_temperature is None
    assert device.target_temperature == 25
    assert device.raw_properties["TemSen"] == invalid

    device.handle_state_update(TemSen=28)
    assert device.current_temperature == 28
    device.handle_state_update(TemSen=65)
    assert device.current_temperature == 25


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", [None, "28", 28.5, True, False, "", -21, 91, 218])
@pytest.mark.parametrize("first,expected", [(28, 25), (40, -15), (19, 25), (65, -15)])
async def test_unusable_temperature_preserves_selected_encoding(invalid, first, expected):
    device = Device(DeviceInfo(*get_mock_info()))
    device.handle_state_update(SetTem=25, TemSen=first, TemUn=0, TemRec=0)
    device.handle_state_update(TemSen=invalid)
    assert device.current_temperature is None
    assert device.target_temperature == 25
    device.handle_state_update(TemSen=25)
    assert device.current_temperature == expected
    device.handle_state_update(Pow=1)
    assert device.current_temperature == expected
    assert device.raw_properties["TemSen"] == 25


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "hid,initial,sensor,expected",
    [
        ("362001060200+U-CS849AV10.bin", 0, 65, 25),
        ("362001000762+U-CS532AE(LT)V3.33.bin", None, 19, 19),
        ("999999999999+U-UNKNOWNV1.bin", None, 28, 28),
    ],
)
async def test_zero_temperature_does_not_learn_or_guess(hid, initial, sensor, expected):
    device = Device(DeviceInfo(*get_mock_info()))
    device.handle_state_update(hid=hid, TemSen=0, SetTem=25, TemUn=0, TemRec=0)
    assert device.current_temperature == initial
    assert device.raw_properties["TemSen"] == 0
    device.handle_state_update(TemSen=sensor)
    assert device.current_temperature == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("hid_first", [False, True])
async def test_trait_overrides_guess_until_learning(hid_first):
    device = Device(DeviceInfo(*get_mock_info()))
    hid = "362001000762+U-CS532AE(LT)V3.33.bin"
    if hid_first:
        device.handle_state_update(hid=hid)
    device.handle_state_update(TemSen=25, TemUn=0, TemRec=0)
    assert device.current_temperature == (-15 if hid_first else 25)
    device.handle_state_update(hid=hid)
    assert device.current_temperature == -15
    assert device.raw_properties["TemSen"] == 25
    assert device.version == "3.33"
    device.handle_state_update(TemSen=19)
    assert device.current_temperature == 19
    device.handle_state_update(TemSen=65)
    assert device.current_temperature == 65


@pytest.mark.asyncio
async def test_trait_keeps_first_ambiguous_guess_as_fallback():
    device = Device(DeviceInfo(*get_mock_info()))
    device.handle_state_update(hid="362001000762+U-CS532AE(LT)V3.33.bin", TemSen=25)
    assert device.current_temperature == -15
    device.handle_state_update(hid="999999999999+U-UNKNOWNV1.bin")
    assert device.current_temperature == 25
    device.handle_state_update(TemSen=45)
    assert device.current_temperature == 45


@pytest.mark.asyncio
@pytest.mark.parametrize("arrival", ["before", "same", "after"])
@pytest.mark.parametrize(
    "hid,sensor,initial,ambiguous,opposite,final",
    [
        ("362001000762+U-CS532AE(LT)V3.33.bin", 19, 19, 25, 65, 65),
        ("362001060200+U-CS849AV10.bin", 65, 25, -15, 19, -21),
    ],
)
async def test_learning_overrides_trait_in_every_arrival_order(
    arrival, hid, sensor, initial, ambiguous, opposite, final
):
    device = Device(DeviceInfo(*get_mock_info()))
    if arrival == "before":
        device.handle_state_update(hid=hid)
    packet = {"TemSen": sensor, "TemUn": 0}
    if arrival == "same":
        packet["hid"] = hid
    device.handle_state_update(**packet)
    assert device.current_temperature == initial
    device.handle_state_update(hid=hid)
    assert device.current_temperature == initial
    device.handle_state_update(TemSen=25)
    assert device.current_temperature == ambiguous
    device.handle_state_update(TemSen=opposite)
    assert device.current_temperature == final
    device.handle_state_update(TemSen=25)
    assert device.current_temperature == ambiguous


@pytest.mark.asyncio
@pytest.mark.parametrize("hid_first", [False, True])
@pytest.mark.parametrize("replacement", [
    "999999999999+U-UNKNOWNV1.bin", "888888888888+U-OTHERV2.bin",
])
async def test_unknown_hid_preserves_guess_until_learning(hid_first, replacement):
    device = Device(DeviceInfo(*get_mock_info()))
    hid = "999999999999+U-UNKNOWNV1.bin"
    if hid_first:
        device.handle_state_update(hid=hid)
    device.handle_state_update(TemSen=25, TemUn=0, TemRec=0)
    device.handle_state_update(hid=replacement, TemSen=45)
    assert device.current_temperature == 45
    device.handle_state_update(hid=replacement, TemSen=65)
    assert device.current_temperature == 25
    assert device.hid == replacement


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "replacement,version",
    [
        ("362001000762+U-CS532AE(LT)V3.33.bin", "3.33"),
        ("362001060200+U-CS849AV10.bin", "10"),
        ("999999999999+U-UNKNOWNV2.bin", "2"),
        ("malformed", None),
        ("", None),
        (None, None),
        (123, None),
    ],
)
@pytest.mark.parametrize("first,expected", [(19, 25), (65, -15)])
async def test_temperature_lock_survives_hid_replacement(first, expected, replacement, version):
    device = Device(DeviceInfo(*get_mock_info()))
    device.handle_state_update(hid="999999999999+U-UNKNOWNV1.bin", TemSen=first, TemUn=0)
    device.handle_state_update(TemSen=25)
    assert device.current_temperature == expected
    device.handle_state_update(hid=replacement)
    assert device.current_temperature == expected
    assert device.version == version
    assert device.hid == replacement
    assert device.raw_properties["TemSen"] == 25


@pytest.mark.asyncio
async def test_temperature_learning_is_per_device():
    direct = Device(DeviceInfo(*get_mock_info()))
    biased = Device(DeviceInfo(*get_mock_info()))
    direct.handle_state_update(TemSen=19)
    biased.handle_state_update(TemSen=65)
    for device in (direct, biased):
        device.handle_state_update(TemSen=25)
    assert direct.current_temperature == 25
    assert biased.current_temperature == -15


@pytest.mark.asyncio
@pytest.mark.parametrize("hid,version", [
    ("362001000762", None),
    ("362001000762+U-CS532AE.bin", None),
    ("invalid+U-CS532AEV3.33.bin", "3.33"),
    (None, None), (123, None), ([], None), ({}, None),
])
async def test_invalid_hid_cannot_supply_temperature_trait(hid, version):
    device = Device(DeviceInfo(*get_mock_info()))
    device.handle_state_update(hid=hid, TemSen=25)
    assert device.current_temperature == 25
    assert device.hid == hid
    assert device.version == version
    assert device.raw_properties["TemSen"] == 25


@pytest.mark.asyncio
@pytest.mark.parametrize("direct_assignment", [False, True])
async def test_temperature_profile_follows_hid_changes(direct_assignment):
    device = Device(DeviceInfo(*get_mock_info()))
    device.handle_state_update(TemSen=45, TemUn=0)
    for hid, expected in [
        ("362001060200+U-CS849AV10.bin", 45),
        ("362001000762+U-CS532AE(LT)V3.33.bin", 5),
        ("999999999999+U-UNKNOWNV1.bin", 5),
        ([], 5),
        (None, 5),
        ("362001060200+U-CS849AV10.bin", 45),
    ]:
        if direct_assignment:
            device.hid = hid
        else:
            device.handle_state_update(hid=hid)
        assert device.current_temperature == expected
        device.handle_state_update(Pow=1)
        assert device.current_temperature == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("use_raw_dict", [False, True])
async def test_local_sensor_mutation_does_not_learn(use_raw_dict):
    device = Device(DeviceInfo(*get_mock_info()))
    device.handle_state_update(SetTem=25, TemRec=0)
    if use_raw_dict:
        device.raw_properties["TemSen"] = 65
    else:
        device.set_property(Props.TEMP_SENSOR, 65)
    assert device.current_temperature is None
    assert device.target_temperature == 25
    device.handle_state_update(Pow=1)
    assert device.current_temperature is None
    device.handle_state_update(TemSen=65)
    assert device.current_temperature == 25


@pytest.mark.asyncio
@pytest.mark.parametrize("reported_version", ["4", "4.0", "7", None])
async def test_version_metadata_does_not_control_temperature(reported_version):
    device = Device(DeviceInfo(*get_mock_info()))
    device.handle_state_update(TemSen=65, TemUn=0, TemRec=0)
    device.version = reported_version
    assert device.current_temperature == 25
    assert device.version == reported_version


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "hid,sensor",
    [
        ("362001000762+U-CS532AE(LT)V3.33.bin", 65),
        ("362001060297+U-CS532AF(MTK)V4.bin", 25),
    ],
)
async def test_temperature_offset_precedes_fahrenheit_conversion(hid, sensor):
    device = Device(DeviceInfo(*get_mock_info()))
    device.handle_state_update(hid=hid, TemSen=sensor, TemUn=1, TemRec=0)
    assert device.current_temperature == 77
    assert device.raw_properties["TemSen"] == sensor


@pytest.mark.asyncio
@pytest.mark.parametrize("samples,expected", [
    ([65, 25, 45, 15, 55], [25, 25, 45, 15, 15]),
    ([45, 25, 45, 65, 45], [5, 25, 45, 25, 5]),
    ([1, 40, 50], [1, 40, 50]),
    ([39], [39]),
    ([40], [0]),
    ([50], [10]),
    ([51], [11]),
    ([90], [50]),
    ([25, 0, 45], [25, 0, 45]),
    ([65, 0, 45], [25, None, 5]),
    ([0, 45, 25], [None, 5, 25]),
])
async def test_runtime_temperature_relearning(samples, expected):
    device = Device(DeviceInfo(*get_mock_info()))
    device.handle_state_update(hid="362001064973+U-W04NV19.bin", TemUn=0, TemRec=0)
    for raw, temperature in zip(samples, expected):
        device.handle_state_update(TemSen=raw)
        assert device.current_temperature == temperature


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", [None, True, False, "25", 25.5, -1, -20, 91])
@pytest.mark.parametrize("first,expected", [(None, 5), (25, 45), (65, 5)])
async def test_runtime_invalid_samples_preserve_inference(invalid, first, expected):
    device = Device(DeviceInfo(*get_mock_info()))
    device.handle_state_update(hid="362001064973+U-W04NV19.bin", TemUn=0)
    if first is not None:
        device.handle_state_update(TemSen=first)
    device.handle_state_update(TemSen=invalid)
    assert device.current_temperature is None
    device.handle_state_update(TemSen=45)
    assert device.current_temperature == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("first,samples,expected", [
    (15, [55], [15]),
    (25, [45, 65], [45, 25]),
])
async def test_runtime_hid_arrival_retains_unknown_inference(first, samples, expected):
    device = Device(DeviceInfo(*get_mock_info()))
    device.handle_state_update(TemSen=first, TemUn=0)
    assert device.current_temperature == first
    device.handle_state_update(hid="362001064973+U-W04NV19.bin")
    assert device.current_temperature == first
    for raw, temperature in zip(samples, expected):
        device.handle_state_update(TemSen=raw)
        assert device.current_temperature == temperature


@pytest.mark.asyncio
@pytest.mark.parametrize("use_raw_dict", [False, True])
async def test_runtime_only_incoming_samples_relearn(use_raw_dict):
    device = Device(DeviceInfo(*get_mock_info()))
    device.handle_state_update(hid="362001064973+U-W04NV19.bin", TemSen=65, TemUn=0)
    if use_raw_dict:
        device.raw_properties["TemSen"] = 25
    else:
        device.set_property(Props.TEMP_SENSOR, 25)
    assert device.current_temperature == -15
    device.handle_state_update(Pow=1)
    assert device.current_temperature == -15
    device.handle_state_update(hid="362001064973+U-W04NV19.bin")
    assert device.current_temperature == -15
    device.handle_state_update(TemSen=25)
    assert device.current_temperature == 25


@pytest.mark.asyncio
@pytest.mark.parametrize("replacement", [
    "362001000762+U-CS532AE(LT)V3.33.bin", "999999999999+U-UNKNOWNV1.bin",
])
async def test_leaving_runtime_profile_freezes_latest_inference(replacement):
    device = Device(DeviceInfo(*get_mock_info()))
    device.handle_state_update(hid="362001064973+U-W04NV19.bin", TemSen=65, TemUn=0)
    device.handle_state_update(TemSen=25)
    device.handle_state_update(hid=replacement, TemSen=65)
    assert device.current_temperature == 65


@pytest.mark.asyncio
async def test_runtime_relearning_precedes_fahrenheit_conversion():
    device = Device(DeviceInfo(*get_mock_info()))
    device.handle_state_update(hid="362001064973+U-W04NV19.bin", TemUn=1, TemRec=0)
    for raw in (65, 25):
        device.handle_state_update(TemSen=raw)
        assert device.current_temperature == 77


@pytest.mark.asyncio
@pytest.mark.parametrize("temperature", [18, 19, 20, 21, 22])
async def test_send_temperature_celsius(temperature, cipher, send):
    """Check that temperature is set and read properly in C."""
    state = get_mock_state()
    state["TemSen"] = temperature + 40
    device = await generate_device_mock_async()
    device.temperature_units = TemperatureUnits.C
    device.target_temperature = temperature

    await device.push_state_update()
    assert send.call_count == 1

    def fake_send(*args, **kwargs):
        device.handle_state_update(**state)
    send.side_effect = fake_send

    await device.update_state()

    assert device.current_temperature == temperature


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "temperature", [60, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 86]
)
async def test_send_temperature_farenheit(temperature, cipher, send):
    """Check that temperature is set and read properly in F."""
    temSet = round((temperature - 32.0) * 5.0 / 9.0)
    temRec = (int)((((temperature - 32.0) * 5.0 / 9.0) - temSet) > 0)

    state = get_mock_state()
    state["TemSen"] = temSet + 40
    state["TemRec"] = temRec
    state["TemUn"] = 1
    device = await generate_device_mock_async()

    device.temperature_units = TemperatureUnits.F
    device.target_temperature = temperature

    await device.push_state_update()
    assert send.call_count == 1

    def fake_send(*args, **kwargs):
        device.handle_state_update(**state)
    send.side_effect = fake_send

    await device.update_state()

    assert device.current_temperature == temperature


@pytest.mark.asyncio
@pytest.mark.parametrize("temperature", [-270, -61, 61, 100])
async def test_send_temperature_out_of_range_celsius(temperature, cipher, send):
    """Check that bad temperatures raise the appropriate error."""
    device = await generate_device_mock_async()

    device.temperature_units = TemperatureUnits.C
    with pytest.raises(ValueError):
        device.target_temperature = temperature


@pytest.mark.asyncio
@pytest.mark.parametrize("temperature", [-270, -61, 141])
async def test_send_temperature_out_of_range_farenheit_set(temperature, cipher, send):
    """Check that bad temperatures raise the appropriate error."""
    device = await generate_device_mock_async()

    for p in Props:
        assert device.get_property(p) is None

    device.temperature_units = TemperatureUnits.F
    with pytest.raises(ValueError):
        device.target_temperature = temperature


@pytest.mark.asyncio
async def test_ambient_fahrenheit_conversion_failure_preserves_lock():
    device = Device(DeviceInfo(*get_mock_info()))
    device.handle_state_update(SetTem=25, TemSen=19, TemRec=0)
    assert device.current_temperature == 19
    device.temperature_units = TemperatureUnits.F
    device.handle_state_update(TemSen=65)
    assert device.current_temperature is None
    assert device.target_temperature == 77
    device.handle_state_update(TemSen=25)
    assert device.current_temperature == 77


@pytest.mark.asyncio
async def test_enable_disable_sleep_mode(cipher, send):
    """Check that properties can be updates."""
    device = await generate_device_mock_async()

    device.sleep = True
    await device.push_state_update()
    assert send.call_count == 1

    assert device.get_property(Props.SLEEP) == 1
    assert device.get_property(Props.SLEEP_MODE) == 1

    device.sleep = False
    await device.push_state_update()
    assert send.call_count == 2

    assert device.get_property(Props.SLEEP) == 0
    assert device.get_property(Props.SLEEP_MODE) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "temperature", [59, 77, 86]
)
async def test_mismatch_temrec_farenheit(temperature, cipher, send):
    """Check that temperature is set and read properly in F."""
    temSet = round((temperature - 32.0) * 5.0 / 9.0)
    temRec = (int)((((temperature - 32.0) * 5.0 / 9.0) - temSet) > 0)
    
    state = get_mock_state()
    state["TemSen"] = temSet + 40
    # Now, we alter the temRec on the device so it is not found in the table.
    state["TemRec"] = (temRec + 1) % 2
    state["TemUn"] = 1
    device = await generate_device_mock_async()
    device.temperature_units = TemperatureUnits.F
    device.target_temperature = temperature
    
    await device.push_state_update()
    assert send.call_count == 1

    def fake_send(*args, **kwargs):
        device.handle_state_update(**state)
    send.side_effect = fake_send

    await device.update_state()

    assert device.current_temperature == temperature


@pytest.mark.asyncio
async def test_device_equality(send):
    """Check that two devices with the same info and key are equal."""

    info1 = DeviceInfo(*get_mock_info())
    device1 = Device(info1)
    await device1.bind(key="fake_key", cipher=CipherV1())

    info2 = DeviceInfo(*get_mock_info())
    device2 = Device(info2)
    await device2.bind(key="fake_key", cipher=CipherV1())

    assert device1 == device2

    # Change the key of the second device
    await device2.bind(key="another_fake_key", cipher=CipherV1())
    assert device1 != device2

    # Change the info of the second device
    info2 = DeviceInfo(*get_mock_info())
    device2 = Device(info2)
    device2.power = True
    await device2.bind(key="fake_key", cipher=CipherV1())
    assert device1 != device2


def test_device_key_set_get():
    """Check that the device key can be set and retrieved."""
    device = Device(DeviceInfo(*get_mock_info()))
    device.device_cipher = CipherV1()
    device.device_key = "fake_key"
    assert device.device_key == "fake_key"


@pytest.mark.asyncio
async def test_buzzer_default(cipher, send):
    """Check that buzzer is enabled by default."""
    device = await generate_device_mock_async()
    assert device.buzzer is True


@pytest.mark.asyncio
async def test_buzzer_disabled(cipher, send):
    """Check that disabling buzzer injects Buzzer_ON_OFF into commands."""
    device = await generate_device_mock_async()

    device.power = True
    device.buzzer = False
    await device.push_state_update()
    assert send.call_count == 1
    assert "Buzzer_ON_OFF" in send.call_args_list[0].args[0]["pack"]["opt"]
    assert not device.buzzer

    send.reset_mock()

    device.power = False
    device.buzzer = True
    await device.push_state_update()
    assert send.call_count == 1
    assert "Buzzer_ON_OFF" not in send.call_args_list[0].args[0]["pack"]["opt"]
    assert device.buzzer


@pytest.mark.asyncio
async def test_buzzer_disabled_every_command(cipher, send):
    """Check that Buzzer_ON_OFF is sent with every command when disabled."""
    device = await generate_device_mock_async()
    device.buzzer = False

    device.power = True
    await device.push_state_update()
    assert "Buzzer_ON_OFF" in send.call_args_list[0].args[0]["pack"]["opt"]

    send.reset_mock()

    device.mode = 1
    await device.push_state_update()
    assert "Buzzer_ON_OFF" in send.call_args_list[0].args[0]["pack"]["opt"]


@pytest.mark.asyncio
async def has_valid_state_with_valid_properties(cipher, send):
    """Check that the device has a valid state with valid properties."""
    device = await generate_device_mock_async()

    def fake_send(*args, **kwargs):
        state = get_mock_state()
        device.handle_state_update(**state)
    send.side_effect = fake_send

    await device.update_state()
    assert device.has_valid_state is True
   
   
@pytest.mark.asyncio
async def request_version_timeout_error(cipher, send):
    """Check that request_version raises DeviceTimeoutError when a timeout occurs."""
    device = await generate_device_mock_async()

    send.side_effect = asyncio.TimeoutError

    with pytest.raises(DeviceTimeoutError):
        await device.request_version() 


@pytest.mark.asyncio
async def test_get_sub_devices(cipher, send):
    """Check that get_sub_devices sends subList and returns DeviceInfo list."""
    info = DeviceInfo("1.1.1.0", "7000", "aabbcc001122", "Gateway", sub_count=2)
    device = Device(info, timeout=1)
    await device.bind(key="fake_key", cipher=CipherV1())

    sub_devices_raw = [
        {"mac": "sub111111", "name": "SubDevice1", "brand": "gree", "model": "model1", "ver": "1.0"},
        {"mac": "sub222222", "name": "SubDevice2"},
    ]

    def fake_send(*args, **kwargs):
        device.handle_sublist_response(sub_devices_raw, generic=kwargs.get("request_cipher") is not None)
    send.side_effect = fake_send

    result = await device.get_sub_devices()

    assert len(result) == 2
    assert result[0].mac == "sub111111"
    assert result[0].name == "SubDevice1"
    assert result[0].ip == info.ip
    assert result[0].port == info.port
    assert result[1].mac == "sub222222"
    assert result[1].name == "SubDevice2"
    assert result[0].gateway_key == "fake_key"
    assert result[1].gateway_key == "fake_key"


@pytest.mark.asyncio
async def test_get_sub_devices_timeout(cipher, send):
    """Check that get_sub_devices raises DeviceTimeoutError on no response."""
    info = DeviceInfo("1.1.1.0", "7000", "aabbcc001122", "Gateway", sub_count=2)
    device = Device(info, timeout=1)
    await device.bind(key="fake_key", cipher=CipherV1())

    with pytest.raises(DeviceTimeoutError):
        await device.get_sub_devices()


@pytest.mark.asyncio
async def test_sub_device_bind_with_key(cipher, send):
    """Check that a sub-device can bind with an explicit key and cipher."""
    sub_info = DeviceInfo("1.1.1.0", "7000", "sub111111", "SubDevice1")
    sub_device = Device(sub_info, timeout=1)

    await sub_device.bind(key="gateway_key", cipher=CipherV1())

    assert sub_device.device_cipher is not None
    assert sub_device.device_cipher.key == "gateway_key"


@pytest.mark.asyncio
async def test_sub_device_update_state(cipher, send):
    """Check that a sub-device can update state through its own transport."""
    sub_info = DeviceInfo("1.1.1.0", "7000", "sub111111", "SubDevice1")
    sub_device = Device(sub_info, timeout=1)
    await sub_device.bind(key="gateway_key", cipher=CipherV1())

    def fake_send(*args, **kwargs):
        sub_device.handle_state_update(**get_mock_state())
    send.side_effect = fake_send

    await sub_device.update_state()
    assert sub_device.power is True
    assert sub_device.has_valid_state is True


@pytest.mark.asyncio
async def test_bind_with_gateway_key(cipher, send):
    """Check that bind uses gateway_key from device_info when no key is provided."""
    sub_info = DeviceInfo("1.1.1.0", "7000", "sub111111", "SubDevice1", gateway_key="gateway_key_123", gateway_cipher=CipherV1())
    device = Device(sub_info, timeout=1, bind_timeout=1)

    def fake_send(*args, **kwargs):
        device.handle_state_update(Pow=1)
    send.side_effect = fake_send

    await device.bind()

    assert device.device_cipher is not None
    assert device.device_cipher.key == "gateway_key_123"


@pytest.mark.asyncio
async def test_get_sub_devices_name_fallback(cipher, send):
    """Sub-device name comes from the response, falling back to mac when absent."""
    info = DeviceInfo("1.1.1.0", "7000", "aabbcc001122", "Gateway", sub_count=2)
    device = Device(info, timeout=1)
    await device.bind(key="fake_key", cipher=CipherV1())

    sub_devices_raw = [
        {"mac": "aabb11223344", "name": "Living Room"},
        {"mac": "ddee55667788"},
    ]

    def fake_send(*args, **kwargs):
        device.handle_sublist_response(sub_devices_raw, generic=kwargs.get("request_cipher") is not None)
    send.side_effect = fake_send

    result = await device.get_sub_devices()

    assert len(result) == 2
    # name present in response is used verbatim
    assert result[0].name == "Living Room"
    # no name in response → DeviceInfo falls back to mac
    assert result[1].name == "ddee55667788"


def test_target_temperature_survives_missing_temrec():
    """Sub-devices omit / null out TemRec; target temperature must not vanish.

    A SetTem command acknowledgement echoes val=[25, null, null] for
    ["SetTem", "TemRec", "TemUn"], which previously reset target_temperature
    to None. TemRec is only the 0.5-degree bit and should default to 0.
    """
    device = Device(DeviceInfo("1.1.1.1", "7000", "aabbcc001122", "Sub"))
    device.version = "1.10"

    # Initial status from a gateway sub-device: TemUn / TemRec are empty strings
    device._properties = {
        Props.POWER.value: 1,
        Props.MODE.value: 1,
        Props.TEMP_SET.value: 25,
        Props.TEMP_UNIT.value: "",
        Props.TEMP_BIT.value: "",
        Props.TEMP_SENSOR.value: "",
    }
    assert device.target_temperature == 25

    # The res echo of a SetTem command writes None for TemRec / TemUn
    device.handle_state_update(SetTem=25, TemRec=None, TemUn=None)
    assert device.target_temperature == 25

    # A missing setpoint still yields None
    device._properties[Props.TEMP_SET.value] = None
    assert device.target_temperature is None

