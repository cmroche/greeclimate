import asyncio
import enum
import json
from contextlib import asynccontextmanager

import pytest

from greeclimate import device_profile
from greeclimate.cipher import CipherV1, CipherV2
from greeclimate.device import Device, DeviceInfo, Props, TemperatureUnits
from greeclimate.device_profile import DeviceProfile
from greeclimate.exceptions import DeviceNotBoundError, DeviceTimeoutError
from greeclimate.mid_profile import match_mid_profile
from greeclimate.network import Response
from tests.common import udp_peer
from tests.test_emulator import peer_packet, peer_reply


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
    assert DeviceInfo(*props).mid is None
    assert DeviceInfo(*props) == DeviceInfo(*props, mid=None)
    assert DeviceInfo(*props, mid="0001") == DeviceInfo(*props, mid="0001")
    assert DeviceInfo(*props, mid="0001") != DeviceInfo(*props, mid="10001")
    assert DeviceInfo(*props, mid="0001") != DeviceInfo(*props)

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
@pytest.mark.parametrize("mid", ["13805", "10001", "60"])
async def test_mid_profile_poll_columns(cipher, send, mid):
    device = Device(DeviceInfo(*get_mock_info(), mid=mid))
    await device.bind(key="0123456789abcdef", cipher=CipherV1())
    profile = match_mid_profile(mid)
    columns = list(profile.status_columns)
    initial = columns if "hid" in columns else columns + ["hid"]

    await device.update_state()
    assert send.call_args.args[0]["pack"]["cols"] == initial
    device.handle_state_update(hid=get_mock_state()["hid"])
    await device.update_state()
    assert send.call_args.args[0]["pack"]["cols"] == columns
    assert send.call_args_list[0].args[0]["pack"]["cols"] == initial
    assert profile.status_columns == tuple(columns)


@pytest.mark.asyncio
@pytest.mark.parametrize("mid", ["unrecorded", None, "605c"])
async def test_unknown_mid_uses_full_poll(cipher, send, mid):
    info = DeviceInfo(*get_mock_info(), mid=mid)
    info.model = "10001"
    device = Device(info)
    await device.bind(key="0123456789abcdef", cipher=CipherV1())
    columns = [prop.value for prop in Props]

    await device.update_state()
    assert send.call_args.args[0]["pack"]["cols"] == columns + ["hid"]
    device.handle_state_update(hid=get_mock_state()["hid"])
    await device.update_state()
    assert send.call_args.args[0]["pack"]["cols"] == columns

    info.mid = "60"
    await device.update_state()
    assert send.call_args.args[0]["pack"]["cols"] == ["hid"]
    info.mid = "unrecorded"
    await device.update_state()
    assert send.call_args.args[0]["pack"]["cols"] == columns


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

    assert device.power is None
    assert device.mode is None
    assert device.target_temperature is None
    assert device.current_temperature is None
    assert device.temperature_units is None
    assert device.fan_speed is None
    assert device.target_humidity is None
    assert device.dehumidifier_mode is None
    assert device.current_humidity is None
    assert device.clean_filter is None
    assert device.water_full is None
    assert device.fresh_air is None
    assert device.xfan is None
    assert device.anion is None
    assert device.sleep is None
    assert device.light is None
    assert device.horizontal_swing is None
    assert device.vertical_swing is None
    assert device.quiet is None
    assert device.turbo is None
    assert device.steady_heat is None
    assert device.power_save is None


@pytest.mark.asyncio
async def test_mid_profile_partial_state_and_extra_fields():
    async with recovery_session() as (device, peer, queue, addr):
        await recovery_receive(queue, device.device_cipher)
        events = asyncio.Queue()
        device.add_handler(Response.DATA, events.put_nowait)
        device.add_handler(Response.RESULT, events.put_nowait)
        peer.sendto(recovery_packet({
            "t": "dat",
            "cols": ["Pow", "Dmod", "Dwet", "DwatSen", "DwatFul", "Dfltr", "airQlt"],
            "dat": [0, 9, 6, 0, 0, 1, 3],
        }, device.device_cipher), addr)
        await asyncio.wait_for(events.get(), 2)
        assert device.power is False
        assert device.dehumidifier_mode == 9
        assert device.target_humidity == 45
        assert device.current_humidity == 0
        assert device.water_full is False
        assert device.clean_filter is True
        assert device.raw_properties["airQlt"] == 3
        assert device.mode is None
        assert device.target_temperature is None
        assert device.current_temperature is None
        assert device.fresh_air is None

        peer.sendto(recovery_packet({
            "t": "dat", "cols": ["TemSen", "TemUn", "TemRec"], "dat": [65, 0, 0],
        }, device.device_cipher), addr)
        await asyncio.wait_for(events.get(), 2)
        assert device.current_temperature == 25
        device.fresh_air = True
        assert device.fresh_air is True
        peer.sendto(recovery_packet({
            "t": "res", "opt": ["Air"], "val": [0],
        }, device.device_cipher), addr)
        await asyncio.wait_for(events.get(), 2)
        assert device.fresh_air is False


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
@pytest.mark.parametrize("hid,properties", [
    ("362001064973+U-W04NV17.bin", ("Buzzer_ON_OFF",)),
    ("362001064973+U-W04NV19.bin", ("Buzzer_ON_OFF",)),
    ("362001065016+U-W04HMV1.05.bin", ("Buzzer_ON_OFF",)),
    ("362001065634+U-WB04BRT13V1.50.bin", ("Buzzer_ON_OFF",)),
    ("362001066763+U-W06A(P3)V6.04.bin", ()),
    ("362001000762+U-CS532AE(LT)V3.33.bin", None),
    ("362001064973+U-W04NV20.bin", None),
    ("362001066763+U-W06A(P3)V6.05.bin", None),
    ("362001066763+U-WB06A(P3)V6.04.bin", None),
    ("999999999999+U-SYNTHETICV1.bin", None),
    ("", None),
    ("malformed", None),
    (None, None),
])
@pytest.mark.parametrize("enabled", [False, True])
async def test_buzzer_fields_follow_exact_firmware_on_every_command(hid, properties, enabled, cipher, send):
    device = await generate_device_mock_async()
    device.handle_state_update(hid=hid)
    device.buzzer = enabled
    assert send.call_count == 0
    expected = {}
    if not enabled and properties and "Buzzer_ON_OFF" in properties:
        expected["Buzzer_ON_OFF"] = 1

    for index, power in enumerate([True, False], start=1):
        device.power = power
        await device.push_state_update()
        pack = send.call_args.args[0]["pack"]
        assert len(pack["opt"]) == len(pack["p"]) == 1 + len(expected)
        assert dict(zip(pack["opt"], pack["p"])) == {"Pow": int(power), **expected}
        assert send.call_count == index
        assert device.buzzer is enabled


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled", [False, True])
async def test_buzzer_ctrl_only_profile_does_not_send_on_off(monkeypatch, enabled, cipher, send):
    hid = "999999999999+U-SYNTHETICV1.bin"
    monkeypatch.setattr(device_profile, "KNOWN_PROFILES", (
        DeviceProfile("999999999999", None, buzzer_properties=("BuzzerCtrl",), exact_hid=hid),
    ))
    device = await generate_device_mock_async()
    device.handle_state_update(hid=hid)
    device.buzzer = enabled
    device.power = True
    await device.push_state_update()
    pack = send.call_args.args[0]["pack"]
    assert dict(zip(pack["opt"], pack["p"])) == {"Pow": 1, "BuzzerCtrl": int(enabled)}
    assert pack["opt"].count("BuzzerCtrl") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("direct_assignment", [False, True])
async def test_buzzer_profile_cache_follows_hid_not_mid(direct_assignment, cipher, send):
    device = await generate_device_mock_async()
    device.device_info.mid = "9300"
    device.buzzer = False
    transitions = [
        ("362001066763+U-W06A(P3)V6.04.bin", {}),
        ("362001065634+U-WB04BRT13V1.50.bin", {"Buzzer_ON_OFF": 1}),
        ("362001066763+U-W06A(P3)V6.05.bin", {}),
        ("362001064973+U-W04NV17.bin", {"Buzzer_ON_OFF": 1}),
        ("362001066763+U-W06A(P3)V6.04.bin", {}),
    ]
    for index, (hid, expected) in enumerate(transitions):
        if direct_assignment:
            device.hid = hid
        else:
            device.handle_state_update(hid=hid)
        device.power = index % 2 == 0
        await device.push_state_update()
        pack = send.call_args.args[0]["pack"]
        assert dict(zip(pack["opt"], pack["p"])) == {"Pow": int(index % 2 == 0), **expected}


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
async def test_request_version_timeout_error(cipher, send):
    """Check that request_version raises DeviceTimeoutError when a timeout occurs."""
    device = await generate_device_mock_async()

    send.side_effect = asyncio.TimeoutError

    with pytest.raises(DeviceTimeoutError):
        await device.request_version() 


RECOVERY_MAC = "020000000001"
RECOVERY_KEY = "0123456789abcdef"


def recovery_packet(inner, cipher=None, outer=None):
    """Use independent ECB framing, or the existing GCM wire implementation."""
    envelope = {"t": "pack", **(outer or {})}
    if cipher is None or isinstance(cipher, CipherV1):
        return peer_packet(envelope, inner, (cipher.key if cipher else "a3K8Bx%2r8Y7#xDh").encode())
    envelope["pack"], envelope["tag"] = cipher.encrypt(inner)
    return json.dumps(envelope).encode()


async def recovery_receive(queue, cipher=None):
    data, addr = await asyncio.wait_for(queue.get(), 2)
    if cipher is None or isinstance(cipher, CipherV1):
        return peer_reply(data, (cipher.key if cipher else "a3K8Bx%2r8Y7#xDh").encode())["inner"], addr
    return cipher.decrypt(json.loads(data)["pack"]), addr


async def recovery_negotiate(device, transport, queue, cipher=None, key=RECOVERY_KEY, **reply):
    task = asyncio.create_task(device.bind(cipher=cipher))
    try:
        request, addr = await recovery_receive(queue, cipher)
        assert request == {"t": "bind", "mac": RECOVERY_MAC, "uid": 0}
        transport.sendto(recovery_packet(
            {"t": "bindok", "mac": RECOVERY_MAC, "key": key, **reply}, cipher
        ), addr)
        await asyncio.wait_for(task, 2)
        return addr
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@asynccontextmanager
async def recovery_session(cipher=None, key=RECOVERY_KEY):
    async with udp_peer() as (transport, queue):
        host, port = transport.get_extra_info("sockname")
        device = Device(DeviceInfo(host, port, RECOVERY_MAC, "saved"), bind_timeout=0.05)
        try:
            addr = await recovery_negotiate(device, transport, queue, cipher, key)
            yield device, transport, queue, addr
        finally:
            device.close()
            if hasattr(device, "_transport_closed"):
                await asyncio.wait_for(device._transport_closed.wait(), 2)
            await asyncio.gather(*device.tasks, return_exceptions=True)


@pytest.mark.parametrize("cipher_type", [CipherV1, CipherV2])
async def test_recovery_saved_info_data_and_control(cipher_type):
    supplied = cipher_type()
    async with recovery_session(supplied) as (device, peer, queue, addr):
        data, results = asyncio.Queue(), asyncio.Queue()
        device.add_handler(Response.DATA, data.put_nowait)
        device.add_handler(Response.RESULT, results.put_nowait)
        request, _ = await recovery_receive(queue, device.device_cipher)
        assert request["t"] == "status"
        peer.sendto(recovery_packet(
            {"t": "dat", "cols": ["Pow", "SetTem"], "dat": [1, 24]}, device.device_cipher
        ), addr)
        assert await asyncio.wait_for(data.get(), 2) == {"Pow": 1, "SetTem": 24}
        assert device.power and device.get_property(Props.TEMP_SET) == 24
        device.power = True
        await device.push_state_update()
        assert queue.empty()
        device.power = False
        await device.push_state_update()
        request, _ = await recovery_receive(queue, device.device_cipher)
        assert request["t"] == "cmd" and dict(zip(request["opt"], request["p"]))["Pow"] == 0
        peer.sendto(recovery_packet(
            {"t": "res", "opt": ["Pow"], "p": [0]}, device.device_cipher
        ), addr)
        assert await asyncio.wait_for(results.get(), 2) == {"Pow": 0}
        assert not device.power
        assert supplied.key == cipher_type().key
        await device.bind()
        await device.update_state()
        request, _ = await recovery_receive(queue, device.device_cipher)
        assert request["t"] == "status" and queue.empty()


@pytest.mark.parametrize("identity", [
    {"mac": "020000000002"}, {"mac": RECOVERY_MAC, "cid": "020000000002"},
    {}, {"mac": None}, {"mac": 123}, {"mac": ""}, {"cid": []},
])
async def test_recovery_rejects_unidentified_or_wrong_unit(identity):
    async with udp_peer() as (peer, queue):
        host, port = peer.get_extra_info("sockname")
        device = Device(DeviceInfo(host, port, RECOVERY_MAC, "saved"), bind_timeout=0.03)
        callbacks = []
        device.add_handler(Response.BIND_OK, callbacks.append)
        task = asyncio.create_task(device.bind(cipher=CipherV1()))
        try:
            _, addr = await recovery_receive(queue)
            peer.sendto(recovery_packet({"t": "bindok", "key": RECOVERY_KEY, **identity}), addr)
            with pytest.raises(DeviceTimeoutError):
                await asyncio.wait_for(task, 2)
            assert not device.ready.is_set() and device.device_cipher is None
            assert not callbacks and not device.has_valid_state
        finally:
            device.close()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("fields", [
    {"key": None}, {"key": ""}, {"key": 123}, {"key": "short"},
    {"key": "\ud800"}, {"r": 500}, {"r": "200"}, {"r": True},
])
async def test_recovery_invalid_matching_bind_fails_cleanly(fields):
    async with udp_peer() as (peer, queue):
        host, port = peer.get_extra_info("sockname")
        device = Device(DeviceInfo(host, port, RECOVERY_MAC, "saved"), bind_timeout=0.03)
        task = asyncio.create_task(device.bind(cipher=CipherV1()))
        try:
            _, addr = await recovery_receive(queue)
            peer.sendto(recovery_packet(
                {"t": "bindok", "mac": RECOVERY_MAC, "key": RECOVERY_KEY, **fields}
            ), addr)
            with pytest.raises(DeviceNotBoundError):
                await asyncio.wait_for(task, 2)
            assert not device.ready.is_set() and device.device_cipher is None
        finally:
            device.close()
            await asyncio.gather(task, return_exceptions=True)


async def test_recovery_close_pending_bind_and_retired_operations():
    async with udp_peer() as (peer, queue):
        host, port = peer.get_extra_info("sockname")
        device = Device(DeviceInfo(host, port, RECOVERY_MAC, "saved"), bind_timeout=0.1)
        task = asyncio.create_task(device.bind(cipher=CipherV1()))
        await recovery_receive(queue)
        device.close()
        device.close()
        with pytest.raises(DeviceNotBoundError):
            await asyncio.wait_for(task, 2)
        for operation in (device.bind, device.update_state, device.request_version, device.push_state_update):
            with pytest.raises(DeviceNotBoundError):
                await operation()
        assert not device.ready.is_set() and device.device_cipher is None


async def test_recovery_retry_failed_bind_without_scan():
    async with udp_peer() as (peer, queue):
        host, port = peer.get_extra_info("sockname")
        device = Device(DeviceInfo(host, port, RECOVERY_MAC, "saved"), bind_timeout=0.02)
        try:
            with pytest.raises(DeviceTimeoutError):
                await device.bind(cipher=CipherV1())
            request, _ = await recovery_receive(queue)
            assert request["t"] == "bind"
            assert device.device_cipher is None and not device.ready.is_set()
            await recovery_negotiate(device, peer, queue, CipherV1())
            status, _ = await recovery_receive(queue, device.device_cipher)
            assert status["t"] == "status"
        finally:
            device.close()


async def test_recovery_pending_bind_cannot_send_session_requests():
    async with udp_peer() as (peer, queue):
        host, port = peer.get_extra_info("sockname")
        device = Device(DeviceInfo(host, port, RECOVERY_MAC, "saved"), bind_timeout=0.1)
        task = asyncio.create_task(device.bind(cipher=CipherV1()))
        try:
            await recovery_receive(queue)
            device.power = True
            for operation in (device.update_state, device.request_version, device.push_state_update):
                with pytest.raises(DeviceNotBoundError):
                    await operation()
        finally:
            device.close()
            await asyncio.gather(task, return_exceptions=True)


async def test_recovery_session_identity_and_stale_key():
    async with recovery_session() as (device, peer, queue, addr):
        await recovery_receive(queue, device.device_cipher)
        events = asyncio.Queue()
        device.add_handler(Response.DATA, events.put_nowait)
        for packet in (
            recovery_packet({"t": "dat", "mac": "020000000002", "cols": ["SetTem"], "dat": [30]}, device.device_cipher),
            recovery_packet({"t": "dat", "cols": ["SetTem"], "dat": [29]}, CipherV1(b"fedcba9876543210")),
            recovery_packet({"t": "bindok", "mac": RECOVERY_MAC, "key": "fedcba9876543210"}, device.device_cipher),
        ):
            peer.sendto(packet, addr)
        peer.sendto(recovery_packet(
            {"t": "dat", "cols": ["SetTem"], "dat": [23]}, device.device_cipher
        ), addr)
        assert await asyncio.wait_for(events.get(), 2) == {"SetTem": 23}
        assert events.empty() and device.get_property(Props.TEMP_SET) == 23 and device.device_key == RECOVERY_KEY


async def test_recovery_same_endpoint_instances_and_shared_cipher():
    async with udp_peer() as (peer, queue):
        host, port = peer.get_extra_info("sockname")
        macs = [RECOVERY_MAC, "020000000002"]
        keys = [RECOVERY_KEY, "fedcba9876543210"]
        devices = [Device(DeviceInfo(host, port, mac, mac), bind_timeout=0.1) for mac in macs]
        supplied = CipherV1()
        events = asyncio.Queue()
        callback = events.put_nowait
        for device in devices:
            device.add_handler(Response.DATA, callback)
        binds = [asyncio.create_task(device.bind(cipher=supplied)) for device in devices]
        addresses = {}
        try:
            for _ in devices:
                request, addr = await recovery_receive(queue)
                index = macs.index(request["mac"])
                addresses[index] = addr
                peer.sendto(recovery_packet({"t": "bindok", "mac": macs[index], "key": keys[index]}), addr)
            await asyncio.wait_for(asyncio.gather(*binds), 2)
            assert [d.device_key for d in devices] == keys
            assert supplied.key == CipherV1().key
            for _ in devices:
                data, addr = await asyncio.wait_for(queue.get(), 2)
                index = next(i for i, endpoint in addresses.items() if endpoint == addr)
                assert peer_reply(data, keys[index].encode())["inner"]["t"] == "status"
            for index in [1, 0]:
                peer.sendto(recovery_packet(
                    {"t": "dat", "cols": ["SetTem"], "dat": [24 + index]}, devices[index].device_cipher
                ), addresses[index])
            assert [await asyncio.wait_for(events.get(), 2) for _ in devices] == [{"SetTem": 25}, {"SetTem": 24}]
            devices[0].remove_handler(Response.DATA, callback)
            devices[0].pause_writing()
            pending = asyncio.create_task(devices[0].update_state())
            await asyncio.wait_for(queue.get(), 2)
            devices[0].close()
            with pytest.raises(DeviceNotBoundError):
                await asyncio.wait_for(pending, 2)
            await devices[1].update_state()
            request, _ = await recovery_receive(queue, devices[1].device_cipher)
            assert request["t"] == "status"
            peer.sendto(recovery_packet(
                {"t": "dat", "cols": ["Pow"], "dat": [1]}, devices[1].device_cipher
            ), addresses[1])
            assert await asyncio.wait_for(events.get(), 2) == {"Pow": 1}
            assert devices[1].power
        finally:
            for device in devices:
                device.close()
            await asyncio.gather(*binds, return_exceptions=True)


async def test_recovery_endpoint_replacement_does_not_retarget_connected_socket():
    async with recovery_session() as (old, old_peer, old_queue, old_addr):
        await recovery_receive(old_queue, old.device_cipher)
        async with udp_peer() as (new_peer, new_queue):
            host, port = new_peer.get_extra_info("sockname")
            old.device_info.ip, old.device_info.port = host, port
            await old.update_state()
            request, _ = await recovery_receive(old_queue, old.device_cipher)
            assert request["t"] == "status" and new_queue.empty()
            old.close()
            replacement = Device(DeviceInfo(host, port, RECOVERY_MAC, "moved"), bind_timeout=0.1)
            events = asyncio.Queue()
            replacement.add_handler(Response.DATA, events.put_nowait)
            try:
                addr = await recovery_negotiate(replacement, new_peer, new_queue, CipherV1())
                await recovery_receive(new_queue, replacement.device_cipher)
                new_peer.sendto(recovery_packet(
                    {"t": "dat", "cols": ["SetTem"], "dat": [28]}, replacement.device_cipher
                ), addr)
                assert await asyncio.wait_for(events.get(), 2) == {"SetTem": 28}
                replacement.power = True
                await replacement.push_state_update()
                command, _ = await recovery_receive(new_queue, replacement.device_cipher)
                assert command["t"] == "cmd" and old_queue.empty()
            finally:
                replacement.close()


async def test_recovery_same_address_reboot_new_session():
    async with recovery_session() as (old, peer, queue, addr):
        await recovery_receive(queue, old.device_cipher)
        host, port = peer.get_extra_info("sockname")
        old.close()
    async with udp_peer(host, port) as (peer, queue):
        replacement = Device(DeviceInfo(host, port, RECOVERY_MAC, "reboot"), bind_timeout=0.1)
        events = asyncio.Queue()
        replacement.add_handler(Response.DATA, events.put_nowait)
        try:
            addr = await recovery_negotiate(replacement, peer, queue, CipherV1(), "fedcba9876543210")
            await recovery_receive(queue, replacement.device_cipher)
            peer.sendto(recovery_packet(
                {"t": "dat", "cols": ["SetTem"], "dat": [27]}, replacement.device_cipher
            ), addr)
            assert await asyncio.wait_for(events.get(), 2) == {"SetTem": 27}
            assert replacement.device_key == "fedcba9876543210"
        finally:
            replacement.close()


async def test_recovery_late_v1_reply_during_v2_negotiation():
    async with udp_peer() as (peer, queue):
        host, port = peer.get_extra_info("sockname")
        device = Device(DeviceInfo(host, port, RECOVERY_MAC, "fallback"), bind_timeout=0.05)
        task = asyncio.create_task(device.bind())
        try:
            first, addr = await recovery_receive(queue)
            assert first["t"] == "bind"
            second, addr = await recovery_receive(queue, CipherV2())
            assert second["t"] == "bind"
            peer.sendto(recovery_packet({"t": "bindok", "mac": RECOVERY_MAC, "key": RECOVERY_KEY}), addr)
            peer.sendto(recovery_packet(
                {"t": "bindOk", "key": RECOVERY_KEY}, CipherV2(), {"cid": RECOVERY_MAC, "tcid": "app"}
            ), addr)
            await asyncio.wait_for(task, 2)
            assert isinstance(device.device_cipher, CipherV2) and device.device_key == RECOVERY_KEY
        finally:
            device.close()
            await asyncio.gather(task, return_exceptions=True)


async def test_recovery_close_during_endpoint_creation(monkeypatch):
    loop = asyncio.get_running_loop()
    create_endpoint = loop.create_datagram_endpoint
    created, release = asyncio.Event(), asyncio.Event()
    transports = []

    async def gated_endpoint(*args, **kwargs):
        transport, protocol = await create_endpoint(*args, **kwargs)
        transports.append(transport)
        created.set()
        await release.wait()
        return transport, protocol

    async with udp_peer() as (peer, queue):
        host, port = peer.get_extra_info("sockname")
        device = Device(DeviceInfo(host, port, RECOVERY_MAC, "race"), bind_timeout=0.02)
        monkeypatch.setattr(loop, "create_datagram_endpoint", gated_endpoint)
        task = asyncio.create_task(device.bind(cipher=CipherV1()))
        try:
            await asyncio.wait_for(created.wait(), 2)
            device.close()
            release.set()
            with pytest.raises(DeviceNotBoundError):
                await asyncio.wait_for(task, 2)
            assert all(transport.is_closing() for transport in transports)
            assert queue.empty() and not device.ready.is_set()
        finally:
            release.set()
            device.close()
            await asyncio.gather(task, return_exceptions=True)


@pytest.fixture(autouse=True)
async def recovery_loop_errors(request):
    if not request.node.name.startswith("test_recovery"):
        yield
        return
    loop = asyncio.get_running_loop()
    previous = loop.get_exception_handler()
    errors = []
    loop.set_exception_handler(lambda _, context: errors.append(context))
    try:
        yield
        barrier = loop.create_future()
        loop.call_soon(barrier.set_result, None)
        await barrier
        assert not errors
    finally:
        loop.set_exception_handler(previous)


@pytest.mark.parametrize("operation", ["update_state", "request_version", "push_state_update"])
async def test_recovery_implicit_bind(operation):
    async with udp_peer() as (peer, queue):
        host, port = peer.get_extra_info("sockname")
        device = Device(DeviceInfo(host, port, RECOVERY_MAC, "implicit"), bind_timeout=0.1)
        if operation == "push_state_update":
            device.power = True
        task = asyncio.create_task(getattr(device, operation)())
        try:
            request, addr = await recovery_receive(queue)
            assert request["t"] == "bind"
            peer.sendto(recovery_packet({"t": "bindok", "mac": RECOVERY_MAC, "key": RECOVERY_KEY}), addr)
            await asyncio.wait_for(task, 2)
            requests = [await recovery_receive(queue, device.device_cipher) for _ in range(2)]
            assert any(r["t"] == ("cmd" if operation == "push_state_update" else "status") for r, _ in requests)
        finally:
            device.close()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("paused_send", [False, True])
async def test_recovery_cancel_bind_then_retry(paused_send):
    async with udp_peer() as (peer, queue):
        host, port = peer.get_extra_info("sockname")
        device = Device(DeviceInfo(host, port, RECOVERY_MAC, "cancel"), bind_timeout=0.1)
        if paused_send:
            await device._loop.create_datagram_endpoint(lambda: device, remote_addr=(host, port))
            device.pause_writing()
        task = asyncio.create_task(device.bind(cipher=CipherV1()))
        try:
            await recovery_receive(queue)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert device.device_cipher is None and not device.ready.is_set()
            await recovery_negotiate(device, peer, queue, CipherV1())
        finally:
            device.close()
            await asyncio.gather(task, return_exceptions=True)


async def test_recovery_concurrent_bind_is_one_session():
    async with udp_peer() as (peer, queue):
        host, port = peer.get_extra_info("sockname")
        device = Device(DeviceInfo(host, port, RECOVERY_MAC, "serialized"), bind_timeout=0.1)
        tasks = [asyncio.create_task(device.bind(cipher=CipherV1())) for _ in range(2)]
        try:
            request, addr = await recovery_receive(queue)
            assert request["t"] == "bind"
            peer.sendto(recovery_packet({"t": "bindok", "mac": RECOVERY_MAC, "key": RECOVERY_KEY}), addr)
            await asyncio.wait_for(asyncio.gather(*tasks), 2)
            request, _ = await recovery_receive(queue, device.device_cipher)
            assert request["t"] == "status" and queue.empty()
        finally:
            device.close()
            await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.parametrize("mac", [None, "", "::--..", 123])
async def test_recovery_invalid_saved_identity_opens_no_socket(mac, monkeypatch):
    device = Device(DeviceInfo("127.0.0.1", 7000, mac, "invalid"))
    opened = []

    async def unexpected_endpoint(*args, **kwargs):
        opened.append(True)
        raise AssertionError("invalid identity opened a socket")

    monkeypatch.setattr(device._loop, "create_datagram_endpoint", unexpected_endpoint)
    try:
        with pytest.raises(DeviceNotBoundError):
            await device.bind()
        assert not opened
    finally:
        device.close()


async def test_recovery_caller_scan_unlocks_retry():
    from ipaddress import IPv4Address
    from greeclimate.discovery import Discovery, Listener

    async with udp_peer(port=7000) as (peer, queue):
        device = Device(DeviceInfo("127.0.0.1", 7000, RECOVERY_MAC, "scan-first"), bind_timeout=0.02)
        discovery = Discovery()
        found = asyncio.Queue()

        class Observer(Listener):
            async def device_found(self, info):
                found.put_nowait(info)

        discovery.add_listener(Observer())
        try:
            with pytest.raises(DeviceTimeoutError):
                await device.bind(cipher=CipherV1())
            request, _ = await recovery_receive(queue)
            assert request["t"] == "bind" and queue.empty()
            await discovery.scan(target_addresses=[IPv4Address("127.0.0.1")])
            data, addr = await asyncio.wait_for(queue.get(), 2)
            assert json.loads(data) == {"t": "scan"}
            peer.sendto(recovery_packet({"t": "dev", "mac": RECOVERY_MAC, "name": "scan-first"}), addr)
            info = await asyncio.wait_for(found.get(), 2)
            assert (info.ip, info.port, info.mac) == ("127.0.0.1", 7000, RECOVERY_MAC)
            await recovery_negotiate(device, peer, queue, CipherV1())
            status, _ = await recovery_receive(queue, device.device_cipher)
            assert status["t"] == "status"
        finally:
            device.close()
            discovery.close()


async def test_recovery_conflicting_outer_bind_and_session_identities():
    async with udp_peer() as (peer, queue):
        host, port = peer.get_extra_info("sockname")
        device = Device(DeviceInfo(host, port, RECOVERY_MAC, "outer"), bind_timeout=0.05)
        events = asyncio.Queue()
        device.add_handler(Response.DATA, events.put_nowait)
        task = asyncio.create_task(device.bind(cipher=CipherV1()))
        try:
            _, addr = await recovery_receive(queue)
            peer.sendto(recovery_packet(
                {"t": "bindok", "mac": RECOVERY_MAC, "key": "fedcba9876543210"},
                outer={"cid": "020000000002"},
            ), addr)
            peer.sendto(recovery_packet(
                {"t": "bindok", "key": RECOVERY_KEY, "r": 200},
                outer={"cid": RECOVERY_MAC, "tcid": "app"},
            ), addr)
            await asyncio.wait_for(task, 2)
            assert device.device_key == RECOVERY_KEY
            await recovery_receive(queue, device.device_cipher)
            for identity in ({"cid": 123}, {"cid": "app"}, {"cid": "020000000002"}):
                peer.sendto(recovery_packet(
                    {"t": "dat", "cols": ["Pow"], "dat": [0]}, device.device_cipher, identity
                ), addr)
            peer.sendto(recovery_packet(
                {"t": "dat", "cols": ["Pow"], "dat": [1]}, device.device_cipher
            ), addr)
            assert await asyncio.wait_for(events.get(), 2) == {"Pow": 1}
            assert events.empty() and device.power
        finally:
            device.close()
            await asyncio.gather(task, return_exceptions=True)


async def test_recovery_noncanonical_public_mac_binds_canonically_and_isolates_senders():
    async with udp_peer() as (peer, queue):
        host, port = peer.get_extra_info("sockname")
        device = Device(DeviceInfo(host, port, "AA:BB:CC:11:22:33", "spelling"), bind_timeout=0.05)
        events = asyncio.Queue()
        device.add_handler(Response.DATA, events.put_nowait)
        task = asyncio.create_task(device.bind(cipher=CipherV1()))
        try:
            request, addr = await recovery_receive(queue)
            assert request["t"] == "bind" and request["mac"] == "aabbcc112233"
            peer.sendto(recovery_packet(
                {"t": "bindok", "mac": "aa:bb:cc:11:22:33", "key": RECOVERY_KEY}
            ), addr)
            await asyncio.wait_for(task, 2)
            assert device.device_key == RECOVERY_KEY
            await recovery_receive(queue, device.device_cipher)
            peer.sendto(recovery_packet(
                {"t": "dat", "cols": ["Pow"], "dat": [1]},
                device.device_cipher, {"cid": "AA-BB-CC-11-22-33"},
            ), addr)
            assert await asyncio.wait_for(events.get(), 2) == {"Pow": 1}
            peer.sendto(recovery_packet(
                {"t": "dat", "cols": ["Pow"], "dat": [0]},
                device.device_cipher, {"cid": "020000000002"},
            ), addr)
            peer.sendto(recovery_packet(
                {"t": "dat", "cols": ["Pow"], "dat": [1]},
                device.device_cipher, {"cid": "AA-BB-CC-11-22-33"},
            ), addr)
            assert await asyncio.wait_for(events.get(), 2) == {"Pow": 1}
            assert events.empty()
        finally:
            device.close()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("stage", ["before-bind", "after-failure"])
async def test_recovery_retired_device_cannot_reopen(stage):
    async with udp_peer() as (peer, queue):
        host, port = peer.get_extra_info("sockname")
        device = Device(DeviceInfo(host, port, RECOVERY_MAC, "retired"), bind_timeout=0.02)
        if stage == "after-failure":
            with pytest.raises(DeviceTimeoutError):
                await device.bind(cipher=CipherV1())
            await recovery_receive(queue)
        device.close()
        device.close()
        for operation in (device.bind, device.update_state, device.request_version, device.push_state_update):
            with pytest.raises(DeviceNotBoundError):
                await operation()
        assert queue.empty()


@pytest.mark.parametrize("reply_before_close", [False, True])
async def test_recovery_close_while_bind_send_is_paused(reply_before_close):
    async with udp_peer() as (peer, queue):
        host, port = peer.get_extra_info("sockname")
        device = Device(DeviceInfo(host, port, RECOVERY_MAC, "paused"), bind_timeout=0.1)
        await device._loop.create_datagram_endpoint(
            lambda: device, remote_addr=(host, port)
        )
        device.pause_writing()
        task = asyncio.create_task(device.bind(cipher=CipherV1()))
        callbacks = asyncio.Queue()
        device.add_handler(Response.BIND_OK, callbacks.put_nowait)
        try:
            _, addr = await recovery_receive(queue)
            packet = recovery_packet({"t": "bindok", "mac": RECOVERY_MAC, "key": RECOVERY_KEY})
            if reply_before_close:
                peer.sendto(packet, addr)
                assert await asyncio.wait_for(callbacks.get(), 2) == RECOVERY_KEY
            device.close()
            device.close()
            peer.sendto(packet, addr)
            with pytest.raises(DeviceNotBoundError):
                await asyncio.wait_for(task, 2)
            assert not device.ready.is_set() and device.device_cipher is None
            assert not device.has_valid_state
        finally:
            device.close()
            await asyncio.gather(task, return_exceptions=True)


async def test_recovery_endpoint_oserror_is_explicit_and_retryable(monkeypatch):
    loop = asyncio.get_running_loop()
    create_endpoint = loop.create_datagram_endpoint
    failure = OSError(24, "synthetic endpoint creation failure")

    async def failed_endpoint(*args, **kwargs):
        raise failure

    async with udp_peer() as (peer, queue):
        host, port = peer.get_extra_info("sockname")
        device = Device(DeviceInfo(host, port, RECOVERY_MAC, "oserror"), bind_timeout=0.1)
        try:
            monkeypatch.setattr(loop, "create_datagram_endpoint", failed_endpoint)
            with pytest.raises(OSError) as raised:
                await device.bind(cipher=CipherV1())
            assert raised.value is failure
            monkeypatch.setattr(loop, "create_datagram_endpoint", create_endpoint)
            await recovery_negotiate(device, peer, queue, CipherV1())
        finally:
            device.close()


async def test_recovery_lost_transport_fails_pending_bind_and_allows_retry():
    async with udp_peer() as (peer, queue):
        host, port = peer.get_extra_info("sockname")
        device = Device(DeviceInfo(host, port, RECOVERY_MAC, "lost"), bind_timeout=0.1)
        task = asyncio.create_task(device.bind(cipher=CipherV1()))
        try:
            await recovery_receive(queue)
            device._transport.close()
            with pytest.raises(DeviceNotBoundError):
                await asyncio.wait_for(task, 2)
            events = asyncio.Queue()
            device.add_handler(Response.DATA, events.put_nowait)
            addr = await recovery_negotiate(device, peer, queue, CipherV1())
            await recovery_receive(queue, device.device_cipher)
            peer.sendto(recovery_packet(
                {"t": "dat", "cols": ["Pow"], "dat": [1]}, device.device_cipher
            ), addr)
            assert await asyncio.wait_for(events.get(), 2) == {"Pow": 1}
        finally:
            device.close()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("boundary", ["closed", "wrong-peer", "missing-pack"])
async def test_recovery_rejected_packet_cannot_change_state(boundary):
    async with recovery_session() as (device, peer, queue, addr):
        await recovery_receive(queue, device.device_cipher)
        device.handle_state_update(Pow=1)
        events = asyncio.Queue()
        device.add_handler(Response.DATA, events.put_nowait)
        endpoint = peer.get_extra_info("sockname")
        packet = {"pack": {"t": "dat", "cols": ["Pow"], "dat": [0]}}
        if boundary == "closed":
            device.close()
        elif boundary == "wrong-peer":
            endpoint = (endpoint[0], 0)
        else:
            packet = {}
        device.packet_received(packet, endpoint)
        device.handle_device_bound("fedcba9876543210")
        assert device.power is True and events.empty()
        if boundary == "closed":
            assert not device.ready.is_set() and device.device_cipher is None
        else:
            assert device.device_key == RECOVERY_KEY
            peer.sendto(recovery_packet(
                {"t": "dat", "cols": ["Pow"], "dat": [0]}, device.device_cipher
            ), addr)
            assert await asyncio.wait_for(events.get(), 2) == {"Pow": 0}
            assert device.power is False


async def test_recovery_status_before_identified_bind_is_not_available():
    async with udp_peer() as (peer, queue):
        host, port = peer.get_extra_info("sockname")
        device = Device(DeviceInfo(host, port, RECOVERY_MAC, "premature"), bind_timeout=1)
        events = asyncio.Queue()
        device.add_handler(Response.DATA, events.put_nowait)
        task = asyncio.create_task(device.bind(cipher=CipherV1()))
        try:
            _, addr = await recovery_receive(queue)
            peer.sendto(recovery_packet({"t": "dat", "cols": ["Pow"], "dat": [0]}), addr)
            peer.sendto(recovery_packet({"t": "bindok", "mac": RECOVERY_MAC, "key": RECOVERY_KEY}), addr)
            await asyncio.wait_for(task, 2)
            assert events.empty() and not device.has_valid_state and device.power is None
            await recovery_receive(queue, device.device_cipher)
            peer.sendto(recovery_packet(
                {"t": "dat", "cols": ["Pow"], "dat": [1]}, device.device_cipher
            ), addr)
            assert await asyncio.wait_for(events.get(), 2) == {"Pow": 1}
            assert device.has_valid_state and device.power is True
        finally:
            device.close()
            await asyncio.gather(task, return_exceptions=True)


async def test_recovery_close_from_bind_callback_cannot_report_success():
    async with udp_peer() as (peer, queue):
        host, port = peer.get_extra_info("sockname")
        device = Device(DeviceInfo(host, port, RECOVERY_MAC, "callback-close"), bind_timeout=1)
        device.add_handler(Response.BIND_OK, lambda key: device.close())
        task = asyncio.create_task(device.bind(cipher=CipherV1()))
        try:
            _, addr = await recovery_receive(queue)
            peer.sendto(recovery_packet({"t": "bindok", "mac": RECOVERY_MAC, "key": RECOVERY_KEY}), addr)
            with pytest.raises(DeviceNotBoundError):
                await asyncio.wait_for(task, 2)
            assert not device.ready.is_set() and device.device_cipher is None
            assert queue.empty()
        finally:
            device.close()
            await asyncio.gather(task, *device.tasks, return_exceptions=True)


async def test_recovery_close_rejects_bind_queued_on_lock():
    device = Device(DeviceInfo("127.0.0.1", 7000, RECOVERY_MAC, "queued"))
    await device._bind_lock.acquire()
    task = asyncio.create_task(device.bind(cipher=CipherV1()))
    barrier = device._loop.create_future()
    device._loop.call_soon(barrier.set_result, None)
    try:
        await barrier
        assert not task.done()
        device.close()
        device._bind_lock.release()
        with pytest.raises(DeviceNotBoundError):
            await asyncio.wait_for(task, 2)
        assert device._transport is None and not device.ready.is_set()
    finally:
        if device._bind_lock.locked():
            device._bind_lock.release()
        device.close()
        await asyncio.gather(task, return_exceptions=True)


async def test_recovery_close_while_retry_waits_for_old_socket(monkeypatch):
    async with udp_peer() as (peer, queue):
        host, port = peer.get_extra_info("sockname")
        device = Device(DeviceInfo(host, port, RECOVERY_MAC, "closing"), bind_timeout=0.02)
        lost = asyncio.Queue()
        connection_lost = device.connection_lost
        monkeypatch.setattr(device, "connection_lost", lost.put_nowait)
        task = None
        try:
            with pytest.raises(DeviceTimeoutError):
                await device.bind(cipher=CipherV1())
            await recovery_receive(queue)
            exc = await asyncio.wait_for(lost.get(), 2)
            task = asyncio.create_task(device.bind(cipher=CipherV1()))
            barrier = device._loop.create_future()
            device._loop.call_soon(barrier.set_result, None)
            await barrier
            assert not task.done()
            device.close()
            connection_lost(exc)
            with pytest.raises(DeviceNotBoundError):
                await asyncio.wait_for(task, 2)
            assert queue.empty() and device.device_cipher is None
        finally:
            device.close()
            connection_lost(None)
            if task is not None:
                await asyncio.gather(task, return_exceptions=True)
