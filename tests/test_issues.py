from unittest.mock import patch

import pytest

from greeclimate.device import Props, Device, DeviceInfo


@pytest.mark.asyncio
async def test_issue_69_encoded_40_is_zero_celsius():
    device = Device(DeviceInfo("127.0.0.1", 7000, "000000000001", "issue69"))
    device.handle_state_update(TemSen=40, TemUn=0, TemRec=0)
    assert device.current_temperature == 0
    device.handle_state_update(TemSen=41)
    assert device.current_temperature == 1
    assert device.raw_properties["TemSen"] == 41


@pytest.mark.asyncio
@pytest.mark.parametrize("delayed_hid", [False, True])
@pytest.mark.parametrize("initial_zero", [False, True])
async def test_delayed_w04nv7_hid_preserves_temperature(delayed_hid, initial_zero):
    device = Device(DeviceInfo("127.0.0.1", 7000, "000000000001", "delayed-hid"))
    hid = "362001061217+U-W04NV7.bin"
    state = {"TemSen": 28, "TemUn": 0, "TemRec": 0}
    if not delayed_hid:
        state["hid"] = hid
    if initial_zero:
        device.handle_state_update(**dict(state, TemSen=0))
        assert device.current_temperature is None
    device.handle_state_update(**state)
    assert device.current_temperature == 28
    if delayed_hid:
        device.handle_state_update(hid=hid)
    assert device.current_temperature == 28
    assert device.version == "7"
    assert device.hid == hid
    assert device.raw_properties["TemSen"] == 28

"""Tests for issue 72"""

@pytest.mark.asyncio
async def test_issue_87_quiet_should_set_2():
    """Check that quiet mode uses 2 instead of 1"""
    from tests.test_device import generate_device_mock_async

    mock_v3_state = { "Quiet": 2 }
    device = await generate_device_mock_async()

    assert device.get_property(Props.QUIET) is None
    device.quiet = True

    def fake_send(*args, **kwargs):
        device.handle_state_update(**mock_v3_state)

    with patch.object(Device, "send", wraps=fake_send()) as mock:
        await device.push_state_update()
        mock.assert_called_once()

    assert device.get_property(Props.QUIET) == 2
