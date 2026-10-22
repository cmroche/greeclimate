import asyncio
from unittest.mock import patch

import pytest

from greeclimate.device import Props, Device, DeviceInfo
from greeclimate.exceptions import DeviceTimeoutError
from greeclimate.network import Response
from tests.test_device import recovery_packet, recovery_receive, recovery_session


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


@pytest.mark.asyncio
@pytest.mark.parametrize("response,packet", [
    (Response.DATA, {"t": "dat", "cols": ["Pow"], "dat": [1]}),
    (Response.RESULT, {"t": "res", "opt": ["Pow"], "val": [1]}),
    (Response.RESULT, {"t": "res", "opt": ["Pow"], "p": [1]}),
])
async def test_issue_146_late_report_does_not_replace_pending_command(response, packet):
    async with recovery_session() as (device, peer, queue, addr):
        await recovery_receive(queue, device.device_cipher)
        device.handle_state_update(Pow=1)
        device.power = False
        assert device.power is False and device.raw_properties["Pow"] == 0
        events = asyncio.Queue()
        device.add_handler(response, events.put_nowait)

        peer.sendto(recovery_packet(packet, device.device_cipher), addr)
        assert await asyncio.wait_for(events.get(), 2) == {"Pow": 1}
        assert device.power is True and device.raw_properties["Pow"] == 1
        assert device.has_valid_state

        await device.push_state_update()
        command, _ = await recovery_receive(queue, device.device_cipher)
        assert command["t"] == "cmd"
        assert dict(zip(command["opt"], command["p"])) == {"Pow": 0}
        await device.push_state_update()
        assert queue.empty()


@pytest.mark.asyncio
@pytest.mark.parametrize("newer", [{"Pow": 1}, {"Mod": 4}, {"Pow": 1, "Mod": 4}])
async def test_issue_146_changes_during_send_reach_next_command(newer):
    async with recovery_session() as (device, peer, queue, addr):
        await recovery_receive(queue, device.device_cipher)
        device.handle_state_update(Pow=1, Mod=0)
        device.power = False
        device.pause_writing()
        task = asyncio.create_task(device.push_state_update())
        try:
            command, _ = await recovery_receive(queue, device.device_cipher)
            assert command["t"] == "cmd"
            assert dict(zip(command["opt"], command["p"])) == {"Pow": 0}
            assert not task.done()
            if "Pow" in newer:
                device.power = True
            if "Mod" in newer:
                device.mode = 4
            device.resume_writing()
            await asyncio.wait_for(task, 2)

            await device.push_state_update()
            command, _ = await recovery_receive(queue, device.device_cipher)
            assert command["t"] == "cmd"
            assert dict(zip(command["opt"], command["p"])) == newer
            await device.push_state_update()
            assert queue.empty()
        finally:
            device.resume_writing()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("cancelled", [False, True])
async def test_issue_146_interrupted_send_retains_intent(cancelled):
    async with recovery_session() as (device, peer, queue, addr):
        await recovery_receive(queue, device.device_cipher)
        device.handle_state_update(Pow=1)
        device.power = False
        device.pause_writing()
        if not cancelled:
            device._timeout = 0
        task = asyncio.create_task(device.push_state_update())
        try:
            command, _ = await recovery_receive(queue, device.device_cipher)
            assert dict(zip(command["opt"], command["p"])) == {"Pow": 0}
            if cancelled:
                assert not task.done()
                task.cancel()
            with pytest.raises(asyncio.CancelledError if cancelled else DeviceTimeoutError):
                await task
            device.handle_state_update(Pow=1)
            device.resume_writing()
            device._timeout = 1

            await device.push_state_update()
            command, _ = await recovery_receive(queue, device.device_cipher)
            assert command["t"] == "cmd"
            assert dict(zip(command["opt"], command["p"])) == {"Pow": 0}
            await device.push_state_update()
            assert queue.empty()
        finally:
            device.resume_writing()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
