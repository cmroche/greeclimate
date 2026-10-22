import asyncio
from unittest.mock import patch

import pytest

from greeclimate.device import Props, Device, DeviceInfo
from greeclimate.cipher import CipherV1
from greeclimate.exceptions import DeviceTimeoutError
from greeclimate.network import DeviceProtocol2, Response
from tests.common import udp_peer
from tests.test_device import recovery_packet, recovery_receive, recovery_session
from tests.test_emulator import peer_packet


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


@pytest.mark.asyncio
@pytest.mark.parametrize("response,value_key", [
    (Response.DATA, "dat"),
    (Response.RESULT, "val"),
    (Response.RESULT, "p"),
])
@pytest.mark.parametrize("initial,target,expected", [
    ({"SetTem": 24, "TemRec": 0, "TemUn": 0}, 25,
     {"SetTem": 25, "TemRec": 0, "TemUn": 0}),
    ({"SetTem": 22, "TemRec": 1, "TemUn": 1}, 74,
     {"SetTem": 23, "TemRec": 1, "TemUn": 1}),
    ({"SetTem": 23, "TemRec": 0, "TemUn": 1}, 74,
     {"SetTem": 23, "TemRec": 1, "TemUn": 1}),
])
async def test_issue_146_late_report_preserves_temperature_tuple(
    response, value_key, initial, target, expected
):
    async with recovery_session() as (device, peer, queue, addr):
        await recovery_receive(queue, device.device_cipher)
        device.handle_state_update(**initial)
        device.target_temperature = target
        assert device.target_temperature == target
        events = asyncio.Queue()
        device.add_handler(response, events.put_nowait)
        reported = {
            "SetTem": 26,
            "TemRec": 1 - initial["TemRec"],
            "TemUn": 1 - initial["TemUn"],
        }
        peer.sendto(recovery_packet({
            "t": response.value,
            "cols" if response is Response.DATA else "opt": list(reported),
            value_key: list(reported.values()),
        }, device.device_cipher), addr)
        assert await asyncio.wait_for(events.get(), 2) == reported
        assert device.raw_properties == reported
        assert device.get_property(Props.TEMP_SET) == reported["SetTem"]
        assert device.temperature_units == reported["TemUn"]
        assert device.has_valid_state

        await device.push_state_update()
        command, _ = await recovery_receive(queue, device.device_cipher)
        assert dict(zip(command["opt"], command["p"])) == expected
        await device.push_state_update()
        assert queue.empty()


@pytest.mark.asyncio
@pytest.mark.parametrize("initial,target", [
    ({"SetTem": 24, "TemRec": 0, "TemUn": 0}, 24),
    ({"SetTem": 23, "TemRec": 0, "TemUn": 1}, 73),
])
async def test_issue_146_temperature_noop_and_standalone_units(initial, target):
    async with recovery_session() as (device, peer, queue, addr):
        await recovery_receive(queue, device.device_cipher)
        device.handle_state_update(**initial)
        device.temperature_units = initial["TemUn"]
        device.target_temperature = target
        await device.push_state_update()
        assert queue.empty()

        units = 1 - initial["TemUn"]
        device.temperature_units = units
        device.target_temperature = device.target_temperature
        await device.push_state_update()
        command, _ = await recovery_receive(queue, device.device_cipher)
        assert dict(zip(command["opt"], command["p"])) == {"TemUn": units}
        device.temperature_units = units
        device.target_temperature = device.target_temperature
        await device.push_state_update()
        assert queue.empty()


@pytest.mark.asyncio
@pytest.mark.parametrize("initial,first_target,newer_target,newer_units,expected", [
    ({"SetTem": 24, "TemRec": 0, "TemUn": 0}, 25, 26, None,
     {"SetTem": 26, "TemRec": 0, "TemUn": 0}),
    ({"SetTem": 22, "TemRec": 1, "TemUn": 1}, 73, 74, None,
     {"SetTem": 23, "TemRec": 1, "TemUn": 1}),
    ({"SetTem": 23, "TemRec": 0, "TemUn": 1}, 74, 75, None,
     {"SetTem": 24, "TemRec": 0, "TemUn": 1}),
    ({"SetTem": 24, "TemRec": 0, "TemUn": 0}, 25, None, 1,
     {"SetTem": 25, "TemRec": 0, "TemUn": 1}),
])
async def test_issue_146_newer_temperature_tuple_survives_awaiting_send(
    initial, first_target, newer_target, newer_units, expected
):
    async with recovery_session() as (device, peer, queue, addr):
        await recovery_receive(queue, device.device_cipher)
        device.handle_state_update(**initial)
        device.target_temperature = first_target
        first = {name: device.raw_properties[name] for name in initial}
        events = asyncio.Queue()
        device.add_handler(Response.DATA, events.put_nowait)
        device.pause_writing()
        task = asyncio.create_task(device.push_state_update())
        try:
            command, _ = await recovery_receive(queue, device.device_cipher)
            assert dict(zip(command["opt"], command["p"])) == first
            assert not task.done()
            reported = {"SetTem": 20, "TemRec": 1, "TemUn": initial["TemUn"]}
            peer.sendto(recovery_packet({
                "t": "dat", "cols": list(reported), "dat": list(reported.values()),
            }, device.device_cipher), addr)
            assert await asyncio.wait_for(events.get(), 2) == reported
            assert device.raw_properties == reported
            if newer_units is not None:
                device.temperature_units = newer_units
            if newer_target is not None:
                device.target_temperature = newer_target
            device.resume_writing()
            await asyncio.wait_for(task, 2)

            await device.push_state_update()
            command, _ = await recovery_receive(queue, device.device_cipher)
            assert dict(zip(command["opt"], command["p"])) == expected
            await device.push_state_update()
            assert queue.empty()
        finally:
            device.resume_writing()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("cancelled", [False, True])
async def test_issue_146_interrupted_temperature_send_retains_tuple(cancelled):
    async with recovery_session() as (device, peer, queue, addr):
        await recovery_receive(queue, device.device_cipher)
        device.handle_state_update(SetTem=23, TemRec=0, TemUn=1)
        device.target_temperature = 74
        expected = {"SetTem": 23, "TemRec": 1, "TemUn": 1}
        events = asyncio.Queue()
        device.add_handler(Response.RESULT, events.put_nowait)
        device.pause_writing()
        if not cancelled:
            device._timeout = 0
        task = asyncio.create_task(device.push_state_update())
        try:
            command, _ = await recovery_receive(queue, device.device_cipher)
            assert dict(zip(command["opt"], command["p"])) == expected
            if cancelled:
                assert not task.done()
                task.cancel()
            with pytest.raises(asyncio.CancelledError if cancelled else DeviceTimeoutError):
                await task
            reported = {"SetTem": 26, "TemRec": 0, "TemUn": 0}
            peer.sendto(recovery_packet({
                "t": "res", "opt": list(reported), "val": list(reported.values()),
            }, device.device_cipher), addr)
            assert await asyncio.wait_for(events.get(), 2) == reported
            device.resume_writing()
            device._timeout = 1

            await device.push_state_update()
            command, _ = await recovery_receive(queue, device.device_cipher)
            assert dict(zip(command["opt"], command["p"])) == expected
            await device.push_state_update()
            assert queue.empty()
        finally:
            device.resume_writing()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("reply", [{"t": "bindok"}, {"t": "vendor-response", "key": "ignored"}])
async def test_issue_214_invalid_bind_and_unknown_reply_preserve_receive_session(reply):
    loop = asyncio.get_running_loop()
    errors, bound = [], []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda loop, context: errors.append(context))
    protocol = DeviceProtocol2()
    key = b"0123456789abcdef"
    protocol.device_cipher = CipherV1(key)
    states, bindings = asyncio.Queue(), asyncio.Queue()
    protocol.add_handler(Response.DATA, states.put_nowait)
    protocol.add_handler(Response.BIND_OK, bound.append)
    protocol.add_handler(Response.BIND_OK, bindings.put_nowait)
    try:
        async with udp_peer() as (peer, _):
            await loop.create_datagram_endpoint(
                lambda: protocol, remote_addr=peer.get_extra_info("sockname")
            )
            endpoint = protocol._transport.get_extra_info("sockname")
            peer.sendto(peer_packet({}, reply, key), endpoint)
            peer.sendto(peer_packet({}, {"t": "dat", "cols": ["Pow"], "dat": [1]}, key), endpoint)
            assert await asyncio.wait_for(states.get(), 1) == {"Pow": 1}
            assert not protocol.ready.is_set()
            assert bound == []
            peer.sendto(peer_packet({}, {"t": "bindok", "key": "accepted"}, key), endpoint)
            assert await asyncio.wait_for(bindings.get(), 1) == "accepted"
            assert bound == ["accepted"]
            assert protocol.ready.is_set()
            assert states.empty()
            assert not errors
    finally:
        protocol.close()
        await asyncio.wait_for(protocol._transport_closed.wait(), 1)
        loop.set_exception_handler(previous_handler)
