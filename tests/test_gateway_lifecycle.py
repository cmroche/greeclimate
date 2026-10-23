"""Encrypted public-client regressions for gateway session ownership."""

import asyncio
from unittest.mock import patch

import pytest

from greeclimate.cipher import CipherV1
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.exceptions import DeviceNotBoundError, DeviceTimeoutError
from greeclimate.gateway import GatewayDevice
from greeclimate.network import Response

from .common import udp_peer
from .test_emulator import peer_packet, peer_reply
from .test_gateway import COMMERCIAL_HID, HID, KEY, ROOT, gateway_peer, records


pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
async def lifecycle_loop_errors():
    loop = asyncio.get_running_loop()
    before = set(asyncio.all_tasks())
    previous = loop.get_exception_handler()
    errors = []
    loop.set_exception_handler(lambda _, context: errors.append(context))
    try:
        yield
        for _ in range(2):
            barrier = loop.create_future()
            loop.call_soon(barrier.set_result, None)
            await barrier
        assert not errors
        assert not {
            task for task in asyncio.all_tasks() - before
            if task is not asyncio.current_task() and not task.done()
        }
    finally:
        loop.set_exception_handler(previous)


async def _started(operation):
    entered = asyncio.Event()

    async def run():
        entered.set()
        return await operation()

    task = asyncio.create_task(run())
    await asyncio.wait_for(entered.wait(), 2)
    return task


async def _reported(peer, device, **properties):
    updates = asyncio.Queue()
    callback = updates.put_nowait
    device.add_handler(Response.DATA, callback)
    try:
        peer.reply({
            "t": "dat", "mac": device.device_info.mac,
            "cols": list(properties), "dat": list(properties.values()),
        })
        assert await asyncio.wait_for(updates.get(), 2) == properties
    finally:
        device.remove_handler(Response.DATA, callback)


async def test_gateway_children_borrow_one_endpoint_and_never_bind_independently():
    async with gateway_peer(bind=False) as (gateway, peer):
        loop = asyncio.get_running_loop()
        with patch.object(loop, "create_datagram_endpoint", wraps=loop.create_datagram_endpoint) as endpoints:
            await peer.bind()
            await peer.enumerate(records(2))
            first, second = gateway.children
            assert first.gateway is gateway and second.gateway is gateway
            assert first.ready.is_set() and second.ready.is_set()
            assert not first.has_valid_state and not second.has_valid_state
            await asyncio.gather(first.bind(), second.bind(), first.request_version())
            request = await peer.receive()
            assert request["inner"]["t"] == "status"
            assert request["inner"]["mac"] == first.device_info.mac
            assert request["outer"]["tcid"] == ROOT
            assert endpoints.call_count == 1
            assert gateway.device_key == first.device_key == second.device_key
        assert peer.queue.empty()
        for kwargs in ({"key": "0123456789abcdef"}, {"cipher": CipherV1()}):
            with pytest.raises(ValueError):
                await first.bind(**kwargs)
        assert peer.queue.empty()


async def test_gateway_child_close_preserves_sibling_state_session_and_recreates_handle():
    async with gateway_peer() as (gateway, peer):
        inventory = records(2)
        await peer.enumerate(inventory)
        first, second = gateway.children
        await _reported(peer, first, Pow=1, SetTem=24)
        await _reported(peer, second, Pow=0, SetTem=22)
        snapshot = dict(first.raw_properties)
        key = gateway.device_key
        late_updates = asyncio.Queue()
        first.add_handler(Response.DATA, late_updates.put_nowait)
        first.close()
        first.close()
        assert gateway.children == (second,)
        assert not first.ready.is_set() and not first.has_valid_state
        assert first.raw_properties == snapshot
        assert gateway.ready.is_set() and second.ready.is_set() and second.has_valid_state
        assert gateway.device_key == key
        peer.reply({"t": "dat", "mac": first.device_info.mac, "cols": ["Pow"], "dat": [0]})
        await _reported(peer, second, Pow=0, SetTem=22)
        assert late_updates.empty() and first.raw_properties == snapshot
        for operation in (first.bind, first.request_version, first.update_state, first.push_state_update):
            with pytest.raises(DeviceNotBoundError):
                await operation()
        await second.update_state(["Pow"])
        request = await peer.receive()
        assert request["inner"]["mac"] == second.device_info.mac
        await peer.enumerate(inventory)
        replacement = next(child for child in gateway.children if child.device_info.mac == first.device_info.mac)
        assert replacement is not first and replacement.gateway is gateway
        assert replacement.ready.is_set() and not replacement.has_valid_state
        assert second in gateway.children and second.get_property("SetTem") == 22
        assert first.tasks == []


async def test_gateway_mid_change_replaces_handle_instead_of_mutating_lifetime_profile():
    async with gateway_peer() as (gateway, peer):
        inventory = records(1)
        await peer.enumerate(inventory)
        old = gateway.children[0]
        await _reported(peer, old, Pow=1, SetTem=24)
        refreshed = [{**inventory[0], "name": "renamed"}]
        await peer.enumerate(refreshed)
        assert gateway.children[0] is old
        assert old.device_info.name == "renamed" and old.has_valid_state
        old_mid = old.device_info.mid
        await peer.enumerate([{**inventory[0], "mid": "unknown-replacement"}])
        replacement = gateway.children[0]
        assert replacement is not old
        assert replacement.device_info.mid == "unknown-replacement"
        assert old.device_info.mid == old_mid
        assert not old.ready.is_set() and not old.has_valid_state
        assert old.get_property("SetTem") == 24
        assert replacement.ready.is_set() and not replacement.has_valid_state
        with pytest.raises(DeviceNotBoundError):
            await old.update_state(["Pow"])
        await replacement.update_state(["Pow"])
        request = await peer.receive()
        assert request["inner"]["mac"] == replacement.device_info.mac


@pytest.mark.parametrize("closed_owner", ["root", "child"])
async def test_gateway_close_during_child_send_wakes_owner_without_cancelling_sibling(closed_owner):
    async with gateway_peer() as (gateway, peer):
        await peer.enumerate(records(2))
        first, second = gateway.children
        await _reported(peer, first, Pow=1)
        await _reported(peer, second, Pow=0)
        first.set_property("Pow", 0)
        second.set_property("Pow", 1)
        gateway.pause_writing()
        first_send = asyncio.create_task(first.push_state_update())
        second_send = asyncio.create_task(second.push_state_update())
        try:
            requests = [await peer.receive(), await peer.receive()]
            assert {request["inner"]["sub"] for request in requests} == {
                first.device_info.mac, second.device_info.mac,
            }
            (gateway if closed_owner == "root" else first).close()
            with pytest.raises(DeviceNotBoundError):
                await asyncio.wait_for(first_send, 2)
            if closed_owner == "child":
                assert not second_send.done()
                assert gateway.ready.is_set() and second.ready.is_set()
                gateway.resume_writing()
                await asyncio.wait_for(second_send, 2)
                assert second.has_valid_state and second.get_property("Pow") == 0
                await second.push_state_update()
                assert peer.queue.empty()
            else:
                with pytest.raises(DeviceNotBoundError):
                    await asyncio.wait_for(second_send, 2)
                assert not first.ready.is_set() and not second.ready.is_set()
                assert not first.has_valid_state and not second.has_valid_state
                assert first.get_property("Pow") == 1 and second.get_property("Pow") == 0
        finally:
            gateway.resume_writing()
            gateway.close()
            await asyncio.gather(first_send, second_send, return_exceptions=True)


async def test_gateway_caller_cancelled_send_does_not_cancel_sibling_send():
    async with gateway_peer() as (gateway, peer):
        await peer.enumerate(records(2))
        first, second = gateway.children
        first.set_property("Pow", 0)
        second.set_property("Pow", 1)
        gateway.pause_writing()
        first_send = asyncio.create_task(first.push_state_update())
        second_send = asyncio.create_task(second.push_state_update())
        try:
            await peer.receive()
            await peer.receive()
            first_send.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first_send
            assert not second_send.done()
            gateway.resume_writing()
            await asyncio.wait_for(second_send, 2)
            await first.push_state_update()
            request = await peer.receive()
            assert request["inner"]["sub"] == first.device_info.mac
            assert dict(zip(request["inner"]["opt"], request["inner"]["p"])) == {"Pow": 0}
            assert gateway.ready.is_set() and second.ready.is_set()
        finally:
            gateway.resume_writing()
            await asyncio.gather(first_send, second_send, return_exceptions=True)


async def _metadata_pending(gateway, peer):
    task = asyncio.create_task(gateway.get_sub_devices())
    request = await peer.receive(generic=True)
    assert request["inner"] == {"t": "bind", "mac": ROOT, "uid": 0}
    peer.reply({"t": "bindok", "mac": ROOT, "key": KEY}, generic=True)
    request = await peer.receive()
    assert request["inner"] == {"t": "status", "mac": ROOT, "cols": ["hid"]}
    return task


@pytest.mark.parametrize("phase", ["metadata", "page"])
async def test_gateway_shared_inventory_survives_one_callers_cancellation(phase):
    async with gateway_peer(bind=False) as (gateway, peer):
        first = await _metadata_pending(gateway, peer)
        second = await _started(gateway.get_sub_devices)
        try:
            if phase == "page":
                await _reported(peer, gateway, hid=HID)
                request = await peer.receive()
                assert request["inner"]["i"] == 0
            first.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first
            assert not second.done() and gateway.ready.is_set()
            if phase == "metadata":
                await _reported(peer, gateway, hid=HID)
                request = await peer.receive()
                assert request["inner"]["i"] == 0
            peer.reply({"t": "sublist", "mac": ROOT, "r": 200, "c": 7, "i": 0,
                        "list": records(5)})
            await peer.page(records(7)[5:], 7)
            children = await asyncio.wait_for(second, 2)
            assert len(children) == 7 and len({id(child) for child in children}) == 7
            assert gateway.children == tuple(children)
            assert len(peer.sources) == 1 and peer.queue.empty()
        finally:
            gateway.close()
            await asyncio.gather(first, second, return_exceptions=True)


@pytest.mark.parametrize("phase", ["bind", "metadata", "page"])
async def test_gateway_root_close_fails_waiters_and_ignores_late_native_replies(phase):
    async with gateway_peer(bind=False) as (gateway, peer):
        if phase == "bind":
            pending = asyncio.create_task(gateway.get_sub_devices())
            await peer.receive(generic=True)
        else:
            pending = await _metadata_pending(gateway, peer)
            if phase == "page":
                await _reported(peer, gateway, hid=HID)
                await peer.page(records(5), 7)
                request = await peer.receive()
                assert request["inner"]["i"] == 5
        retained = gateway.children
        snapshot = tuple(dict(child.raw_properties) for child in retained)
        root_events = asyncio.Queue()
        gateway.add_handler(Response.DATA, root_events.put_nowait)
        gateway.close()
        gateway.close()
        with pytest.raises(DeviceNotBoundError):
            await asyncio.wait_for(pending, 2)
        if phase == "bind":
            peer.reply({"t": "bindok", "mac": ROOT, "key": KEY}, generic=True)
        else:
            peer.reply({"t": "dat", "mac": ROOT, "cols": ["hid"], "dat": [HID]})
            peer.reply({"t": "sublist", "mac": ROOT, "r": 200, "c": 7, "i": 5,
                        "list": records(7)[5:]})
        await asyncio.wait_for(gateway._transport_closed.wait(), 2)
        assert not gateway.ready.is_set() and not gateway.has_valid_state
        assert gateway.children == () and root_events.empty()
        assert all(not child.ready.is_set() and not child.has_valid_state for child in retained)
        assert tuple(dict(child.raw_properties) for child in retained) == snapshot
        for operation in (gateway.bind, gateway.get_sub_devices, gateway.request_version):
            with pytest.raises(DeviceNotBoundError):
                await operation()
        await asyncio.gather(*gateway.tasks, *(task for child in retained for task in child.tasks),
                             return_exceptions=True)
        assert gateway.tasks == [] and all(child.tasks == [] for child in retained)
        assert peer.queue.empty()


@pytest.mark.parametrize("phase", ["bind", "metadata", "page"])
@pytest.mark.parametrize("closed_owner", ["root", "child"])
@pytest.mark.parametrize("operation", ["bind", "request_version", "update_state", "push_state_update"])
async def test_gateway_close_during_child_rejoin_preserves_ownership(phase, closed_owner, operation):
    async with gateway_peer() as (gateway, peer):
        await peer.enumerate(records(2))
        first, second = gateway.children
        await _reported(peer, first, Pow=1)
        first.set_property("Pow", 0)
        transport = gateway._transport
        transport.close()
        await asyncio.wait_for(gateway._transport_closed.wait(), 2)
        if phase == "bind":
            parent_inventory = asyncio.create_task(gateway.get_sub_devices())
            await peer.receive(generic=True)
        else:
            parent_inventory = await _metadata_pending(gateway, peer)
        join = await _started(getattr(first, operation))
        try:
            if phase == "page":
                await _reported(peer, gateway, hid=HID)
                await peer.receive()
            (gateway if closed_owner == "root" else first).close()
            with pytest.raises(DeviceNotBoundError):
                await asyncio.wait_for(join, 2)
            if closed_owner == "root":
                with pytest.raises(DeviceNotBoundError):
                    await asyncio.wait_for(parent_inventory, 2)
                assert not second.ready.is_set() and not second.has_valid_state
                assert first.get_property("Pow") == 1
                return
            assert not parent_inventory.done()
            assert gateway.ready.is_set() == (phase != "bind")
            if phase == "bind":
                peer.reply({"t": "bindok", "mac": ROOT, "key": KEY}, generic=True)
                request = await peer.receive()
                assert request["inner"] == {"t": "status", "mac": ROOT, "cols": ["hid"]}
            if phase in {"bind", "metadata"}:
                await _reported(peer, gateway, hid=HID)
                await peer.receive()
            peer.reply({"t": "sublist", "mac": ROOT, "r": 200, "c": 1, "i": 0,
                        "list": records(2)[1:]})
            children = await asyncio.wait_for(parent_inventory, 2)
            assert len(children) == 1 and children[0] is second
            assert gateway.children == (second,) and second.ready.is_set()
            assert not first.ready.is_set() and first.get_property("Pow") == 1
            await second.update_state(["Pow"])
            request = await peer.receive()
            assert request["inner"]["mac"] == second.device_info.mac
            assert first.tasks == []
        finally:
            gateway.close()
            await asyncio.gather(parent_inventory, join, return_exceptions=True)


async def test_gateway_transport_loss_requires_fresh_bind_and_observed_child_membership():
    async with gateway_peer() as (gateway, peer):
        inventory = records(2)
        await peer.enumerate(inventory)
        first, second = gateway.children
        await _reported(peer, first, Pow=1, SetTem=24)
        await _reported(peer, second, Pow=0, SetTem=22)
        old_transport = gateway._transport
        old_uid = peer.outer["uid"]
        snapshots = [dict(child.raw_properties) for child in (first, second)]
        gateway._transport.close()
        await asyncio.wait_for(gateway._transport_closed.wait(), 2)
        assert not gateway.ready.is_set() and not gateway.has_valid_state
        assert gateway.children == (first, second)
        assert all(not child.ready.is_set() and not child.has_valid_state for child in (first, second))
        assert [dict(child.raw_properties) for child in (first, second)] == snapshots

        pending = asyncio.create_task(first.update_state(["Pow"]))
        try:
            request = await peer.receive(generic=True)
            assert request["inner"] == {"t": "bind", "mac": ROOT, "uid": 0}
            assert gateway._transport is not old_transport
            peer.reply({"t": "bindok", "mac": ROOT, "key": KEY}, generic=True)
            request = await peer.receive()
            assert request["inner"] == {"t": "status", "mac": ROOT, "cols": ["hid"]}
            await _reported(peer, gateway, hid=HID)
            request = await peer.receive()
            assert request["inner"]["t"] == "subDev" and request["outer"]["uid"] > old_uid
            peer.reply({"t": "sublist", "mac": ROOT, "r": 200, "c": 2, "i": 0,
                        "list": inventory}, outer={"uid": old_uid})
            peer.reply({"t": "sublist", "mac": ROOT, "r": 200, "c": 1, "i": 0,
                        "list": inventory[1:]})
            with pytest.raises(DeviceNotBoundError):
                await asyncio.wait_for(pending, 2)
            assert peer.queue.empty()
            assert gateway.ready.is_set() and second.ready.is_set()
            assert not first.ready.is_set() and not first.has_valid_state
            assert first.get_property("SetTem") == 24
            assert not second.has_valid_state and second.get_property("SetTem") == 22
            assert gateway.children == (first, second)
            peer.reply({"t": "dat", "mac": first.device_info.mac, "cols": ["Pow"], "dat": [99]})
            await _reported(peer, second, Pow=0, SetTem=22)
            assert first.get_property("Pow") == 1 and not first.has_valid_state

            first.set_property("Pow", 0)
            send = asyncio.create_task(first.push_state_update())
            try:
                await peer.page(inventory[1:])
                with pytest.raises(DeviceNotBoundError):
                    await asyncio.wait_for(send, 2)
                assert peer.queue.empty()
            finally:
                if not send.done():
                    send.cancel()
                await asyncio.gather(send, return_exceptions=True)
            returned = await peer.enumerate(inventory)
            assert returned[0] is first and returned[1] is second
            assert first.ready.is_set() and not first.has_valid_state
            await first.push_state_update()
            request = await peer.receive()
            assert request["inner"]["sub"] == first.device_info.mac
            assert dict(zip(request["inner"]["opt"], request["inner"]["p"])) == {"Pow": 0}
            assert len(peer.sources) <= 2
        finally:
            gateway.close()
            await asyncio.gather(pending, return_exceptions=True)


@pytest.mark.parametrize("changed_hid", [
    "362001066380+U-WB05BRV1.38.bin", "unknown+U-NOT-QUALIFIED.bin", "", None, 123,
])
async def test_gateway_every_reported_hid_change_invalidates_old_child_context(changed_hid):
    async with gateway_peer() as (gateway, peer):
        inventory = records(2)
        await peer.enumerate(inventory)
        first, second = gateway.children
        await _reported(peer, first, Pow=1, SetTem=24)
        await _reported(peer, second, Pow=0)
        snapshots = [dict(child.raw_properties) for child in (first, second)]
        await _reported(peer, gateway, hid=changed_hid)
        assert not first.ready.is_set() and not second.ready.is_set()
        assert not first.has_valid_state and not second.has_valid_state
        assert [dict(child.raw_properties) for child in (first, second)] == snapshots
        assert gateway.children == (first, second)
        if changed_hid != "362001066380+U-WB05BRV1.38.bin":
            with pytest.raises(ValueError):
                await gateway.get_sub_devices()
            with pytest.raises(ValueError):
                await first.bind()
            assert peer.queue.empty()
        else:
            returned = await peer.enumerate(inventory[:1])
            assert returned[0] is first and returned[1] is second
            assert first.ready.is_set() and not first.has_valid_state
            assert not second.ready.is_set()

        await _reported(peer, gateway, hid=HID)
        assert not first.ready.is_set() and not second.ready.is_set()
        returned = await peer.enumerate(inventory)
        assert returned[0] is first and returned[1] is second
        assert all(child.ready.is_set() and not child.has_valid_state for child in returned)
        await second.update_state(["Pow"])
        request = await peer.receive()
        assert request["inner"]["mac"] == second.device_info.mac


async def test_gateway_hid_change_during_send_fails_old_owner_and_keeps_intent():
    async with gateway_peer() as (gateway, peer):
        inventory = records(1)
        await peer.enumerate(inventory)
        child = gateway.children[0]
        await _reported(peer, child, Pow=1)
        child.set_property("Pow", 0)
        gateway.pause_writing()
        pending = asyncio.create_task(child.push_state_update())
        try:
            await peer.receive()
            await _reported(peer, gateway, hid="unknown")
            with pytest.raises(DeviceNotBoundError):
                await asyncio.wait_for(pending, 2)
            assert not child.ready.is_set() and not child.has_valid_state
            assert child.get_property("Pow") == 1
            gateway.resume_writing()
            await _reported(peer, gateway, hid=HID)
            await peer.enumerate(inventory)
            await child.push_state_update()
            request = await peer.receive()
            assert request["inner"]["sub"] == child.device_info.mac
            assert dict(zip(request["inner"]["opt"], request["inner"]["p"])) == {"Pow": 0}
        finally:
            gateway.resume_writing()
            await asyncio.gather(pending, return_exceptions=True)


@pytest.mark.parametrize("replacement", [
    {"mac": ROOT + "01", "mid": "Filter"},
    {"mac": ROOT + "00", "mid": "6200"},
])
async def test_gateway_commercial_role_replacement_retires_old_shared_cache_route(replacement):
    async with gateway_peer(hid=COMMERCIAL_HID) as (gateway, peer):
        original = {"mac": ROOT + "00", "mid": "6400"}
        await peer.enumerate([original])
        child = gateway.children[0]
        await _reported(peer, child, Pow=1, SetTem=24)
        child.set_property("Pow", 0)
        await peer.enumerate([replacement])
        current = next(handle for handle in gateway.children if handle is not child)
        assert current.device_info.mac == replacement["mac"]
        assert current.device_info.mid == replacement["mid"]
        assert not current.ready.is_set() and not current.has_valid_state
        assert not child.ready.is_set() and not child.has_valid_state
        assert child.get_property("SetTem") == 24
        for operation in (current.bind, current.request_version, current.update_state,
                          current.push_state_update):
            with pytest.raises(ValueError):
                await operation()
        for operation in (child.bind, child.request_version, child.update_state, child.push_state_update):
            if replacement["mac"] == original["mac"]:
                with pytest.raises(DeviceNotBoundError):
                    await operation()
            else:
                with pytest.raises(ValueError):
                    await operation()
        if replacement["mac"] != original["mac"]:
            with pytest.raises(ValueError):
                child.set_property("Pow", 0)
        assert peer.queue.empty()
        with pytest.raises(ValueError):
            current.set_property("Pow", 0)
        child.close()
        await peer.enumerate([original])
        restored = next(handle for handle in gateway.children
                        if handle.device_info.mac == original["mac"] and handle.device_info.mid == "6400")
        assert restored is not child and restored.ready.is_set() and not restored.has_valid_state
        restored.set_property("Pow", 0)
        await restored.push_state_update()
        request = await peer.receive()
        assert request["inner"]["sub"] == original["mac"]
        assert "mac" not in request["inner"]


@pytest.mark.parametrize("report_before_retry", [False, True])
async def test_gateway_hid_timeout_retires_waiter_and_next_enumeration_can_qualify(report_before_retry):
    async with gateway_peer(bind=False) as (gateway, peer):
        await peer.bind(report=False)
        with pytest.raises(DeviceTimeoutError):
            await gateway.get_sub_devices()
        assert gateway.ready.is_set() and gateway.children == ()
        assert peer.queue.empty()
        if report_before_retry:
            await _reported(peer, gateway, hid=HID)
        retry = asyncio.create_task(gateway.get_sub_devices())
        try:
            if not report_before_retry:
                request = await peer.receive()
                assert request["inner"] == {"t": "status", "mac": ROOT, "cols": ["hid"]}
                await _reported(peer, gateway, hid=HID)
            await peer.page(records(1))
            children = await asyncio.wait_for(retry, 2)
            assert len(children) == 1 and children[0].ready.is_set()
            assert not children[0].has_valid_state and peer.queue.empty()
        finally:
            gateway.close()
            await asyncio.gather(retry, return_exceptions=True)


async def test_gateway_legacy_configured_key_is_not_a_bound_session():
    async with gateway_peer(bind=False) as (gateway, peer):
        await gateway.bind(key=KEY, cipher=CipherV1())
        assert not gateway.ready.is_set() and peer.queue.empty()
        pending = await _metadata_pending(gateway, peer)
        try:
            await _reported(peer, gateway, hid=HID)
            await peer.page(records(1))
            children = await asyncio.wait_for(pending, 2)
            assert len(children) == 1 and children[0].ready.is_set()
            assert len(peer.sources) == 1 and gateway.device_key == KEY
        finally:
            gateway.close()
            await asyncio.gather(pending, return_exceptions=True)


@pytest.mark.parametrize("phase", ["metadata", "page"])
async def test_gateway_unexpected_loss_fails_active_inventory_waits(phase):
    async with gateway_peer(bind=False) as (gateway, peer):
        pending = await _metadata_pending(gateway, peer)
        if phase == "page":
            await _reported(peer, gateway, hid=HID)
            await peer.page(records(5), 7)
            request = await peer.receive()
            assert request["inner"]["i"] == 5
        retained = gateway.children
        gateway._transport.close()
        await asyncio.wait_for(gateway._transport_closed.wait(), 2)
        with pytest.raises(DeviceNotBoundError):
            await asyncio.wait_for(pending, 2)
        assert not gateway.ready.is_set() and not gateway.has_valid_state
        assert gateway.children == retained
        assert all(not child.ready.is_set() and not child.has_valid_state for child in retained)
        assert peer.queue.empty()


async def test_gateway_hid_context_change_fails_page_and_old_uid_cannot_complete_new_inventory():
    async with gateway_peer() as (gateway, peer):
        await peer.enumerate(records(1))
        child = gateway.children[0]
        await _reported(peer, child, Pow=1)
        pending = asyncio.create_task(gateway.get_sub_devices())
        request = await peer.receive()
        old_uid = request["outer"]["uid"]
        await _reported(peer, gateway, hid="362001066380+U-WB05BRV1.38.bin")
        with pytest.raises(DeviceNotBoundError):
            await asyncio.wait_for(pending, 2)
        assert not child.ready.is_set() and not child.has_valid_state
        assert child.get_property("Pow") == 1
        retry = asyncio.create_task(gateway.get_sub_devices())
        try:
            request = await peer.receive()
            assert request["outer"]["uid"] != old_uid
            peer.reply({"t": "sublist", "mac": ROOT, "r": 200, "c": 1, "i": 0,
                        "list": [{"mac": records(2)[1]["mac"], "mid": "604a"}]},
                       outer={"uid": old_uid})
            peer.reply({"t": "sublist", "mac": ROOT, "r": 200, "c": 1, "i": 0,
                        "list": records(1)})
            children = await asyncio.wait_for(retry, 2)
            assert len(children) == 1 and children[0] is child
            assert child.ready.is_set() and not child.has_valid_state
            assert gateway.children == (child,)
        finally:
            gateway.close()
            await asyncio.gather(retry, return_exceptions=True)


@pytest.mark.parametrize("replacement_mac", [ROOT, "020000000002"])
async def test_gateway_endpoint_and_root_identity_replacement_are_caller_owned(replacement_mac):
    async with gateway_peer() as (old, old_peer), udp_peer() as (transport, queue):
        await old_peer.enumerate(records(1))
        old_child = old.children[0]
        await _reported(old_peer, old_child, Pow=1)
        host, port = transport.get_extra_info("sockname")
        replacement = GatewayDevice(
            DeviceInfo(host, port, replacement_mac, "moved", mid="60"), bind_timeout=1,
        )
        assert not replacement.ready.is_set() and replacement.children == ()
        assert queue.empty()
        await old_child.update_state(["Pow"])
        request = await old_peer.receive()
        assert request["inner"]["mac"] == old_child.device_info.mac and queue.empty()
        old.close()
        await asyncio.wait_for(old._transport_closed.wait(), 2)
        assert not old_child.ready.is_set() and not old_child.has_valid_state
        assert old_child.get_property("Pow") == 1
        pending = asyncio.create_task(replacement.get_sub_devices())
        outer = {"t": "pack", "cid": replacement_mac, "tcid": "app", "i": 0}
        try:
            data, source = await asyncio.wait_for(queue.get(), 2)
            request = peer_reply(data, b"a3K8Bx%2r8Y7#xDh")
            assert request["inner"] == {"t": "bind", "mac": replacement_mac, "uid": 0}
            transport.sendto(peer_packet(
                outer, {"t": "bindok", "mac": replacement_mac, "key": KEY},
            ), source)
            data, status_source = await asyncio.wait_for(queue.get(), 2)
            request = peer_reply(data, KEY.encode())
            assert status_source == source
            assert request["inner"] == {"t": "status", "mac": replacement_mac, "cols": ["hid"]}
            transport.sendto(peer_packet(
                outer, {"t": "dat", "mac": replacement_mac, "cols": ["hid"], "dat": [HID]},
                KEY.encode(),
            ), source)
            data, inventory_source = await asyncio.wait_for(queue.get(), 2)
            request = peer_reply(data, KEY.encode())
            assert inventory_source == source and request["outer"]["tcid"] == replacement_mac
            transport.sendto(peer_packet(
                {**outer, "uid": request["outer"]["uid"]},
                {"t": "sublist", "mac": replacement_mac, "r": 200, "c": 1, "i": 0,
                 "list": records(1)}, KEY.encode(),
            ), source)
            children = await asyncio.wait_for(pending, 2)
            assert len(children) == 1 and children[0] is not old_child
            assert children[0].gateway is replacement
            assert children[0].device_info.port == port and children[0].ready.is_set()
            assert not children[0].has_valid_state and old_peer.queue.empty()
            with pytest.raises(DeviceNotBoundError):
                await old_child.bind()
        finally:
            replacement.close()
            await asyncio.gather(pending, *replacement.tasks, return_exceptions=True)
            await asyncio.wait_for(replacement._transport_closed.wait(), 2)


async def test_gateway_child_caller_cancellation_during_bind_join_keeps_parent_and_sibling_alive():
    async with gateway_peer() as (gateway, peer):
        inventory = records(2)
        await peer.enumerate(inventory)
        first, second = gateway.children
        gateway._transport.close()
        await asyncio.wait_for(gateway._transport_closed.wait(), 2)
        parent_inventory = asyncio.create_task(gateway.get_sub_devices())
        request = await peer.receive(generic=True)
        assert request["inner"]["t"] == "bind"
        join = await _started(first.bind)
        try:
            join.cancel()
            with pytest.raises(asyncio.CancelledError):
                await join
            assert not parent_inventory.done() and not gateway.ready.is_set()
            peer.reply({"t": "bindok", "mac": ROOT, "key": KEY}, generic=True)
            request = await peer.receive()
            assert request["inner"] == {"t": "status", "mac": ROOT, "cols": ["hid"]}
            await _reported(peer, gateway, hid=HID)
            await peer.page(inventory)
            children = await asyncio.wait_for(parent_inventory, 2)
            assert children[0] is first and children[1] is second
            assert first.ready.is_set() and second.ready.is_set() and gateway.ready.is_set()
            assert not first.has_valid_state and not second.has_valid_state
            await second.update_state(["Pow"])
            request = await peer.receive()
            assert request["inner"]["mac"] == second.device_info.mac
        finally:
            gateway.close()
            await asyncio.gather(parent_inventory, join, return_exceptions=True)


@pytest.mark.parametrize("invalid", [
    "address", "cipher", "outer-target", "selector", "bind", "sibling-status", "sibling-command",
])
async def test_gateway_child_send_cannot_escape_owner_route_or_replace_session(invalid):
    async with gateway_peer() as (gateway, peer):
        await peer.enumerate(records(2))
        first, second = gateway.children
        root_cipher = gateway.device_cipher
        payload = {
            "t": "pack", "cid": "app", "tcid": ROOT, "i": 0, "uid": 0,
            "pack": {"t": "status", "mac": first.device_info.mac, "cols": ["Pow"]},
        }
        kwargs = {}
        if invalid == "address":
            kwargs["addr"] = peer.transport.get_extra_info("sockname")
        elif invalid == "cipher":
            kwargs["cipher"] = CipherV1()
        elif invalid == "outer-target":
            payload["tcid"] = first.device_info.mac
        elif invalid == "selector":
            payload["i"] = 1
        elif invalid == "bind":
            payload["pack"] = {"t": "bind", "mac": first.device_info.mac, "uid": 0}
        elif invalid == "sibling-status":
            payload["pack"]["mac"] = second.device_info.mac
        else:
            payload["pack"] = {
                "t": "cmd", "mac": ROOT, "sub": second.device_info.mac, "opt": ["Pow"], "p": [0],
            }
        with pytest.raises(ValueError):
            await first.send(payload, **kwargs)
        with pytest.raises(ValueError):
            first.device_key = "fedcba9876543210"
        with pytest.raises(ValueError):
            first.device_cipher = CipherV1()
        assert gateway.device_cipher is root_cipher and gateway.device_key == KEY
        assert gateway.ready.is_set() and first.ready.is_set() and second.ready.is_set()
        assert peer.queue.empty()
        await second.update_state(["Pow"])
        request = await peer.receive()
        assert request["inner"] == {"t": "status", "mac": second.device_info.mac, "cols": ["Pow"]}
        assert len(peer.sources) == 1
