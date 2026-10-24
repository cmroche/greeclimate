"""Consumer-facing gateway inventory and raw-send boundary regressions."""

import asyncio

import pytest

from greeclimate.exceptions import DeviceNotBoundError, DeviceTimeoutError
from greeclimate.network import Response

from .test_gateway import COMMERCIAL_HID, KEY, ROOT, gateway_peer, records
from .test_gateway_lifecycle import _reported, _started
from .test_gateway_lifecycle import lifecycle_loop_errors as lifecycle_loop_errors


pytestmark = pytest.mark.asyncio


async def test_inventory_uid_exhaustion_never_wraps_or_reuses_a_transaction():
    async with gateway_peer() as (gateway, peer):
        # Reach the finite wire boundary without issuing two billion requests.
        gateway._inventory_serial = 0x7ffffffe
        child = (await peer.enumerate(records(1)))[0]
        assert peer.outer["uid"] == 0x7fffffff
        for _ in range(2):
            with pytest.raises(ValueError, match="UID space exhausted"):
                await gateway.get_sub_devices()
            assert peer.queue.empty()
        assert gateway.children == (child,) and child.ready.is_set()
        await child.update_state(["Pow"])
        assert (await peer.receive())["inner"]["mac"] == child.device_info.mac
        assert gateway.device_key == KEY


async def test_commercial_multiple_children_rejects_page_before_accepting_any_record():
    async with gateway_peer(COMMERCIAL_HID) as (gateway, peer):
        ac = {"mac": ROOT + "00", "mid": "6400"}
        child = (await peer.enumerate([ac]))[0]
        pending = asyncio.create_task(gateway.get_sub_devices())
        await peer.page([ac, {"mac": ROOT + "01", "mid": "6200"}])
        with pytest.raises(ValueError, match="single-child"):
            await asyncio.wait_for(pending, 2)
        assert gateway.children == (child,) and child.ready.is_set()
        await child.update_state(["Pow"])
        assert (await peer.receive())["inner"]["mac"] == ROOT + "00"


async def test_non_record_inventory_slots_advance_pagination_without_creating_children():
    async with gateway_peer() as (gateway, peer):
        children = await peer.enumerate([None, [], "not a record", 42, False, *records(1)])
        assert peer.offsets == [0, 5]
        assert [child.device_info.mac for child in children] == [records(1)[0]["mac"]]
        assert gateway.children == tuple(children)


async def test_sent_controls_can_be_reversed_before_fresh_data():
    async with gateway_peer() as (gateway, peer):
        child = (await peer.enumerate(records(1)))[0]
        await _reported(peer, child, Pow=0)
        results = asyncio.Queue()
        child.add_handler(Response.RESULT, results.put_nowait)
        for value in (1, 0):
            child.set_property("Pow", value)
            child.set_property("Pow", value)
            await child.push_state_update()
            request = await peer.receive()
            assert request["inner"]["opt"] == ["Pow"]
            assert request["inner"]["p"] == [value]
            peer.reply({"t": "res", "mac": child.device_info.mac, "opt": ["Pow"], "p": [value]})
            assert await asyncio.wait_for(results.get(), 2) == {"Pow": value}
            assert child.get_property("Pow") == 0
            await child.push_state_update()
            assert peer.queue.empty()


@pytest.mark.parametrize("owner", ["child", "gateway"])
async def test_closed_child_cannot_stage_properties(owner):
    async with gateway_peer() as (gateway, peer):
        child = (await peer.enumerate(records(1)))[0]
        await _reported(peer, child, Pow=0)
        (child if owner == "child" else gateway).close()
        with pytest.raises(DeviceNotBoundError):
            child.set_property("Pow", 1)
        assert child.get_property("Pow") == 0 and peer.queue.empty()


@pytest.mark.parametrize("invalid", [
    "not-object", "not-pack", "outer-type", "sender", "bool-selector", "inner-owner",
    "status-with-sub", "command-with-child-mac", "command-without-mac", "commercial-mac",
])
async def test_child_raw_send_rejects_conflicting_envelope_and_route_identities(invalid):
    hid = COMMERCIAL_HID if invalid == "commercial-mac" else None
    kwargs = {"hid": hid} if hid else {}
    async with gateway_peer(**kwargs) as (gateway, peer):
        rows = [{"mac": ROOT + "00", "mid": "6400"}] if hid else records(1)
        child = (await peer.enumerate(rows))[0]
        payload = child.create_status_message(child.device_info, "Pow")
        if invalid == "not-object":
            payload = None
        elif invalid == "not-pack":
            payload["pack"] = []
        elif invalid == "outer-type":
            payload["t"] = "scan"
        elif invalid == "sender":
            payload["cid"] = ROOT
        elif invalid == "bool-selector":
            payload["i"] = False
        elif invalid == "inner-owner":
            payload["pack"]["cid"] = child.device_info.mac
        elif invalid == "status-with-sub":
            payload["pack"]["sub"] = child.device_info.mac
        else:
            payload = child.create_command_message(child.device_info, Pow=1)
            if invalid == "command-with-child-mac":
                payload["pack"]["mac"] = child.device_info.mac
            elif invalid == "command-without-mac":
                payload["pack"].pop("mac")
            else:
                payload["pack"]["mac"] = ROOT
        with pytest.raises(ValueError):
            await child.send(payload)
        assert peer.queue.empty()
        assert gateway.ready.is_set() and child.ready.is_set() and gateway.device_key == KEY
        updates = asyncio.Queue()
        child.add_handler(Response.DATA, updates.put_nowait)
        await child.update_state(["Pow"])
        assert (await peer.receive())["inner"] == {
            "t": "status", "mac": child.device_info.mac, "cols": ["Pow"],
        }
        peer.reply({"t": "dat", "mac": child.device_info.mac, "cols": ["Pow"], "dat": [0]})
        assert await asyncio.wait_for(updates.get(), 2) == {"Pow": 0}
        assert peer.queue.empty() and len(peer.sources) == 1


async def test_late_completed_inventory_reply_cannot_poison_the_next_traversal():
    async with gateway_peer() as (gateway, peer):
        child = (await peer.enumerate(records(1)))[0]
        completed_uid = peer.outer["uid"]
        late = {"t": "subList", "mac": ROOT, "r": 200, "c": 1, "i": 0,
                "list": records(2)[1:]}
        peer.reply(late)
        await _reported(peer, gateway, Pow=0)
        assert gateway.children == (child,)
        pending = asyncio.create_task(gateway.get_sub_devices())
        request = await peer.receive()
        assert request["outer"]["uid"] > completed_uid
        peer.reply(late, {"uid": completed_uid})
        await peer.assert_inventory_pending(pending)
        assert gateway.children == (child,)
        peer.reply({"t": "subList", "mac": ROOT, "r": 200, "c": 1, "i": 0,
                    "list": [{**records(1)[0], "name": "Fresh inventory"}]})
        assert await asyncio.wait_for(pending, 2) == [child]
        assert child.device_info.name == "Fresh inventory" and child.ready.is_set()
        assert gateway.children == (child,) and peer.queue.empty()


async def test_aborting_root_owned_inventory_task_fails_waiters_but_allows_retry():
    async with gateway_peer() as (gateway, peer):
        child = (await peer.enumerate(records(1)))[0]
        first = asyncio.create_task(gateway.get_sub_devices())
        await peer.receive()
        second = await _started(gateway.get_sub_devices)
        await peer.assert_inventory_pending(second)
        owned = [task for task in gateway.tasks if not task.done()]
        assert len(owned) == 1
        owned[0].cancel()
        for waiter in (first, second):
            with pytest.raises(DeviceNotBoundError):
                await asyncio.wait_for(waiter, 2)
        assert gateway.ready.is_set() and child.ready.is_set()
        assert await peer.enumerate(records(1)) == [child]
        assert len(peer.sources) == 1 and peer.queue.empty()


async def test_inventory_timeout_while_udp_send_is_draining_retires_unused_waiter():
    async with gateway_peer() as (gateway, peer):
        gateway.pause_writing()
        pending = asyncio.create_task(gateway.get_sub_devices())
        try:
            request = await peer.receive()
            assert request["inner"] == {"t": "subDev", "mac": ROOT, "i": 0}
            expired_uid = request["outer"]["uid"]
            with pytest.raises(DeviceTimeoutError):
                await asyncio.wait_for(pending, 2)
            assert gateway.children == () and gateway.ready.is_set()
        finally:
            gateway.resume_writing()
        fresh = asyncio.create_task(gateway.get_sub_devices())
        request = await peer.receive()
        assert request["outer"]["uid"] > expired_uid
        peer.reply({"t": "subList", "mac": ROOT, "r": 200, "c": 1, "i": 0,
                    "list": records(2)[1:]}, {"uid": expired_uid})
        await peer.assert_inventory_pending(fresh)
        assert gateway.children == ()
        peer.reply({"t": "subList", "mac": ROOT, "r": 200, "c": 1, "i": 0,
                    "list": records(1)})
        children = await asyncio.wait_for(fresh, 2)
        assert [child.device_info.mac for child in children] == [records(1)[0]["mac"]]
        assert gateway.children == tuple(children) and peer.queue.empty()


@pytest.mark.parametrize("retire", ["child-close", "root-close", "transport-loss"])
async def test_raw_child_send_rejects_retired_session_before_transmitting(retire):
    async with gateway_peer() as (gateway, peer):
        child = (await peer.enumerate(records(1)))[0]
        payload = child.create_status_message(child.device_info, "Pow")
        if retire == "transport-loss":
            gateway._transport.close()
            await asyncio.wait_for(gateway._transport_closed.wait(), 2)
        else:
            (child if retire == "child-close" else gateway).close()
        with pytest.raises(DeviceNotBoundError):
            await child.send(payload)
        assert peer.queue.empty() and not child.ready.is_set()
        if retire == "child-close":
            assert gateway.ready.is_set() and gateway.device_key == KEY


async def test_child_borrows_fresh_cipher_after_real_root_rebind():
    async with gateway_peer() as (gateway, peer):
        child = (await peer.enumerate(records(1)))[0]
        previous_cipher = child.device_cipher
        assert previous_cipher is gateway.device_cipher
        gateway._transport.close()
        await asyncio.wait_for(gateway._transport_closed.wait(), 2)
        assert child.device_cipher is None and not child.ready.is_set()
        await peer.bind()
        assert gateway.device_cipher is not previous_cipher
        assert child.device_cipher is gateway.device_cipher
        assert child.device_key == KEY
        assert await peer.enumerate(records(1)) == [child]
        await child.update_state(["Pow"])
        assert (await peer.receive())["inner"] == {
            "t": "status", "mac": child.device_info.mac, "cols": ["Pow"],
        }
        await _reported(peer, child, Pow=1)
        assert child.get_property("Pow") == 1 and child.has_valid_state
        assert child.device_cipher is gateway.device_cipher and peer.queue.empty()


async def test_late_public_bind_event_cannot_replace_a_live_or_closed_session():
    async with gateway_peer() as (gateway, peer):
        child = (await peer.enumerate(records(1)))[0]
        await _reported(peer, child, Pow=1)
        cipher = gateway.device_cipher
        gateway.handle_device_bound("fedcba9876543210")
        assert gateway.device_cipher is cipher and child.device_cipher is cipher
        assert gateway.device_key == KEY and child.ready.is_set() and child.has_valid_state
        await child.update_state(["Pow"])
        assert (await peer.receive())["inner"]["mac"] == child.device_info.mac
        gateway.close()
        gateway.handle_device_bound("fedcba9876543210")
        assert gateway.device_cipher is None and not gateway.ready.is_set()
        assert not child.ready.is_set() and peer.queue.empty()


async def test_child_close_after_actual_udp_send_preserves_unsent_intent(monkeypatch):
    async with gateway_peer() as (gateway, peer):
        child = (await peer.enumerate(records(1)))[0]
        await _reported(peer, child, Pow=0)
        child.set_property("Pow", 1)
        send = gateway.send

        async def send_then_close(*args, **kwargs):
            await send(*args, **kwargs)
            child.close()

        monkeypatch.setattr(gateway, "send", send_then_close)
        with pytest.raises(DeviceNotBoundError):
            await child.push_state_update()
        request = await peer.receive()
        assert request["inner"] == {
            "t": "cmd", "mac": ROOT, "sub": child.device_info.mac, "opt": ["Pow"], "p": [1],
        }
        assert child._dirty == {"Pow": 1} and child.get_property("Pow") == 0
        assert not child.ready.is_set() and gateway.ready.is_set()
        assert gateway.children == () and peer.queue.empty()


async def test_bind_extension_retiring_owner_cannot_start_inventory(monkeypatch):
    async with gateway_peer() as (gateway, peer):
        bind = gateway.bind

        async def bind_then_close(*args, **kwargs):
            await bind(*args, **kwargs)
            gateway.close()

        monkeypatch.setattr(gateway, "bind", bind_then_close)
        with pytest.raises(DeviceNotBoundError):
            await gateway.get_sub_devices()
        assert gateway.children == () and peer.queue.empty()


async def test_version_extension_retiring_owner_after_real_hid_report_rejects_inventory(monkeypatch):
    async with gateway_peer(bind=False) as (gateway, peer):
        await peer.bind(report=False)
        with pytest.raises(DeviceTimeoutError):
            await gateway.get_sub_devices()
        assert gateway.ready.is_set() and peer.queue.empty()
        reports = asyncio.Queue()
        gateway.add_handler(Response.DATA, reports.put_nowait)
        request_version = gateway.request_version

        async def request_version_then_close():
            await request_version()
            assert await asyncio.wait_for(reports.get(), 2) == {"hid": peer.hid}
            gateway.close()

        monkeypatch.setattr(gateway, "request_version", request_version_then_close)
        pending = asyncio.create_task(gateway.get_sub_devices())
        request = await peer.receive()
        assert request["inner"] == {"t": "status", "mac": ROOT, "cols": ["hid"]}
        peer.reply({"t": "dat", "mac": ROOT, "cols": ["hid"], "dat": [peer.hid]})
        with pytest.raises(DeviceNotBoundError):
            await asyncio.wait_for(pending, 2)
        assert gateway.children == () and peer.queue.empty()


async def test_send_extension_retiring_owner_after_real_page_report_rejects_inventory(monkeypatch):
    async with gateway_peer() as (gateway, peer):
        pages = asyncio.Queue()
        gateway.add_handler(Response.SUBLIST, pages.put_nowait)
        send = gateway.send

        async def send_then_close(*args, **kwargs):
            await send(*args, **kwargs)
            page = await asyncio.wait_for(pages.get(), 2)
            assert page["list"] == records(1)
            gateway.close()

        monkeypatch.setattr(gateway, "send", send_then_close)
        pending = asyncio.create_task(gateway.get_sub_devices())
        await peer.page(records(1))
        with pytest.raises(DeviceNotBoundError):
            await asyncio.wait_for(pending, 2)
        assert gateway.children == () and peer.queue.empty()
