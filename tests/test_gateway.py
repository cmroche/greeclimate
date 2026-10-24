"""Public gateway behavior against an independently framed encrypted UDP peer."""
import asyncio
from contextlib import asynccontextmanager

import pytest

from greeclimate.cipher import CipherV1
from greeclimate.device import DeviceTimeoutError
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.gateway import GatewayDevice
from greeclimate.network import Response
from tests.common import udp_peer
from tests.test_emulator import peer_packet, peer_reply

pytestmark = pytest.mark.asyncio
ROOT = "020000000001"
KEY = "0123456789abcdef"
HID = "362001067012+U-W06AV30.bin"
COMMERCIAL_HID = "362001065634+U-WB04BRT13V1.50.bin"


def records(count):
    return [{"mac": f"ab123456{index:06x}", "mid": "604a"} for index in range(count)]


class GatewayPeer:
    def __init__(self, gateway, transport, queue, hid):
        self.gateway, self.transport, self.queue, self.hid = gateway, transport, queue, hid
        self.addr = None
        self.outer = {}
        self.sources = set()
        self.offsets = []

    async def receive(self, generic=False):
        data, self.addr = await asyncio.wait_for(self.queue.get(), 2)
        self.sources.add(self.addr)
        decoded = peer_reply(data, b"a3K8Bx%2r8Y7#xDh" if generic else KEY.encode())
        self.outer = decoded["outer"]
        return decoded

    def reply(self, inner, outer=None, generic=False):
        envelope = {"t": "pack", "cid": ROOT, "tcid": "app", "i": 0,
                    "uid": self.outer.get("uid", 0), **(outer or {})}
        self.transport.sendto(peer_packet(envelope, inner,
                              b"a3K8Bx%2r8Y7#xDh" if generic else KEY.encode()), self.addr)

    async def assert_inventory_pending(self, task):
        callbacks = asyncio.Queue()
        self.gateway.add_handler(Response.DATA, callbacks.put_nowait)
        try:
            self.reply({"t": "dat", "mac": ROOT, "cols": ["Pow"], "dat": [0]})
            assert await asyncio.wait_for(callbacks.get(), 2) == {"Pow": 0}
            assert callbacks.empty() and not task.done()
        finally:
            self.gateway.remove_handler(Response.DATA, callbacks.put_nowait)

    async def bind(self, report=True):
        task = asyncio.create_task(self.gateway.bind(cipher=CipherV1()))
        request = await self.receive(generic=True)
        assert request["inner"] == {"t": "bind", "mac": ROOT, "uid": 0}
        self.reply({"t": "bindok", "mac": ROOT, "key": KEY}, generic=True)
        await asyncio.wait_for(task, 2)
        request = await self.receive()
        assert request["inner"] == {"t": "status", "mac": ROOT, "cols": ["hid"]}
        if report:
            self.reply({"t": "dat", "mac": ROOT, "cols": ["hid"], "dat": [self.hid]})
        return request

    async def page(self, rows, count=None, offset=None, **fields):
        request = await self.receive()
        inner, outer = request["inner"], request["outer"]
        assert inner["t"] == "subDev" and inner["mac"] == ROOT
        assert outer["tcid"] == ROOT and outer["cid"] == "app" and outer["i"] == 0
        self.offsets.append(inner["i"])
        self.reply({"t": "subList", "mac": ROOT, "r": 200,
                    "c": len(rows) if count is None else count,
                    "i": inner["i"] if offset is None else offset, "list": rows, **fields})
        return request

    async def enumerate(self, rows):
        task = asyncio.create_task(self.gateway.get_sub_devices())
        for offset in range(0, max(1, len(rows)), 5):
            await self.page(rows[offset:offset + 5], len(rows))
        return await asyncio.wait_for(task, 2)


@asynccontextmanager
async def gateway_peer(hid=HID, bind=True):
    async with udp_peer() as (transport, queue):
        host, port = transport.get_extra_info("sockname")
        gateway = GatewayDevice(DeviceInfo(host, port, ROOT, "Gateway", mid="60"), bind_timeout=0.08)
        peer = GatewayPeer(gateway, transport, queue, hid)
        try:
            if bind:
                await peer.bind()
            yield gateway, peer
        finally:
            children = gateway.children
            gateway.close()
            await asyncio.wait_for(gateway._transport_closed.wait(), 2)
            await asyncio.gather(*gateway.tasks, *(task for child in children for task in child.tasks),
                                 return_exceptions=True)


@pytest.mark.parametrize("count", [0, 1, 5, 6, 7, 10, 11, 255])
async def test_public_enumeration_boundaries_and_single_session(count):
    async with gateway_peer() as (gateway, peer):
        children = await peer.enumerate(records(count))
        assert [child.device_info.mac for child in children] == [row["mac"] for row in records(count)]
        assert peer.offsets == list(range(0, max(1, count), 5))
        assert 256 not in peer.offsets and len(peer.sources) == 1
        assert gateway.device_key == KEY
        assert gateway.children == tuple(children)
        assert all(child.gateway is gateway and child.ready.is_set() and not child.has_valid_state
                   for child in children)
        assert all(child.device_info.ip == gateway.device_info.ip and
                   child.device_info.port == gateway.device_info.port for child in children)
        assert all(all(value is None for value in child.capabilities.values()) for child in children)
        again = await peer.enumerate(records(count))
        assert all(left is right for left, right in zip(children, again))
        assert again is not children


async def test_raw_slot_offsets_full_ids_optional_fields_and_unknown_mid():
    rows = [{"mac": "AB123456000001", "mid": "unknown"},
            {"mac": "ab123456000001", "mid": "unknown"},
            {"mac": ROOT}, {"mac": "bad"}, {"mac": "ab123456000002", "name": None},
            {"mac": "ff654321000001", "mid": "608f", "lock": []},
            {"mac": "ab123456000003", "mid": "605c", "model": None}]
    async with gateway_peer() as (gateway, peer):
        children = await peer.enumerate(rows)
        assert peer.offsets == [0, 5]
        assert [child.device_info.mac for child in children] == [
            "AB123456000001", "ab123456000002", "ff654321000001", "ab123456000003"]
        assert children[0].device_info.mid == "unknown"
        assert children[0].device_info.name == "AB123456000001"
        assert children[1].device_info.mid is None


@pytest.mark.parametrize("second", [
    {"c": 7, "list": []}, {"c": 6, "list": records(1)},
    {"c": 7, "list": records(6)}, {"c": 256, "list": records(2)},
])
async def test_contradictory_pages_fail_without_losing_prefix(second):
    async with gateway_peer() as (gateway, peer):
        task = asyncio.create_task(gateway.get_sub_devices())
        await peer.page(records(5), 7)
        await peer.receive()
        peer.reply({"t": "subList", "mac": ROOT, "r": 200, "i": 5, **second})
        with pytest.raises(ValueError):
            await task
        assert len(gateway.children) == 5
        assert all(child.ready.is_set() for child in gateway.children)


@pytest.mark.parametrize("count,size", [(-1, 1), (1, 2), (6, 6)])
async def test_contradictory_first_page_does_not_accept_new_handles(count, size):
    async with gateway_peer() as (gateway, peer):
        cached = tuple(await peer.enumerate(records(1)))
        task = asyncio.create_task(gateway.get_sub_devices())
        await peer.page(records(size + 1)[1:], count)
        with pytest.raises(ValueError):
            await task
        assert gateway.children == cached
        assert cached[0].ready.is_set()


async def test_missing_page_times_out_and_empty_inventory_preserves_cache():
    async with gateway_peer() as (gateway, peer):
        task = asyncio.create_task(gateway.get_sub_devices())
        await peer.page(records(5), 7)
        await peer.receive()
        with pytest.raises(DeviceTimeoutError):
            await task
        cached = gateway.children
        assert await peer.enumerate([]) == list(cached)
        assert gateway.children == cached


@pytest.mark.parametrize("fields", [
    {"r": 500}, {"r": True}, {"c": True}, {"i": True}, {"c": "1"},
    {"list": {}}, {"i": 5},
])
async def test_malformed_or_unrelated_page_does_not_complete_waiter(fields):
    async with gateway_peer() as (gateway, peer):
        task = asyncio.create_task(gateway.get_sub_devices())
        await peer.receive()
        peer.reply({"t": "subList", "mac": ROOT, "r": 200, "i": 0,
                    "c": 1, "list": records(1), **fields})
        await peer.assert_inventory_pending(task)
        assert gateway.children == ()
        peer.reply({"t": "SUBLIST", "mac": ROOT, "r": 200, "i": 0,
                    "c": 1, "list": records(1)})
        assert len(await task) == 1


@pytest.mark.parametrize("hid", [HID, "362001066380+U-WB05BRV1.38.bin", COMMERCIAL_HID])
async def test_inventory_uid_is_source_echoed_monotonic_and_stale_reply_is_ignored(hid):
    async with gateway_peer(hid) as (gateway, peer):
        rows = [{"mac": ROOT + "00", "mid": "6400"}] if hid == COMMERCIAL_HID else records(1)
        task = asyncio.create_task(gateway.get_sub_devices())
        request = await peer.receive()
        uid = request["outer"]["uid"]
        assert type(uid) is int and 0 < uid <= 0x7fffffff
        payload = {"t": "subList", "r": 200, "i": 0, "c": 1, "list": rows}
        peer.reply(payload, {"uid": uid + 1})
        await peer.assert_inventory_pending(task)
        assert gateway.children == ()
        peer.reply(payload)
        first = (await task)[0]
        task = asyncio.create_task(gateway.get_sub_devices())
        request = await peer.receive()
        assert request["outer"]["uid"] > uid
        peer.reply(payload, {"uid": uid})
        await peer.assert_inventory_pending(task)
        peer.reply(payload)
        assert (await task)[0] is first


@pytest.mark.parametrize("change", [
    "missing-uid", "negative-uid", "overflow-uid", "bool-uid",
    "root", "mac", "tcid", "selector",
])
async def test_inventory_rejects_untrusted_transaction_envelopes(change):
    async with gateway_peer() as (gateway, peer):
        task = asyncio.create_task(gateway.get_sub_devices())
        request = await peer.receive()
        assert request["inner"] == {"t": "subDev", "mac": ROOT, "i": 0}
        assert request["outer"]["cid"] == "app"
        assert request["outer"]["tcid"] == ROOT and request["outer"]["i"] == 0
        uid = request["outer"]["uid"]
        assert type(uid) is int and 0 < uid <= 0x7fffffff
        outer = {"t": "pack", "cid": ROOT, "tcid": "app", "i": 0, "uid": uid}
        inner = {"t": "subList", "mac": ROOT, "r": 200, "i": 0,
                 "c": 1, "list": records(2)[1:]}
        if change == "missing-uid":
            outer.pop("uid")
        elif change == "negative-uid":
            outer["uid"] = -1
        elif change == "overflow-uid":
            outer["uid"] = 0x80000000
        elif change == "bool-uid":
            outer["uid"] = True
        elif change == "root":
            outer["cid"] = "ffffffffffff"
        elif change == "mac":
            inner["mac"] = "ffffffffffff"
        elif change == "tcid":
            outer["tcid"] = "another-app"
        else:
            outer["i"] = 1
        peer.transport.sendto(peer_packet(outer, inner, KEY.encode()), peer.addr)
        await peer.assert_inventory_pending(task)
        assert gateway.children == ()
        peer.reply({**inner, "mac": ROOT, "list": records(1)})
        children = await asyncio.wait_for(task, 2)
        assert [child.device_info.mac for child in children] == ["ab123456000000"]


@pytest.mark.parametrize("code", [
    "362001061433", "362001067012", "362001066326", "362001066380", "362001065634",
])
@pytest.mark.parametrize("suffix", [
    "", "+arbitrary-module", "+OTHER(MTK)V999.0.bin", "+U-W06AV30.binextra",
])
async def test_reported_firmware_code_selects_inventory_dialect(code, suffix):
    async with gateway_peer(code + suffix) as (gateway, peer):
        rows = [{"mac": ROOT + "00", "mid": "6400"}] if code == "362001065634" else records(1)
        children = await peer.enumerate(rows)
        assert [child.device_info.mac for child in children] == [row["mac"] for row in rows]
        assert all(child.ready.is_set() for child in children)
        assert gateway.hid == code + suffix


@pytest.mark.parametrize("hid", [
    "999999999999+U-W06AV30.bin", "redacted+U-WB05BRV1.10.bin",
    "362001065279+U-WB05RT13V1.64.bin", "362001000762+U-CS532AE(LT)V3.33.bin",
])
async def test_unknown_or_non_gateway_firmware_code_rejects_inventory(hid):
    async with gateway_peer(hid) as (gateway, peer):
        with pytest.raises(ValueError, match="unsupported|Unsupported|qualif"):
            await gateway.get_sub_devices()
        assert peer.queue.empty()
        assert gateway.hid == hid and gateway.children == ()


async def test_only_validated_root_data_qualifies_hid():
    async with gateway_peer(bind=False) as (gateway, peer):
        await peer.bind(report=False)
        gateway.hid = HID
        gateway.handle_state_update(hid=HID)
        peer.reply({"t": "res", "mac": ROOT, "opt": ["hid"], "p": [HID]})
        task = asyncio.create_task(gateway.get_sub_devices())
        # No accepted DATA means even manually assigned/RESULT HID cannot open inventory.
        with pytest.raises(DeviceTimeoutError):
            await task
        while not peer.queue.empty():
            request = await peer.receive()
            assert request["inner"]["t"] == "status"
        task = asyncio.create_task(gateway.get_sub_devices())
        request = await peer.receive()
        assert request["inner"]["cols"] == ["hid"]
        peer.reply({"t": "dat", "mac": ROOT, "cols": ["hid"], "dat": [HID]})
        await peer.page(records(1), 1)
        assert len(await task) == 1


@pytest.mark.parametrize("change", [
    "peer", "root", "mac", "selector", "length", "columns", "values", "column-name",
])
async def test_root_metadata_rejects_untrusted_data_before_qualification(change):
    async with gateway_peer(bind=False) as (gateway, peer):
        await peer.bind(report=False)
        task = asyncio.create_task(gateway.get_sub_devices())
        outer = {"t": "pack", "cid": ROOT, "tcid": "app", "i": 0, "uid": 0}
        inner = {"t": "dat", "mac": ROOT, "cols": ["hid"], "dat": [HID]}
        if change == "root":
            outer["cid"] = "ffffffffffff"
        elif change == "mac":
            inner["mac"] = "ffffffffffff"
        elif change == "selector":
            outer["i"] = 1
        elif change == "length":
            inner["dat"] = [HID, HID]
        elif change == "columns":
            inner["cols"] = "hid"
        elif change == "values":
            inner["dat"] = HID
        elif change == "column-name":
            inner["cols"] = [None]
        packet = peer_packet(outer, inner, KEY.encode())
        if change == "peer":
            async with udp_peer() as (foreign, _):
                foreign.sendto(packet, peer.addr)
                await peer.assert_inventory_pending(task)
        else:
            peer.transport.sendto(packet, peer.addr)
            await peer.assert_inventory_pending(task)
        assert "hid" not in gateway.raw_properties and gateway.children == ()
        assert peer.queue.empty()
        peer.reply({"t": "dat", "mac": ROOT, "cols": ["hid"], "dat": [HID]})
        await peer.page(records(1), 1)
        assert len(await asyncio.wait_for(task, 2)) == 1 and gateway.hid == HID


async def test_stable_cache_metadata_refresh_and_mid_replacement():
    async with gateway_peer() as (gateway, peer):
        first = (await peer.enumerate(records(1)))[0]
        refreshed = [{**records(1)[0], "name": "new name"}]
        assert (await peer.enumerate(refreshed))[0] is first
        assert first.device_info.name == "new name"
        replaced = (await peer.enumerate([{**refreshed[0], "mid": "605c"}]))[0]
        assert replaced is not first and not first.ready.is_set()
        assert replaced.device_info.mid == "605c" and first.device_info.mid == "604a"
        replaced.close()
        assert gateway.children == ()
        assert (await peer.enumerate(refreshed))[0] is not replaced


async def deliver(peer, child, response="dat", values=None, outer=None, **fields):
    values = {"Pow": 0, "Mod": 1, "SetTem": 24} if values is None else values
    columns, data = ("cols", "dat") if response == "dat" else ("opt", "p")
    peer.reply({"t": response, "mac": child.device_info.mac,
                columns: list(values), data: list(values.values()), **fields}, outer)
    await asyncio.sleep(0.01)


async def test_public_child_status_raw_controls_and_independent_result_data():
    async with gateway_peer() as (gateway, peer):
        first, second = await peer.enumerate(records(2))
        data, results = asyncio.Queue(), asyncio.Queue()
        first.add_handler(Response.DATA, data.put_nowait)
        first.add_handler(Response.RESULT, results.put_nowait)
        await first.bind()
        assert peer.queue.empty()
        await first.update_state()
        request = await peer.receive()
        assert request["outer"]["tcid"] == ROOT
        assert request["inner"]["mac"] == first.device_info.mac
        assert {"Pow", "Mod", "SetTem", "TemBody"} <= set(request["inner"]["cols"])
        await deliver(peer, first)
        assert await data.get() == {"Pow": 0, "Mod": 1, "SetTem": 24}
        assert first.has_valid_state and not second.has_valid_state
        for name, value in (("Mod", 2), ("SetTem", 22), ("Pow", 1)):
            first.set_property(name, value)
        assert first.get_property("Pow") == 0 and first.get_property("SetTem") == 24
        await first.push_state_update()
        request = await peer.receive()
        assert request["inner"] == {"t": "cmd", "mac": ROOT, "sub": first.device_info.mac,
                                    "opt": ["Mod", "SetTem", "Pow"], "p": [2, 22, 1]}
        await deliver(peer, first, "res", {"Mod": 2, "SetTem": 22, "Pow": 1})
        assert await results.get() == {"Mod": 2, "SetTem": 22, "Pow": 1}
        assert first.get_property("Pow") == 0 and second.raw_properties == {}
        assert data.empty()
        await first.push_state_update()
        assert peer.queue.empty()
        await first.update_state(["Pow", "SetTem"])
        await peer.receive()
        await deliver(peer, first, values={"Pow": 0, "SetTem": 25})
        assert first.get_property("SetTem") == 25
        assert results.empty()
        assert gateway.raw_properties == {}


async def test_queued_replacement_failure_and_concurrent_intent(monkeypatch):
    async with gateway_peer() as (gateway, peer):
        child = (await peer.enumerate(records(1)))[0]
        await deliver(peer, child)
        child.set_property("Pow", 1)
        child.set_property("Pow", 0)
        await child.push_state_update()
        assert (await peer.receive())["inner"]["p"] == [0]
        original_send = gateway.send

        async def fail(*args, **kwargs):
            raise OSError("send failed")

        monkeypatch.setattr(gateway, "send", fail)
        child.set_property("Pow", 1)
        with pytest.raises(OSError, match="send failed"):
            await child.push_state_update()
        monkeypatch.setattr(gateway, "send", original_send)
        entered, release = asyncio.Event(), asyncio.Event()

        async def paused(*args, **kwargs):
            entered.set()
            await release.wait()
            await original_send(*args, **kwargs)

        monkeypatch.setattr(gateway, "send", paused)
        task = asyncio.create_task(child.push_state_update())
        await entered.wait()
        child.set_property("Pow", 0)
        release.set()
        await task
        assert (await peer.receive())["inner"]["p"] == [1]
        monkeypatch.setattr(gateway, "send", original_send)
        await child.push_state_update()
        assert (await peer.receive())["inner"]["p"] == [0]
        assert child.get_property("Pow") == 0


@pytest.mark.parametrize("change", ["peer", "root", "cid", "tcid", "key", "unknown", "missing", "ciphertext"])
async def test_child_routing_rejects_untrusted_envelopes(change):
    async with gateway_peer() as (gateway, peer):
        child = (await peer.enumerate(records(1)))[0]
        callbacks = asyncio.Queue()
        child.add_handler(Response.DATA, callbacks.put_nowait)
        inner = {"t": "dat", "mac": child.device_info.mac, "cols": ["Pow"], "dat": [1]}
        outer = {"t": "pack", "cid": ROOT, "tcid": "app", "i": 0, "uid": 0}
        key = KEY.encode()
        if change == "root":
            outer["cid"] = "ffffffffffff"
        elif change == "cid":
            inner["cid"] = "ffffffffffff"
        elif change == "tcid":
            outer["tcid"] = "another-app"
        elif change == "key":
            outer["i"] = 1
        elif change == "unknown":
            inner["mac"] = "ff123456000001"
        elif change == "missing":
            inner.pop("mac")
        elif change == "ciphertext":
            key = b"fedcba9876543210"
        packet = peer_packet(outer, inner, key)
        if change == "peer":
            async with udp_peer() as (foreign, _):
                foreign.sendto(packet, peer.addr)
                await asyncio.sleep(0.01)
        else:
            peer.transport.sendto(packet, peer.addr)
            await asyncio.sleep(0.01)
        assert callbacks.empty() and not child.has_valid_state and child.raw_properties == {}
        await deliver(peer, child)
        assert not callbacks.empty() and child.has_valid_state


@pytest.mark.parametrize("response", ["dat", "res"])
@pytest.mark.parametrize("names,values", [(["Pow", "Mod"], [1]), ("Pow", [1]),
                                          (["Pow"], "1"), ([None], [1])])
async def test_malformed_arrays_do_not_mutate_child(response, names, values):
    async with gateway_peer() as (gateway, peer):
        child = (await peer.enumerate(records(1)))[0]
        callbacks = asyncio.Queue()
        child.add_handler(Response.DATA if response == "dat" else Response.RESULT, callbacks.put_nowait)
        a, b = ("cols", "dat") if response == "dat" else ("opt", "p")
        peer.reply({"t": response, "mac": child.device_info.mac, a: names, b: values})
        await asyncio.sleep(0.01)
        assert callbacks.empty() and child.raw_properties == {} and not child.has_valid_state


@pytest.mark.parametrize("response", ["dat", "res"])
async def test_duplicate_columns_preserve_existing_last_value_normalization(response):
    async with gateway_peer() as (gateway, peer):
        child = (await peer.enumerate(records(1)))[0]
        callbacks = asyncio.Queue()
        child.add_handler(Response.DATA if response == "dat" else Response.RESULT, callbacks.put_nowait)
        a, b = ("cols", "dat") if response == "dat" else ("opt", "p")
        peer.reply({"t": response, "mac": child.device_info.mac, a: ["Pow", "Pow"], b: [0, 1]})
        assert await asyncio.wait_for(callbacks.get(), 2) == {"Pow": 1}
        assert child.raw_properties == ({"Pow": 1} if response == "dat" else {})
        assert child.has_valid_state is (response == "dat")


@pytest.mark.parametrize("mid", ["6400", "6045", "609d"])
async def test_commercial_ac_routes_use_sub_without_mac(mid):
    async with gateway_peer(COMMERCIAL_HID) as (gateway, peer):
        child = (await peer.enumerate([{"mac": ROOT + "00", "mid": mid}]))[0]
        await child.update_state(["Pow"])
        assert (await peer.receive())["inner"] == {"t": "status", "mac": ROOT + "00", "cols": ["Pow"]}
        await deliver(peer, child, values={"Pow": 0}, cid=ROOT)
        assert child.get_property("Pow") == 0
        child.set_property("Pow", 1)
        await child.push_state_update()
        assert (await peer.receive())["inner"] == {"t": "cmd", "sub": ROOT + "00", "opt": ["Pow"], "p": [1]}
        await deliver(peer, child, "res", {"Pow": 1}, cid=ROOT)
        assert child.get_property("Pow") == 0


@pytest.mark.parametrize("suffix,mid", [("01", "6045"), ("00", "6200"), ("00", "9999"), ("01", None)])
async def test_commercial_unqualified_roles_are_metadata_only(suffix, mid):
    async with gateway_peer(COMMERCIAL_HID) as (gateway, peer):
        child = (await peer.enumerate([{"mac": ROOT + suffix, "mid": mid}]))[0]
        assert child.device_info.mid == mid and not child.ready.is_set()
        for operation in (child.bind, child.update_state, child.request_version, child.push_state_update):
            with pytest.raises(ValueError):
                await operation()
        with pytest.raises(ValueError):
            child.set_property("Pow", 1)
        assert peer.queue.empty()


async def test_commercial_filter_replacement_retires_old_ac_route():
    async with gateway_peer(COMMERCIAL_HID) as (gateway, peer):
        ac = (await peer.enumerate([{"mac": ROOT + "00", "mid": "6400"}]))[0]
        await deliver(peer, ac, values={"Pow": 1}, cid=ROOT)
        await peer.enumerate([{"mac": ROOT + "01", "mid": "6200"}])
        assert len(gateway.children) == 2 and not ac.ready.is_set() and not ac.has_valid_state
        with pytest.raises(ValueError):
            ac.set_property("Pow", 0)
        assert peer.queue.empty()


async def test_child_version_and_dirty_intent_are_instance_local():
    async with gateway_peer() as (gateway, peer):
        first, second = await peer.enumerate(records(2))
        await deliver(peer, first, values={"Pow": 0})
        await deliver(peer, second, values={"Pow": 1})
        first.set_property("Pow", 1)
        second.set_property("Pow", 0)
        await first.push_state_update()
        first_command = (await peer.receive())["inner"]
        assert first_command["sub"] == first.device_info.mac and first_command["p"] == [1]
        await deliver(peer, first, "res", {"Pow": 1})
        await second.push_state_update()
        second_command = (await peer.receive())["inner"]
        assert second_command["sub"] == second.device_info.mac and second_command["p"] == [0]
        assert first.get_property("Pow") == 0 and second.get_property("Pow") == 1
        await first.request_version()
        assert (await peer.receive())["inner"] == {
            "t": "status", "mac": first.device_info.mac, "cols": ["hid"]}
        await deliver(peer, first, values={"hid": "362001065279+U-WB05RT13V1.64.bin"})
        assert first.hid == "362001065279+U-WB05RT13V1.64.bin"
        assert gateway.hid == HID and gateway.ready.is_set() and first.ready.is_set()
        assert all(value is None for value in first.capabilities.values())
        assert second.hid is None
