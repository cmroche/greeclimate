"""Gateway discovery and cached-session regressions."""
import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from greeclimate.cipher import CipherV1
from greeclimate.device import Device
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.discovery import Discovery, Listener
from greeclimate.exceptions import DeviceTimeoutError
from greeclimate.network import DeviceProtocol2, Response


class RecordingListener(Listener):
    def __init__(self):
        self.macs = []

    async def device_found(self, device_info):
        self.macs.append(device_info.mac)


def gateway_packet():
    return {"pack": {"mac": "aabbcc001122", "name": "Gateway", "subCnt": 1}}


@pytest.mark.asyncio
async def test_scan_waits_for_gateway_query_created_by_packet_task():
    discovery = Discovery()
    started = asyncio.Event()
    release = asyncio.Event()
    sub_info = DeviceInfo("127.0.0.1", 7000, "aabbcc001133", "Indoor")

    async def query_gateway(info):
        started.set()
        await release.wait()
        await discovery.device_found(sub_info)

    async def search(*args, **kwargs):
        discovery.packet_received(gateway_packet(), ("127.0.0.1", 7000))

    async def end_window(*args):
        return None

    with patch.object(discovery, "search_devices", side_effect=search), \
         patch.object(discovery, "_query_gateway", side_effect=query_gateway), \
         patch("greeclimate.discovery.asyncio.sleep", side_effect=end_window):
        scan = asyncio.create_task(discovery.scan(wait_for=1))
        try:
            await asyncio.wait_for(started.wait(), 1)
            # Advance the loop so a prematurely completed scan is observable.
            for _ in range(5):
                tick = asyncio.get_running_loop().create_future()
                asyncio.get_running_loop().call_soon(tick.set_result, None)
                await tick
            assert not scan.done()
            release.set()
            devices = await asyncio.wait_for(scan, 1)
            assert [info.mac for info in devices] == [sub_info.mac]
        finally:
            release.set()
            await asyncio.gather(scan, *discovery.tasks, return_exceptions=True)


@pytest.mark.asyncio
async def test_no_wait_scan_keeps_gateway_policy_for_late_responses():
    discovery = Discovery()
    listener = RecordingListener()
    discovery.add_listener(listener)
    with patch.object(discovery, "search_devices", new_callable=AsyncMock), \
         patch.object(discovery, "_query_gateway", new_callable=AsyncMock):
        await discovery.scan(include_gateways=True)
        discovery.packet_received(gateway_packet(), ("127.0.0.1", 7000))
        await asyncio.gather(*discovery.tasks)
    assert listener.macs == ["aabbcc001122"]


@pytest.mark.asyncio
async def test_overlapping_scans_do_not_replace_active_gateway_policy():
    discovery = Discovery()
    listener = RecordingListener()
    discovery.add_listener(listener)
    first_search = asyncio.Event()
    release = asyncio.Event()
    calls = []

    async def search(*args, **kwargs):
        calls.append(len(calls))
        if len(calls) == 1:
            first_search.set()
            await release.wait()
            await discovery.device_found(DeviceInfo(
                "127.0.0.1", 7000, "aabbcc001122", "Gateway", sub_count=1
            ))

    with patch.object(discovery, "search_devices", side_effect=search), \
         patch.object(discovery, "_query_gateway", new_callable=AsyncMock):
        first = asyncio.create_task(discovery.scan(include_gateways=True))
        await asyncio.wait_for(first_search.wait(), 1)
        second = asyncio.create_task(discovery.scan(include_gateways=False))
        try:
            await asyncio.sleep(0)
        finally:
            release.set()
            await asyncio.gather(first, second)
    assert listener.macs == ["aabbcc001122"]


@pytest.mark.parametrize("pack", [None, {}, {"list": []}])
def test_top_level_sublist_dispatch_preserves_devices_and_nested_precedence(pack):
    protocol = DeviceProtocol2()
    callback = []
    protocol.add_handler(Response.SUBLIST, callback.append)
    devices = [{"mac": "aabbcc001133"}]
    packet = {"t": "subList", "list": devices}
    if pack is not None:
        packet["pack"] = pack
    protocol.packet_received(packet, ("127.0.0.1", 7000))
    assert callback == ([[]] if pack == {"list": []} else [devices])


@pytest.mark.asyncio
async def test_invalid_cached_key_binding_has_no_transport_side_effect():
    device = Device(DeviceInfo("127.0.0.1", 7000, "aabbcc001122", "Gateway"))
    loop = asyncio.get_running_loop()
    with patch.object(loop, "create_datagram_endpoint", new_callable=AsyncMock,
                      return_value=(object(), device)) as endpoint:
        with pytest.raises(ValueError, match="cipher must be provided"):
            await device.bind(key="1234567890123456")
        endpoint.assert_not_awaited()
    assert device._transport is None


@pytest.mark.asyncio
async def test_cached_gateway_enumeration_does_not_wait_for_unrequested_state():
    device = Device(DeviceInfo("127.0.0.1", 7000, "aabbcc001122", "Gateway"))
    # Bind creates a real UDP transport; the query response is injected at send.
    await device.bind(key="1234567890123456", cipher=CipherV1())

    async def send(*args, **kwargs):
        device.handle_sublist_response(
            [{"mac": "aabbcc001133", "name": "Indoor"}], generic=kwargs.get("request_cipher") is not None
        )

    try:
        with patch.object(device, "send", side_effect=send):
            result = await asyncio.wait_for(device.get_sub_devices(), 0.5)
        assert [info.mac for info in result] == ["aabbcc001133"]
        assert result[0].gateway_key == "1234567890123456"
    finally:
        device.close()


@pytest.mark.asyncio
async def test_enumeration_waits_for_requested_state_then_reuses_valid_session():
    device = Device(DeviceInfo("127.0.0.1", 7000, "aabbcc001122", "Gateway"))
    await device.bind(key="1234567890123456", cipher=CipherV1())
    query_sent = asyncio.Event()

    async def send(packet, **kwargs):
        if packet.get("t") == "subList" or packet.get("pack", {}).get("t") in ("subList", "subDev"):
            query_sent.set()
            device.handle_sublist_response([{"mac": "aabbcc001133"}], generic=packet["i"] == 1)

    try:
        with patch.object(device, "send", side_effect=send):
            await device.update_state()
            query = asyncio.create_task(device.get_sub_devices())
            try:
                await asyncio.sleep(0)
                assert not query_sent.is_set()
                device.handle_state_update(Pow=1)
                result = await asyncio.wait_for(query, 0.5)
                assert result[0].mac == "aabbcc001133"
                query_sent.clear()
                result = await asyncio.wait_for(device.get_sub_devices(), 0.5)
                assert result[0].mac == "aabbcc001133"
            finally:
                if not query.done():
                    query.cancel()
                await asyncio.gather(query, return_exceptions=True)
    finally:
        device.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("first_response", ["timeout", "empty", "partial"])
async def test_gateway_rescan_recovers_missing_indoor_units(first_response):
    """Issue 1: a cached gateway must not make an incomplete first scan permanent."""
    discovery = Discovery()
    gateway = DeviceInfo("127.0.0.1", 7000, "aabbcc001122", "Gateway", sub_count=2)
    children = [
        DeviceInfo(gateway.ip, gateway.port, mac, "Indoor", gateway_mac=gateway.mac)
        for mac in ("aabbcc001133", "aabbcc001144")
    ]
    initial = children[:1] if first_response == "partial" else []
    response = DeviceTimeoutError() if first_response == "timeout" else initial

    async def search(*args, **kwargs):
        await discovery.device_found(gateway)

    with patch.object(discovery, "search_devices", side_effect=search), \
         patch.object(Device, "bind", new_callable=AsyncMock), \
         patch.object(Device, "get_sub_devices", side_effect=[response, children]), \
         patch.object(Device, "close"):
        first = await discovery.scan()
        assert {info.mac for info in first} == {info.mac for info in initial}
        recovered = await discovery.scan()

    assert {info.mac for info in recovered} == {info.mac for info in children}


@pytest.mark.asyncio
async def test_gateway_address_change_refreshes_indoor_addresses():
    """Issue 1: indoor units must follow their gateway to its new address."""
    discovery = Discovery()
    gateways = [
        DeviceInfo(ip, 7000, "aabbcc001122", "Gateway", sub_count=1)
        for ip in ("127.0.0.1", "127.0.0.2")
    ]
    children = [
        DeviceInfo(gateway.ip, gateway.port, "aabbcc001133", "Indoor", gateway_mac=gateway.mac)
        for gateway in gateways
    ]
    advertisements = iter(gateways)

    async def search(*args, **kwargs):
        await discovery.device_found(next(advertisements))

    with patch.object(discovery, "search_devices", side_effect=search), \
         patch.object(Device, "bind", new_callable=AsyncMock), \
         patch.object(Device, "get_sub_devices", side_effect=[[child] for child in children]), \
         patch.object(Device, "close"):
        first = await discovery.scan()
        assert [(info.mac, info.ip) for info in first] == [(children[0].mac, gateways[0].ip)]
        refreshed = await discovery.scan()

    assert [(info.mac, info.ip) for info in refreshed] == [(children[1].mac, gateways[1].ip)]


@pytest.mark.asyncio
async def test_excluded_gateway_is_not_replayed_to_late_listener():
    """Issue 4: registering after a scan must not expose an excluded gateway."""
    discovery = Discovery()
    gateway = DeviceInfo("127.0.0.1", 7000, "aabbcc001122", "Gateway", sub_count=1)
    child = DeviceInfo(gateway.ip, gateway.port, "aabbcc001133", "Indoor", gateway_mac=gateway.mac)
    early = RecordingListener()
    discovery.add_listener(early)

    async def search(*args, **kwargs):
        await discovery.device_found(gateway)

    with patch.object(discovery, "search_devices", side_effect=search), \
         patch.object(Device, "bind", new_callable=AsyncMock), \
         patch.object(Device, "get_sub_devices", return_value=[child]), \
         patch.object(Device, "close"):
        devices = await discovery.scan(include_gateways=False)

    assert [info.mac for info in devices] == [child.mac]
    assert early.macs == [child.mac]
    late = RecordingListener()
    await asyncio.gather(*discovery.add_listener(late))
    assert late.macs == [child.mac]


@pytest.mark.asyncio
async def test_excluded_gateway_does_not_emit_address_updates():
    """Issue 4: a hidden gateway must stay hidden when its address changes."""
    discovery = Discovery()
    listener = AsyncMock(spec=Listener)
    discovery.add_listener(listener)
    gateways = iter([
        DeviceInfo(ip, 7000, "aabbcc001122", "Gateway", sub_count=1)
        for ip in ("127.0.0.1", "127.0.0.2")
    ])

    async def search(*args, **kwargs):
        await discovery.device_found(next(gateways))

    with patch.object(discovery, "search_devices", side_effect=search), \
         patch.object(discovery, "_query_gateway", new_callable=AsyncMock):
        await discovery.scan(include_gateways=False)
        listener.device_found.assert_not_awaited()
        await discovery.scan(include_gateways=False)

    listener.device_update.assert_not_awaited()


@pytest.mark.asyncio
async def test_duplicate_gateway_advertisements_share_active_enumeration():
    discovery = Discovery()
    gateway = DeviceInfo("127.0.0.1", 7000, "aabbcc001122", "Gateway", sub_count=1)
    child = DeviceInfo(gateway.ip, gateway.port, "aabbcc001133", "Indoor", gateway_mac=gateway.mac)
    listener = RecordingListener()
    discovery.add_listener(listener)
    started = asyncio.Event()
    release = asyncio.Event()
    queries = []

    async def query_gateway(info):
        queries.append(info.mac)
        started.set()
        await release.wait()
        await discovery.device_found(child)

    with patch.object(discovery, "_query_gateway", side_effect=query_gateway):
        first = asyncio.create_task(discovery.device_found(gateway))
        duplicate = None
        try:
            await asyncio.wait_for(started.wait(), 1)
            duplicate = asyncio.create_task(discovery.device_found(gateway))
            await asyncio.sleep(0)
        finally:
            release.set()
            await asyncio.gather(first, *([duplicate] if duplicate else []))
        assert queries == [gateway.mac]
        assert listener.macs == [child.mac]
        await discovery.device_found(gateway)

    assert queries == [gateway.mac, gateway.mac]
    assert listener.macs == [child.mac]
