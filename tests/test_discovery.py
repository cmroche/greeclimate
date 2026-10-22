import asyncio
import json
import socket
from contextlib import AsyncExitStack, asynccontextmanager
from ipaddress import IPv4Address
from threading import Thread
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import ifaddr
import pytest

from greeclimate.cipher import CipherV1
from greeclimate.device import Device
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.discovery import Discovery, Listener
from greeclimate.network import Commands, DeviceProtocol2
from .common import (
    DEFAULT_TIMEOUT,
    DISCOVERY_REQUEST,
    DISCOVERY_RESPONSE,
    Responder,
    get_mock_device_info, encrypt_payload, encrypt_payload_v2,
)
from .common import udp_peer
from .test_emulator import peer_packet, peer_reply


@pytest.mark.asyncio
async def test_get_broadcast_addresses_lan(ifaddr_adapters):
    ifaddr_adapters.return_value = [
        ifaddr.Adapter("lan0", "lan0", [
            ifaddr.IP("192.0.2.10", 24, "lan0"),
            ifaddr.IP("198.51.100.3", 23, "lan0"),
            ifaddr.IP(("2001:db8::1", 0, 1), 64, "lan0"),
        ]),
        ifaddr.Adapter("lan1", "lan1", [ifaddr.IP("203.0.113.5", 30, "lan1")]),
    ]

    assert Discovery()._get_broadcast_addresses() == [
        IPv4Address("192.0.2.255"),
        IPv4Address("198.51.101.255"),
        IPv4Address("203.0.113.7"),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("allow_loopback", [False, True])
async def test_get_broadcast_addresses_loopback(ifaddr_adapters, allow_loopback):
    ifaddr_adapters.return_value = [
        ifaddr.Adapter("lo", "lo", [
            ifaddr.IP("127.0.0.1", 8, "lo"),
            ifaddr.IP("127.0.0.2", 32, "lo"),
        ]),
    ]

    expected = [IPv4Address("127.0.0.1"), IPv4Address("127.0.0.2")] if allow_loopback else []
    assert Discovery(allow_loopback=allow_loopback)._get_broadcast_addresses() == expected


@pytest.mark.asyncio
async def test_get_broadcast_addresses_non_broadcast_subnets(ifaddr_adapters):
    ifaddr_adapters.return_value = [
        ifaddr.Adapter("lan", "lan", [
            ifaddr.IP("192.0.2.10", 31, "lan"),
            ifaddr.IP("198.51.100.7", 32, "lan"),
        ]),
    ]

    assert Discovery(allow_loopback=True)._get_broadcast_addresses() == []


@pytest.mark.asyncio
@pytest.mark.parametrize("adapters", [
    [],
    [ifaddr.Adapter("empty", "empty", [])],
    [ifaddr.Adapter("ipv6", "ipv6", [ifaddr.IP(("2001:db8::1", 0, 1), 64, "ipv6")])],
], ids=["no-adapters", "no-addresses", "ipv6-only"])
async def test_get_broadcast_addresses_no_ipv4(ifaddr_adapters, adapters):
    ifaddr_adapters.return_value = adapters

    assert Discovery()._get_broadcast_addresses() == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,family", [(("127.0.0.1", 7000), socket.AF_INET)]
)
@pytest.mark.parametrize("scan_args,scan_kwargs", [
    ((), {}),
    ((), {"target_addresses": [IPv4Address("127.0.0.1")]}),
    ((), {"bcast_ifaces": [IPv4Address("127.0.0.1")]}),
    (([IPv4Address("127.0.0.1")],), {}),
    ((), {"target_addresses": None}),
    ((), {"target_addresses": []}),
    ((), {"bcast_ifaces": []}),
], ids=["automatic", "target_addresses", "bcast_ifaces", "positional", "none", "empty", "legacy-empty"])
async def test_discover_devices(ifaddr_adapters, addr, family, scan_args, scan_kwargs):
    ifaddr_adapters.return_value = [] if scan_args or any(scan_kwargs.values()) else [
        ifaddr.Adapter("lo", "lo", [ifaddr.IP(addr[0], 8, "lo")])
    ]

    devices = [
        {"cid": "aabbcc001122", "mac": "aabbcc001122", "name": "MockDevice1"},
        {"cid": "aabbcc001123", "mac": "aabbcc001123", "name": "MockDevice2"},
        {"cid": "", "mac": "aabbcc001124", "name": "MockDevice3"},
    ]

    with Responder(family, addr[1]) as sock:

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)
            assert p == DISCOVERY_REQUEST

            for d in devices:
                r = DISCOVERY_RESPONSE.copy()
                r["pack"].update(d)
                p = json.dumps(encrypt_payload(r))
                s.sendto(p.encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        discovery = Discovery(allow_loopback=True)
        try:
            devices = await discovery.scan(DEFAULT_TIMEOUT, *scan_args, **scan_kwargs)
            assert {device.mac for device in devices} == {
                "aabbcc001122", "aabbcc001123", "aabbcc001124",
            }
            assert all(device.mid == "10001" for device in devices)
        finally:
            discovery.close()

        sock.close()
        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
@pytest.mark.parametrize("args,kwargs", [
    ((), {"target_addresses": [IPv4Address("127.0.0.1")]}),
    ((), {"broadcastAddrs": [IPv4Address("127.0.0.1")]}),
    (([IPv4Address("127.0.0.1")],), {}),
    ((), {}),
    ((), {"target_addresses": None}),
    ((), {"target_addresses": []}),
    ((), {"broadcastAddrs": None}),
    ((), {"broadcastAddrs": []}),
])
async def test_search_devices_sends_discovery_packet(ifaddr_adapters, args, kwargs):
    ifaddr_adapters.return_value = [] if args or any(kwargs.values()) else [
        ifaddr.Adapter("lo", "lo", [ifaddr.IP("127.0.0.1", 8, "lo")])
    ]
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    discovery = Discovery(allow_loopback=True)
    try:
        receiver.bind(("127.0.0.1", 7000))
        receiver.setblocking(False)
        await discovery.search_devices(*args, **kwargs)
        data, _ = await asyncio.wait_for(
            asyncio.get_running_loop().sock_recvfrom(receiver, 2048), DEFAULT_TIMEOUT
        )
        assert json.loads(data) == DISCOVERY_REQUEST
    finally:
        if discovery._transport is not None:
            discovery.close()
        receiver.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("legacy_addresses", [[], [IPv4Address("127.0.0.1")]])
@pytest.mark.parametrize("method,legacy_parameter", [
    ("scan", "bcast_ifaces"), ("search_devices", "broadcastAddrs"),
])
async def test_discovery_rejects_conflicting_address_parameters(legacy_addresses, method, legacy_parameter):
    discovery = Discovery()
    with pytest.raises(ValueError, match="Use either target_addresses or " + legacy_parameter):
        await getattr(discovery, method)(**{legacy_parameter: legacy_addresses, "target_addresses": []})


@pytest.mark.asyncio
async def test_discover_no_devices(ifaddr_adapters):
    ifaddr_adapters.return_value = [ifaddr.Adapter("lo", "lo", [ifaddr.IP("127.0.0.1", 8, "lo")])]

    discovery = Discovery(allow_loopback=True)
    devices = await discovery.scan(wait_for=DEFAULT_TIMEOUT)

    assert devices is not None
    assert len(devices) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,family", [(("127.0.0.1", 7000), socket.AF_INET)]
)
async def test_discover_deduplicate_multiple_discoveries(
    ifaddr_adapters, addr, family
):
    ifaddr_adapters.return_value = [ifaddr.Adapter("lo", "lo", [ifaddr.IP(addr[0], 8, "lo")])]

    devices = [
        {"cid": "aabbcc001122", "mac": "aabbcc001122", "name": "MockDevice1"},
        {"cid": "aabbcc001123", "mac": "aabbcc001123", "name": "MockDevice2"},
        {"cid": "aabbcc001123", "mac": "aabbcc001123", "name": "MockDevice2"},
    ]

    with Responder(family, addr[1]) as sock:

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)
            assert p == DISCOVERY_REQUEST

            for d in devices:
                r = DISCOVERY_RESPONSE.copy()
                r["pack"].update(d)
                p = json.dumps(encrypt_payload(r))
                s.sendto(p.encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        discovery = Discovery(allow_loopback=True)
        devices = await discovery.scan(wait_for=DEFAULT_TIMEOUT)
        assert devices is not None
        assert len(devices) == 2

        sock.close()
        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,family", [(("127.0.0.1", 7000), socket.AF_INET)]
)
async def test_discovery_events(ifaddr_adapters, addr, family):
    ifaddr_adapters.return_value = [ifaddr.Adapter("lo", "lo", [ifaddr.IP(addr[0], 8, "lo")])]

    with Responder(family, addr[1]) as sock:

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)
            assert p == DISCOVERY_REQUEST

            p = json.dumps(encrypt_payload(DISCOVERY_RESPONSE))
            s.sendto(p.encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        with patch.object(Discovery, "packet_received", return_value=None) as mock:
            discovery = Discovery(allow_loopback=True)
            await discovery.scan()
            await asyncio.sleep(DEFAULT_TIMEOUT)

            assert mock.call_count == 1

        sock.close()
        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
@pytest.mark.parametrize("mid", ["0001", "10f01", None])
async def test_discovery_preserves_reported_mid(mid):
    discovery = Discovery()
    pack = {"mac": "000000000001", "name": "mid-test", "model": "10001"}
    if mid is not None:
        pack["mid"] = mid
    discovery.packet_received({"pack": pack}, ("127.0.0.1", 7000))
    await asyncio.gather(*discovery.tasks)

    device_info, = discovery.devices
    assert device_info.mid == mid
    assert device_info.model == "10001"


@pytest.mark.asyncio
async def test_discovery_device_update_events():
    discovery = Discovery(allow_loopback=True)
    discovery.packet_received(
        {
            "pack": {
                "mac": "aa11bb22cc33",
                "cid": 1,
                "name": "MockDevice",
                "brand": "",
                "model": "",
                "ver": "1.0.0",
            }
        },
        ("1.1.1.1", 7000),
    )

    await asyncio.gather(*discovery.tasks, return_exceptions=True)

    assert len(discovery.devices) == 1
    assert discovery.devices[0].mac == "aa11bb22cc33"
    assert discovery.devices[0].ip == "1.1.1.1"

    discovery.packet_received(
        {
            "pack": {
                "mac": "aa11bb22cc33",
                "cid": 1,
                "name": "MockDevice",
                "brand": "",
                "model": "",
                "ver": "1.0.0",
            }
        },
        ("1.1.2.2", 7000),
    )

    await asyncio.gather(*discovery.tasks, return_exceptions=True)

    assert len(discovery.devices) == 1
    assert discovery.devices[0].mac == "aa11bb22cc33"
    assert discovery.devices[0].ip == "1.1.2.2"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,family", [(("127.0.0.1", 7000), socket.AF_INET)]
)
async def test_discover_devices_bad_data(ifaddr_adapters, addr, family):
    """Create a socket broadcast responder, an async broadcast listener,
    test discovery responses.
    """
    ifaddr_adapters.return_value = [ifaddr.Adapter("lo", "lo", [ifaddr.IP(addr[0], 8, "lo")])]

    with Responder(family, addr[1]) as sock:

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)
            assert p == DISCOVERY_REQUEST

            s.sendto("garbage data".encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        # Run the listener portion now
        discovery = Discovery(allow_loopback=True)
        response = await discovery.scan(wait_for=DEFAULT_TIMEOUT)

        assert response is not None
        assert len(response) == 0

        sock.close()
        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,family", [(("127.0.0.1", 7000), socket.AF_INET)]
)
async def test_discover_devices_cipherv2_fallback(ifaddr_adapters, addr, family):
    """Devices that only encrypt their scan reply with CipherV2 (AES-GCM)
    must still be discovered: Discovery should fall back to CipherV2 when
    CipherV1 fails to decrypt the reply, same as Device.bind() already
    does.
    """
    ifaddr_adapters.return_value = [ifaddr.Adapter("lo", "lo", [ifaddr.IP(addr[0], 8, "lo")])]

    with Responder(family, addr[1]) as sock:

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)
            assert p == DISCOVERY_REQUEST

            p = json.dumps(encrypt_payload_v2(DISCOVERY_RESPONSE))
            s.sendto(p.encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        discovery = Discovery(allow_loopback=True)
        devices = await discovery.scan(wait_for=DEFAULT_TIMEOUT)

        assert devices is not None
        assert len(devices) == 1
        assert devices[0].mac == DISCOVERY_RESPONSE["pack"]["mac"]

        sock.close()
        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,family", [(("127.0.0.1", 7000), socket.AF_INET)]
)
async def test_discover_devices_undecryptable_reply_ignored(
    ifaddr_adapters, addr, family
):
    """A reply that fails to decrypt under both CipherV1 and CipherV2
    should be discarded without raising, and should not prevent other
    devices from being discovered.
    """
    ifaddr_adapters.return_value = [ifaddr.Adapter("lo", "lo", [ifaddr.IP(addr[0], 8, "lo")])]

    with Responder(family, addr[1]) as sock:

        def responder(s):
            (d, addr) = s.recvfrom(2048)
            p = json.loads(d)
            assert p == DISCOVERY_REQUEST

            bad = DISCOVERY_RESPONSE.copy()
            bad["pack"] = "not-valid-base64-ciphertext"
            s.sendto(json.dumps(bad).encode(), addr)

            good = encrypt_payload(DISCOVERY_RESPONSE)
            s.sendto(json.dumps(good).encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        discovery = Discovery(allow_loopback=True)
        devices = await discovery.scan(wait_for=DEFAULT_TIMEOUT)

        assert devices is not None
        assert len(devices) == 1
        assert devices[0].mac == DISCOVERY_RESPONSE["pack"]["mac"]

        sock.close()
        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
async def test_add_new_listener():
    """Register a listener, test that is registered."""

    listener = MagicMock(spec_set=Listener)
    discovery = Discovery()

    result = discovery.add_listener(listener)
    assert result is not None

    result = discovery.add_listener(listener)
    assert result is None


@pytest.mark.asyncio
async def test_add_new_listener_with_devices():
    """Register a listener, test that is registered."""

    with patch.object(Discovery, "devices", new_callable=PropertyMock) as mock:
        mock.return_value = [get_mock_device_info()]
        listener = MagicMock(spec_set=Listener)
        discovery = Discovery()

        result = discovery.add_listener(listener)
        await asyncio.gather(*discovery.tasks)

        assert result is not None
        assert len(result) == 1
        assert listener.device_found.call_count == 1


@pytest.mark.asyncio
async def test_remove_listener():
    """Register, remove listener, test results."""

    listener = MagicMock(spec_set=Listener)
    discovery = Discovery()

    result = discovery.add_listener(listener)
    assert result is not None

    result = discovery.remove_listener(listener)
    assert result is True

    result = discovery.remove_listener(listener)
    assert result is False


class _RecoveryDiscovery(Discovery):
    """Expose completed observations and actual transport closure to tests."""

    def __init__(self):
        super().__init__(allow_loopback=True)
        self.observations = asyncio.Queue()
        self.closed_transports = asyncio.Queue()

    async def device_found(self, device_info):
        await super().device_found(device_info)
        self.observations.put_nowait(device_info)

    def connection_lost(self, exc):
        try:
            super().connection_lost(exc)
        finally:
            self.closed_transports.put_nowait(exc)


class _RecoveryListener(Listener):
    def __init__(self):
        self.events = asyncio.Queue()

    async def device_found(self, device_info):
        self.events.put_nowait(("found", device_info))

    async def device_update(self, device_info):
        self.events.put_nowait(("update", device_info))


@asynccontextmanager
async def _recovery_discovery():
    discovery = _RecoveryDiscovery()
    await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: discovery, local_addr=("127.0.0.1", 0)
    )
    try:
        yield discovery
    finally:
        if discovery._transport is not None:
            discovery.close()
            await asyncio.wait_for(discovery.closed_transports.get(), DEFAULT_TIMEOUT)
        if discovery.tasks:
            await asyncio.wait_for(
                asyncio.gather(*discovery.tasks, return_exceptions=True),
                DEFAULT_TIMEOUT,
            )


async def _recovery_observe(discovery, peer, pack):
    transport, received = peer
    await discovery.send(DISCOVERY_REQUEST, transport.get_extra_info("sockname"))
    data, source = await asyncio.wait_for(received.get(), DEFAULT_TIMEOUT)
    assert json.loads(data) == DISCOVERY_REQUEST
    transport.sendto(peer_packet({"t": "pack"}, pack), source)
    return await asyncio.wait_for(discovery.observations.get(), DEFAULT_TIMEOUT)


@pytest.mark.asyncio
async def test_recovery_discovery_canonical_identity_latest_snapshot_and_port():
    async with udp_peer() as old_peer, udp_peer() as new_peer, _recovery_discovery() as discovery:
        listener = _RecoveryListener()
        discovery.add_listener(listener)
        cache = discovery.devices
        initial = {"mac": "02:AA:BB:00:00:01", "name": "original"}
        old_info = await _recovery_observe(discovery, old_peer, initial)
        assert listener.events.get_nowait() == ("found", old_info)
        other = await _recovery_observe(
            discovery, old_peer, {"mac": "020000000002", "name": "other"}
        )
        assert listener.events.get_nowait() == ("found", other)
        metadata = {
            "mac": "02-AA-BB-00-00-01", "name": "latest", "brand": "new-brand",
            "model": "new-model", "ver": "new-version", "mid": "new-mid",
        }
        latest = await _recovery_observe(discovery, old_peer, metadata)
        assert discovery.devices is cache
        assert [info.mac for info in cache] == ["02:AA:BB:00:00:01", "020000000002"]
        assert cache[0] is latest
        assert cache[1] is other
        assert (latest.name, latest.brand, latest.model, latest.version, latest.mid) == (
            "latest", "new-brand", "new-model", "new-version", "new-mid"
        )
        assert listener.events.empty()

        for spelling in ("02AA.BB00.0001", "02aabb000001"):
            latest = await _recovery_observe(
                discovery, old_peer, {**metadata, "mac": spelling}
            )
            assert cache[0] is latest
            assert latest.mac == "02:AA:BB:00:00:01"
            assert listener.events.empty()

        replay = _RecoveryListener()
        await asyncio.wait_for(
            asyncio.gather(*discovery.add_listener(replay)), DEFAULT_TIMEOUT
        )
        assert replay.events.get_nowait() == ("found", latest)
        assert replay.events.get_nowait() == ("found", other)
        moved = await _recovery_observe(discovery, new_peer, metadata)
        assert listener.events.get_nowait() == ("update", moved)
        assert replay.events.get_nowait() == ("update", moved)
        assert discovery.devices is cache
        assert cache == [moved, other]
        assert cache[0] is moved
        assert (old_info.ip, old_info.port, old_info.name) == (
            "127.0.0.1", old_peer[0].get_extra_info("sockname")[1], "original"
        )
        assert moved.port == new_peer[0].get_extra_info("sockname")[1]
        await _recovery_observe(discovery, new_peer, metadata)
        assert listener.events.empty()
        assert replay.events.empty()


@pytest.mark.asyncio
async def test_recovery_discovery_ip_only_source_boundary():
    discovery = _RecoveryDiscovery()
    listener = _RecoveryListener()
    discovery.add_listener(listener)
    cache = discovery.devices
    pack = {"mac": "02AA.BB00.0001", "name": "portable"}
    discovery.packet_received({"pack": pack}, ("127.0.0.1", 7000))
    old_info = await asyncio.wait_for(discovery.observations.get(), DEFAULT_TIMEOUT)
    assert listener.events.get_nowait() == ("found", old_info)
    discovery.packet_received({"pack": pack}, ("127.0.0.2", 7000))
    moved = await asyncio.wait_for(discovery.observations.get(), DEFAULT_TIMEOUT)
    assert listener.events.get_nowait() == ("update", moved)
    assert discovery.devices is cache
    assert len(cache) == 1
    assert cache[0] is moved
    assert (moved.mac, moved.ip, moved.port) == ("02AA.BB00.0001", "127.0.0.2", 7000)
    assert (old_info.ip, old_info.port) == ("127.0.0.1", 7000)
    discovery.packet_received({"pack": pack}, ("127.0.0.2", 7000))
    await asyncio.wait_for(discovery.observations.get(), DEFAULT_TIMEOUT)
    assert listener.events.empty()


@pytest.mark.asyncio
async def test_recovery_discovery_ip_only_udp_move():
    async with AsyncExitStack() as stack:
        old_peer = await stack.enter_async_context(udp_peer())
        port = old_peer[0].get_extra_info("sockname")[1]
        try:
            new_peer = await stack.enter_async_context(udp_peer("127.0.0.2", port))
        except OSError as exc:
            pytest.skip(f"127.0.0.2:{port} unavailable: {exc!r}")
        discovery = await stack.enter_async_context(_recovery_discovery())
        listener = _RecoveryListener()
        discovery.add_listener(listener)
        pack = {"mac": "020000000001", "name": "moving"}
        old_info = await _recovery_observe(discovery, old_peer, pack)
        assert listener.events.get_nowait() == ("found", old_info)
        moved = await _recovery_observe(discovery, new_peer, pack)
        assert listener.events.get_nowait() == ("update", moved)
        assert len(discovery.devices) == 1
        assert discovery.devices[0] is moved
        assert (moved.ip, moved.port) == ("127.0.0.2", port)
        assert (old_info.ip, old_info.port) == ("127.0.0.1", port)
        await _recovery_observe(discovery, new_peer, pack)
        assert listener.events.empty()


@pytest.mark.asyncio
@pytest.mark.parametrize("pack", [
    None, [], ["not-a-dictionary"], "not-a-dictionary", 7,
    {}, {"name": "missing"}, {"mac": None}, {"mac": ""},
    {"mac": ":-."}, {"cid": None}, {"cid": ""}, {"cid": 123},
    {"mac": 123, "cid": "020000000001"},
    {"mac": [], "cid": "020000000001"},
    {"mac": "", "cid": ["020000000001"]},
])
async def test_recovery_discovery_rejects_invalid_packet_identity(pack):
    discovery = Discovery()
    try:
        discovery.packet_received({"pack": pack}, ("127.0.0.1", 7000))
        assert discovery.tasks == []
        assert discovery.devices == []
    finally:
        if discovery.tasks:
            await asyncio.wait_for(
                asyncio.gather(*discovery.tasks, return_exceptions=True), DEFAULT_TIMEOUT
            )


@pytest.mark.asyncio
@pytest.mark.parametrize("identity,expected", [
    ({"mac": "02:AA:BB:00:00:01", "cid": 123}, "02:AA:BB:00:00:01"),
    ({"mac": "02:AA:BB:00:00:01", "cid": "different"}, "02:AA:BB:00:00:01"),
    ({"cid": "02-AA-BB-00-00-01"}, "02-AA-BB-00-00-01"),
    ({"mac": None, "cid": "02AA.BB00.0001"}, "02AA.BB00.0001"),
    ({"mac": "", "cid": "02AA.BB00.0001"}, "02AA.BB00.0001"),
    ({"mac": "02:00:00:00:00:00:01"}, "02:00:00:00:00:00:01"),
])
async def test_recovery_discovery_accepts_valid_identity_precedence(identity, expected):
    async with udp_peer() as peer, _recovery_discovery() as discovery:
        info = await _recovery_observe(discovery, peer, {**identity, "name": "identity"})
        assert len(discovery.devices) == 1
        assert discovery.devices[0] is info
        assert info.mac == expected


@pytest.mark.asyncio
async def test_recovery_discovery_duplicate_while_listener_waits_and_exceptions():
    entered = asyncio.Event()
    release = asyncio.Event()
    events = asyncio.Queue()

    class SlowListener(Listener):
        async def device_found(self, device_info):
            entered.set()
            await release.wait()
            events.put_nowait(("found", device_info))

        async def device_update(self, device_info):
            events.put_nowait(("update", device_info))

    class BrokenListener(Listener):
        async def device_found(self, device_info):
            raise RuntimeError("synthetic listener failure")

        async def device_update(self, device_info):
            raise RuntimeError("synthetic listener failure")

    async with udp_peer() as peer, udp_peer() as moved_peer, _recovery_discovery() as discovery:
        discovery.add_listener(BrokenListener())
        discovery.add_listener(SlowListener())
        try:
            await discovery.send(DISCOVERY_REQUEST, peer[0].get_extra_info("sockname"))
            _, source = await asyncio.wait_for(peer[1].get(), DEFAULT_TIMEOUT)
            packet = peer_packet({"t": "pack"}, {"mac": "020000000001", "name": "slow"})
            peer[0].sendto(packet, source)
            await asyncio.wait_for(entered.wait(), DEFAULT_TIMEOUT)
            peer[0].sendto(packet, source)
            await asyncio.wait_for(discovery.observations.get(), DEFAULT_TIMEOUT)
            assert len(discovery.devices) == 1
        finally:
            release.set()
        await asyncio.wait_for(discovery.observations.get(), DEFAULT_TIMEOUT)
        assert events.get_nowait()[0] == "found"
        assert events.empty()
        moved = await _recovery_observe(
            discovery, moved_peer, {"mac": "020000000001", "name": "slow"}
        )
        assert events.get_nowait() == ("update", moved)
        assert events.empty()


@pytest.mark.asyncio
async def test_recovery_discovery_simultaneous_searches_share_endpoint():
    discovery = _RecoveryDiscovery()
    loop = asyncio.get_running_loop()
    transports = []
    create_endpoint = loop.create_datagram_endpoint

    async def record_endpoint(*args, **kwargs):
        transport, protocol = await create_endpoint(*args, **kwargs)
        transports.append(transport)
        return transport, protocol

    async with udp_peer(port=7000) as peer:
        try:
            with patch.object(loop, "create_datagram_endpoint", side_effect=record_endpoint):
                await asyncio.wait_for(asyncio.gather(*(
                    discovery.search_on_interface(IPv4Address("127.0.0.1"))
                    for _ in range(3)
                )), DEFAULT_TIMEOUT)
            requests = [
                await asyncio.wait_for(peer[1].get(), DEFAULT_TIMEOUT)
                for _ in range(3)
            ]
            assert all(json.loads(data) == DISCOVERY_REQUEST for data, _ in requests)
            assert len({source for _, source in requests}) == 1
            assert len(transports) == 1
            peer[0].sendto(
                peer_packet({"t": "pack"}, {"mac": "020000000001", "name": "shared"}),
                requests[0][1],
            )
            await asyncio.wait_for(discovery.observations.get(), DEFAULT_TIMEOUT)
            assert len(discovery.devices) == 1
        finally:
            if discovery._transport is not None:
                discovery.close()
            for transport in transports:
                if not transport.is_closing():
                    transport.close()
            for _ in transports:
                await asyncio.wait_for(discovery.closed_transports.get(), DEFAULT_TIMEOUT)


@pytest.mark.asyncio
async def test_recovery_discovery_close_cancels_scheduled_searches():
    discovery = _RecoveryDiscovery()
    loop = asyncio.get_running_loop()
    search = None
    async with udp_peer(port=7000) as peer:
        try:
            with patch.object(loop, "create_datagram_endpoint", wraps=loop.create_datagram_endpoint) as create_endpoint:
                search = asyncio.create_task(discovery.search_devices(
                    target_addresses=[IPv4Address("127.0.0.1")] * 2
                ))
                await asyncio.sleep(0)
                pending = tuple(discovery.tasks)
                discovery.close()
                discovery.close()
                await asyncio.wait_for(search, DEFAULT_TIMEOUT)
                create_endpoint.assert_not_called()
            assert len(pending) == 2
            assert all(task.cancelled() for task in pending)
            assert discovery.tasks == []
            assert discovery._transport is None and discovery._closing
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(peer[1].get(), 0.05)

            await discovery.search_devices(target_addresses=[IPv4Address("127.0.0.1")])
            data, _ = await asyncio.wait_for(peer[1].get(), DEFAULT_TIMEOUT)
            assert json.loads(data) == DISCOVERY_REQUEST
            assert discovery._transport is not None and not discovery._closing
            assert discovery.tasks == []
        finally:
            discovery.close()
            if search is not None:
                if not search.done():
                    search.cancel()
                await asyncio.gather(search, return_exceptions=True)
            await asyncio.wait_for(discovery._transport_closed.wait(), DEFAULT_TIMEOUT)


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["before_connection", "after_connection"])
@pytest.mark.parametrize("method", ["search_devices", "search_on_interface"])
async def test_recovery_discovery_close_during_endpoint_creation(phase, method):
    discovery = _RecoveryDiscovery()
    loop = asyncio.get_running_loop()
    create_endpoint = loop.create_datagram_endpoint
    entered, release, cancelled = asyncio.Event(), asyncio.Event(), asyncio.Event()
    transports = []
    search = None

    async def wait_for_close():
        entered.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            # Endpoint completion can win its race with cancellation.
            cancelled.set()
            await release.wait()

    async def gated_endpoint(*args, **kwargs):
        if phase == "before_connection":
            await wait_for_close()
        transport, protocol = await create_endpoint(*args, **kwargs)
        transports.append(transport)
        if phase == "after_connection":
            await wait_for_close()
        return transport, protocol

    async with udp_peer(port=7000) as peer:
        try:
            with patch.object(loop, "create_datagram_endpoint", side_effect=gated_endpoint):
                if method == "search_devices":
                    search = asyncio.create_task(discovery.search_devices(
                        target_addresses=[IPv4Address("127.0.0.1")] * 2
                    ))
                else:
                    search = asyncio.create_task(discovery.search_on_interface(IPv4Address("127.0.0.1")))
                await asyncio.wait_for(entered.wait(), DEFAULT_TIMEOUT)
                discovery.close()
                discovery.close()
                release.set()
                await asyncio.wait_for(search, DEFAULT_TIMEOUT)
            await asyncio.wait_for(discovery._transport_closed.wait(), DEFAULT_TIMEOUT)
            if method == "search_devices":
                assert cancelled.is_set()
            assert len(transports) == 1 and transports[0].is_closing()
            assert discovery._transport is None and discovery._closing
            assert discovery.tasks == []
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(peer[1].get(), 0.05)

            await discovery.search_devices(target_addresses=[IPv4Address("127.0.0.1")])
            data, _ = await asyncio.wait_for(peer[1].get(), DEFAULT_TIMEOUT)
            assert json.loads(data) == DISCOVERY_REQUEST
            assert discovery._transport is not transports[0] and not discovery._closing
            assert discovery.tasks == []
        finally:
            release.set()
            discovery.close()
            if search is not None:
                if not search.done():
                    search.cancel()
                await asyncio.gather(search, return_exceptions=True)
            for transport in transports:
                transport.close()
            await asyncio.wait_for(discovery._transport_closed.wait(), DEFAULT_TIMEOUT)


@pytest.mark.asyncio
async def test_recovery_discovery_close_invalidates_direct_search_waiting_for_endpoint_lock():
    discovery = _RecoveryDiscovery()
    loop = asyncio.get_running_loop()
    create_endpoint = loop.create_datagram_endpoint
    entered, release, queued = asyncio.Event(), asyncio.Event(), asyncio.Event()
    transports = []
    searches = []

    async def gated_endpoint(*args, **kwargs):
        entered.set()
        await release.wait()
        transport, protocol = await create_endpoint(*args, **kwargs)
        transports.append(transport)
        return transport, protocol

    async def queued_search():
        queued.set()
        await discovery.search_on_interface(IPv4Address("127.0.0.1"))

    async with udp_peer(port=7000) as peer:
        try:
            with patch.object(loop, "create_datagram_endpoint", side_effect=gated_endpoint):
                searches.append(asyncio.create_task(
                    discovery.search_on_interface(IPv4Address("127.0.0.1"))
                ))
                await asyncio.wait_for(entered.wait(), DEFAULT_TIMEOUT)
                searches.append(asyncio.create_task(queued_search()))
                await asyncio.wait_for(queued.wait(), DEFAULT_TIMEOUT)
                assert discovery._endpoint_lock.locked()
                assert not searches[1].done()
                discovery.close()
                release.set()
                await asyncio.wait_for(asyncio.gather(*searches), DEFAULT_TIMEOUT)
            await asyncio.wait_for(discovery._transport_closed.wait(), DEFAULT_TIMEOUT)
            assert len(transports) == 1 and transports[0].is_closing()
            assert discovery._transport is None and discovery._closing
            assert discovery.tasks == []
            assert not discovery._endpoint_lock.locked()
            assert all(search.done() and not search.cancelled() for search in searches)
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(peer[1].get(), 0.05)

            await discovery.search_on_interface(IPv4Address("127.0.0.1"))
            data, source = await asyncio.wait_for(peer[1].get(), DEFAULT_TIMEOUT)
            assert json.loads(data) == DISCOVERY_REQUEST
            assert discovery._transport is not transports[0] and not discovery._closing
            peer[0].sendto(
                peer_packet({"t": "pack"}, {"mac": "020000000001", "name": "reopened"}),
                source,
            )
            observed = await asyncio.wait_for(discovery.observations.get(), DEFAULT_TIMEOUT)
            assert discovery.devices == [observed]
            assert observed.name == "reopened"
        finally:
            release.set()
            discovery.close()
            for search in searches:
                if not search.done():
                    search.cancel()
            await asyncio.gather(*searches, return_exceptions=True)
            for transport in transports:
                transport.close()
            await asyncio.wait_for(discovery._transport_closed.wait(), DEFAULT_TIMEOUT)


@pytest.mark.asyncio
async def test_recovery_discovery_close_invalidates_direct_search_waiting_for_transport_closure():
    discovery = _RecoveryDiscovery()
    loop = asyncio.get_running_loop()
    closure_pending, entered = asyncio.Event(), asyncio.Event()
    deferred = []
    search = None

    def defer_connection_lost(exc):
        deferred.append(exc)
        closure_pending.set()

    async def waiting_search():
        entered.set()
        await discovery.search_on_interface(IPv4Address("127.0.0.1"))

    async with udp_peer(port=7000) as peer:
        try:
            await loop.create_datagram_endpoint(
                lambda: discovery, local_addr=("127.0.0.1", 0)
            )
            old_transport = discovery._transport
            with patch.object(discovery, "connection_lost", side_effect=defer_connection_lost):
                discovery.close()
                await asyncio.wait_for(closure_pending.wait(), DEFAULT_TIMEOUT)
            with patch.object(loop, "create_datagram_endpoint", wraps=loop.create_datagram_endpoint) as create_endpoint:
                search = asyncio.create_task(waiting_search())
                await asyncio.wait_for(entered.wait(), DEFAULT_TIMEOUT)
                assert not discovery._transport_closed.is_set()
                assert discovery._endpoint_lock.locked()
                assert not search.done()
                discovery.close()
                discovery.connection_lost(deferred.pop())
                await asyncio.wait_for(search, DEFAULT_TIMEOUT)
                create_endpoint.assert_not_called()
            assert old_transport.is_closing()
            assert discovery._transport is None and discovery._closing
            assert discovery.tasks == []
            assert not discovery._endpoint_lock.locked()
            assert not search.cancelled()
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(peer[1].get(), 0.05)

            await discovery.search_on_interface(IPv4Address("127.0.0.1"))
            data, source = await asyncio.wait_for(peer[1].get(), DEFAULT_TIMEOUT)
            assert json.loads(data) == DISCOVERY_REQUEST
            assert discovery._transport is not old_transport and not discovery._closing
            peer[0].sendto(
                peer_packet({"t": "pack"}, {"mac": "020000000001", "name": "reopened"}),
                source,
            )
            observed = await asyncio.wait_for(discovery.observations.get(), DEFAULT_TIMEOUT)
            assert discovery.devices == [observed]
            assert observed.name == "reopened"
        finally:
            if deferred:
                discovery.connection_lost(deferred.pop())
            discovery.close()
            if search is not None:
                if not search.done():
                    search.cancel()
                await asyncio.gather(search, return_exceptions=True)
            await asyncio.wait_for(discovery._transport_closed.wait(), DEFAULT_TIMEOUT)


@pytest.mark.asyncio
async def test_recovery_discovery_close_cancels_listener_and_reopens():
    discovery = _RecoveryDiscovery()
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    never = asyncio.Event()

    class WaitingListener(Listener):
        async def device_found(self, device_info):
            entered.set()
            try:
                await never.wait()
            finally:
                cancelled.set()

    async with udp_peer(port=7000) as peer:
        try:
            listener = WaitingListener()
            discovery.add_listener(listener)
            await discovery.search_on_interface(IPv4Address("127.0.0.1"))
            data, old_source = await asyncio.wait_for(peer[1].get(), DEFAULT_TIMEOUT)
            assert json.loads(data) == DISCOVERY_REQUEST
            packet = peer_packet({"t": "pack"}, {"mac": "020000000001", "name": "before"})
            peer[0].sendto(packet, old_source)
            await asyncio.wait_for(entered.wait(), DEFAULT_TIMEOUT)
            old_transport = discovery._transport
            pending = tuple(discovery.tasks)
            discovery.close()
            discovery.close()
            await asyncio.wait_for(cancelled.wait(), DEFAULT_TIMEOUT)
            await asyncio.wait_for(
                asyncio.gather(*pending, return_exceptions=True), DEFAULT_TIMEOUT
            )
            await asyncio.wait_for(discovery.closed_transports.get(), DEFAULT_TIMEOUT)
            assert old_transport.is_closing()
            assert discovery.remove_listener(listener) is False
            peer[0].sendto(
                peer_packet({"t": "pack"}, {"mac": "020000000099", "name": "late"}),
                old_source,
            )
            assert discovery.tasks == []
            assert len(discovery.devices) == 1

            await discovery.search_on_interface(IPv4Address("127.0.0.1"))
            data, source = await asyncio.wait_for(peer[1].get(), DEFAULT_TIMEOUT)
            assert json.loads(data) == DISCOVERY_REQUEST
            assert discovery._transport is not old_transport
            fresh_listener = _RecoveryListener()
            await asyncio.wait_for(
                asyncio.gather(*discovery.add_listener(fresh_listener)), DEFAULT_TIMEOUT
            )
            assert fresh_listener.events.get_nowait()[0] == "found"
            peer[0].sendto(
                peer_packet({"t": "pack"}, {"mac": "020000000001", "name": "after"}),
                source,
            )
            observed = await asyncio.wait_for(discovery.observations.get(), DEFAULT_TIMEOUT)
            assert observed.name == "after"
            assert discovery.devices[0] is observed
            assert fresh_listener.events.empty()
        finally:
            never.set()
            if discovery._transport is not None:
                discovery.close()
                await asyncio.wait_for(discovery.closed_transports.get(), DEFAULT_TIMEOUT)
            if discovery.tasks:
                await asyncio.wait_for(
                    asyncio.gather(*discovery.tasks, return_exceptions=True), DEFAULT_TIMEOUT
                )


@pytest.mark.asyncio
async def test_recovery_discovery_enrollment_requires_explicit_selection():
    async with udp_peer() as peer, _recovery_discovery() as discovery:
        listener = _RecoveryListener()
        discovery.add_listener(listener)
        for mac in ("020000000001", "020000000002"):
            info = await _recovery_observe(
                discovery, peer, {"mac": mac, "name": "not-yet-approved"}
            )
            assert listener.events.get_nowait() == ("found", info)
        assert len(discovery.devices) == 2
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(peer[1].get(), 0.05)

        selected = discovery.devices[1]
        device = Device(selected, bind_timeout=DEFAULT_TIMEOUT)
        bind = asyncio.create_task(device.bind(cipher=CipherV1()))
        try:
            data, source = await asyncio.wait_for(peer[1].get(), DEFAULT_TIMEOUT)
            request = peer_reply(data, b"a3K8Bx%2r8Y7#xDh")
            assert request["inner"]["t"] == "bind"
            assert request["inner"]["mac"] == selected.mac
            assert request["outer"]["tcid"] == selected.mac
            key = b"0123456789abcdef"
            peer[0].sendto(
                peer_packet(
                    {"t": "pack", "cid": selected.mac},
                    {"t": "bindok", "mac": selected.mac, "r": 200, "key": key.decode()},
                ),
                source,
            )
            await asyncio.wait_for(bind, DEFAULT_TIMEOUT)
            data, status_source = await asyncio.wait_for(peer[1].get(), DEFAULT_TIMEOUT)
            status = peer_reply(data, key)
            assert status_source == source
            assert status["inner"]["t"] == "status"
            assert status["inner"]["mac"] == selected.mac
            assert status["outer"]["tcid"] == selected.mac
        finally:
            device.close()
            if not bind.done():
                bind.cancel()
            await asyncio.gather(bind, return_exceptions=True)


@pytest.mark.asyncio
async def test_recovery_discovery_port_only_update_preserves_old_snapshot():
    async with udp_peer() as old_peer, udp_peer() as new_peer, _recovery_discovery() as discovery:
        listener = _RecoveryListener()
        discovery.add_listener(listener)
        cache = discovery.devices
        pack = {"mac": "020000000001", "name": "same-metadata"}
        original = await _recovery_observe(discovery, old_peer, pack)
        assert listener.events.get_nowait() == ("found", original)
        moved = await _recovery_observe(discovery, new_peer, pack)
        assert listener.events.get_nowait() == ("update", moved)
        assert discovery.devices is cache
        assert len(cache) == 1
        assert cache[0] is moved
        assert (original.ip, original.port) == old_peer[0].get_extra_info("sockname")
        assert (moved.ip, moved.port) == new_peer[0].get_extra_info("sockname")
        await _recovery_observe(discovery, new_peer, pack)
        assert listener.events.empty()


@pytest.mark.asyncio
async def test_recovery_discovery_close_before_search_is_safe_and_reopenable():
    discovery = _RecoveryDiscovery()
    discovery.close()
    discovery.close()
    async with udp_peer(port=7000) as peer:
        try:
            await discovery.search_on_interface(IPv4Address("127.0.0.1"))
            data, source = await asyncio.wait_for(peer[1].get(), DEFAULT_TIMEOUT)
            assert json.loads(data) == DISCOVERY_REQUEST
            peer[0].sendto(
                peer_packet({"t": "pack"}, {"mac": "020000000001", "name": "reopened"}),
                source,
            )
            info = await asyncio.wait_for(discovery.observations.get(), DEFAULT_TIMEOUT)
            assert discovery.devices == [info]
        finally:
            if discovery._transport is not None:
                discovery.close()
                await asyncio.wait_for(discovery.closed_transports.get(), DEFAULT_TIMEOUT)


async def test_recovery_discovery_late_observations_cannot_revive_closed_owner():
    discovery = Discovery()
    listener = _RecoveryListener()
    initial = DeviceInfo("127.0.0.1", 7000, "020000000001", "saved")
    await discovery.device_found(initial)
    discovery.close()
    try:
        assert discovery.add_listener(listener) is None
        moved = DeviceInfo("127.0.0.1", 7001, initial.mac, "late")
        await discovery.device_found(moved)
        discovery.packet_received(
            {"pack": {"mac": "020000000002", "name": "late-new"}},
            ("127.0.0.1", 7002),
        )
        assert discovery.devices == [initial]
        assert discovery.devices[0] is initial
        assert listener.events.empty() and discovery.tasks == []
        assert discovery.remove_listener(listener) is False
    finally:
        discovery.close()


@pytest.mark.parametrize("mac", [None, "", ":-.", 123])
async def test_recovery_discovery_invalid_direct_observation_preserves_cache(mac):
    discovery = Discovery()
    listener = _RecoveryListener()
    discovery.add_listener(listener)
    initial = DeviceInfo("127.0.0.1", 7000, "020000000001", "saved")
    try:
        await discovery.device_found(initial)
        assert listener.events.get_nowait() == ("found", initial)
        await discovery.device_found(DeviceInfo("127.0.0.1", 7001, mac, "invalid"))
        assert discovery.devices == [initial] and listener.events.empty()
    finally:
        discovery.close()


@pytest.mark.asyncio
async def test_recovery_discovery_preserves_first_observed_mac_spelling():
    async with udp_peer() as peer, udp_peer() as new_peer, _recovery_discovery() as discovery:
        listener = _RecoveryListener()
        discovery.add_listener(listener)
        info = await _recovery_observe(
            discovery, peer, {"mac": "AA:BB:CC:11:22:33", "name": "spelling"}
        )
        assert info.mac == "AA:BB:CC:11:22:33"
        assert listener.events.get_nowait() == ("found", info)

        moved = await _recovery_observe(
            discovery, new_peer, {"mac": "aa-bb-cc-11-22-33", "name": "spelling"}
        )
        assert len(discovery.devices) == 1
        assert moved.mac == "AA:BB:CC:11:22:33"
        assert listener.events.get_nowait() == ("update", moved)
        assert discovery.devices[0] is moved

        refreshed = await _recovery_observe(
            discovery, new_peer, {"mac": "AA.BB.CC.11.22.33", "name": "renamed"}
        )
        assert refreshed.mac == "AA:BB:CC:11:22:33"
        assert refreshed.name == "renamed"
        assert listener.events.empty()

        replay = _RecoveryListener()
        await asyncio.wait_for(
            asyncio.gather(*discovery.add_listener(replay)), DEFAULT_TIMEOUT
        )
        assert replay.events.get_nowait() == ("found", refreshed)
        assert replay.events.empty()

        protocol = DeviceProtocol2()
        payload = protocol._generate_payload(Commands.BIND, discovery.devices[0], {"uid": 0})
        assert payload["tcid"] == "aabbcc112233"
        assert payload["pack"]["mac"] == "aabbcc112233"


async def deliver_atw_discovery(discovery, ip, mid=None):
    """Deliver fresh metadata without touching the shared discovery template."""
    pack = {
        "t": "dev", "mac": "001122334455", "cid": "001122334455",
        "name": "Synthetic ATW", "brand": "gree", "model": "gree", "ver": "V5.0.0.0",
    }
    if mid is not None:
        pack["mid"] = mid
    discovery.packet_received({"t": "pack", "pack": pack}, (ip, 7000))
    await asyncio.gather(*discovery.tasks)



@pytest.mark.asyncio
@pytest.mark.parametrize("mid", [None, "9300"])
async def test_discovery_delivers_optional_atw_mid(mid):
    discovery = Discovery()
    listener = MagicMock(spec_set=Listener)
    listener.device_found = AsyncMock()
    listener.device_update = AsyncMock()
    discovery.add_listener(listener)

    await deliver_atw_discovery(discovery, "192.0.2.10", mid)

    assert len(discovery.devices) == 1
    info = discovery.devices[0]
    assert info.mid == mid
    assert info.ip == "192.0.2.10"
    assert info.port == 7000
    assert info.mac == "001122334455"
    listener.device_found.assert_awaited_once_with(info)
    listener.device_update.assert_not_awaited()



@pytest.mark.asyncio
async def test_discovery_late_mid_and_omitted_mid_refresh_snapshots_without_events():
    discovery = Discovery()
    listener = MagicMock(spec_set=Listener)
    listener.device_found = AsyncMock()
    listener.device_update = AsyncMock()
    discovery.add_listener(listener)

    await deliver_atw_discovery(discovery, "192.0.2.10")
    first_info = discovery.devices[0]
    assert first_info.mid is None
    listener.device_found.assert_awaited_once_with(first_info)

    await deliver_atw_discovery(discovery, "192.0.2.10", "9300")
    assert len(discovery.devices) == 1
    mid_info = discovery.devices[0]
    assert mid_info is not first_info
    assert mid_info.mid == "9300"
    assert first_info.mid is None
    assert listener.device_found.await_count == 1
    listener.device_update.assert_not_awaited()

    await deliver_atw_discovery(discovery, "192.0.2.10")
    omitted_info = discovery.devices[0]
    assert omitted_info is not mid_info
    assert omitted_info.mid is None
    assert mid_info.mid == "9300"
    assert listener.device_found.await_count == 1
    listener.device_update.assert_not_awaited()

    await deliver_atw_discovery(discovery, "192.0.2.11")
    assert len(discovery.devices) == 1
    updated_info = discovery.devices[0]
    assert updated_info.ip == "192.0.2.11"
    assert updated_info.mid is None
    assert updated_info is not omitted_info
    assert omitted_info.ip == "192.0.2.10"
    assert listener.device_found.await_count == 1
    listener.device_update.assert_awaited_once_with(updated_info)

    await deliver_atw_discovery(discovery, "192.0.2.11", "9300")
    assert len(discovery.devices) == 1
    assert discovery.devices[0].mid == "9300"
    assert listener.device_found.await_count == 1
    assert listener.device_update.await_count == 1



@pytest.mark.asyncio
async def test_discovery_receives_late_mid_and_clears_omitted_mid_on_ip_change():
    discovery = Discovery()
    listener = MagicMock(spec_set=Listener)
    listener.device_found = AsyncMock()
    listener.device_update = AsyncMock()
    discovery.add_listener(listener)
    await deliver_atw_discovery(discovery, "192.0.2.10")
    first_info = discovery.devices[0]
    assert first_info.mid is None

    await deliver_atw_discovery(discovery, "192.0.2.11", "9300")
    assert len(discovery.devices) == 1
    info = discovery.devices[0]
    assert info.ip == "192.0.2.11"
    assert info.mid == "9300"
    assert (first_info.ip, first_info.mid) == ("192.0.2.10", None)
    assert listener.device_found.await_count == 1
    listener.device_update.assert_awaited_once_with(info)

    await deliver_atw_discovery(discovery, "192.0.2.12")
    assert len(discovery.devices) == 1
    assert discovery.devices[0].mid is None
    assert (info.ip, info.mid) == ("192.0.2.11", "9300")
    assert discovery.devices[0].ip == "192.0.2.12"
    assert listener.device_found.await_count == 1
    assert listener.device_update.await_count == 2
    assert listener.device_update.await_args.args[0] is discovery.devices[0]



@pytest.mark.asyncio
async def test_discovery_mid_family_changes_refresh_one_canonical_identity():
    discovery = Discovery()
    listener = MagicMock(spec_set=Listener)
    discovery.add_listener(listener)

    await deliver_atw_discovery(discovery, "192.0.2.10", "9300")
    atw_info = discovery.devices[0]
    await deliver_atw_discovery(discovery, "192.0.2.10", "10001")
    ac_info, = discovery.devices
    assert ac_info is not atw_info
    assert ac_info.mid == "10001"
    assert atw_info.mid == "9300"
    listener.device_found.assert_awaited_once_with(atw_info)
    listener.device_update.assert_not_awaited()

    await deliver_atw_discovery(discovery, "192.0.2.11", "9300")
    moved_info, = discovery.devices
    assert (moved_info.ip, moved_info.mid) == ("192.0.2.11", "9300")
    assert (ac_info.ip, ac_info.mid) == ("192.0.2.10", "10001")
    listener.device_found.assert_awaited_once_with(atw_info)
    listener.device_update.assert_awaited_once_with(moved_info)

