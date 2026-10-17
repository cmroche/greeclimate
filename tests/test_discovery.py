import asyncio
import json
import socket
from ipaddress import IPv4Address
from threading import Thread
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import ifaddr
import pytest

from greeclimate.discovery import Discovery, Listener
from greeclimate.device import Device
from greeclimate.deviceinfo import DeviceInfo
from .common import (
    DEFAULT_TIMEOUT,
    DISCOVERY_REQUEST,
    DISCOVERY_RESPONSE,
    Responder,
    get_mock_device_info, encrypt_payload, encrypt_payload_v2,
)


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


@pytest.mark.asyncio
@patch.object(Discovery, "_query_gateway", new_callable=AsyncMock)
async def test_discovery_sub_count(query_gateway):
    """Test that subCnt from scan response is passed to DeviceInfo."""
    discovery = Discovery(allow_loopback=True)
    discovery.packet_received(
        {
            "pack": {
                "mac": "aabbcc112233",
                "cid": "aabbcc112233",
                "name": "GatewayDevice",
                "brand": "gree",
                "model": "gree",
                "ver": "V1.0.0",
                "subCnt": 3,
            }
        },
        ("1.1.1.1", 7000),
    )

    await asyncio.gather(*discovery.tasks, return_exceptions=True)

    assert len(discovery.devices) == 1
    assert discovery.devices[0].sub_count == 3


@pytest.mark.asyncio
async def test_discovery_no_sub_count():
    """Test that devices without subCnt default to 0."""
    discovery = Discovery(allow_loopback=True)
    discovery.packet_received(
        {
            "pack": {
                "mac": "aabbcc112233",
                "cid": "aabbcc112233",
                "name": "RegularDevice",
                "brand": "gree",
                "model": "gree",
                "ver": "V1.0.0",
            }
        },
        ("1.1.1.1", 7000),
    )

    await asyncio.gather(*discovery.tasks, return_exceptions=True)

    assert len(discovery.devices) == 1
    assert discovery.devices[0].sub_count == 0


@pytest.mark.asyncio
async def test_scan_queries_gateway_sub_devices():
    """Test that scan queries gateways for sub-devices and returns them."""
    discovery = Discovery(allow_loopback=True)

    gw_info = DeviceInfo("1.1.1.1", 7000, "aabbcc001122", "Gateway", sub_count=2)

    sub_infos = [
        DeviceInfo("1.1.1.1", 7000, "sub111111", "Sub1", gateway_key="test_key"),
        DeviceInfo("1.1.1.1", 7000, "sub222222", "Sub2", gateway_key="test_key"),
    ]

    async def fake_search(*args, **kwargs):
        await discovery.device_found(gw_info)

    with patch.object(Discovery, "search_devices", side_effect=fake_search), \
         patch.object(Device, "bind", new_callable=AsyncMock), \
         patch.object(Device, "get_sub_devices", new_callable=AsyncMock, return_value=sub_infos), \
         patch.object(Device, "close"):
        devices = await discovery.scan(wait_for=1)

    assert len(devices) == 2
    assert devices[0].mac == "sub111111"
    assert devices[1].mac == "sub222222"


@pytest.mark.asyncio
async def test_scan_include_gateways():
    """Test that scan includes gateways when include_gateways=True."""
    discovery = Discovery(allow_loopback=True)

    gw_info = DeviceInfo("1.1.1.1", 7000, "aabbcc001122", "Gateway", sub_count=2)

    sub_infos = [
        DeviceInfo("1.1.1.1", 7000, "sub111111", "Sub1", gateway_key="test_key"),
    ]

    async def fake_search(*args, **kwargs):
        await discovery.device_found(gw_info)

    with patch.object(Discovery, "search_devices", side_effect=fake_search), \
         patch.object(Device, "bind", new_callable=AsyncMock), \
         patch.object(Device, "get_sub_devices", new_callable=AsyncMock, return_value=sub_infos), \
         patch.object(Device, "close"):
        devices = await discovery.scan(wait_for=1, include_gateways=True)

    assert len(devices) == 2
    macs = {d.mac for d in devices}
    assert "aabbcc001122" in macs
    assert "sub111111" in macs


@pytest.mark.asyncio
async def test_scan_gateway_bind_failure():
    """Test that scan handles gateway bind failure gracefully."""
    from greeclimate.exceptions import DeviceNotBoundError

    discovery = Discovery(allow_loopback=True)
    gw_info = DeviceInfo("1.1.1.1", 7000, "aabbcc001122", "Gateway", sub_count=2)

    async def fake_search(*args, **kwargs):
        await discovery.device_found(gw_info)

    with patch.object(Discovery, "search_devices", side_effect=fake_search), \
         patch.object(Device, "bind", new_callable=AsyncMock, side_effect=DeviceNotBoundError), \
         patch.object(Device, "close", side_effect=RuntimeError):
        devices = await discovery.scan(wait_for=1)

    assert len(devices) == 0


@pytest.mark.asyncio
async def test_scan_gateway_timeout_failure():
    """Test that scan handles gateway timeout gracefully."""
    from greeclimate.exceptions import DeviceTimeoutError

    discovery = Discovery(allow_loopback=True)
    gw_info = DeviceInfo("1.1.1.1", 7000, "aabbcc001122", "Gateway", sub_count=2)

    async def fake_search(*args, **kwargs):
        await discovery.device_found(gw_info)

    with patch.object(Discovery, "search_devices", side_effect=fake_search), \
         patch.object(Device, "bind", new_callable=AsyncMock, side_effect=DeviceTimeoutError), \
         patch.object(Device, "close"):
        devices = await discovery.scan(wait_for=1)

    assert len(devices) == 0


@pytest.mark.asyncio
async def test_scan_include_gateways_notifies_listeners():
    """Test that gateway devices notify listeners when include_gateways=True."""
    discovery = Discovery(allow_loopback=True)
    gw_info = DeviceInfo("1.1.1.1", 7000, "aabbcc001122", "Gateway", sub_count=2)

    listener = MagicMock(spec_set=Listener)
    listener.device_found = AsyncMock()
    discovery.add_listener(listener)

    sub_infos = [
        DeviceInfo("1.1.1.1", 7000, "sub111111", "Sub1", gateway_key="test_key"),
    ]

    async def fake_search(*args, **kwargs):
        await discovery.device_found(gw_info)

    with patch.object(Discovery, "search_devices", side_effect=fake_search), \
         patch.object(Device, "bind", new_callable=AsyncMock), \
         patch.object(Device, "get_sub_devices", new_callable=AsyncMock, return_value=sub_infos), \
         patch.object(Device, "close"):
        await discovery.scan(wait_for=1, include_gateways=True)

    # Listener should be notified for both gateway and sub-device
    found_macs = [call.args[0].mac for call in listener.device_found.call_args_list]
    assert "aabbcc001122" in found_macs
    assert "sub111111" in found_macs


@pytest.mark.asyncio
async def test_scan_exclude_gateways_skips_listener():
    """Test that gateway devices do NOT notify listeners when include_gateways=False."""
    discovery = Discovery(allow_loopback=True)
    gw_info = DeviceInfo("1.1.1.1", 7000, "aabbcc001122", "Gateway", sub_count=1)

    listener = MagicMock(spec_set=Listener)
    listener.device_found = AsyncMock()
    discovery.add_listener(listener)

    sub_infos = [
        DeviceInfo("1.1.1.1", 7000, "sub111111", "Sub1", gateway_key="test_key"),
    ]

    async def fake_search(*args, **kwargs):
        await discovery.device_found(gw_info)

    with patch.object(Discovery, "search_devices", side_effect=fake_search), \
         patch.object(Device, "bind", new_callable=AsyncMock), \
         patch.object(Device, "get_sub_devices", new_callable=AsyncMock, return_value=sub_infos), \
         patch.object(Device, "close"):
        devices = await discovery.scan(wait_for=1)

    # scan() return excludes gateways
    assert len(devices) == 1
    assert devices[0].mac == "sub111111"

    # Listener should only be notified for sub-device, not gateway
    found_macs = [call.args[0].mac for call in listener.device_found.call_args_list]
    assert "aabbcc001122" not in found_macs
    assert "sub111111" in found_macs
