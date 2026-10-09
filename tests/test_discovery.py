import asyncio
import json
import socket
from ipaddress import IPv4Address
from threading import Thread
from unittest.mock import MagicMock, PropertyMock, patch

import ifaddr
import pytest

from greeclimate.discovery import Discovery, Listener
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
async def test_discover_devices(ifaddr_adapters, addr, family):
    ifaddr_adapters.return_value = [ifaddr.Adapter("lo", "lo", [ifaddr.IP(addr[0], 8, "lo")])]

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
        devices = await discovery.scan(wait_for=DEFAULT_TIMEOUT)
        assert devices is not None
        assert len(devices) == 3

        sock.close()
        serv.join(timeout=DEFAULT_TIMEOUT)


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
