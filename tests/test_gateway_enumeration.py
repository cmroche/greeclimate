"""Encrypted UDP gateway enumeration regressions."""
import asyncio
import json
from unittest.mock import patch

import pytest

from greeclimate.cipher import CipherV1
from greeclimate.device import Device
from greeclimate.deviceinfo import DeviceInfo


class Gateway(asyncio.DatagramProtocol):
    def __init__(self, responses, drop_first=None):
        self.responses = responses
        self.cipher = CipherV1(b"0123456789abcdef")
        self.requests = []
        self.drop_first = set(drop_first or [])

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        envelope = json.loads(data)
        generic = envelope.get("i") == 1
        cipher = CipherV1() if generic else self.cipher
        inner = cipher.decrypt(envelope["pack"]) if "pack" in envelope else {}
        label = "generic-key" if generic else inner.get("t", "plain")
        self.requests.append((label, envelope, inner))
        if label in self.drop_first:
            self.drop_first.remove(label)
            return
        if label not in self.responses:
            return
        body = {"t": "subList", "i": envelope["i"], "c": 6,
                "r": 200, "list": self.responses[label]}
        pack, _ = cipher.encrypt(body)
        self.transport.sendto(json.dumps({"t": "pack", "i": envelope["i"], "pack": pack}).encode(), addr)


def unit(number):
    return {"mac": f"aabbccdd{number:06x}", "mid": "608f"}


@pytest.mark.asyncio
@pytest.mark.parametrize("responses, expected", [
    ({"plain": [], "subList": [unit(i) for i in range(5)],
      "generic-key": [unit(i) for i in range(1, 6)], "subDev": []}, 6),
    ({"subDev": [unit(i) for i in range(3)]}, 3),
    ({"plain": [unit(1)], "subList": [unit(1)], "generic-key": [unit(1)], "subDev": [unit(1)]}, 1),
    ({"plain": [], "subList": [], "generic-key": [], "subDev": []}, 0),
])
@pytest.mark.parametrize("drop_first", [False, True])
async def test_gateway_enumeration_over_real_encrypted_udp(responses, expected, drop_first):
    loop = asyncio.get_running_loop()
    transport, gateway = await loop.create_datagram_endpoint(
        lambda: Gateway(responses, responses.keys() if drop_first else None), local_addr=("127.0.0.1", 0))
    info = DeviceInfo("127.0.0.1", transport.get_extra_info("sockname")[1], "aabbcc001122", "Gateway")
    device = Device(info, bind_timeout=0.05)
    cipher = CipherV1(b"0123456789abcdef")
    try:
        await device.bind(key=cipher.key, cipher=cipher)
        result = await device.get_sub_devices()
        assert len(result) == expected
        assert len({d.mac for d in result}) == expected
        assert device.device_cipher is cipher
        assert device.device_key == "0123456789abcdef"
        labels = [r[0] for r in gateway.requests]
        assert list(dict.fromkeys(labels)) == ["plain", "subList", "generic-key", "subDev"]
        for label in ("plain", "subList", "generic-key", "subDev"):
            assert labels.count(label) == (2 if drop_first or label not in responses else 1)
        assert all(r[1]["uid"] == 0 for r in gateway.requests)
        assert gateway.requests[-1][2]["cid"] == info.mac
        assert all(d.gateway_key == device.device_key for d in result)
        assert all(d.gateway_mac == info.mac for d in result)
    finally:
        device.close()
        transport.close()


def encrypted_sublist(cipher, entries, *, generic=False, outer_type=False):
    body = {"list": entries}
    if not outer_type:
        body["t"] = "subList"
    pack, _ = cipher.encrypt(body)
    return json.dumps({
        "t": "subList" if outer_type else "pack", "i": int(generic), "pack": pack,
    }).encode()


@pytest.mark.asyncio
@pytest.mark.parametrize("late_unit", [1, 3], ids=["duplicate", "additional-unit"])
async def test_delayed_bound_reply_does_not_finish_generic_enumeration(late_unit):
    """Issue 2: a late duplicate must not discard the generic-only indoor unit."""
    address = ("127.0.0.1", 7000)
    device = Device(DeviceInfo(*address, "aabbcc001122", "Gateway"), bind_timeout=1)
    cipher = CipherV1(b"0123456789abcdef")
    device.device_cipher = cipher
    bound_reply = encrypted_sublist(cipher, [unit(1)])
    generic_reply = encrypted_sublist(CipherV1(), [unit(2)], generic=True)
    generic_requested = asyncio.Event()
    release_subdev = asyncio.Event()

    async def send(packet, **kwargs):
        if packet["i"] == 1:
            # Deliver a delayed duplicate from a previous bound-key query first.
            device.datagram_received(encrypted_sublist(cipher, [unit(late_unit)]), address)
            generic_requested.set()
        else:
            if packet.get("pack", {}).get("t") == "subDev":
                await release_subdev.wait()
            device.datagram_received(bound_reply, address)

    with patch.object(device, "send", side_effect=send):
        query = asyncio.create_task(device.get_sub_devices())
        try:
            await asyncio.wait_for(generic_requested.wait(), 1)
            # Drain ready callbacks without a wall-clock race between packet timers.
            for _ in range(10):
                await asyncio.sleep(0)
            device.datagram_received(generic_reply, address)
            release_subdev.set()
            result = await asyncio.wait_for(query, 1)
            assert {info.mac for info in result} == {
                unit(1)["mac"], unit(2)["mac"], unit(late_unit)["mac"],
            }
        finally:
            release_subdev.set()
            if not query.done():
                query.cancel()
            await asyncio.gather(query, return_exceptions=True)


@pytest.mark.asyncio
async def test_generic_enumeration_accepts_outer_response_type():
    """Issue 3: outer subList type must survive generic-key packet decryption."""
    address = ("127.0.0.1", 7000)
    device = Device(DeviceInfo(*address, "aabbcc001122", "Gateway"), bind_timeout=1)
    cipher = CipherV1(b"0123456789abcdef")
    device.device_cipher = cipher

    async def send(packet, **kwargs):
        generic = packet["i"] == 1
        reply = encrypted_sublist(
            CipherV1() if generic else cipher,
            [unit(2)] if generic else [unit(1)],
            generic=generic,
            outer_type=generic,
        )
        device.datagram_received(reply, address)

    with patch.object(device, "send", side_effect=send):
        result = await asyncio.wait_for(device.get_sub_devices(), 1)

    assert {info.mac for info in result} == {unit(1)["mac"], unit(2)["mac"]}


@pytest.mark.asyncio
async def test_delayed_bound_status_during_generic_enumeration():
    address = ("127.0.0.1", 7000)
    device = Device(DeviceInfo(*address, "aabbcc001122", "Gateway"), bind_timeout=1)
    cipher = CipherV1(b"0123456789abcdef")
    device.device_cipher = cipher
    status_pack, _ = cipher.encrypt({"t": "dat", "cols": ["Pow"], "dat": [1]})
    delayed_status = json.dumps({"t": "pack", "i": 1, "pack": status_pack}).encode()

    async def send(packet, **kwargs):
        generic = packet["i"] == 1
        if generic:
            device.datagram_received(delayed_status, address)
            assert device.power is True
            assert device.device_cipher is cipher
        device.datagram_received(encrypted_sublist(
            CipherV1() if generic else cipher,
            [unit(2)] if generic else [unit(1)],
            generic=generic,
        ), address)

    with patch.object(device, "send", side_effect=send):
        result = await asyncio.wait_for(device.get_sub_devices(), 1)
    assert {info.mac for info in result} == {unit(1)["mac"], unit(2)["mac"]}
    assert device.power is True
    assert device.device_cipher is cipher
    assert device.device_key == "0123456789abcdef"


@pytest.mark.asyncio
async def test_gateway_enumeration_skips_malformed_entries_and_merges_mac_formats():
    first = {"mac": "AA:BB:CC:DD:EE:FF", "name": "First indoor unit"}
    responses = {
        "plain": [None, 1, "invalid", [], {}, {"mac": None}, {"mac": 123},
                  {"mac": ""}, {"mac": " \t"}, first],
        "subList": [{"mac": "aabbccddeeff", "name": "Duplicate"}, unit(2)],
        "generic-key": [{"mac": "aa-bb-cc-dd-ee-ff"}, unit(2)],
        "subDev": [],
    }
    loop = asyncio.get_running_loop()
    transport, gateway = await loop.create_datagram_endpoint(
        lambda: Gateway(responses), local_addr=("127.0.0.1", 0))
    info = DeviceInfo("127.0.0.1", transport.get_extra_info("sockname")[1], "aabbcc001122", "Gateway")
    device = Device(info, bind_timeout=1)
    cipher = CipherV1(b"0123456789abcdef")
    try:
        await device.bind(key=cipher.key, cipher=cipher)
        result = await asyncio.wait_for(device.get_sub_devices(), 2)
        assert [indoor.mac for indoor in result] == [first["mac"], unit(2)["mac"]]
        assert result[0].name == first["name"]
        assert [request[0] for request in gateway.requests] == ["plain", "subList", "generic-key", "subDev"]
        assert all(indoor.gateway_cipher is cipher for indoor in result)
    finally:
        device.close()
        transport.close()
