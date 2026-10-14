"""Encrypted UDP gateway enumeration regressions."""
import asyncio
import json

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
    finally:
        device.close()
        transport.close()
