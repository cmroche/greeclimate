"""WB05DRA's original UDP listener admits only sender port 5001."""

import asyncio
import base64
from copy import deepcopy
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import pytest

from gree_emulator.__main__ import load_config
from gree_emulator.server import start_server
from tests.common import udp_peer


PROFILE = "sim-wb05dra-v2.05-coordinator"


def config(state=None):
    return {"devices": [{"id": "dra", "profile": PROFILE, "mid": "10001",
                         "state": state or {}}]}


@pytest.mark.parametrize("kind", ["scan", "plaintext-control", "encrypted-control"])
@pytest.mark.asyncio
async def test_dra_rejects_wrong_sender_port_before_any_mutation(kind):
    device = load_config(config())[2][0]
    before = deepcopy(device.state)
    inner = {"t": "metadata", "p": [1]}
    if kind == "scan":
        packet = {"t": "scan"}
    elif kind == "plaintext-control":
        packet = inner
    else:
        ciphertext = AES.new(device.key, AES.MODE_ECB).encrypt(
            pad(json.dumps(inner).encode(), 16))
        packet = {"t": "pack", "i": 0, "tcid": device.mac,
                  "pack": base64.b64encode(ciphertext).decode()}
    transport, server = await start_server([device], "127.0.0.1", 0)
    try:
        async with udp_peer() as (peer, received):
            assert peer.get_extra_info("sockname")[1] != 5001
            peer.sendto(json.dumps(packet).encode(), transport.get_extra_info("sockname"))
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(received.get(), 0.03)
            assert device.state == before
    finally:
        transport.close()
        await server.wait_closed()


@pytest.mark.parametrize("outbound", [["reset"], None, {}])
def test_config_cannot_inject_pending_coordinator_work(outbound):
    with pytest.raises(ValueError, match="outbound work must start as an empty list"):
        load_config(config({"outbound": outbound}))


def test_configuration_preflight_does_not_consume_discovery_sequence():
    device = load_config(config())[2][0]
    first = device.profile.handler.advertise(device, {"t": "scan"})[0]
    second = device.profile.handler.advertise(device, {"t": "scan"})[0]
    assert (first.outer["msgId"], second.outer["msgId"]) == (1, 2)
