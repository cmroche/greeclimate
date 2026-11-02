import asyncio

import pytest
from gree_emulator.__main__ import load_config
from gree_emulator.server import start_server
from greeclimate.device import Device, DeviceInfo
from greeclimate.mid_profile import (
    FALLBACK_MID_PROFILE, KNOWN_MID_PROFILES, match_mid_profile,
)
from greeclimate.network import Response


@pytest.mark.asyncio
async def test_11002_default_poll_exposes_climate_state():
    emulator = load_config({"seed": "mid-profile-test", "devices": [{
        "id": "office", "profile": "sim-w04n-v17", "mid": "11002",
        "room_c": 19, "ambient_c": 19,
        "state": {
            "Pow": 1, "Mod": 1, "SetTem": 24, "TemUn": 0, "TemRec": 0,
            "Air": 1, "Blo": 1, "Lig": 0, "SwingLfRig": 6, "SwUpDn": 11,
        },
    }]})[2][0]
    transport, server = await start_server([emulator], "127.0.0.1", 0)
    host, port = transport.get_extra_info("sockname")
    device = Device(DeviceInfo(host, port, emulator.mac, emulator.name, mid="11002"))
    events = asyncio.Queue()
    device.add_handler(Response.DATA, events.put_nowait)
    try:
        await device.bind()
        await asyncio.wait_for(events.get(), 2)
        assert device.current_temperature == 19
        assert device.target_temperature == 24
        assert device.horizontal_swing == 6
        assert device.vertical_swing == 11
        assert device.fresh_air is True
        assert device.xfan is True
        assert device.light is False
    finally:
        device.close()
        server.close()
        await asyncio.gather(
            device._transport_closed.wait(),
            server.wait_closed(),
            *device.tasks,
            return_exceptions=True,
        )


@pytest.mark.parametrize("mid", ["0001", "10f01"])
def test_exact_mid_matches_registry_object(mid):
    expected = next(profile for profile in KNOWN_MID_PROFILES if profile.mid == mid)
    assert match_mid_profile(mid) is expected


@pytest.mark.parametrize("mid", [
    1, "1", "10F01", " 0001", "unrecorded", None, "", [], {},
])
def test_unknown_or_malformed_mid_uses_fallback(mid):
    assert match_mid_profile(mid) is FALLBACK_MID_PROFILE
