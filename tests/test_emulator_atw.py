"""Independent exact-build LAN vectors and explicit, uncalibrated ATW model policy."""

import asyncio
import copy
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from gree_emulator.__main__ import load_config
from gree_emulator.server import start_server
from gree_emulator.wire import InvalidPacket, decode_outer, decode_pack, encode_reply
from greeclimate.air_to_water import AirToWaterDevice, AirToWaterMode
from greeclimate.device_factory import create_device
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.network import Response
from tests.test_emulator import (
    GENERIC_KEY, VECTOR_DIRECTORY, peer_packet, peer_reply, receive, vector_device,
)


MAC = "020000000001"
KEY = b"0123456789abcdef"


def device_for(mid="9300"):
    return vector_device(json.loads((VECTOR_DIRECTORY / f"atw-{mid}.json").read_text()))


def request(inner, selector=0, key=KEY, **fields):
    return decode_outer(peer_packet(
        {"t": "pack", "i": selector, "uid": 17, "cid": "peer", "tcid": MAC, **fields},
        inner, key,
    ))


def handle(device, inner, **fields):
    return device.profile.handler.handle(device, request(inner, **fields))


def status(device, cols):
    return handle(device, {"t": "status", "mac": device.mac, "cols": cols})[0].inner


@pytest.fixture
def example_config():
    path = Path(__file__).resolve().parents[1] / "examples" / "emulator-atw-devices.json"
    return json.loads(path.read_text())


def test_example_per_mid_profiles_load_with_configured_controls(example_config):
    devices = load_config(example_config)[2]
    assert [(device.mid, device.profile.id) for device in devices] == [
        ("9300", "sim-w06a-p3-v6.04-9300"),
        ("9301", "sim-w06a-p3-v6.04-9301"),
        ("9302", "sim-w06a-p3-v6.04-9302"),
    ]
    for device, mode in zip(devices, [1, 2, 1], strict=True):
        reply = device.profile.handler.handle(device, request(
            {"t": "status", "mac": device.mac,
             "cols": ["Pow", "Mod", "HeHomTemSet", "WatBoxTemSet"]},
            key=device.key, tcid=device.mac,
        ))[0].inner
        assert reply["dat"] == [
            0, mode, 24, 50,
        ]


@pytest.mark.parametrize("overrides,field", [
    ({"state": {"RmoHomTemHi": 126}}, "RmoHomTemHi"),
    ({"state": {"_private": 0}}, "_private"),
    ({"state": {"AllErr": 0}}, "AllErr"),
    ({"state": {"unknown": 0}}, "unknown"),
    ({"state": {"Pow": True}}, "Pow"),
    *[({"state": {"HeHomTemSet": value}}, "HeHomTemSet")
      for value in [float("nan"), float("inf"), -float("inf"), 15, 31]],
    ({"name": "x" * 2048}, "name"),
])
def test_invalid_startup_overrides_fail_before_listening(
    example_config, overrides, field, tmp_path,
):
    example_config["devices"][0].update(overrides)
    with pytest.raises(ValueError, match=field):
        load_config(example_config)
    path = tmp_path / "devices.json"
    path.write_text(json.dumps(example_config))
    result = subprocess.run(
        [sys.executable, "-m", "gree_emulator", "--config", str(path)],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 2
    assert "Listening" not in result.stdout
    assert "error:" in result.stderr
    assert "Traceback" not in result.stderr


def test_source_ciphertexts_and_exact_reply_casing():
    bind = json.loads(
        (Path(__file__).resolve().parent / "fixtures" / "atw-bind-generic2.json").read_text()
    )
    device = device_for()
    replies = device.profile.handler.handle(device, bind["request_outer"])
    expected = bind["replies"][0]
    assert encode_reply(replies[0]) == expected["datagram"].encode()
    assert replies[0].inner["t"] == "bindok"
    # Source ciphertext, not a client/runtime-produced expected packet.
    assert decode_pack(bind["request_outer"], GENERIC_KEY, "aes-ecb-pkcs7") == {
        "t": "bind", "mac": MAC,
    }
    scan = device.profile.handler.advertise(device, {"t": "scan"})[0]
    assert "ModelType" in scan.inner and "modeltype" not in scan.inner
    assert "vender" in scan.inner and "vendor" not in scan.inner


@pytest.mark.parametrize("selector,key", [(0, KEY), (1, GENERIC_KEY), (2, GENERIC_KEY), (256, KEY)])
def test_bind_selectors_never_rotate_and_always_reply_generic(selector, key):
    device = device_for()
    before = device.key
    for _ in range(2):
        reply = handle(device, {"t": "bind", "mac": MAC}, selector=selector, key=key)[0]
        assert reply.outer == {"t": "pack", "i": 1, "uid": 17, "cid": MAC, "tcid": "peer"}
        assert reply.key == GENERIC_KEY
        assert reply.inner == {"t": "bindok", "mac": MAC, "key": KEY.decode(), "r": 200}
        assert device.key == before


@pytest.mark.parametrize("selector", [1, 2, 256])
@pytest.mark.parametrize("inner", [
    {"t": "status", "mac": MAC, "cols": ["Pow"]},
    {"t": "cmd", "opt": ["Pow"], "p": [1]},
])
def test_controls_require_exact_selector_zero(selector, inner):
    with pytest.raises(InvalidPacket):
        handle(device_for(), inner, selector=selector, key=KEY if selector == 256 else GENERIC_KEY)


@pytest.mark.parametrize("batch", [
    {"opt": ["Pow", "unknown"], "p": [1, 0]},
    {"opt": ["Pow", "AllErr"], "p": [1, 0]},
    {"opt": ["Pow", "RmoHomTemHi"], "p": [1, 126]},
    {"opt": ["Pow"], "val": [1]},
    {"opt": ["Pow", "Mod"], "p": [1]},
    {"opt": [], "p": []},
    *[{"opt": ["Pow"], "p": [value]} for value in [True, 1.0, "1", -1, 256]],
    {"opt": ["Mod"], "p": [0]},
    {"opt": ["HeWatOutTemSet"], "p": [61]},
    {"opt": ["CoWatOutTemSet"], "p": [6]},
    {"opt": ["WatBoxTemSet"], "p": [39]},
    {"opt": ["HeHomTemSet"], "p": [31]},
    {"opt": ["Pow"] * 50, "p": [1] * 50},
])
def test_safe_atomic_rejection_never_reads_clock_or_mutates(batch, monkeypatch):
    device = device_for()
    before = (copy.deepcopy(device.state), device.room_c, device.last_step)

    def forbidden_clock():
        pytest.fail("invalid batch read the thermal clock")
    monkeypatch.setattr("gree_emulator.profiles.atw.time.monotonic", forbidden_clock)
    with pytest.raises(InvalidPacket):
        handle(device, {"t": "cmd", **batch})
    assert (device.state, device.room_c, device.last_step) == before


def test_order_unknowns_duplicates_and_final_status():
    device = device_for()
    reply = handle(device, {"t": "cmd", "opt": ["Pow", "HeWatOutTemSet", "Pow"], "p": [1, 40, 0]})[0]
    assert reply.inner == {"t": "res", "r": 200, "opt": ["Pow", "HeWatOutTemSet", "Pow"], "p": [1, 40, 0], "val": [1, 40, 0]}
    assert status(device, ["unknown", "Pow", "HeWatOutTemSet", "Pow", "EnvironmentTem", "TemSen", "FlagPool"]) == {
        "t": "dat", "r": 200, "mac": MAC, "cols": ["Pow", "HeWatOutTemSet", "Pow"], "dat": [0, 40, 0],
    }


def test_case_insensitive_members_but_not_values_and_safe_collision_rejection():
    device = device_for()
    outer = request({"T": "status", "MAC": MAC, "COLS": ["Pow", "pow"]})
    outer = {key.upper() if key in ("uid", "cid") else key: value for key, value in outer.items()}
    assert device.profile.handler.handle(device, outer)[0].inner["cols"] == ["Pow"]
    for outer in [request({"t": "status", "T": "status", "mac": MAC, "cols": ["Pow"]}),
                  {**request({"t": "status", "mac": MAC, "cols": ["Pow"]}), "I": 0}]:
        with pytest.raises(InvalidPacket):
            device.profile.handler.handle(device, outer)
    assert handle(device, {"t": "STATUS", "mac": MAC, "cols": ["Pow"]}) == []


@pytest.mark.parametrize("count,expected", [(49, 49), (50, 0)])
def test_exact_fifty_status_slots_preserve_native_counter_behavior(count, expected):
    reply = status(device_for(), ["Pow"] * count)
    assert reply["cols"] == ["Pow"] * expected
    assert reply["dat"] == [0] * expected


def test_safe_status_name_and_member_bounds():
    device = device_for()
    for inner in [
        {"t": "status", "mac": MAC, "cols": ["Pow"] * 51},
        {"t": "status", "mac": MAC, "cols": ["x" * 20]},
        {"t": "status", "mac": MAC, "cols": ["é" * 10]},
        {"t": "status", "mac": "020000000002", "cols": ["Pow"]},
        {"t": "status", "mac": MAC, "cols": ["Pow"], **{f"x{i}": 0 for i in range(28)}},
    ]:
        with pytest.raises(InvalidPacket):
            handle(device, inner)
    with pytest.raises(InvalidPacket):
        handle(device, {"t": "bind", "mac": MAC}, selector=1, key=GENERIC_KEY, cid="x" * 20)


def test_reply_bound_precedes_mutation_but_not_outgoing_udp_limit():
    device = device_for()
    # A short request can expand when metadata values are selected repeatedly.
    device.name = "x" * 1100
    before = (device.state.copy(), device.last_step)
    with pytest.raises(InvalidPacket):
        status(device, ["name", "name"])
    assert (device.state, device.last_step) == before
    device.name = "x" * 700
    reply = handle(device, {"t": "status", "mac": MAC, "cols": ["name"]})[0]
    assert len(encode_reply(reply)) > 1024


@pytest.mark.parametrize("operation", ["cmd", "status"])
def test_outer_twenty_member_boundary(operation):
    device = device_for()
    inner = (
        {"t": "cmd", "opt": ["Pow"], "p": [1]}
        if operation == "cmd"
        else {"t": "status", "mac": MAC, "cols": ["Pow"]}
    )
    outer = request(inner, **{f"x{i}": 0 for i in range(14)})
    assert len(outer) == 20
    before = (device.state.copy(), device.room_c, device.last_step)
    with pytest.raises(InvalidPacket):
        device.profile.handler.handle(device, {**outer, "extra": 0})
    assert (device.state, device.room_c, device.last_step) == before
    reply = device.profile.handler.handle(device, outer)[0].inner
    assert reply["p" if operation == "cmd" else "dat"] == [
        1 if operation == "cmd" else 0,
    ]


@pytest.mark.parametrize("mid,sensors", [
    ("9300", ["RmoHomTemHi", "RmoHomTemLo"]),
    ("9301", ["WatBoxTemHi", "WatBoxTemLo"]),
    ("9302", ["AllInWatTemHi", "AllInWatTemLo", "AllOutWatTemHi", "AllOutWatTemLo"]),
])
@pytest.mark.parametrize("temperature,encoded", [(-101, [0, 0]), (-0.05, [99, 9]), (26.39, [126, 3]), (200, [255, 9])])
def test_role_sensor_quantization_is_policy_not_calibration(mid, sensors, temperature, encoded):
    device = device_for(mid)
    device.room_c = temperature
    device.profile.handler.encode_room(device)
    assert [device.state[name] for name in sensors] == encoded * (len(sensors) // 2)
    assert not {"TemSen", "EnvironmentTem", "FlagPool"} & device.state.keys()


@pytest.mark.parametrize("mid,mode,action,target", [
    ("9300", 1, "heat", 24), ("9300", 4, "heat", 24),
    ("9300", 3, "cool", 24), ("9300", 5, "cool", 24), ("9300", 2, "idle", 26),
    ("9301", 2, "heat", 50), ("9301", 3, "heat", 50), ("9301", 4, "heat", 50),
    ("9301", 1, "idle", 26), ("9301", 5, "idle", 26),
    ("9302", 1, "heat", 35), ("9302", 4, "heat", 35),
    ("9302", 3, "cool", 18), ("9302", 5, "cool", 18), ("9302", 2, "idle", 26),
])
def test_role_specific_thermal_targets_and_display_units(mid, mode, action, target):
    device = device_for(mid)
    device.state.update(Pow=1, Mod=mode)
    before_units = device.profile.handler.thermal_target(device)
    assert before_units[0] == action
    if action != "idle":
        assert before_units[1] == target
    device.state["TemUn"] = 1
    assert device.profile.handler.thermal_target(device) == before_units
    device.state["Pow"] = 0
    assert device.profile.handler.thermal_target(device)[0] == "idle"


@pytest.mark.parametrize("mid,mode,target", [
    ("9300", 1, "HeHomTemSet"), ("9301", 2, "WatBoxTemSet"), ("9302", 1, "HeWatOutTemSet"),
])
def test_old_controls_advance_before_new_controls_and_device_isolation(mid, mode, target, monkeypatch):
    first, second = device_for(mid), device_for(mid)
    first.room_c = first.ambient_c = 20
    first.last_step = 100
    first.state.update(Pow=1, Mod=mode)
    monkeypatch.setattr("gree_emulator.profiles.atw.time.monotonic", lambda: 220)
    untouched = (second.state.copy(), second.room_c, second.last_step, second.key)
    handle(first, {"t": "cmd", "opt": ["Pow", target], "p": [0, 30 if mid == "9300" else 60]})
    assert first.room_c == pytest.approx(22)
    assert first.last_step == 220
    first.advance(340)
    assert first.room_c == pytest.approx(21.8)
    assert (second.state, second.room_c, second.last_step, second.key) == untouched


@pytest.mark.parametrize("pack_size,accepted", [(684, True), (704, False), (792, False)])
async def test_source_pack_boundary_and_unchanged_large_poll_rejection(pack_size, accepted):
    device = device_for()
    inner = {"t": "status", "mac": MAC, "cols": ["Pow"], "padding": ""}
    plain = json.dumps(inner, separators=(",", ":")).encode()
    # AES/base64 size is selected independently; padding is an ignored JSON member.
    cipher_bytes = {684: 512, 704: 528, 792: 592}[pack_size]
    inner["padding"] = "x" * (cipher_bytes - 1 - len(plain))
    packet = peer_packet({"t": "pack", "i": 0, "uid": 17, "cid": "peer", "tcid": MAC}, inner, KEY)
    assert len(json.loads(packet)["pack"]) == pack_size
    assert len(packet) < 1024
    transport, server = await start_server([device], "127.0.0.1", 0)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.settimeout(0.15)
            address = transport.get_extra_info("sockname")
            peer.sendto(packet, address)
            if accepted:
                reply = peer_reply(await asyncio.to_thread(receive, peer), KEY)
                assert reply["inner"]["dat"] == [0]
                peer.sendto(packet + b" " * (1025 - len(packet)), address)
            with pytest.raises(socket.timeout):
                await asyncio.to_thread(receive, peer)
            peer.sendto(peer_packet(
                {"t": "pack", "i": 0, "uid": 17, "cid": "peer", "tcid": MAC},
                {"t": "status", "mac": MAC, "cols": ["Pow"]}, KEY,
            ), address)
            assert peer_reply(await asyncio.to_thread(receive, peer), KEY)["inner"]["dat"] == [0]
    finally:
        server.close()
        await server.wait_closed()


async def test_public_atw_fresh_bind_acquires_default_state_and_guarded_writes():
    _, _, devices = load_config({"seed": "atw-client", "devices": [{
        "id": "atw", "profile": "sim-w06a-p3-v6.04-9300", "mid": "9300",
        "room_c": 26, "ambient_c": 26,
        "state": {"Pow": 0, "TemUn": 0, "Mod": 1},
    }]})
    simulator, = devices
    transport, server = await start_server(devices, "127.0.0.1", 0)
    host, port = transport.get_extra_info("sockname")
    unit = create_device(DeviceInfo(host, port, simulator.mac, "ATW", mid="9300"),
                         bind_timeout=1)
    assert type(unit) is AirToWaterDevice
    data, results = asyncio.Queue(), asyncio.Queue()
    unit.add_handler(Response.DATA, data.put_nowait)
    unit.add_handler(Response.RESULT, results.put_nowait)
    try:
        assert not unit.has_valid_state
        with pytest.raises(ValueError):
            unit.heating_water_target_temperature_c = 36
        await unit.bind()
        while (unit.temperature_units != 0 or unit.power is None
               or unit.room_temperature_c is None or unit.hid is None):
            await asyncio.wait_for(data.get(), 2)
        assert unit.has_valid_state
        assert unit.power is False
        assert unit.room_temperature_c == 26.0
        assert unit.mode is AirToWaterMode.Heat
        assert unit.hid == "362001066763+U-W06A(P3)V6.04.bin"
        assert unit.raw_properties["RmoHomTemHi"] == 126
        assert unit.raw_properties["RmoHomTemLo"] == 0

        unit.mode = AirToWaterMode.Cool
        await unit.push_state_update()
        assert (await asyncio.wait_for(results.get(), 2))["Mod"] == 5
        assert simulator.state["Mod"] == 5
        unit.heating_water_target_temperature_c = 36
        await unit.push_state_update()
        assert (await asyncio.wait_for(results.get(), 2))["HeWatOutTemSet"] == 36
        assert simulator.state["HeWatOutTemSet"] == 36
        unit.power = True
        await unit.push_state_update()
        assert (await asyncio.wait_for(results.get(), 2))["Pow"] == 1
        assert simulator.state["Pow"] == 1
        with pytest.raises(ValueError):
            unit.mode = AirToWaterMode.Heat
    finally:
        unit.close()
        await asyncio.wait_for(unit._transport_closed.wait(), 2)
        await asyncio.gather(*unit.tasks, return_exceptions=True)
        server.close()
        await server.wait_closed()
