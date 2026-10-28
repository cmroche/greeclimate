"""Independent literal radar wire/cache expectations; no measured presence claim."""

import asyncio
import base64
from copy import deepcopy
import json
from pathlib import Path
import signal
import socket
import sys
from unittest.mock import AsyncMock

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.catalog_esp_radar import GENERIC_KEY, PROFILES
from gree_emulator.wire import InvalidPacket, decode_outer, encode_reply
from greeclimate.cipher import CipherV1
from greeclimate.device import Device
from greeclimate.device_factory import create_device
from greeclimate.deviceinfo import DeviceInfo

VECTORS = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-esp-radar-vectors_research.json").read_text())


@pytest.fixture(params=range(2), ids=("gr-v1.1", "gr-v2.5"))
def model(request):
    profile = PROFILES[request.param]
    device = EmulatedDevice("radar", VECTORS["mac"], VECTORS["name"], "80261",
                            VECTORS["key"].encode(), profile, dict(profile.initial_state))
    return device, VECTORS["builds"][request.param]


def packet(device, inner, *, index=0, key=None, uid=73, cid="raw-peer"):
    selected = key if key is not None else device.key if index == 0 else GENERIC_KEY
    plain = json.dumps(inner, separators=(",", ":")).encode()
    if index == 2:
        return {"t": "pack", "i": 2, "uid": uid, "cid": cid, "tcid": device.mac, "pack": plain.decode()}
    return {"t": "pack", "i": index, "uid": uid, "cid": cid, "tcid": device.mac,
            "pack": base64.b64encode(AES.new(selected, AES.MODE_ECB).encrypt(pad(plain, 16))).decode()}


def response(device, inner, **kwargs):
    result, = device.profile.handler.handle(device, packet(device, inner, **kwargs))
    encoded = encode_reply(result)
    assert not encoded.endswith(b"\n")
    outer = json.loads(encoded)
    assert {name: value for name, value in outer.items() if name != "pack"} == {
        "t": "pack", "i": kwargs.get("index", 0), "uid": kwargs.get("uid", 73),
        "cid": device.mac, "tcid": kwargs.get("cid", "raw-peer")}
    key = device.key if outer["i"] == 0 else GENERIC_KEY
    return json.loads(unpad(AES.new(key, AES.MODE_ECB).decrypt(base64.b64decode(outer["pack"])), 16))


def status(device, cols):
    return response(device, {"t": "status", "cols": cols})


def command(device, opt, values):
    return response(device, {"t": "cmd", "opt": opt, "p": values})


def test_all_known_getters_and_build_identity(model):
    device, vector = model
    assert device.profile.source_sha256 == vector["source_sha256"]
    assert device.profile.hid == vector["hid"]
    assert device.profile.mids == ("80261",)
    assert status(device, vector["cols"]) == {
        "t": "dat", "r": 200, "mac": VECTORS["mac"], "cols": vector["cols"], "dat": vector["dat"]}


def test_complete_command_namespace_ack_then_independent_status(model):
    device, vector = model
    for transaction in vector["transactions"]:
        assert command(device, transaction["opt"], transaction["p"]) == {
            "t": "res", "r": transaction["r"], "mac": device.mac,
            "opt": transaction.get("ack_opt", transaction["opt"]), "p": transaction["ack_p"]}
        assert status(device, transaction["cols"])["dat"] == transaction["dat"]


def test_discovery_bind_and_exact_context_gate(model):
    device, _ = model
    scan_reply, = device.profile.handler.advertise(device, {"t": "scan"})
    outer = json.loads(encode_reply(scan_reply))
    assert outer["i"] == 1
    scan = json.loads(unpad(AES.new(GENERIC_KEY, AES.MODE_ECB).decrypt(base64.b64decode(outer["pack"])), 16))
    assert scan == {"t": "dev", "cid": device.mac, "bc": "gree", "brand": "gree", "catalog": "gree",
                    "mac": device.mac, "mid": "80261", "model": "gree", "series": "gree",
                    "name": VECTORS["name"], "vender": "1", "ver": "V3.0.0", "lock": 0}
    assert "hid" not in scan
    for _ in range(2):
        assert response(device, {"t": "bind", "mac": device.mac}, index=1) == {
            "t": "bindok", "r": 200, "mac": device.mac, "key": VECTORS["key"]}
    for index, operation in [(0, "bind"), (1, "status"), (1, "cmd"), (3, "bind"), (-1, "bind")]:
        assert device.profile.handler.handle(device, packet(device, {"t": operation, "cols": ["count"]}, index=index)) == []


def test_plaintext_selector_scan_and_registered_command_gates(model):
    device, _ = model
    outer = {"t": "pack", "i": 2, "uid": 17, "cid": "plain-peer", "tcid": device.mac,
             "pack": "{\"t\":\"scan\"}"}
    reply, = device.profile.handler.handle(device, decode_outer(json.dumps(outer).encode()))
    assert reply.outer == {"t": "pack", "i": 1, "uid": 17, "cid": device.mac, "tcid": "plain-peer"}
    assert reply.inner["mid"] == "80261"
    assert reply.key == GENERIC_KEY
    outer["pack"] = "{\"t\":\"status\",\"cols\":[\"count\"]}"
    assert device.profile.handler.handle(device, outer) == []
    for malformed in ("{\"t\":\"scan\",\"t\":\"scan\"}", "[]", "not-json"):
        with pytest.raises(InvalidPacket):
            device.profile.handler.handle(device, {**outer, "pack": malformed})


def test_order_duplicates_empty_unknown_and_readonly(model):
    device, _ = model
    assert status(device, ["TemSen", "count", "Count", "count", "Pow"])["dat"] == [0, 0, 0, 0, 0]
    assert status(device, ["TemSen", "count", "Count", "count", "Pow"])["cols"] == ["TemSen", "count", "Count", "count", "Pow"]
    assert status(device, [])["dat"] == []
    assert command(device, [], []) == {"t": "res", "r": 200, "mac": device.mac, "opt": "", "p": ""}
    assert command(device, ["doortotal", "doortotal", "count"], [257, 258, 9])["p"] == [257, 258, 9]
    assert status(device, ["doortotal", "count", "doortotal"])["dat"] == [2, 0, 2]
    assert command(device, ["hid", "ver", "name"], [1, 2, 3])["r"] == 200
    assert status(device, ["hid", "ver", "name"])["dat"] == [device.profile.hid, "V3.0.0", VECTORS["name"]]


def test_native_array_numbers_become_decimal_strings_before_selected_string_ack(model):
    device, _ = model
    assert command(device, ["ReportClientID", "host", "time"], [7, 200, 404])["p"] == ["7", "200", "404"]
    if device.profile.id == "sim-esp32-gr-v1.1":
        assert command(device, ["time_range"], [90])["p"] == ["90"]
    else:
        assert command(device, ["Week"], [7])["p"] == ["7"]
        assert status(device, ["Week"])["dat"] == ["7"]


@pytest.mark.parametrize("bad", VECTORS["safe_invalid_scalars"])
def test_safe_atomic_validation_does_not_mutate_any_cache(model, bad):
    device, _ = model
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        command(device, ["doortotal", "installtype"], [3, bad])
    assert device.state == before


def test_safe_lengths_target_key_uid_and_recovery(model):
    device, _ = model
    bad_inners = [{"t": "cmd", "opt": ["doortotal"], "p": []},
                  {"t": "cmd", "opt": ["ReportClientID"], "p": ["a" * 32]},
                  {"t": "status", "cols": ["count"] * 33},
                  {"t": "status", "cols": [None]},
                  {"t": "status", "cols": ["a" * 64]},
                  {"t": "status", "cols": ["count"], "track": True},
                  {"t": "status", "cols": ["count"], "mac": "02000000eeee"}]
    before = deepcopy(device.state)
    for inner in bad_inners:
        with pytest.raises(InvalidPacket):
            device.profile.handler.handle(device, packet(device, inner))
        assert device.state == before
    for outer in [packet(device, {"t": "status", "cols": []}, key=b"badkeybadkeybadk"),
                  packet(device, {"t": "status", "cols": []}, uid=1 << 31),
                  packet(device, {"t": "status", "cols": []}, cid="a" * 13),
                  {**packet(device, {"t": "status", "cols": []}), "tcid": "02000000eeee"}]:
        with pytest.raises(InvalidPacket):
            device.profile.handler.handle(device, outer)
    assert status(device, ["count"])["dat"] == [0]
    with pytest.raises(InvalidPacket):
        decode_outer(b'{"t":"scan","t":"scan"}')


def test_reply_bound_checks_before_mutation(model):
    device, _ = model
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        command(device, ["doortotal"] + ["x" * 63] * 31, [3] + [1] * 31)
    assert device.state == before


def test_sensorless_cache_isolation_reset_and_no_fake_boundary(model):
    device, vector = model
    second = EmulatedDevice("other", "02000000e202", VECTORS["name"], "80261", device.key,
                            device.profile, dict(device.profile.initial_state))
    command(device, ["doortotal"], [3])
    boundary = [" "] if device.profile.id == "sim-esp32-gr-v1.1" else {"list": [""]}
    assert status(second, ["doortotal", "count", "NumPerson", "borderlist"])["dat"] == [0, 0, 0, boundary]
    device.advance(device.last_step + 3600)
    assert device.profile.handler.thermal_target(device) is None
    assert status(device, ["count", "NumPerson", "x", "y", "doorposition"])["dat"] == [0, 0, 0, 0, 0]
    assert status(second, vector["cols"])["dat"] == vector["dat"]
    assert "val" not in command(device, ["bordertype"], [1])
    assert command(device, ["bordertype"], [1])["r"] == 200
    assert device.profile.handler.handle(device, packet(device, {"t": "subDev"})) == []
    assert device.profile.handler.handle(device, {"t": "mate", "host": "localhost"}) == []


def test_synthetic_geometry_success_timeout_and_safe_atomic_index(model):
    device, _ = model
    assert command(device, ["bordertype"], [4]) == {
        "t": "res", "r": 200, "mac": device.mac,
        "opt": ["bordertype", "borderout", "x", "y"], "p": [4, 0, 0.0, 0.0]}
    assert command(device, ["bordertype", "doorindex"], [1, 7]) == {
        "t": "res", "r": 200, "mac": device.mac,
        "opt": ["bordertype", "doorindex", "borderout", "x", "y", "doorposition"],
        "p": [1, 7, 0, 0.0, 0.0, 0]}
    device.state["_queue_complete"] = False
    assert command(device, ["bordertype"], [2]) == {
        "t": "res", "r": 404, "mac": device.mac, "opt": ["bordertype"], "p": [2]}
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        command(device, ["doortotal", "bordertype", "doorindex"], [4, 7, 0])
    assert device.state == before
    with pytest.raises(InvalidPacket):
        command(device, ["doortotal"], [2])
    assert device.state == before
    assert status(device, ["count", "border", "doorenable"])["dat"] == [0, 0, 0]


def test_source_boundary_shape_zero_door_sentinels_and_valid_synthetic_door(model):
    device, _ = model
    early = device.profile.id == "sim-esp32-gr-v1.1"
    assert status(device, ["borderlist"])["dat"] == [[" "] if early else {"list": [""]}]
    command(device, ["installtype", "doortotal"], [1, 1])
    if early:
        assert status(device, ["borderlist"])["dat"] == [[" "]]
        command(device, ["bordertype", "doorindex"], [5, 1])
    else:
        command(device, ["border"], [1])
    assert status(device, ["borderlist"])["dat"] == [{
        "left": 0.0, "right": 0.0, "farthest": 0.0,
        "list": [{"x": 0.0, "y": 0.0, "doorposition": 0}]}]
    command(device, ["reset"], [1])
    assert status(device, ["border", "doortotal", "borderlist"])["dat"] == (
        [0, 0, ""] if early else [0, 1, {
            "left": 0.0, "right": 0.0, "farthest": 0.0,
            "list": [{"x": 0.0, "y": 0.0, "doorposition": 0}]}])


def test_native_modes_without_a_queue_producer_remain_timeouts(model):
    device, _ = model
    assert command(device, ["bordertype"], [6]) == {
        "t": "res", "r": 404, "mac": device.mac, "opt": ["bordertype"], "p": [6]}
    assert command(device, ["bordertype"], [7]) == {
        "t": "res", "r": 404 if device.profile.id == "sim-esp32-gr-v1.1" else 200,
        "mac": device.mac, "opt": ["bordertype"], "p": [7]}


@pytest.mark.parametrize("value", [6, 255, -1])
def test_native_five_door_limit_has_safe_atomic_command_and_configuration_bounds(model, value):
    device, _ = model
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        command(device, ["installtype", "doortotal"], [2, value])
    assert device.state == before
    with pytest.raises(ValueError):
        device.profile.handler.validate_state({"doortotal": value})


def test_silent_management_callbacks_preserve_key_and_commit_only_valid_peer_context(model):
    device, _ = model
    key = device.key
    for inner, index in (({"t": "loginRes", "r": 200, "key": "not-a-new-key"}, 1),
                         ({"t": "hbok"}, 2), ({"t": "tm", "time": "2026-10-23 12:34:56"}, 2)):
        assert device.profile.handler.handle(device, packet(device, inner, index=index)) == []
    assert device.key == key
    assert device.state["_module_time"] == "2026-10-23 12:34:56"
    assert device.profile.handler.advertise(device, {})[0].outer["uid"] == 73
    assert device.profile.handler.handle(device, {
        "t": "tm", "time": "2026-10-23 12:34:57", "uid": 99, "cid": "ignored"}) == []
    assert device.state["_module_time"] == "2026-10-23 12:34:57"
    assert (device.state["_uid"], device.state["_peer_cid"]) == (73, "raw-peer")
    for inner in ({"t": "loginRes", "r": 200}, {"t": "hbok"}, {"t": "tm", "time": "2026-10-23 12:34:58"}):
        assert device.profile.handler.handle(device, packet(device, inner, index=0)) == []
    before = deepcopy(device.state)
    for bad in ("2026-02-30 12:00:00", "2026-10-23", 200, None):
        with pytest.raises(InvalidPacket):
            device.profile.handler.handle(device, packet(device, {"t": "tm", "time": bad}, index=2, uid=99))
        assert device.state == before


def test_ota_is_an_explicit_atomic_safety_rejection_not_a_fake_upgrade(model):
    device, _ = model
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket, match="not emulated"):
        device.profile.handler.handle(device, packet(device, {
            "t": "upgrade", "url": "https://example.invalid/no-firmware.bin", "type": 0}))
    assert device.state == before


def test_wlan_source_handler_is_plaintext_noop_not_network_reconfiguration(model):
    device, _ = model
    before = deepcopy(device.state)
    reply, = device.profile.handler.handle(device, packet(
        device, {"t": "wlan", "ssid": "synthetic", "psw": "not-a-secret", "host": "localhost"}, index=1))
    assert json.loads(encode_reply(reply)) == {"t": "ret", "r": 200, "mac": device.mac}
    assert device.state == {**before, "_uid": 73, "_peer_cid": "raw-peer"}
    with pytest.raises(InvalidPacket):
        device.profile.handler.handle(device, packet(device, {"t": "wlan", "ssid": "x" * 32}, index=1))


def test_late_dump_callback_plaintext_reply_has_no_logging_or_board_mutation(model):
    device, _ = model
    request = packet(device, {"t": "dump", "period": 0.5, "cnt": 258})
    replies = device.profile.handler.handle(device, request)
    if device.profile.id == "sim-esp32-gr-v1.1":
        assert replies == []
        return
    reply, = replies
    assert json.loads(encode_reply(reply)) == {"t": "ret", "r": 200, "mac": device.mac}
    for value in (True, False):
        reply, = device.profile.handler.handle(device, packet(device, {"t": "dump", "cnt": value}))
        assert json.loads(encode_reply(reply)) == {"t": "ret", "r": 200, "mac": device.mac}
    assert status(device, ["count", "WorkState", "period", "cnt"])["dat"] == [0, 1, 0, 0]
    assert device.profile.handler.handle(device, packet(device, {"t": "dump"}, index=1)) == []
    with pytest.raises(InvalidPacket):
        device.profile.handler.handle(device, packet(device, {"t": "dump", "period": "bad"}))


def test_late_install_aliases_schedule_types_and_border_rollback(model):
    device, _ = model
    if device.profile.id != "sim-esp32-gr-v2.5":
        assert command(device, ["setinstalltype", "Week", "timeStatus"], [2, 7, 1])["p"] == [2, 7, 1]
        assert status(device, ["setinstalltype", "Week", "timeStatus"])["dat"] == [0, 0, 0]
        return
    assert command(device, ["WorkState"], [2])["p"] == [2]
    assert status(device, ["WorkState", "count"])["dat"] == [3, 0]
    assert command(device, ["WorkState"], [257])["p"] == [257]
    assert status(device, ["WorkState"])["dat"] == [1]
    command(device, ["installtype"], [1])
    assert status(device, ["installtype", "setinstalltype"])["dat"] == [1, 1]
    command(device, ["bordertype", "GoBack"], [0, 1])
    assert device.state["_border_type"] == 2
    command(device, ["bordertype", "GoBack"], [2, 1])
    assert device.state["_border_type"] == 1
    command(device, ["installtype"], [2])
    for requested, expected in [(0, 3), (3, 4), (4, 1), (5, 5)]:
        command(device, ["bordertype", "GoBack"], [requested, 1])
        assert device.state["_border_type"] == expected
    before = deepcopy(device.state)
    for name, value in [("Week", "8"), ("Week", "1,9"), ("time_range", "25:00-08:00"),
                        ("time_range", "8:00-9:00"), ("Week", [1, 3])]:
        with pytest.raises(InvalidPacket):
            command(device, ["doortotal", name], [4, value])
        assert device.state == before


def test_uid_and_peer_cache_survive_scan_and_rebind_without_cross_device_leak(model):
    device, _ = model
    response(device, {"t": "status", "cols": ["count"]}, uid=-7, cid="reader-2")
    scan, = device.profile.handler.advertise(device, {"t": "scan", "uid": 123, "cid": "ignored"})
    outer = json.loads(encode_reply(scan))
    assert (outer["uid"], outer["tcid"]) == (-7, "reader-2")
    response(device, {"t": "bind"}, index=1, uid=92, cid="rebound")
    scan, = device.profile.handler.advertise(device, {"t": "scan"})
    assert (scan.outer["uid"], scan.outer["tcid"]) == (92, "rebound")
    assert status(device, ["key", "_uid", "_peer_cid"])["dat"] == [0, 0, 0]


@pytest.mark.parametrize("name", ["count", "NumPerson", "hid", "_border_type", "TemSen", "Week"])
def test_config_cannot_override_readonly_or_private_state(model, name):
    device, _ = model
    with pytest.raises(ValueError):
        device.profile.handler.validate_state({name: 1})


@pytest.mark.asyncio
async def test_public_consumer_remains_raw_and_keeps_literal_property_types():
    unit = create_device(DeviceInfo("127.0.0.1", 7000, VECTORS["mac"], VECTORS["name"], mid="80261"))
    try:
        assert type(unit) is Device
        await unit.bind(key=VECTORS["key"], cipher=CipherV1())
        unit.send = AsyncMock()
        unit.handle_state_update(hid="362001061898+U-ESP32_GRV2.5.bin", count=0,
                                 Week="1,3,7", time_range="08:15-19:45", WorkState=3)
        assert unit.raw_properties["Week"] == "1,3,7"
        assert unit.get_property("WorkState") == 3
        await unit.update_state()
        assert unit.send.call_args.args[0]["pack"]["cols"] == [
            "WorkState", "count", "border", "JFerr", "doorenable", "doortotal",
            "host", "ver", "name", "rssi", "hid", "InHid", "OEEPHid", "InHidDownPer",
            "devinhidownver", "induptype"]
    finally:
        unit.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("profile", PROFILES, ids=lambda profile: profile.id)
async def test_actual_cli_raw_peer_wlan_context_recovery_and_socket_release(profile):
    root = Path(__file__).resolve().parents[1]
    process = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "gree_emulator", "--profile", profile.id, "--mid", "80261",
        "--seed", "radar-cli", "--listen", "127.0.0.1", "--port", "0", cwd=root,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.settimeout(1)
    address = None
    try:
        line = await asyncio.wait_for(process.stdout.readline(), 5)
        prefix = b"Listening on 127.0.0.1:"
        assert line.startswith(prefix), line
        address = ("127.0.0.1", int(line[len(prefix):]))
        announced = json.loads(await asyncio.wait_for(process.stdout.readline(), 5))
        local = EmulatedDevice("peer", announced["mac"], announced["name"], "80261",
                               b"0123456789abcdef", profile, {})

        async def receive():
            raw, _ = await asyncio.to_thread(peer.recvfrom, 65535)
            assert not raw.endswith(b"\n")
            outer = json.loads(raw)
            if "pack" not in outer:
                return outer
            key = GENERIC_KEY if outer["i"] == 1 else local.key
            return json.loads(unpad(AES.new(key, AES.MODE_ECB).decrypt(base64.b64decode(outer["pack"])), 16))

        async def ask(inner, index=0):
            peer.sendto(json.dumps(packet(local, inner, index=index)).encode(), address)
            return await receive()

        peer.sendto(b'{"t":"scan"}', address)
        scan = await receive()
        assert scan["mid"] == "80261" and scan["ver"] == "V3.0.0" and "hid" not in scan
        peer.settimeout(0.15)
        peer.sendto(b'{"t":"wlan","i":1,"ssid":"synthetic","psw":"not-a-secret"}', address)
        with pytest.raises(socket.timeout):
            await asyncio.to_thread(peer.recvfrom, 65535)
        peer.settimeout(1)
        bound = await ask({"t": "bind", "mac": local.mac}, 1)
        assert bound["t"] == "bindok" and bound["r"] == 200 and bound["mac"] == local.mac
        local.key = bound["key"].encode("ascii")
        assert len(local.key) == 16
        assert await ask({"t": "cmd", "opt": ["doortotal"], "p": [257]}) == {
            "t": "res", "r": 200, "mac": local.mac, "opt": ["doortotal"], "p": [257]}
        expected_hid = next(row["hid"] for row in VECTORS["builds"] if row["profile"] == profile.id)
        assert (await ask({"t": "status", "cols": ["doortotal", "count", "hid"]}))["dat"] == [1, 0, expected_hid]
        assert await ask({"t": "wlan", "ssid": "synthetic", "psw": "not-a-secret"}, 1) == {
            "t": "ret", "r": 200, "mac": local.mac}
        peer.settimeout(0.15)
        peer.sendto(b'{"t":"pack","t":"pack","pack":"bad"}', address)
        with pytest.raises(socket.timeout):
            await asyncio.to_thread(peer.recvfrom, 65535)
        peer.settimeout(1)
        assert (await ask({"t": "status", "cols": ["doortotal"]}))["dat"] == [1]
    finally:
        peer.close()
        if process.returncode is None:
            process.send_signal(signal.SIGINT)
        try:
            _, stderr = await asyncio.wait_for(process.communicate(), 5)
        except asyncio.TimeoutError:
            process.kill()
            _, stderr = await asyncio.wait_for(process.communicate(), 5)
        if address is not None:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as released:
                released.bind(address)
        assert process.returncode == 0, stderr.decode(errors="replace")
