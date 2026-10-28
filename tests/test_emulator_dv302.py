"""DV3.02 room policy and native decrypt-byte versus control-index boundary."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from gree_emulator.__main__ import load_config
from gree_emulator.profiles.gateway import GENERIC_KEY
from gree_emulator.server import EmulatorServer
from gree_emulator.wire import InvalidPacket, decode_outer, encode_reply
from tests.test_emulator import peer_packet, peer_reply


def controller(profile="sim-w06dv-v3.02", **overrides):
    return load_config({"devices": [
        {"id": "controller", "profile": profile, "mid": "3018", **overrides},
    ]})[2][0]


def request(device, index, inner, key):
    return peer_packet({"t": "pack", "tcid": device.mac, "cid": "peer",
                        "i": index, "uid": 17}, inner, key)


@pytest.mark.parametrize("field", ("room_c", "ambient_c"))
def test_dv302_config_rejects_room_overrides(field):
    with pytest.raises(ValueError, match=field):
        controller(**{field: 24})


def test_dv302_commands_and_elapsed_time_never_create_room():
    device = controller()
    assert device.profile.handler.thermal_target(device) is None
    assert device.room_c is device.ambient_c is None
    device.last_step = 0
    device.advance(120)
    inner = {"t": "cmd", "opt": ["Pow", "Mod", "SetTem"], "p": [1, 1, 18]}
    replies = device.profile.handler.handle(device, decode_outer(request(device, 0, inner, device.key)))
    assert replies[0].inner["t"] == "res"
    assert device.state["Pow"] == 1 and device.state["SetTem"] == 18
    device.advance(device.last_step + 120)
    assert device.profile.handler.thermal_target(device) is None
    assert device.room_c is device.ambient_c is None


def test_v401_retains_internal_room_and_thermal_policy():
    device = controller("sim-w06dv-v4.01", room_c=26, ambient_c=28,
                        state={"Pow": 1, "Mod": 1, "SetTem": 22})
    assert device.profile.handler.thermal_target(device) == ("cool", 22)
    device.last_step = 0
    device.advance(120)
    assert device.room_c == pytest.approx(24)
    assert device.ambient_c == 28


# Source DV3.02 extui at0xa0ac95 feeds key selector0xa091c4, not the control gate.
@pytest.mark.parametrize("index,session", [(0, True), (1, False), (255, False),
                                           (256, True), (257, False), (512, True)])
def test_dv302_bind_uses_low_byte_key_selector(index, session):
    device = controller()
    key = device.key if session else GENERIC_KEY
    wrong_key = GENERIC_KEY if session else device.key
    inner = {"t": "bind", "mac": device.mac}
    replies = device.profile.handler.handle(device, decode_outer(request(device, index, inner, key)))
    reply = peer_reply(encode_reply(replies[0]), GENERIC_KEY)["inner"]
    assert reply == {"t": "bindok", "mac": device.mac,
                     "key": device.key.decode("ascii"), "r": 200}
    with pytest.raises(InvalidPacket):
        device.profile.handler.handle(device, decode_outer(request(device, index, inner, wrong_key)))


def test_v401_uses_its_source_low_byte_decrypt_selection():
    device = controller("sim-w06dv-v4.01")
    inner = {"t": "bind", "mac": device.mac}
    assert device.profile.handler.handle(
        device, decode_outer(request(device, 256, inner, device.key)))[0].inner["t"] == "bindok"
    with pytest.raises(InvalidPacket):
        device.profile.handler.handle(device, decode_outer(request(device, 256, inner, GENERIC_KEY)))


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ("status", "cmd"))
async def test_dv302_index256_controls_silently_reject_without_mutation(kind):
    device = controller()
    device.last_step = 0
    before = dict(device.state), device.last_step, device.room_c, device.ambient_c
    inner = ({"t": "status", "mac": device.mac, "cols": ["Pow", "SetTem"]}
             if kind == "status" else {"t": "cmd", "opt": ["Pow"], "p": [1]})
    sent = []
    server = EmulatorServer([device])
    server.transport = SimpleNamespace(sendto=lambda *args: sent.append(args))
    server.datagram_received(request(device, 256, inner, device.key), ("127.0.0.1", 12345))
    assert sent == []
    assert (device.state, device.last_step, device.room_c, device.ambient_c) == before
    # The same request at exact zero remains authorized and returns a reply.
    server.datagram_received(request(device, 0, inner, device.key), ("127.0.0.1", 12345))
    assert len(sent) == 1
    reply = peer_reply(sent[0][0], device.key)["inner"]
    assert reply["t"] == ("dat" if kind == "status" else "res")
    if kind == "cmd":
        assert device.state["Pow"] == 1


def exchange(device, inner):
    replies = device.profile.handler.handle(
        device, decode_outer(request(device, 0, inner, device.key)))
    return peer_reply(encode_reply(replies[0]), device.key)["inner"]


def poll(device, columns):
    return exchange(device, {"t": "status", "mac": device.mac, "cols": columns})


def test_dv302_discovery_omits_hid_but_requested_status_has_full_source_hid():
    device = controller()
    assert "hid" not in device.profile.handler.advertise(device, {"t": "scan"})[0].inner
    assert poll(device, ["hid", "hid"]) == {
        "t": "dat", "r": 200, "mac": device.mac, "cols": ["hid", "hid"],
        "dat": ["362001067592+U-W06DV3.02.bin", "362001067592+U-W06DV3.02.bin"],
    }


def test_dv302_literal_source_commands_and_fresh_status():
    fixture = json.loads((Path(__file__).parent / "fixtures" / "emulator"
                          / "session-qca-dv-quirks_research.json").read_text())
    device = controller()
    for vector in fixture["commands"]:
        assert exchange(device, {"t": "cmd", "opt": vector["opt"], "p": vector["p"]}) == {
            "t": "res", "r": 200, "opt": vector["opt"],
            "p": vector["p"], "val": vector["p"],
        }
        assert poll(device, vector["poll"]) == {
            "t": "dat", "r": 200, "mac": device.mac,
            "cols": vector["poll"], "dat": vector["dat"],
        }
    metadata = fixture["metadata"]
    assert poll(device, metadata["cols"]) == {
        "t": "dat", "r": 200, "mac": device.mac,
        "cols": metadata["selected"], "dat": metadata["dat"],
    }
    assert device.room_c is device.ambient_c is None


@pytest.mark.parametrize("name,value", [
    ("SetTem", -1), ("SetTem", 2**31), ("SetTem", True), ("SetTem", "1"),
    ("SetTem", 1.5), ("SetTem", None), ("SetTem", []), ("SetTem", {}),
    ("Pow", 2), ("Quiet", 2), ("Mod", 5), ("WdSpd", 7),
    ("HeatCoolType", 2), ("AllErr", -1), ("Health", 1), ("TemSen", 1),
])
def test_dv302_bad_tail_is_atomic_including_clock(name, value):
    device = controller()
    device.last_step = 0
    before = dict(device.state), device.last_step, device.name
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "cmd", "opt": ["Pow", name], "p": [1, value]})
    assert (device.state, device.last_step, device.name) == before
    assert poll(device, ["Pow"])["dat"] == [0]


def test_dv302_metadata_command_ack_and_status_read_final_text():
    device = controller()
    assert exchange(device, {
        "t": "cmd", "opt": ["name", "host", "time"],
        "p": ["Renamed", "local", "2026-10-24 12:34:56"],
    }) == {"t": "res", "r": 200, "opt": ["name", "host", "time"],
           "p": ["Renamed", "local", "2026-10-24 12:34:56"],
           "val": ["Renamed", "local", "2026-10-24 12:34:56"]}
    assert poll(device, ["name", "host", "time"])["dat"] == [
        "Renamed", "local", "2026-10-24 12:34:56"]
    fresh = controller()
    assert poll(fresh, ["host", "time"])["dat"] == ["", "1970-01-01 00:00:00"]


def test_dv302_oversized_command_precedes_cache_and_clock_mutation():
    device = controller()
    device.last_step = 0
    before = dict(device.state), device.last_step, device.name
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "cmd", "opt": ["HeatSvStTemMax"] * 40, "p": [1] * 40})
    assert (device.state, device.last_step, device.name) == before


@pytest.mark.parametrize("count", (49, 50, 51))
def test_dv302_column_count_source_cliff_and_safe_overflow(count):
    device = controller()
    if count == 49:
        assert poll(device, ["Pow"] * count)["dat"] == [0] * count
    elif count == 50:
        assert poll(device, ["Pow"] * count) == {
            "t": "dat", "r": 200, "mac": device.mac, "cols": [], "dat": []}
    else:
        with pytest.raises(InvalidPacket):
            poll(device, ["Pow"] * count)


def test_dv302_valueless_metadata_keeps_columns_without_fake_readouts():
    device = controller()
    columns = ["SwhWifi", "SwhWifiRes", "SwhWifiConf", "AutoConnCloud",
               "datDump", "datRep", "datFailRep", "datPeroid", "subCnt",
               "useTCP", "country", "city", "cnty", "cityid", "lat", "lon"]
    assert poll(device, columns) == {
        "t": "dat", "r": 200, "mac": device.mac, "cols": columns, "dat": []}


@pytest.mark.parametrize("name,limit", [("name", 90), ("host", 20)])
def test_dv302_metadata_width_and_atomic_duplicate_readback(name, limit):
    device = controller()
    text = "x" * limit
    reply = exchange(device, {"t": "cmd", "opt": [name, name], "p": ["first", text]})
    assert reply["p"] == reply["val"] == [text, text]
    assert poll(device, [name])["dat"] == [text]
    before = dict(device.state), device.name, device.last_step
    for invalid in ("", text + "x", "nul\0tail"):
        with pytest.raises(InvalidPacket):
            exchange(device, {"t": "cmd", "opt": ["Pow", name], "p": [1, invalid]})
        assert (device.state, device.name, device.last_step) == before


@pytest.mark.parametrize("requested,normalized", [
    ("2026-1-2 3:4:5", "2026-01-02 03:04:05"),
    ("2026-02-30 00:00:00", "2026-03-02 00:00:00"),
    ("2026-01-02 03:04:05Z", "2026-01-02 03:04:05"),
    ("1970-01-01 00:00:00", "1970-01-01 00:00:00"),
    ("1969-12-31 23:59:59", "2106-02-07 06:28:15"),
])
def test_dv302_calendar_normalizes_before_ack_and_fresh_status(requested, normalized):
    device = controller()
    reply = exchange(device, {"t": "cmd", "opt": ["time"], "p": [requested]})
    assert reply["p"] == reply["val"] == [normalized]
    assert poll(device, ["time"])["dat"] == [normalized]


@pytest.mark.parametrize("invalid", ["x" * 20, "2026-10-24", "2026-10-24 12:34",
                                   "2026-10-24 12:34:56ZZ"])
def test_dv302_partial_clock_parse_is_safe_atomic_rejection(invalid):
    device = controller()
    before = dict(device.state), device.last_step
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "cmd", "opt": ["Pow", "time"], "p": [1, invalid]})
    assert (device.state, device.last_step) == before


def test_dv302_final_metadata_reply_amplification_preflights_before_mutation():
    device = controller()
    device.last_step = 0
    before = dict(device.state), device.name, device.last_step
    # Short duplicate inputs expand into30 copies of the final90-byte getter in each array.
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "cmd", "opt": ["name"] * 30,
                          "p": ["a"] * 29 + ["z" * 90]})
    assert (device.state, device.name, device.last_step) == before


@pytest.mark.parametrize("name,count", [("name", 45), ("host", 10)])
def test_dv302_metadata_limits_count_utf8_bytes(name, count):
    device = controller()
    text = "é" * count
    assert exchange(device, {"t": "cmd", "opt": [name], "p": [text]})["val"] == [text]
    assert poll(device, [name])["dat"] == [text]
    before = dict(device.state), device.name, device.last_step
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "cmd", "opt": ["Pow", name], "p": [1, text + "é"]})
    assert (device.state, device.name, device.last_step) == before


def test_dv302_name_change_updates_discovery_and_failed_batch_does_not():
    device = controller()
    exchange(device, {"t": "cmd", "opt": ["name"], "p": ["Renamed"]})
    assert device.profile.handler.advertise(device, {"t": "scan"})[0].inner["name"] == "Renamed"
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "cmd", "opt": ["name", "apssid"], "p": ["Wrong", "ssid"]})
    assert device.profile.handler.advertise(device, {"t": "scan"})[0].inner["name"] == "Renamed"
    assert poll(device, ["name", "apssid", "appsw"])["dat"] == ["Renamed", "", ""]


def test_dv302_fifty_commands_mutate_but_return_native_empty_arrays():
    device = controller()
    assert exchange(device, {"t": "cmd", "opt": ["Pow"] * 50, "p": [0] * 49 + [1]}) == {
        "t": "res", "r": 200, "opt": [], "p": [], "val": []}
    assert poll(device, ["Pow"])["dat"] == [1]


def test_dv302_fifty_filled_status_slots_include_short_unknown_names():
    device = controller()
    assert poll(device, ["Pow"] * 49 + ["Unknown"]) == {
        "t": "dat", "r": 200, "mac": device.mac, "cols": [], "dat": []}
    assert poll(device, ["Pow"] * 48 + ["Unknown"])["dat"] == [0] * 48
