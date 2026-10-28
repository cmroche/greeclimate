"""Independent MC-ETSBH01 native vectors and explicitly bounded root model."""

import asyncio
import copy
import json
import socket
from pathlib import Path

import pytest

from gree_emulator.__main__ import load_config
from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles import PROFILES, central
from gree_emulator.server import EmulatorServer, start_server
from gree_emulator.wire import InvalidPacket, decode_outer, encode_reply
from tests.test_emulator import peer_packet, peer_reply, receive


FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/session-central_research.json").read_text())
MAC = "020000000001"
KEY = b"0123456789abcdef"
DEFAULT_KEY = b"{yxAHAY_Lm6pbCtd"


def device(mac=MAC, key=KEY):
    profile = central.PROFILES[0]
    return EmulatedDevice(id=mac, mac=mac, name="Not a source metadata override", mid="80901",
                          key=key, profile=profile, state=dict(profile.initial_state),
                          room_c=None, ambient_c=None)


def packet(inner, *, root=MAC, key=KEY, index=0, uid=7, **outer):
    return peer_packet({"t": "pack", "i": index, "uid": uid, "cid": "ignored-peer",
                        "tcid": root, **outer}, inner, key)


def handle(root, inner, **kwargs):
    return root.profile.handler.handle(root, decode_outer(packet(inner, root=root.mac, **kwargs)))


def test_exact_independent_native_vectors():
    root = device()
    for row in FIXTURE["vectors"]:
        outer = decode_outer(json.dumps(row["input_outer"]).encode())
        if outer["t"] == "mate":
            replies = root.profile.handler.mate(root, outer)
        elif outer["t"] == "scan":
            replies = root.profile.handler.advertise(root, outer)
        else:
            replies = root.profile.handler.handle(root, outer)
        assert [encode_reply(reply).decode() for reply in replies] == row["datagrams"], row["label"]
        assert [reply.inner for reply in replies] == row["independent_decrypted"], row["label"]
    assert root.state["Meshid"] == "2a7b"
    assert root.state["Unbind"] == "020000000099"
    assert "Pow" not in root.state
    assert root.profile.handler.thermal_target(root) is None
    assert root.room_c is None


@pytest.mark.parametrize("host", [None, 1, True, [], {}, "", "x" * 256, "white space",
                                  "line\nbreak", "null\0byte", "é", "\x7f"])
def test_mate_host_validation(host):
    with pytest.raises(InvalidPacket):
        decode_outer(json.dumps({"t": "mate", "host": host}).encode())
    with pytest.raises(InvalidPacket):
        decode_outer(b'{"t":"mate"}')


def test_mate_ignores_all_identity_and_pack_selectors():
    root = device()
    outer = decode_outer(json.dumps({"t": "mate", "host": "synthetic-host", "cid": [],
                                     "tcid": {}, "mac": False, "i": True, "uid": "ignored"}).encode())
    reply = root.profile.handler.mate(root, outer)[0]
    assert reply.outer == {"t": "pack", "i": 1, "uid": 0, "cid": MAC, "tcid": "app"}
    assert reply.inner["private_key"] == KEY.decode()
    assert root.state["_host"] == "synthetic-host"


def test_remate_preserves_key_uid_and_root_cache():
    root = device()
    handle(root, {"t": "cmd", "mac": "ignored", "opt": ["Meshid", "Unbind", "Pow"],
                  "p": ["ABCD", "020000000099", 0]}, uid=91)
    for host in ("first-host", "replacement-host"):
        reply = root.profile.handler.mate(root, decode_outer(peer_packet({"t": "mate", "host": host})))[0]
        assert reply.outer["uid"] == 91
        assert reply.inner["private_key"] == KEY.decode()
        assert root.state["_host"] == host
    status = handle(root, {"t": "status", "mac": MAC, "cols": ["Pow", "Meshid", "Unbind"]})[0]
    assert status.inner["dat"] == [1, "abcd", "020000000099"]
    assert device().state == {"Meshid": "0000", "Unbind": ""}


def test_getters_order_duplicates_and_unavailable_fields(monkeypatch):
    monkeypatch.setattr(central.time, "gmtime", lambda: (1970, 1, 1, 0, 0, 0, 3, 1, 0))
    root = device()
    columns = ["Pow", "Meshid", "Pow", "BleON", "Reota", "Lpn", "time", "name",
               "SetTem", "TemSen", "pow", 3, None, {}, "a" * 16, "SubOnline"]
    reply = handle(root, {"t": "status", "mac": MAC, "cols": columns})[0]
    assert reply.inner == {"t": "dat", "mac": MAC, "r": 200,
                           "cols": ["Pow", "Meshid", "Pow", "BleON", "Reota", "Lpn",
                                    "time", "name", "SubOnline"],
                           "dat": [1, "0000", 1, "1970-01-01 00:00:00", []]}


@pytest.mark.parametrize("value", [0, 1, 65535])
def test_pow_is_acknowledgment_not_appliance_power(value):
    root = device()
    reply = handle(root, {"t": "cmd", "opt": ["Pow"], "p": [value]})[0]
    assert reply.inner["p"] == [value]
    assert "val" not in reply.inner
    assert handle(root, {"t": "status", "mac": MAC, "cols": ["Pow"]})[0].inner["dat"] == [1]
    assert root.room_c is None and root.profile.handler.thermal_target(root) is None


@pytest.mark.parametrize("inner", [
    {"t": "cmd", "opt": ["Meshid", "Unknown"], "p": ["abcd", 1]},
    {"t": "cmd", "opt": ["Meshid", "Pow"], "p": ["abcd", True]},
    {"t": "cmd", "opt": ["Meshid", "Pow"], "p": ["abcd", -1]},
    {"t": "cmd", "opt": ["Meshid", "Pow"], "p": ["abcd", 65536]},
    {"t": "cmd", "opt": ["Meshid"], "p": ["123"]},
    {"t": "cmd", "opt": ["Meshid"], "p": ["gggg"]},
    {"t": "cmd", "opt": ["Unbind"], "p": ["not-a-mac"]},
    {"t": "cmd", "opt": ["Pow"], "p": [0.5]},
    {"t": "cmd", "opt": ["Pow"], "p": []},
    {"t": "cmd", "opt": [], "p": []},
    {"t": "cmd", "opt": [{}], "p": [0]},
    {"t": "cmd", "opt": ["name"], "p": ["new-name"]},
    {"t": "status", "mac": "020000000099", "cols": ["Pow"]},
    {"t": "status", "mac": MAC, "sub": MAC, "cols": ["Pow"]},
    {"t": "subDev", "i": -1},
    {"t": "subDev", "i": True},
])
def test_invalid_batches_and_routes_are_atomic(inner):
    root = device()
    before = copy.deepcopy(root.state), root.last_step
    with pytest.raises(InvalidPacket):
        handle(root, inner, uid=99)
    assert (root.state, root.last_step) == before


@pytest.mark.parametrize("page", [0, 5, 300, 2**31 - 1])
def test_empty_topology_retains_page(page):
    reply = handle(device(), {"t": "subDev", "i": page})[0]
    assert reply.inner == {"t": "subList", "r": 200, "c": 0, "i": page, "list": []}


def test_bound_operations_and_ordinary_bind_silence():
    root = device()
    assert handle(root, {"t": "bind", "mac": MAC}, key=DEFAULT_KEY, index=1) == []
    with pytest.raises(InvalidPacket):
        handle(root, {"t": "status", "mac": MAC, "cols": ["Pow"]}, key=DEFAULT_KEY, index=1)
    with pytest.raises(InvalidPacket):
        handle(root, {"t": "status", "mac": MAC, "cols": ["Pow"]}, key=b"fedcba9876543210")


def compact_length(value):
    return len(json.dumps(value, separators=(",", ":")).encode())


def test_native_scratch_bounds_not_fabricated_outer_limit():
    root = device()
    accepted = []
    for count in range(1, 40):
        try:
            reply = handle(root, {"t": "status", "mac": MAC, "cols": ["hid"] * count})[0]
        except InvalidPacket:
            break
        encoded = encode_reply(reply)
        assert compact_length(reply.inner) + 1 <= 1024
        assert len(json.loads(encoded)["pack"]) + 1 <= 1024
        assert encoded.endswith(b"\n") and not encoded.endswith(b"\n\n")
        accepted.append(encoded)
    assert accepted and len(accepted[-1]) > 1024
    assert count < 40
    # Native plaintext scratch is separate from base64 scratch.
    with pytest.raises(InvalidPacket):
        central._reply(root, {"t": "res", "text": "x" * 1024}, 0, 0)


def test_oversize_reply_cannot_mutate_command_or_uid_cache():
    root = device()
    before = copy.deepcopy(root.state), root.last_step
    # Choose a small request whose larger res/mac reply exceeds the native output scratch.
    for count in range(1, 100):
        inner = {"t": "cmd", "opt": ["Meshid"] * count, "p": ["abcd"] * count}
        expected = {"t": "res", "mac": MAC, "r": 200, "opt": inner["opt"], "p": inner["p"]}
        request_cipher = (compact_length(inner) // 16 + 1) * 16
        response_cipher = (compact_length(expected) // 16 + 1) * 16
        if 4 * ((request_cipher + 2) // 3) < 1024 <= 4 * ((response_cipher + 2) // 3):
            break
    else:
        pytest.fail("missing scratch-boundary command")
    with pytest.raises(InvalidPacket):
        handle(root, inner, uid=99)
    assert (root.state, root.last_step) == before
    malformed = decode_outer(packet({"t": "cmd", "opt": ["Meshid"], "p": ["abcd"]}))
    malformed["pack"] = "!"
    with pytest.raises(InvalidPacket):
        root.profile.handler.handle(root, malformed)
    assert (root.state, root.last_step) == before


def test_large_input_does_not_inherit_output_scratch_limit():
    root = device()
    wire = packet({"t": "cmd", "opt": ["Meshid"], "p": ["abcd"], "padding": "x" * 1000})
    assert 1024 < len(wire) <= 2048
    reply = root.profile.handler.handle(root, decode_outer(wire))[0]
    assert reply.inner["p"] == ["abcd"] and root.state["Meshid"] == "abcd"


class Transport:
    def __init__(self):
        self.sent = []

    def sendto(self, data, address):
        self.sent.append((data, address))


async def test_original_receive_bytes_and_ordinary_routing_unchanged():
    root = device()
    ordinary = load_config({"devices": [{"id": "ordinary", "profile": "sim-w04h-v3.55",
                                         "mid": "10001", "mac": "020000000099"}]})[2][0]
    server = EmulatorServer([root, ordinary])
    transport = Transport()
    server.transport = transport
    try:
        wire = packet({"t": "cmd", "opt": ["Meshid"], "p": ["abcd"]})
        server.datagram_received(wire + b" " * (2049 - len(wire)), ("127.0.0.1", 1000))
        assert not transport.sent and root.state == {"Meshid": "0000", "Unbind": ""}
        server.datagram_received(wire + b" " * (2048 - len(wire)), ("127.0.0.1", 1000))
        assert len(transport.sent) == 1 and root.state["Meshid"] == "abcd"
        transport.sent.clear()
        mate = peer_packet({"t": "mate", "host": "synthetic-host"})
        server.datagram_received(mate + b" " * (2049 - len(mate)), ("127.0.0.1", 1000))
        assert not transport.sent and "_host" not in root.state
        server.datagram_received(mate + b" " * (2048 - len(mate)), ("127.0.0.1", 1000))
        assert len(transport.sent) == 1 and "_host" not in ordinary.state
        transport.sent.clear()
        server.datagram_received(peer_packet({"t": "subList", "tcid": MAC}), ("127.0.0.1", 1000))
        assert not transport.sent
        scan = peer_packet({"t": "scan"})
        for size, expected in (
            (1024, {MAC, ordinary.mac}),
            (1025, {MAC}),
            (2048, {MAC}),
            (2049, set()),
        ):
            transport.sent.clear()
            server.datagram_received(scan + b" " * (size - len(scan)), ("127.0.0.1", 1000))
            assert {json.loads(data)["cid"] for data, _ in transport.sent} == expected
    finally:
        server.transport = None
        server.close()
        await server.wait_closed()


async def test_two_central_roots_mate_fanout_and_malformed_recovery():
    roots = [device(), device("020000000002", b"fedcba9876543210")]
    ordinary = load_config({"devices": [{"id": "ordinary", "profile": "sim-w04h-v3.55", "mid": "10001"}]})[2]
    transport, server = await start_server([*roots, *ordinary], "127.0.0.1", 0)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.settimeout(0.15)
            address = transport.get_extra_info("sockname")
            for malformed in (b'{"t":"mate"}', b'{"t":"mate","host":null}',
                              b'{"t":"mate","host":"bad\\nline"}',
                              b'{"t":"mate","host":"a","host":"b"}'):
                peer.sendto(malformed, address)
                with pytest.raises(socket.timeout):
                    await asyncio.to_thread(receive, peer)
            assert all("_host" not in root.state for root in roots)
            for host in ("synthetic-host", "replacement-host"):
                peer.sendto(peer_packet({"t": "mate", "host": host, "tcid": "ignored",
                                         "cid": "ignored", "mac": "ignored"}), address)
                replies = [peer_reply(await asyncio.to_thread(receive, peer), DEFAULT_KEY) for _ in roots]
                assert {reply["outer"]["cid"]: reply["inner"]["private_key"] for reply in replies} == {
                    MAC: "0123456789abcdef", "020000000002": "fedcba9876543210"}
                assert all(root.state["_host"] == host for root in roots)
                assert "_host" not in ordinary[0].state
                with pytest.raises(socket.timeout):
                    await asyncio.to_thread(receive, peer)
            peer.sendto(packet({"t": "cmd", "opt": ["Pow"], "p": [0]}), address)
            assert peer_reply(await asyncio.to_thread(receive, peer), KEY)["inner"]["p"] == [0]
            peer.sendto(packet({"t": "status", "mac": MAC, "cols": ["Pow"]}), address)
            assert peer_reply(await asyncio.to_thread(receive, peer), KEY)["inner"]["dat"] == [1]
    finally:
        server.close()
        await server.wait_closed()


def test_cli_compatible_config_stable_identity_and_no_children():
    assert PROFILES["sim-mc-etsbh01-v1.38"] is central.PROFILES[0]
    config = FIXTURE["cli_config"]
    listen, port, roots = load_config(config)
    assert listen == "127.0.0.1" and port == 0
    assert roots[0].mac == MAC and roots[0].room_c is None and roots[0].ambient_c is None
    assert roots[0].key == load_config(config)[2][0].key
    assert roots[0].profile.max_children == 0
    for field in ("room_c", "ambient_c"):
        invalid = copy.deepcopy(config)
        invalid["devices"][0][field] = 24
        with pytest.raises(ValueError, match=field):
            load_config(invalid)
    invalid = copy.deepcopy(config)
    invalid["devices"].append({"id": "child", "profile": "sim-mc-etsbh01-v1.38", "mid": "80901", "parent": "central"})
    with pytest.raises(ValueError, match="parent"):
        load_config(invalid)
    for state in ({"Pow": 0}, {"Meshid": "bad"}, {"Unbind": "abcd"}, {"Meshid": "ABCD"}):
        invalid = copy.deepcopy(config)
        invalid["devices"][0]["state"] = state
        with pytest.raises(ValueError):
            load_config(invalid)


def test_source_timer_crud_vectors_and_replacement():
    fixture = json.loads((Path(__file__).parent / "fixtures/emulator/session-central-timers_research.json").read_text())
    root = device()
    for row in fixture["vectors"]:
        assert handle(root, row["request"])[0].inner == row["expected"], row["label"]


def test_timer_atomic_errors_isolation_restart_and_recovery():
    fixture = json.loads((Path(__file__).parent / "fixtures/emulator/session-central-timers_research.json").read_text())
    request = fixture["vectors"][0]["request"]
    root, other = device(), device("020000000002")
    handle(root, request)
    before = copy.deepcopy(root.state)
    for invalid in (
        {**request, "week": [1]},
        {**request, "cmd": [{"mac": [MAC], "opt": ["A|B"], "p": [1]}]},
        {"t": "queryT", "index": -1, "count": 1},
        {"t": "deleteT", "id": True},
    ):
        with pytest.raises(InvalidPacket):
            handle(root, invalid, uid=999)
        assert root.state == before
    query = {"t": "queryT", "index": 0, "count": 1}
    assert handle(root, query)[0].inner["total"] == 1
    assert handle(other, query)[0].inner["total"] == 0
    assert handle(device(), query)[0].inner["total"] == 0
    assert handle(root, {"t": "queryT", "index": 1, "count": 5})[0].inner["list"] == []
    assert handle(root, {"t": "deleteT", "id": 99})[0].inner == {"t": "resT", "r": 200}
    assert handle(root, query)[0].inner["total"] == 1


@pytest.mark.parametrize("page, expected", [(0, 0), (256, 0), (-1, 255), (511, 255)])
def test_lowercase_mesh_enumeration(page, expected):
    assert handle(device(), {"t": "subdev", "i": page})[0].inner == {
        "t": "sublist", "r": 200, "c": 0, "i": expected, "list": []}


def test_mesh_ack_normalizes_and_time_command_is_readout(monkeypatch):
    root = device()
    assert handle(root, {"t": "cmd", "opt": ["Meshid"], "p": ["2A7B"]})[0].inner["p"] == ["2a7b"]
    monkeypatch.setattr(central, "_clock", lambda: "1970-01-01 00:00:00")
    assert handle(root, {"t": "cmd", "opt": ["time"], "p": ["2099-12-31 12:00:00"]})[0].inner["p"] == ["1970-01-01 00:00:00"]
    assert handle(root, {"t": "status", "mac": MAC, "cols": ["No", "time"]})[0].inner == {
        "t": "dat", "mac": MAC, "r": 200, "cols": ["No"] * 21 + ["time"],
        "dat": ["1970-01-01 00:00:00"]}


def test_numeric_parameter_acks_are_not_balanced_getter_values():
    root = device()
    result = handle(root, {"t": "cmd", "opt": ["brand", "brand", "Meshid", "Unbind"],
                           "p": [65536, -1, 42, 7]})[0].inner
    assert result["p"] == [0, 65535, 42, 7]
    assert handle(root, {"t": "status", "mac": MAC,
                         "cols": ["brand", "Meshid", "Unbind"]})[0].inner == {
        "t": "dat", "mac": MAC, "r": 200, "cols": ["brand", "Meshid", "Unbind"],
        "dat": ["0000", ""]}
    assert root.profile.handler.advertise(root, {})[0].inner["brand"] == "gree"


def test_timer_reply_preflight_precedes_state_and_uid_mutation(monkeypatch):
    fixture = json.loads((Path(__file__).parent / "fixtures/emulator/session-central-timers_research.json").read_text())
    root = device()
    before = copy.deepcopy(root.state)
    def oversized(*args):
        raise InvalidPacket("synthetic preflight failure")
    monkeypatch.setattr(central, "_reply", oversized)
    with pytest.raises(InvalidPacket):
        handle(root, fixture["vectors"][0]["request"], uid=999)
    assert root.state == before


def test_mesh_provisioning_state_only_changes_for_first_selector():
    root = device()
    handle(root, {"t": "cmd", "opt": ["Pow", "Mesh"], "p": [0, 9]})
    assert handle(root, {"t": "status", "mac": MAC, "cols": ["Mesh"]})[0].inner["dat"] == [0]
    assert handle(root, {"t": "cmd", "opt": ["Mesh"], "p": [9]})[0].inner["p"] == [9]
    assert handle(root, {"t": "status", "mac": MAC, "cols": ["Mesh"]})[0].inner["dat"] == [2]


def test_multiple_timer_ids_replace_order_pagination_and_delete():
    root = device()
    first = {"t": "setT", "id": 7, "name": "wake", "enable": 1, "hr": 6, "min": 30,
             "week": [1, 0, 0, 0, 0, 0, 0],
             "cmd": [{"mac": [MAC], "opt": ["Pow"], "p": [1]}]}
    second = {"t": "updateT", "id": 8, "name": "sleep", "enable": 0, "hr": 22, "min": 45,
              "week": [0, 1, 0, 0, 0, 0, 0],
              "cmd": [{"mac": [MAC], "opt": ["Pow"], "p": [0]}]}
    first_row = {"id": 7, "name": "wake", "enable": 1, "tz": 8, "sec": 0,
                 "hr": 6, "min": 30, "week": [1, 0, 0, 0, 0, 0, 0],
                 "cmd": [{"mac": [MAC], "opt": ["Pow"], "p": [1]}]}
    second_row = {"id": 8, "name": "sleep", "enable": 0, "tz": 8, "sec": 0,
                  "hr": 22, "min": 45, "week": [0, 1, 0, 0, 0, 0, 0],
                  "cmd": [{"mac": [MAC], "opt": ["Pow"], "p": [0]}]}
    for request in (first, second):
        assert handle(root, request)[0].inner == {"t": "resT", "r": 200}
    query = {"t": "queryT", "index": 0, "count": 2}
    assert handle(root, query)[0].inner == {
        "t": "listT", "index": 0, "total": 2, "list": [first_row, second_row]}
    assert handle(root, {**query, "index": 1})[0].inner == {
        "t": "listT", "index": 1, "total": 2, "list": [second_row]}
    handle(root, {**first, "name": "replaced", "hr": 7})
    assert handle(root, query)[0].inner == {
        "t": "listT", "index": 0, "total": 2,
        "list": [second_row, {**first_row, "name": "replaced", "hr": 7}]}
    handle(root, {"t": "deleteT", "id": 8})
    assert handle(root, query)[0].inner == {
        "t": "listT", "index": 0, "total": 1,
        "list": [{**first_row, "name": "replaced", "hr": 7}]}
    assert handle(root, {**query, "count": 0})[0].inner["list"] == []
    assert handle(device(), query)[0].inner == {
        "t": "listT", "index": 0, "total": 0, "list": []}
