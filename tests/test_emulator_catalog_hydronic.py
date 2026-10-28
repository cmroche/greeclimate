"""Literal source expectations for the bounded W05F hydronic wire model."""

import base64
from copy import deepcopy
import json
from pathlib import Path
import socket

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.catalog_hydronic import GENERIC_KEY, PROFILES, READABLE
from gree_emulator.wire import InvalidPacket, decode_outer, encode_reply

VECTORS = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-hydronic-vectors_research.json").read_text())


@pytest.fixture
def device(monkeypatch):
    monkeypatch.setattr("gree_emulator.profiles.catalog_hydronic.monotonic", lambda: 1000)
    profile, = PROFILES
    return EmulatedDevice("hydronic", VECTORS["mac"], "synthetic-hydronic", "809030",
                          VECTORS["key"].encode(), profile,
                          dict(profile.initial_state), last_step=1000)


def packet(device, inner, selector=0, uid=37, **changes):
    payload = inner if selector == 2 else base64.b64encode(
        AES.new(device.key if selector == 0 else GENERIC_KEY, AES.MODE_ECB).encrypt(
            pad(json.dumps(inner, separators=(",", ":")).encode(), 16))).decode()
    return {"t": "pack", "i": selector, "uid": uid, "cid": "independent-peer",
            "tcid": device.mac, "pack": payload, **changes}


def response(device, inner, selector=0, uid=37):
    reply, = device.profile.handler.handle(device, packet(device, inner, selector, uid))
    wire = encode_reply(reply)
    assert not wire.endswith(b"\n")
    outer = json.loads(wire)
    expected_selector = 1 if inner["t"] == "bind" else 0
    assert outer["i"] == expected_selector
    assert outer["uid"] == (0 if inner["t"] == "bind" else uid)
    assert outer["tcid"] == ("null" if inner["t"] == "bind" else "independent-peer")
    selected = GENERIC_KEY if expected_selector else device.key
    return json.loads(unpad(AES.new(selected, AES.MODE_ECB).decrypt(base64.b64decode(outer["pack"])), 16))


def status(device, columns):
    return response(device, {"t": "status", "mac": device.mac, "cols": columns})


def test_exact_identity_boundaries_and_bind_lifecycle(device):
    handler = device.profile.handler
    assert device.profile.mids == ("809030",)
    advert, = handler.advertise(device, {"t": "scan"})
    discovered = json.loads(unpad(AES.new(GENERIC_KEY, AES.MODE_ECB).decrypt(
        base64.b64decode(json.loads(encode_reply(advert))["pack"])), 16))
    assert discovered == {"t": "dev", "cid": device.mac, "mac": device.mac,
                          "key": VECTORS["key"], "lock": 0, "mid": "809030",
                          "name": "synthetic-hydronic"}
    assert device.profile.hid == "362001060629+W05F(QCOM)V4.2.bin"
    assert device.profile.max_request_bytes == 3072
    for selector in (0, 1, 2, 256):
        result = response(device, {"t": "bind", "mac": "source-ignores-inner-target"}, selector)
        assert result == {"t": "bindok", "r": 200, "mac": device.mac, "key": VECTORS["key"]}
    assert set(READABLE) == set(VECTORS["readable"])
    assert len(READABLE) + len(VECTORS["write_only"]) == 38
    response(device, {"t": "cmd", "opt": ["lock"], "p": [1]})
    assert handler.handle(device, packet(device, {"t": "bind"}, 1)) == []
    assert status(device, ["lock"])["dat"] == [1]
    response(device, {"t": "cmd", "opt": ["lock"], "p": [0]})
    assert response(device, {"t": "bind"}, 1)["key"] == VECTORS["key"]


@pytest.mark.parametrize("vector", VECTORS["uniform_reports"])
def test_every_scalar_getter_uses_original_constructor_and_raw_units(device, vector):
    status(device, ["Pow"])
    device.state["_hydronic"]["report"][:] = bytes([vector["byte"]]) * (8 * 0x74)
    assert status(device, VECTORS["scalar_columns"])["dat"] == vector["dat"]


def test_arrays_error_references_and_read_write_roles(device):
    status(device, ["Pow"])
    runtime = device.state["_hydronic"]
    runtime["report"][:] = bytes(8 * 0x74)
    assert status(device, ["as1", "as2", "as3", "err", "Er"])["dat"] == [
        ["", ""], ["", "", ""], ["", "", ""], [], 0]
    runtime = device.state["_hydronic"]
    runtime["report"][2 * 0x74 + 8] = 1
    runtime["report"][2 * 0x74 + 10:2 * 0x74 + 110] = bytes([40]) * 100
    runtime["errors"][:] = [3, 17]
    assert status(device, ["as2", "err", "err", "Er"])["dat"] == [
        ["28" * 100, "", ""], [3, 17], [3, 17], 1]
    result = status(device, ["Pow", "name", "as", "mac", "ClrEr", "missing", "Pow"])
    assert result["cols"] == ["Pow", "Pow"] and result["dat"] == [0, 0]
    assert status(device, ["name", "as", "mac", "ClrEr"])["r"] == 417


@pytest.mark.parametrize("vector", VECTORS["commands"])
def test_requested_ack_distinct_from_pending_and_fresh_board_reports(device, monkeypatch, vector):
    result = response(device, {"t": "cmd", "opt": vector["opt"], "p": vector["p"]})
    assert result == {"t": "res", "r": 200, "opt": vector["opt"], "p": vector["p"]}
    assert status(device, vector["cols"])["dat"] == vector["immediate"]
    monkeypatch.setattr("gree_emulator.profiles.catalog_hydronic.monotonic", lambda: 1011.9)
    assert status(device, vector["cols"])["dat"] == vector["immediate"]
    monkeypatch.setattr("gree_emulator.profiles.catalog_hydronic.monotonic", lambda: 1012)
    assert status(device, vector["cols"])["dat"] == vector["after_12_seconds"]


def test_command_order_bitwise_accumulation_and_unknown_filtering(device):
    result = response(device, {"t": "cmd", "mac": "arbitrary-native-ack-target",
                               "opt": ["Pow", "Pow", "Mod", "Quiet", "Temp", "lock"],
                               "p": [1, 0, 3, 2, 22, 2]})
    assert result == {"t": "res", "r": 200, "mac": "arbitrary-native-ack-target",
                      "opt": ["Pow", "Pow", "Quiet"], "p": [1, 0, 2]}
    assert status(device, ["Pow", "Mod", "Quiet", "lock"])["dat"] == [0, 1, 0, 0]
    control = device.state["_hydronic"]["control"]
    assert control[10] == 3 and control[11] == 1
    assert response(device, {"t": "cmd", "opt": ["Temp", "TemSen", "name"],
                             "p": [77, 66, "x" * 40]})["opt"] == ["name"]
    assert device.state["_hydronic"]["name"] == "x" * 31


@pytest.mark.parametrize("bad", [None, True, False, 1.5, [], {}, "1", 2147483648, -2147483649])
def test_safe_atomic_validation_keeps_all_state_and_clock(device, bad):
    before, clock = deepcopy(device.state), device.last_step
    with pytest.raises(InvalidPacket):
        response(device, {"t": "cmd", "opt": ["Pow", "ColSetTem"], "p": [1, bad]})
    assert device.state == before and device.last_step == clock


def test_object_input_and_encrypted_only_outputs_with_malformed_recovery(device):
    outer = packet(device, {"t": "status", "mac": device.mac, "cols": ["Pow"]}, 2)
    assert decode_outer(json.dumps(outer).encode())["pack"] == outer["pack"]
    assert response(device, outer["pack"], 2)["dat"] == [0]
    for bad in ({**outer, "i": -1}, {**outer, "i": True}, {**outer, "pack": "{}"},
                {**packet(device, outer["pack"]), "pack": "not-base64"}):
        with pytest.raises(InvalidPacket):
            device.profile.handler.handle(device, bad)
    with pytest.raises(InvalidPacket):
        decode_outer(b'{"t":"pack","i":0,"i":1,"pack":"x"}')
    assert status(device, ["Pow"])["dat"] == [0]


def test_reply_preflight_and_stationary_synthetic_reports_are_isolated(device):
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        response(device, {"t": "cmd", "opt": ["Pow", "name"], "p": [1, "a" * 1000]})
    assert device.state == before
    response(device, {"t": "cmd", "opt": ["Pow", "ColSetTem"], "p": [1, 10]})
    assert device.profile.handler.thermal_target(device) is None
    device.advance(1060)
    assert device.room_c == 26
    other = EmulatedDevice("other", "020000000124", "other", "809030", device.key,
                           device.profile, dict(device.profile.initial_state), last_step=1000)
    assert status(other, ["Pow", "ColSetTem"])["dat"] == [0, 22]


def test_initial_state_does_not_accept_readouts_identity_or_private_fields(device):
    for state in ({"Temp": 20}, {"hid": 1}, {"_hydronic": {}}, {"Mod": 3}, {"lock": 2}):
        with pytest.raises(ValueError):
            device.profile.handler.validate_state(state)


def test_native_hash_aliases_preserve_requested_names_and_duplicate_order(device):
    response(device, {"t": "cmd", "opt": ["ColSxxxxx", "Quiex"], "p": [35, 1]})
    observed = response(device, {"t": "statxx", "mac": device.mac,
                                 "cols": ["ColSxxxxx", "ColSetTem", "Quiex", "Quiet"]})
    assert observed["cols"] == ["ColSxxxxx", "ColSetTem", "Quiex", "Quiet"]
    assert observed["dat"] == [35, 35, 0, 0]


def timer(timer_id=1):
    return {"t": "setT", "id": timer_id, "name": "heating", "enable": 0,
            "hr": 6, "min": 30, "sec": 0, "week": [1, 1, 1, 1, 1, 0, 0], "tz": -5,
            "cmd": [{"mac": [VECTORS["mac"]], "opt": ["Pow", "HtSetTem"], "p": [1, 35]}]}


def test_complete_timer_crud_order_pagination_and_native_errors(device):
    first = timer()
    assert response(device, first) == {"t": "resT", "r": 200}
    assert response(device, first) == {"t": "resT", "r": 403, "msg": "id has been exsit!"}
    stored = {name: value for name, value in first.items() if name != "t"}
    assert response(device, {"t": "queryT", "index": 0, "count": 10}) == {
        "t": "listT", "total": 1, "index": 0, "list": [stored]}
    assert response(device, {**first, "t": "updateT", "hr": 7}) == {"t": "resT", "r": 200}
    assert response(device, {"t": "queryT", "index": 1, "count": 10}) == {
        "t": "listT", "total": 1, "index": 1, "list": []}
    assert response(device, {**first, "id": 2, "hr": 24}) == {
        "t": "resT", "r": 416, "msg": "name/enable/hr/min/sec/week/tz err!"}
    assert response(device, {**first, "id": 2, "cmd": [{"mac": [], "opt": [], "p": []}]}) == {
        "t": "resT", "r": 407, "msg": "cmd/id/mac/opt/p err!"}
    for index in range(2, 11):
        assert response(device, timer(index)) == {"t": "resT", "r": 200}
    assert response(device, timer(11)) == {"t": "resT", "r": 503, "msg": "no place to set time."}
    assert response(device, {"t": "deleteT", "id": 1}) == {"t": "resT", "r": 200}
    assert response(device, {"t": "deleteT", "id": 1}) == {
        "t": "resT", "r": 504, "msg": "id no exsit!"}
    assert response(device, {**timer(), "t": "updateT"}) == {
        "t": "resT", "r": 504, "msg": "id no exsit!"}
    assert device.profile.handler.handle(device, packet(device, {"t": "queryT"})) == []


def test_network_metadata_update_acceptance_never_retains_credentials(device):
    handler = device.profile.handler
    reply, = handler.wlan(device, {"t": "wlan", "ssid": "synthetic", "psw": "not-stored",
                                  "host": "example.invalid"})
    assert json.loads(encode_reply(reply)) == {"t": "ret", "mac": device.mac, "r": 200}
    assert status(device, ["host"])["dat"] == ["example.invalid"]
    assert "not-stored" not in repr(device.state)
    reply, = handler.wlan(device, {"t": "wlan", "ssid": "x" * 32, "psw": "", "host": ""})
    assert json.loads(encode_reply(reply)) == {
        "t": "ret", "mac": device.mac, "r": 416, "msg": "ssid/psw/host len err!"}
    for request in ({"t": "svr", "datHostPort": 7001, "datHost": "192.0.2.1",
                     "tcpPort": 7002, "host": "example.invalid"}, {"t": "loginRes", "r": 200}):
        assert handler.handle(device, packet(device, request)) == []
    assert device.state["_hydronic"]["server"] == {
        "datHostPort": 7001, "datHost": "192.0.2.1", "tcpPort": 7002,
        "host": "example.invalid", "authenticated": True}


def test_update_request_plain_ret_is_queue_acceptance_not_flash_success(device):
    handler = device.profile.handler
    missing, = handler.handle(device, packet(device, {"t": "upgrade"}))
    assert json.loads(encode_reply(missing)) == {
        "t": "ret", "mac": device.mac, "r": 407, "msg": "url err!"}
    queued, = handler.handle(device, packet(device, {"t": "upgrade", "url": "http://example.invalid:8080/fw.bin"}))
    assert json.loads(encode_reply(queued)) == {"t": "ret", "mac": device.mac, "r": 200}
    assert device.state["_hydronic"]["upgrade"] == {
        "url": "http://example.invalid:8080/fw.bin", "host": "example.invalid", "port": 8, "path": "/fw.bin"}
    busy, = handler.handle(device, packet(device, {"t": "upgrade", "url": "http://example.invalid/new.bin"}))
    assert json.loads(encode_reply(busy)) == {
        "t": "ret", "mac": device.mac, "r": 505, "msg": "being Escalating!"}


def test_report_readiness_and_error_gate_do_not_invent_board_success(device, monkeypatch):
    status(device, ["Pow"])
    device.state["_hydronic"]["report"][1] = 0
    observed = response(device, {"t": "cmd", "opt": ["Pow"], "p": [1]})
    assert observed == {"t": "res", "opt": ["Pow"], "p": [1], "r": 404, "msg": "dev exit!"}
    assert status(device, ["Pow"])["dat"] == [0]
    device.state["_hydronic"]["report"][1] = 3
    response(device, {"t": "cmd", "opt": ["Pow"], "p": [1]})
    device.state["_hydronic"]["errors"][:] = [3]
    monkeypatch.setattr("gree_emulator.profiles.catalog_hydronic.monotonic", lambda: 1030)
    assert status(device, ["Pow", "err", "Er"])["dat"] == [1, [3], 1]
    device.state["_hydronic"]["errors"].clear()
    assert status(device, ["Pow"])["dat"] == [0]


def test_signed_selector_uid_and_source_target_rules(device):
    handler = device.profile.handler
    inner = {"t": "status", "mac": device.mac, "cols": ["Pow"]}
    assert response(device, inner, selector=256, uid=-19)["dat"] == [0]
    reply, = handler.handle(device, packet(device, inner, tcid="source-root-does-not-check"))
    assert reply.inner["dat"] == [0]
    for change in ({"uid": 1 << 31}, {"i": 1 << 31}, {"uid": True}):
        with pytest.raises(InvalidPacket):
            handler.handle(device, packet(device, inner, **change))
    wrong_key = AES.new(b"wrongkeywrongkey", AES.MODE_ECB).encrypt(pad(b'{\"t\":\"status\"}', 16))
    with pytest.raises(InvalidPacket):
        handler.handle(device, packet(device, inner, pack=base64.b64encode(wrong_key).decode()))
    assert status(device, ["Pow"])["dat"] == [0]


def test_actual_cli_hydronic_raw_peer_complete_surface():
    from tests.test_emulator_firmware_cli import cli_server, packet as raw_packet, unpack

    records = [{"id": "hydronic", "profile": "sim-catalog-w05f-hydronic-v4.2",
                "mid": "809030", "mac": VECTORS["mac"], "name": "synthetic-hydronic"}]
    with cli_server(records) as (address, identities), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(1)

        def exchange(payload, key=GENERIC_KEY):
            peer.sendto(payload, address)
            data, source = peer.recvfrom(8192)
            assert source == address and not data.endswith(b"\n")
            return unpack(data, key)

        _, advertised = exchange(raw_packet({"t": "scan"}))
        mac, key = advertised["mac"], advertised["key"].encode()
        assert mac == identities["hydronic"]["mac"] == VECTORS["mac"]
        assert advertised == {"t": "dev", "cid": mac, "mac": mac, "key": key.decode(),
                              "lock": 0, "mid": "809030", "name": "synthetic-hydronic"}

        def request(inner, selector=0, uid=37):
            outer = {"t": "pack", "i": selector, "uid": uid, "cid": "raw-peer", "tcid": mac}
            payload = (json.dumps({**outer, "pack": inner}).encode() if selector == 2
                       else raw_packet(outer, inner, key if selector == 0 else GENERIC_KEY))
            return exchange(payload, GENERIC_KEY if inner["t"] == "bind" else key)

        outer, bound = request({"t": "bind", "mac": mac}, 1)
        assert bound == {"t": "bindok", "r": 200, "mac": mac, "key": key.decode()}
        assert (outer["i"], outer["uid"], outer["tcid"]) == (1, 0, "null")
        _, written = request({"t": "cmd", "mac": mac, "opt": ["Pow", "ColSetTem"], "p": [1, 35]})
        assert written == {"t": "res", "mac": mac, "opt": ["Pow", "ColSetTem"], "p": [1, 35], "r": 200}
        outer, fresh = request({"t": "status", "mac": mac,
                                "cols": ["Pow", "ColSetTem", "name", "ClrEr", "TemSen"]}, 2, -19)
        assert fresh == {"t": "dat", "r": 200, "cid": mac, "mac": mac,
                         "cols": ["Pow", "ColSetTem"], "dat": [1, 35]}
        assert (outer["i"], outer["uid"], outer["tcid"]) == (0, -19, "raw-peer")
        request({"t": "bind", "mac": mac}, 1)
        assert request({"t": "status", "mac": mac, "cols": ["Pow", "ColSetTem"]})[1]["dat"] == [1, 35]
        _, configured = exchange(raw_packet({"t": "wlan", "ssid": "synthetic",
                                             "psw": "never-retained", "host": "example.invalid"}))
        assert configured == {"t": "ret", "mac": mac, "r": 200}
        assert request({"t": "status", "mac": mac, "cols": ["host"]})[1]["dat"] == ["example.invalid"]
        first = timer()
        assert request(first)[1] == {"t": "resT", "r": 200}
        assert request({"t": "queryT", "index": 0, "count": 10})[1] == {
            "t": "listT", "total": 1, "index": 0,
            "list": [{name: value for name, value in first.items() if name != "t"}]}
        assert request({"t": "deleteT", "id": 1})[1] == {"t": "resT", "r": 200}
        assert request({"t": "upgrade"})[1] == {"t": "ret", "mac": mac, "r": 407, "msg": "url err!"}
        for malformed in (
                b'{"t":"pack","i":0,"uid":37,"tcid":"' + mac.encode() + b'","pack":"not-base64"}',
                raw_packet({"t": "pack", "i": 0, "uid": 37, "tcid": "020000ffffff"},
                           {"t": "status", "mac": mac, "cols": ["Pow"]}, key)):
            peer.sendto(malformed, address)
            peer.settimeout(0.15)
            with pytest.raises(socket.timeout):
                peer.recvfrom(8192)
            peer.settimeout(1)
        assert request({"t": "status", "mac": mac, "cols": ["Pow"]})[1]["dat"] == [1]
