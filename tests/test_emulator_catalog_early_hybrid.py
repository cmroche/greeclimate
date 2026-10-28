"""Independent WB05DF/UR vectors; non-WB hybrid sources remain paused."""
import base64
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.profiles import catalog_early_hybrid as hybrid
from gree_emulator.wire import InvalidPacket, encode_reply

EVIDENCE = json.loads((Path(__file__).parent / "fixtures" / "emulator" /
                       "catalog-early-hybrid_research.json").read_text())
WIRE = json.loads((Path(__file__).parent / "fixtures" / "emulator" /
                   "catalog-early-hybrid-wb-wire_research.json").read_text())
LIFECYCLE = json.loads((Path(__file__).parent / "fixtures" / "emulator" /
                        "catalog-early-hybrid-wb-lifecycle_research.json").read_text())
UDP = json.loads((Path(__file__).parent / "fixtures" / "emulator" /
                  "catalog-early-hybrid-wb-udp_research.json").read_text())
SOURCES = [source for source in EVIDENCE["sources"] if source["historical_index"] in (20, 21)]
KEY = b"0123456789abcdef"
GENERIC = b"a3K8Bx%2r8Y7#xDh"
GCM_GENERIC = b"{yxAHAY_Lm6pbC/<"
MAC = "020000000001"


def device(source):
    profile = next(profile for profile in hybrid.WB_PROFILES
                   if profile.source_sha256 == source["source_sha256"])
    return SimpleNamespace(profile=profile, mac=MAC, mid=profile.mids[0], name="Hybrid",
                           key=KEY, last_step=1000.0, state=dict(profile.initial_state))


def packet(inner, *, index=0, uid=42, target=MAC, key=None, ecb=False):
    plain = json.dumps(inner, separators=(",", ":")).encode()
    key = key or ((GENERIC if ecb else GCM_GENERIC) if index else KEY)
    outer = {"t": "pack", "i": index, "uid": uid, "cid": "peer", "tcid": target}
    if ecb:
        encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(plain, 16))
    else:
        cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex("5440784449675a516c5e6313"))
        cipher.update(b"qualcomm-test")
        encrypted, tag = cipher.encrypt_and_digest(plain)
        outer["tag"] = base64.b64encode(tag).decode()
    outer["pack"] = base64.b64encode(encrypted).decode()
    return outer


def unpack(reply, *, discovery=False):
    raw = encode_reply(reply)
    assert not raw.endswith(b"\n")
    outer = json.loads(raw)
    assert outer["cid"] == ("" if discovery else MAC)
    assert outer["tcid"] == ("" if discovery else "peer")
    if discovery:
        assert outer["uid"] == 0 and outer["i"] == 1
    encrypted = base64.b64decode(outer["pack"])
    if discovery:
        assert "tag" not in outer and reply.codec == "aes-ecb-pkcs7"
        plain = unpad(AES.new(GENERIC, AES.MODE_ECB).decrypt(encrypted), 16)
    else:
        assert "tag" in outer and reply.codec == "aes-gcm"
        key = GCM_GENERIC if outer["i"] else KEY
        cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex("5440784449675a516c5e6313"))
        cipher.update(b"qualcomm-test")
        plain = cipher.decrypt_and_verify(encrypted, base64.b64decode(outer["tag"]))
    assert not plain.endswith(b"\n")
    return json.loads(plain)


def exchange(root, inner, **kwargs):
    reply, = root.profile.handler.handle(root, packet({"mac": MAC, **inner}, **kwargs))
    assert reply.codec == "aes-gcm"
    return unpack(reply)


@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_exact_finite_table_and_every_raw_numeric_get_set(source):
    root = device(source)
    handler = root.profile.handler
    assert list(handler.ordered_names) == source["numeric_slots"]
    assert len(handler.ordered_names) == source["numeric_bound"] == 495
    native = next(row["numeric_setter_native"] for row in WIRE["sources"]
                  if row["source_sha256"] == source["source_sha256"])
    proven = set(native["ACK_names"]) | {"Pow"} | set(source["numeric_getter_override_names"])
    assert handler.numeric - hybrid.LOCAL <= proven
    for name in dict.fromkeys(source["numeric_slots"]):
        if name in handler.special or name in hybrid.LOCAL:
            continue
        assert exchange(root, {"t": "cmd", "opt": [name], "p": [65537]}) == {
            "t": "res", "mac": "", "p": [65537], "opt": [name], "r": 200}
        assert exchange(root, {"t": "status", "cols": [name]}) == {
            "t": "dat", "uid": 42, "mac": MAC, "cid": MAC,
            "dat": [1], "cols": [name], "r": 200}
    assert ("EnvTem" in handler.fields) == (source["historical_index"] != 17)


@pytest.mark.parametrize("source", SOURCES)
def test_every_metadata_getter_ragged_values_and_unknown_order(source):
    root = device(source)
    for vector in source["metadata_getters"]:
        result = exchange(root, {"t": "status", "cols": [vector["name"]]})
        assert result["cols"] == [vector["name"]]
        assert result["dat"] == vector["values"]
    result = exchange(root, {"t": "status", "cols": [
        "unknown", "Pow", "MOta", "DevID", "MafIdf", "Pow", "hid"]})
    assert result["cols"] == ["Pow", "MOta", "DevID", "MafIdf", "Pow", "hid"]
    assert result["dat"] == [0, 0, source["hid"]]
    assert exchange(root, {"t": "status", "cols": ["Onoff", "ReportClientID"]})["cols"] == []


@pytest.mark.parametrize("source", SOURCES)
def test_every_numeric_boundary_duplicates_ack_and_fresh_status(source):
    root = device(source)
    for vector in EVIDENCE["numeric_boundaries"]:
        result = exchange(root, {"t": "cmd", "opt": ["Pow"], "p": [vector["input"]]})
        assert result["p"] == [vector["input"]] and "val" not in result
        assert exchange(root, {"t": "status", "cols": ["Pow"]})["dat"] == [vector["stored"]]
    assert exchange(root, {"t": "cmd", "opt": ["Pow", "Pow", "Pow"],
                           "p": [7, 65537, -1]}) == {
        "t": "res", "mac": "", "p": [7, 65537, -1],
        "opt": ["Pow", "Pow", "Pow"], "r": 200}
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket, match="mixed scalar namespaces"):
        exchange(root, {"t": "cmd", "opt": ["Pow", "name"], "p": [1, "ignored"]})
    assert root.state == before
    assert exchange(root, {"t": "status", "cols": ["Pow", "Pow"]})["dat"] == [65535, 65535]


@pytest.mark.parametrize("source", SOURCES)
def test_separate_numeric_setter_and_metadata_getter_storage(source):
    root = device(source)
    for name in source["numeric_getter_override_names"]:
        value = next(row["values"] for row in source["metadata_getters"] if row["name"] == name)
        assert exchange(root, {"t": "cmd", "opt": [name], "p": [65537]})["p"] == [65537]
        assert root.state[name] == 1
        result = exchange(root, {"t": "status", "cols": [name]})
        assert result["cols"] == [name] and result["dat"] == value


@pytest.mark.parametrize("source", SOURCES)
def test_local_setters_raw_addresses_write_only_frames_and_clock(source):
    root = device(source)
    for name in source["rejected_local_setters"]:
        before = deepcopy(root.state)
        with pytest.raises(InvalidPacket):
            exchange(root, {"t": "cmd", "opt": ["Pow", name], "p": [1, "ignored"]})
        assert root.state == before
    for name, value in (("host", "test.example"), ("lat", "12.5"), ("lon", "-1.0")):
        expected = "" if name == "host" else value
        assert exchange(root, {"t": "cmd", "opt": [name], "p": [value]})["p"] == [expected]
    assert root.state["_runtime"]["host"] == "test.example"
    assert exchange(root, {"t": "cmd", "opt": ["name"], "p": ["ignored"]})["p"] == [""]
    assert root.name == "Hybrid"
    assert exchange(root, {"t": "cmd", "opt": ["lat", "lat"], "p": ["1", "2"]})["p"] == ["2", "2"]
    assert exchange(root, {"t": "status", "cols": ["lat", "lat"]})["dat"] == ["2", "2"]
    exchange(root, {"t": "cmd", "opt": ["time"], "p": ["2026-02-03 04:05:06"]})
    root.last_step += 2
    assert exchange(root, {"t": "status", "cols": ["time"]})["dat"] == ["2026-02-03 04:05:08"]
    exchange(root, {"t": "cmd", "opt": ["BleON", "Meshid"],
                    "p": ["aabbccddeeff", "1234"]})
    assert exchange(root, {"t": "status", "cols": ["BleON", "Mesh", "Meshid"]})["dat"] == [
        "aabbccddeeff", 0, "1234"]
    assert exchange(root, {"t": "cmd", "opt": ["Mesh", "Unbind"],
                           "p": ["010203040506", "aabbccddeeff"]})["p"] == [
        0, "aabbccddeeff"]
    assert exchange(root, {"t": "status", "cols": ["BleON", "Mesh", "Unbind"]})["dat"] == [
        "010203040506", 0, "aabbccddeeff"]
    response = exchange(root, {"t": "cmd", "opt": ["ReportClientID", "Onoff"],
                               "p": ["app", '["1234011"]']})
    assert response["p"] == [] and response["opt"] == []
    assert root.state["_runtime"]["frames"]["ReportClientID"] == bytes.fromhex(
        "7e7e126a61707000000000000000000000000000")
    assert root.state["_runtime"]["onoff_frames"] == [bytes.fromhex("000334120600010530020001")]
    assert exchange(root, {"t": "cmd", "opt": ["AppTimer", "ModelType"],
                           "p": ["ignored", "ignored"]})["p"] == [0, ""]


@pytest.mark.parametrize("source", SOURCES)
def test_timer_full_lifecycle_and_unchanged_appliance_cache(source):
    root = device(source)
    vectors = WIRE["canonical_timer"]
    assert exchange(root, vectors["set"]) == {"t": "resT", "r": 200}
    assert exchange(root, vectors["query"]) == vectors["expected"]
    assert exchange(root, {"t": "status", "cols": ["Pow"]})["dat"] == [0]
    updated = {**vectors["set"], "t": "updateT", "name": "Changed"}
    assert exchange(root, updated) == {"t": "resT", "r": 200}
    assert exchange(root, vectors["query"])["list"][0]["name"] == "Changed"
    assert exchange(root, {"t": "deleteT", "id": 257}) == {"t": "resT", "r": 200}
    assert exchange(root, vectors["query"])["list"] == []
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "deleteT", "id": 257})
    assert root.state == before


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("value", (True, None, 1.5, [], {}, 2147483648, -2147483649))
def test_safe_atomic_invalid_scalar_policy(source, value):
    root = device(source)
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "cmd", "opt": ["Pow", "Mod"], "p": [1, value]})
    assert root.state == before


@pytest.mark.parametrize("source", SOURCES)
def test_wire_binding_discovery_targets_keys_isolation_and_restart(source):
    root, other = device(source), device(source)
    advertised, = root.profile.handler.advertise(root, {"t": "scan"})
    discovery = unpack(advertised, discovery=True)
    assert discovery["mid"] == root.mid
    assert ("hid" in discovery) == (source["historical_index"] != 17)
    for index in (0, 1):
        assert exchange(root, {"t": "bind", "mac": MAC}, index=index) == {
            "r": 200, "t": "bindok", "mac": MAC, "key": KEY.decode()}
    exchange(root, {"t": "cmd", "opt": ["Pow"], "p": [1]})
    assert other.state["Pow"] == 0 and device(source).state["Pow"] == 0
    for arguments in ({"index": 2}, {"target": "020000000002"}, {"key": b"xxxxxxxxxxxxxxxx"}):
        before = deepcopy(root.state)
        with pytest.raises(InvalidPacket):
            root.profile.handler.handle(root, packet({"t": "status", "cols": ["Pow"]}, **arguments))
        assert root.state == before
    for request in ({"t": "cmd", "opt": ["Pow", "unknown"], "p": [1, 2]},
                    {"t": "cmd", "opt": ["Pow"], "p": []},
                    {"t": "status", "cols": ["Pow"] * 65},
                    {"t": "status", "cols": ["Pow"], "mac": "020000000002"}):
        before = deepcopy(root.state)
        with pytest.raises(InvalidPacket):
            exchange(root, request)
        assert root.state == before
    assert exchange(root, {"t": "dump", "period": 1, "cnt": 1}) == {"t": "ret", "r": 200}
    for kind in ("unknown", "subDev", "binCmd"):
        assert root.profile.handler.handle(root, packet({"t": kind})) == []


@pytest.mark.parametrize("source", SOURCES)
def test_plaintext_lifecycle_and_upgrade_request_acknowledgement(source):
    root = device(source)
    handler = root.profile.handler
    assert handler.plaintext_types == ("hbok", "tm", "wlan")
    assert handler.handle(root, {"t": "tm", "time": "2026-03-04 05:06:07"}) == []
    assert exchange(root, {"t": "status", "cols": ["time"]})["dat"] == ["2026-03-04 05:06:07"]
    root.state["_runtime"]["heartbeat_retries"] = 2
    assert handler.handle(root, {"t": "hbok"}) == []
    assert root.state["_runtime"]["heartbeat_retries"] == 0
    response, = handler.handle(root, {
        "t": "wlan", "host": "example.invalid", "ssid": "synthetic", "psw": "example",
    })
    assert encode_reply(response) == b'{"t":"ret","r":200,"mac":""}'
    assert root.state["_runtime"]["network"]["ssid"] == "synthetic"
    assert exchange(root, {"t": "status", "cols": ["host", "mac", "mid"]})["dat"] == ["", "", ""]
    assert exchange(root, {"t": "upgrade", "url": "https://example.invalid/firmware.bin"}) == {
        "t": "ret", "r": 200}
    assert root.state["_runtime"]["upgrade_url"] == "https://example.invalid/firmware.bin"
    for request in ({"t": "wlan", "host": "x", "ssid": "x" * 33, "psw": ""},
                    {"t": "tm", "time": "not-a-calendar"}):
        before = deepcopy(root.state)
        with pytest.raises(InvalidPacket):
            handler.handle(root, request)
        assert root.state == before


@pytest.mark.parametrize("source", SOURCES)
def test_missing_inner_status_target_uses_independent_raw_mac_cache(source):
    root = device(source)
    reply, = root.profile.handler.handle(root, packet({"t": "status", "cols": ["Pow"]}))
    assert unpack(reply)["mac"] == ""


@pytest.mark.parametrize("source", SOURCES)
def test_native_numeric_ack_and_distinct_mid_roles_are_independent_literals(source):
    native = json.loads((Path(__file__).parent / "fixtures" / "emulator" /
                         "catalog-early-hybrid-wb-native_research.json").read_text())
    evidence = next(row for row in native["sources"]
                    if row["source_sha256"] == source["source_sha256"])
    preset = next(vector for vector in evidence["mid_vectors"]
                  if vector["supplied_uint32"] == 65537)
    assert preset["producer_completed"] and preset["discovery_completed"]
    assert preset["discovery"]["mid"] == "10001"
    assert preset["fresh_raw_getter"]["dat"] == [""]
    root = device(source)
    assert root.profile.mids == ("10001",)
    for transaction in evidence["transactions"]:
        if (transaction["qualification"] != "diagnostic-context"
                or transaction["request"].get("opt") != ["Pow"]
                or not isinstance(transaction["output"], dict)
                or type(transaction["request"]["p"][0]) is not int):
            continue
        assert exchange(root, transaction["request"]) == transaction["output"]
        expected = dict(transaction["fresh_status"]["output"], uid=42, cid=MAC)
        assert exchange(root, {"t": "status", "mac": MAC, "cols": ["Pow"]}) == expected


@pytest.mark.parametrize("source", SOURCES)
def test_session_selector_and_peer_direction_are_preserved(source):
    root = device(source)
    for index in (0, 1):
        reply, = root.profile.handler.handle(root, packet(
            {"t": "status", "mac": MAC, "cols": ["Pow"]}, index=index, uid=-1))
        outer = json.loads(encode_reply(reply))
        assert outer["i"] == index and outer["uid"] == -1
        assert outer["cid"] == MAC and outer["tcid"] == "peer"
        assert unpack(reply)["dat"] == [0]
    for peer in ("x" * 64, "bad\0peer"):
        outer = packet({"t": "status", "cols": ["Pow"]})
        outer["cid"] = peer
        before = deepcopy(root.state)
        with pytest.raises(InvalidPacket):
            root.profile.handler.handle(root, outer)
        assert root.state == before


@pytest.mark.parametrize("source", SOURCES)
def test_actual_udp_uses_gcm_packs_and_legacy_discovery(source):
    assert len(hybrid.PROFILES) == 2
    assert all(not profile.id.endswith("-gcm") for profile in hybrid.PROFILES)
    root = device(source)
    advertised, = root.profile.handler.advertise(root, {"t": "scan"})
    assert unpack(advertised, discovery=True)["hid"] == source["hid"]
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        root.profile.handler.handle(root, packet({"t": "status", "cols": ["Pow"]}, ecb=True))
    damaged = packet({"t": "status", "cols": ["Pow"]})
    damaged["tag"] = base64.b64encode(bytes(16)).decode()
    with pytest.raises(InvalidPacket):
        root.profile.handler.handle(root, damaged)
    assert root.state == before
    for index in (0, 1):
        assert exchange(root, {"t": "status", "cols": ["Pow"]}, index=index)["dat"] == [0]


@pytest.mark.parametrize("source", SOURCES)
def test_native_timer_mac_arrays_id_order_and_query_windows(source):
    root = device(source)
    timer = WIRE["canonical_timer"]["set"]
    for timer_id, name in ((9, "Late"), (1, "Timer")):
        exchange(root, {**timer, "id": timer_id, "name": name})
    native = next(row for row in WIRE["sources"]
                  if row["source_sha256"] == source["source_sha256"])
    for vector in native["native_timer_queries"]:
        if vector["scenario"] == "multiple-reordered-query":
            assert exchange(root, vector["input"]) == vector["output"]
    assert exchange(root, {"t": "status", "cols": ["Pow"]})["dat"] == [0]



@pytest.mark.parametrize("source", SOURCES)
def test_native_created_timer_and_calendar_full_transactions(source):
    evidence = next(row for row in LIFECYCLE["sources"]
                    if row["source_sha256"] == source["source_sha256"])
    root = device(source)
    for vector in evidence["created_timer_transactions"]:
        assert exchange(root, vector["input"]) == vector["output"]
    calendar = evidence["calendar"]
    assert exchange(root, calendar["input"], uid=0) == calendar["output"]
    assert exchange(root, {"t": "status", "cols": ["time"]}, uid=0) == calendar["fresh"]


@pytest.mark.parametrize("source", SOURCES)
def test_native_optional_timer_seconds_retains_minute_scratch(source):
    evidence = next(row for row in LIFECYCLE["sources"]
                    if row["source_sha256"] == source["source_sha256"])
    setter, query = evidence["optional_seconds_transactions"]
    root = device(source)
    assert exchange(root, setter["input"]) == setter["output"]
    actual, = exchange(root, query["input"])["list"]
    expected, = query["output"]["list"]
    for field in ("id", "name", "enable", "week", "hr", "min", "sec"):
        assert actual[field] == expected[field]
    assert actual["cmd"][0]["mac"] == [MAC]


@pytest.mark.parametrize("source", SOURCES)
def test_timer_unsupported_targets_and_commands_reject_atomically(source):
    root = device(source)
    before = deepcopy(root.state)
    for command in (
            {"mac": ["020000000002"], "opt": ["Pow"], "p": [1]},
            {"mac": MAC, "opt": ["Pow"], "p": [1]},
            {"opt": ["Mod"], "p": [1]},
            {"opt": ["Pow"], "p": [True]}):
        with pytest.raises(InvalidPacket):
            exchange(root, {**WIRE["canonical_timer"]["set"], "cmd": [command]})
        assert root.state == before


@pytest.mark.parametrize("source", SOURCES)
def test_original_udp_ingress_cipher_roles_are_independent_literals(source):
    evidence = next(row for row in UDP["sources"]
                    if row["source_sha256"] == source["source_sha256"])
    root = device(source)
    for kind in ("session_GCM", "generic_GCM"):
        vector = evidence[kind]
        assert vector["mode_before_receive"] == 0
        assert vector["mode_after_receive"] == vector["mode_after_router"] == 2
        reply, = root.profile.handler.handle(root, vector["input"])
        assert unpack(reply)["dat"] == [0]
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        root.profile.handler.handle(root, evidence["tagless_ECB_rejected"]["input"])
    assert root.state == before


@pytest.mark.parametrize("source", SOURCES)
def test_independent_gcm_reference_math_matches_proved_udp_generic_key(source):
    evidence = next(row for row in WIRE["sources"]
                    if row["source_sha256"] == source["source_sha256"])
    root = device(source)
    for vector in evidence["GCM_standard_reference"]:
        outer = {"t": "pack", "i": 1, "uid": 42, "cid": "peer", "tcid": MAC,
                 "pack": base64.b64encode(bytes.fromhex(vector["ciphertext_hex"])).decode(),
                 "tag": base64.b64encode(bytes.fromhex(vector["tag_hex"])).decode()}
        reply, = root.profile.handler.handle(root, outer)
        result = unpack(reply)
        if json.loads(vector["plaintext"])["t"] == "status":
            assert result["dat"] == [0] and result["mac"] == ""
        else:
            assert result == {"t": "res", "mac": "", "p": [1], "opt": ["Pow"], "r": 200}


@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
async def test_actual_cli_wb_hybrid_complete_source_surface(source):
    """Exercise synthetic CLI caches only; no native-boot or hardware claim."""
    import asyncio
    import socket

    from greeclimate.cipher import CipherV2
    from greeclimate.device import Device
    from greeclimate.deviceinfo import DeviceInfo

    from tests.test_emulator_firmware_cli import (
        AAD as CLI_AAD,
        ECB_KEY as CLI_ECB_KEY,
        GCM_KEY as CLI_GCM_KEY,
        NONCE as CLI_NONCE,
        Peer,
        cli_server,
        packet as cli_packet,
        unpack as cli_unpack,
    )

    fixtures = Path(__file__).parent / "fixtures" / "emulator"
    native = json.loads((fixtures / "catalog-early-hybrid-wb-native_research.json").read_text())
    native_source = next(row for row in native["sources"]
                         if row["source_sha256"] == source["source_sha256"])
    wire_source = next(row for row in WIRE["sources"]
                       if row["source_sha256"] == source["source_sha256"])
    lifecycle_source = next(row for row in LIFECYCLE["sources"]
                            if row["source_sha256"] == source["source_sha256"])
    udp_source = next(row for row in UDP["sources"]
                      if row["source_sha256"] == source["source_sha256"])
    profile = next(profile for profile in hybrid.WB_PROFILES
                   if profile.source_sha256 == source["source_sha256"])
    assert profile.id in ("sim-wb05df13-v2.01-10001", "sim-wb05ur-v1.05-10001")
    assert profile.hid == source["hid"] == native_source["hid"]
    assert CLI_ECB_KEY == b"a3K8Bx%2r8Y7#xDh"
    assert CLI_GCM_KEY == b"{yxAHAY_Lm6pbC/<"
    assert (CLI_GCM_KEY.decode(), CLI_NONCE.hex(), CLI_AAD.decode()) == (
        WIRE["GCM"]["generic_key_ASCII"], WIRE["GCM"]["nonce_hex"],
        WIRE["GCM"]["AAD_ASCII"])
    assert UDP["actual_wire"]["GCM_generic_key_ASCII"] == CLI_GCM_KEY.decode()
    assert UDP["actual_wire"]["discovery"] == (
        f"legacy AES-ECB PKCS7 generic {CLI_ECB_KEY.decode()}")
    record = {"id": "hybrid", "profile": profile.id,
              "mid": native_source["mid_vectors"][0]["expected_emitted_mid"],
              "mac": MAC}

    with cli_server([record]) as (address, identities), socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM) as sock:
        peer = Peer(sock, address, identities)
        mac = identities["hybrid"]["mac"]
        assert mac == MAC

        sock.sendto(b'{"t":"scan"}', address)
        discovery_outer, discovery = cli_unpack(peer.receive(), CLI_ECB_KEY)
        assert (discovery_outer["i"], discovery_outer["uid"]) == (1, 0)
        assert discovery_outer["cid"] == discovery_outer["tcid"] == ""
        assert "tag" not in discovery_outer
        assert discovery["mid"] == native_source["mid_vectors"][0]["expected_emitted_mid"]
        assert discovery["hid"] == source["hid"] and discovery["mac"] == mac

        bound = peer.request("hybrid", "bind", generic=True, gcm=True)
        assert bound["t"] == "bindok" and bound["r"] == 200 and bound["mac"] == mac
        session_key = bound["key"].encode("ascii")
        assert len(session_key) == 16
        peer.keys["hybrid"] = session_key
        assert peer.request("hybrid", "bind", gcm=True) == bound

        def exchange(inner, *, selector=0, uid=42, cid="peer", add_mac=True):
            payload = dict(inner)
            if add_mac:
                payload.setdefault("mac", mac)
            key = CLI_GCM_KEY if selector else session_key
            outer = {"t": "pack", "i": selector, "uid": uid, "cid": cid, "tcid": mac}
            sock.sendto(cli_packet(outer, payload, key, gcm=True), address)
            data, sender = sock.recvfrom(65535)
            assert sender == address
            envelope, response = cli_unpack(data, key, gcm=True)
            assert (envelope["i"], envelope["uid"]) == (selector, uid)
            assert envelope["cid"] == mac and envelope["tcid"] == cid
            return response

        def reject(inner, *, selector=0, cid="peer", target=mac, key=None):
            payload = dict(inner)
            payload.setdefault("mac", mac)
            key = key if key is not None else (CLI_GCM_KEY if selector else session_key)
            outer = {"t": "pack", "i": selector, "uid": 42, "cid": cid, "tcid": target}
            peer.quiet(cli_packet(outer, payload, key, gcm=True))

        # The source's independent literal generic-selector packet uses GCM,
        # while discovery above alone is the legacy ECB reply.
        generic_input = udp_source["generic_GCM"]["input"]
        sock.sendto(json.dumps(generic_input, separators=(",", ":")).encode(), address)
        generic_outer, generic_status = cli_unpack(peer.receive(), CLI_GCM_KEY, gcm=True)
        assert (generic_outer["i"], generic_outer["uid"]) == (1, 42)
        assert generic_outer["cid"] == mac and generic_outer["tcid"] == "peer"
        assert generic_status["dat"] == [0] and generic_status["cols"] == ["Pow"]

        initial_pow = next(row["output"] for row in native_source["transactions"]
                           if row["qualification"] == "initial" and row["name"] == "Pow")
        initial_mid = native_source["mid_vectors"][0]["fresh_raw_getter"]
        assert exchange({"t": "status", "cols": ["Pow"]})["dat"] == initial_pow["dat"]
        assert exchange({"t": "status", "cols": ["mid"]})["dat"] == initial_mid["dat"] == [""]
        # The configured/emitted MID is 10001; the separate fresh getter remains empty.
        assert discovery["mid"] == "10001"

        reordered = exchange({"t": "status", "cols": [
            "unknown", "Pow", "MOta", "DevID", "MafIdf", "Pow", "hid"]})
        assert reordered == {
            "t": "dat", "uid": 42, "mac": mac, "cid": mac,
            "dat": [0, 0, source["hid"]],
            "cols": ["Pow", "MOta", "DevID", "MafIdf", "Pow", "hid"], "r": 200}
        unknown = exchange({"t": "status", "cols": ["__unknown__"]})
        assert unknown["cols"] == unknown["dat"] == []

        for selector in (0, 1):
            selected = exchange({"t": "status", "cols": ["Pow"]},
                                selector=selector, uid=-1, cid=f"selector-{selector}")
            assert selected["dat"] == [0] and selected["mac"] == mac
        missing_target = exchange({"t": "status", "cols": ["Pow"]}, add_mac=False)
        assert missing_target["mac"] == "" and missing_target["cid"] == mac
        assert missing_target["dat"] == [0]

        # Rejected envelopes and malformed datagrams must not alter the raw cache.
        reject({"t": "status", "cols": ["Pow"]}, key=b"x" * 16)
        reject({"t": "status", "cols": ["Pow"]}, selector=1, key=CLI_ECB_KEY)
        reject({"t": "status", "cols": ["Pow"]}, target="020000000002")
        reject({"t": "status", "mac": "020000000002", "cols": ["Pow"]})
        reject({"t": "status", "cols": ["Pow"]}, cid="x" * 64)
        reject({"t": "status", "cols": ["Pow"]}, selector=2)
        damaged = json.loads(cli_packet(
            {"t": "pack", "i": 0, "uid": 42, "cid": "peer", "tcid": mac},
            {"t": "status", "mac": mac, "cols": ["Pow"]}, session_key, gcm=True))
        damaged["tag"] = base64.b64encode(bytes(16)).decode()
        peer.quiet(json.dumps(damaged, separators=(",", ":")).encode())
        peer.quiet(json.dumps(udp_source["tagless_ECB_rejected"]["input"],
                              separators=(",", ":")).encode())
        peer.quiet(b'{"t":"pack"')
        assert exchange({"t": "status", "cols": ["Pow"]})["dat"] == [0]

        for value in (True, None, 1.5, [], {}, 2147483648, -2147483649):
            reject({"t": "cmd", "opt": ["Pow", "Mod"], "p": [1, value]})
            assert exchange({"t": "status", "cols": ["Pow", "Mod"]})["dat"] == [0, 0]

        for vector in source["metadata_getters"]:
            actual = exchange({"t": "status", "cols": [vector["name"]]})
            if vector["name"] == "time":
                assert len(actual["dat"]) == len(vector["values"]) == 1
                assert actual["dat"][0][:10] == vector["values"][0][:10]
            else:
                assert actual == {
                    "t": "dat", "uid": 42, "mac": mac, "cid": mac,
                    "dat": vector["values"], "cols": [vector["name"]], "r": 200}


        assert len(source["numeric_slots"]) == source["numeric_bound"] == 495
        native_numeric = wire_source["numeric_setter_native"]
        metadata_names = {row["name"]: row["values"] for row in source["metadata_getters"]}
        numeric_names = list(dict.fromkeys(
            [*native_numeric["ACK_names"], "Pow", *source["numeric_getter_override_names"]]))
        assert set(numeric_names) <= set(source["numeric_slots"])
        assert set(source["numeric_slots"]) <= (
            set(numeric_names) | set(metadata_names))
        for offset in range(0, len(numeric_names), 12):
            names = numeric_names[offset:offset + 12]
            requested = native_numeric["requested"]
            ack = exchange({"t": "cmd", "opt": names, "p": [requested] * len(names)})
            assert ack == {
                "t": "res", "mac": native_numeric["ACK_mac"],
                "p": [requested] * len(names), "opt": names,
                "r": native_numeric["ACK_r"]}
            values = []
            for name in names:
                if name in source["numeric_getter_override_names"]:
                    values.extend(metadata_names[name])
                else:
                    assert name == "Pow" or name in native_numeric["fresh_uint16_names"]
                    values.append(native_numeric["fresh_uint16"])
            fresh = exchange({"t": "status", "cols": names})
            assert fresh == {
                "t": "dat", "uid": 42, "mac": mac, "cid": mac,
                "dat": values, "cols": names, "r": 200}

        for vector in EVIDENCE["numeric_boundaries"]:
            ack = exchange({"t": "cmd", "opt": ["Pow"], "p": [vector["input"]]})
            assert ack == {"t": "res", "mac": "", "p": [vector["input"]],
                           "opt": ["Pow"], "r": 200}
            assert exchange({"t": "status", "cols": ["Pow"]})["dat"] == [vector["stored"]]
        ragged = exchange({"t": "status", "cols": ["Pow", "BtHid"]})
        assert ragged["cols"] == ["Pow", "BtHid"] and ragged["dat"] == [65535]

        client = Device(
            DeviceInfo(address[0], address[1], mac, "Hybrid public client", mid="10001"),
            timeout=2, bind_timeout=1)
        try:
            await client.bind(cipher=CipherV2())
            assert client.device_cipher.key == session_key.decode("ascii")
            await asyncio.wait_for(client._valid_state.wait(), 2)
            assert client.hid == source["hid"]

            client._valid_state.clear()
            await client.update_state(columns=["Pow", "mid", "mac", "hid"])
            await asyncio.wait_for(client._valid_state.wait(), 2)
            assert client.device_info.mac == mac
            assert client.hid == source["hid"]
            assert client.raw_properties["Pow"] == 65535
            assert client.raw_properties["mid"] == ""
            assert client.raw_properties["mac"] == ""

            prior = dict(client.raw_properties)
            client._valid_state.clear()
            # BtHid has a source-empty value vector; the public parser rejects
            # this unequal-width response rather than normalizing it.
            await client.update_state(columns=["Pow", "BtHid"])
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(client._valid_state.wait(), 0.2)
            assert client.raw_properties == prior
        finally:
            client.close()


        for vector in wire_source["local_context_transactions"]:
            if vector["name"] == "bind-explicit-session-context":
                continue
            assert exchange(vector["input"], uid=0) == vector["output"]
            fresh = exchange({"t": "status", "cols": vector["fresh"]["cols"]}, uid=0)
            assert fresh == vector["fresh"]
        for name, value, visible in (
                ("host", "test.example", ""),
                ("lat", "12.5", "12.5"),
                ("lon", "-1.0", "-1.0")):
            result = exchange({"t": "cmd", "opt": [name], "p": [value]})
            assert result["p"] == [visible]
            assert exchange({"t": "status", "cols": [name]})["dat"] == [visible]


        # Private frames and host/WLAN caches have no public wire readback; assert
        # only source-visible responses, never synthetic getters for internals.
        write_only = exchange({
            "t": "cmd", "opt": ["ReportClientID", "Onoff"],
            "p": ["app", '["1234011"]']})
        assert write_only["p"] == write_only["opt"] == []

        peer.quiet(json.dumps(
            {"t": "tm", "tcid": mac, "time": "2026-03-04 05:06:07"},
            separators=(",", ":")).encode())
        synced = exchange({"t": "status", "cols": ["time"]})["dat"][0]
        assert synced.startswith("2026-03-04 ")

        sock.sendto(json.dumps({
            "t": "wlan", "tcid": mac, "host": "example.invalid",
            "ssid": "synthetic", "psw": "example",
        }, separators=(",", ":")).encode(), address)
        wlan_reply, sender = sock.recvfrom(65535)
        assert sender == address and json.loads(wlan_reply) == {
            "t": "ret", "r": 200, "mac": ""}

        # Request acceptance only: this is not a firmware install.
        upgrade = wire_source["upgrade_native"]
        assert exchange(upgrade["input"]) == upgrade["output"]
        assert exchange({"t": "dump", "period": 1, "cnt": 1}) == {"t": "ret", "r": 200}

        empty_query = next(vector for vector in wire_source["native_timer_queries"]
                           if vector["scenario"] == "empty-query")
        invalid_timer = {
            **WIRE["canonical_timer"]["set"],
            "cmd": [{"mac": ["020000000002"], "opt": ["Pow"], "p": [1]}],
        }
        reject(invalid_timer)
        assert exchange(empty_query["input"], uid=0) == empty_query["output"]

        timer = WIRE["canonical_timer"]
        assert exchange(timer["set"]) == {"t": "resT", "r": 200}
        assert exchange(timer["query"]) == timer["expected"]
        assert exchange({"t": "status", "cols": ["Pow"]})["dat"] == [65535]
        updated = {**timer["set"], "t": "updateT", "name": "Changed"}
        assert exchange(updated) == {"t": "resT", "r": 200}
        assert exchange(timer["query"])["list"][0]["name"] == "Changed"
        assert exchange({"t": "deleteT", "id": 257}) == {"t": "resT", "r": 200}
        assert exchange(timer["query"])["list"] == []

        calendar = lifecycle_source["calendar"]
        assert exchange(calendar["input"], uid=0) == calendar["output"]
        calendar_fresh = exchange({"t": "status", "cols": ["time"]}, uid=0)
        assert calendar_fresh["cols"] == calendar["fresh"]["cols"]
        assert calendar_fresh["mac"] == calendar["fresh"]["mac"] == mac
        assert calendar_fresh["cid"] == mac and calendar_fresh["uid"] == 0
        assert len(calendar_fresh["dat"]) == len(calendar["fresh"]["dat"]) == 1
        assert calendar_fresh["dat"][0][:16] == calendar["fresh"]["dat"][0][:16]
        for vector in lifecycle_source["created_timer_transactions"]:
            assert exchange(vector["input"], uid=0) == vector["output"]
        setter, query = lifecycle_source["optional_seconds_transactions"]
        assert exchange(setter["input"], uid=0) == setter["output"]
        optional = exchange(query["input"], uid=0)["list"][0]
        expected_optional = query["output"]["list"][0]
        for field in ("id", "name", "enable", "week", "hr", "min", "sec"):
            assert optional[field] == expected_optional[field]
        assert optional["cmd"][0]["mac"] == [mac]
        assert exchange({"t": "deleteT", "id": expected_optional["id"]}, uid=0) == {
            "t": "resT", "r": 200}

        for timer_id, name in ((9, "Late"), (1, "Timer")):
            assert exchange({**timer["set"], "id": timer_id, "name": name}, uid=0) == {
                "t": "resT", "r": 200}
        for vector in wire_source["native_timer_queries"]:
            if vector["scenario"] == "multiple-reordered-query":
                assert exchange(vector["input"], uid=0) == vector["output"]


@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(source["historical_index"]))
def test_actual_cli_wb_hybrid_restart_restores_seed_identity_key_and_cache(source):
    """Verify configured synthetic state, seeded identity, and key after real restarts."""
    import socket

    from tests.test_emulator_firmware_cli import Peer, cli_server

    profile = next(profile for profile in hybrid.WB_PROFILES
                   if profile.source_sha256 == source["source_sha256"])
    record = {"id": "restart-hybrid", "profile": profile.id, "mid": "10001",
              "state": {"Pow": 7, "Mod": 9}}
    previous = None
    for restart in range(2):
        with cli_server([record]) as (address, identities), socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM) as sock:
            peer = Peer(sock, address, identities)
            bound = peer.request("restart-hybrid", "bind", generic=True, gcm=True)
            key = bound["key"].encode("ascii")
            peer.keys["restart-hybrid"] = key
            identity = identities["restart-hybrid"]["mac"]
            if previous is None:
                assert peer.request("restart-hybrid", "status",
                                    {"cols": ["Pow", "Mod"]}, gcm=True)["dat"] == [7, 9]
                written = peer.request("restart-hybrid", "cmd",
                                       {"opt": ["Pow"], "p": [65537]}, gcm=True)
                assert written == {
                    "t": "res", "mac": "", "p": [65537], "opt": ["Pow"], "r": 200}
                assert peer.request("restart-hybrid", "status",
                                    {"cols": ["Pow"]}, gcm=True)["dat"] == [1]
                previous = (identity, key)
            else:
                assert (identity, key) == previous
                assert peer.request("restart-hybrid", "status",
                                    {"cols": ["Pow", "Mod"]}, gcm=True)["dat"] == [7, 9]
