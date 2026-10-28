"""Actual-CLI acceptance for the exact-source WB05MR V1.05 model."""

import asyncio
import base64
from datetime import datetime, timedelta
import json
from pathlib import Path
import socket

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from greeclimate.cipher import CipherV1
from greeclimate.device import Device
from greeclimate.deviceinfo import DeviceInfo
from tests.test_emulator_firmware_cli import cli_server


FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator" /
                      "catalog-early-scalar_research.json").read_text())
SOURCE, = FIXTURE["sources"]
MAC = SOURCE["native_discovery"]["json_output"]["mac"]
GENERIC_KEY = FIXTURE["wire_contract"]["generic_key_ascii"].encode("ascii")
PROFILE_ID = SOURCE["profile_id"]
HID = SOURCE["hid"]
UART_MID = "10001"
PEER = "mr-cli-peer"
MAX_REQUEST = 1460


def _record(identifier="mr-root"):
    return {"id": identifier, "profile": PROFILE_ID, "mid": UART_MID,
            "mac": MAC}


def _packet(inner, key, selector=0, *, uid=0, cid=PEER, target=MAC,
            raw=None, i_token=None, uid_token=None):
    plaintext = (raw if raw is not None else json.dumps(
        inner, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8"))
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(plaintext, 16))
    outer = {"t": "pack", "i": selector, "uid": uid, "cid": cid,
             "tcid": target, "pack": base64.b64encode(encrypted).decode("ascii")}
    packet = json.dumps(outer, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if i_token is not None:
        packet = packet.replace(f'"i":{selector}'.encode(), f'"i":{i_token}'.encode(), 1)
    if uid_token is not None:
        packet = packet.replace(f'"uid":{uid}'.encode(), f'"uid":{uid_token}'.encode(), 1)
    return packet


def _send(sock, address, inner, key, selector=0, *, uid=0, cid=PEER,
          target=MAC, raw=None, i_token=None, uid_token=None, enforce_limit=True):
    packet = _packet(inner, key, selector, uid=uid, cid=cid, target=target,
                     raw=raw, i_token=i_token, uid_token=uid_token)
    if enforce_limit:
        assert len(packet) <= MAX_REQUEST
    sock.sendto(packet, address)
    return packet


def _receive(sock, address, key):
    packet, sender = sock.recvfrom(65535)
    assert sender == address
    assert not packet.endswith(b"\n")
    outer = json.loads(packet)
    assert outer["t"] == "pack" and "tag" not in outer
    encrypted = base64.b64decode(outer["pack"], validate=True)
    plaintext = unpad(AES.new(key, AES.MODE_ECB).decrypt(encrypted), 16)
    assert not plaintext.endswith(b"\n")
    return outer, json.loads(plaintext)


def _header(outer):
    return {name: value for name, value in outer.items() if name != "pack"}


def _exchange(sock, address, inner, key, selector=0, *, uid=0, raw=None,
              i_token=None, uid_token=None, target=MAC):
    _send(sock, address, inner, key, selector, uid=uid, raw=raw,
          i_token=i_token, uid_token=uid_token, target=target)
    outer, response = _receive(sock, address, key)
    assert _header(outer) == {"t": "pack", "i": selector, "uid": uid,
                              "cid": target, "tcid": PEER}
    return response


def _quiet(sock):
    timeout = sock.gettimeout()
    sock.settimeout(0.12)
    try:
        with pytest.raises(socket.timeout):
            sock.recvfrom(65535)
    finally:
        sock.settimeout(timeout)


def _bind(sock, address):
    response = _exchange(sock, address, {"t": "bind", "mac": MAC},
                         GENERIC_KEY, selector=1)
    assert response["t"] == "bindok" and response["r"] == 200
    assert response["mac"] == MAC
    key = response["key"].encode("ascii")
    assert len(key) == 16
    return key


def _expected_status(cols, values, *, uid=0, mac=MAC):
    return {"t": "dat", "uid": uid, "mac": mac, "cid": MAC,
            "dat": values, "cols": cols, "r": 200}


def _status_time(value):
    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")


def test_mr_actual_cli_discovery_full_namespace_metadata_and_numeric_setters():
    source = SOURCE
    record = _record()
    with cli_server([record]) as (address, identities), socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(2)
        identity = identities[record["id"]]
        assert identity["profile"] == PROFILE_ID
        assert identity["mid"] == UART_MID
        assert identity["mac"] == MAC

        peer.sendto(b'{"t":"scan"}', address)
        outer, discovered = _receive(peer, address, GENERIC_KEY)
        assert _header(outer) == {"t": "pack", "i": 1, "uid": 0,
                                  "cid": "", "tcid": ""}
        assert discovered == source["native_discovery"]["json_output"]
        assert discovered["hid"] == HID and discovered["mid"] == UART_MID
        key = _bind(peer, address)

        # The fixture describes 495 ordered slots, represented by 297 distinct names.
        ordered = source["ordered_names"]
        fields = source["fields"]
        assert source["slot_count"] == len(ordered) == 495
        assert len(fields) == len(source["numeric_names"]) == 297
        started = datetime.now()
        for field in fields:
            assert field["slot_indices"] == [index for index, name in enumerate(ordered)
                                             if name == field["name"]]
            response = _exchange(peer, address,
                                 {"t": "status", "cols": field["native_get"]["cols"]},
                                 key)
            if field["name"] == "time":
                observed = _status_time(response["dat"][0])
                base = datetime(2036, 3, 9, 6, 28, 16)
                elapsed = (datetime.now() - started).total_seconds()
                assert 0 <= (observed - base).total_seconds() <= elapsed + 3
            else:
                assert response == _expected_status(field["native_get"]["cols"],
                                                    field["native_get"]["dat"]), field["name"]
        for getter in source["metadata_getters"]:
            if getter["native_outcome"] == "fault":
                _send(peer, address, {"t": "status", "cols": [getter["name"]]}, key)
                _quiet(peer)
                continue
            response = _exchange(peer, address,
                                 {"t": "status", "cols": [getter["name"]]}, key)
            assert response["cols"] == getter["cols"], getter["name"]
            assert response["t"] == "dat" and response["uid"] == 0
            assert response["mac"] == response["cid"] == MAC and response["r"] == 200
            if getter["name"] == "time":
                observed = _status_time(response["dat"][0])
                base = datetime(2036, 3, 9, 6, 28, 16)
                elapsed = (datetime.now() - started).total_seconds()
                assert 0 <= (observed - base).total_seconds() <= elapsed + 3
                continue
            assert response["dat"] == getter["dat"], getter["name"]
        assert {getter["name"] for getter in source["metadata_getters"]} == set(
            source["metadata_names"])

        numeric_fields = [field for field in fields
                          if field["write_class"] == "uint16_cache"]
        assert len(numeric_fields) == 288
        for field in numeric_fields:
            vector = field["native_write"]
            assert _exchange(peer, address, vector["request"], key) == vector["ack"], field["name"]
            fresh = vector["fresh"]
            response = _exchange(peer, address,
                                 {"t": "status", "cols": fresh["cols"]}, key)
            assert response == fresh, field["name"]

        # The cJSON getter can emit named columns with no matching scalar values.
        ragged = _exchange(peer, address,
                           {"t": "status", "cols": ["Pow", "DevID", "MafIdf", "Pow"]}, key)
        assert ragged == _expected_status(["Pow", "DevID", "MafIdf", "Pow"],
                                          [65535, 65535])


def test_mr_actual_cli_lexemes_targets_operations_boundaries_and_recovery():
    source = SOURCE
    record = _record("mr-ops")
    with cli_server([record]) as (address, identities), socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(2)
        assert identities[record["id"]]["profile"] == PROFILE_ID
        key = _bind(peer, address)

        target_vectors = {row["id"]: row for row in FIXTURE[
            "target_precedence_native"]["vectors"]}
        for vector_id in ("status-mac-before-sub", "status-long-mac-sub-fallback"):
            vector = target_vectors[vector_id]
            assert _exchange(peer, address, vector["request"], key) == vector["native_ack"]
        command = target_vectors["command-sub-fallback"]
        assert _exchange(peer, address, command["request"], key) == command["native_ack"]
        assert _exchange(peer, address, {"t": "status", "cols": ["Pow"]}, key) == (
            _expected_status(["Pow"], [7]))

        for vector in source["binding_runs"]:
            assert _exchange(peer, address, vector["request"], key) == vector["native_ack"], vector["id"]
            fresh = vector["native_fresh_status"]
            assert _exchange(peer, address, {"t": "status", "cols": fresh["cols"]}, key) == fresh
        duplicate = source["duplicates"]
        assert _exchange(peer, address, duplicate["request"], key) == duplicate["ack"]
        assert _exchange(peer, address, {"t": "status", "cols": duplicate["fresh"]["cols"]}, key) == duplicate["fresh"]
        mixed = source["mixed"]
        assert _exchange(peer, address, mixed["request"], key) == mixed["ack"]
        assert _exchange(peer, address, {"t": "status", "cols": mixed["fresh"]["cols"]}, key) == mixed["fresh"]

        lexical = source["lexical_number_run"]
        assert _exchange(peer, address, {}, key, raw=lexical["raw_request"]) == lexical["native_ack"]
        assert _exchange(peer, address, {"t": "status", "cols": lexical["fresh_status"]["cols"]}, key) == lexical["fresh_status"]
        for vector in source["lexical_edge_run"]["vectors"]:
            assert _exchange(peer, address, {}, key, raw=vector["raw_request"]) == vector["native_ack"], vector["name"]
            fresh = vector["native_fresh_status"]
            assert _exchange(peer, address, {"t": "status", "cols": fresh["cols"]}, key) == fresh
        for vector in source["signed_boundaries"]:
            assert _exchange(peer, address, vector["request"], key) == vector["ack"], vector["id"]
            fresh = vector["fresh"]
            assert _exchange(peer, address, {"t": "status", "cols": fresh["cols"]}, key) == fresh

        for vector in source["buzzer_state_runs"]:
            assert _exchange(peer, address, vector["request"], key) == vector["native_ack"]
            fresh = vector["native_fresh_status"]
            assert _exchange(peer, address, {"t": "status", "cols": fresh["cols"]}, key) == fresh
        # All source callback categories are exercised at the wire boundary.
        operations = {row["id"]: row for row in source["protocol_operations"]}
        upgrade = operations["upgrade"]["request"]
        assert upgrade["url"].startswith("http://emulator.invalid/")
        assert _exchange(peer, address, upgrade, key) == {"t": "ret", "r": 200}
        # This is the bounded virtual OTA queue only: no download or flash occurs.
        assert _exchange(peer, address, {"t": "dump", "period": 1, "cnt": 2}, key) == {
            "t": "ret", "r": 200}

        for vector in source["extended_protocols"]["binCmd"]:
            assert vector["registered"] is True
            assert _exchange(peer, address, vector["request"], key) == (
                vector["source_closure_expected"]["ack"]), vector["id"]
        frequency = {vector["id"]: vector for vector in
                     source["extended_protocols"]["freqCount"]}
        for vector_id in ("freq-cols-send", "freq-empty"):
            _send(peer, address, frequency[vector_id]["request"], key)
            _quiet(peer)
        known_frequency = frequency["freq-known-write"]
        _send(peer, address, known_frequency["request"], key)
        _quiet(peer)
        fresh = known_frequency["native_fresh"]
        assert _exchange(peer, address, {"t": "status", "cols": fresh["cols"]}, key) == fresh
        _send(peer, address, operations["freqCount"]["request"], key)
        _quiet(peer)

        timer = source["timer_record"]
        assert _exchange(peer, address, timer["input"], key) == timer[
            "setT_source_closed_response"]["json"]
        for vector in timer["queries"]:
            assert _exchange(peer, address, vector["request"], key) == vector[
                "native_response"]
        optional = source["timer_optional_seconds"]
        assert _exchange(peer, address, optional["input"], key) == timer[
            "setT_source_closed_response"]["json"]
        for vector in optional["queries"]:
            assert _exchange(peer, address, vector["request"], key) == vector[
                "native_response"]
        deleted = _exchange(peer, address, {"t": "deleteT", "id": 257}, key)
        assert deleted == {"t": "resT", "r": 200}
        assert _exchange(peer, address, {"t": "queryT", "index": 0, "count": 10}, key) == {
            "t": "listT", "total": 0, "index": 0, "list": []}
        update = source["timer_update_missing_id_static"]
        assert _exchange(peer, address, update["request"], key) == update[
            "source_closed_ack"]

        # Local metadata setters retain bounded/no-reply distinctions.
        for name in ("name", "AppTimer"):
            vector = source["local_operations"][name]
            assert _exchange(peer, address, vector["request"], key) == vector["native_ack"]
            fresh = vector["native_fresh"]
            assert _exchange(peer, address, {"t": "status", "cols": fresh["cols"]}, key) == fresh
        time_before = _exchange(peer, address, {"t": "status", "cols": ["time"]}, key)["dat"][0]
        time_vector = source["local_operations"]["time"]
        time_ack = _exchange(peer, address, time_vector["request"], key)
        assert time_ack["t"] == "res" and time_ack["mac"] == MAC
        assert time_ack["opt"] == ["time"] and time_ack["r"] == 200
        assert time_ack["p"] == [time_before] or _status_time(time_before) <= _status_time(time_ack["p"][0])
        report = source["binary_vectors"]["ReportClientID"]
        assert _exchange(peer, address, report["request"], key) == report["native_ack"]
        assert _exchange(peer, address, {"t": "cmd", "opt": ["ReportClientID"],
                                         "p": ["é" * 13]}, key) == report["native_ack"]
        _send(peer, address, {"t": "cmd", "opt": ["ReportClientID"],
                              "p": ["é" * 14]}, key)
        _quiet(peer)
        for name in ("host", "lock", "AutoUpdate", "hid", "mid", "bc",
                     "DevID", "MafIdf", "MidType", "rssi"):
            request = {"t": "cmd", "opt": [name], "p": ["x"]}
            _send(peer, address, request, key)
            _quiet(peer)

        # Plaintext callbacks stay loopback-local and never imply LAN configuration.
        peer.sendto(json.dumps({"t": "hbok", "tcid": MAC}, separators=(",", ":")).encode(), address)
        _quiet(peer)
        peer.sendto(json.dumps({"t": "tm", "tcid": MAC,
                                "time": "2036-03-09 06:28:16"},
                               separators=(",", ":")).encode(), address)
        _quiet(peer)
        time_after_tm = _exchange(peer, address, {"t": "status", "cols": ["time"]}, key)
        synced = _status_time(time_after_tm["dat"][0])
        base = datetime(2036, 3, 9, 14, 28, 16)
        assert timedelta(0) <= synced - base <= timedelta(seconds=2)
        peer.sendto(json.dumps({"t": "wlan", "tcid": MAC, "host": "virtual.local",
                                "ssid": "offline", "psw": "synthetic"},
                               separators=(",", ":")).encode(), address)
        plain, sender = peer.recvfrom(65535)
        assert sender == address and json.loads(plain) == {"t": "ret", "r": 200, "mac": ""}

        # Unqualified namespaces, key/channel/target boundaries, and malformed input drop atomically.
        for value in FIXTURE["numeric_policy_vectors"]["invalid_model_inputs"]:
            _send(peer, address, {"t": "cmd", "opt": ["Pow"], "p": [value]}, key)
            _quiet(peer)
        _send(peer, address, source["unknown"]["request"], key)
        _quiet(peer)
        _send(peer, address, {"t": "cmd", "opt": ["Pow", "__unknown__"],
                              "p": [1, 2]}, key)
        _quiet(peer)
        _send(peer, address, {"t": "status", "cols": ["Pow"]}, b"wrong-sessionkey")
        _quiet(peer)
        _send(peer, address, {"t": "bind", "mac": MAC}, b"wrong-generickey", 1)
        _quiet(peer)
        _send(peer, address, {"t": "status", "cols": ["Pow"]}, key, target="000000000000")
        _quiet(peer)
        _send(peer, address, {"t": "status", "cols": ["Pow"]}, key, cid="x" * 64)
        _quiet(peer)
        _send(peer, address, {"t": "status", "cols": ["Pow"]}, key, selector=2)
        _quiet(peer)
        _send(peer, address, {}, key, raw="{malformed", enforce_limit=False)
        _quiet(peer)
        peer.sendto(b"{malformed JSON", address)
        _quiet(peer)
        peer.sendto(json.dumps({"t": "pack", "i": 0, "uid": 0, "cid": PEER,
                                "tcid": MAC, "pack": "%%%"},
                               separators=(",", ":")).encode(), address)
        _quiet(peer)
        oversized = _packet({"t": "status", "cols": ["Pow"], "padding": "x" * 1600}, key)
        assert len(oversized) > MAX_REQUEST
        peer.sendto(oversized, address)
        _quiet(peer)
        assert _exchange(peer, address, {"t": "status", "cols": ["Pow"]}, key) == (
            _expected_status(["Pow"], [77]))


async def test_mr_actual_cli_unmodified_public_device_v1_control():
    record = _record("mr-public-client")
    with cli_server([record]) as (address, identities):
        identity = identities[record["id"]]
        client = Device(DeviceInfo(address[0], address[1], identity["mac"],
                                   "WB05MR CLI", mid=UART_MID),
                        timeout=2, bind_timeout=1)
        try:
            await client.bind(cipher=CipherV1())
            assert len(client.device_cipher.key.encode("ascii")) == 16
            await asyncio.wait_for(client._valid_state.wait(), 2)
            client._valid_state.clear()
            await client.update_state(columns=["Pow", "name", "host"])
            await asyncio.wait_for(client._valid_state.wait(), 2)
            assert [client.raw_properties[name] for name in
                    ("Pow", "name", "host")] == [0, "", ""]
            client.set_property("Pow", 7)
            client._valid_state.clear()
            await client.push_state_update()
            await asyncio.wait_for(client._valid_state.wait(), 2)
            client._valid_state.clear()
            await client.update_state(columns=["Pow"])
            await asyncio.wait_for(client._valid_state.wait(), 2)
            assert client.raw_properties["Pow"] == 7
            # The native empty DevID column is ragged; the ordinary client cannot accept it.
            client._valid_state.clear()
            await client.update_state(columns=["Pow", "DevID"])
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(client._valid_state.wait(), 0.25)
            assert not client.has_valid_state and client.raw_properties["Pow"] == 7
        finally:
            client.close()


def test_mr_actual_cli_fresh_process_key_and_cache_restart():
    record = _record("mr-restart")
    previous_key = None
    for restart in range(2):
        with cli_server([record]) as (address, identities), socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.settimeout(2)
            assert identities[record["id"]]["profile"] == PROFILE_ID
            key = _bind(peer, address)
            assert previous_key is None or key == previous_key
            previous_key = key
            initial = _exchange(peer, address, {"t": "status", "cols": ["Pow"]}, key)
            assert initial == _expected_status(["Pow"], [0])
            if restart == 0:
                assert _exchange(peer, address,
                                 {"t": "cmd", "opt": ["Pow"], "p": [7]}, key) == {
                    "t": "res", "mac": MAC, "p": [7], "opt": ["Pow"], "r": 200}
                assert _exchange(peer, address,
                                 {"t": "status", "cols": ["Pow"]}, key) == (
                    _expected_status(["Pow"], [7]))
