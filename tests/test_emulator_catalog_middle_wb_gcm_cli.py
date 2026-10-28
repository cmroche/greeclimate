"""Independent real-CLI acceptance for the three middle WB GCM sources."""

import asyncio
import base64
from datetime import datetime
import json
from pathlib import Path
import socket

from Crypto.Cipher import AES
import pytest

from greeclimate.cipher import CipherV2
from greeclimate.device import Device
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.network import Response
from tests.test_emulator_firmware_cli import (
    AAD,
    ECB_KEY,
    GCM_KEY,
    NONCE,
    Peer,
    cli_server,
    packet,
    unpack,
)


FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-realtek-middle-wb_research.json").read_text())
PROFILE_IDS = {
    38: "sim-middle-wb-841d662c-10001",
    39: "sim-middle-wb-5f14dd18-10001",
    40: "sim-middle-wb-e8068e53-10001",
}
SOURCE_HIDS = {
    38: "362001066300+U-4MWB05DF13V3.05.bin",
    39: "362001067540+U-WB05WR13V2.06.bin",
    40: "362001067541+U-WB05WR11V2.04.bin",
}
SOURCES = {
    row["assessment_index"]: row for row in FIXTURE["sources"]
    if row["assessment_index"] in PROFILE_IDS
}
CASES = [pytest.param(SOURCES[index], PROFILE_IDS[index], id=PROFILE_IDS[index])
         for index in (38, 39, 40)]
MAC = "020000000001"
MID = "10001"
READONLY_CLASSIFIED = (
    "lock", "AutoUpdate", "hid", "mid", "bc", "DevID", "MafIdf", "MidType",
)
CLASSIFIED = {
    "time", "name", "lock", "AutoUpdate", "host", "hid", "mid", "bc", "DevID", "MafIdf",
    "AppTimer", "MidType", "BleON", "Mesh", "Unbind", "Meshid", "lat", "lon",
    "ReportClientID", "Onoff", "ModelType",
}


def _records(profile_id):
    return [{"id": "office", "profile": profile_id, "mid": MID, "mac": MAC}]


def _plain_outer(envelope):
    return {name: value for name, value in envelope.items() if name not in ("pack", "tag")}


def _replace_outer_token(wire, field, token):
    prefix = f'"{field}": '.encode()
    start = wire.index(prefix) + len(prefix)
    end = wire.index(b",", start)
    return wire[:start] + token.encode() + wire[end:]


def _wire(inner, key, selector=0, *, uid=42, cid="cli-peer", tcid=MAC,
          outer_overrides=None, raw_header=None, gcm=True):
    outer = {"t": "pack", "i": selector, "uid": uid, "cid": cid, "tcid": tcid}
    if outer_overrides:
        outer.update(outer_overrides)
    wire = packet(outer, inner, key, gcm=gcm)
    for field, token in (raw_header or {}).items():
        wire = _replace_outer_token(wire, field, token)
    assert len(wire) <= 1460
    return wire


def _exchange(sock, address, inner, key, selector=0, *, uid=42, cid="cli-peer", tcid=MAC,
              outer_overrides=None, raw_header=None):
    wire = _wire(inner, key, selector, uid=uid, cid=cid, tcid=tcid,
                 outer_overrides=outer_overrides, raw_header=raw_header)
    sock.sendto(wire, address)
    data, sender = sock.recvfrom(65535)
    assert sender == address
    return unpack(data, key, gcm=True)


def _literal_gcm_wire(outer, inner_json, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=NONCE)
    cipher.update(AAD)
    encrypted, tag = cipher.encrypt_and_digest(inner_json.encode())
    outer = dict(outer, pack=base64.b64encode(encrypted).decode(), tag=base64.b64encode(tag).decode())
    wire = json.dumps(outer).encode()
    assert len(wire) <= 1460
    return wire


def _status(sock, address, key, columns, selector=0, **outer):
    return _exchange(sock, address, {"t": "status", "cols": columns, "mac": MAC}, key, selector,
                     **outer)


def _bind(sock, address):
    envelope, reply = _exchange(sock, address, {"t": "bind", "mac": MAC}, GCM_KEY, 1)
    assert _plain_outer(envelope) == {
        "t": "pack", "i": 1, "uid": 42, "cid": MAC, "tcid": "cli-peer",
    }
    assert reply["t"] == "bindok" and reply["r"] == 200 and reply["mac"] == MAC
    key = reply["key"].encode("ascii")
    assert len(key) == 16
    return key


def _scan(sock, address, source):
    # These sources use the independent ECB discovery envelope, not their GCM pack codec.
    sock.sendto(b'{"t":"scan","i":"ignored","uid":[],"cid":["wrong"],"tcid":"not-empty"}', address)
    data, sender = sock.recvfrom(65535)
    assert sender == address
    envelope, advertisement = unpack(data, ECB_KEY)
    assert "tag" not in envelope
    assert _plain_outer(envelope) == {"t": "pack", "i": 1, "uid": 0, "cid": "", "tcid": ""}
    assert advertisement["t"] == "dev"
    assert advertisement["mac"] == MAC and advertisement["mid"] == MID
    assert advertisement["ver"] == source["sdk_ver"]
    assert ("hid" in advertisement) is source["dev_hid_present"]
    if source["dev_hid_present"]:
        assert advertisement["hid"] == source["constructed_hid"]


def _client_identity(identities, profile_id):
    row = identities["office"]
    assert row["profile"] == profile_id and row["mid"] == MID
    assert row["mac"] == MAC


def _quiet(peer, wire):
    peer.quiet(wire)


@pytest.mark.parametrize("source,profile_id", CASES)
async def test_middle_wb_gcm_actual_cli_full_namespace_client_recovery_and_restarts(source, profile_id):
    index = source["assessment_index"]
    assert source["source_sha256"][:8] == profile_id.removeprefix("sim-middle-wb-").split("-", 1)[0]
    assert source["codec"] == "aes-gcm"
    assert source["constructed_hid"] == SOURCE_HIDS[index]
    assert source["registered_operations"] == [
        "bind", "status", "cmd", "upgrade", "dump", "setT", "queryT", "deleteT", "updateT",
    ] + (["binCmd"] if index == 38 else [])
    records = _records(profile_id)

    with cli_server(records) as (address, identities), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        peer = Peer(sock, address, identities)
        _client_identity(identities, profile_id)
        _scan(sock, address, source)
        key = _bind(sock, address)

        metadata = ["hid", "ver", "mid", "mac"]
        envelope, reply = _status(sock, address, key, metadata)
        assert _plain_outer(envelope) == {
            "t": "pack", "i": 0, "uid": 42, "cid": MAC, "tcid": "cli-peer",
        }
        assert reply == {
            "t": "dat", "uid": 42, "mac": MAC, "cid": MAC,
            "dat": [source["constructed_hid"], source["sdk_ver"], "", MAC],
            "cols": metadata, "r": 200,
        }

        # The 495 native entries repeat names; exercise every slot through its string ABI.
        source_entries = source["source_entries"]
        assert len(source_entries) == 495
        getters = dict(source["initial_getters"])
        slot_names = [entry["name"] for entry in source_entries]
        assert all(type(name) is str and name for name in slot_names)
        slots = list(range(495))
        first_slots = {}
        for entry in source_entries:
            name = entry["name"]
            first_slots.setdefault(name, entry["slot"])
            assert entry["first_name_slot"] == first_slots[name] == source["first_match_slots"][name]
            assert entry["first_slot_reachable_by_numeric_cmd"] is (
                entry["slot"] == entry["first_name_slot"] and name not in CLASSIFIED
            )
            assert entry["cmd_primary_classified"] is (name in CLASSIFIED)
            assert entry["status_primary_shadowed"] is (name in source["primary_read_names"])
        assert [entry["slot"] for entry in source_entries] == slots
        assert len(first_slots) == 286
        assert len(source["first_match_slots"]) == 286
        assert source["first_match_slots"]["NoD"] == 57
        assert max(source["first_match_slots"].values()) == 475
        for offset in range(0, len(slot_names), 16):
            names = slot_names[offset:offset + 16]
            _, actual = _status(sock, address, key, names)
            expected_dat = [value for name in names for value in getters[name]]
            position = 0
            for name in names:
                if name == "time":
                    value = actual["dat"][position]
                    parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
                    initial = datetime.strptime(getters[name][0], "%Y-%m-%d %H:%M:%S")
                    assert parsed >= initial
                    expected_dat[position] = value
                position += len(getters[name])
            assert actual == {
                "t": "dat", "uid": 42, "mac": MAC, "cid": MAC,
                "dat": expected_dat, "cols": names, "r": 200,
            }
        getter_names = [name for name, _ in source["initial_getters"]]
        assert len(getter_names) == 293 and len(set(getter_names)) == 293
        metadata_only = [name for name in getter_names if name not in source["first_match_slots"]]
        assert set(metadata_only) == {"BtHid", "MOta", "DevID", "MafIdf", "MidType", "rssi", "FaultDisplay"}
        _, actual = _status(sock, address, key, metadata_only)
        assert actual == {
            "t": "dat", "uid": 42, "mac": MAC, "cid": MAC,
            "dat": [value for name in metadata_only for value in getters[name]],
            "cols": metadata_only, "r": 200,
        }

        assert set(source["primary_classified_names"]) == CLASSIFIED
        numeric_names = [
            entry["name"] for entry in source_entries
            if entry["first_slot_reachable_by_numeric_cmd"] and not entry["cmd_primary_classified"]
        ]
        assert len(numeric_names) == len(set(numeric_names))
        assert numeric_names == [
            name for name in source["first_match_slots"] if name not in CLASSIFIED
        ]
        shadowed_names = {
            entry["name"] for entry in source_entries if entry["status_primary_shadowed"]
        }
        assert all(getters[name] == [0] for name in numeric_names if name not in shadowed_names)
        for offset in range(0, len(numeric_names), 8):
            names = numeric_names[offset:offset + 8]
            values = [7] * len(names)
            _, ack = _exchange(sock, address, {"t": "cmd", "opt": names, "p": values}, key)
            assert ack == {"t": "res", "mac": MAC, "p": values, "opt": names, "r": 200}
            _, actual = _status(sock, address, key, names)
            expected = [
                value for name in names
                for value in (getters[name] if name in shadowed_names else [7])
            ]
            assert actual["cols"] == names and actual["dat"] == expected
        _, ack = _exchange(sock, address, {
            "t": "cmd", "opt": ["BleON"], "p": ["aabbccddeeff"],
        }, key)
        assert ack == {
            "t": "res", "mac": MAC, "p": ["aabbccddeeff"], "opt": ["BleON"], "r": 200,
        }
        assert _status(sock, address, key, ["BleON"])[1]["dat"] == ["aabbccddeeff"]

        readonly_names = [name for name in source["primary_classified_names"] if name in READONLY_CLASSIFIED]
        assert tuple(readonly_names) == READONLY_CLASSIFIED
        for name in readonly_names:
            _quiet(peer, _wire({"t": "cmd", "opt": [name], "p": ["7"]}, key))
        _, ack = _exchange(sock, address, {
            "t": "cmd", "opt": ["name", "ModelType", "AppTimer"],
            "p": ["new", "new-model", "7"],
        }, key)
        assert ack == {
            "t": "res", "mac": MAC, "p": ["", "", 0],
            "opt": ["name", "ModelType", "AppTimer"], "r": 200,
        }
        timestamp = "2026-02-03 04:05:06"
        primary = ["time", "host", "lat", "lon"]
        _, ack = _exchange(sock, address, {
            "t": "cmd", "opt": primary,
            "p": [timestamp, "host.example", "1234567890", "12345678901"],
        }, key)
        assert ack == {
            "t": "res", "mac": MAC, "p": [timestamp, "", "1234567890", ""],
            "opt": primary, "r": 200,
        }
        assert _status(sock, address, key, primary)[1]["dat"] == [timestamp, "", "1234567890", ""]
        mesh_fields = ["Mesh", "Unbind", "Meshid"]
        expected_ble = "123456789abc" if index == 38 else "003456789abc"
        expected_meshid = "ff80" if index == 38 else "fe80"
        _, ack = _exchange(sock, address, {
            "t": "cmd", "opt": mesh_fields, "p": ["123456789abc", "001122334455", "ff80"],
        }, key)
        assert ack == {
            "t": "res", "mac": MAC, "p": [0, "001122334455", expected_meshid],
            "opt": mesh_fields, "r": 200,
        }
        assert _status(sock, address, key, ["BleON", "Unbind", "Meshid"])[1]["dat"] == [
            expected_ble, "001122334455", expected_meshid,
        ]
        for name, value in (("ReportClientID", "literal-client"), ("Onoff", "0x0000000")):
            _, ack = _exchange(sock, address, {"t": "cmd", "opt": [name], "p": [value]}, key)
            assert ack == {"t": "res", "mac": MAC, "p": [], "opt": [], "r": 200}

        # The outer target is reply metadata, not a source MAC-equality filter.
        envelope, reply = _exchange(sock, address, {"t": "status", "mac": MAC, "cols": ["Pow"]}, key,
                                    tcid="unrelated-target")
        assert _plain_outer(envelope) == {
            "t": "pack", "i": 0, "uid": 42, "cid": "unrelated-target", "tcid": "cli-peer",
        }
        assert reply["dat"] == [7]

        bad_tag = json.loads(_wire({"t": "status", "mac": MAC, "cols": ["Pow"]}, key))
        tag = bytearray(base64.b64decode(bad_tag["tag"]))
        tag[0] ^= 1
        bad_tag["tag"] = base64.b64encode(tag).decode()
        for malformed in (
            _wire({"t": "status", "mac": MAC, "cols": ["Pow"]}, b"fedcba9876543210"),
            _wire({"t": "status", "mac": MAC, "cols": ["Pow"]}, key, selector=1),
            json.dumps(bad_tag).encode(),
            _wire({"t": "status", "mac": MAC, "cols": ["Pow"]}, key, gcm=False),
            _wire({"t": "status", "mac": MAC, "cols": "not-a-list"}, key),
            _wire({"t": "cmd", "opt": ["Pow"], "p": [True]}, key),
            _wire({"t": "status", "mac": MAC, "cols": ["Pow"]}, GCM_KEY, selector=2),
            b"{invalid JSON",
        ):
            _quiet(peer, malformed)
        oversized = json.dumps({
            "t": "pack", "i": 0, "uid": 42, "cid": "cli-peer", "tcid": MAC,
            "pack": "", "unused": "x" * 1500,
        }).encode()
        assert len(oversized) > 1460
        _quiet(peer, oversized)
        _, recovery = _status(sock, address, key, ["Pow", "SetTem"])
        assert recovery["dat"] == [7, 7]
        _, ragged = _status(sock, address, key, ["Pow", "BtHid"])
        assert ragged == {
            "t": "dat", "uid": 42, "mac": MAC, "cid": MAC,
            "dat": [7], "cols": ["Pow", "BtHid"], "r": 200,
        }

        client = Device(
            DeviceInfo(address[0], address[1], MAC, "Middle WB CLI", mid=MID),
            timeout=2, bind_timeout=1,
        )
        data, results = asyncio.Queue(), asyncio.Queue()
        client.add_handler(Response.DATA, data.put_nowait)
        client.add_handler(Response.RESULT, results.put_nowait)
        try:
            await client.bind(cipher=CipherV2())
            assert client.device_cipher.key == key.decode("ascii")
            await asyncio.wait_for(data.get(), 2)
            await client.update_state(columns=["Pow", "SetTem", "mid"])
            assert await asyncio.wait_for(data.get(), 2) == {"Pow": 7, "SetTem": 7, "mid": ""}
            assert [client.raw_properties[name] for name in ("Pow", "SetTem", "mid")] == [7, 7, ""]
            client.set_property("Pow", 65537)
            await client.push_state_update()
            assert await asyncio.wait_for(results.get(), 2) == {"Pow": 65537}
            await client.update_state(columns=["Pow"])
            assert await asyncio.wait_for(data.get(), 2) == {"Pow": 1}
            assert client.raw_properties["Pow"] == 1
            prior = dict(client.raw_properties)
            await client.update_state(columns=["Pow", "BtHid"])
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(data.get(), 0.2)
            assert client.raw_properties == prior
        finally:
            client.close()

        first_key = key.decode("ascii")
        first_identity = {name: identities["office"][name] for name in ("id", "profile", "mid", "mac")}

    with cli_server(records) as (address, identities), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        _client_identity(identities, profile_id)
        assert {name: identities["office"][name] for name in first_identity} == first_identity
        key = _bind(sock, address)
        assert key.decode("ascii") == first_key
        assert _status(sock, address, key, ["Pow", "SetTem"])[1]["dat"] == [0, 0]
        _, ack = _exchange(sock, address, {"t": "cmd", "opt": ["Pow"], "p": [9]}, key)
        assert ack["p"] == [9]
        assert _status(sock, address, key, ["Pow"])[1]["dat"] == [9]

    with cli_server(records) as (address, identities), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        _client_identity(identities, profile_id)
        assert {name: identities["office"][name] for name in first_identity} == first_identity
        key = _bind(sock, address)
        assert key.decode("ascii") == first_key
        assert _status(sock, address, key, ["Pow", "SetTem"])[1]["dat"] == [0, 0]


@pytest.mark.parametrize("source,profile_id", CASES)
def test_middle_wb_gcm_actual_cli_native_numeric_lexemes_and_outer_aliases(source, profile_id):
    contract = FIXTURE["outer_header_contract"]
    records = _records(profile_id)
    with cli_server(records) as (address, identities), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        _client_identity(identities, profile_id)
        bound_key = _bind(sock, address)
        peer = Peer(sock, address, identities)

        for vector in contract["scalar_vectors"]:
            selector = vector["i"]
            wire_key = GCM_KEY if selector else bound_key
            envelope, reply = _exchange(
                sock, address, {"t": "status", "mac": MAC, "cols": ["Pow"]}, wire_key, selector,
                raw_header={"i": vector["i_json"], "uid": vector["uid_json"]},
            )
            assert _plain_outer(envelope) == {
                "t": "pack", "i": selector, "uid": vector["uid"], "cid": MAC, "tcid": "cli-peer",
            }
            assert reply == {
                "t": "dat", "uid": vector["uid"], "mac": MAC, "cid": MAC,
                "dat": [0], "cols": ["Pow"], "r": 200,
            }

        identity_vectors = [
            (row["cid"], row["tcid"], row["normalized_cid"], row["normalized_tcid"])
            for row in contract["identity_vectors"]
        ] + [
            ("x" * 64, "x" * 32, "", ""),
            ("a\0suffix", False, "a", "false"),
        ]
        for cid, tcid, normalized_cid, normalized_tcid in identity_vectors:
            envelope, reply = _exchange(
                sock, address, {"t": "status", "mac": MAC, "cols": ["Pow"]}, bound_key,
                outer_overrides={"cid": cid, "tcid": tcid},
            )
            assert _plain_outer(envelope) == {
                "t": "pack", "i": 0, "uid": 42, "cid": normalized_tcid, "tcid": normalized_cid,
            }
            assert reply["dat"] == [0]

        for raw_values, ack_values, stored_values in (
            ("1e3,2", [1, 3], [1, 3]),
            ("1e-3,2", [1, -3], [1, 65533]),
        ):
            outer = {"t": "pack", "i": 0, "uid": 42, "cid": "cli-peer", "tcid": MAC}
            wire = _literal_gcm_wire(
                outer, '{"t":"cmd","opt":["Pow","SetTem"],"p":[' + raw_values + ']}', bound_key,
            )
            sock.sendto(wire, address)
            data, sender = sock.recvfrom(65535)
            assert sender == address
            envelope, ack = unpack(data, bound_key, gcm=True)
            assert _plain_outer(envelope) == {
                "t": "pack", "i": 0, "uid": 42, "cid": MAC, "tcid": "cli-peer",
            }
            assert ack == {
                "t": "res", "mac": MAC, "p": ack_values, "opt": ["Pow", "SetTem"], "r": 200,
            }
            assert _status(sock, address, bound_key, ["Pow", "SetTem"])[1]["dat"] == stored_values

        before = _status(sock, address, bound_key, ["Pow", "SetTem"])[1]["dat"]
        malformed = _literal_gcm_wire(
            {"t": "pack", "i": 0, "uid": 42, "cid": "cli-peer", "tcid": MAC},
            '{"t":"cmd","opt":["Pow","SetTem"],"p":[1e+3,2]}', bound_key,
        )
        _quiet(peer, malformed)
        assert _status(sock, address, bound_key, ["Pow", "SetTem"])[1]["dat"] == before
        _quiet(peer, _wire({"t": "status", "mac": MAC, "cols": ["Pow"]}, GCM_KEY, selector=2))


@pytest.mark.parametrize("source,profile_id", CASES)
def test_middle_wb_gcm_actual_cli_registered_operations_and_schedules(source, profile_id):
    index = source["assessment_index"]
    expected_operations = [
        "bind", "status", "cmd", "upgrade", "dump", "setT", "queryT", "deleteT", "updateT",
    ] + (["binCmd"] if index == 38 else [])
    assert source["registered_operations"] == expected_operations
    schedule = source["schedule_contract"]
    assert schedule["source_evidence"]["source_sha256"] == source["source_sha256"]
    assert schedule["chosen_virtual_readouts"]["module_mac"] == MAC
    vectors = schedule["vectors"]
    records = _records(profile_id)
    with cli_server(records) as (address, identities), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        _client_identity(identities, profile_id)
        key = _bind(sock, address)
        peer = Peer(sock, address, identities)

        assert _status(sock, address, key, ["Pow"])[1]["dat"] == [0]
        _, ack = _exchange(sock, address, {"t": "cmd", "opt": ["Pow"], "p": [8]}, key)
        assert ack == {"t": "res", "mac": MAC, "p": [8], "opt": ["Pow"], "r": 200}
        assert _status(sock, address, key, ["Pow"])[1]["dat"] == [8]
        assert _exchange(sock, address, {"t": "dump"}, key)[1] == {"t": "ret", "r": 200}
        assert _exchange(sock, address, {"t": "upgrade", "url": "xy"}, key)[1] == {"t": "ret", "r": 200}

        invalid_timer = dict(vectors["set_request"], cmd=[])
        _quiet(peer, _wire(invalid_timer, key))
        empty_query = dict(vectors["query_after_set"], total=0, list=[])
        assert _exchange(sock, address, vectors["query_request"], key)[1] == empty_query

        assert _exchange(sock, address, vectors["set_request"], key)[1] == vectors["set_reply"]
        assert _exchange(sock, address, vectors["query_request"], key)[1] == vectors["query_after_set"]
        assert _exchange(sock, address, vectors["duplicate_upsert_request"], key)[1] == (
            vectors["duplicate_upsert_reply"]
        )
        changed = dict(vectors["query_after_set"])
        changed_record = dict(vectors["query_after_set"]["list"][0])
        changed_record["name"] = vectors["duplicate_upsert_request"]["name"]
        changed["list"] = [changed_record]
        assert _exchange(sock, address, vectors["query_request"], key)[1] == changed

        assert _exchange(sock, address, vectors["missing_sec_request"], key)[1] == vectors["set_reply"]
        missing_sec = dict(vectors["query_after_set"])
        missing_sec["list"] = [vectors["missing_sec_record"]]
        assert _exchange(sock, address, vectors["query_request"], key)[1] == missing_sec

        update_request = dict(vectors["set_request"], t="updateT", name="updated")
        update_request["cmd"] = [
            dict(vectors["set_request"]["cmd"][0], p=[258]),
            vectors["set_request"]["cmd"][1],
        ]
        assert _exchange(sock, address, update_request, key)[1] == vectors["update_missing_reply"]
        updated = dict(vectors["query_after_set"])
        updated_record = dict(vectors["query_after_set"]["list"][0], name="updated")
        updated_record["cmd"] = [
            dict(vectors["query_after_set"]["list"][0]["cmd"][0], p=[2]),
        ]
        updated["list"] = [updated_record]
        assert _exchange(sock, address, vectors["query_request"], key)[1] == updated
        assert _exchange(sock, address, vectors["update_missing_request"], key)[1] == (
            vectors["update_missing_reply"]
        )
        assert _exchange(sock, address, vectors["query_request"], key)[1] == updated

        assert _exchange(sock, address, vectors["absent_delete_request"], key)[1] == (
            vectors["absent_delete_reply"]
        )
        after_absent_delete = dict(updated, total=vectors["total_after_absent_delete"])
        assert _exchange(sock, address, vectors["query_request"], key)[1] == after_absent_delete
        assert _exchange(sock, address, vectors["delete_existing_request"], key)[1] == (
            vectors["absent_delete_reply"]
        )
        assert _exchange(sock, address, vectors["query_request"], key)[1] == (
            vectors["query_after_counter_underflow"]
        )
        assert vectors["set_when_count255_replies"] == []
        _quiet(peer, _wire(vectors["set_when_count255_request"], key))

        bin_request = {
            "t": "binCmd", "hex01": base64.b64encode(bytes.fromhex("7e7e0801020304050607")).decode(),
        }
        if index == 38:
            assert _exchange(sock, address, bin_request, key)[1] == {"t": "res", "r": 200}
        else:
            _quiet(peer, _wire(bin_request, key))
        _quiet(peer, _wire({"t": "not-registered"}, key))
        assert _status(sock, address, key, ["Pow"])[1]["dat"] == [8]
