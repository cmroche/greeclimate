"""Actual-CLI acceptance for the two exact middle WB ECB sources."""

import asyncio
import base64
import json
from pathlib import Path
import socket

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import pytest

from greeclimate.cipher import CipherV1
from greeclimate.device import Device
from greeclimate.deviceinfo import DeviceInfo
from tests.test_emulator_firmware_cli import (
    ECB_KEY,
    cli_profiles,
    cli_server,
    packet,
    unpack,
)


FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "emulator" /
                      "catalog-realtek-middle-wb_research.json").read_text())
SOURCES = tuple(source for source in FIXTURE["sources"]
                if source["assessment_index"] in (34, 36))
PROFILE_IDS = {
    34: "sim-middle-wb-a53e88d3-10001",
    36: "sim-middle-wb-d9418735-10001",
}
SOURCE_SHA256 = {
    34: "a53e88d30bf65b3987ff65c362ac8159f63b3f2a36650e816905f2fc4a2cbb85",
    36: "d94187356e299bc8df99a237f7fd396bf14d6446ec8a8393b087218951421260",
}
HIDS = {
    34: "362001065811+U-WB63DF(RT)V1.00.bin",
    36: "362001067928+U-WB65AR11V1.00.bin",
}
MAC = "020000000001"
UART_PRESET_MID = "10001"  # Configured MCU 0x44 input; not a qualified appliance MID.
PEER = "middle-wb-cli-peer"
MAX_DATAGRAM = 1460


def _profile_id(source):
    return PROFILE_IDS[source["assessment_index"]]


def _record(source, logical_id="wb"):
    return {"id": logical_id, "profile": _profile_id(source),
            "mid": UART_PRESET_MID, "mac": MAC}


def _wire_reply(sock, address, key):
    data, sender = sock.recvfrom(65535)
    assert sender == address
    assert not data.endswith(b"\n")
    return unpack(data, key)


def _exchange(sock, address, inner, key, *, outer=None, gcm=False):
    if outer is None:
        outer = {"t": "pack", "i": 0, "uid": 7, "cid": PEER, "tcid": MAC}
    encoded = packet(outer, inner, key, gcm=gcm)
    assert len(encoded) <= MAX_DATAGRAM
    sock.sendto(encoded, address)
    return _wire_reply(sock, address, key)


def _exchange_raw(sock, address, outer, inner_json, key):
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(inner_json.encode(), AES.block_size))
    envelope = {**outer, "pack": base64.b64encode(encrypted).decode("ascii")}
    encoded = json.dumps(envelope).encode()
    assert len(encoded) <= MAX_DATAGRAM
    sock.sendto(encoded, address)
    return _wire_reply(sock, address, key)


def _quiet(sock):
    timeout = sock.gettimeout()
    sock.settimeout(0.15)
    try:
        with pytest.raises(socket.timeout):
            sock.recvfrom(65535)
    finally:
        sock.settimeout(timeout)


def _reject(sock, address, encoded):
    sock.sendto(encoded, address)
    _quiet(sock)


def _outer_fields(outer):
    return {name: value for name, value in outer.items() if name != "pack"}


def _scan(sock, address, source):
    # Each source's scan parser reads only `t`; its unused outer fields stay unguarded.
    sock.sendto(json.dumps({"t": "scan", "i": [], "uid": {}, "cid": {},
                            "tcid": MAC}, separators=(",", ":")).encode(), address)
    outer, advertisement = _wire_reply(sock, address, ECB_KEY)
    assert _outer_fields(outer) == {
        "t": "pack", "i": 1, "uid": 0, "cid": "", "tcid": "",
    }
    expected = {
        "t": "dev", "cid": "", "bc": "", "brand": "", "catalog": "",
        "mac": MAC, "mid": UART_PRESET_MID, "model": "", "name": "",
        "lock": 0, "series": "", "vender": "", "ver": source["sdk_ver"],
    }
    if source["dev_hid_present"]:
        expected["hid"] = source["constructed_hid"]
    assert advertisement == expected


def _bind(sock, address, *, selector=1, key=ECB_KEY, outer=None, mac=MAC):
    if outer is None:
        outer = {"t": "pack", "i": selector, "uid": 7,
                 "cid": PEER, "tcid": MAC}
    envelope, reply = _exchange(sock, address, {"t": "bind", "mac": mac}, key,
                                outer=outer)
    return envelope, reply


def test_middle_wb_ecb_cli_profiles_match_exact_sha_hid_and_configured_uart_mid():
    profiles = cli_profiles()
    assert len(SOURCES) == 2
    for source in SOURCES:
        index = source["assessment_index"]
        profile_id = PROFILE_IDS[index]
        hid = HIDS[index]
        assert profile_id == f"sim-middle-wb-{SOURCE_SHA256[index][:8]}-{UART_PRESET_MID}"
        assert source["source_sha256"] == SOURCE_SHA256[index]
        assert source["constructed_hid"] == hid
        rows = profiles[profile_id]
        assert len(rows) == 1
        assert rows[0]["role"] == "standalone"
        assert rows[0]["profile"] == profile_id
        assert rows[0]["mid"] == UART_PRESET_MID
        assert rows[0]["hid"] == hid


@pytest.mark.parametrize("source", SOURCES,
                         ids=lambda source: str(source["assessment_index"]))
def test_middle_wb_ecb_cli_complete_495_slot_get_namespace_and_void_cardinality(source):
    index = source["assessment_index"]
    slots = source["first_match_slots"]
    getter_rows = source["initial_getters"]
    slot_counts = {34: 177, 36: 282}
    getter_counts = {34: 191, 36: 288}
    max_slots = {34: 176, 36: 475}
    assert source["codec"] == "aes-ecb-pkcs7"
    assert len(slots) == slot_counts[index]
    assert len(getter_rows) == getter_counts[index]
    assert max(slots.values()) == max_slots[index] < 495
    assert all(0 <= slot < 495 for slot in slots.values())
    getter_names = [row[0] for row in getter_rows]
    assert set(slots) <= set(getter_names)
    assert set(source["primary_read_names"]) <= set(getter_names)

    record = _record(source)
    with cli_server([record]) as (address, identities), socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(2)
        identity = identities[record["id"]]
        assert identity["profile"] == _profile_id(source)
        assert identity["mid"] == UART_PRESET_MID
        assert identity["mac"] == MAC
        _scan(peer, address, source)

        outer, bound = _bind(peer, address)
        assert _outer_fields(outer) == {
            "t": "pack", "i": 1, "uid": 7, "cid": MAC, "tcid": PEER,
        }
        assert bound["t"] == "bindok" and bound["r"] == 200 and bound["mac"] == MAC
        key = bound["key"].encode("ascii")
        assert len(key) == 16

        # Reset the source clock from its independent fixture literal, then read it back.
        source_time = next(values for name, values in getter_rows if name == "time")[0]
        _, command = _exchange(peer, address, {
            "t": "cmd", "mac": MAC, "opt": ["time"], "p": [source_time],
        }, key)
        assert command == {"t": "res", "mac": MAC, "p": [source_time],
                          "opt": ["time"], "r": 200}
        _, clock = _exchange(peer, address, {
            "t": "status", "mac": MAC, "cols": ["time"],
        }, key)
        assert clock["cols"] == ["time"] and clock["dat"] == [source_time]

        # Keep source getter rows as an ordered list: null rows and repeated names
        # are protocol cardinality, not a mapping that can be collapsed.
        query_rows = [row for row in getter_rows if row[0] != "time"]
        for start in range(0, len(query_rows), 24):
            rows = query_rows[start:start + 24]
            columns = [name for name, _ in rows]
            _, reply = _exchange(peer, address, {
                "t": "status", "mac": MAC, "cols": columns,
            }, key)
            expected_values = [value for _, values in rows for value in values]
            assert reply == {
                "t": "dat", "uid": 7, "mac": MAC, "cid": MAC,
                "dat": expected_values, "cols": columns, "r": 200,
            }

        # Two repeated scalar rows survive; void getters keep their names but add no value.
        _, duplicate = _exchange(peer, address, {
            "t": "status", "mac": MAC,
            "cols": ["Pow", "Pow", "BtHid", "__unknown__", "mid", "BtHid"],
        }, key)
        assert duplicate == {
            "t": "dat", "uid": 7, "mac": MAC, "cid": MAC,
            "dat": [0, 0, ""], "cols": ["Pow", "Pow", "BtHid", "mid", "BtHid"],
            "r": 200,
        }
        assert len(duplicate["cols"]) == 5 and len(duplicate["dat"]) == 3
        _, only_void = _exchange(peer, address, {
            "t": "status", "mac": MAC, "cols": ["BtHid"],
        }, key)
        assert only_void["cols"] == ["BtHid"] and only_void["dat"] == []
        _, unknown = _exchange(peer, address, {
            "t": "status", "mac": MAC, "cols": ["__unknown__"],
        }, key)
        assert unknown["cols"] == [] and unknown["dat"] == []


@pytest.mark.parametrize("source", SOURCES,
                         ids=lambda source: str(source["assessment_index"]))
def test_middle_wb_ecb_cli_header_aliases_metadata_precedence_and_numeric_command_lexemes(source):
    index = source["assessment_index"]
    record = _record(source)
    with cli_server([record]) as (address, identities), socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(2)
        _scan(peer, address, source)
        outer, bound = _bind(peer, address, outer={
            "t": "pack", "i": 1, "uid": 7,
            "cid": "bind-controller", "tcid": "unrelated-outer-target",
        })
        assert _outer_fields(outer) == {
            "t": "pack", "i": 1, "uid": 7,
            "cid": "unrelated-outer-target", "tcid": "bind-controller",
        }
        assert bound["t"] == "bindok" and bound["mac"] == MAC
        key = bound["key"].encode("ascii")

        _, paired_bind = _bind(peer, address, selector=0, key=key)
        assert paired_bind["t"] == "bindok" and paired_bind["key"].encode() == key

        # This source parser converts decimal-prefix header tokens before generic
        # validation and echoes decoded tcid/cid in swapped outer fields.
        header, response = _exchange(peer, address, {
            "t": "status", "mac": "inner-target-is-informational", "cols": ["Pow"],
        }, ECB_KEY, outer={
            "t": "pack", "i": 1.9, "uid": 3.9,
            "cid": True, "tcid": "wrong-outer-target",
        })
        assert _outer_fields(header) == {
            "t": "pack", "i": 1, "uid": 3,
            "cid": "wrong-outer-target", "tcid": "true",
        }
        assert response == {
            "t": "dat", "uid": 3, "mac": "inner-target-is-informational",
            "cid": MAC, "dat": [0], "cols": ["Pow"], "r": 200,
        }

        # Missing/wrongly typed uid defaults to zero; STR conversions are source-local.
        header, response = _exchange(peer, address, {
            "t": "status", "mac": MAC, "cols": ["Pow"],
        }, key, outer={
            "t": "pack", "i": 0.9, "uid": [], "cid": None, "tcid": 123,
        })
        assert _outer_fields(header) == {
            "t": "pack", "i": 0, "uid": 0, "cid": "", "tcid": "null",
        }
        assert response["uid"] == 0 and response["mac"] == MAC

        aliases = [
            ({"sub": "sub-target", "mac": "mac-target"}, "sub-target"),
            ({"sub": True, "mac": "fallback"}, "true"),
            ({"sub": None, "mac": "fallback"}, "null"),
            ({"sub": 13, "mac": "fallback"}, "fallback"),
            ({"sub": "x" * 32, "mac": "fallback"}, "fallback"),
            ({"sub": "", "mac": "ignored"}, ""),
            ({"mac": None}, "null"),
            ({"sub": [], "mac": {}}, MAC),
        ]
        for fields, expected_mac in aliases:
            _, reply = _exchange(peer, address, {
                "t": "status", "cols": ["Pow"], **fields,
            }, key)
            assert reply["mac"] == expected_mac and reply["cid"] == MAC
            assert reply["dat"] == [0]

        # Source metadata wins over the configured UART input for status reads.
        _, metadata = _exchange(peer, address, {
            "t": "status", "mac": MAC, "cols": ["hid", "mid"],
        }, key)
        assert metadata["cols"] == ["hid", "mid"]
        assert metadata["dat"] == [source["constructed_hid"], ""]
        assert identities[record["id"]]["mid"] == UART_PRESET_MID

        _, status_write = _exchange(peer, address, {
            "t": "status", "mac": MAC, "opt": ["Pow"], "p": [7],
        }, key)
        assert status_write["cols"] == ["Pow"] and status_write["dat"] == [7]
        source_time = next(values for name, values in source["initial_getters"]
                           if name == "time")[0]
        classified = set(source["primary_classified_names"])
        mixed_options = ["Pow", "time"]
        assert [name for name in mixed_options if name in classified] == ["time"]
        _, mixed = _exchange(peer, address, {
            "t": "cmd", "mac": MAC, "opt": mixed_options,
            "p": [5, source_time],
        }, key)
        assert mixed["opt"] == ["time", "Pow"]
        assert mixed["p"] == [source_time, 5]
        _, cmd_cols_precedence = _exchange(peer, address, {
            "t": "cmd", "mac": MAC, "cols": ["Pow"],
            "opt": ["Pow"], "p": [9],
        }, key)
        assert cmd_cols_precedence["opt"] == ["Pow"]
        assert cmd_cols_precedence["p"] == [0]
        _, unchanged = _exchange(peer, address, {
            "t": "status", "mac": MAC, "cols": ["Pow"],
        }, key)
        assert unchanged["dat"] == [5]

        outer = {"t": "pack", "i": 0, "uid": 7, "cid": PEER, "tcid": MAC}
        _, numeric = _exchange_raw(
            peer, address, outer,
            '{"t":"cmd","mac":"020000000001","opt":["Pow","Mod"],"p":[1e3,2]}',
            key,
        )
        assert numeric["opt"] == ["Pow", "Mod"] and numeric["p"] == [1, 3]
        _, fresh = _exchange(peer, address, {
            "t": "status", "mac": MAC, "cols": ["Pow", "Mod"],
        }, key)
        assert fresh["dat"] == [1, 3]

        high_name = max(source["first_match_slots"], key=source["first_match_slots"].get)
        assert high_name == ({34: "NoD", 36: "OEEPHidSvrVer"}[index])
        _, high_write = _exchange(peer, address, {
            "t": "cmd", "mac": MAC, "opt": [high_name], "p": [19],
        }, key)
        assert high_write["opt"] == [high_name] and high_write["p"] == [19]
        _, high_read = _exchange(peer, address, {
            "t": "status", "mac": MAC, "cols": [high_name],
        }, key)
        assert high_read["dat"] == [19]

        _, dump = _exchange(peer, address, {"t": "dump", "mac": MAC}, key)
        assert dump == {"t": "ret", "r": 200}
        _, upgrade = _exchange(peer, address, {
            "t": "upgrade", "mac": MAC, "url": "firmware.bin",
        }, key)
        assert upgrade == {"t": "ret", "r": 200}

        operations = source["registered_operations"]
        assert "bind" in operations and "status" in operations and "cmd" in operations
        if index == 34:
            assert operations == ["bind", "status", "cmd", "upgrade", "dump"]
            _reject(peer, address, packet({
                "t": "pack", "i": 0, "uid": 7, "cid": PEER, "tcid": MAC,
            }, {"t": "setT", "mac": MAC}, key))
        else:
            assert operations == ["bind", "status", "cmd", "upgrade", "dump",
                                  "setT", "queryT", "deleteT", "updateT"]


@pytest.mark.parametrize("source", [source for source in SOURCES
                                      if source["assessment_index"] == 36],
                         ids=lambda source: str(source["assessment_index"]))
def test_middle_wb_ecb_cli_registered_schedule_operations_and_numeric_lexemes(source):
    assert source["registered_operations"] == [
        "bind", "status", "cmd", "upgrade", "dump",
        "setT", "queryT", "deleteT", "updateT",
    ]
    record = _record(source)
    with cli_server([record]) as (address, _), socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(2)
        _scan(peer, address, source)
        _, bound = _bind(peer, address)
        key = bound["key"].encode("ascii")
        outer = {"t": "pack", "i": 0, "uid": 7, "cid": PEER, "tcid": MAC}
        schedule = (
            '{"t":"setT","mac":"020000000001","id":257,'
            '"name":"lexical schedule","enable":1,"tz":-1,'
            '"hr":2e3,"min":3e4,"sec":40,'
            '"week":[1e3,2,0,0,0,0,0],'
            '"cmd":[{"mac":["ignored"],"opt":["Pow"],"p":[4e5]},'
            '{"opt":["Pow"],"p":[9]}]}'
        )
        _, created = _exchange_raw(peer, address, outer, schedule, key)
        assert created == {"t": "resT", "r": 200}
        _, listed = _exchange(peer, address, {
            "t": "queryT", "mac": MAC, "index": 0, "count": 10,
        }, key)
        assert listed == {"t": "listT", "total": 1, "index": 0, "list": [{
            "id": 1, "name": "lexical schedule", "enable": 1,
            "week": [1, 1, 1, 1, 0, 0, 0], "hr": 2, "min": 3, "sec": 0,
            "cmd": [{"mac": [MAC], "opt": ["Pow"], "p": [4]}],
        }]}

        # These are the source's local queried schedule records, not a claim of
        # physical appliance scheduling or delivery.
        duplicate = packet(outer, {
            "t": "setT", "mac": MAC, "id": 1, "name": "ignored duplicate",
            "enable": 0, "tz": 0, "hr": 1, "min": 2,
            "week": [0, 0, 0, 0, 0, 0, 0],
            "cmd": [{"opt": ["Pow"], "p": [9]}],
        }, key)
        _reject(peer, address, duplicate)
        _, after_duplicate = _exchange(peer, address, {
            "t": "queryT", "mac": MAC, "index": 0, "count": 10,
        }, key)
        assert after_duplicate == listed

        _, updated = _exchange(peer, address, {
            "t": "updateT", "mac": MAC, "id": 1, "name": "updated schedule",
            "enable": 0, "tz": 0, "hr": 8, "min": 9,
            "week": [1, 0, 0, 0, 0, 0, 0],
            "cmd": [{"opt": ["Pow"], "p": [7]}],
        }, key)
        assert updated == {"t": "resT", "r": 200}
        _, updated_list = _exchange(peer, address, {
            "t": "queryT", "mac": MAC, "index": 0, "count": 10,
        }, key)
        assert updated_list == {"t": "listT", "total": 1, "index": 0, "list": [{
            "id": 1, "name": "updated schedule", "enable": 0,
            "week": [1, 0, 0, 0, 0, 0, 0], "hr": 8, "min": 9, "sec": 9,
            "cmd": [{"mac": [MAC], "opt": ["Pow"], "p": [7]}],
        }]}
        _, deleted = _exchange(peer, address, {
            "t": "deleteT", "mac": MAC, "id": 1,
        }, key)
        assert deleted == {"t": "resT", "r": 200}
        _, empty = _exchange(peer, address, {
            "t": "queryT", "mac": MAC, "index": 0, "count": 10,
        }, key)
        assert empty == {"t": "listT", "total": 0, "index": 0, "list": []}


@pytest.mark.parametrize("source", SOURCES,
                         ids=lambda source: str(source["assessment_index"]))
def test_middle_wb_ecb_cli_wrong_key_codec_schema_rejections_and_recovery(source):
    record = _record(source)
    with cli_server([record]) as (address, _), socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(2)
        _scan(peer, address, source)
        _, bound = _bind(peer, address)
        key = bound["key"].encode("ascii")
        _, command = _exchange(peer, address, {
            "t": "cmd", "mac": MAC, "opt": ["Pow"], "p": [7],
        }, key)
        assert command["p"] == [7]

        outer = {"t": "pack", "i": 0, "uid": 7, "cid": PEER, "tcid": MAC}
        wrong_key = packet(outer, {"t": "status", "mac": MAC, "cols": ["Pow"]},
                           b"0000000000000000")
        _reject(peer, address, wrong_key)
        _reject(peer, address, packet({**outer, "i": 1}, {
            "t": "bind", "mac": MAC,
        }, b"0000000000000000"))
        _reject(peer, address, packet({**outer, "i": 2}, {
            "t": "status", "mac": MAC, "cols": ["Pow"],
        }, key))
        # An authenticated GCM envelope is not this source's ECB wire codec.
        _reject(peer, address, packet(outer, {
            "t": "status", "mac": MAC, "cols": ["Pow"],
        }, key, gcm=True))
        _reject(peer, address, json.dumps({
            **outer, "pack": "%%%",
        }).encode())
        _reject(peer, address, packet(outer, {
            "t": "cmd", "mac": MAC, "opt": ["Pow"], "p": [],
        }, key))
        _reject(peer, address, packet(outer, {
            "t": "cmd", "mac": MAC, "opt": ["hid", "Pow"],
            "p": ["forged metadata", 9],
        }, key))
        _reject(peer, address, packet(outer, {
            "t": "status", "mac": MAC, "cols": ["Pow"] * 65,
        }, key))
        _reject(peer, address, b"{invalid JSON")
        _reject(peer, address, b" " * (MAX_DATAGRAM + 1))

        _, recovered = _exchange(peer, address, {
            "t": "status", "mac": MAC, "cols": ["Pow"],
        }, key)
        assert recovered["dat"] == [7]


@pytest.mark.parametrize("source", SOURCES,
                         ids=lambda source: str(source["assessment_index"]))
def test_middle_wb_ecb_cli_seeded_key_and_fresh_read_survive_process_restart(source):
    record = _record(source, "wb-restart")
    previous_key = None
    for restart in range(2):
        with cli_server([record]) as (address, identities), socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.settimeout(2)
            identity = identities[record["id"]]
            assert identity["profile"] == _profile_id(source)
            assert identity["mid"] == UART_PRESET_MID and identity["mac"] == MAC
            _, bound = _bind(peer, address)
            key = bound["key"].encode("ascii")
            assert len(key) == 16
            assert previous_key is None or key == previous_key
            previous_key = key
            _, initial = _exchange(peer, address, {
                "t": "status", "mac": MAC, "cols": ["Pow"],
            }, key)
            assert initial["dat"] == [0]
            if restart == 0:
                _exchange(peer, address, {
                    "t": "cmd", "mac": MAC, "opt": ["Pow"], "p": [7],
                }, key)
                _, changed = _exchange(peer, address, {
                    "t": "status", "mac": MAC, "cols": ["Pow"],
                }, key)
                assert changed["dat"] == [7]


@pytest.mark.parametrize("source", SOURCES,
                         ids=lambda source: str(source["assessment_index"]))
async def test_middle_wb_ecb_cli_unmodified_device_v1_control_and_ragged_getter_limit(source):
    record = _record(source)
    with cli_server([record]) as (address, identities):
        mac = identities[record["id"]]["mac"]
        client = Device(DeviceInfo(address[0], address[1], mac, "middle WB CLI",
                                   mid=UART_PRESET_MID), timeout=2, bind_timeout=1)
        try:
            await client.bind(cipher=CipherV1())
            await asyncio.wait_for(client._valid_state.wait(), 2)
            assert len(client.device_cipher.key.encode("ascii")) == 16

            client._valid_state.clear()
            await client.update_state(columns=["Pow"])
            await asyncio.wait_for(client._valid_state.wait(), 2)
            assert client.raw_properties["Pow"] == 0

            client.set_property("Pow", 7)
            client._valid_state.clear()
            await client.push_state_update()
            await asyncio.wait_for(client._valid_state.wait(), 2)
            assert client.raw_properties["Pow"] == 7
            client._valid_state.clear()
            await client.update_state(columns=["Pow"])
            await asyncio.wait_for(client._valid_state.wait(), 2)
            assert client.raw_properties["Pow"] == 7

            # The source returns a named void BtHid column without a scalar. The
            # unmodified client correctly refuses the unequal cols/dat response.
            client._valid_state.clear()
            await client.update_state(columns=["Pow", "BtHid"])
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(client._valid_state.wait(), 0.25)
            assert not client.has_valid_state
            assert client.raw_properties["Pow"] == 7
        finally:
            client.close()
