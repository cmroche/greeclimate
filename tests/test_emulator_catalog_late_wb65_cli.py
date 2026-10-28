"""Real subprocess acceptance for the exact late WB65VR GCM profiles."""

import asyncio
import base64
import json
from pathlib import Path
import socket

from Crypto.Cipher import AES
import pytest

from greeclimate.cipher import CipherV2
from greeclimate.device import Device
from greeclimate.deviceinfo import DeviceInfo
from tests.test_emulator_firmware_cli import (
    AAD, ECB_KEY, GCM_KEY, NONCE, cli_server, unpack,
)


FIXTURES = Path(__file__).parent / "fixtures" / "emulator"
MAC = "020000000001"
NAME = "WB65 CLI"
CID = "cli-peer"
SOURCES = (
    pytest.param(
        "v210", "sim-wb65vr-v2.10-10001",
        "c1dc1448cc0441c4cd8da8262b90c93b3ce181a0de5ca739f41aa07ba0f921df",
        "362001068254+U-4MWB65VRV2.10.bin", True,
        id="sim-wb65vr-v2.10-10001",
    ),
    pytest.param(
        "v211", "sim-wb65vr-v2.11-10001",
        "40f85264c8f450acd9e329a25fb9731b89940aa20cc38bd085c764495b5edf27",
        "362001068254+U-4MWB65VRV2.11.bin", True,
        id="sim-wb65vr-v2.11-10001",
    ),
    pytest.param(
        "v105", "sim-wb65vr-v1.05-10001",
        "107efeb2ab0cc8b32ffbe796ef711eb904d8b8c1d25f92b3095e0fca805739ac",
        "362001067419+U-WB65VRV1.05.bin", False,
        id="sim-wb65vr-v1.05-10001",
    ),
)


def source_fixture(version):
    return json.loads((FIXTURES / f"catalog-late-wb65-{version}_research.json").read_text())


def encrypted_outer(inner, key, selector, *, target=MAC, uid=42, cid=CID,
                    safe_suffix=True, extra_spaces=0, outer_fields=None, literal=None):
    """Build the source GCM envelope; normal probes avoid its zero-tail defect."""
    plain = literal if literal is not None else json.dumps(
        inner, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    plain += b" " * extra_spaces
    while True:
        cipher = AES.new(key, AES.MODE_GCM, nonce=NONCE)
        cipher.update(AAD)
        encrypted, tag = cipher.encrypt_and_digest(plain)
        if not safe_suffix or encrypted[-1] != 0:
            break
        # WB65's receiver trims decoded-zero tails; ordinary source-valid probes use JSON whitespace.
        plain += b" "
    outer = {
        "t": "pack", "i": selector, "uid": uid, "cid": cid, "tcid": target,
        "pack": base64.b64encode(encrypted).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }
    if outer_fields:
        outer.update(outer_fields)
    return outer


def encode_outer(outer):
    return json.dumps(outer, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def raw_wlan_reply(sock, address, request):
    sock.sendto(request, address)
    return sock.recvfrom(65535)[0]


def assert_gcm_envelope(raw, *, selector, uid=42):
    outer = json.loads(raw)
    assert not raw.endswith(b"\n")
    assert {name: value for name, value in outer.items() if name not in ("pack", "tag")} == {
        "t": "pack", "i": selector, "uid": uid, "cid": MAC, "tcid": "",
    }


def assert_status_shape(reply, requested, kinds):
    assert reply["t"] == "dat" and reply["r"] == 200
    assert reply["cols"] == requested
    widths = [len(kinds[name]) if name in kinds else 1 for name in requested]
    assert len(reply["dat"]) == sum(widths)
    offset = 0
    for name, width in zip(requested, widths):
        values = reply["dat"][offset:offset + width]
        offset += width
        for value, kind in zip(values, kinds.get(name, ["integer"])):
            assert type(value) is (str if kind == "string" else int)
            if kind != "string":
                assert value == 0


@pytest.mark.parametrize("version,profile_id,sha256,hid,v2", SOURCES)
async def test_wb65_actual_cli_source_matrix(version, profile_id, sha256, hid, v2):
    source = source_fixture(version)
    assert (source["profile_id"], source["source_sha256"], source["hid"]) == (
        profile_id, sha256, hid,
    )
    assert source["configured_mainboard_mid"] == "10001"
    assert source["numeric_bound"] == len(source["numeric_slots"]) == 495
    assert source["native_admission"]["literal_mid_match"]
    assert all(stage["returned"] and stage["mid_word"] == 65537
               and stage["mid_string"] == "10001"
               for stage in source["native_admission"]["stages"])
    wire = source["wire_runtime"]
    expected_operations = ["bind", "status", "cmd", "upgrade", "setT", "queryT",
                           "deleteT", "updateT", "dump"]
    if v2:
        expected_operations.append("binCmd")
    assert wire["operation_table"] == expected_operations
    assert wire["codec"]["gcm_i0"] == "device key"
    assert wire["codec"]["gcm_i1"] == "source context+0x58 key"
    assert wire["transport"]["udp_reply_appends_lf"] is False
    assert wire["plain_hooks"]["hbok_tm_reply"] == "original UDP request bytes and length unchanged; no LF"
    assert wire["timers"]["cache_capacity"] == 10
    assert wire["evidence_basis"]["callback_execution"] == "static-source-only"

    records = [{"id": "root", "profile": profile_id, "mid": "10001",
                "mac": MAC, "name": NAME}]
    advertisement = None
    device_key = None
    with cli_server(records) as (address, identities), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        assert identities["root"]["mac"] == MAC

        # Discovery is the source's separate ECB response, not an authenticated GCM packet.
        sock.sendto(b'{"t":"scan"}', address)
        discovery_raw = sock.recvfrom(65535)[0]
        discovery_outer, advertisement = unpack(discovery_raw, ECB_KEY)
        assert "tag" not in discovery_outer
        assert {name: value for name, value in discovery_outer.items()
                if name not in ("pack",)} == {
            "t": "pack", "i": 1, "uid": 0, "cid": MAC, "tcid": "",
        }
        expected_advertisement = {
            "t": "dev", "cid": "", "bc": "", "brand": "", "catalog": "",
            "mac": MAC, "mid": "10001", "model": "", "name": NAME,
            "lock": 0, "series": "", "vender": "", "ver": "", "hid": hid,
        }
        if v2:
            expected_advertisement["ModelType"] = ""
        assert advertisement == expected_advertisement
        assert set(advertisement) == set(wire["advertisement_fields"])

        def request(inner=None, *, literal=None, selector=0, key=None, outer_fields=None, target=MAC):
            if key is None:
                key = device_key if selector == 0 else GCM_KEY
            assert key is not None
            encoded = encode_outer(encrypted_outer(
                inner, key, selector, target=target, outer_fields=outer_fields, literal=literal,
            ))
            sock.sendto(encoded, address)
            response_raw = sock.recvfrom(65535)[0]
            assert_gcm_envelope(response_raw, selector=selector)
            _, response = unpack(response_raw, key, gcm=True)
            return response

        def quiet_and_recover(encoded, expected_pow=0):
            sock.sendto(encoded, address)
            sock.settimeout(0.12)
            try:
                with pytest.raises(socket.timeout):
                    sock.recvfrom(65535)
            finally:
                sock.settimeout(2)
            recovered = request({"t": "status", "mac": MAC, "cols": ["Pow"]})
            assert recovered["cols"] == ["Pow"] and recovered["dat"] == [expected_pow]

        bound = request({"t": "bind", "mac": MAC}, selector=1)
        assert bound["t"] == "bindok" and bound["r"] == 200 and bound["mac"] == MAC
        device_key = bound["key"].encode("ascii")
        assert len(device_key) == 16
        assert request({"t": "status", "mac": MAC, "cols": ["Pow"]})["dat"] == [0]
        assert request({"t": "status", "mac": MAC, "cols": ["Pow"]},
                       selector=1)["dat"] == [0]

        # Exercise all 495 source indexes, including repeated NoD aliases and metadata widths.
        getter_kinds = dict(source["metadata_getter_argument_kinds"])
        getter_kinds.update({"time": ["string"], "host": ["string"]})
        slots = source["numeric_slots"]
        for offset in range(0, len(slots), 32):
            columns = slots[offset:offset + 32]
            result = request({"t": "status", "mac": MAC, "cols": columns})
            assert_status_shape(result, columns, getter_kinds)

        metadata_names = list(getter_kinds)
        metadata = request({"t": "status", "mac": MAC, "cols": metadata_names})
        assert_status_shape(metadata, metadata_names, getter_kinds)
        negative_name = source["negative_metadata_getter_vectors"][0]["name"]
        missing = request({"t": "status", "mac": MAC, "cols": ["Pow", negative_name]})
        assert missing["cols"] == ["Pow"] and missing["dat"] == [0]

        # Metadata getters take precedence over raw slots with the same source name.
        metadata_columns = ["hid", "mid", "name", "ModelType", "mac"]
        assert request({"t": "status", "mac": MAC, "cols": metadata_columns})["dat"] == [
            hid, "", NAME, "", MAC,
        ]
        command_columns = ["host", "time", "lat", "lon"]
        command_values = ["cli-host", "2026-10-24 13:14:15", "1.2", "-3.4"]
        command_ack = request({"t": "cmd", "mac": MAC,
                               "opt": command_columns, "p": command_values})
        assert command_ack == {"t": "res", "r": 200, "mac": "",
                               "opt": command_columns, "p": command_values}
        assert request({"t": "status", "mac": MAC, "cols": command_columns})["dat"] == command_values

        # Every unique ordinary scalar name accepts an ACKed command and independent fresh cache read.
        scalar_names = list(dict.fromkeys(
            name for name in slots if name not in getter_kinds
        ))
        for offset in range(0, len(scalar_names), 32):
            names = scalar_names[offset:offset + 32]
            values = [65537] * len(names)
            ack = request({"t": "cmd", "mac": MAC, "opt": names, "p": values})
            assert ack == {"t": "res", "r": 200, "mac": "", "opt": names, "p": values}
            fresh = request({"t": "status", "mac": MAC, "cols": names})
            assert fresh["cols"] == names and fresh["dat"] == [1] * len(names)
            negative_values = [-1] * len(names)
            ack = request({"t": "cmd", "mac": MAC, "opt": names, "p": negative_values})
            assert ack["p"] == negative_values
            fresh = request({"t": "status", "mac": MAC, "cols": names})
            assert fresh["cols"] == names and fresh["dat"] == [65535] * len(names)

        for vector in source["command_parse_native"]["vectors"]:
            parsed = request(literal=vector["request"].encode("utf-8"))
            assert parsed["t"] == "res" and parsed["r"] == 200
            names = list(vector["cache"])
            fresh = request({"t": "status", "mac": MAC, "cols": names})
            assert fresh["cols"] == names and fresh["dat"] == list(vector["cache"].values())

        unknown_ack = request({"t": "cmd", "mac": MAC,
                               "opt": ["Pow", negative_name], "p": [17, 23]})
        assert unknown_ack["opt"] == ["Pow", negative_name]
        assert unknown_ack["p"] == [17, 23]
        unknown_readback = request({"t": "status", "mac": MAC,
                                    "cols": ["Pow", negative_name]})
        assert unknown_readback["cols"] == ["Pow"] and unknown_readback["dat"] == [17]

        # Codec positives and negatives stay source-qualified; no client packet is padded here.
        extended_tag = encrypted_outer(
            {"t": "status", "mac": MAC, "cols": ["Pow"]}, GCM_KEY, 1,
        )
        extended_tag["tag"] += "A"
        sock.sendto(encode_outer(extended_tag), address)
        extended_raw = sock.recvfrom(65535)[0]
        assert_gcm_envelope(extended_raw, selector=1)
        assert unpack(extended_raw, GCM_KEY, gcm=True)[1]["dat"] == [17]

        nonalphabet = None
        for extra_spaces in range(128):
            candidate = encrypted_outer(
                {"t": "status", "mac": MAC, "cols": ["Pow"]}, GCM_KEY, 1,
                extra_spaces=extra_spaces,
            )
            if "A" in candidate["tag"]:
                candidate["tag"] = candidate["tag"].replace("A", "?", 1)
                nonalphabet = candidate
                break
        assert nonalphabet is not None
        sock.sendto(encode_outer(nonalphabet), address)
        nonalphabet_raw = sock.recvfrom(65535)[0]
        assert unpack(nonalphabet_raw, GCM_KEY, gcm=True)[1]["dat"] == [17]

        malformed = []
        wrong_key = encrypted_outer(
            {"t": "status", "mac": MAC, "cols": ["Pow"]}, b"fedcba9876543210", 0,
        )
        malformed.append(encode_outer(wrong_key))
        wrong_selector = encrypted_outer(
            {"t": "status", "mac": MAC, "cols": ["Pow"]}, GCM_KEY, 1,
            outer_fields={"i": 0},
        )
        malformed.append(encode_outer(wrong_selector))
        wrong_target = encrypted_outer(
            {"t": "status", "mac": MAC, "cols": ["Pow"]}, GCM_KEY, 1,
            target="020000000002",
        )
        malformed.append(encode_outer(wrong_target))
        invalid_selector = encrypted_outer(
            {"t": "status", "mac": MAC, "cols": ["Pow"]}, GCM_KEY, 1,
            outer_fields={"i": 2},
        )
        malformed.append(encode_outer(invalid_selector))
        invalid_uid = encrypted_outer(
            {"t": "status", "mac": MAC, "cols": ["Pow"]}, GCM_KEY, 1,
            outer_fields={"uid": True},
        )
        malformed.append(encode_outer(invalid_uid))
        invalid_cid = encrypted_outer(
            {"t": "status", "mac": MAC, "cols": ["Pow"]}, GCM_KEY, 1,
            outer_fields={"cid": 7},
        )
        malformed.append(encode_outer(invalid_cid))
        invalid_tag = encrypted_outer(
            {"t": "status", "mac": MAC, "cols": ["Pow"]}, GCM_KEY, 1,
        )
        tag = bytearray(base64.b64decode(invalid_tag["tag"]))
        tag[0] ^= 1
        invalid_tag["tag"] = base64.b64encode(tag).decode("ascii")
        malformed.append(encode_outer(invalid_tag))
        missing_tag = encrypted_outer(
            {"t": "status", "mac": MAC, "cols": ["Pow"]}, GCM_KEY, 1,
        )
        del missing_tag["tag"]
        malformed.append(encode_outer(missing_tag))
        malformed.extend((
            encode_outer(encrypted_outer(
                {"t": "status", "mac": 17, "cols": ["Pow"]}, GCM_KEY, 1,
            )),
            encode_outer(encrypted_outer(
                {"t": "status", "mac": "bad\0mac", "cols": ["Pow"]}, GCM_KEY, 1,
            )),
            encode_outer(encrypted_outer(
                {"t": "status", "mac": MAC, "cols": None}, GCM_KEY, 1,
            )),
            encode_outer(encrypted_outer(
                {"t": "status", "mac": MAC, "cols": ["Pow"] * 65}, GCM_KEY, 1,
            )),
            encode_outer(encrypted_outer(
                {"t": "status", "mac": MAC, "cols": [17]}, GCM_KEY, 1,
            )),
            encode_outer(encrypted_outer(
                {"t": "cmd", "mac": MAC, "opt": ["Pow"], "p": []}, GCM_KEY, 1,
            )),
            encode_outer(encrypted_outer(
                {"t": "cmd", "mac": MAC, "opt": ["Pow"] * 33, "p": [1] * 33}, GCM_KEY, 1,
            )),
            b"{invalid JSON",
        ))
        for invalid in malformed:
            quiet_and_recover(invalid, expected_pow=17)

        # Deliberately reproduce the source's decoded-zero-tail failure without the normal safe suffix.
        zero_tail = None
        zero_tail_plain = {"t": "status", "mac": MAC, "cols": ["Pow"]}
        for extra_spaces in range(4096):
            candidate = encrypted_outer(
                zero_tail_plain, GCM_KEY, 1, safe_suffix=False, extra_spaces=extra_spaces,
            )
            if base64.b64decode(candidate["pack"])[-1] == 0:
                zero_tail = candidate
                break
        assert zero_tail is not None
        quiet_and_recover(encode_outer(zero_tail), expected_pow=17)

        # Local operations have exact wire acceptance only; this does not assert cloud, flash, or MCU delivery.
        assert request({"t": "upgrade", "mac": MAC,
                        "url": "https://" + "x" * (119 - len("https://"))}) == {
            "t": "ret", "r": 200,
        }
        quiet_and_recover(encode_outer(encrypted_outer(
            {"t": "upgrade", "mac": MAC, "url": "https://" + "x" * (120 - len("https://"))},
            device_key, 0,
        )), expected_pow=17)
        assert request({"t": "dump", "mac": MAC, "period": 30, "cnt": 2}) == {
            "t": "ret", "r": 200,
        }

        timer = {
            "t": "setT", "mac": MAC, "id": 258, "name": "night", "enable": 1,
            "tz": 0, "hr": 6, "min": 45, "sec": 59, "week": [1, 0, 1, 0, 0, 1, 0],
            "cmd": [{"mac": MAC, "opt": ["Pow"], "p": [17]}],
        }
        assert request(timer) == {"t": "resT", "r": 200}
        assert request({"t": "queryT", "mac": MAC, "index": 0, "count": 10}) == {
            "t": "listT", "total": 1, "index": 0, "list": [{
                "id": 2, "name": "night", "enable": 1, "week": [1, 0, 1, 0, 0, 1, 0],
                "hr": 6, "min": 45, "sec": 0,
                "cmd": [{"mac": MAC, "opt": ["Pow"], "p": [17]}],
            }],
        }
        updated = dict(timer, t="updateT", name="later", enable=0, sec=12,
                       cmd=[{"mac": MAC, "opt": ["Pow"], "p": [23]}])
        assert request(updated) == {"t": "resT", "r": 200}
        assert request({"t": "queryT", "mac": MAC, "index": 0, "count": 10}) == {
            "t": "listT", "total": 1, "index": 0, "list": [{
                "id": 2, "name": "later", "enable": 0, "week": [1, 0, 1, 0, 0, 1, 0],
                "hr": 6, "min": 45, "sec": 0,
                "cmd": [{"mac": MAC, "opt": ["Pow"], "p": [23]}],
            }],
        }
        assert request({"t": "deleteT", "mac": MAC, "id": 258}) == {"t": "resT", "r": 200}
        assert request({"t": "queryT", "mac": MAC, "index": 0, "count": 10}) == {
            "t": "listT", "total": 0, "index": 0, "list": [],
        }

        for identifier in range(10):
            full_timer = dict(timer, id=identifier, name=f"slot-{identifier}")
            assert request(full_timer) == {"t": "resT", "r": 200}
        full_table = request({"t": "queryT", "mac": MAC, "index": 0, "count": 3})
        assert full_table["t"] == "listT" and full_table["total"] == 10
        all_ids = [record["id"] for record in full_table["list"]]
        for index in (3, 6, 9):
            page = request({"t": "queryT", "mac": MAC, "index": index, "count": 3})
            assert page["total"] == 10
            all_ids.extend(record["id"] for record in page["list"])
        assert all_ids == list(range(10))
        peer_timer = dict(timer, id=10, name="eleventh")
        quiet_and_recover(encode_outer(encrypted_outer(peer_timer, device_key, 0)), expected_pow=17)
        assert request({"t": "queryT", "mac": MAC, "index": 0, "count": 3})["total"] == 10
        for identifier in range(10):
            assert request({"t": "deleteT", "mac": MAC, "id": identifier}) == {
                "t": "resT", "r": 200,
            }
        assert request({"t": "queryT", "mac": MAC, "index": 0, "count": 10})["total"] == 0
        malformed_timer = dict(timer, id=30, week=[1] * 6)
        quiet_and_recover(encode_outer(encrypted_outer(malformed_timer, device_key, 0)),
                          expected_pow=17)
        assert request({"t": "queryT", "mac": MAC, "index": 0, "count": 10})["total"] == 0

        if v2:
            frame = bytearray(44)
            frame[:3] = b"\x7e\x7e\x2a"
            frame[7], frame[43] = 0x7E, 0x01
            binary = {"t": "binCmd", "mac": MAC,
                      "hex01": base64.b64encode(frame).decode("ascii"),
                      "ReportFreq": 0xFF, "ReportClientID": "x" * 26}
            assert request(binary) == {"t": "res", "r": 200}
            oversized_frame = bytearray(61)
            oversized_frame[:3] = b"\x7e\x7e\x3b"
            invalid_binary = {"t": "binCmd", "mac": MAC,
                              "hex01": base64.b64encode(oversized_frame).decode("ascii")}
            quiet_and_recover(encode_outer(encrypted_outer(invalid_binary, device_key, 0)),
                              expected_pow=17)
            invalid_client_id = dict(binary, ReportClientID="x" * 27)
            quiet_and_recover(encode_outer(encrypted_outer(invalid_client_id, device_key, 0)),
                              expected_pow=17)
        else:
            absent_operation = {"t": "binCmd", "mac": MAC,
                                "hex01": base64.b64encode(bytes(44)).decode("ascii")}
            quiet_and_recover(encode_outer(encrypted_outer(absent_operation, device_key, 0)),
                              expected_pow=17)

        assert request({"t": "status", "mac": MAC, "cols": ["Pow"]})["dat"] == [17]

        # WLAN state is private, so assert only the source's externally visible WLAN acknowledgement.
        wlan = (b'{ "psw" : "secret", "t" : "wlan", "ssid" : "caf\xc3\xa9", '
                b'"host" : "dis.gree.com", "tcid" : "020000000001" }\r\n')
        assert json.loads(raw_wlan_reply(sock, address, wlan)) == {
            "t": "ret", "r": 200, "mac": MAC,
        }
        heartbeat = b'{ "note" : "caf\xc3\xa9", "t" : "hbok", "tcid" : "020000000001" }\r\n'
        assert raw_wlan_reply(sock, address, heartbeat) == heartbeat
        time_message = (b' \n{"time":"2026-10-24 13:14:15","t":"tm",'
                        b'"note":"\xe6\xb8\xa9\xe5\xba\xa6","tcid":"020000000001"}\t ')
        assert raw_wlan_reply(sock, address, time_message) == time_message
        assert request({"t": "status", "mac": MAC, "cols": ["time"]})["dat"] == [
            "2026-10-24 13:14:15",
        ]
        wrong_plain_target = b'{"t":"hbok","tcid":"020000000002"}'
        sock.sendto(wrong_plain_target, address)
        sock.settimeout(0.12)
        try:
            with pytest.raises(socket.timeout):
                sock.recvfrom(65535)
        finally:
            sock.settimeout(2)
        bad_time = b'{"t":"tm","time":"' + b"x" * 33 + b'","tcid":"020000000001"}'
        sock.sendto(bad_time, address)
        sock.settimeout(0.12)
        try:
            with pytest.raises(socket.timeout):
                sock.recvfrom(65535)
        finally:
            sock.settimeout(2)
        assert request({"t": "status", "mac": MAC, "cols": ["time"]})["dat"] == [
            "2026-10-24 13:14:15",
        ]

        # Stock client packets have no compatibility whitespace; these seeded bind/status bytes pass,
        # while the earlier zero-tail probe records the separate source-specific edge.
        client = Device(DeviceInfo(address[0], address[1], MAC, NAME, mid="10001"),
                        timeout=2, bind_timeout=1)
        try:
            await client.bind(cipher=CipherV2())
            assert client.device_cipher.key == device_key.decode("ascii")
            client._valid_state.clear()
            await client.update_state(columns=["Pow", "SetTem"])
            await asyncio.wait_for(client._valid_state.wait(), 2)
            assert [client.raw_properties[name] for name in ("Pow", "SetTem")] == [17, 65535]
        finally:
            client.close()

    # A second real CLI process proves stable seeded binding and fresh scalar state after restart.
    with cli_server(records) as (address, identities), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        assert identities["root"]["mac"] == MAC
        sock.sendto(b'{"t":"scan"}', address)
        restarted_outer, restarted_advertisement = unpack(sock.recvfrom(65535)[0], ECB_KEY)
        assert restarted_advertisement == advertisement
        assert restarted_outer["i"] == 1 and restarted_outer["uid"] == 0
        restarted_bound_outer = encrypted_outer({"t": "bind", "mac": MAC}, GCM_KEY, 1)
        sock.sendto(encode_outer(restarted_bound_outer), address)
        restarted_raw = sock.recvfrom(65535)[0]
        assert_gcm_envelope(restarted_raw, selector=1)
        restarted_key = unpack(restarted_raw, GCM_KEY, gcm=True)[1]["key"]
        assert restarted_key == device_key.decode("ascii")
        restarted_status = encrypted_outer(
            {"t": "status", "mac": MAC, "cols": ["Pow"]},
            restarted_key.encode("ascii"), 0,
        )
        sock.sendto(encode_outer(restarted_status), address)
        status_raw = sock.recvfrom(65535)[0]
        assert_gcm_envelope(status_raw, selector=0)
        assert unpack(status_raw, restarted_key.encode("ascii"), gcm=True)[1]["dat"] == [0]
