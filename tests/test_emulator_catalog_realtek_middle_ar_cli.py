"""Real CLI acceptance for the exact-source Realtek WB AR models."""

import asyncio
import base64
import json
from pathlib import Path
import socket

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import pytest

from greeclimate.cipher import CipherV1
from greeclimate.device import Device
from greeclimate.deviceinfo import DeviceInfo
from tests.test_emulator_firmware_cli import (
    ECB_KEY,
    cli_server,
    packet as cli_packet,
    unpack as cli_unpack,
)

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "emulator" /
                      "catalog-realtek-middle-ar_research.json").read_text())
AR0_MAC = "020000000001"
AR1_MAC = "020000000002"
AR7_MAC = "020000000007"
PEER_ID = "ar-cli-peer"
AR0_START_TIME = "2026-05-01 11:45:00"


def _send(sock, address, mac, inner, channel, key=None, *, cid=PEER_ID,
          target=None, gcm=False):
    outer = {"t": "pack", "i": channel, "uid": 42, "cid": cid,
             "tcid": mac if target is None else target}
    if (channel & 0xff) == 2:
        outer["pack"] = inner
        encoded = cli_packet(outer)
    else:
        encoded = cli_packet(outer, inner, key, gcm=gcm)
    sock.sendto(encoded, address)


def _receive(sock, address, key=None):
    data, sender = sock.recvfrom(65535)
    assert sender == address
    assert not data.endswith(b"\n")
    outer = json.loads(data)
    assert "tag" not in outer
    if isinstance(outer.get("pack"), dict):
        return outer, outer["pack"]
    assert key is not None
    decoded_outer, inner = cli_unpack(data, key)
    encrypted = base64.b64decode(outer["pack"], validate=True)
    plain = unpad(AES.new(key, AES.MODE_ECB).decrypt(encrypted), AES.block_size)
    assert plain.endswith(b"\n")
    assert json.loads(plain[:-1]) == inner
    assert decoded_outer == outer
    return outer, inner


def _quiet(sock):
    timeout = sock.gettimeout()
    sock.settimeout(0.15)
    try:
        with pytest.raises(socket.timeout):
            sock.recvfrom(65535)
    finally:
        sock.settimeout(timeout)


def _reject(sock, reply_sock=None):
    _quiet(sock)
    if reply_sock is not None and reply_sock is not sock:
        _quiet(reply_sock)


def _assert_ar1r_outer(outer, mac, channel):
    assert {name: value for name, value in outer.items() if name != "pack"} == {
        "t": "pack", "i": channel, "uid": 42, "cid": mac,
        "tcid": PEER_ID,
    }
    assert isinstance(outer["pack"], str)


async def test_ar0_real_cli_full_namespace_metadata_negatives_and_public_device():
    source = FIXTURE["profiles"][0]
    assert source["channels"] == {
        "0": {"key": "dynamic source key buffer; caller-supplied device key",
              "operations": ["status", "cmd", "binCmd", "upgrade", "queryT"]},
        "1": {"key": "a3K8Bx%2r8Y7#xDh", "operations": ["bind"]},
        "2": {"key": None, "operations": ["scan", "wlan", "tm"]},
    }
    assert ECB_KEY.decode("ascii") == source["channels"]["1"]["key"]
    record = {
        "id": "ar0", "profile": source["id"], "mid": source["emitted_mid"],
        "mac": AR0_MAC,
        "state": {"host": "ar0.local", "ver": "V3.5.M-test",
                  "time": AR0_START_TIME, "rssi": -49, "bc": "ar0-bc"},
    }
    with cli_server([record]) as (address, identities), socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(2)
        identity = identities["ar0"]
        assert identity["profile"] == source["id"]
        assert identity["mid"] == source["emitted_mid"]
        mac = identity["mac"]
        assert mac == AR0_MAC

        _send(peer, address, mac, {"t": "scan"}, 2)
        outer, scan = _receive(peer, address)
        assert outer == {"t": "pack", "i": 2, "uid": 0, "cid": mac,
                         "pack": scan, "tcid": "app"}
        assert scan == {
            "t": "dev", "mac": mac, "mid": "10001", "name": scan["name"],
            "ver": "V3.5.M-test", "lock": 0, "bc": "ar0-bc", "brand": "gree",
            "catalog": "gree", "model": "gree", "series": "gree", "vender": "gree",
        }
        assert isinstance(scan["name"], str)
        assert "hid" not in scan
        # Outer cJSON selectors are converted to valueint's low byte before dispatch.
        _send(peer, address, mac, {"t": "scan"}, 258)
        normalized_outer, normalized_scan = _receive(peer, address)
        assert normalized_outer == {"t": "pack", "i": 2, "uid": 0, "cid": mac,
                                    "pack": normalized_scan, "tcid": "app"}
        assert normalized_scan == scan

        _send(peer, address, mac, {"t": "bind", "mac": mac}, 257, ECB_KEY)
        outer, bound = _receive(peer, address, ECB_KEY)
        assert {name: value for name, value in outer.items() if name != "pack"} == {
            "t": "pack", "i": 1, "uid": 0, "cid": mac, "tcid": "asvr",
        }
        assert bound["t"] == "bindok" and bound["r"] == 200 and bound["mac"] == mac
        key = bound["key"].encode("ascii")
        assert len(key) == 16

        cols = ["host", "ver", "hid", "mid", "unknown", "host", "time", "rssi", "bc"]
        _send(peer, address, mac, {"t": "status", "cols": cols}, 0, key)
        outer, status = _receive(peer, address, key)
        assert {name: value for name, value in outer.items() if name != "pack"} == {
            "t": "pack", "i": 0, "uid": 0, "cid": mac, "tcid": "asvr",
        }
        assert status == {
            "t": "dat", "r": 200, "mac": mac, "cols": cols,
            "dat": ["ar0.local", "V3.5.M-test", source["status_hid"], "10001",
                    "ar0.local", AR0_START_TIME, -49, "ar0-bc"],
        }

        _send(peer, address, mac, {
            "t": "cmd", "opt": ["RawOnly", "time", "ReportClientID"],
            "p": ["1e3", "2026-05-01 11:45:00", "local-client"],
        }, 0, key)
        _, command = _receive(peer, address, key)
        assert command == {
            "t": "res", "r": 200, "mac": mac,
            "opt": ["RawOnly", "time", "ReportClientID"],
            "p": [1, "2026-05-01 11:45:00", "local-client"],
            "val": [1, "2026-05-01 11:45:00", "local-client"],
        }
        _send(peer, address, mac, {"t": "status", "cols": ["time"]}, 0, key)
        assert _receive(peer, address, key)[1]["dat"] == ["2026-05-01 11:45:00"]

        _send(peer, address, mac, {
            "t": "binCmd", "hex6C": [1, 2, 3],
            "fragment": [{"cmd_type": 0x91, "byte": 0, "mask": 0x0f, "value": 3}],
        }, 0, key)
        assert _receive(peer, address, key)[1] == {"t": "res", "r": 200, "mac": mac}
        _send(peer, address, mac, {
            "t": "upgrade", "mac": mac[:8], "url": "https://example.invalid/update.bin",
        }, 0, key)
        assert _receive(peer, address, key)[1] == {"t": "ret", "r": 200, "mac": mac}
        _send(peer, address, mac, {"t": "queryT", "index": 260, "count": 9}, 0, key)
        assert _receive(peer, address, key)[1] == {"t": "listT", "total": 0, "index": 4}
        _send(peer, address, mac, {"t": "wlan", "ssid": "synthetic", "psw": "unused",
                                   "host": "example.invalid"}, 2)
        assert _receive(peer, address)[1] == {"t": "ret", "r": 200, "mac": mac}
        _send(peer, address, mac, {"t": "tm", "time": "2026-06-01 12:00:00"}, 2)
        _quiet(peer)
        _send(peer, address, mac, {"t": "status", "cols": ["time"]}, 0, key)
        assert _receive(peer, address, key)[1]["dat"] == ["2026-06-01 12:00:00"]

        for bad_key, selector, kind in (
            (b"0000000000000000", 1, {"t": "bind", "mac": mac}),
            (key, 1, {"t": "status", "cols": ["hid"]}),
            (b"0000000000000000", 0, {"t": "queryT", "index": 0, "count": 10}),
        ):
            _send(peer, address, mac, kind, selector, bad_key)
            _quiet(peer)
        _send(peer, address, mac, {"t": "status", "cols": ["hid"]}, 0, key,
              target="020000000099")
        _quiet(peer)
        _send(peer, address, mac, {"t": "queryT", "index": 0, "count": 1}, 0, key,
              gcm=True)
        _quiet(peer)
        _send(peer, address, mac, {"t": "cmd", "opt": ["Pow"], "p": []}, 0, key)
        _quiet(peer)
        _send(peer, address, mac, {"t": "binCmd", "hex91": [1, 2, 3]}, 0, key)
        _quiet(peer)
        peer.sendto(json.dumps({"t": "pack", "i": 2, "uid": 42, "cid": PEER_ID,
                                "tcid": mac, "pack": "not-a-plaintext-object"}).encode(), address)
        _quiet(peer)
        peer.sendto(b"{invalid JSON", address)
        _quiet(peer)
        peer.sendto(json.dumps({"t": "pack", "i": 0, "uid": 42, "cid": PEER_ID,
                                "tcid": mac, "pack": "%%%"}).encode(), address)
        _quiet(peer)
        _send(peer, address, mac, {"t": "status", "cols": ["host", "time"]}, 0, key)
        assert _receive(peer, address, key)[1]["dat"] == ["ar0.local", "2026-06-01 12:00:00"]

        client = Device(
            DeviceInfo(address[0], address[1], mac, "AR0 CLI acceptance", mid=source["emitted_mid"]),
            timeout=2, bind_timeout=1,
        )
        try:
            await client.bind(cipher=CipherV1())
            assert client.device_cipher.key == key.decode("ascii")
            client._valid_state.clear()
            columns = ["host", "ver", "hid", "mid", "name", "rssi", "bc", "time"]
            await client.update_state(columns=columns)
            await asyncio.wait_for(client._valid_state.wait(), 2)
            assert client.hid == source["status_hid"]
            assert {name: client.raw_properties[name] for name in columns if name not in ("hid", "name")} == {
                "host": "ar0.local", "ver": "V3.5.M-test", "mid": "10001",
                "rssi": -49, "bc": "ar0-bc",
                "time": "2026-06-01 12:00:00",
            }
            assert isinstance(client.raw_properties["name"], str)
        finally:
            client.close()


def test_ar0_cli_restart_restores_configured_cache_and_seeded_key():
    source = FIXTURE["profiles"][0]
    record = {"id": "ar0-restart", "profile": source["id"],
              "mid": source["emitted_mid"], "mac": AR0_MAC,
              "state": {"time": AR0_START_TIME}}
    previous = None
    for restart in range(2):
        with cli_server([record]) as (address, identities), socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.settimeout(2)
            mac = identities["ar0-restart"]["mac"]
            _send(peer, address, mac, {"t": "bind", "mac": mac}, 1, ECB_KEY)
            _, bound = _receive(peer, address, ECB_KEY)
            key = bound["key"].encode("ascii")
            first = previous is None
            assert first or previous == (mac, key)
            previous = (mac, key)
            expected_time = AR0_START_TIME
            if first:
                expected_time = "2026-06-01 12:00:00"
                _send(peer, address, mac, {"t": "tm", "time": expected_time}, 2)
                _quiet(peer)
            _send(peer, address, mac, {"t": "status", "cols": ["time"]}, 0, key)
            assert _receive(peer, address, key)[1]["dat"] == [expected_time]


def test_ar1_ar7_real_cli_fixed_ports_callbacks_negatives_and_fresh_restart():
    for source, mac in zip(FIXTURE["profiles"][1:], (AR1_MAC, AR7_MAC), strict=True):
        channel1_key = source["channel1_key_readout"]["bytes_ascii"].encode("ascii")
        assert len(channel1_key) == 16 and channel1_key != ECB_KEY
        record = {"id": source["id"], "profile": source["id"],
                  "mid": source["emitted_mid"], "mac": mac}
        previous = None
        for restart in range(2):
            with cli_server([record]) as (address, identities), \
                    socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer, \
                    socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reply, \
                    socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rejected:
                peer.bind(("127.0.0.1", source["peer_source_port"]))
                reply.bind(("127.0.0.1", source["reply_port"]))
                for sock in (peer, reply, rejected):
                    sock.settimeout(2)
                identity = identities[source["id"]]
                assert identity["profile"] == source["id"]
                assert identity["mid"] == source["emitted_mid"]
                assert identity["mac"] == mac
                assert peer.getsockname()[1] == 5001
                assert reply.getsockname()[1] == 5000

                _send(peer, address, mac, {"t": "scan"}, 1, channel1_key)
                outer, advertisement = _receive(reply, address, channel1_key)
                _assert_ar1r_outer(outer, mac, 1)
                assert advertisement["t"] == source["scan_type"] == "UBind"
                assert advertisement["mid"] == source["emitted_mid"]
                assert advertisement["ver"] == "V3.5.M"
                assert isinstance(advertisement["devkey"], str)
                assert advertisement["hid"] == source["hid"]
                device_key = advertisement["devkey"].encode("ascii")
                assert len(device_key) == 16 and device_key != channel1_key
                assert set(advertisement) == set(source["ubind_fields"])
                if source["index"] == 1:
                    assert advertisement["scene"] == 1
                else:
                    # AR7 writes scene into the input buffer; its UBind output omits it.
                    assert "scene" not in advertisement
                assert "GnetID" not in advertisement and "memberMAC" not in advertisement
                assert previous is None or previous == (mac, device_key)
                previous = (mac, device_key)
                _send(peer, address, mac, {"t": "scan"}, 257, channel1_key)
                normalized_outer, normalized_scan = _receive(reply, address, channel1_key)
                _assert_ar1r_outer(normalized_outer, mac, 1)
                assert normalized_scan == advertisement

                if restart:
                    _send(peer, address, mac, {"t": "reset", "mac": mac[:6]}, 0, device_key)
                    reset_outer, reset = _receive(reply, address, device_key)
                    _assert_ar1r_outer(reset_outer, mac, 0)
                    assert reset == {"t": "res", "r": 200, "mac": mac}
                    continue

                # The source table's channel flags are an exact per-hash contract.
                _send(peer, address, mac, {"t": "scan"}, 0, device_key)
                _reject(peer, reply)
                _send(peer, address, mac, {"t": "scan"}, 1, b"0000000000000000")
                _reject(peer, reply)
                _send(peer, address, mac, {"t": "scan"}, 1, channel1_key,
                      target="020000000099")
                _reject(peer, reply)
                _send(peer, address, mac, {"t": "reset", "mac": mac[:6]}, 0,
                      b"0000000000000000")
                _reject(peer, reply)
                _send(peer, address, mac, {"t": "reset", "mac": mac[:6]}, 0,
                      device_key, gcm=True)
                _reject(peer, reply)
                _send(peer, address, mac, {
                    "t": "binCmd", "sceneId": 2, "operType": 1, "sence_enable": 1,
                    "fragment": [{"cmd_type": 0x91}],
                }, 0, device_key)
                _reject(peer, reply)
                peer.sendto(b"{invalid JSON", address)
                _reject(peer, reply)
                peer.sendto(json.dumps({
                    "t": "pack", "i": 0, "uid": 42, "cid": PEER_ID,
                    "tcid": mac, "pack": "%%%",
                }).encode(), address)
                _reject(peer, reply)
                rejected.sendto(cli_packet({
                    "t": "pack", "i": 1, "uid": 42, "cid": PEER_ID, "tcid": mac,
                }, {"t": "scan"}, channel1_key), address)
                _reject(rejected, reply)
                _send(peer, address, mac, {"t": "scan"}, 1, channel1_key)
                recovered_outer, recovered = _receive(reply, address, channel1_key)
                _assert_ar1r_outer(recovered_outer, mac, 1)
                assert recovered == advertisement

                if source["index"] == 1:
                    _send(peer, address, mac, {
                        "t": "UBindok", "mac": "020000000099", "roomId": 7,
                        "hostManaged": 0,
                    }, 0, device_key)
                    _reject(peer, reply)
                    _send(peer, address, mac, {"t": "scan"}, 1, channel1_key)
                    _, unbound_scan = _receive(reply, address, channel1_key)
                    assert unbound_scan["t"] == "UBind" and unbound_scan["lock"] == 0
                    assert unbound_scan["scene"] == 1

                # UBindok is silent; scan exposes only the modeled lock/readiness state.
                _send(peer, address, mac, {
                    "t": "UBindok", "mac": "020000000099", "roomId": 7,
                }, 0, device_key)
                _reject(peer, reply)
                _send(peer, address, mac, {"t": "scan"}, 1, channel1_key)
                _reject(peer, reply)
                _send(peer, address, mac, {"t": "scan", "allRange": 1}, 1, channel1_key)
                ready_outer, ready_scan = _receive(reply, address, channel1_key)
                _assert_ar1r_outer(ready_outer, mac, 1)
                assert ready_scan["lock"] == 1
                if source["index"] == 1:
                    assert ready_scan["scene"] == 1
                else:
                    assert "scene" not in ready_scan

                _send(peer, address, mac, {"t": "hbok"}, 1, channel1_key)
                _reject(peer, reply)
                # Scene 1 creates the source's default pair without sence_enable.
                _send(peer, address, mac, {"t": "binCmd", "sceneId": 1, "operType": 1,
                                           "fragment": [{"cmd_type": 0x91, "byte": 0,
                                                          "mask": 0x0f, "value": 5,
                                                          "initval": 9}]}, 0, device_key)
                ack_outer, acknowledgement = _receive(reply, address, device_key)
                _assert_ar1r_outer(ack_outer, mac, 0)
                assert acknowledgement == {"t": "res", "r": 200, "mac": mac}
                _send(peer, address, mac, {"t": "reset", "mac": mac[:6]}, 0, device_key)
                reset_outer, reset = _receive(reply, address, device_key)
                _assert_ar1r_outer(reset_outer, mac, 0)
                assert reset == {"t": "res", "r": 200, "mac": mac}
                _send(peer, address, mac, {"t": "Utm", "time": "2026-06-01 12:00:00"},
                      0, device_key)
                _reject(peer, reply)
                _send(peer, address, mac, {"t": "loginInfoRes", "r": 200,
                                           "loginInfo": {"GnetID": 258}}, 0, device_key)
                _reject(peer, reply)
                _send(peer, address, mac, {"t": "ret", "r": 200}, 0, device_key)
                _reject(peer, reply)
                _send(peer, address, mac, {"t": "statusCheck"}, 0, device_key)
                _reject(peer, reply)
