"""Actual-CLI native-peer acceptance for source-24/source-35 Middle WB."""

import base64
import json
from pathlib import Path
import socket

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from tests.test_emulator_firmware_cli import cli_server


FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-realtek-middle-wb-legacy_research.json").read_text())
SOURCES = tuple(FIXTURE["sources"])
MAC = "020000000001"
HOST_MAC = "aabbccddeeff"
PEER = "middle-wb-native-peer"
UART_PRESET_MID = FIXTURE["initial_mid"]
MAX_REQUEST = 1536
EXPECTED_OPERATIONS = {
    24: {"scan": 1, "UBindok": 0, "ret": 0, "binCmd": 0, "reset": 0,
         "hbok": 1, "Utm": 0, "loginInfoRes": 0, "statusCheck": 0},
    35: {"scan": 1, "UBindok": 0, "ret": 0, "binCmd": 0, "reset": 0,
         "hbok": 1, "Utm": 0},
}


def _wire(inner, key, selector, *, uid=42, raw=None, i_token=None, uid_token=None,
          cid=PEER, tcid="not-the-module"):
    plain = (raw if raw is not None else json.dumps(
        inner, separators=(",", ":"), ensure_ascii=False,
    ).encode())
    if not plain.endswith(b"\n"):
        plain += b"\n"
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(plain, 16))
    outer = {"t": "pack", "i": selector, "uid": uid, "cid": cid,
             "tcid": tcid, "pack": base64.b64encode(encrypted).decode("ascii")}
    packet = json.dumps(outer, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if i_token is not None:
        packet = packet.replace(f'"i":{selector}'.encode(), f'"i":{i_token}'.encode(), 1)
    if uid_token is not None:
        packet = packet.replace(f'"uid":{uid}'.encode(), f'"uid":{uid_token}'.encode(), 1)
    return packet


def _send(sock, address, inner, key, selector, **kwargs):
    packet = _wire(inner, key, selector, **kwargs)
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
    plain = unpad(AES.new(key, AES.MODE_ECB).decrypt(encrypted), 16)
    assert plain.endswith(b"\n")
    return outer, json.loads(plain)


def _quiet(sock):
    previous = sock.gettimeout()
    sock.settimeout(0.12)
    try:
        with pytest.raises(socket.timeout):
            sock.recvfrom(65535)
    finally:
        sock.settimeout(previous)


def _reply_header(outer):
    return {name: value for name, value in outer.items() if name != "pack"}


def _record(source):
    return {"id": "legacy-root", "profile": source["profile_id"],
            "mid": UART_PRESET_MID, "mac": MAC}


def _sockets():
    transmit = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    transmit.bind(("127.0.0.1", 5001))
    receive.bind(("127.0.0.1", 5000))
    receive.settimeout(2)
    return transmit, receive


def _scan(transmit, receive, address, source, *, first=False):
    factory_key = bytes.fromhex(source["factory_key_hex"])
    if first:
        _send(transmit, address, {"t": "scan"}, factory_key, 1,
              i_token="257", uid_token="true", cid=["ignored"],
              tcid={"ignored": True})
        expected_uid = 1
    else:
        _send(transmit, address, {"t": "scan"}, factory_key, 1)
        expected_uid = 42
    outer, inner = _receive(receive, address, factory_key)
    device_key = inner["devkey"].encode("ascii")
    assert len(device_key) == 16 and device_key.decode("ascii").isalnum()
    expected = {"t": "UBind", "mid": UART_PRESET_MID, "ver": source["sdk_ver"],
                "devkey": device_key.decode("ascii"), "hid": source["hid"], "lock": 0}
    if source["scan_scene_output"]:
        expected["scene"] = 1
    assert inner == expected
    assert _reply_header(outer) == {
        "t": "pack", "i": 1, "uid": expected_uid, "cid": MAC,
        "msgId": 1, "tcid": "",
    }
    return device_key


@pytest.mark.parametrize("source", SOURCES,
                         ids=lambda source: source["profile_id"])
def test_legacy_middle_actual_cli_native_callbacks_recovery_and_fresh_process(source):
    index = source["assessment_index"]
    assert UART_PRESET_MID == "10001"
    assert source["profile_id"] == f"sim-middle-wb-legacy-{source['source_sha256'][:8]}-10001"
    assert source["operations"] == EXPECTED_OPERATIONS[index]
    assert len(EXPECTED_OPERATIONS[index]) == (9 if index == 24 else 7)
    record = _record(source)
    learned_key = None

    for restart in range(2):
        with cli_server([record]) as (address, identities):
            assert identities["legacy-root"]["profile"] == source["profile_id"]
            assert identities["legacy-root"]["mid"] == UART_PRESET_MID
            assert identities["legacy-root"]["mac"] == MAC
            transmit, receive = _sockets()
            try:
                factory_key = bytes.fromhex(source["factory_key_hex"])
                _send(transmit, address, {"t": "scan"}, b"wrongfactorykey1", 1)
                _quiet(receive)

                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as wrong_port:
                    wrong_port.bind(("127.0.0.1", 5002))
                    _send(wrong_port, address, {"t": "scan"}, factory_key, 1)
                    _quiet(receive)

                if restart == 0:
                    device_key = _scan(transmit, receive, address, source, first=True)
                else:
                    device_key = _scan(transmit, receive, address, source)
                    assert device_key == learned_key
                if learned_key is None:
                    learned_key = device_key

                if restart == 0:
                    _send(transmit, address, {"t": "binCmd"}, b"wrong-sessionkey", 0)
                    _quiet(receive)
                    _send(transmit, address, {"t": "binCmd"}, device_key, 0,
                          raw=b'{"T":"BINCMD","t":"status","HEX92":null,"hex92":"ignored-second"}',
                          i_token="0.9", uid_token="-3.9")
                    outer, inner = _receive(receive, address, device_key)
                    assert inner == FIXTURE["ordinary_ack"]
                    assert _reply_header(outer) == {
                        "t": "pack", "i": 0, "uid": -3, "cid": MAC,
                        "msgId": 2, "tcid": "",
                    }

                    _send(transmit, address, {"t": "reset", "mac": "000000000000"}, device_key, 0)
                    _quiet(receive)
                    _send(transmit, address, {"t": "reset", "mac": MAC}, device_key, 0)
                    outer, inner = _receive(receive, address, device_key)
                    assert inner == FIXTURE["ordinary_ack"]
                    assert _reply_header(outer) == {
                        "t": "pack", "i": 0, "uid": 42, "cid": MAC,
                        "msgId": 2, "tcid": "",
                    }

                    _send(transmit, address,
                          {"t": "UBindok", "mac": HOST_MAC, "roomId": 258},
                          device_key, 0)
                    immediate = [_receive(receive, address, device_key)
                                 for _ in source["ubind_immediate_packets"]]
                    assert [inner["t"] for _, inner in immediate] == source["ubind_immediate_packets"]
                    assert [outer["msgId"] for outer, _ in immediate] == (
                        [2, 3] if index == 24 else [2]
                    )
                    for outer, _ in immediate:
                        assert _reply_header(outer) == {
                            "t": "pack", "i": 0, "msgId": outer["msgId"],
                            "cid": MAC, "tcid": HOST_MAC,
                        }

                    # A completed coordinator bind gates subsequent scan unless allRange is set.
                    _send(transmit, address, {"t": "scan"}, factory_key, 1)
                    _quiet(receive)
                    _send(transmit, address, {"t": "scan", "allRange": 1}, factory_key, 1)
                    outer, online = _receive(receive, address, factory_key)
                    assert online["t"] == "UBind" and online["devkey"] == learned_key.decode("ascii")
                    assert online["mid"] == UART_PRESET_MID and online["hid"] == source["hid"]
                    assert online.get("scene") == (0 if source["scan_scene_output"] else None)
                    assert outer["i"] == 1 and outer["cid"] == MAC and outer["tcid"] == HOST_MAC

                    quiet_calls = [
                        ({"t": "ret", "r": 200}, device_key, 0),
                        ({"t": "hbok"}, factory_key, 1),
                        ({"t": "Utm", "time": "2024-02-03 04:05:06"}, device_key, 0),
                    ]
                    quiet_calls.extend([
                        ({"t": "loginInfoRes", "r": 404}, device_key, 0),
                        ({"t": "statusCheck"}, device_key, 0),
                    ])
                    quiet_calls.extend(
                        ({"t": kind}, device_key, 0)
                        for kind in ("bind", "status", "cmd", "wlan", "tm")
                    )
                    for inner_request, key, selector in quiet_calls:
                        _send(transmit, address, inner_request, key, selector)
                        _quiet(receive)

                    # Wrong channel and malformed/key/size inputs stay silent; a valid callback still recovers.
                    _send(transmit, address, {"t": "hbok"}, device_key, 0)
                    _quiet(receive)
                    transmit.sendto(b"{invalid JSON", address)
                    _quiet(receive)
                    transmit.sendto(json.dumps({
                        "t": "pack", "i": 1, "uid": 42, "cid": PEER,
                        "tcid": MAC, "pack": "!!!!",
                    }, separators=(",", ":")).encode(), address)
                    _quiet(receive)
                    oversized = json.dumps({
                        "t": "pack", "i": 1, "uid": 42, "cid": PEER,
                        "tcid": MAC, "pack": "x" * MAX_REQUEST,
                    }, separators=(",", ":")).encode()
                    assert len(oversized) > MAX_REQUEST
                    transmit.sendto(oversized, address)
                    _quiet(receive)
                    _send(transmit, address, {"t": "binCmd"}, device_key, 0)
                    outer, recovered = _receive(receive, address, device_key)
                    assert recovered == FIXTURE["ordinary_ack"]
                    assert outer["i"] == 0 and outer["cid"] == MAC
                else:
                    _send(transmit, address, {"t": "binCmd"}, device_key, 0)
                    _, recovered = _receive(receive, address, device_key)
                    assert recovered == FIXTURE["ordinary_ack"]
            finally:
                transmit.close()
                receive.close()
