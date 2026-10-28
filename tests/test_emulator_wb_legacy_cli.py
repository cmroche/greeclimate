"""Source-qualified V1.04/V1.10 ECB and V1.45 GCM real CLI acceptance."""
import asyncio
import base64
import json
from pathlib import Path
import socket

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import pytest

from greeclimate.cipher import CipherV1, CipherV2
from greeclimate.device import Device
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.network import Response

from tests.test_emulator_firmware_cli import (
    AAD, ECB_KEY, GCM_KEY, NONCE, Peer, cli_server, packet, unpack,
)


FIXTURES = Path(__file__).parent / "fixtures/emulator"
MAC = "020000000001"
CASES = (
    ("1.04", "bc7c2add630e86d938995cc3dd0d1a8094025b15a9b4f5627c302d9fbed4c756"),
    ("1.10", "caa7f0ac2ba63b7ecd4aef0073ba5d21b2f06b53f2b13ae04d8f2948b07a766e"),
    ("1.45", "2f12c03c97e4e7302acbc8ee72cda18e31e7d9843519d5a3fb1bdcb1a4f2ffec"),
)


class SourcePeer(Peer):
    def __init__(self, sock, address, version):
        super().__init__(sock, address, {})
        self.version = version
        self.gcm = version == "1.45"
        self.generic = GCM_KEY if self.gcm else ECB_KEY
        self.key = None

    def wire(self, inner=None, *, literal=None, index=0, key=None, target=MAC):
        selected = key if key is not None else self.generic if index else self.key
        outer = {"t": "pack", "i": index, "uid": 42, "cid": "app", "tcid": target}
        if literal is None:
            return packet(outer, inner, selected, gcm=self.gcm)
        if self.gcm:
            cipher = AES.new(selected, AES.MODE_GCM, nonce=NONCE)
            cipher.update(AAD)
            encrypted, tag = cipher.encrypt_and_digest(literal)
            outer["tag"] = base64.b64encode(tag).decode()
        else:
            encrypted = AES.new(selected, AES.MODE_ECB).encrypt(pad(literal, 16))
        outer["pack"] = base64.b64encode(encrypted).decode()
        return json.dumps(outer).encode()

    def exchange(self, inner=None, *, literal=None, index=0):
        self.sock.sendto(self.wire(inner, literal=literal, index=index), self.address)
        selected = self.generic if index else self.key
        envelope, response = unpack(self.receive(), selected, gcm=self.gcm)
        assert {name: value for name, value in envelope.items() if name not in ("pack", "tag")} == {
            "t": "pack", "i": index, "uid": 42, "cid": MAC, "tcid": "app"}
        return response

    def bind_session(self, index=1, mac=MAC):
        response = self.exchange({"t": "bind", "mac": mac}, index=index)
        assert {name: value for name, value in response.items() if name != "key"} == {
            "r": 200, "t": "bindok", "mac": MAC}
        key = response["key"].encode("ascii")
        assert len(key) == 16
        if self.key is not None:
            assert key == self.key
        self.key = key

    def status(self, names):
        response = self.exchange({"t": "status", "mac": MAC, "cols": names})
        assert response["t"] == "dat" and response["r"] == 200
        assert response["cols"] == names
        return response["dat"]

    def discover(self):
        self.sock.sendto(b'{"t":"scan"}', self.address)
        envelope, advertised = unpack(self.receive())
        assert {name: value for name, value in envelope.items() if name != "pack"} == {
            "t": "pack", "i": 1, "uid": 0, "cid": "", "tcid": ""}
        assert (advertised["t"], advertised["mac"], advertised["mid"]) == ("dev", MAC, "10001")
        if self.version in ("1.04", "1.10"):
            source = json.loads((FIXTURES / f"wb-rt13-v{self.version.replace('.', '')}-source_research.json").read_text())
            assert "hid" not in advertised
            assert advertised["ver"] == "V" + self.version
            assert set(advertised) == set(source["scan_fields"]) | {"t"}
            assert advertised["bc"] == ""
        else:
            assert advertised["hid"] == "362001065279+U-WB05RT13V1.45.bin"
        return advertised


@pytest.mark.parametrize("version,source_sha256", CASES, ids=[row[0] for row in CASES])
async def test_new_rt13_actual_cli_fields_operations_numeric_tokens_and_restart(version, source_sha256):
    profile = "sim-wb05rt13-v" + version
    namespace = json.loads((FIXTURES / f"wb-rt13-v{version.replace('.', '')}-fields_research.json").read_text())
    assert namespace["source"]["sha256"] == source_sha256
    names = list(dict.fromkeys(filter(None, namespace["numeric_slots"])))
    if "metadata_overrides" in namespace:
        local = {row["name"] for row in namespace["metadata_overrides"]["local_callback_comparison_keys"]}
        classifier = {row["name"] for row in namespace["metadata_overrides"]["classifier_names"]}
        write_only = sorted((set(names) & local) - classifier)
    else:
        local = set(namespace["local_callback_names"])
        classifier = set()
        write_only = namespace["raw_write_only_names"]
    raw_names = [name for name in names if name not in local | classifier]
    assert len(namespace["numeric_slots"]) == 495
    assert len(raw_names) == {"1.04": 278, "1.10": 283, "1.45": 288}[version]
    records = [{"id": "office", "profile": profile, "mid": "10001", "mac": MAC,
                "name": "Emulator Office", "room_c": 26, "ambient_c": 26}]
    with cli_server(records) as (address, identities), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        peer = SourcePeer(sock, address, version)
        advertised = peer.discover()
        peer.bind_session()
        first_key = peer.key
        assert peer.status(["mid", "Pow", "SetTem"]) == ["", 0, 24]
        assert peer.status(["hid"]) == [f"362001065279+U-WB05RT13V{version}.bin"]
        acknowledgement = peer.exchange({"t": "cmd", "opt": ["Pow", "SetTem"], "p": [-1, 65537]})
        assert acknowledgement == {"t": "res", "mac": MAC, "opt": ["Pow", "SetTem"], "p": [-1, 65537], "r": 200}
        assert peer.status(["Pow", "SetTem"]) == [65535, 1]
        for lexeme in (b"1.9", b"1e3"):
            response = peer.exchange(literal=b'{"t":"cmd","opt":["Pow"],"p":[' + lexeme + b']}')
            assert response["p"] == [1]
            assert peer.status(["Pow"]) == [1]
        for literal in (
            b'{"t":"cmd","opt":["Pow"],"p":[true]}',
            b'{"t":"cmd","opt":["Pow","SetTem"],"p":[7e3,2]}',
            b'{"t":"cmd","opt":["Pow"],"p":[0],"p":[1]}',
        ):
            peer.quiet(peer.wire(literal=literal))
            assert peer.status(["Pow", "SetTem"]) == [1, 1]
        command = {"t": "cmd", "opt": ["Pow"], "p": [0]}
        for malformed in (
            peer.wire(command, key=b"xxxxxxxxxxxxxxxx"),
            peer.wire(command, target="020000000002"),
            peer.wire(dict(command, mac="020000000002")),
            peer.wire(dict(command, sub="020000000002")),
            b"{invalid JSON",
        ):
            peer.quiet(malformed)
            assert peer.status(["Pow", "SetTem"]) == [1, 1]
        wrong_codec = packet({"t": "pack", "i": 1, "uid": 42, "cid": "app", "tcid": MAC},
                             {"t": "bind", "mac": MAC}, ECB_KEY if peer.gcm else GCM_KEY,
                             gcm=not peer.gcm)
        peer.quiet(wrong_codec)
        assert peer.status(["Pow"]) == [1]
        peer.bind_session(mac=["invalid"])
        peer.bind_session(index=0)
        assert peer.status(["Pow"]) == [1]
        response = peer.exchange({"t": "status", "opt": ["time", "Pow"],
                                  "p": ["2024-01-02 03:04:05", 8]})
        assert response["dat"] == ["2024-01-02 03:04:05", 8]
        assert peer.status(["Pow"]) == [8]
        response = peer.exchange({"t": "cmd", "opt": ["ReportClientID"], "p": ["room-1"]})
        assert response["opt"] == ["ReportClientID"] and response["p"] == []
        getter = peer.exchange({"t": "status", "cols": ["ReportClientID"]})
        assert getter["cols"] == getter["dat"] == []
        if version == "1.04":
            empty_getter = peer.exchange({"t": "status", "cols": ["MOta", "Pow"]})
            assert empty_getter["cols"] == ["MOta", "Pow"] and empty_getter["dat"] == [8]
            peer.quiet(peer.wire({"t": "cmd", "cols": ["MOta"]}))
        timer = {"id": 3, "name": "native", "enable": 1, "tz": 0, "hr": 19,
                 "min": 30, "sec": 45, "week": [1, 0, 1, 0, 0, 0, 0],
                 "cmd": [{"opt": ["Pow"], "p": [1]}]}
        assert peer.exchange({"t": "setT", **timer}) == {"t": "resT", "r": 200}
        expected_row = {"id": 3, "enable": 1, "week": timer["week"], "hr": 19, "min": 30, "sec": 45,
                        "cmd": {"mac": [MAC], "opt": ["Pow"], "p": [1]}}
        if version != "1.04":
            expected_row["name"] = "native"
        assert peer.exchange({"t": "queryT", "index": 3, "count": 1}) == {
            "t": "listT", "total": 1, "index": 3, "list": [expected_row]}
        assert peer.exchange({"t": "queryT", "index": 0, "count": 1})["list"] == []
        updated = dict(timer, name="updated", enable=0, sec=12, cmd=[{"opt": ["Pow"], "p": [0]}])
        assert peer.exchange({"t": "updateT", **updated}) == {"t": "resT", "r": 200}
        expected_row.update(enable=0, sec=12)
        expected_row["cmd"]["p"] = [0]
        if version != "1.04":
            expected_row["name"] = "updated"
        assert peer.exchange({"t": "queryT", "index": 3, "count": 1})["list"] == [expected_row]
        assert peer.exchange({"t": "deleteT", "id": 259}) == {"t": "resT", "r": 200}
        assert peer.exchange({"t": "queryT", "index": 0, "count": 10})["list"] == []
        assert peer.exchange({"t": "dump", "period": 2, "cnt": 0}) == {"t": "ret", "r": 200}
        assert peer.exchange({"t": "upgrade", "url": "https://example.invalid/fw.bin"}) == {"t": "ret", "r": 200}
        if peer.gcm:
            peer.quiet(peer.wire({"t": "freqCount", "opt": ["SendFreq", "FreqTime", "DRTime"],
                                  "p": [1, 30, 60]}))
            peer.quiet(peer.wire({"t": "ReportCtrl", "ActiveTime": 7, "ReportInterval": 13,
                                  "reportAnyway": True}))
            frame = base64.b64encode(bytes.fromhex("7e7e0601020304af")).decode()
            assert peer.exchange({"t": "binCmd", "hex01": frame, "ReportClientID": "room-1", "ReportFreq": 255}) == {
                "t": "res", "r": 200}
            assert peer.exchange({"t": "binCmd", "hex15": frame}) == {"t": "res", "r": 200}
            peer.quiet(peer.wire({"t": "reset", "mac": MAC}))
            assert peer.exchange({"t": "reset", "mac": "020000000099"}) == {}
            peer.quiet(peer.wire({"t": "Ackup"}))
        assert peer.status(["Pow", "SetTem"]) == [8, 1]
        for offset in range(0, len(raw_names), 8):
            selected = raw_names[offset:offset + 8]
            for requested, stored in ((511, 511), (-1, 65535)):
                values = [requested] * len(selected)
                assert peer.exchange({"t": "cmd", "opt": selected, "p": values}) == {
                    "t": "res", "mac": MAC, "opt": selected, "p": values, "r": 200}
                assert peer.status(selected) == [stored] * len(selected)
        for name in write_only:
            assert peer.exchange({"t": "cmd", "opt": [name], "p": [65537]})["p"] == [65537]
            assert peer.status([name]) == [""]
        if version == "1.04":
            absent = ["CpsTem", "DFPoint", "EnergyFlow", "EnvTem", "FaultDisplay", "TemsSenOut"]
            response = peer.exchange({"t": "status", "cols": absent})
            assert response["cols"] == response["dat"] == []
            for name in absent:
                peer.quiet(peer.wire({"t": "cmd", "opt": [name], "p": [7]}))
        client = Device(DeviceInfo(address[0], address[1], MAC, "Emulator Office", mid="10001"),
                        timeout=2, bind_timeout=1)
        data, results = asyncio.Queue(), asyncio.Queue()
        client.add_handler(Response.DATA, data.put_nowait)
        client.add_handler(Response.RESULT, results.put_nowait)
        try:
            await client.bind(cipher=CipherV2() if peer.gcm else CipherV1())
            assert client.device_cipher.key == first_key.decode("ascii")
            await asyncio.wait_for(data.get(), 2)  # Drain bind's automatic initial status.
            assert data.empty()
            await client.update_state(columns=["Pow", "SetTem"])
            assert await asyncio.wait_for(data.get(), 2) == {"Pow": 65535, "SetTem": 65535}
            assert [client.raw_properties[name] for name in ("Pow", "SetTem")] == [65535, 65535]
            client.set_property("Pow", 65537)
            await client.push_state_update()
            assert await asyncio.wait_for(results.get(), 2) == {"Pow": 65537}
            assert client.raw_properties["Pow"] == 65537  # Native ACK echoes the request, not storage.
            await client.update_state(columns=["Pow", "SetTem"])
            assert await asyncio.wait_for(data.get(), 2) == {"Pow": 1, "SetTem": 65535}
            assert [client.raw_properties[name] for name in ("Pow", "SetTem")] == [1, 65535]
            ragged = peer.exchange({"t": "status", "cols": ["Pow", "DevID"]})
            assert ragged["cols"] == ["Pow", "DevID"] and ragged["dat"] == [1]
            prior = dict(client.raw_properties)
            await client.update_state(columns=["Pow", "DevID"])
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(data.get(), 0.2)
            assert client.raw_properties == prior
        finally:
            client.close()
        assert peer.status(["Pow", "SetTem"]) == [1, 65535]
        first_identity = {name: identities["office"][name] for name in ("id", "mac", "mid", "profile", "name")}
    with cli_server(records) as (address, identities), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        restarted = SourcePeer(sock, address, version)
        assert restarted.discover() == advertised
        restarted.bind_session()
        assert restarted.key == first_key
        assert restarted.status(["mid", "Pow", "SetTem"]) == ["", 0, 24]
        assert {name: identities["office"][name] for name in first_identity} == first_identity
