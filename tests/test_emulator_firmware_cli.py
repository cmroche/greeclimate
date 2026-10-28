"""Consumer-side subprocess regressions, with independent ECB/GCM peers."""

import asyncio
import base64
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import select
import signal
import struct
import socket
import subprocess
import sys
import tempfile
from time import monotonic

import pytest

from gree_emulator.profiles import PROFILES
from greeclimate.cipher import CipherV1, CipherV2
from greeclimate.device import Device
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.exceptions import DeviceNotBoundError, DeviceTimeoutError
from greeclimate.gateway import GatewayDevice
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


REPO = Path(__file__).resolve().parents[1]
ECB_KEY = b"a3K8Bx%2r8Y7#xDh"
GCM_KEY = b"{yxAHAY_Lm6pbC/<"
NONCE = bytes.fromhex("5440784449675a516c5e6313")
AAD = b"qualcomm-test"
W06_IDS = tuple("sim-w06av-" + version for version in (
    "v7", "v16", "v16-eu", "v16-kf", "v20", "v30",
))
WB_IDS = tuple("sim-wb05br-v1." + version for version in ("13", "16", "18", "22", "31", "38"))
RT_IDS = tuple("sim-wb05rt13-v" + version for version in ("1.54", "1.64", "1.57", "1.54-c9e8d4b563f7"))
GCM_SOURCE_IDS = frozenset(RT_IDS + (
    "sim-wb05rt13-v1.45", "sim-wb05df13-v2.01-10001",
    "sim-wb05ur-v1.05-10001", "sim-wb65vr-v1.02-11f00",
    "sim-wb65vr-v2.10-10001", "sim-wb65vr-v2.11-10001", "sim-wb65vr-v1.05-10001",
    "sim-middle-wb-841d662c-10001", "sim-middle-wb-5f14dd18-10001",
    "sim-middle-wb-e8068e53-10001",
))
ROOT_IDS = W06_IDS + WB_IDS + RT_IDS

# Roots using different native transports/topologies have dedicated raw-peer
# acceptance below or in the controller/MF4 suites; do not force them through
# Device.bind's ordinary encrypted JSON contract.
PUBLIC_CLIENT_FAMILIES = frozenset({
    "w04", "w04n", "w05z", "wb", "hb", "commercial", "controller", "gateway",
    "wb_gateway", "wb_rt13", "wb_rt13_v104", "wb_rt13_v110", "wb_remaining", "voice",
    "realtek_controller", "hi3861", "wb_adr", "atw", "catalog_early_frvr",
    "catalog_early_small", "catalog_early_hybrid", "catalog_early_scalar",
    "catalog_realtek_late", "catalog_realtek_middle", "catalog_realtek_middle_ar",
    "catalog_realtek_middle_wb", "catalog_esp", "catalog_esp_alarm", "catalog_esp_radar",
    "catalog_hydronic", "catalog_legacy_direct", "catalog_mtk", "catalog_late_wb65",
    "catalog_realtek_third_bl", "catalog_realtek_third_companions",
    "catalog_realtek_third_numeric", "catalog_realtek_third_w04", "catalog_early_w05j",
})
SOURCE_SPECIFIC_CLIENT_FAMILIES = frozenset({
    "catalog_cv", "zones", "central", "catalog_zts", "catalog_tg_apj",
    "catalog_late_wb05crt", "catalog_realtek_middle_wb_mf4",
    "catalog_realtek_middle_wb_legacy", "catalog_realtek_third_tables",
})
FIXED_PORT_PROFILE_IDS = frozenset(
    row["id"]
    for row in json.loads(
        (REPO / "tests/fixtures/emulator/catalog-realtek-middle-ar_research.json").read_text()
    )["profiles"]
    if row["peer_source_port"] is not None
)

DRA_PROFILE_ID = json.loads(
    (REPO / "tests/fixtures/emulator/catalog-wb-remaining_research.json").read_text()
)["dra"]["profile"]
FIXED_PORT_PROFILE_IDS = FIXED_PORT_PROFILE_IDS | {DRA_PROFILE_ID}
PUBLIC_GATEWAY_CODES = {
    "362001061433", "362001061437", "362001065634", "362001066326",
    "362001066380", "362001067012", "362001067524",
}


def source_identity_literals():
    documentation = (REPO / "docs/HIDS.md").read_text()
    literals = {
        html or inline
        for html, inline in re.findall(r"<code>([^<]+)</code>|`([^`]+)`", documentation)
    }

    def collect(value):
        if isinstance(value, str):
            literals.add(value)
        elif isinstance(value, list):
            for item in value:
                collect(item)
        elif isinstance(value, dict):
            for item in value.values():
                collect(item)

    for path in (REPO / "tests/fixtures/emulator").rglob("*.json"):
        collect(json.loads(path.read_text()))
    return literals


FIRMWARE_IDENTITY_LITERALS = source_identity_literals()
AV_EMPTY_STATUS_HID_PROFILES = frozenset(json.loads(
    (REPO / "tests/fixtures/emulator/catalog-av-schedules_research.json").read_text()
)["empty_status_hid_profiles"])
W06_HIDS = (
    "362001061433+U-W06AV7.bin",
    "362001067012+U-W06AV16.bin",
    "362001067012+U-W06AV16.bin",
    "362001067012+U-W06AV16.bin",
    "362001067012+U-W06AV20.bin",
    "362001067012+U-W06AV30.bin",
)


def source_root_hid(name):
    if name in W06_IDS:
        return W06_HIDS[W06_IDS.index(name)]
    if name in WB_IDS:
        version = name.rsplit("-v", 1)[1]
        code = "362001066326" if version in ("1.16", "1.18") else "362001066380"
        return f"{code}+U-WB05BRV{version}.bin"
    if name in RT_IDS:
        version = name.rsplit("-v", 1)[1].split("-", 1)[0]
        return f"362001065279+U-WB05RT13V{version}.bin"
    raise AssertionError(f"no source identity case for {name}")


def cli_profiles():
    result = subprocess.run(
        [sys.executable, "-m", "gree_emulator", "--list-profiles"],
        cwd=REPO, capture_output=True, timeout=10, check=True,
    )
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    profiles = {}
    for row in rows:
        profiles.setdefault(row["profile"], []).append(row)
    expected = set(ROOT_IDS) | {name + "-ac" for name in W06_IDS + WB_IDS}
    assert expected <= profiles.keys(), sorted(expected - profiles.keys())
    for name in ROOT_IDS:
        assert profiles[name][0]["role"] == ("standalone" if name in RT_IDS else "gateway/container")
        expected_hid = source_root_hid(name)
        hid_code = expected_hid.split("+", 1)[0]
        assert expected_hid in FIRMWARE_IDENTITY_LITERALS or hid_code in FIRMWARE_IDENTITY_LITERALS
        assert profiles[name][0]["hid"] == expected_hid
        if name not in RT_IDS:
            assert all(row["parents"] == [name] and row["role"] == "child"
                       for row in profiles[name + "-ac"])
            assert all(row["hid"] == expected_hid for row in profiles[name + "-ac"])
    return profiles


@contextmanager
def cli_server(records):
    """Bound startup/shutdown; reap even a failed startup and check UDP release."""
    address = None
    with tempfile.TemporaryDirectory(prefix="gree-firmware-cli-") as directory, tempfile.TemporaryFile() as errors:
        config = Path(directory) / "devices.json"
        config.write_text(json.dumps({"listen": "127.0.0.1", "port": 0,
                                     "seed": "firmware-cli-consumer", "devices": records}), encoding="utf-8")
        process = subprocess.Popen(
            [sys.executable, "-m", "gree_emulator", "--config", str(config)],
            cwd=REPO, stdout=subprocess.PIPE, stderr=errors,
        )
        try:
            pending = b""
            lines = []
            deadline = monotonic() + 10
            while len(lines) < len(records) + 1:
                remaining = deadline - monotonic()
                if remaining <= 0 or not select.select([process.stdout], [], [], max(0, remaining))[0]:
                    raise AssertionError("CLI startup timed out")
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    errors.seek(0)
                    raise AssertionError("CLI startup failed: " + errors.read().decode(errors="replace"))
                pending += chunk
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    lines.append(line.decode())
            assert lines[0].startswith("Listening on 127.0.0.1:")
            address = ("127.0.0.1", int(lines[0].rsplit(":", 1)[1]))
            assert address[1] > 0
            identities = {row["id"]: row for row in map(json.loads, lines[1:])}
            assert set(identities) == {record["id"] for record in records}
            yield address, identities
        finally:
            stopped = process.poll() is None
            if stopped:
                process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            process.stdout.close()
            if address is not None:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as released:
                    released.bind(address)
            if stopped:
                assert process.returncode == 0, "CLI did not exit cleanly on Ctrl-C"


def packet(outer, inner=None, key=ECB_KEY, *, gcm=False):
    outer = dict(outer)
    if inner is not None:
        plain = json.dumps(inner, separators=(",", ":")).encode()
        if gcm:
            cipher = AES.new(key, AES.MODE_GCM, nonce=NONCE)
            cipher.update(AAD)
            encrypted, tag = cipher.encrypt_and_digest(plain)
            outer["tag"] = base64.b64encode(tag).decode()
        else:
            encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(plain, 16))
        outer["pack"] = base64.b64encode(encrypted).decode()
    return json.dumps(outer).encode()


def unpack(data, key=ECB_KEY, *, gcm=False):
    outer = json.loads(data)
    if "pack" not in outer:
        return outer, outer
    encrypted = base64.b64decode(outer["pack"], validate=True)
    if gcm:
        tag = base64.b64decode(outer["tag"], validate=True)
        assert len(tag) == 16
        cipher = AES.new(key, AES.MODE_GCM, nonce=NONCE)
        cipher.update(AAD)
        plain = cipher.decrypt_and_verify(encrypted, tag)
    else:
        assert "tag" not in outer
        plain = unpad(AES.new(key, AES.MODE_ECB).decrypt(encrypted), 16)
    return outer, json.loads(plain)


class Peer:
    def __init__(self, sock, address, identities):
        self.sock, self.address, self.identities = sock, address, identities
        self.keys = {}
        sock.settimeout(2)

    def receive(self):
        data, address = self.sock.recvfrom(65535)
        assert address == self.address
        return data

    def quiet(self, data):
        self.sock.sendto(data, self.address)
        self.sock.settimeout(0.15)
        try:
            try:
                unexpected = self.receive()
            except socket.timeout:
                return
            raise AssertionError(f"Unexpected reply to rejected packet: {unexpected!r}")
        finally:
            self.sock.settimeout(2)

    def request(self, root, kind, fields=None, *, generic=False, gcm=None):
        record = self.identities[root]
        if gcm is None:
            gcm = record["profile"] in GCM_SOURCE_IDS
        key = (GCM_KEY if gcm else ECB_KEY) if generic else self.keys[root]
        outer = {"t": "pack", "i": int(generic), "uid": 7, "cid": "cli-peer", "tcid": record["mac"]}
        inner = {"t": kind, "mac": record["mac"], **(fields or {})}
        self.sock.sendto(packet(outer, inner, key, gcm=gcm), self.address)
        envelope, reply = unpack(self.receive(), key, gcm=gcm)
        assert envelope["cid"] == record["mac"]
        assert envelope["tcid"] == "cli-peer"
        assert (envelope["i"], envelope["uid"]) == (int(generic), 7)
        return reply

    def bind(self, root):
        reply = self.request(root, "bind", generic=True)
        assert reply["t"].lower() == "bindok" and reply["r"] == 200
        assert reply["mac"] == self.identities[root]["mac"]
        self.keys[root] = reply["key"].encode("ascii")
        assert len(self.keys[root]) == 16

    def status(self, root, target, expected=None, *, columns=None, generic=False):
        columns = columns or ["Pow", "Mod", "SetTem"]
        reply = self.request(root, "status", {"mac": self.identities[target]["mac"], "cols": columns}, generic=generic)
        assert reply["t"] == "dat" and reply["r"] == 200
        assert reply["mac"] == self.identities[target]["mac"]
        assert reply["cols"] == columns
        if expected is not None:
            assert reply["dat"] == expected
        return reply["dat"]


def configuration(profiles, names, *, seven=False):
    records = []
    for name in names:
        records.append({"id": name, "profile": name, "mid": profiles[name][0]["mid"]})
        if name not in RT_IDS:
            for index in range(7 if seven else 2):
                records.append({"id": f"{name}-child-{index}", "profile": name + "-ac",
                                "mid": profiles[name + "-ac"][0]["mid"], "parent": name})
    return records


def exercise(records, *, pages=False):
    """Exercise the literal W06/WB/RT13 cross-family transport cases."""
    with cli_server(records) as (address, identities), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        peer = Peer(sock, address, identities)
        roots = [record for record in records if "parent" not in record]
        peer.sock.sendto(b'{"t":"scan"}', address)
        advertisements = {}
        for _ in roots:
            envelope, reply = unpack(peer.receive())
            assert reply["t"] == "dev"
            advertisements[reply["mac"]] = reply
        assert set(advertisements) == {identities[record["id"]]["mac"] for record in roots}
        for record in roots:
            root, name = record["id"], record["profile"]
            advert = advertisements[identities[root]["mac"]]
            assert advert["mid"] == record["mid"]
            expected_hid = source_root_hid(name)
            if name in WB_IDS:
                assert "hid" not in advert and "brand" not in advert
            elif name in W06_IDS[:4]:
                assert "hid" not in advert
            else:
                assert advert["hid"] == expected_hid
            peer.bind(root)
            status_hid = "" if name in AV_EMPTY_STATUS_HID_PROFILES else expected_hid
            peer.status(root, root, [status_hid], columns=["hid"])
        assert len(set(peer.keys.values())) == len(roots)
        peer.quiet(b"\xff")
        for record in roots:
            root, name = record["id"], record["profile"]
            children = [child["id"] for child in records if child.get("parent") == root]
            initial = [0, 1 if name in WB_IDS else 0, 24]
            if children:
                for offset in ((0, 5) if pages else (0,)):
                    reply = peer.request(root, "subDev", {"i": offset})
                    assert (reply["t"], reply["r"], reply["i"], reply["c"]) == ("subList", 200, offset, len(children))
                    assert [row["mac"] for row in reply["list"]] == [
                        identities[child]["mac"] for child in children[offset:offset + 5]]
                if name in WB_IDS:
                    for generic in (False, True):
                        key = ECB_KEY if generic else peer.keys[root]
                        peer.sock.sendto(packet({
                            "t": "subList", "i": int(generic), "uid": 7,
                            "cid": "cli-peer", "tcid": identities[root]["mac"],
                        }), address)
                        envelope, plain_list = unpack(peer.receive(), key)
                        assert envelope["i"] == int(generic)
                        assert (envelope["cid"], envelope["tcid"]) == (identities[root]["mac"], "cli-peer")
                        offset = int(generic)
                        assert (plain_list["t"], plain_list["r"], plain_list["i"], plain_list["c"]) == (
                            "subList", 200, offset, len(children))
                        assert [row["mac"] for row in plain_list["list"]] == [
                            identities[child]["mac"] for child in children[offset:offset + 5]]
                    generic_list = peer.request(root, "subDev", {"i": 5}, generic=True)
                    assert generic_list["i"] == 5 and generic_list["c"] == len(children)
                    assert [row["mac"] for row in generic_list["list"]] == [
                        identities[child]["mac"] for child in children[5:10]]
                target = children[0]
            else:
                target = root
                assert name in RT_IDS
                assert advertisements[identities[root]["mac"]]["hid"] == source_root_hid(name)
                peer.status(root, target, [0, 0, 24], generic=True)
                peer.quiet(packet({"t": "pack", "i": 1, "uid": 7, "cid": "cli-peer", "tcid": identities[root]["mac"]},
                                  {"t": "bind", "mac": identities[root]["mac"]}))
            peer.status(root, target, initial)
            other_key = next((key for parent, key in peer.keys.items() if parent != root), None)
            if other_key is not None:
                peer.quiet(packet(
                    {"t": "pack", "i": 0, "uid": 7, "cid": "cli-peer", "tcid": identities[root]["mac"]},
                    {"t": "cmd", "mac": identities[root]["mac"], "sub": identities[target]["mac"],
                     "opt": ["Pow"], "p": [0]}, other_key, gcm=name in RT_IDS,
                ))
            command = peer.request(root, "cmd", {
                "sub": identities[target]["mac"], "opt": ["Pow", "Mod", "SetTem"], "p": [1, 1, 22]})
            assert command["t"] == "res" and command["r"] == 200
            peer.status(root, target, [1, 1, 22])
            for child in children[1:]:
                peer.status(root, child, initial)
            peer.quiet(b'{"t":"pack","pack":"not base64","tcid":' + json.dumps(identities[root]["mac"]).encode() + b'}')
            if name in RT_IDS:
                bad = json.loads(packet({"t": "pack", "i": 0, "uid": 7, "cid": "cli-peer", "tcid": identities[root]["mac"]},
                                        {"t": "cmd", "opt": ["Pow"], "p": [0]}, peer.keys[root], gcm=True))
                tag = bytearray(base64.b64decode(bad["tag"], validate=True))
                tag[0] ^= 1
                bad["tag"] = base64.b64encode(tag).decode()
                peer.quiet(json.dumps(bad).encode())
            peer.status(root, target, [1, 1, 22])
            foreign = next((child for child in records
                            if child.get("parent") not in (None, root)), None)
            if children and foreign is not None:
                peer.quiet(packet(
                    {"t": "pack", "i": 0, "uid": 7, "cid": "cli-peer", "tcid": identities[root]["mac"]},
                    {"t": "cmd", "mac": identities[root]["mac"], "sub": identities[foreign["id"]]["mac"],
                     "opt": ["Pow"], "p": [0]}, peer.keys[root],
                ))
                peer.status(root, target, [1, 1, 22])
        for record in roots:
            root = record["id"]
            children = [child["id"] for child in records if child.get("parent") == root]
            peer.status(root, children[0] if children else root, [1, 1, 22])
            for child in children[1:]:
                peer.status(root, child, [0, 1 if record["profile"] in WB_IDS else 0, 24])
        return identities, peer.keys.copy()


def test_actual_cli_lists_all_firmware_and_keeps_cross_family_routes_separate():
    profiles = cli_profiles()
    records = configuration(profiles, [W06_IDS[0], WB_IDS[-1], RT_IDS[1]])
    exercise(records)


def test_actual_cli_stable_seed_survives_restart_and_declaration_reorder():
    profiles = cli_profiles()
    records = configuration(profiles, [W06_IDS[0], W06_IDS[-1]])
    first, keys = exercise(records)
    second, restarted_keys = exercise(list(reversed(records)))
    assert first == second
    assert keys == restarted_keys

def catalog_cli_cases():
    families = {
        profile.handler.__class__.__module__.rsplit(".", 1)[-1]
        for profile in PROFILES.values()
    }
    assert families <= PUBLIC_CLIENT_FAMILIES | SOURCE_SPECIFIC_CLIENT_FAMILIES
    return [
        pytest.param(profile.id, id=profile.id)
        for profile in PROFILES.values()
        if profile.handler.__class__.__module__.rsplit(".", 1)[-1] in PUBLIC_CLIENT_FAMILIES
        and profile.id not in FIXED_PORT_PROFILE_IDS
        and (
            not profile.parent_profiles
            or PROFILES[profile.parent_profiles[0]].handler.__class__.__module__.rsplit(".", 1)[-1]
            in PUBLIC_CLIENT_FAMILIES
        )
    ]


@pytest.mark.parametrize("profile_id", catalog_cli_cases())
async def test_registered_model_actual_cli_and_unmodified_client(profile_id):
    profile = PROFILES[profile_id]
    root = PROFILES[profile.parent_profiles[0]] if profile.parent_profiles else profile
    records = [{"id": "root", "profile": root.id, "mid": root.mids[0]}]
    if profile.parent_profiles:
        records.append({"id": "child", "profile": profile.id, "mid": profile.mids[0], "parent": "root"})
    if root.id.startswith("sim-wb04brt13-"):
        records[0]["mac"] = "020000000001"
        if profile.parent_profiles:
            records[1]["mac"] = "02000000000100"
        elif root.max_children:
            child_profile = next(candidate for candidate in PROFILES.values()
                                 if root.id in candidate.parent_profiles)
            records.append({"id": "appliance", "profile": child_profile.id, "mid": child_profile.mids[0],
                            "parent": "root", "mac": "02000000000100"})

    expected_hid = root.hid
    assert expected_hid in FIRMWARE_IDENTITY_LITERALS, (
        f"{profile_id}: missing independent HID literal {expected_hid!r}")
    if profile_id in AV_EMPTY_STATUS_HID_PROFILES:
        expected_hid = ""
    with cli_server(records) as (address, identities), socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        mac = identities["root"]["mac"]
        gcm = root.id in GCM_SOURCE_IDS
        generic = GCM_KEY if gcm else ECB_KEY

        def request(inner, key, selector=0):
            envelope = {"t": "pack", "i": selector, "uid": 7, "cid": "app", "tcid": mac}
            sock.sendto(packet(envelope, inner, key, gcm=gcm), address)
            data, sender = sock.recvfrom(65535)
            assert sender == address
            return unpack(data, key, gcm=gcm)[1]

        bound = request({"t": "bind", "mac": mac}, generic, selector=1)
        assert (bound["t"].casefold(), bound["r"], bound["mac"]) == ("bindok", 200, mac)
        key = bound["key"].encode("ascii")
        assert len(key) == 16
        sock.sendto(b"{invalid JSON", address)
        metadata = request({"t": "status", "mac": mac, "cols": ["hid"]}, key)
        assert (metadata["t"], metadata["cols"], metadata["dat"]) == (
            "dat", ["hid"], [expected_hid])
        if profile.parent_profiles:
            child_mac = identities["child"]["mac"]
            if root.id.startswith("sim-wb05br-"):
                fresh = request({"t": "status", "mac": child_mac, "cols": ["Pow"]}, key)
                assert fresh["cols"] == ["Pow"]
                expected_child_pow = "" if profile.id.endswith(("-water", "-energy")) else 0
                assert fresh["dat"] == [expected_child_pow]

        client_type = GatewayDevice if profile.parent_profiles else Device
        client = client_type(
            DeviceInfo(address[0], address[1], mac, "CLI acceptance", mid=root.mids[0]),
            timeout=2, bind_timeout=1,
        )
        try:
            await client.bind(cipher=CipherV2() if gcm else CipherV1())
            assert client.device_cipher.key == key.decode("ascii")
            client._valid_state.clear()
            await client.update_state(columns=["hid"])
            await asyncio.wait_for(client._valid_state.wait(), 2)
            assert client.hid == expected_hid
            if root.id in ("sim-w05g-v4.3", "sim-w05g-v4.4", "sim-w05g-v13-mesh-root"):
                client._valid_state.clear()
                await client.update_state()
                await asyncio.wait_for(client._valid_state.wait(), 2)
                expected_mesh = "000000000000" if root.id == "sim-w05g-v13-mesh-root" else 0
                assert client.get_property("Mesh") == expected_mesh
                assert client.get_property("SubOnline") == "[]"
                assert client.get_property("Onoff") == "OK"
                assert client.get_property("Scene") == "FAIL"
            elif root.id == "sim-w04r-v203-sdk-fan":
                client.set_property("WorkMode", 5)
                await client.push_state_update()
                client._valid_state.clear()
                await client.update_state()
                await asyncio.wait_for(client._valid_state.wait(), 2)
                client._valid_state.clear()
                await client.update_state(columns=["WorkMode"])
                await asyncio.wait_for(client._valid_state.wait(), 2)
                assert client.get_property("WorkMode") == 5
            if profile.parent_profiles:
                if not expected_hid or expected_hid.split("+", 1)[0] not in PUBLIC_GATEWAY_CODES:
                    with pytest.raises(ValueError, match="Unsupported gateway HID"):
                        await client.get_sub_devices()
                    return
                children = await client.get_sub_devices()
                assert len(children) == 1
                child = children[0]
                assert child.device_info.mac == child_mac
                if root.id.startswith("sim-wb05br-"):
                    child._valid_state.clear()
                    await child.update_state(columns=["Pow"])
                    await asyncio.wait_for(child._valid_state.wait(), 2)
                    assert child.raw_properties["Pow"] == expected_child_pow
        finally:
            client.close()


FINITE_TABLE_PROFILE_IDS = (
    "sim-w05m-v118-fan",
    "sim-w05m-v118-washer",
    "sim-w06t-v110-humidifier",
    "sim-w06t-v110-washer",
    "sim-w06t-v110-jd-cache-humidifier",
    "sim-w06t-v110-jd-cache-washer",
)


@pytest.mark.parametrize("profile_id", FINITE_TABLE_PROFILE_IDS)
async def test_finite_table_cli_bind_r_zero_is_rejected_by_public_client(profile_id):
    source = json.loads(
        (REPO / "tests/fixtures/emulator/catalog-realtek-third-tables-vectors_research.json").read_text()
    )
    vector = next(row for row in source["vectors"] if row["request"]["t"] == "bind")
    mac = source["mac"]
    profile = PROFILES[profile_id]
    record = {"id": "finite-table", "profile": profile_id, "mid": profile.mids[0], "mac": mac}
    with cli_server([record]) as (address, _), socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        outer = {"t": "pack", "i": 1, "uid": 7, "cid": "app", "tcid": mac}
        sock.sendto(packet(outer, vector["request"], ECB_KEY), address)
        data, sender = sock.recvfrom(65535)
        assert sender == address
        reply_outer, bound = unpack(data)
        assert (reply_outer["i"], reply_outer["uid"], reply_outer["cid"], reply_outer["tcid"]) == (
            1, 7, mac, "")
        assert bound == dict(vector["response"], key=bound["key"])
        client = Device(
            DeviceInfo(address[0], address[1], mac, "Finite-table source", mid=profile.mids[0]),
            timeout=2, bind_timeout=1,
        )
        try:
            with pytest.raises(DeviceNotBoundError):
                await client.bind(cipher=CipherV1())
        finally:
            client.close()


async def test_cv_cli_requires_root_and_source_ordered_children():
    source = json.loads((REPO / "tests/fixtures/emulator/catalog-cv_research.json").read_text())
    mac = "020000000001"
    records = [
        {"id": "root", "profile": "sim-w06c-v2", "mid": "9100",
         "name": "CV source fixture", "mac": mac},
        {"id": "water", "profile": "sim-w06c-v2-910001", "mid": "910001",
         "parent": "root", "name": "GreeHot", "mac": mac + "01"},
        {"id": "ac", "profile": "sim-w06c-v2-910002", "mid": "910002",
         "parent": "root", "name": "GreeAc", "mac": mac + "02"},
        {"id": "heat", "profile": "sim-w06c-v2-910003", "mid": "910003",
         "parent": "root", "name": "GreeHeat", "mac": mac + "03"},
    ]
    with cli_server(records) as (address, identities), socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM) as sock:
        peer = Peer(sock, address, identities)
        peer.sock.sendto(b'{"t":"scan"}', address)
        advertisement = unpack(peer.receive())[1]
        assert (advertisement["t"], advertisement["mac"], advertisement["mid"],
                advertisement["subCnt"]) == ("dev", mac, "9100", 3)
        assert "hid" not in advertisement

        peer.bind("root")
        assert peer.request("root", "subDev", {"i": 0}) == source["subList"]
        vector = source["command_vector"]
        reply = peer.request("root", "cmd", {
            "sub": identities["water"]["mac"], "opt": vector["names"],
            "p": vector["requested"],
        })
        assert (reply["t"], reply["r"], reply["mac"], reply["opt"],
                reply["p"], reply["val"]) == (
                    "res", 200, identities["water"]["mac"], vector["names"],
                    vector["ack_p"], vector["ack_val"])
        assert peer.status("root", "water", vector["fresh"], columns=["Pow"]) == vector["fresh"]


async def test_zones_cli_uses_valid_parent_and_slot_derived_macs():
    source = json.loads((REPO / "tests/fixtures/emulator/zones-complete_research.json").read_text())
    assert source["source_sha256"] == (
        "aae6c0782b8d2a3d7fd5c071fbd23ab292dc1d42cf864c1307df961d9305e864")
    mac = "020000000001"
    records = [
        {"id": "root", "profile": source["profile"], "mid": "50", "mac": mac},
        {"id": "master", "profile": source["profile"] + "-master", "mid": "5000",
         "parent": "root", "mac": mac + "00"},
        {"id": "one", "profile": source["profile"] + "-zone", "mid": "5001",
         "parent": "root", "mac": mac + "01"},
        {"id": "eight", "profile": source["profile"] + "-zone", "mid": "5001",
         "parent": "root", "mac": mac + "08"},
    ]
    with cli_server(records) as (address, identities), socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(b'{"t":"scan"}', address)
        outer, advertisement = unpack(sock.recvfrom(65535)[0])
        assert (outer["t"], outer["i"], outer["uid"], outer["cid"], outer["tcid"]) == (
            "pack", 1, 0, mac, "app")
        assert (advertisement["t"], advertisement["mac"], advertisement["mid"],
                advertisement["subCnt"]) == ("dev", mac, "50", 3)
        assert "hid" not in advertisement

        def exchange(kind, fields, index, key):
            outer = {"t": "pack", "i": index, "uid": 7, "cid": "app", "tcid": mac}
            inner = {"t": kind, "mac": mac, **fields}
            sock.sendto(packet(outer, inner, key), address)
            envelope, reply = unpack(sock.recvfrom(65535)[0], key)
            assert (envelope["t"], envelope["i"], envelope["uid"],
                    envelope["cid"], envelope["tcid"]) == (
                "pack", index, 7, mac, "app")
            return reply

        bound = exchange("bind", {}, 1, ECB_KEY)
        assert (bound["t"], bound["r"], bound["mac"]) == ("bindOk", 200, mac)
        key = bound["key"].encode("ascii")
        assert len(key) == 16
        assert {
            name: identities[name]["mac"] for name in ("root", "master", "one", "eight")
        } == {
            "root": mac, "master": mac + "00", "one": mac + "01", "eight": mac + "08",
        }
        children = exchange("subDev", {"i": 0}, 0, key)
        assert children == {
            "t": "subList", "r": 200, "c": 3, "i": 0,
            "list": [
                {"mac": mac + "00", "mid": "5000", "name": "zone", "model": "gree", "lock": 0},
                {"mac": mac + "01", "mid": "5001", "name": "zone", "model": "gree", "lock": 0},
                {"mac": mac + "08", "mid": "5001", "name": "zone", "model": "gree", "lock": 0},
            ],
        }
        hid = exchange("status", {"cols": ["hid"]}, 0, key)
        assert (hid["t"], hid["r"], hid["mac"], hid["cols"], hid["dat"]) == (
            "dat", 200, mac, ["hid"], ["362001062617+U-W05SAV1.28.bin"])
        one_mac = mac + "01"
        command = exchange("cmd", {"sub": one_mac, "opt": ["Pow"], "p": [1]}, 0, key)
        assert (command["t"], command["r"], command["mac"], command["opt"], command["p"]) == (
            "res", 200, one_mac, ["Pow"], [1])
        status = exchange("status", {"mac": one_mac, "cols": ["Pow"]}, 0, key)
        assert (status["t"], status["r"], status["mac"], status["cols"], status["dat"]) == (
            "dat", 200, one_mac, ["Pow"], [1])


async def _assert_public_bind_times_out(address, mac, mid):
    client = Device(
        DeviceInfo(address[0], address[1], mac, "Source-specific incompatibility", mid=mid),
        timeout=0.15, bind_timeout=0.15,
    )
    try:
        with pytest.raises(DeviceTimeoutError):
            await client.bind(cipher=CipherV1())
    finally:
        client.close()


async def test_central_cli_uses_clear_scan_and_has_no_ordinary_bind():
    source = json.loads((REPO / "tests/fixtures/emulator/session-central_research.json").read_text())
    contract = source["contract"]
    mac = "020000000001"
    record = {"id": "central", "profile": source["profile"], "mid": source["mid"], "mac": mac}
    key = contract["wire"]["default_key_ascii"].encode("ascii")
    scan = next(row for row in source["vectors"] if row["label"] == "scan_uid_persists")
    with cli_server([record]) as (address, _), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(2)
        peer.sendto(json.dumps({"t": "scan"}).encode(), address)
        outer, inner = unpack(peer.recvfrom(65535)[0], key)
        assert inner == scan["independent_decrypted"][0]
        assert (outer["t"], outer["i"], outer["uid"], outer["cid"], outer["tcid"]) == (
            "pack", 1, 0, mac, "app")

        peer.sendto(packet({"t": "pack", "i": 1, "uid": 7, "cid": "app", "tcid": mac},
                           {"t": "bind", "mac": mac}, key), address)
        peer.settimeout(0.15)
        with pytest.raises(socket.timeout):
            peer.recvfrom(65535)
        peer.settimeout(2)
        await _assert_public_bind_times_out(address, mac, source["mid"])


async def test_zts_cli_uses_msgid_ubind_and_rejects_generic_client_bind():
    vector = json.loads(
        (REPO / "tests/fixtures/emulator/catalog-zts-vectors_research.json").read_text()
    )
    record = {"id": "zts", "profile": vector["profile"], "mid": vector["mid"], "mac": vector["mac"]}

    def request(inner, selector, key):
        plain = json.dumps(inner, separators=(",", ":")).encode() + b"\n"
        encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(plain, 16))
        outer = {
            "t": "pack", "cid": "miniApp", "tcid": vector["mac"], "i": selector,
            "msgId": 37, "pack": base64.b64encode(encrypted).decode(),
        }
        return json.dumps(outer).encode()

    with cli_server([record]) as (address, _), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(0.15)
        peer.sendto(b'{"t":"scan"}', address)
        with pytest.raises(socket.timeout):
            peer.recvfrom(65535)
        peer.settimeout(2)

        peer.sendto(request(vector["miniApp_UBind"], 1, ECB_KEY), address)
        outer, bound = unpack(peer.recvfrom(65535)[0], ECB_KEY)
        expected_bound = dict(vector["miniApp_UBindok"], key=bound["key"])
        assert bound == expected_bound and len(bound["key"]) == 16
        assert (outer["msgId"], outer["i"], outer["cid"], outer["tcid"]) == (
            37, 1, vector["mac"], "miniApp")
        assert "uid" not in outer

        host_key = bound["key"].encode("ascii")
        peer.sendto(request({
            "t": "status", "mac": vector["mac"], "cols": vector["root_columns"],
        }, 0, host_key), address)
        status_outer, status = unpack(peer.recvfrom(65535)[0], host_key)
        assert status == {
            "mac": vector["mac"], "cols": vector["miniApp_root_columns"],
            "dat": vector["miniApp_root_values"], "t": "dat", "r": 200,
        }
        assert (status_outer["msgId"], status_outer["i"], status_outer["cid"],
                status_outer["tcid"]) == (37, 0, vector["mac"], "miniApp")
        await _assert_public_bind_times_out(address, vector["mac"], vector["mid"])


async def test_tg_apj_cli_uses_native_binary_discovery_not_gree_json():
    source = json.loads((REPO / "tests/fixtures/emulator/catalog-tg-apj_research.json").read_text())
    record = {"id": "apj", "profile": source["profile"], "mid": source["configured_mid"],
              "mac": source["mac"]}
    payload = b"{}"
    header = bytearray(16)
    header[:4] = bytes.fromhex(source["magic_hex"])
    struct.pack_into("<HH", header, 4, 0, len(payload))
    header[8], header[9], header[12] = 1, 1, 0
    with cli_server([record]) as (address, _), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(2)
        peer.sendto(bytes(header) + payload, address)
        response = peer.recvfrom(65535)[0]
        assert response[:4] == bytes.fromhex(source["magic_hex"])
        assert json.loads(response[16:]) == source["native_discovery_fields"]
        await _assert_public_bind_times_out(address, source["mac"], source["configured_mid"])


def fixed_port_client_cases():
    ar = json.loads(
        (REPO / "tests/fixtures/emulator/catalog-realtek-middle-ar_research.json").read_text()
    )
    remaining = json.loads(
        (REPO / "tests/fixtures/emulator/catalog-wb-remaining_research.json").read_text()
    )
    cases = [
        pytest.param(row["id"], row["emitted_mid"], row["peer_source_port"],
                     id=row["id"])
        for row in ar["profiles"] if row["peer_source_port"] is not None
    ]
    cases.append(pytest.param(remaining["dra"]["profile"], remaining["dra"]["mid"],
                              remaining["dra"]["port"], id=remaining["dra"]["profile"]))
    return cases


@pytest.mark.parametrize("profile_id,mid,source_port", fixed_port_client_cases())
async def test_unmodified_device_cannot_use_fixed_source_port_coordinators(profile_id, mid, source_port):
    assert source_port == 5001
    mac = "020000000001"
    record = {"id": "fixed-port", "profile": profile_id, "mid": mid, "mac": mac}
    with cli_server([record]) as (address, _):
        await _assert_public_bind_times_out(address, mac, mid)


def native_diagnostic_cli_cases():
    fixtures = REPO / "tests/fixtures/emulator"
    w04 = json.loads((fixtures / "catalog-realtek-third-w04_research.json").read_text())
    broadlink = json.loads((fixtures / "catalog_realtek_third_bl_research.json").read_text())
    cases = []
    for row in w04["surver_vectors"]:
        profile, = [profile for profile in PROFILES.values()
                    if profile.source_sha256 == row["source_sha256"] and row["mid"] in profile.mids]
        cases.append(pytest.param(profile.id, bytes.fromhex(row["literal_complete_reply_hex"]), id=profile.id))
    for row in broadlink["surver_native"]:
        profile = next(profile for profile in PROFILES.values()
                       if profile.handler.__class__.__module__.endswith(".catalog_realtek_third_bl")
                       and profile.handler.version == row["version"])
        cases.append(pytest.param(profile.id, row["outer_ascii"].encode(), id=profile.id))
    return cases


@pytest.mark.parametrize("profile_id,expected", native_diagnostic_cli_cases())
def test_actual_cli_preserves_literal_native_diagnostic_frames(profile_id, expected):
    profile = PROFILES[profile_id]
    mac = "020000000001"
    records = [{"id": "diagnostic", "profile": profile_id, "mid": profile.mids[0], "mac": mac}]
    with cli_server(records) as (address, _), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        outer = {"t": "pack", "i": 1, "uid": 42, "cid": "app", "tcid": mac}
        sock.settimeout(0.05)
        sock.sendto(packet(outer, {"t": "cmd", "opt": ["time"], "p": ["2026-10-24 00:00:00"]}), address)
        # Setup ACK ownership differs by source; only the source-native
        # diagnostic frame below is this test's independent expected value.
        try:
            while True:
                sock.recvfrom(65535)
        except socket.timeout:
            pass
        sock.settimeout(2)
        sock.sendto(packet(outer, {"t": "surver"}), address)
        actual, sender = sock.recvfrom(65535)
        assert sender == address
        assert actual == expected


NUMERIC_WIRE = json.loads(
    (REPO / "tests/fixtures/emulator/catalog-realtek-third-numeric-wire_research.json").read_text()
)


@pytest.mark.parametrize("row", NUMERIC_WIRE["cases"], ids=lambda row: row["build"] + "-" + row["request"]["t"])
def test_actual_cli_preserves_native_numeric_diagnostic_and_upgrade_quirks(row):
    profile_id = next(case["profile"] for case in NUMERIC_WIRE["cases"]
                      if case["build"] == row["build"] and "profile" in case)
    profile = PROFILES[profile_id]
    records = [{"id": "numeric", "profile": profile_id, "mid": profile.mids[0], "mac": NUMERIC_WIRE["mac"]}]
    with cli_server(records) as (address, _), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        outer = {"t": "pack", "i": 1, "uid": NUMERIC_WIRE["uid"], "cid": "app", "tcid": NUMERIC_WIRE["mac"]}
        sock.sendto(packet(outer, row["request"]), address)
        actual, sender = sock.recvfrom(65535)
        assert sender == address
        assert actual == json.dumps(row["outer"], separators=(",", ":")).encode() + b"\n" * row["newline_count"]


@pytest.mark.parametrize("profile_id", ["sim-w04n-v17", "sim-w04n-v19", "sim-w04n-jd-v12"])
def test_actual_cli_w04n_space_lexer_numeric_tokens_and_atomic_errors(profile_id):
    records = [{"id": "w04n", "profile": profile_id, "mid": "10001"}]
    with cli_server(records) as (address, identities), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)

        def send_literal(plaintext):
            outer = {"t": "pack", "i": 1, "uid": 37, "cid": "app", "tcid": identities["w04n"]["mac"]}
            outer["pack"] = base64.b64encode(AES.new(ECB_KEY, AES.MODE_ECB).encrypt(pad(plaintext, 16))).decode()
            sock.sendto(json.dumps(outer).encode(), address)

        send_literal(br'{"t": "cmd", "opt": ["name"], "p": ["A B\u0020C\tD"]}')
        _, acknowledgement = unpack(sock.recvfrom(65535)[0])
        assert acknowledgement["opt"] == ["name"]
        assert acknowledgement["p"] == acknowledgement["val"] == ["AB C\tD"]
        send_literal(br'{"t":"cmd","opt":["Pow"],"p":[1.5]}')
        _, numeric = unpack(sock.recvfrom(65535)[0])
        assert numeric["p"] == [1] and numeric["val"] == [1]
        send_literal(br'{"t":"cmd","opt":["Pow"],"p":[2e3]}')
        _, numeric = unpack(sock.recvfrom(65535)[0])
        assert numeric["p"] == [2] and numeric["val"] == [2]
        for values, effective in (([0, 1], 0), ([1, 0], 1)):
            send_literal(json.dumps({"t": "cmd", "opt": ["Pow", "Pow"], "p": values}).encode())
            _, duplicate = unpack(sock.recvfrom(65535)[0])
            assert duplicate["p"] == values
            assert duplicate["val"] == [effective, effective]
            send_literal(br'{"t":"status","cols":["Pow"]}')
            _, fresh = unpack(sock.recvfrom(65535)[0])
            assert fresh["dat"] == [effective]
        for token in (b"1.0", b"2147483650"):
            send_literal(br'{"t":"cmd","opt":["lock"],"p":[1]}')
            _, locked = unpack(sock.recvfrom(65535)[0])
            assert locked["p"] == locked["val"] == [1]
            send_literal(b'{"t":"cmd","opt":["lock"],"p":[' + token + b"]}")
            _, unlocked = unpack(sock.recvfrom(65535)[0])
            assert unlocked["p"] == unlocked["val"] == [0]
            send_literal(br'{"t":"status","cols":["lock","Pow"]}')
            _, fresh = unpack(sock.recvfrom(65535)[0])
            assert fresh["dat"] == [0, 1]
        send_literal(br'{"t":"status","cols":["P ow","P\u0020ow","Po\u0077","Po\tw","name"]}')
        _, fresh = unpack(sock.recvfrom(65535)[0])
        assert fresh["cols"] == ["Pow", "Pow", "name"]
        assert fresh["dat"] == [1, 1, "AB C\tD"]
        for malformed in (
            br'{"t":"cmd","opt":["Pow"],"p":[1],"p":[0]}',
            br'{"t":"cmd","opt":["Pow"],"p":[1],"\u0070":[0]}',
            br'{"t":"cmd","opt":["Pow"],"p":[1],"p ":[0]}',
            br'{"t":"cmd","opt":["Pow"],"p":[true]}',
            br'{"t":"cmd","opt":["Pow"],"p":[1]',
        ):
            send_literal(malformed)
            sock.settimeout(0.15)
            with pytest.raises(socket.timeout):
                sock.recvfrom(65535)
            sock.settimeout(2)
            send_literal(br'{"t":"status","cols":["Pow","name"]}')
            _, fresh = unpack(sock.recvfrom(65535)[0])
            assert fresh["dat"] == [1, "AB C\tD"]


def original_wb_property_cli_cases():
    cases = []
    for version in ("1.13", "1.16", "1.18", "1.22", "1.31", "1.38"):
        code = "362001066326" if version in ("1.16", "1.18") else "362001066380"
        cases.append(pytest.param({
            "profile": "sim-wb05br-v" + version, "mid": "60", "kind": "gateway",
            "hid": f"{code}+U-WB05BRV{version}.bin",
            "fresh": [23, 0 if version in ("1.16", "1.18") else 1, 23, "", ""],
        }, id="wb05br-v" + version))
    commercial = json.loads((REPO / "tests/fixtures/emulator/catalog-wb-commercial_research.json").read_text())
    for source in commercial["sources"]:
        version = source["version"]
        cases.append(pytest.param({
            "profile": f"sim-wb04brt13-v{version}-3027", "mid": "3027", "kind": "raw",
            "hid": f"362001065634+U-WB04BRT13V{version}.bin",
        }, id="wb04brt13-v" + version))
    remaining = json.loads((REPO / "tests/fixtures/emulator/catalog-wb-remaining_research.json").read_text())
    for source in remaining["sources"]:
        cases.append(pytest.param({**source, "kind": "raw"}, id=source["profile"]))
    return cases


@pytest.mark.parametrize("case", original_wb_property_cli_cases())
def test_original_wb_actual_cli_discovery_controls_fresh_status_and_recovery(case):
    mac = "020000000001"
    records = [{"id": "root", "profile": case["profile"], "mid": case["mid"], "mac": mac}]
    if case["kind"] == "gateway":
        records.append({"id": "child", "profile": case["profile"] + "-ac", "mid": "608f",
                        "parent": "root", "mac": "0244668800017f"})
    with cli_server(records) as (address, _), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(b'{"t":"scan"}', address)
        _, advertisement = unpack(sock.recvfrom(65535)[0])
        assert (advertisement["t"], advertisement["mac"], advertisement["mid"]) == ("dev", mac, case["mid"])
        if case["kind"] == "gateway":
            assert "hid" not in advertisement

        def request(inner, key, index=0):
            outer = {"t": "pack", "i": index, "uid": 7, "cid": "app", "tcid": mac}
            sock.sendto(packet(outer, inner, key), address)
            data, sender = sock.recvfrom(65535)
            assert sender == address
            return unpack(data, key)[1]

        bound = request({"t": "bind", "mac": mac}, ECB_KEY, 1)
        assert bound["t"].casefold() == "bindok" and bound["r"] == 200 and bound["mac"] == mac
        key = bound["key"].encode("ascii")
        assert len(key) == 16
        assert request({"t": "status", "mac": mac, "cols": ["hid"]}, key)["dat"] == [case["hid"]]
        if case["kind"] == "gateway":
            target = records[1]["mac"]
            names, values = ["Pow", "Mod", "SetTem", "WdSpd"], [1, 4, 23, 2]
            columns, expected = ["SetTem", "Pow", "SetTem", "TemSor", "TemSen"], case["fresh"]
        else:
            target = mac
            names, values = ["Pow", "SetTem"], [-1, 74565]
            columns, expected = ["Pow", "SetTem"], [65535, 9029]
        command = request({"t": "cmd", "mac": mac, "sub": target, "opt": names, "p": values}, key)
        assert command["t"] == "res" and command["r"] == 200
        assert command["opt"] == names and command["p"] == values
        fresh = request({"t": "status", "mac": target, "cols": columns}, key)
        assert fresh["cols"] == columns and fresh["dat"] == expected
        sock.sendto(b"{invalid JSON", address)
        sock.settimeout(0.15)
        with pytest.raises(socket.timeout):
            sock.recvfrom(65535)
        sock.settimeout(2)
        recovered = request({"t": "status", "mac": target, "cols": columns}, key)
        assert recovered["cols"] == columns and recovered["dat"] == expected


def test_wb_dra_actual_cli_coordinator_port_and_fresh_metadata():
    source = json.loads(
        (REPO / "tests/fixtures/emulator/catalog-wb-remaining_research.json").read_text()
    )["dra"]
    mac = "020000000001"
    records = [{"id": "dra", "profile": source["profile"], "mid": source["mid"], "mac": mac}]
    with cli_server(records) as (address, _), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rejected:
        peer.bind(("127.0.0.1", source["port"]))
        peer.settimeout(2)

        def quiet():
            peer.settimeout(0.15)
            with pytest.raises(socket.timeout):
                peer.recvfrom(65535)
            peer.settimeout(2)

        def send(inner, key, index=0, *, sender=peer):
            sender.sendto(packet({"t": "pack", "i": index, "uid": 7, "cid": "peer", "tcid": mac},
                                 inner, key), address)

        def receive(key=ECB_KEY):
            data, sender = peer.recvfrom(65535)
            assert sender == address
            return unpack(data, key)

        rejected.sendto(b'{"t":"scan"}', address)
        quiet()
        peer.sendto(b'{"t":"scan"}', address)
        envelope, advertisement = receive()
        assert envelope["msgId"] == 1
        assert advertisement["t"] == "UBind" and advertisement["mid"] == source["mid"]
        assert advertisement["hid"] == source["hid"]
        send({"t": "bind", "mac": mac}, ECB_KEY, 1)
        _, bound = receive()
        assert bound == {"t": "blekey", "mac": mac, "Gnet": 1, "IsCP": 1, "key": advertisement["devkey"]}
        key = bound["key"].encode("ascii")

        def request(inner):
            send(inner, key)
            return receive(key)[1]

        send({"t": "metadata", "p": [257]}, key, sender=rejected)
        quiet()
        send({"t": "metadatapub"}, key)
        _, unchanged = receive(key)
        assert unchanged == {"t": "metadata", "mac": mac, "opt": ["permitStatus"], "p": [0]}
        send({"t": "metadata", "p": [257]}, key)
        quiet()
        send({"t": "metadatapub"}, key)
        _, fresh = receive(key)
        assert fresh == {"t": "metadata", "mac": mac, "opt": ["permitStatus"], "p": [1]}
        send({"t": "metadata", "p": [0]}, key, sender=rejected)
        quiet()
        peer.sendto(b"{invalid JSON", address)
        send({"t": "metadatapub"}, key)
        _, recovered = receive(key)
        assert recovered == fresh

        native = source["native_literals"]
        assert request({"t": "metadatapub"}) == fresh

        # ACKs expose the source scene transitions; UART work and stored frame bytes have no wire getter.
        expected_ack = {"t": "res", "mac": mac, "r": native["binCmd_acks"][0]}
        assert request({"t": "binCmd", "hex01": "fn4DEAAA", "roomId": 257}) == expected_ack
        assert request({"t": "binCmd", "hex01": "fn4DEAAA", "fragment": [[16, 1, 240, 2]],
                        "sceneId": 1, "operType": 1}) == expected_ack
        assert request({"t": "binCmd", "sceneId": 1, "operType": 2}) == expected_ack
        assert request({"t": "binCmd", "sceneId": 1, "operType": 1}) == {
            "t": "res", "mac": mac, "r": native["binCmd_acks"][1]}
        assert request({"t": "metadatapub"}) == fresh

        # These source callbacks are silent and their private state has no supported wire readback.
        # The source selects NRA by substring, then fetches the array from the exact NRA key.
        send({"t": "ReportLimit", "prefixCtrlFunc": "fn4DEAEC", "prefixNRA": True,
              "NRA": [[272, -1, 3.9], [1, 2, 3, 99]], "midReportInterval": -7.9}, key)
        quiet()
        send({"t": "ReportLimit", "NRA": []}, key)
        quiet()
        assert request({"t": "metadatapub"}) == fresh

        send({"t": "networkInfo", "gnetKey": "ffffffff"}, key)
        quiet()
        send({"t": "networkInfo", "prefixgnetkeysuffix": "a1b2c3d4extra"}, key)
        quiet()
        send({"t": "networkInfo", "gnetkey": "00000000"}, key)
        quiet()
        assert request({"t": "metadatapub"}) == fresh

        send({"t": "freqCount", "opt": ["prefixSendFreq", "FreqTimeSuffix", "FreqCount"],
              "p": [0, 7, 99]}, key)
        quiet()
        assert request({"t": "metadatapub"}) == fresh

        rejected.settimeout(0.15)
        with pytest.raises(socket.timeout):
            rejected.recvfrom(65535)




RT13_NAMESPACE_VECTORS = json.loads(
    (REPO / "tests/fixtures/emulator/catalog-wb-standalone_research.json").read_text()
)["sources"]


@pytest.mark.parametrize("source", [row for row in RT13_NAMESPACE_VECTORS
                                  if row["profile"] in RT_IDS], ids=lambda row: row["profile"])
async def test_rt13_actual_cli_authenticated_full_namespace_and_recovery(source):
    vector = json.loads((REPO / "tests/fixtures/emulator/wb-rt13-vectors_research.json").read_text())
    mac = "020000000001"
    version = source["profile"].rsplit("-v", 1)[1].split("-", 1)[0]
    hid = f"362001065279+U-WB05RT13V{version}.bin"
    records = [{"id": "office", "profile": source["profile"], "mid": source["mid"], "mac": mac,
                "name": vector["device"]["name"], "room_c": 26, "ambient_c": 26}]
    with cli_server(records) as (address, identities), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        peer = Peer(sock, address, identities)
        sock.sendto(b'{"t":"scan"}', address)
        envelope, advertisement = unpack(peer.receive())
        assert {name: value for name, value in envelope.items() if name != "pack"} == (
            vector["expected_replies"][0][0]["outer"])
        expected_advertisement = dict(vector["expected_replies"][0][0]["inner"], mid=source["mid"], hid=hid)
        assert advertisement == expected_advertisement
        key = None

        def request(inner, selected_key, index=0):
            outer = {"t": "pack", "i": index, "uid": 42, "cid": "app", "tcid": mac}
            sock.sendto(packet(outer, inner, selected_key, gcm=True), address)
            envelope, response = unpack(peer.receive(), selected_key, gcm=True)
            assert {name: value for name, value in envelope.items() if name not in ("pack", "tag")} == {
                "t": "pack", "i": index, "uid": 42, "cid": mac, "tcid": "app"}
            return response

        for transaction in vector["authenticated_transactions"]:
            index = transaction["selector"]
            response = request(transaction["request"], GCM_KEY if index else key, index)
            expected = dict(transaction["reply"])
            if transaction["request"]["t"] == "bind":
                if key is None:
                    key = response["key"].encode("ascii")
                    assert len(key) == 16
                expected["key"] = key.decode("ascii")
            assert response == expected
        assert request({"t": "status", "cols": ["hid"]}, key)["dat"] == [hid]
        outer = {"t": "pack", "i": 0, "uid": 42, "cid": "app", "tcid": mac}
        command = {"t": "cmd", "opt": ["Pow"], "p": [0]}
        bad_tag = json.loads(packet(outer, command, key, gcm=True))
        tag = bytearray(base64.b64decode(bad_tag["tag"]))
        tag[0] ^= 1
        bad_tag["tag"] = base64.b64encode(tag).decode()
        for malformed in (
            packet(outer, command, b"fedcba9876543210", gcm=True),
            packet(dict(outer, tcid="020000000002"), command, key, gcm=True),
            packet(outer, dict(command, mac="020000000002"), key, gcm=True),
            packet(outer, dict(command, sub="020000000002"), key, gcm=True),
            json.dumps(bad_tag).encode(),
            packet(dict(outer, i=1), {"t": "bind", "mac": mac}),
            b"{invalid JSON",
        ):
            peer.quiet(malformed)
            assert request({"t": "status", "cols": ["Pow", "SetTem"]}, key)["dat"] == [1, 22]
        for offset in range(0, len(source["raw_names"]), 8):
            names = source["raw_names"][offset:offset + 8]
            for requested, stored in (
                (source["literal_probe_read"], source["literal_probe_read"]),
                (source["literal_probe_write_input"], source["literal_probe_write_stored"]),
            ):
                values = [requested] * len(names)
                acknowledgement = request({"t": "cmd", "opt": names, "p": values}, key)
                assert acknowledgement == {"t": "res", "mac": mac, "opt": names, "p": values, "r": 200}
                fresh = request({"t": "status", "cols": names}, key)
                assert fresh["cols"] == names and fresh["dat"] == [stored] * len(names)
        for name in source["raw_write_only_names"]:
            acknowledgement = request({"t": "cmd", "opt": [name], "p": [65537]}, key)
            assert acknowledgement["p"] == [65537]
            assert request({"t": "status", "cols": [name]}, key)["dat"] == [""]
        client = Device(DeviceInfo(address[0], address[1], mac, vector["device"]["name"], mid=source["mid"]),
                        timeout=2, bind_timeout=1)
        try:
            await client.bind(cipher=CipherV2())
            assert client.device_cipher.key == key.decode("ascii")
            client._valid_state.clear()
            await client.update_state(columns=["Pow", "SetTem"])
            await asyncio.wait_for(client._valid_state.wait(), 2)
            assert [client.raw_properties[name] for name in ("Pow", "SetTem")] == [65535, 65535]
        finally:
            client.close()


@pytest.mark.parametrize("mid", ["10f05", "10010", "10011", "11011", "11012"])
def test_wb04_actual_cli_source_operation_lifecycle(mid):
    vectors = json.loads((REPO / "tests/fixtures/emulator/wb04a-operations_research.json").read_text())
    timer = vectors["timer"]
    mac = "020000000001"
    records = [{"id": "wb04", "profile": vectors["profile"], "mid": mid, "mac": mac, "name": "WB04"}]
    with cli_server(records) as (address, identities), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        peer = Peer(sock, address, identities)
        sock.sendto(b'{"t":"scan"}', address)
        _, advertisement = unpack(peer.receive())
        assert (advertisement["t"], advertisement["mac"], advertisement["mid"]) == ("dev", mac, mid)

        def wire(inner, key, index=0):
            return packet({"t": "pack", "i": index, "uid": 9, "cid": "peer", "tcid": mac}, inner, key)

        def request(inner, key):
            sock.sendto(wire(inner, key), address)
            return unpack(peer.receive(), key)[1]

        sock.sendto(wire({"t": "bind", "mac": mac}, ECB_KEY, 1), address)
        _, bound = unpack(peer.receive())
        assert bound["t"].casefold() == "bindok" and bound["mac"] == mac
        key = bound["key"].encode("ascii")
        assert len(key) == 16
        fallback = request({"t": "status", "cols": None, "opt": ["Pow"], "p": [1]}, key)
        assert fallback["cols"] == ["Pow"] and fallback["dat"] == [1]
        assert request({"t": "status", "cols": ["Pow"]}, key)["dat"] == [1]
        fallback = request({"t": "cmd", "cols": None, "opt": ["Pow"], "p": [0]}, key)
        assert fallback["opt"] == ["Pow"] and fallback["p"] == [0]
        assert request({"t": "status", "cols": ["Pow"]}, key)["dat"] == [0]
        for request_name, expected_name in (
            ("set_request", "response"), ("query_request", "query_response"),
            ("update_request", "response"), ("query_request", "update_query_response"),
            ("delete_request", "response"), ("query_request", "empty_query_response"),
        ):
            assert request(timer[request_name], key) == timer[expected_name]

        bounded = deepcopy(timer["set_request"])
        bounded.update(id=4, name="Bound", cmd={"opt": ["Pow"] * 32, "p": list(range(32))})
        assert request(bounded, key) == timer["response"]
        bounded_query = deepcopy(timer["query_response"])
        bounded_query["list"][0].update(id=4, name="Bound")
        bounded_query["list"][0]["cmd"]["p"] = [31]
        assert request(timer["query_request"], key) == bounded_query
        for invalid_command in (
            {"opt": ["Pow"] * 33, "p": [1] * 33},
            [{"opt": ["Pow"], "p": [1]}],
            {"opt": ["Pow"], "p": []},
        ):
            rejected = dict(bounded, id=5, name="Rejected", cmd=invalid_command)
            peer.quiet(wire(rejected, key))
            assert request(timer["query_request"], key) == bounded_query
        assert request({"t": "deleteT", "id": 4}, key) == timer["response"]
        assert request(timer["query_request"], key) == timer["empty_query_response"]
        for identifier in (9, 2, 7, 4, 1, 8, 0, 6, 5, 3):
            entry = dict(timer["set_request"], id=identifier, name=f"slot-{identifier}")
            assert request(entry, key) == timer["response"]
        peer.quiet(wire(dict(timer["set_request"], id=10, name="eleventh"), key))
        expected_rows = []
        for identifier in (5, 3):
            entry = deepcopy(timer["query_response"]["list"][0])
            entry.update(id=identifier, name=f"slot-{identifier}")
            expected_rows.append(entry)
        assert request({"t": "queryT", "index": 8, "count": 10}, key) == {
            "t": "listT", "total": 10, "index": 8, "list": expected_rows}
        assert request({"t": "queryT", "index": 10, "count": 1}, key) == {
            "t": "listT", "total": 10, "index": 10, "list": []}
        assert vectors["freqCount"]["response"] == []
        peer.quiet(wire(vectors["freqCount"]["request"], key))
        assert request({"t": "status", "cols": ["Pow"]}, key)["dat"] == [0]
        peer.quiet(wire({"t": "freqCount", "cols": None, "opt": ["FreqTime"], "p": [8]}, key))
        assert request({"t": "status", "cols": ["Pow"]}, key)["dat"] == [0]
        assert request(vectors["upgrade"]["request"], key) == vectors["upgrade"]["response"]
        peer.quiet(wire({"t": "upgrade", "url": "x" * 120}, key))
        peer.quiet(b"{invalid JSON")
        assert request({"t": "status", "cols": ["Pow", "SetTem"]}, key)["dat"] == [0, 24]
