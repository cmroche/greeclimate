"""Consumer-side subprocess regressions, with independent ECB/GCM peers."""

import base64
from contextlib import contextmanager
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
from time import monotonic

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
RT_IDS = tuple("sim-wb05rt13-v1." + version for version in ("45", "54", "64"))
ROOT_IDS = W06_IDS + WB_IDS + RT_IDS
W06_HIDS = (
    "362001061433+U-W06AV7.bin",
    "362001067012+U-W06AV16.bin",
    "362001067012+U-W06AV16.bin",
    "362001067012+U-W06AV16.bin",
    "362001067012+U-W06AV20.bin",
    "362001067012+U-W06AV30.bin",
)


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
        if name in W06_IDS:
            assert profiles[name][0]["hid"] == W06_HIDS[W06_IDS.index(name)]
        elif name in WB_IDS:
            version = name.rsplit("-v", 1)[1]
            code = "362001066326" if version in ("1.16", "1.18") else "362001066380"
            assert profiles[name][0]["hid"] == f"{code}+U-WB05BRV{version}.bin"
        else:
            assert profiles[name][0]["hid"] == f"362001065279+U-WB05RT13V{name.rsplit('-v', 1)[1]}.bin"
        if name not in RT_IDS:
            assert all(row["parents"] == [name] and row["role"] == "child"
                       for row in profiles[name + "-ac"])
            assert all(row["hid"] == profiles[name][0]["hid"] for row in profiles[name + "-ac"])
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
            gcm = record["profile"] in RT_IDS
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


def exercise(records, profiles, *, pages=False):
    """Shared by the two focused regressions and the disposable all-build smoke."""
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
            if name in WB_IDS:
                assert "hid" not in advert and "brand" not in advert
            else:
                assert advert["hid"] == profiles[name][0]["hid"]
            peer.bind(root)
            peer.status(root, root, [profiles[name][0]["hid"]], columns=["hid"])
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
                assert advertisements[identities[root]["mac"]]["hid"] == (
                    f"362001065279+U-WB05RT13V{name.rsplit('-v', 1)[1]}.bin")
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
    exercise(records, profiles)


def test_actual_cli_stable_seed_survives_restart_and_declaration_reorder():
    profiles = cli_profiles()
    records = configuration(profiles, [W06_IDS[0], W06_IDS[-1]])
    first, keys = exercise(records, profiles)
    second, restarted_keys = exercise(list(reversed(records)), profiles)
    assert first == second
    assert keys == restarted_keys
