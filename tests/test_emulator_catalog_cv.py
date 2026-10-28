"""Independent source literals and declared synthetic CV readout policies."""
import asyncio
from copy import deepcopy
import json
from pathlib import Path
import socket

import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles import catalog_cv as family
from gree_emulator.server import start_server
from gree_emulator.wire import InvalidPacket, Reply, decode_outer, decode_pack, encode_reply
from greeclimate.cipher import CipherV1
from greeclimate.device import Device
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.gateway import GatewayDevice
from tests.test_emulator_firmware_cli import cli_server

FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-cv_research.json").read_text())
KEY = b"0123456789abcdef"
MAC = "020000000001"


@pytest.mark.parametrize(("version", "source_index"), (("v2", 0), ("v7", 1)))
async def test_cv_full_source_topology_unmodified_client_bind_and_hid(version, source_index):
    source = FIXTURE["sources"][source_index]
    records = [{"id": "root", "profile": f"sim-w06c-{version}", "mid": "9100",
                "name": "CV source fixture", "mac": MAC}]
    for suffix, (mid, name) in enumerate(zip(
            ("910001", "910002", "910003"), ("GreeHot", "GreeAc", "GreeHeat")), 1):
        records.append({
            "id": ("water", "ac", "heat")[suffix - 1],
            "profile": f"sim-w06c-{version}-{mid}", "mid": mid,
            "parent": "root", "name": name, "mac": MAC + f"{suffix:02x}",
        })
    with cli_server(records) as (address, identities):
        assert set(identities) == {"root", "water", "ac", "heat"}
        assert identities["root"]["mac"] == MAC
        info = DeviceInfo(address[0], address[1], MAC, "CV source fixture", mid="9100")
        client = Device(info, timeout=2, bind_timeout=1)
        try:
            await client.bind(cipher=CipherV1())
            await asyncio.wait_for(client._valid_state.wait(), 2)
            client._valid_state.clear()
            await client.update_state(columns=["hid"])
            await asyncio.wait_for(client._valid_state.wait(), 2)
            assert client.hid == source["hid"]
        finally:
            client.close()

        gateway = GatewayDevice(info, timeout=2, bind_timeout=1)
        try:
            await gateway.bind(cipher=CipherV1())
            await asyncio.wait_for(gateway._valid_state.wait(), 2)
            gateway._valid_state.clear()
            await gateway.update_state(columns=["hid"])
            await asyncio.wait_for(gateway._valid_state.wait(), 2)
            assert gateway.hid == source["hid"]
            with pytest.raises(ValueError, match="Unsupported gateway HID"):
                await gateway.get_sub_devices()
        finally:
            gateway.close()


def devices(version="v2"):
    profiles = {profile.id: profile for profile in family.PROFILES}
    profile = profiles[f"sim-w06c-{version}"]
    root = EmulatedDevice("root", MAC, "CV source fixture", "9100", KEY,
                          profile, dict(profile.initial_state), room_c=None, ambient_c=None)
    for suffix, (mid, name) in enumerate(zip(
            ("910001", "910002", "910003"), ("GreeHot", "GreeAc", "GreeHeat")), 1):
        child = profiles[f"sim-w06c-{version}-{mid}"]
        root.children.append(EmulatedDevice(
            mid, MAC + f"{suffix:02x}", name, mid, KEY, child,
            dict(child.initial_state), room_c=None, ambient_c=None))
    return root


def exchange(root, inner, index=0, uid=17, peer="peer", target=MAC):
    request = Reply({"t": "pack", "i": index, "uid": uid, "cid": peer, "tcid": target},
                    inner, KEY if index & 255 == 0 else family.GENERIC_KEY, family.CODEC)
    return root.profile.handler.handle(root, decode_outer(encode_reply(request)))


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch):
    monkeypatch.setattr(family, "monotonic", lambda: 0.0)


@pytest.mark.parametrize("version", ("v2", "v7"))
def test_every_finite_getter_and_ragged_metadata(version):
    root = devices(version)
    assert list(family.NAMES) == FIXTURE["names"]
    for target in (root, *root.children):
        for start in range(0, len(FIXTURE["names"]), 10):
            names = FIXTURE["names"][start:start + 10]
            response = exchange(root, {"t": "status", "mac": target.mac, "cols": names})[0]
            expected = []
            for name in names:
                if name in FIXTURE["metadata"]:
                    if name == "hid":
                        expected.append(FIXTURE["sources"][0 if version == "v2" else 1]["hid"])
                    elif name == "mac":
                        expected.append(MAC)
                    elif name == "name":
                        if target is not root:
                            expected.append(target.name)
                    elif name in FIXTURE["metadata_values"]:
                        expected.append(FIXTURE["metadata_values"][name])
                elif target is not root:
                    expected.append(0)
            assert response.inner == {"t": "dat", "r": 200, "mac": target.mac,
                                      "cols": names, "dat": expected}
            assert response.outer["i"] == 0
            assert response.key == KEY


def test_command_requested_ack_differs_from_byte_storage():
    root = devices()
    child = root.children[0]
    vector = FIXTURE["command_vector"]
    response = exchange(root, {"t": "cmd", "sub": child.mac,
                               "opt": vector["names"], "p": vector["requested"]})[0]
    assert response.inner == {"t": "res", "r": 200, "mac": child.mac,
                              "opt": vector["names"], "p": vector["ack_p"], "val": vector["ack_val"]}
    assert exchange(root, {"t": "status", "mac": child.mac, "cols": ["Pow"]})[0].inner["dat"] == [1]
    response = exchange(root, {"t": "cmd", "sub": child.mac, "opt": ["Wstate"], "p": [257]})[0]
    assert response.inner["p"] == response.inner["val"] == [257]
    assert exchange(root, {"t": "status", "mac": child.mac, "cols": ["Wstate"]})[0].inner["dat"] == [1]
    assert exchange(root, {"t": "status", "mac": root.children[1].mac, "cols": ["Pow"]})[0].inner["dat"] == [0]


def test_unknown_first_hole_duplicates_and_exact_capacity():
    root = devices()
    child = root.children[0]
    response = exchange(root, {"t": "status", "mac": child.mac,
                               "cols": ["Pow", "unknown", "country", "Pow"]})[0].inner
    assert response["cols"] == ["Pow", "country", "Pow"]
    assert response["dat"] == [0, 0]
    assert exchange(root, {"t": "status", "mac": child.mac,
                           "cols": ["Pow", "", "Wstate"]})[0].inner["cols"] == ["Pow"]
    response = exchange(root, {"t": "status", "mac": child.mac, "cols": ["Pow"] * 50})[0].inner
    assert response["cols"] == response["dat"] == []
    response = exchange(root, {"t": "cmd", "sub": child.mac,
                               "opt": ["Pow"] * 50, "p": [1] * 50})[0].inner
    assert response["opt"] == response["p"] == response["val"] == []
    assert exchange(root, {"t": "status", "mac": child.mac, "cols": ["Pow"]})[0].inner["dat"] == [1]


def test_invalid_batch_is_atomic_and_recovery_works():
    root = devices()
    root.profile.handler.advertise(root, {"t": "scan"})
    before = deepcopy(root.state), deepcopy(root.children[0].state)
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "cmd", "sub": root.children[0].mac,
                        "opt": ["Pow", "SetTemInt"], "p": [1, 999]})
    assert (root.state, root.children[0].state) == before
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "cmd", "sub": root.children[0].mac, "opt": ["Pow"], "p": [True]})
    assert exchange(root, {"t": "status", "mac": root.children[0].mac, "cols": ["Pow"]})[0].inner["dat"] == [0]


def test_topology_scan_enumeration_and_key_index_semantics():
    root = devices()
    root.profile.handler.validate_topology(root)
    scan = root.profile.handler.advertise(root, {"t": "scan"})[0]
    assert scan.inner["mid"] == "9100" and scan.inner["subCnt"] == 3
    assert "hid" not in scan.inner
    assert scan.key == family.GENERIC_KEY and not scan.trailing_newline
    bound = exchange(root, {"t": "bind", "mac": MAC}, index=1)[0]
    assert bound.inner == {"t": "bindok", "mac": MAC, "key": "0123456789abcdef", "r": 200}
    assert bound.outer == {"t": "pack", "i": 1, "uid": 17, "cid": MAC, "tcid": "peer"}
    assert exchange(root, {"t": "subDev", "mac": MAC, "i": 0})[0].inner == FIXTURE["subList"]
    page = exchange(root, {"t": "subDev", "mac": MAC, "i": -1})[0].inner
    assert page == {"t": "subList", "c": 3, "i": 255, "r": 200, "list": []}
    assert exchange(root, {"t": "status", "mac": MAC, "cols": ["hid"]}, index=256)[0].key == KEY
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "status", "mac": MAC, "cols": ["hid"]}, index=-1)
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "status", "mac": MAC, "cols": ["hid"]}, target="ffffffffffff")
    with pytest.raises(InvalidPacket):
        root.profile.handler.handle(root, {"t": "pack", "i": 2, "uid": 0,
                                           "cid": "peer", "tcid": MAC, "pack": {"t": "bind"}})


def test_metadata_clock_and_local_acceptance_are_not_external_actions():
    root = devices()
    root.profile.handler.handle(root, {"t": "tm", "time": "2026-10-01 12:34:56"})
    assert exchange(root, {"t": "status", "mac": MAC, "cols": ["time"]})[0].inner["dat"] == ["2026-00-01 12:34:56"]
    response = root.profile.handler.handle(root, {"t": "wlan", "ssid": "synthetic",
                                                 "psw": "synthetic", "host": ""})[0]
    assert response.inner == {"t": "ret", "r": 200, "mac": MAC}
    assert response.outer["i"] == 2
    response = exchange(root, {"t": "upgrade", "url": "http://synthetic.invalid/device.bin"})[0]
    assert response.inner == {"t": "ret", "r": 200, "mac": MAC}
    assert response.outer["i"] == 1
    assert root.state["_cv"]["pending_upgrade"] == "http://synthetic.invalid/device.bin"
    assert devices().state == {"lock": 0}


def test_schedule_integration_and_independent_restart():
    root = devices()
    request = {"t": "setT", "id": 2, "enable": 0, "hr": 0, "min": 0, "sec": 0,
               "tz": 0, "name": "synthetic", "week": [0] * 7,
               "cmd": [{"mac": [root.children[1].mac], "opt": ["Pow"], "p": [1]}]}
    assert exchange(root, request)[0].inner == {"t": "resT", "r": 200}
    listing = exchange(root, {"t": "queryT", "index": 2, "count": 3})[0].inner
    assert listing == {"t": "listT", "total": 10, "index": 2, "list": [
        {"id": 2, "name": "synthetic", "enable": 0, "hr": 0, "min": 0, "sec": 0,
         "week": [0] * 7, "cmd": [{"mac": [MAC], "opt": ["Pow"], "p": [1]}]}]}
    assert exchange(root, {"t": "status", "mac": root.children[1].mac, "cols": ["Pow"]})[0].inner["dat"] == [0]
    assert root.state["_cv"]["queue"] == 3
    other = devices()
    assert exchange(other, {"t": "queryT", "index": 2, "count": 1})[0].inner["list"] == []


def test_generated_child_identity_follows_seeded_parent_across_reorder():
    from gree_emulator.__main__ import load_config

    configured = [
        {"id": "root", "profile": "sim-w06c-v2", "mid": "9100"},
        {"id": "water", "profile": "sim-w06c-v2-910001", "mid": "910001", "parent": "root"},
        {"id": "heat", "profile": "sim-w06c-v2-910003", "mid": "910003", "parent": "root"},
    ]
    first = load_config({"seed": "cv-identities", "devices": configured})[2]
    reordered = load_config({"seed": "cv-identities", "devices": list(reversed(configured))})[2]
    first = {device.id: device for device in first}
    reordered = {device.id: device for device in reordered}
    assert first["water"].mac == first["root"].mac + "01"
    assert first["heat"].mac == first["root"].mac + "03"
    assert {name: (device.mac, device.key) for name, device in first.items()} == {
        name: (device.mac, device.key) for name, device in reordered.items()}


def test_explicit_child_identity_is_validated_not_rewritten():
    from gree_emulator.__main__ import load_config

    config = {"seed": "cv-explicit", "devices": [
        {"id": "root", "profile": "sim-w06c-v2", "mid": "9100", "mac": MAC},
        {"id": "water", "profile": "sim-w06c-v2-910001", "mid": "910001",
         "parent": "root", "mac": "02000000000201"},
    ]}
    with pytest.raises(ValueError, match="root MAC"):
        load_config(config)
    config["devices"][1]["mac"] = MAC + "01"
    devices_by_id = {device.id: device for device in load_config(config)[2]}
    assert devices_by_id["water"].mac == MAC + "01"

@pytest.mark.parametrize("version", ("v2", "v7"))
async def test_source_plaintext_ingress_routes_only_to_admitted_families(version):
    from gree_emulator.profiles.catalog_early_dom import PROFILES as OLD_DOM_PROFILES
    from gree_emulator.profiles.catalog_early_m26s import PROFILES as M26S_PROFILES
    from gree_emulator.profiles.catalog_early_small import PROFILES as SMALL_PROFILES

    cv = devices(version)
    profiles = {
        "small": SMALL_PROFILES[0],
        "old-dom": OLD_DOM_PROFILES[0],
        "descriptor": next(profile for profile in SMALL_PROFILES
                           if profile.id == "sim-w04r-v203-air"),
        "builtin-wlan": M26S_PROFILES[0],
    }
    others = [
        EmulatedDevice(name, f"02000000000{index}", name, profile.mids[0], KEY, profile,
                       dict(profile.initial_state), room_c=None, ambient_c=None)
        for index, (name, profile) in enumerate(profiles.items(), 2)
    ]
    strict = others
    assert tuple(FIXTURE["udp_plaintext"]["types"]) == cv.profile.handler.plaintext_types
    assert profiles["small"].handler.plaintext_types == ("wlan",)
    assert profiles["old-dom"].handler.plaintext_types == ("wlan",)
    assert profiles["descriptor"].handler.plaintext_types == ("wlan",)
    assert not hasattr(profiles["builtin-wlan"].handler, "plaintext_types")

    transport, server = await start_server([cv, *cv.children, *others], "127.0.0.1", 0)
    try:
        endpoint = transport.get_extra_info("sockname")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.settimeout(0.1)

            async def quiet(packet):
                peer.sendto(packet, endpoint)
                with pytest.raises(socket.timeout):
                    await asyncio.to_thread(peer.recvfrom, 65535)

            before = [dict(device.state) for device in strict]
            await quiet(b'{"t":"tm","time":"2026-10-01 12:34:56"}')
            assert cv.state["_cv"]["epoch"] > 0
            assert [device.state for device in strict] == before
            await quiet(b'{"t":"hbok"}')
            assert cv.state["_cv"]["heartbeat_at"] == 0.0
            assert [device.state for device in strict] == before

            await quiet(b'{"t":"surver"}')
            assert [device.state for device in strict] == before

            wlan = json.dumps({"t": "wlan", "ssid": "synthetic", "psw": "synthetic",
                               "host": "synthetic.local", "lat": "1", "lon": "2"},
                              separators=(",", ":")).encode()
            peer.sendto(wlan, endpoint)
            replies = [await asyncio.to_thread(peer.recvfrom, 65535) for _ in range(5)]
            assert all(address == endpoint for _, address in replies)

            plain_replies = {}
            cv_reply = None
            for raw, _ in replies:
                outer = json.loads(raw)
                if outer.get("t") == "pack":
                    cv_reply = outer
                else:
                    plain_replies[outer["mac"]] = outer

            assert cv_reply is not None and cv_reply["i"] == 2
            assert decode_pack(cv_reply, family.GENERIC_KEY, family.CODEC) == {
                "t": "ret", "r": 200, "mac": cv.mac}
            assert set(plain_replies) == {device.mac for device in others}
            assert all(reply == {"t": "ret", "r": 200, "mac": mac}
                       for mac, reply in plain_replies.items())

            assert cv.state["_cv"]["ssid"] == "synthetic"
            assert all(device.state["_small"]["host"] == "synthetic.local"
                       for device in others[:3])
            assert others[3].state["_tables"]["wlan_host"] == "synthetic.local"
    finally:
        server.close()
        await server.wait_closed()
