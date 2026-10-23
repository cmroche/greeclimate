"""Exact W06 wire dialects; appliance/cache/thermal behavior stays synthetic."""

import copy
import json
from pathlib import Path

import pytest

from gree_emulator.__main__ import load_config
from gree_emulator.wire import InvalidPacket, decode_outer, encode_reply
from tests.test_emulator import (
    peer_packet, peer_reply, vector_device,
    test_protocol_and_model_vectors_over_udp as run_udp_vectors,
)


VECTOR = json.loads((Path(__file__).parent / "fixtures/emulator/gateway_firmware.json").read_text())
VARIANTS = VECTOR["variants"]
MAC = "020000000001"
CHILD = "02000000000001"
KEY = b"0123456789abcdef"


def variant_vector(build):
    vector = copy.deepcopy(VECTOR)
    vector["profile"] = build["profile"]
    vector["expected_replies"][0][0]["inner"]["hid"] = build["hid"]
    for child in vector["children"]:
        child["profile"] = build["profile"] + "-ac"
    if not build["five_fields"]:
        for replies in vector["expected_replies"]:
            for reply in replies:
                if reply["inner"]["t"] == "subList":
                    for record in reply["inner"]["list"]:
                        for name in ("name", "model", "lock"):
                            del record[name]
    return vector


def devices(build):
    vector = variant_vector(build)
    root = vector_device(vector)
    root.children = [vector_device(child, root.key) for child in vector["children"]]
    return root


def exchange(root, inner, **outer):
    packet = peer_packet({"t": "pack", "i": 0, "uid": 7, "cid": "app",
                          "tcid": MAC, **outer}, inner, KEY)
    replies = root.profile.handler.handle(root, decode_outer(packet))
    return [peer_reply(encode_reply(reply), KEY)["inner"] for reply in replies]


@pytest.mark.parametrize("build", VARIANTS, ids=lambda build: build["profile"])
async def test_each_build_encrypted_bind_pages_controls_and_isolation(build):
    # Literal fixture includes malformed packets followed by successful recovery,
    # 5/2/0 pages, ordered status, atomic errors, and untouched second child.
    await run_udp_vectors(build["profile"], variant_vector(build))


@pytest.mark.parametrize("build", VARIANTS, ids=lambda build: build["profile"])
def test_build_specific_metadata_and_finite_namespace_policy(build):
    root = devices(build)
    result = exchange(root, {"t": "status", "mac": CHILD,
                             "cols": ["hid", "WFConfig", "TemUn", "notAField"]})[0]
    expected_cols = ["hid", "notAField"] if build["water_fields"] else ["hid", "WFConfig", "notAField"]
    expected_values = [build["hid"], ""] if build["water_fields"] else [build["hid"], "", ""]
    assert result == {"t": "dat", "mac": CHILD, "r": 200,
                      "cols": expected_cols, "dat": expected_values}
    assert exchange(root, {"t": "subList", "mac": MAC, "i": 0}) == []
    assert exchange(root, {"t": "subDev", "mac": MAC, "i": 256}) == exchange(
        root, {"t": "subDev", "mac": MAC, "i": 0})


@pytest.mark.parametrize("build", VARIANTS, ids=lambda build: build["profile"])
@pytest.mark.parametrize("names,values", [
    (["SetTem", "TemRec", "TemUn"], [18, 0, 0]),
    (["Pow", "SetTem"], [1, 31]),
    (["Pow"], [True]),
    (["Pow", "Mod"], [1]),
])
def test_safe_atomic_policy_rejects_bad_batches_without_native_staging(build, names, values):
    root = devices(build)
    before = [copy.deepcopy(child.state) for child in root.children]
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "cmd", "sub": CHILD, "opt": names, "p": values})
    assert [child.state for child in root.children] == before
    assert exchange(root, {"t": "status", "mac": CHILD, "cols": ["Pow", "SetTem"]})[0]["dat"] == [0, 24]


@pytest.mark.parametrize("build", VARIANTS, ids=lambda build: build["profile"])
def test_parent_endpoint_and_seven_byte_child_identity_are_required(build):
    root = devices(build)
    for inner, outer in [
        ({"t": "status", "mac": CHILD[:12], "cols": ["Pow"]}, {}),
        ({"t": "cmd", "sub": CHILD[:12], "opt": ["Pow"], "p": [1]}, {}),
        ({"t": "status", "mac": CHILD, "cols": ["Pow"]}, {"tcid": CHILD}),
        ({"t": "subDev", "mac": MAC, "i": True}, {}),
    ]:
        with pytest.raises(InvalidPacket):
            exchange(root, inner, **outer)
    assert exchange(root, {"t": "status", "mac": CHILD, "cols": ["Pow"]})[0]["dat"] == [0]
    child = root.children[0]
    assert child.profile.handler.advertise(child, {"t": "scan"}) == []
    assert child.profile.handler.handle(child, {}) == []


@pytest.mark.parametrize("build", VARIANTS, ids=lambda build: build["profile"])
@pytest.mark.parametrize("change,field", [
    ("root_room", "room_c"), ("root_state", "state"),
    ("no_parent", "parent"), ("wrong_build", "parent"),
    ("short_child", "mac"), ("sensor_override", "state"),
])
def test_build_topology_and_model_config_rejection(build, change, field):
    root = {"id": "root", "profile": build["profile"], "mid": "60", "mac": MAC}
    child = {"id": "child", "profile": build["profile"] + "-ac", "mid": "604a",
             "parent": "root", "mac": CHILD}
    if change == "root_room":
        root["room_c"] = 22
    elif change == "root_state":
        root["state"] = {"Pow": 1}
    elif change == "no_parent":
        del child["parent"]
    elif change == "wrong_build":
        child["profile"] = "sim-w06av-v7-ac" if build["profile"] != "sim-w06av-v7" else "sim-w06av-v30-ac"
    elif change == "short_child":
        child["mac"] = CHILD[:12]
    else:
        child["state"] = {"TemBody": 22}
    with pytest.raises(ValueError, match=field):
        load_config({"devices": [root, child]})


@pytest.mark.parametrize("build", VARIANTS, ids=lambda build: build["profile"])
def test_configured_children_share_only_parent_key_not_controls(build):
    root, first, second = load_config({"seed": "firmware-gateway", "devices": [
        {"id": "root", "profile": build["profile"], "mid": "60", "mac": MAC},
        {"id": "first", "profile": build["profile"] + "-ac", "mid": "604a", "parent": "root"},
        {"id": "second", "profile": build["profile"] + "-ac", "mid": "604a", "parent": "root"},
    ]})[2]
    assert first.key == second.key == root.key
    assert len(first.mac) == len(second.mac) == 14
    first.state["Pow"] = 1
    assert second.state["Pow"] == 0
