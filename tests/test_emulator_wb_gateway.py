"""Public WB05BR wire/model checks; no research repository or client imports."""

import base64
import json
from pathlib import Path

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.wb_gateway import PROFILES
from gree_emulator.wire import InvalidPacket, decode_outer, encode_reply


VECTOR = json.loads((Path(__file__).parent / "fixtures/emulator/wb-gateway.json").read_text())
GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
DEVICE_KEY = b"0123456789abcdef"
IDENTITIES = (
    "0244668800017f", "024466880002a1", "02446688000302", "024466880004ff",
    "02aabbccdd05e1", "02aabbccdd06b2", "029988776607c3",
)
VARIANTS = (
    ("1.13", "362001066380+U-WB05BRV1.13.bin"),
    ("1.16", "362001066326+U-WB05BRV1.16.bin"),
    ("1.18", "362001066326+U-WB05BRV1.18.bin"),
    ("1.22", "362001066380+U-WB05BRV1.22.bin"),
    ("1.31", "362001066380+U-WB05BRV1.31.bin"),
    ("1.38", "362001066380+U-WB05BRV1.38.bin"),
)


def gateway(version="1.13", count=4):
    root_profile = next(profile for profile in PROFILES if profile.id == f"sim-wb05br-v{version}")
    child_profile = next(profile for profile in PROFILES if profile.id == root_profile.id + "-ac")
    root = EmulatedDevice(id="gateway", mac="020000000001", name="WB Gateway", mid="60",
                          key=DEVICE_KEY, profile=root_profile, state={})
    root.children = [
        EmulatedDevice(id=f"child-{index}", mac=identity, name=f"Child {index}",
                       mid="605c" if index == 3 else "608f",
                       key=DEVICE_KEY, profile=child_profile, state=dict(child_profile.initial_state))
        for index, identity in enumerate(IDENTITIES[:count])
    ]
    root.profile.handler.validate_topology(root)
    return root


def outer(index=0, **changes):
    return {"t": "pack", "cid": "app", "tcid": "020000000001", "uid": 7,
            "i": index, **changes}


def packet(envelope, inner=None, key=None, suffix=b""):
    envelope = dict(envelope)
    if inner is not None:
        key = key if key is not None else GENERIC_KEY if envelope["i"] == 1 else DEVICE_KEY
        plaintext = json.dumps(inner, separators=(",", ":")).encode() + suffix
        envelope["pack"] = base64.b64encode(AES.new(key, AES.MODE_ECB).encrypt(pad(plaintext, 16))).decode()
    return decode_outer(json.dumps(envelope).encode())


def exchange(device, envelope, inner=None, key=None):
    replies = device.profile.handler.handle(device, packet(envelope, inner, key))
    result = []
    for reply in replies:
        encoded = json.loads(encode_reply(reply))
        selected_key = GENERIC_KEY if encoded["i"] == 1 else DEVICE_KEY
        encrypted = base64.b64decode(encoded.pop("pack"), validate=True)
        plaintext = unpad(AES.new(selected_key, AES.MODE_ECB).decrypt(encrypted), 16)
        result.append({"outer": encoded, "inner": json.loads(plaintext)})
    return result


@pytest.mark.parametrize("version,hid", VARIANTS)
def test_four_query_forms_preserve_four_four_three_four(version, hid):
    device = gateway(version)
    for request, expected in zip(VECTOR["requests"][2:6], VECTOR["expected_replies"][2:6], strict=True):
        assert exchange(device, request["outer"], request.get("inner")) == expected


@pytest.mark.parametrize("version,hid", VARIANTS)
@pytest.mark.parametrize("kind", ("subList", "subDev"))
@pytest.mark.parametrize("index", (0, 1))
@pytest.mark.parametrize("offset,members", (
    (0, (0, 1, 2, 3, 4)), (1, (1, 2, 3, 4, 5)), (5, (5, 6)), (7, ()), (256, ()),
))
def test_seven_children_use_offsets_not_page_numbers_or_key_selectors(version, hid, kind, index, offset, members):
    device = gateway(version, 7)
    result = exchange(device, outer(index), {"t": kind, "mac": device.mac, "i": offset})
    assert result == [{
        "outer": {"t": "pack", "cid": device.mac, "tcid": "app", "uid": 7, "i": index},
        "inner": {"t": "subList", "i": offset, "c": 7, "r": 200,
                  "list": [{"mac": IDENTITIES[number], "mid": "605c" if number == 3 else "608f"}
                           for number in members]},
    }]


@pytest.mark.parametrize("version,hid", VARIANTS)
def test_firmware_identity_is_observable_without_w06_discovery_fields(version, hid):
    device = gateway(version)
    advertisement = device.profile.handler.advertise(device, {"t": "scan"})[0]
    assert advertisement.inner == VECTOR["expected_replies"][0][0]["inner"]
    reply = exchange(device, outer(), {"t": "status", "mac": device.mac,
                                       "cols": ["hid", "Pow", "mid", "ver", "TemSor", "hid"]})
    assert reply[0]["inner"] == {"t": "dat", "mac": device.mac,
                                 "cols": ["hid", "Pow", "mid", "ver", "TemSor", "hid"],
                                 "dat": [hid, "", "60", "V3.2.M", "", hid], "r": 200}
    assert device.profile.handler.thermal_target(device.children[0]) is None


@pytest.mark.parametrize("version,hid", VARIANTS)
def test_control_changes_only_selected_child_and_fresh_status(version, hid):
    device = gateway(version)
    independent = gateway(version)
    command = {"t": "cmd", "mac": device.mac, "sub": IDENTITIES[0],
               "opt": ["Pow", "Mod", "SetTem", "WdSpd"], "p": [1, 4, 23, 2],
               "val": [0, 0, 30, 0]}
    reply = exchange(device, outer(), command)
    assert reply[0]["inner"] == {"t": "res", "mac": IDENTITIES[0], "r": 200,
                                 "opt": ["Pow", "Mod", "SetTem", "WdSpd"],
                                 "p": [1, 4, 23, 2], "val": [1, 4, 23, 2]}
    for target, identity, expected in (
        (device, IDENTITIES[0], [23, 1, 23, "", ""]),
        (device, IDENTITIES[1], [24, 0, 24, "", ""]),
        (independent, IDENTITIES[0], [24, 0, 24, "", ""]),
    ):
        fresh = exchange(target, outer(), {"t": "status", "mac": identity,
                                           "cols": ["SetTem", "Pow", "SetTem", "TemSor", "TemSen"]})
        assert fresh[0]["inner"]["dat"] == expected


def test_direct_child_mac_routing_and_simulated_duplicate_control_order():
    device = gateway()
    reply = exchange(device, outer(), {"t": "cmd", "mac": IDENTITIES[0],
                                       "opt": ["SetTem", "SetTem"], "p": [19, 25]})
    assert reply[0]["inner"]["p"] == [19, 25]
    assert reply[0]["inner"]["val"] == [19, 25]
    assert exchange(device, outer(), {"t": "status", "mac": IDENTITIES[0],
                                      "cols": ["SetTem"]})[0]["inner"]["dat"] == [25]


@pytest.mark.parametrize("version,hid", VARIANTS)
def test_observed_605c_child_uses_an_independent_sensorless_simulation_cache(version, hid):
    device = gateway(version, 7)
    response = exchange(device, outer(), {"t": "cmd", "sub": IDENTITIES[3],
                                          "opt": ["Pow", "SetTem"], "p": [1, 21]})
    assert response[0]["inner"] == {"t": "res", "mac": IDENTITIES[3], "r": 200,
                                    "opt": ["Pow", "SetTem"], "p": [1, 21], "val": [1, 21]}
    fresh = exchange(device, outer(), {"t": "status", "mac": IDENTITIES[3],
                                       "cols": ["Pow", "SetTem", "TemSor"]})
    assert fresh[0]["inner"]["dat"] == [1, 21, ""]
    assert exchange(device, outer(), {"t": "status", "mac": IDENTITIES[2],
                                      "cols": ["Pow", "SetTem"]})[0]["inner"]["dat"] == [0, 24]


@pytest.mark.parametrize("offset", (None, -1, True, "0", 0.5, 2**31))
def test_invalid_list_offsets_do_not_wrap(offset):
    device = gateway()
    with pytest.raises(InvalidPacket):
        exchange(device, outer(), {"t": "subList", "mac": device.mac, "i": offset})


@pytest.mark.parametrize("changes", (
    {"tcid": "020000000009"}, {"tcid": IDENTITIES[0]}, {"i": 2}, {"i": -1},
    {"i": True}, {"uid": True}, {"uid": 2**31}, {"cid": None},
    {"cid": "x" * 15}, {"cid": "app\u0000"},
))
def test_wrong_envelope_targets_key_slots_and_types(changes):
    with pytest.raises(InvalidPacket):
        exchange(gateway(), outer(**changes), {"t": "subList", "i": 0})


def test_wrong_key_and_invalid_encrypted_pack_do_not_become_plain_requests():
    device = gateway()
    with pytest.raises(InvalidPacket):
        exchange(device, outer(), {"t": "subList", "i": 0}, b"wrong-key-000000")
    with pytest.raises(InvalidPacket):
        exchange(device, outer(pack="ignored only on subList"))
    result = exchange(device, outer(1, t="subList", pack={"ignored": True}))
    assert result[0]["inner"]["i"] == 1
    assert [child["mac"] for child in result[0]["inner"]["list"]] == list(IDENTITIES[1:4])


@pytest.mark.parametrize("inner,index", (
    ({"t": "bind", "mac": "020000000001"}, 0),
    ({"t": "bind", "mac": IDENTITIES[0]}, 1),
    ({"t": "status", "mac": "020000000001", "cols": ["hid"]}, 1),
    ({"t": "status", "mac": IDENTITIES[0][:-2], "cols": ["Pow"]}, 0),
    ({"t": "status", "mac": IDENTITIES[0], "cols": [True]}, 0),
    ({"t": "subList", "mac": "020000000009", "i": 0}, 0),
    ({"t": "cmd", "sub": IDENTITIES[0], "opt": ["Pow"], "p": [1]}, 1),
    ({"t": "cmd", "mac": "020000000009", "sub": IDENTITIES[0], "opt": ["Pow"], "p": [1]}, 0),
))
def test_inner_routing_and_type_boundaries(inner, index):
    with pytest.raises(InvalidPacket):
        exchange(gateway(), outer(index), inner)


@pytest.mark.parametrize("names,values", (
    (["Pow", "SetTem"], [1, 31]), (["Pow", "Pow"], [True, 1]),
    (["SetTem", "SetTem"], [15, 20]), (["Pow"], [1.0]),
    (["Pow", "TemSor"], [1, 20]), (["Pow", "BuzzerCtrl"], [1, 1]),
    (["Pow", "Mod"], [1]), ([], []), (["Pow"], "1"),
))
def test_invalid_command_is_atomic_including_earlier_duplicate_values(names, values):
    device = gateway()
    before = [dict(child.state) for child in device.children]
    clocks = [child.last_step for child in device.children]
    with pytest.raises(InvalidPacket):
        exchange(device, outer(), {"t": "cmd", "sub": IDENTITIES[0], "opt": names, "p": values})
    assert [child.state for child in device.children] == before
    assert [child.last_step for child in device.children] == clocks


def test_oversized_response_is_rejected_before_any_control_or_clock_mutation():
    device = gateway()
    before = dict(device.children[0].state)
    clock = device.children[0].last_step
    with pytest.raises(InvalidPacket, match="UDP payload"):
        exchange(device, outer(), {"t": "cmd", "sub": IDENTITIES[0],
                                   "opt": ["Pow"] * 7000, "p": [1] * 7000})
    assert device.children[0].state == before
    assert device.children[0].last_step == clock


def test_strict_ecb_safety_boundary_rejects_nul_and_corruption():
    device = gateway()
    inner = {"t": "subList", "i": 0}
    with pytest.raises(InvalidPacket):
        device.profile.handler.handle(device, packet(outer(), inner, suffix=b"\0"))
    # An independently encrypted full block without PKCS7 is not accepted.
    plaintext = b'{"t":"subList"} '
    encrypted = AES.new(DEVICE_KEY, AES.MODE_ECB).encrypt(plaintext)
    with pytest.raises(InvalidPacket):
        exchange(device, outer(pack=base64.b64encode(encrypted).decode()))


def test_child_identity_validation_does_not_impose_a_parent_prefix_or_zero_suffix():
    device = gateway()
    device.children[0].mac = "02fedcba9876ef"
    device.profile.handler.validate_topology(device)
    assert exchange(device, outer(), {"t": "subDev", "i": 0})[0]["inner"]["list"][0] == {
        "mac": "02fedcba9876ef", "mid": "608f"}
    device.children[0].mac = "02fedcba9876"
    with pytest.raises(ValueError, match="seven-byte"):
        device.profile.handler.validate_topology(device)
    device.children[0].mac = IDENTITIES[0]
    device.children[0].profile = next(profile for profile in PROFILES if profile.id == "sim-wb05br-v1.18-ac")
    with pytest.raises(ValueError, match="exact parent firmware"):
        device.profile.handler.validate_topology(device)
