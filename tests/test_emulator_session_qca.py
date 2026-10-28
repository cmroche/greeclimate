"""Source-qualified QCA raw caches, metadata, topology and safe parser boundaries."""

import copy
import json
from pathlib import Path

import pytest

from gree_emulator.__main__ import load_config
from gree_emulator.wire import InvalidPacket, decode_outer, encode_reply
from tests.test_emulator import GENERIC_KEY, peer_packet, peer_reply


def qca_gateway_records(count):
    return [{"id": "gateway", "profile": "sim-w06bv-v20", "mid": "60"}] + [
        {"id": f"child-{index}", "profile": "sim-w06bv-v20-ac",
         "mid": "604a", "parent": "gateway"}
        for index in range(count)
    ]


def test_qca_gateway_accepts_source_maximum():
    devices = load_config({"devices": qca_gateway_records(100)})[2]
    assert len(devices[0].children) == 100


def test_qca_gateway_rejects_above_source_maximum():
    with pytest.raises(ValueError, match="at most 100 children"):
        load_config({"devices": qca_gateway_records(101)})


@pytest.mark.parametrize("mid", ("6099", "608d", "6091", "60a9"))
def test_qca_alternate_child_is_not_an_ac(mid):
    records = qca_gateway_records(1)
    records[1]["mid"] = mid
    with pytest.raises(ValueError, match="mid"):
        load_config({"devices": records})


def test_qca_fan_is_a_separate_sensorless_child():
    records = qca_gateway_records(1)
    records[1].update(profile="sim-w06bv-v20-fan", mid="6079")
    child = load_config({"devices": records})[2][1]
    assert child.profile.mids == ("6079",)
    assert child.profile.identity_bytes == 7
    assert child.profile.parent_profiles == ("sim-w06bv-v20",)
    assert child.state["_cache"][5] == 0x55
    assert child.room_c is None and child.ambient_c is None
    assert child.profile.handler.thermal_target(child) is None
    assert child.profile.handler.advertise(child, {"t": "scan"}) == []
    assert child.profile.handler.handle(child, {}) == []
    records[1]["profile"] = "sim-w06bv-v20-ac"
    with pytest.raises(ValueError, match="mid"):
        load_config({"devices": records})


@pytest.mark.parametrize("state", [
    {"TemBody": 22}, {"rssi": 1}, {"hid": 1}, {"BuzzerCtrl": 1},
    {"Pow": 2}, {"Mod": 12}, {"FanMod": 2**31}, {"WdSpd": -(2**31)-1},
    {"Pow": True}, {"FanMod": 1.0},
])
def test_qca_fan_configuration_accepts_only_modeled_controls(state):
    records = qca_gateway_records(1)
    records[1].update(profile="sim-w06bv-v20-fan", mid="6079", state=state)
    with pytest.raises(ValueError, match="state"):
        load_config({"devices": records})


@pytest.mark.parametrize("mid", ("6099", "608d", "6091", "60a9"))
def test_qca_fan_rejects_stored_normalization_aliases(mid):
    records = qca_gateway_records(1)
    records[1].update(profile="sim-w06bv-v20-fan", mid=mid)
    with pytest.raises(ValueError, match="mid"):
        load_config({"devices": records})


@pytest.mark.parametrize("profile,index,generic", [
    ("sim-w06bv-v20", 256, False),
    ("sim-w06bv-v20", 512, False),
    ("sim-w06bv-v20", 257, True),
    ("sim-w06av-v30", 256, True),
])
def test_gateway_build_uses_its_native_decrypt_index(profile, index, generic):
    root = load_config({"devices": [{"id": "gateway", "profile": profile, "mid": "60"}]})[2][0]
    key = GENERIC_KEY if generic else root.key
    outer = decode_outer(peer_packet(
        {"t": "pack", "i": index, "uid": 42, "cid": "app", "tcid": root.mac},
        {"t": "bind", "mac": root.mac}, key,
    ))
    reply, = root.profile.handler.handle(root, outer)
    decoded = peer_reply(encode_reply(reply), GENERIC_KEY)
    assert decoded["inner"] == {"t": "bindOk", "mac": root.mac, "key": root.key.decode(), "r": 200}
    assert decoded["outer"]["i"] == 1


MATRIX = json.loads((Path(__file__).parent / "fixtures/emulator/"
                     "session-qca-gateway-quirks_research.json").read_text())
RAW_BUILDS = ("sim-w06av-v16-eu", "sim-w06av-v20", "sim-w06av-v30", "sim-w06bv-v20")


def raw_devices(profile="sim-w06bv-v20", *, alternate=False, count=1):
    records = [{"id": "gateway", "profile": profile, "mid": "60"}]
    records += [{"id": f"child-{index}", "profile": profile + ("-fan" if alternate else "-ac"),
                 "mid": "6079" if alternate else "604a", "parent": "gateway"}
                for index in range(count)]
    return load_config({"devices": records})[2]


def raw_request(root, inner):
    outer = decode_outer(peer_packet(
        {"t": "pack", "i": 0, "uid": -17, "cid": "app", "tcid": root.mac},
        inner, root.key,
    ))
    reply, = root.profile.handler.handle(root, outer)
    return peer_reply(encode_reply(reply), root.key)["inner"]


def raw_status(root, child, columns):
    return raw_request(root, {"t": "status", "mac": child.mac, "cols": columns})


@pytest.mark.parametrize("vector", MATRIX["raw_write_vectors"],
                         ids=lambda row: row["route"] + "-" + row["field"])
def test_every_raw_descriptor_command_ack_and_independent_fresh_status(vector):
    profiles = RAW_BUILDS
    for profile in profiles:
        root, child = raw_devices(profile, alternate=vector["route"] == "alternate")
        name, requested = vector["field"], vector["requested"]
        acknowledged = vector.get("ack", requested)
        result = raw_request(root, {"t": "cmd", "sub": child.mac,
                                    "opt": [name], "p": [requested]})
        assert result == {"t": "res", "mac": child.mac, "r": 200,
                          "opt": [name], "p": [acknowledged], "val": [acknowledged]}
        assert raw_status(root, child, [name, name]) == {
            "t": "dat", "mac": child.mac, "r": 200,
            "cols": [name, name], "dat": [vector["fresh"], vector["fresh"]],
        }
        assert child.room_c is None and child.ambient_c is None


@pytest.mark.parametrize("profile", RAW_BUILDS)
def test_gateway_raw_aliases_duplicates_width_and_child_isolation(profile):
    root, child, other = raw_devices(profile, count=2)
    raw_request(root, {"t": "cmd", "sub": child.mac,
                      "opt": ["Air", "Air", "GoOut", "AssHt", "ErrType1", "SetDeciTem"],
                      "p": [255, 256, -1, 257, -1, 245]})
    cols = ["Air", "OutHome", "GoOut", "AidHeat", "AssHt", "ErrType1",
            "Add0.1", "SetTem", "Add0.5", "Add0.1", "SetDeciTem"]
    assert raw_status(root, child, cols)["dat"] == [0, 255, 255, 1, 1, 65535, 0, 24, 1, 5, 245]
    assert raw_status(root, other, ["Air", "SetTem", "TemBody"])["dat"] == [0, 24, 0]
    root2, child2 = raw_devices(profile)
    assert raw_status(root2, child2, ["Air", "SetTem", "TemBody"])["dat"] == [0, 24, 0]


@pytest.mark.parametrize("profile", RAW_BUILDS)
@pytest.mark.parametrize("names,values,expected", [
    (["SetTem", "Add0.5"], [24, 1], [24, 241, 1]),
    (["Add0.5", "SetTem"], [1, 24], [24, 245, 5]),
    (["SetTem", "Add0.1"], [24, 9], [24, 249, 9]),
    (["Add0.1", "SetTem"], [9, 24], [24, 249, 9]),
])
def test_gateway_fraction_command_order_is_not_normalized(profile, names, values, expected):
    root, child = raw_devices(profile)
    raw_request(root, {"t": "cmd", "sub": child.mac, "opt": names, "p": values})
    assert raw_status(root, child, ["SetTem", "SetDeciTem", "Add0.1"])["dat"] == expected


@pytest.mark.parametrize("profile", RAW_BUILDS)
def test_gateway_metadata_root_scope_and_unrouted_raw_defaults(profile):
    root, child = raw_devices(profile)
    hid = "" if profile == "sim-w06av-v16-eu" else root.profile.hid
    time = "2017-6-15 00:00:00" if profile == "sim-w06av-v16-eu" else ""
    for target in (root, child):
        assert raw_status(root, target, ["hid", "rssi", "GcloudHid", "time", "hid"])["dat"] == [
            hid, 219, "", time, hid,
        ]
    advertisement = root.profile.handler.advertise(root, {"t": "scan"})[0].inner
    if profile == "sim-w06av-v16-eu":
        assert "hid" not in advertisement
    else:
        assert advertisement["hid"] == root.profile.hid
    assert raw_status(root, child, ["TemBody", "Lig", "FanMod", "nonexistent"])["dat"] == [0, 0, 0, ""]
    before = copy.deepcopy(child.state)
    with pytest.raises(InvalidPacket):
        raw_request(root, {"t": "cmd", "sub": child.mac,
                          "opt": ["Air", "rssi"], "p": [1, 42]})
    assert child.state == before


@pytest.mark.parametrize("values", ([1, True], [1, 1.0], [1, "2"], [1, 2**31], [1, None]))
def test_gateway_raw_batch_is_atomic_across_invalid_types_and_int32_width(values):
    root, child = raw_devices()
    before = copy.deepcopy(child.state)
    with pytest.raises(InvalidPacket):
        raw_request(root, {"t": "cmd", "sub": child.mac,
                          "opt": ["Air", "Blo"], "p": values})
    assert child.state == before
    assert raw_status(root, child, ["Air", "Blo"])["dat"] == [0, 0]


def test_gateway_oversize_request_does_not_apply_valid_command():
    root, child = raw_devices()
    before = copy.deepcopy(child.state)
    with pytest.raises(InvalidPacket):
        raw_request(root, {"t": "cmd", "sub": child.mac,
                          "opt": ["Heat3DSvStTemMax"] * 20, "p": [2147483647] * 20})
    assert child.state == before


def test_gateway_alternate_temperature_unit_first_slot_and_raw_width():
    root, child = raw_devices(alternate=True)
    raw_request(root, {"t": "cmd", "sub": child.mac,
                      "opt": ["TemUn", "SetTem", "PM2P5", "ExWdSpd"], "p": [1, 24, 65537, 256]})
    # Source UART/numeric getter wrap ExWdSpd to zero; LAN name serialization is still empty.
    assert raw_status(root, child, ["SetTem", "TemRec", "TemUn", "PM2P5", "ExWdSpd"])["dat"] == [
        24, 0, 1, 1, "",
    ]
    raw_request(root, {"t": "cmd", "sub": child.mac, "opt": ["SetTem"], "p": [24]})
    assert raw_status(root, child, ["SetTem", "TemUn"])["dat"] == [24, 0]


def test_gateway_ordinary_native_inverse_failure_is_not_fabricated_status():
    root, child = raw_devices()
    raw_request(root, {"t": "cmd", "sub": child.mac, "opt": ["WdSpd"], "p": [7]})
    with pytest.raises(InvalidPacket, match="inverse"):
        raw_status(root, child, ["WdSpd"])
    assert raw_status(root, child, ["Pow"])["dat"] == [0]


@pytest.mark.parametrize("profile", RAW_BUILDS)
def test_alternate_error_word_is_readout_not_unit_or_half_flag(profile):
    root, child = raw_devices(profile, alternate=True)
    raw_request(root, {"t": "cmd", "sub": child.mac,
                      "opt": ["TemRec", "TemUn"], "p": [1, 1]})
    assert raw_status(root, child, ["GetEr", "TemRec", "TemUn"])["dat"] == [0, 1, 1]
    raw_request(root, {"t": "cmd", "sub": child.mac, "opt": ["ErrType"], "p": [256]})
    assert raw_status(root, child, ["GetEr", "ErrType"])["dat"] == [1, 256]
    raw_request(root, {"t": "cmd", "sub": child.mac, "opt": ["ErrType"], "p": [0]})
    assert raw_status(root, child, ["GetEr"])["dat"] == [0]


@pytest.mark.parametrize("profile", ("sim-w06av-v7", "sim-w06av-v16", "sim-w06av-v16-kf"))
def test_older_av_builds_use_their_source_raw_cache_namespace(profile):
    root, child = raw_devices(profile)
    raw_request(root, {"t": "cmd", "sub": child.mac, "opt": ["ErrType1"], "p": [-1]})
    assert raw_status(root, child, ["ErrType1"])["dat"] == [65535]
    if profile == "sim-w06av-v7":
        with pytest.raises(InvalidPacket):
            raw_request(root, {"t": "cmd", "sub": child.mac, "opt": ["WFConfig"], "p": [1]})
