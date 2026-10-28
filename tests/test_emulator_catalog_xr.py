"""Source-derived XR slot boundaries; software cipher and synthetic state only."""

import base64
from copy import deepcopy
import json
from pathlib import Path

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles import catalog_xr
from gree_emulator.wire import InvalidPacket, encode_reply


FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-xr_research.json").read_text())
GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"


@pytest.fixture
def device(monkeypatch):
    monkeypatch.setattr(catalog_xr.time, "monotonic", lambda: 1000.0)
    profile, = catalog_xr.PROFILES
    profile.handler.validate_state(dict(profile.initial_state))
    return EmulatedDevice("xr", FIXTURE["mac"], "xr-test", "10001",
                          FIXTURE["key"].encode(), profile, dict(profile.initial_state),
                          room_c=None, ambient_c=None, last_step=1000)


def unpack(reply, key):
    raw = encode_reply(reply)
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    outer = json.loads(raw)
    inner_bytes = unpad(AES.new(key, AES.MODE_ECB).decrypt(
        base64.b64decode(outer.pop("pack"), validate=True)), 16)
    assert not inner_bytes.endswith(b"\n")
    return outer, json.loads(inner_bytes)


def request(device, inner, *, index=0, uid=-7, key=None, target=None):
    key = key or (GENERIC_KEY if index else device.key)
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(
        json.dumps(inner, separators=(",", ":")).encode(), 16))
    return device.profile.handler.handle(device, {
        "t": "pack", "i": index, "uid": uid, "cid": "peer", "tcid": target or device.mac,
        "pack": base64.b64encode(encrypted).decode()})


def exchange(device, inner, **kwargs):
    reply, = request(device, inner, **kwargs)
    key = GENERIC_KEY if reply.outer["i"] and inner["t"] not in (
        "setT", "updateT", "deleteT", "queryT") else device.key
    outer, response = unpack(reply, key)
    assert outer == {"t": "pack", "i": reply.outer["i"], "uid": kwargs.get("uid", -7),
                     "cid": device.mac, "tcid": ""}
    return response


def status(device, names):
    return exchange(device, {"t": "status", "cols": names})


def test_exact_identity_keys_lifecycle_and_discovery(device):
    assert device.profile.id == FIXTURE["profile"]
    assert device.profile.mids == ("10001",)
    assert device.profile.hid == FIXTURE["hid"]
    assert device.profile.source_sha256 == FIXTURE["source_sha256"]
    reply, = device.profile.handler.advertise(device, {"t": "scan"})
    envelope, inner = unpack(reply, GENERIC_KEY)
    assert envelope == {"t": "pack", "i": 1, "uid": 0, "cid": device.mac, "tcid": ""}
    assert inner == {"t": "dev", "cid": "", "bc": "gree", "catalog": "gree",
                     "mid": "10001", "lock": 0, "model": "gree", "name": "xr-test",
                     "series": "gree", "vender": "2", "ver": "V3.0.0", "brand": "gree",
                     "mac": device.mac}
    for index in (1, 2, -1, 256):
        assert exchange(device, {"t": "bind", "mac": device.mac}, index=index) == {
            "t": "bindok", "mac": device.mac, "r": 200, "key": FIXTURE["key"]}
    assert exchange(device, {"t": "cmd", "opt": ["lock"], "p": [9]})["p"] == [9]
    assert exchange(device, {"t": "bind", "mac": device.mac}, index=1)["key"] == FIXTURE["key"]
    reply, = device.profile.handler.advertise(device, {"t": "scan"})
    assert unpack(reply, GENERIC_KEY)[1]["lock"] == 9
    assert device.profile.handler.thermal_target(device) is None


@pytest.mark.parametrize("row", FIXTURE["slot_matrix"], ids=lambda row: str(row["index"]))
def test_every_original_slot_and_first_match_numeric_semantics(device, row):
    index, name = row["index"], row["name"]
    assert catalog_xr.SELECTORS[index] == name
    if name is None:
        assert row["boundary"] == "null-reserved"
        return
    assert catalog_xr.FIRST_INDEX[name] == row["resolved_index"]
    selected = [name] if row["status_name_admitted"] else []
    initial = status(device, [name])
    assert initial["cols"] == selected
    assert initial["dat"] == (row["initial_dat"] if selected else [])
    ack = exchange(device, {"t": "cmd", "opt": [name], "p": [-1]})
    assert ack == {"t": "res", "mac": device.mac, "r": 200,
                   "opt": [name], "p": row["numeric_minus1_ack_p"]}
    fresh = status(device, [name])
    assert fresh["dat"] == (row["numeric_minus1_fresh_dat"] if selected else [])
    assert device.state["_cache"][row["resolved_index"]] == 65535
    if row["resolved_index"] != index:
        assert device.state["_cache"][index] == 0
    assert len(device.state["_cache"]) == 495


@pytest.mark.parametrize("vector", FIXTURE["string_vectors"], ids=lambda row: row["name"])
def test_mutable_strings_calendar_and_native_string_noop(device, vector):
    name, value = vector["name"], vector["value"]
    ack = exchange(device, {"t": "cmd", "opt": [name], "p": [value]})
    assert ack["opt"] == [name]
    assert ack["p"] == vector["ack"]
    assert status(device, [name])["dat"] == vector["ack"]


def test_order_duplicates_holes_ragged_metadata_and_progress_side_effect(device):
    assert exchange(device, {"t": "cmd", "opt": ["NoD", "NoD"], "p": [65536, -1]})["p"] == [0, 65535]
    assert status(device, ["NoD", "apssid", "Pow", "model", "vender"])["dat"] == [65535, 0, "2"]
    assert status(device, ["Pow"] * 29)["dat"] == [0] * 29
    assert status(device, ["Pow"] * 30)["cols"] == []
    assert status(device, ["unknown"] * 30)["dat"] == []
    for hole in ("", None, 1, "x" * 16):
        result = status(device, ["Pow", hole, "unknown"])
        assert result["cols"] == ["Pow"] and result["dat"] == [0]
    exchange(device, {"t": "cmd", "opt": ["HidDownPer"], "p": [42]})
    assert status(device, ["HidDownPer", "hid", "HidDownPer"])["dat"] == [42, FIXTURE["hid"], 0]
    assert exchange(device, {"t": "cmd", "opt": ["rssi", "voiceHidPer"], "p": [-1, 100]})["p"] == [65535, 100]
    assert status(device, ["rssi", "voiceHidPer"])["dat"] == [-50, 0]


@pytest.mark.parametrize("inner", [
    {},
    {"t": 1},
    {"t": "cmd", "opt": ["Pow", "unknown"], "p": [1, 2]},
    {"t": "cmd", "opt": ["Pow", "Mod"], "p": [1]},
    {"t": "cmd", "opt": ["Pow", "Mod"], "p": [1, True]},
    {"t": "cmd", "opt": ["Pow"], "p": [None]},
    {"t": "cmd", "opt": ["Pow"], "p": [1.5]},
    {"t": "cmd", "opt": ["Pow"], "p": [2147483648]},
    {"t": "cmd", "opt": ["name"], "p": ["x" * 32]},
    {"t": "cmd", "opt": ["time"], "p": ["2023-02-29 00:00:00"]},
    {"t": "status", "cols": ["Pow", "unknown"]},
    {"t": "status", "cols": ["Pow"] * 31},
    {"t": "cmd", "mac": "ffffffffffff", "opt": ["Pow"], "p": [1]},
])
def test_safe_atomic_fault_rejection_and_recovery(device, inner):
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        request(device, inner)
    assert device.state == before
    assert exchange(device, {"t": "cmd", "opt": ["Pow"], "p": [1]})["p"] == [1]
    assert status(device, ["Pow"])["dat"] == [1]


def test_wrong_cipher_target_and_isolated_full_cache(device):
    for kwargs in ({"key": b"fedcba9876543210"}, {"target": "ffffffffffff"}):
        before = deepcopy(device.state)
        with pytest.raises(InvalidPacket):
            request(device, {"t": "status", "cols": ["Pow"]}, **kwargs)
        assert device.state == before
    exchange(device, {"t": "cmd", "opt": ["Pow", "name"], "p": [1, "one"]})
    profile = device.profile
    other = EmulatedDevice("other", "020000000968", "other", "10001", b"fedcba9876543210",
                           profile, dict(profile.initial_state), room_c=None, ambient_c=None)
    assert status(other, ["Pow", "name"])["dat"] == [0, "other"]
    assert device.state["_cache"] is not other.state["_cache"]
    assert all(value == 0 for value in other.state["_cache"])


def test_virtual_clock_elapsed_and_silent_external_operations(device, monkeypatch):
    exchange(device, {"t": "cmd", "opt": ["time"], "p": ["2024-02-29 23:59:59"]})
    monkeypatch.setattr(catalog_xr.time, "monotonic", lambda: 1002.5)
    assert status(device, ["time"])["dat"] == ["2024-03-01 00:00:01"]
    assert request(device, {"t": "upgrade", "url": "http://192.0.2.1/synthetic"}) == []
    assert request(device, {"t": "not-dispatched"}) == []


def test_reply_size_failure_is_atomic(device):
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        request(device, {"t": "cmd", "opt": ["hid"] * 30, "p": [-1] * 30})
    assert device.state == before


def test_plaintext_provisioning_is_memory_only_and_keeps_device_key(device):
    packet = {"t": "wlan", "host": "192.0.2.1", "ssid": "synthetic",
              "psw": "not-a-real-secret", "lat": "-12.5", "lon": "123.4"}
    key = device.key
    reply, = device.profile.handler.wlan(device, packet)
    assert encode_reply(reply) == (
        b'{"t":"ret","r":200,"mac":"020000000967"}\n')
    assert device.key == key
    assert status(device, ["host", "lat", "lon", "apssid", "appsw"])["dat"] == [
        "192.0.2.1", "-12.5", "123.4"]
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        device.profile.handler.wlan(device, {**packet, "ssid": "x" * 65})
    assert device.state == before


def test_server_tick_advances_virtual_clock_without_packets(device):
    status(device, [])
    assert device.profile.handler.tick(device, 1002.5) == []
    assert device.state["_clock"] == 2.5


def test_timer_wrapper_keeps_cached_sourceflag_but_always_uses_device_key(device):
    exchange(device, {"t": "bind", "mac": device.mac}, index=1)
    reply, = request(device, {"t": "queryT", "index": 0, "count": 10}, index=1)
    envelope, inner = unpack(reply, device.key)
    assert envelope["i"] == 1
    assert inner == {"t": "listT", "total": 10, "index": 0}
    status(device, [])
    reply, = request(device, {"t": "queryT", "index": 255, "count": 255}, index=1)
    envelope, inner = unpack(reply, device.key)
    assert envelope["i"] == 0
    assert inner == {"t": "listT", "total": 255, "index": 255}


def test_explicit_time_command_refreshes_source_timer_clock(device, monkeypatch):
    refreshed = []
    original = catalog_xr.catalog_xr_timers.refresh_clock

    def refresh(state, clock):
        refreshed.append(clock)
        return original(state, clock)

    monkeypatch.setattr(catalog_xr.catalog_xr_timers, "refresh_clock", refresh)
    exchange(device, {"t": "cmd", "opt": ["time", "time"],
                      "p": ["2024-02-29 23:59:59", "1970-01-01 00:00:00"]})
    assert refreshed == [1709251199, 0]
