"""Literal finite namespace checks and separately labeled atomic model policies."""
import base64
from copy import deepcopy
import json
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.catalog_realtek_third_companions import PROFILES
from gree_emulator.wire import InvalidPacket, encode_reply

FIXTURE = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-realtek-third-companions_research.json").read_text())


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    monkeypatch.setattr("gree_emulator.profiles.catalog_realtek_third_companions.monotonic", lambda: 1000)
    monkeypatch.setattr("gree_emulator.profiles.catalog_realtek_third_tables.monotonic", lambda: 1000)


def device(build):
    profile = next(profile for profile in PROFILES if profile.handler.build == build)
    return EmulatedDevice("companion", FIXTURE["mac"], "", profile.mids[0],
                          FIXTURE["key"].encode(), profile, deepcopy(dict(profile.initial_state)),
                          room_c=None, ambient_c=None, last_step=1000)


def send(unit, inner, index=0, **override):
    key = b"a3K8Bx%2r8Y7#xDh" if index else unit.key
    ciphertext = AES.new(key, AES.MODE_ECB).encrypt(pad(json.dumps(inner).encode(), 16))
    outer = {"t": "pack", "tcid": unit.mac, "i": index, "uid": -2147483648,
             "pack": base64.b64encode(ciphertext).decode()}
    outer.update(override)
    return unit.profile.handler.handle(unit, outer)


def status(unit, columns):
    reply, = send(unit, {"t": "status", "cols": columns})
    assert reply.outer["uid"] == -2147483648
    assert reply.inner["r"] == 200
    assert encode_reply(reply).endswith(b"\n")
    return reply.inner


@pytest.mark.parametrize("row", FIXTURE["sources"], ids=lambda row: row["build"])
def test_exact_source_profiles_and_literal_ordered_status(row):
    unit = device(row["build"])
    assert unit.profile.id == row["profile"]
    assert unit.profile.mids == (row["mid"],)
    assert unit.profile.hid == row["hid"] and unit.profile.source_sha256 == row["sha256"]
    assert list(unit.profile.handler.fields) == row["fields"]
    actual = status(unit, row["status"]["request"])
    assert actual["cols"] == row["status"]["columns"]
    assert actual["dat"] == row["status"]["data"]
    assert row["banks"] == [0, 1]
    assert unit.profile.handler.thermal_target(unit) is None


def test_every_an_raw_getter_including_energy_and_reminder_readouts():
    unit = device("an")
    row = FIXTURE["sources"][0]
    for name in row["zero_getters"]:
        assert status(unit, [name])["dat"] == [0]
    for name, value in row["initialized_getters"].items():
        assert status(unit, [name])["dat"] == [value]
    assert status(unit, ["hid"])["dat"] == [row["hid"]]
    assert status(unit, ["time"])["dat"] == ["1970-01-01 00:00:00"]
    vector = row["ref_buttons"]
    actual = status(unit, vector["request"])
    assert actual["cols"] == vector["columns"] and actual["dat"] == vector["data"]


def test_every_mesh_getter_and_recognized_zero_datum_metadata():
    unit = device("g")
    row = FIXTURE["sources"][1]
    for name, value in row["readouts"].items():
        assert status(unit, [name])["dat"] == [value]
    for name in row["empty_getters"]:
        actual = status(unit, [name])
        assert actual["cols"] == [name] and actual["dat"] == []
    for name in ("host", "name", "lat", "lon", "vender", "ver", "BtHid"):
        assert status(unit, [name])["dat"] == [""]
    assert status(unit, ["mac"])["dat"] == [unit.mac]
    assert status(unit, ["hid"])["dat"] == [row["hid"]]
    assert status(unit, ["time"])["dat"] == ["1970-01-01 00:00:00"]


@pytest.mark.parametrize("row", FIXTURE["sources"], ids=lambda row: row["build"])
def test_requested_ack_and_independent_fresh_getter(row):
    unit = device(row["build"])
    result = send(unit, row["command"]["request"])
    if row["build"] == "an":
        assert result == row["command"]["replies"]
    else:
        assert result[0].inner == row["command"]["reply"]
    assert status(unit, ["Pow", "Pow"])["dat"] == row["command"]["fresh_data"]
    assert status(device("an"), ["Pow"])["dat"] == [0]


def test_an_cross_field_coercion_and_synthetic_button_lifecycle():
    unit = device("an")
    assert send(unit, {"t": "cmd", "opt": ["Mod", "WdSpd", "Studied"], "p": [2, 7, 2]}) == []
    assert status(unit, ["Mod", "WdSpd", "Studied"])["dat"] == [2, 1, 0]
    send(unit, {"t": "cmd", "opt": ["AddButton", "ConBtnNum", "ConBtnName"], "p": [1, 1, "Synthetic"]})
    assert status(unit, ["RefBtnList"])["dat"] == [[1], ["Synthetic"]]
    send(unit, {"t": "cmd", "opt": ["DelButton"], "p": [1]})
    assert status(unit, ["RefBtnList"])["dat"] == [[], []]
    assert status(device("an"), ["RefBtnList"])["dat"] == [[], []]


def test_mesh_string_writes_and_numeric_hidden_slots_are_separate():
    unit = device("g")
    reply, = send(unit, {"t": "cmd", "opt": ["Ble", "host", "lat"], "p": ["ABCDEF012345", "example.test", "12.5"]})
    assert reply.inner["p"] == ["abcdef012345", "example.test", "12.5"]
    send(unit, {"t": "cmd", "opt": ["BleStatus"], "p": [65537]})
    assert status(unit, ["Ble", "BleStatus", "host", "lat"])["dat"] == ["abcdef012345", 0, "example.test", "12.5"]
    assert unit.state["_tables"]["slots"]["BleStatus"] == 1


@pytest.mark.parametrize("build", ["an", "g"])
@pytest.mark.parametrize("bad", [True, None, 1.5, [], {}, 1 << 31])
def test_atomic_safety_policy(build, bad):
    unit = device(build)
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        send(unit, {"t": "cmd", "opt": ["Pow", "Mod" if build == "an" else "Mesh_t"], "p": [1, bad]})
    assert unit.state == before and unit.last_step == 1000


@pytest.mark.parametrize("build", ["an", "g"])
def test_transport_identity_key_width_lf_and_unknown_requests(build):
    unit = device(build)
    scan, = unit.profile.handler.advertise(unit, {"t": "scan"})
    assert scan.inner["mid"] == unit.mid and scan.inner["mac"] == unit.mac
    assert scan.inner["vender"] == ("2" if build == "an" else "1")
    bind, = send(unit, {"t": "bind", "mac": unit.mac}, index=2)
    assert bind.inner == {"t": "bindok", "mac": unit.mac, "r": 200, "key": FIXTURE["key"]}
    assert bind.outer["i"] == 1
    assert send(unit, {"t": "unqualified"}) == []
    with pytest.raises(InvalidPacket):
        send(unit, {"t": "status", "cols": ["Pow"]}, tcid="020000000099")
    with pytest.raises(InvalidPacket):
        send(unit, {"t": "status", "cols": ["Pow"], "sub": "020000000099"})
    upgrade, = send(unit, {"t": "upgrade", "url": "https://example.test/image"})
    assert upgrade.outer == {"t": "ret", "r": 200, "mac": unit.mac}
    assert unit.state["_tables"]["upgrade_url"] == "https://example.test/image"


def test_mesh_empty_topology_and_no_invented_companion_ack():
    unit = device("g")
    reply, = send(unit, {"t": "subDev", "i": 0})
    assert reply.inner == FIXTURE["sources"][1]["sublist"]
    raw, = send(unit, {"t": "meshstatus", "meshmac": [unit.mac], "len": [1]})
    assert raw.inner == {"t": "substatus", "mac": unit.mac, "meshmac": [], "status": []}
    for kind in ("bin", "dump", "setT"):
        assert send(unit, {"t": kind}) == []
    with pytest.raises(InvalidPacket):
        status(unit, ["missing"])
    assert status(unit, ["", "BleStatus"])["dat"] == [0]


def test_late_ref_button_loop_and_shape_limits_are_safely_bounded():
    unit = device("an")
    with pytest.raises(InvalidPacket):
        status(unit, ["Pow"]*26 + ["RefBtnList"])
    assert status(unit, ["Pow"]*35)["dat"] == [0]*35
    with pytest.raises(InvalidPacket):
        status(unit, ["Pow"]*342)
    with pytest.raises(InvalidPacket):
        send(unit, {"t": "cmd", "opt": ["Pow", "Mod"], "p": [1]})


def test_metadata_clock_and_wlan_coordinate_storage_are_source_specific():
    unit = device("g")
    reply, = send(unit, {"t": "cmd", "opt": ["time", "name"],
                        "p": ["2026-01-01 00:00:00", "ignored"]})
    assert reply.inner["p"] == ["2026-01-01 00:00:00", ""]
    assert status(unit, ["time", "name"])["dat"] == ["2026-01-01 00:00:00", ""]
    result = unit.profile.handler.handle(unit, {"t": "wlan", "ssid": "synthetic",
        "psw": "", "host": "example.test", "lat": "12.5", "lon": "-6.25"})
    assert result[0].outer == {"t": "ret", "r": 200, "mac": unit.mac}
    assert status(unit, ["host", "lat", "lon"])["dat"] == ["example.test", "12.5", "-6.25"]
    an = device("an")
    send(an, {"t": "cmd", "opt": ["time"], "p": ["2026-01-01 00:00:00"]})
    assert status(an, ["time"])["dat"] == ["1970-01-01 00:00:00"]


def test_state_configuration_preserves_raw_widths_and_empty_mesh_topology():
    for build, state in (("an", {"Pow": -1}), ("an", {"hid": 1}),
                         ("g", {"Subcount": 1}), ("g", {"Ble": "not-hex"})):
        with pytest.raises(ValueError):
            device(build).profile.handler.validate_state(state)
