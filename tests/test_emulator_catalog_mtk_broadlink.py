"""Original callback vectors and independently encrypted RTL8710 wire cases."""
import base64
from copy import deepcopy
import json
from pathlib import Path

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.catalog_mtk import GENERIC_KEY, PROFILES, Broadlink
from gree_emulator.wire import InvalidPacket, encode_reply

VECTORS = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-mtk-broadlink-vectors_research.json").read_text())


@pytest.fixture
def device(monkeypatch):
    monkeypatch.setattr("gree_emulator.profiles.catalog_mtk.monotonic", lambda: 1000)
    profile = next(profile for profile in PROFILES if type(profile.handler) is Broadlink)
    return EmulatedDevice("broad", VECTORS["mac"], "board", "10001", VECTORS["key"].encode(),
                          profile, {}, last_step=1000)


def packet(device, inner, index=0, key=None):
    selected = key if key is not None else GENERIC_KEY if index else device.key
    plain = json.dumps(inner, separators=(",", ":")).encode()
    return {"t": "pack", "i": index, "uid": 37, "cid": "raw-peer", "tcid": device.mac,
            "pack": base64.b64encode(AES.new(selected, AES.MODE_ECB).encrypt(pad(plain, 16))).decode()}


def reply(device, inner, index=0):
    result, = device.profile.handler.handle(device, packet(device, inner, index))
    encoded = encode_reply(result)
    assert not encoded.endswith(b"\n")
    envelope = json.loads(encoded)
    assert {name: value for name, value in envelope.items() if name != "pack"} == {
        "t": "pack", "i": index, "uid": 37, "cid": device.mac, "tcid": "raw-peer"}
    selected = GENERIC_KEY if index else device.key
    return json.loads(unpad(AES.new(selected, AES.MODE_ECB).decrypt(base64.b64decode(envelope["pack"])), 16))


def command(device, names, values):
    return reply(device, {"t": "cmd", "opt": names, "p": values})


def status(device, names):
    return reply(device, {"t": "status", "cols": names})


def test_original_callback_values_and_every_cache_store(device):
    handler = device.profile.handler
    for vector in VECTORS["native_vectors"]:
        cache = [0] * 0x800
        handler._write(cache, vector["name"], vector["p"])
        assert handler._read(cache, vector["name"]) == vector["dat"], vector
        assert [{"offset": offset, "value": value} for offset, value in enumerate(cache) if value] == vector["cache"], vector


def test_platform9_sensor_keeps_encoded_bias_and_sentinel(device):
    handler = device.profile.handler
    cache = handler._cache(device)
    for raw, expected in VECTORS["sensor_vectors"]:
        cache[399] = raw
        assert handler._read(cache, "TemSen") == expected
    assert status(device, ["TemSen", "HumSen", "DwatSen"])["dat"] == [66, 0]


def test_native_scan_bind_and_compiled_hid(device):
    result, = device.profile.handler.advertise(device, {"t": "scan"})
    envelope = json.loads(encode_reply(result))
    assert envelope["i"] == 1
    scan = json.loads(unpad(AES.new(GENERIC_KEY, AES.MODE_ECB).decrypt(base64.b64decode(envelope["pack"])), 16))
    assert scan["cid"] == "" and scan["mid"] == "10001"
    assert "hid" not in scan and "subCnt" not in scan
    bound = reply(device, {"t": "bind", "mac": device.mac}, 1)
    assert bound == {"r": 200, "t": "bindok", "mac": device.mac, "key": VECTORS["key"]}
    assert status(device, ["hid", "mid"])["dat"] == ["362001061383+U-BL3332_JDV18.bin", "10001"]


def test_packed_control_ack_fresh_status_and_case_sensitive_admission(device):
    result = command(device, ["EnvArea1St", "EnvArea4St", "SetTem", "Pow"], [1, 1, 40, 1])
    assert result["p"] == result["val"] == [0, 1, 24, 1]
    result = status(device, ["Pow", "pow", "SetTem", "HumSen", "DwatSen", "AllErr", "Null", "EnvArea1St"])
    assert result["cols"] == ["Pow", "SetTem", "HumSen", "EnvArea1St"]
    assert result["dat"] == [1, 24, 0, 0]
    assert command(device, ["Buzzer_ON_OFF", "StHt"], [3, 1])["val"] == [1, 1]
    assert status(device, ["Buzzer_ON_OFF", "StHt", "SvSt"])["dat"] == [1, 1, 1]


def test_source_specific_mobile_mid_uses_coarse_fan(device):
    device.mid = "13000"
    device.room_c = None
    for requested, expected in ((0, 0), (1, 1), (2, 1), (3, 3), (4, 3), (5, 5)):
        assert command(device, ["WdSpd"], [requested])["val"] == [expected]
        assert status(device, ["WdSpd"])["dat"] == [expected]
    command(device, ["WdSpd"], [2])
    device.mid = "10001"
    assert status(device, ["WdSpd"])["dat"] == [2]


def test_original_metadata_string_array_and_batch_indexing(device):
    result = command(device, ["name", "host"], ["Board Room", "cloud host"])
    assert result["p"] == result["val"] == ["BoardRoom", "BoardRoom"]
    assert status(device, ["name", "host"])["dat"] == ["BoardRoom", "BoardRoom"]
    assert command(device, ["Pow", "name"], [1, "New Name"])["val"] == [1, "NewName"]
    assert command(device, ["Pow", "AutoUpdate"], [1, 0])["val"] == [1, 1]
    assert command(device, ["lock", "Pow"], [1, 0])["val"] == [0, 0]
    assert command(device, ["lock", "Pow"], [0, 1])["val"] == [1, 1]
    assert command(device, ["name", "host"], ["", "Next Host"])["val"] == ["NextHost", "NextHost"]


def test_calendar_write_only_report_and_ignored_mid_do_not_leak_private_state(device):
    assert command(device, ["time"], ["2026-01-02 03:04:05"])["val"] == ["2026-01-02 03:04:05"]
    assert command(device, ["ReportClientID"], ["peer-id"])["val"] == []
    assert status(device, ["ReportClientID", "_report_client_id", "time"])["dat"] == ["2026-01-02 03:04:05"]
    assert command(device, ["mid"], ["99999"])["val"] == ["10001"]
    result = status(device, ["MOta", "Pow"])
    assert result["cols"] == ["MOta", "Pow"] and result["dat"] == [0]


def test_self_enumeration_is_not_a_fabricated_second_device(device):
    for start, expected in ((0, [{"mac": device.mac, "mid": "10001", "name": "GreeHot", "model": "gree", "lock": 0}]), (1, []), (-1, [])):
        assert reply(device, {"t": "subDev", "i": start}) == {"t": "subList", "r": 200, "i": start, "c": 1, "list": expected}


def test_atomic_validation_bad_keys_and_recovery(device):
    status(device, ["Pow"])
    before = deepcopy(device.state)
    for names, values in ((["Pow", "unknown"], [1, 2]), (["Pow"], [True]), (["Pow"], [])):
        with pytest.raises(InvalidPacket):
            command(device, names, values)
        assert device.state == before
    bad = packet(device, {"t": "status", "cols": ["Pow"]}, key=b"wrongkeywrongkey")
    with pytest.raises(InvalidPacket):
        device.profile.handler.handle(device, bad)
    bad = packet(device, {"t": "status", "cols": ["Pow"]})
    bad["cid"] = "x" * 64
    with pytest.raises(InvalidPacket):
        device.profile.handler.handle(device, bad)
    assert status(device, ["Pow"])["dat"] == [0]
