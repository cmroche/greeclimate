"""Literal original-source cache vectors, not profile-generated expectations."""

import base64
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.profiles import catalog_early_frvr as frvr
from gree_emulator.wire import InvalidPacket, encode_reply


FIXTURES = Path(__file__).parent / "fixtures" / "emulator"
KEY = b"0123456789abcdef"
MAC = "020000000001"


def fixture(family):
    return json.loads((FIXTURES / f"catalog-early-frvr-{family}_research.json").read_text())


def device(family):
    evidence = fixture(family)
    profile = next(profile for profile in frvr.PROFILES
                   if profile.source_sha256 == evidence["source_sha256"])
    assert profile.mids == (evidence["configured_mainboard_mid"],)
    return SimpleNamespace(
        mac=MAC, mid=evidence["configured_mainboard_mid"],
        name="FrVr", key=KEY, last_step=1000, profile=profile,
        state=dict(profile.initial_state),
    )


def packet(inner, *, index=0, uid=42, target=MAC, key=None, gcm=False):
    payload = json.dumps(inner, separators=(",", ":")).encode()
    generic = b"{yxAHAY_Lm6pbC/<" if gcm else b"a3K8Bx%2r8Y7#xDh"
    key = key or (generic if index else KEY)
    outer = {"t": "pack", "i": index, "uid": uid, "cid": "app", "tcid": target}
    if gcm:
        cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex("5440784449675a516c5e6313"))
        cipher.update(b"qualcomm-test")
        encrypted, tag = cipher.encrypt_and_digest(payload)
        outer["tag"] = base64.b64encode(tag).decode()
    else:
        encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(payload, 16))
    outer["pack"] = base64.b64encode(encrypted).decode()
    return outer


def exchange(root, inner, **kwargs):
    kwargs.setdefault("gcm", root.profile.handler.vr)
    reply, = root.profile.handler.handle(root, packet(inner, **kwargs))
    raw = encode_reply(reply)
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    outer = json.loads(raw)
    generic = b"{yxAHAY_Lm6pbC/<" if root.profile.handler.vr else b"a3K8Bx%2r8Y7#xDh"
    key = generic if outer["i"] else KEY
    encrypted = base64.b64decode(outer["pack"], validate=True)
    if root.profile.handler.vr:
        cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex("5440784449675a516c5e6313"))
        cipher.update(b"qualcomm-test")
        plain = cipher.decrypt_and_verify(encrypted, base64.b64decode(outer["tag"], validate=True))
    else:
        assert "tag" not in outer
        plain = unpad(AES.new(key, AES.MODE_ECB).decrypt(encrypted), 16)
    result = json.loads(plain)
    assert outer["cid"] == MAC and outer["tcid"] == ""
    return result


@pytest.mark.parametrize("family", ("fr", "vr"))
def test_exact_source_tables_and_every_numeric_cache_vector(family):
    evidence = fixture(family)
    slots = frvr.FR_NUMERIC if family == "fr" else frvr.VR_NUMERIC
    assert list(slots) == evidence["numeric_slots"]
    assert len(slots) == evidence["numeric_bound"]
    root = device(family)
    for vector in evidence["native_numeric_vectors"]:
        name = vector["name"]
        if name in root.profile.handler.special:
            continue  # Exercised separately: local metadata wins over these slots.
        if vector["operation"] == "get":
            root.state[name] = vector["seed"]
        else:
            result = exchange(root, {"t": "cmd", "opt": [name], "p": [vector["input"]]})
            assert result == {"t": "res", "mac": MAC, "p": [vector["input"]],
                              "opt": [name], "r": 200}
            assert root.state[name] == vector["expected"]
        result = exchange(root, {"t": "status", "cols": [name]})
        assert result == {"t": "dat", "uid": 42, "mac": MAC, "cid": MAC,
                          "dat": [vector["expected"]], "cols": [name], "r": 200}


@pytest.mark.parametrize("family", ("fr", "vr"))
def test_special_precedence_hid_initializer_and_empty_serializer_callbacks(family):
    root = device(family)
    root.state.update({"hid": 65535, "name": 65535, "mid": 65535, "AppTimer": 65535})
    result = exchange(root, {"t": "status", "cols": ["Pow", "hid", "DevID", "MafIdf",
                                                       "MOta", "name", "AppTimer", "Pow"]})
    assert result["cols"] == ["Pow", "hid", "DevID", "MafIdf", "MOta", "name", "AppTimer", "Pow"]
    assert result["dat"] == [0, fixture(family)["hid"], "FrVr", 0, 0]
    assert exchange(root, {"t": "status", "cols": ["unknown", "hid"]})["cols"] == ["hid"]


@pytest.mark.parametrize("family", ("fr", "vr"))
def test_signed_duplicates_ack_requested_and_fresh_unsigned_cache(family):
    root = device(family)
    response = exchange(root, {"t": "cmd", "opt": ["Pow", "Pow", "Pow"], "p": [7, 65537, -1]})
    assert response == {"t": "res", "mac": MAC, "p": [7, 65537, -1],
                        "opt": ["Pow", "Pow", "Pow"], "r": 200}
    assert exchange(root, {"t": "status", "cols": ["Pow", "Pow"]})["dat"] == [65535, 65535]
    assert "val" not in response


@pytest.mark.parametrize("family", ("fr", "vr"))
def test_metadata_reordering_and_synthetic_calendar(family):
    root = device(family)
    response = exchange(root, {"t": "cmd", "opt": ["Pow", "name", "Mod"],
                               "p": [65537, "ignored", -1]})
    assert response["opt"] == ["name", "Pow", "Mod"]
    assert response["p"] == ["FrVr", 65537, -1]
    root.last_step += 2
    assert exchange(root, {"t": "status", "cols": ["time"]})["dat"] == ["2026-01-01 00:00:02"]
    if family == "fr":
        assert exchange(root, {"t": "cmd", "opt": ["time"], "p": ["ignored"]})["p"] == ["2026-01-01 00:00:02"]
        assert root.state["_runtime"]["time_sync_pending"]


@pytest.mark.parametrize("family", ("fr", "vr"))
@pytest.mark.parametrize("value", (True, None, 1.5, [], {}, 2147483648, -2147483649))
def test_invalid_scalar_is_atomic(family, value):
    root = device(family)
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "cmd", "opt": ["Pow", "Mod"], "p": [1, value]})
    assert root.state == before


@pytest.mark.parametrize("family", ("fr", "vr"))
def test_unknown_companion_command_no_fake_ack(family):
    root = device(family)
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket, match="mainboard boundary"):
        exchange(root, {"t": "cmd", "opt": ["Pow", "unknown"], "p": [1, 2]})
    assert root.state == before
    assert root.profile.handler.handle(root, packet(
        {"t": "not-registered"}, gcm=root.profile.handler.vr)) == []


@pytest.mark.parametrize("family", ("fr", "vr"))
def test_binding_session_target_isolation_and_restart(family):
    root, second = device(family), device(family)
    for selector in (0, 1):
        assert exchange(root, {"t": "bind", "mac": MAC}, index=selector)["key"] == KEY.decode()
    for selector in (2, -1, 256):
        before = deepcopy(root.state)
        with pytest.raises(InvalidPacket, match="session selector"):
            exchange(root, {"t": "bind", "mac": MAC}, index=selector)
        assert root.state == before
    exchange(root, {"t": "cmd", "opt": ["Pow"], "p": [-1]})
    assert root.state["Pow"] == 65535 and second.state["Pow"] == 0
    assert device(family).state["Pow"] == 0
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        root.profile.handler.handle(root, packet({"t": "status", "cols": ["hid"]}, target="020000000002"))
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "cmd", "mac": "020000000002", "opt": ["Pow"], "p": [0]})
    assert root.state == before


def test_source_specific_names_and_untyped_temperature_readouts():
    fr, vr = device("fr"), device("vr")
    assert "TemSen" not in fr.profile.handler.numeric
    for name in ("TemBody", "InTem", "TemSor"):
        fr.state[name] = 32768
        assert exchange(fr, {"t": "status", "cols": [name]})["dat"] == [32768]
    vr.state["TemSen"] = 255
    assert exchange(vr, {"t": "status", "cols": ["TemSen", "NoD"]})["dat"] == [255, 0]
    assert frvr.VR_NUMERIC.index("NoD") == 57
    assert frvr.VR_NUMERIC[59] == "Buzzer_ON_OFF"
    assert frvr.FR_NUMERIC[330] == "Buzzer_ON_OFF"


def test_fr_source_profile_metadata_raw_frames_alias_and_restart():
    evidence = json.loads((FIXTURES / "catalog-early-frvr-wire_research.json").read_text())["fr"]
    root = device("fr")
    profile = frvr.PROFILES[0]
    assert profile.id == "sim-wb05fr-v1.40-4005"
    assert profile.mids == ("4005",)
    assert profile.source_sha256 == evidence["source_sha256"]
    reply, = root.profile.handler.advertise(root, {"t": "scan"})
    assert reply.inner == evidence["discovery"]
    assert exchange(root, evidence["subdev_request"]) == evidence["subdev_response"]
    assert exchange(root, {"t": "subDev", "i": 1}) == {
        "t": "subList", "r": 200, "c": 1, "i": 1, "list": [],
    }
    assert exchange(root, evidence["binary_request"]) == evidence["binary_response"]
    assert root.state["_runtime"]["frames"]["hex01"].hex() == evidence["binary_primary_after_hex"]
    assert root.state["_runtime"]["raw_pending"]
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        exchange(root, {"t": "binCmd", "hex01": "fn4GAQIDBAU="})
    assert root.state == before
    assert exchange(root, evidence["dump_request"]) == evidence["dump_response"]
    assert root.state["_runtime"]["dump_period"] == evidence["dump_cache"]["period"]
    assert root.state["_runtime"]["dump_count"] == evidence["dump_cache"]["cnt"]
    result = exchange(root, {"t": "cmd", "sub": MAC + "00", "opt": ["Pow"], "p": [-1]})
    assert result["mac"] == MAC + "00" and result["p"] == [-1]
    assert exchange(root, {"t": "status", "cols": ["Pow"]})["dat"] == [65535]
    assert exchange(root, evidence["reset_request"]) == evidence["reset_response"]
    assert root.state["Pow"] == 0 and "_runtime" not in root.state


def test_vr_literal_timer_storage_masks_update_query_delete_and_calendar():
    evidence = json.loads((FIXTURES / "catalog-early-frvr-wire_research.json").read_text())["vr"]
    root = device("vr")
    assert evidence["configured_mid"] == "11f00"
    assert root.profile.id == "sim-wb65vr-v1.02-11f00"
    reply, = root.profile.handler.advertise(root, {"t": "scan"})
    assert reply.inner == evidence["discovery"]
    assert exchange(root, {"t": "status", "cols": ["bc", "mid", "ver", "host"]})["dat"] == [
        "67726565", "", "V2.0.0", "dis.gree.com",
    ]
    assert exchange(root, evidence["timer_set"]) == evidence["timer_ack"]
    assert exchange(root, evidence["timer_query"]) == evidence["timer_response"]
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        exchange(root, evidence["timer_set"])
    assert root.state == before
    update = {**evidence["timer_set"], "t": "updateT", "name": "updated", "enable": 0}
    assert exchange(root, update) == evidence["timer_ack"]
    result = exchange(root, evidence["timer_query"])
    assert result["list"][0]["name"] == "updated" and result["list"][0]["enable"] == 0
    assert exchange(root, evidence["timer_delete"]) == evidence["timer_ack"]
    assert exchange(root, evidence["timer_query"]) == evidence["timer_empty"]
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket, match="underflow"):
        exchange(root, evidence["timer_delete"])
    assert root.state == before
    assert exchange(root, evidence["time_request"]) == evidence["time_response"]
    root.last_step += 2
    assert exchange(root, {"t": "status", "cols": ["time"]})["dat"] == ["2026-03-01 00:00:01"]


def test_vr_udp_mode2_is_fixed_by_transport_not_tag_negotiation():
    root = device("vr")
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket):
        root.profile.handler.handle(root, packet({"t": "cmd", "opt": ["Pow"], "p": [0]}))
    assert root.state == before
    evidence = json.loads((FIXTURES / "catalog-early-frvr-wire_research.json").read_text())["vr"]
    request = evidence["literal_gcm_status_request"]
    reply, = root.profile.handler.handle(root, request)
    assert reply.codec == "aes-gcm" and reply.inner["dat"] == [0]
    before = deepcopy(root.state)
    tampered = {**request, "tag": base64.b64encode(bytes(16)).decode()}
    with pytest.raises(InvalidPacket):
        root.profile.handler.handle(root, tampered)
    assert root.state == before
    discovery, = root.profile.handler.advertise(root, {"t": "scan"})
    assert discovery.codec == "aes-ecb-pkcs7"


def test_write_only_raw_callbacks_omit_ack_names_but_mutate_source_frames():
    for family in ("fr", "vr"):
        root = device(family)
        reply = exchange(root, {"t": "cmd", "opt": ["ReportClientID"],
                                "p": ["02000000000100"]})
        assert reply == {"t": "res", "mac": MAC, "p": [], "opt": [], "r": 200}
        assert root.state["_runtime"]["frames"]["ReportClientID"].hex() == (
            "7e7e126a30323030303030303030303130300000")
        assert exchange(root, {"t": "status", "cols": ["ReportClientID", "hid"]})["cols"] == ["hid"]
    root = device("vr")
    reply = exchange(root, {"t": "cmd", "opt": ["Onoff"], "p": ['["01021aF"]']})
    assert reply == {"t": "res", "mac": MAC, "p": [], "opt": [], "r": 200}
    assert [frame.hex() for frame in root.state["_runtime"]["onoff_frames"]] == [
        "00f10201060001053002010a",
    ]
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket, match="seven-hex"):
        exchange(root, {"t": "cmd", "opt": ["Onoff"], "p": ['["bad"]']})
    assert root.state == before


def test_vr_metadata_duplicates_read_final_shared_cache_and_raw_batch_order():
    root = device("vr")
    result = exchange(root, {"t": "cmd", "opt": ["host", "Pow", "host", "BleON", "Mesh"],
                            "p": ["one", 65537, "two", "010203040506", "112233445566"]})
    assert result["opt"] == ["host", "host", "BleON", "Mesh", "Pow"]
    assert result["p"] == ["two", "two", "112233445566", 0, 65537]
    assert exchange(root, {"t": "status", "cols": ["host", "Pow", "BleON", "Mesh"]})["dat"] == [
        "two", 1, "112233445566", 0,
    ]
    result = exchange(root, {"t": "cmd", "opt": ["Onoff", "Onoff"],
                            "p": ['["01021a0"]', '["01021aF"]']})
    assert result["opt"] == [] and result["p"] == []
    assert [frame.hex() for frame in root.state["_runtime"]["onoff_frames"]] == [
        "00020201060001053002010a", "00f10201060001053002010a",
    ]


def test_fr_literal_raw_bind_status_optional_frame_and_source_no_reply_heartbeat():
    evidence = json.loads((FIXTURES / "catalog-early-frvr-wire_research.json").read_text())["fr"]
    root = device("fr")
    assert exchange(root, evidence["bindok_request"]) == evidence["bindok_response"]
    assert exchange(root, {"t": "status", "cols": ["lock"]})["dat"] == [1]
    reply, = root.profile.handler.advertise(root, {"t": "scan"})
    assert reply.inner["lock"] == 0
    assert exchange(root, evidence["auxiliary_binary_request"]) == {"t": "res", "r": 200}
    assert exchange(root, evidence["bindok_request"]) == {
        **evidence["bindok_response"], "binStatus": evidence["bindok_auxiliary_payload"],
    }
    assert exchange(root, evidence["bindok_request"]) == evidence["bindok_response"]
    exchange(root, {"t": "dump", "period": 10, "cnt": 1})
    assert root.state["_runtime"]["dump_pending"] is True
    assert root.profile.handler.handle(root, packet({"t": "hbok"})) == []
    assert root.state["_runtime"]["dump_pending"] is False
    before = deepcopy(root.state)
    with pytest.raises(InvalidPacket, match="companion boundary"):
        exchange(root, {"t": "upgrade", "url": "https://example.invalid/fw.bin"})
    assert root.state == before


def test_fr_ble_gnet_provisioning_is_not_a_registered_udp_operation():
    root = device("fr")
    before = deepcopy(root.state)
    request = {"t": "GnetDev", "host": "dis.gree.com", "ssid": "synthetic",
               "psw": "synthetic", "GnetKey": "0123456789abcdef", "GnetID": 1}
    assert root.profile.handler.handle(root, packet(request)) == []
    assert root.state == before
    assert root.profile.mids == ("4005",)
