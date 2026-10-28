"""Source-qualified MF4 CLI and capture-only row-six acceptance."""

import asyncio
import base64
import copy
import json
from pathlib import Path
import socket

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.__main__ import load_config
from gree_emulator.server import EmulatorServer
from greeclimate.cipher import CipherV1
from greeclimate.device import Device
from greeclimate.deviceinfo import DeviceInfo
from tests.test_emulator_firmware_cli import (
    cli_profiles,
    cli_server,
    packet,
    unpack,
)


FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "emulator" /
                      "catalog-realtek-middle-wb-mf4_research.json").read_text())
SOURCES = tuple(row for row in FIXTURE["profiles"]
                if row["assessment_index"] in (5, 6, 16))
CLI_SOURCES = tuple(row for row in SOURCES if row["assessment_index"] in (5, 16))
SOURCE_BY_INDEX = {row["assessment_index"]: row for row in SOURCES}
MAC = "020000000001"
PEER = "mf4-cli-independent-peer"
GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
MAX_DATAGRAM = 1460
EXPECTED_OPERATIONS = {
    5: ["bind", "status", "freqCount", "cmd", "upgrade", "ReportCtrl",
        "ReportLimit", "reset", "lifeCycle", "binCmd", "scan", "UBindok", "hbok",
        "setT", "queryT", "deleteT", "updateT"],
    6: ["bind", "status", "freqCount", "cmd", "upgrade", "dump", "ReportCtrl",
        "ReportLimit", "reset", "lifeCycle", "binCmd", "scan", "UBindok", "hbok",
        "networkInfo", "loginInfoRes", "statusCheck", "setT", "queryT", "deleteT", "updateT"],
    16: ["bind", "status", "cmd", "upgrade", "dump",
         "setT", "queryT", "deleteT", "updateT"],
}

# Independent finite source-table expectations, kept literal rather than read
# from the production handler. HR inserts its four source-specific names before Dmod.
MA_NAMES = tuple("""
Pow Mod SetTem WdSpd Tur Quiet SwUpDn SwingLfRig Add0.5 TemUn TemRec Lig Air Blo Health SvSt
SwhSw HeatCoolType StHt LTemDry Wet SwhSlp SlpMod HasTmr TmrLpTms TmrOff TmrOn CurTmHor CurTmMin
TmrOnHorLf TmrOnMinLf TmrOffHorLf TmrOffMinLf DsplySt EnvFun JFErrorCode AssHt SwhFreAir AllErr
Coolmod HeatCool LedLig SmartMod Add0.1 ModelType NoD Buzzer_ON_OFF ElcEn EnvTem DFPoint CpsTem
TemsSenOut FaultDisplay Wind UDFanPort DnPUDSwing DnPLLRSwing DnPRLRSwing AirQ PM2P5 ElcDatHor
ElcDatDte ElcDatMth HumSen ElcP ElcOnKwh ElcAllKwhClr ElcAllKwhH ElcAllKwhL AutoClean TemSen
Emod PctCleOnTm EvapClr NobodySave BlkTemCom HabitLearn SmartWind HandCtl VocCtl VocIdiom VocRole
ImgUpdateCol EnvArea1St EnvArea2St EnvArea3St EnvArea4St EnvArea5St EnvArea6St EnvArea7St EnvArea8St
EnvArea9St FbidBloPer DIYGra1PoiAmo SwhDIYGra1 Slp1L1 Slp1H1 Slp1L2 Slp1H2 Slp1L3 Slp1H3 Slp1L4
Slp1H4 Slp1L5 Slp1H5 Slp1L6 Slp1H6 Slp1L7 Slp1H7 Slp1L8 Slp1H8 ImgVerSta VocUpdateCol VocVerSta
LigSen Video PctCleSetTm AppTimer CO2Level Dazzling NewTimer NewTimerSet UvcControl MasSub MasIDUMod
GetEr HeatSvStTemMax HumiSvStTemMin CoolSvStTemMin Wmod WsetTmp WschOn WschOnMin WschOff WschOffMin
Wtmr1 Wtmr1Min Wtmr2 Wtmr2Min Wtmr3 Wtmr3Min WsenTmpH WsenTmpM WsenTmpL Werr WsenNub WstpSv WstpH
WatTmp MaeS FanMod ModS VitiGr GasN TemSor HumSor PM2P5V VOC CO2 PctCle PctRe IDUAirQu AirQu ODUViti
GasAvail GasLED GasMod GasMas PM2P5Sta SorErr CommErr EnergyFlow Dmod Dfltr Dpump Dwet DwatFul DwatSen
estateInsta21 estateInsta22 estateInsta23 estateInsta24 ChildLock Smod Sfog RemWarnLig Security SecurityMode
ImageRecovery Srst Swat Swash SrstPP SrstPF SrstCF SrstRF SrstAF MakeWat WatErr mode wspd light StTmr
fltrst wipm25 wopm25 estate airQlt Purify ImgUpdateSucs VocUpdateRes MicroSen ReplaceHEPA
UnmanedShutDown UnmanedOffTime PMVComfort Defrost Antifreeze FavorMode ImgUpdateSta ImgUpdateFail
VocUpdateSta SmartSlpMod SmartSlpModEx StSlp1C StSlp1CInc StSlp1CSp StSlp1H StSlp1HInc StSlp1HSp
StSlp2C StSlp2CInc StSlp2CSp StSlp2H StSlp2HInc StSlp2HSp StSlp3C StSlp3CInc StSlp3CSp StSlp3H
StSlp3HInc StSlp3HSp StSlp4C StSlp4CInc StSlp4CSp StSlp4H StSlp4HInc StSlp4HSp AntiDirectBlow
SwhWifi SwhWifiRe SwhWifiCo datDump datRep datFailRe datPeroid subCnt HidDownPer InHidDownPer OEEPHidDownPer
ACStupPos SaveGuid NoiseSet RoomLen RoomWid RoomHigh CoolNoise HeatNoise ElcErg ElcGear Elc1Kwh AutoUpdate
AutoComnCloud lock apssid appsw host name time lat lon vender bc mid model series brand catalog country hid mac
ver HidSvrVer InHid InHidSvrVer OEEPHid OEEPHidSvrVer DevID MafIdf MidType rssi
""".split())
Dmod_index = MA_NAMES.index("Dmod")
HR_NAMES = (MA_NAMES[:Dmod_index] +
            ("OutEnvTem", "InEvaTem", "CompressorTem", "CompressorFqy") +
            MA_NAMES[Dmod_index:])
NAMES_BY_INDEX = {5: MA_NAMES, 6: MA_NAMES, 16: HR_NAMES}


EMPTY_GETTERS = frozenset(("DevID", "MafIdf"))


def _source(index):
    return SOURCE_BY_INDEX[index]


def _record(source, *, logical_id=None, state=None):
    configured_state = {"mcu_mid_raw": 0}
    if state is not None:
        configured_state.update(state)
    return {
        "id": logical_id or f"mf4-row-{source['assessment_index']}",
        "profile": source["id"],
        # 10001 is the configured selector and conditional zero-MID retry fallback,
        # not a universal physical appliance MID.
        "mid": "10001",
        "mac": MAC,
        "state": configured_state,
    }


def _decrypt_wire(data, key):
    outer = json.loads(data)
    ciphertext = base64.b64decode(outer["pack"], validate=True)
    plaintext = unpad(AES.new(key, AES.MODE_ECB).decrypt(ciphertext), AES.block_size)
    assert plaintext.endswith(b"}") and not plaintext.endswith(b"}\n")
    assert not data.endswith(b"\n")
    return outer, json.loads(plaintext), plaintext


def _wire_reply(sock, address, key):
    data, sender = sock.recvfrom(65535)
    assert sender == address
    outer, inner, _ = _decrypt_wire(data, key)
    # Keep the shared peer-side decoder in the acceptance path as well as the
    # raw consumer check above; both must agree on the independent AES result.
    assert unpack(data, key) == (outer, inner)
    return outer, inner


def _exchange(sock, address, inner, key, *, selector=0, outer=None, gcm=False):
    if outer is None:
        outer = {"t": "pack", "i": selector, "uid": 7,
                 "cid": PEER, "tcid": MAC}
    encoded = packet(outer, inner, key, gcm=gcm)
    assert len(encoded) <= MAX_DATAGRAM
    sock.sendto(encoded, address)
    return _wire_reply(sock, address, key)


def _exchange_raw(sock, address, outer, inner_json, key):
    plain = inner_json.encode("utf-8") if isinstance(inner_json, str) else inner_json
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(plain, AES.block_size))
    encoded = json.dumps({**outer, "pack": base64.b64encode(encrypted).decode("ascii")},
                         separators=(",", ":")).encode("ascii")
    assert len(encoded) <= MAX_DATAGRAM
    sock.sendto(encoded, address)
    return _wire_reply(sock, address, key)


def _quiet(sock):
    timeout = sock.gettimeout()
    sock.settimeout(0.15)
    try:
        with pytest.raises(socket.timeout):
            sock.recvfrom(65535)
    finally:
        sock.settimeout(timeout)


def _no_reply(sock, address, encoded):
    sock.sendto(encoded, address)
    _quiet(sock)


def _raw_request(inner_json, *, selector, key, uid=7, cid=PEER):
    plain = inner_json.encode("utf-8") if isinstance(inner_json, str) else inner_json
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(plain, AES.block_size))
    return json.dumps({"t": "pack", "i": selector, "uid": uid, "cid": cid,
                       "tcid": MAC, "pack": base64.b64encode(encrypted).decode("ascii")},
                      separators=(",", ":")).encode("ascii")


def _scan(sock, address, source, *, mid, version):
    sock.sendto(b'{"t":"scan"}', address)
    outer, advertisement = _wire_reply(sock, address, GENERIC_KEY)
    assert {name: value for name, value in outer.items() if name != "pack"} == {
        "t": "pack", "i": 1, "uid": 0, "cid": "", "tcid": "",
    }
    assert advertisement == {
        "t": "dev", "cid": "", "bc": "", "brand": "gree", "catalog": "gree",
        "mac": MAC, "mid": mid, "model": "gree", "name": "Synthetic module",
        "lock": 0, "series": "gree", "vender": "", "ver": version, "hid": source["hid"],
    }


def _bind(sock, address, *, selector, key):
    return _exchange(sock, address, {"t": "bind", "mac": MAC}, key, selector=selector)


def _expected_status(source, names, *, version=None):
    view = FIXTURE["chosen_virtual_readouts"]
    metadata = dict(view["status_text"])
    metadata.update(view["special"])
    metadata["hid"] = source["hid"]
    metadata["ver"] = (view["constructor_versions"]["row_16"]["dev_version_initial"]
                        if source["assessment_index"] == 16 else
                        view["constructor_versions"]["rows_5_6"]["dev_version_initial"])
    if version is not None:
        metadata["ver"] = version
    if source["assessment_index"] == 16:
        metadata.update(view["strings"])
    raw_defaults = view["raw"]
    return (
        [metadata[name] for name in names if name in metadata and name not in EMPTY_GETTERS]
        + [raw_defaults.get(name, 0) for name in names
           if name not in metadata and name not in EMPTY_GETTERS]
    )


def _query_names(sock, address, source, key, names, *, selector=0):
    for start in range(0, len(names), 22):
        columns = list(names[start:start + 22])
        _, response = _exchange(sock, address, {
            "t": "status", "mac": MAC, "cols": columns,
        }, key, selector=selector)
        assert response == {
            "t": "dat", "uid": 0, "mac": MAC, "cid": MAC,
            "dat": _expected_status(source, columns), "cols": columns, "r": 200,
        }


def _schedule(timer_id, *, name, enable, hour, minute, week, option="Pow", value=4,
              kind="setT"):
    return {
        "t": kind, "mac": MAC, "id": timer_id, "name": name,
        "enable": enable, "tz": 9, "hr": hour, "min": minute, "sec": 41,
        "week": week, "cmd": [{"opt": [option], "p": [value]}],
    }


def _expected_ubind(*, route_word, word2, readouts, identities, client_text=None,
                    first_frame=bytes(3)):
    header = bytearray(39)
    header[:2] = b"fg"
    for offset, identity in zip((4, 10, 16), identities):
        header[offset:offset + 6] = bytes.fromhex(identity)
    header[22:26] = route_word.to_bytes(4, "big")
    header[26:30] = word2.to_bytes(4, "big")
    header[30], header[32] = 2, 0x32
    header[33:38] = bytes(value & 255 for value in readouts)
    header[38] = 2
    payload = bytes(header) + first_frame + bytes(12)
    if client_text is not None:
        client = bytearray(30)
        client[:4] = b"\x7e\x7e\x12\x6a"
        client[4:4 + len(client_text)] = client_text.encode("utf-8")
        payload += bytes(client[:client[2] + 3])
    length = len(payload) + 2
    encoded_length = bytearray()
    while length >= 0x80:
        encoded_length.append((length & 0x7f) | 0x80)
        length >>= 7
    encoded_length.append(length)
    packet_bytes = b"\x00\x01\x00" + bytes(encoded_length) + b"\x01\x00" + payload
    return {
        "t": "binStatus", "binStatus": base64.b64encode(packet_bytes).decode("ascii"),
        "header": base64.b64encode(header).decode("ascii"), "mac": MAC,
    }


def test_mf4_registered_nodes_and_source_qualified_namespace_counts():
    listed = cli_profiles()
    assert len(SOURCES) == 3
    assert {row["assessment_index"] for row in SOURCES} == {5, 6, 16}
    for source in SOURCES:
        rows = listed[source["id"]]
        assert len(rows) == 1
        assert rows[0]["profile"] == source["id"]
        assert rows[0]["role"] == "standalone"
        assert rows[0]["hid"] == source["hid"]
        assert rows[0]["mid"] == "10001"
        assert len(NAMES_BY_INDEX[source["assessment_index"]]) == source["raw_name_count"]
        assert source["registered_operations"] == EXPECTED_OPERATIONS[source["assessment_index"]]
    assert len(MA_NAMES) == FIXTURE["raw_names"]["ma170_ma183"] == 301
    assert len(HR_NAMES) == FIXTURE["raw_names"]["wb05hr"] == 305
    assert MAX_DATAGRAM == 1460
    assert "255.255.255.255:5000" in FIXTURE["wire"]["reply_route"]


@pytest.mark.parametrize("source", CLI_SOURCES, ids=lambda row: row["id"])
def test_mf4_actual_cli_complete_native_getter_namespace_and_ragged_columns(source):
    index = source["assessment_index"]
    names = NAMES_BY_INDEX[index]
    assert len(names) == source["raw_name_count"]
    record = _record(source)
    with cli_server([record]) as (address, identities), socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(2)
        assert identities[record["id"]]["mid"] == "10001"
        # The configured zero MCU word takes the exact-source retry-count >5
        # fallback; it is not a firmware-wide or physical MID default.
        _scan(peer, address, source, mid="10001",
              version="V3.0.0" if index == 16 else "V3.4.M")

        outer, bound = _bind(peer, address, selector=1, key=GENERIC_KEY)
        assert {name: value for name, value in outer.items() if name != "pack"} == {
            "t": "pack", "i": 1, "uid": 7, "cid": MAC, "tcid": PEER,
        }
        assert bound["r"] == 200 and bound["t"] == "bindok" and bound["mac"] == MAC
        key = bound["key"].encode("ascii")
        assert len(key) == 16
        _, paired = _bind(peer, address, selector=0, key=key)
        assert paired["t"] == "bindok" and paired["key"] == bound["key"]
        _, generic_status = _exchange(peer, address, {
            "t": "status", "mac": MAC, "cols": ["Pow"],
        }, GENERIC_KEY, selector=1)
        assert generic_status["dat"] == [0]

        _query_names(peer, address, source, key, names)
        _, repeated = _exchange(peer, address, {
            "t": "status", "mac": MAC,
            "cols": ["Pow", "mid", "DevID", "SetTem", "Pow", "MafIdf", "NoD", "rssi"],
        }, key)
        assert repeated["cols"] == ["Pow", "mid", "DevID", "SetTem", "Pow", "MafIdf", "NoD", "rssi"]
        assert repeated["dat"] == ["", -55, 0, 24, 0, 0]
        assert "val" not in repeated
        _, unknown = _exchange(peer, address, {
            "t": "status", "mac": MAC, "cols": ["unlisted-mf4-name"],
        }, key)
        assert unknown["cols"] == ["unlisted-mf4-name"] and unknown["dat"] == []


@pytest.mark.parametrize("source", CLI_SOURCES, ids=lambda row: row["id"])
def test_mf4_actual_cli_advertised_mid_is_separate_from_profile_and_status_mid(source):
    record = _record(source, state={"mcu_mid_raw": 0x1234abcd})
    with cli_server([record]) as (address, identities), socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(2)
        # 10001 is only this profile's configured selection/fallback value.
        assert identities[record["id"]]["mid"] == "10001"
        version = "V3.0.0" if source["assessment_index"] == 16 else "V3.4.M"
        _scan(peer, address, source, mid="1234abcd", version=version)
        _, bound = _bind(peer, address, selector=1, key=GENERIC_KEY)
        key = bound["key"].encode("ascii")
        _, status = _exchange(peer, address, {
            "t": "status", "mac": MAC, "cols": ["mid", "hid"],
        }, key)
        assert status["dat"] == ["", source["hid"]]
        assert status["dat"][0] != identities[record["id"]]["mid"]


@pytest.mark.parametrize("source", CLI_SOURCES, ids=lambda row: row["id"])
def test_mf4_actual_cli_numeric_command_shapes_and_source_operations(source):
    index = source["assessment_index"]
    state = {}
    if index == 5:
        state.update(
            gnet_id=1,
            report_route_word=255,
            freq_secondary_ready=True,
            ubind_identity1="010203040506",
            ubind_identity2="111213141516",
            ubind_identity3="a1a2a3a4a5a6",
            ubind_word2=0x87654321,
            ubind_readouts=[0x101, 0x202, 0x303, 0x404, 0x505],
        )
    else:
        state["hr_persist_gate_word"] = 0x5b03b45c
    record = _record(source, state=state)
    operations = source["registered_operations"]
    assert operations == EXPECTED_OPERATIONS[index]
    assert "bind" in operations and "status" in operations and "cmd" in operations
    assert "setT" in operations and "queryT" in operations
    with cli_server([record]) as (address, identities), socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(2)
        _scan(peer, address, source, mid="10001",
              version=("V3.4.MF4" if index == 5 else "V3.0.0"))
        _, bound = _bind(peer, address, selector=1, key=GENERIC_KEY)
        key = bound["key"].encode("ascii")
        outer = {"t": "pack", "i": 0, "uid": 7, "cid": PEER, "tcid": MAC}

        # Row 5/16 accept selector 0 private and selector 1 static a3 generic keys.
        header, command = _exchange(peer, address, {
            "t": "cmd", "mac": MAC, "opt": ["Pow", "Mod", "SetTem"],
            "p": [2147483648, 1000, 4294967295],
        }, key)
        assert header["i"] == 0
        assert command == {"t": "res", "mac": MAC, "opt": ["Pow", "Mod", "SetTem"],
                          "p": [-2147483648, 1000, -1], "r": 200}
        _, precedence = _exchange(peer, address, {
            "t": "cmd", "mac": MAC, "cols": ["Pow"], "opt": ["Mod"], "p": [9],
        }, key)
        assert precedence == {"t": "res", "mac": MAC, "opt": ["Pow"], "p": [9], "r": 200}
        _, readback = _exchange(peer, address, {
            "t": "status", "mac": MAC, "cols": ["Pow", "Mod", "SetTem"],
        }, key)
        assert readback["dat"] == [9, 1000, 65535]
        _, lexical = _exchange_raw(peer, address, outer,
                                   '{"t":"cmd","mac":"020000000001","opt":["Pow","Mod"],"p":[1e3,2]}',
                                   key)
        assert lexical["p"] == [1, 2]
        _, lexical_state = _exchange(peer, address, {
            "t": "status", "mac": MAC, "cols": ["Pow", "Mod"],
        }, key)
        assert lexical_state["dat"] == [1, 2]
        _, metadata_write = _exchange(peer, address, {
            "t": "cmd", "mac": MAC, "opt": ["name", "AppTimer"],
            "p": ["ignored name", "ignored timer"],
        }, key)
        assert metadata_write["p"] == ["Synthetic module", 0]
        _, metadata_read = _exchange(peer, address, {
            "t": "status", "mac": MAC, "cols": ["name", "AppTimer"],
        }, key)
        assert metadata_read["dat"] == ["Synthetic module", 0]

        if index == 16:
            _, modeltype = _exchange(peer, address, {
                "t": "cmd", "mac": MAC, "opt": ["ModelType"], "p": ["ignored"],
            }, key)
            assert modeltype["p"] == [""]
            _, time_ack = _exchange(peer, address, {
                "t": "cmd", "mac": MAC, "opt": ["time"], "p": ["2026-01-01 12:34:56"],
            }, key)
            assert time_ack["p"] == ["2026-01-01 12:34:56"]
            _, time_read = _exchange(peer, address, {
                "t": "status", "mac": MAC, "cols": ["time"],
            }, key)
            assert time_read["dat"] == ["2026-01-01 12:34:56"]
            assert "dump" in operations
            _, dump = _exchange(peer, address, {"t": "dump", "period": 1, "cnt": 40000}, key)
            assert dump == {"t": "ret", "r": 200}
            assert "upgrade" in operations
            _, upgrade = _exchange(peer, address, {"t": "upgrade", "url": "synthetic-firmware"}, key)
            assert upgrade == {"t": "ret", "r": 200}
        else:
            # MA time is a source config request and returns the unchanged virtual RTC.
            _, time_ack = _exchange(peer, address, {
                "t": "cmd", "mac": MAC, "opt": ["time"], "p": ["ignored time text"],
            }, key)
            assert time_ack["p"] == ["2026-01-01 00:00:00"]
            _, time_read = _exchange(peer, address, {
                "t": "status", "mac": MAC, "cols": ["time"],
            }, key)
            assert time_read["dat"] == ["2026-01-01 00:00:00"]
            assert "freqCount" in operations
            _no_reply(peer, address, packet(outer, {
                "t": "freqCount", "cols": ["SendFreq", "FreqTime", "Pow"],
                "p": [1, 30, 4],
            }, key))
            _, freq_read = _exchange(peer, address, {
                "t": "status", "mac": MAC, "cols": ["Pow"],
            }, key)
            assert freq_read["dat"] == [4]
            for operation, body in (
                ("ReportCtrl", {"t": "ReportCtrl", "ActiveTime": 2,
                                 "ReportInterval": 3, "reportAnyway": True}),
                ("ReportLimit", {"t": "ReportLimit", "NRA": [[1, 2, 3], [4, 5, 6]]}),
                ("lifeCycle", {"t": "lifeCycle", "LifeCycleFlag": 0x101,
                                "LifeCycleSwitch": 2}),
                ("hbok", {"t": "hbok"}),
            ):
                assert operation in operations
                _no_reply(peer, address, packet(outer, body, key))
            assert "reset" in operations
            _no_reply(peer, address, packet(outer, {"t": "reset"}, key))
            assert "scan" in operations and "UBindok" in operations and "binCmd" in operations
            _, ubind = _exchange(peer, address, {"t": "scan"}, key)
            assert ubind == {"t": "UBind", "mid": "10001", "ver": "V3.4.MF4",
                             "lock": 0, "devkey": key.decode("ascii"),
                             "hid": source["hid"], "GnetID": 1, "scene": 0}
            _, client_ack = _exchange(peer, address, {
                "t": "cmd", "mac": MAC, "opt": ["ReportClientID"],
                "p": ["source-cli-client"],
            }, key)
            assert client_ack["p"] == []
            _, bin_status = _exchange(peer, address, {"t": "UBindok"}, key)
            assert bin_status["t"] == "binStatus"
            frame = b"~~" + bytes([45]) + bytes(range(44))
            _, staged = _exchange(peer, address, {
                "t": "binCmd", "hex01": base64.b64encode(frame).decode("ascii"),
            }, key)
            assert staged == {"t": "res", "r": 200}
            assert "upgrade" in operations
            _, upgrade = _exchange(peer, address, {"t": "upgrade", "url": "synthetic-firmware"}, key)
            assert upgrade == {"t": "ret", "r": 200}

        assert identities[record["id"]]["mid"] == "10001"


@pytest.mark.parametrize("source", CLI_SOURCES, ids=lambda row: row["id"])
def test_mf4_actual_cli_schedule_lexing_order_crud_and_native_capacity(source):
    record = _record(source)
    with cli_server([record]) as (address, _), socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(2)
        _, bound = _bind(peer, address, selector=1, key=GENERIC_KEY)
        key = bound["key"].encode("ascii")
        outer = {"t": "pack", "i": 0, "uid": 7, "cid": PEER, "tcid": MAC}

        lexical = (
            '{"t":"setT","mac":"020000000001","id":1e3,'
            '"name":"lexical schedule","enable":1.2,"tz":9,'
            '"hr":7.5,"min":8,"sec":41.9,'
            '"week":[1e3,2,0,0,0,0,0],'
            '"cmd":[{"opt":["Pow","Mod"],"p":[1e3,99]},'
            '{"opt":["Pow"],"p":[9]}]}'
        )
        _, created = _exchange_raw(peer, address, outer, lexical, key)
        assert created == {"t": "resT", "r": 200}
        _, first = _exchange(peer, address, {
            "t": "queryT", "mac": MAC, "index": 0, "count": 10,
        }, key)
        first_item = {
            "id": 1, "name": "lexical schedule", "enable": 1,
            "week": [1, 1, 1, 1, 0, 0, 0], "hr": 7, "min": 8, "sec": 0,
            "cmd": [{"opt": ["Pow", "Mod"], "p": [1, 3]}],
            "mac": MAC, "opt": ["Pow", "Mod"], "Pow": 1, "p": [1, 3],
        }
        assert first == {"t": "listT", "total": 1, "index": 0, "list": [first_item]}

        _, created_seven = _exchange(peer, address, _schedule(
            7, name="seven", enable=2, hour=5, minute=6,
            week=[0, 1, 0, 1, 0, 1, 0], value=9,
        ), key)
        assert created_seven == {"t": "resT", "r": 200}
        _, page = _exchange(peer, address, {
            "t": "queryT", "mac": MAC, "index": 2, "count": 2,
        }, key)
        assert page == {"t": "listT", "total": 2, "index": 2, "list": []}

        _, replaced = _exchange(peer, address, _schedule(
            1, name="replacement", enable=0, hour=1, minute=2,
            week=[0, 0, 0, 0, 0, 0, 0], value=8,
        ), key)
        assert replaced == {"t": "resT", "r": 200}
        _, updated = _exchange(peer, address, _schedule(
            1, name="updated", enable=1, hour=8, minute=9,
            week=[1, 0, 0, 0, 0, 0, 0], value=7, kind="updateT",
        ), key)
        assert updated == {"t": "resT", "r": 200}
        _, missing_update = _exchange(peer, address, _schedule(
            9, name="not inserted", enable=1, hour=8, minute=9,
            week=[0, 0, 0, 0, 0, 0, 0], value=7, kind="updateT",
        ), key)
        assert missing_update == {"t": "resT", "r": 200}
        _, ordered = _exchange(peer, address, {
            "t": "queryT", "mac": MAC, "index": 0, "count": 10,
        }, key)
        assert ordered["total"] == 2
        assert [item["id"] for item in ordered["list"]] == [1, 7]
        assert ordered["list"][0] == {
            "id": 1, "name": "updated", "enable": 1,
            "week": [1, 0, 0, 0, 0, 0, 0], "hr": 8, "min": 9, "sec": 0,
            "cmd": [{"opt": ["Pow"], "p": [7]}],
            "mac": MAC, "opt": ["Pow"], "Pow": 7, "p": [7],
        }
        _, missing_delete = _exchange(peer, address, {
            "t": "deleteT", "mac": MAC, "id": 99,
        }, key)
        assert missing_delete == {"t": "resT", "r": 200}
        _, undercount = _exchange(peer, address, {
            "t": "queryT", "mac": MAC, "index": 0, "count": 10,
        }, key)
        assert undercount["total"] == 1 and [item["id"] for item in undercount["list"]] == [1, 7]
        _, non_head_delete = _exchange(peer, address, {
            "t": "deleteT", "mac": MAC, "id": 1,
        }, key)
        assert non_head_delete == {"t": "resT", "r": 200}
        _, empty = _exchange(peer, address, {
            "t": "queryT", "mac": MAC, "index": 0, "count": 10,
        }, key)
        assert empty == {"t": "listT", "total": 0, "index": 0, "list": []}

    # Capacity is a separate fresh process so its ten-record boundary is exact.
    with cli_server([record]) as (address, _), socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(2)
        _, bound = _bind(peer, address, selector=1, key=GENERIC_KEY)
        key = bound["key"].encode("ascii")
        outer = {"t": "pack", "i": 0, "uid": 7, "cid": PEER, "tcid": MAC}
        for timer_id in range(10):
            _, ack = _exchange(peer, address, _schedule(
                timer_id, name=f"timer-{timer_id}", enable=1, hour=1, minute=2,
                week=[0, 0, 0, 0, 0, 0, 0], value=4,
            ), key)
            assert ack == {"t": "resT", "r": 200}
        full_request = packet(outer, _schedule(
            0, name="cannot replace at capacity", enable=1, hour=3, minute=4,
            week=[0, 0, 0, 0, 0, 0, 0], value=5,
        ), key)
        _no_reply(peer, address, full_request)
        pages = []
        for index in range(10):
            _, page = _exchange(peer, address, {
                "t": "queryT", "mac": MAC, "index": index, "count": 1,
            }, key)
            assert page["total"] == 10 and page["index"] == index
            assert len(page["list"]) == 1
            pages.extend(page["list"])
        assert [item["id"] for item in pages] == list(range(10))
        assert all(item["name"] == f"timer-{item['id']}" for item in pages)


@pytest.mark.parametrize("source", CLI_SOURCES, ids=lambda row: row["id"])
def test_mf4_actual_cli_rejects_bad_crypto_schema_and_recovers_at_native_limit(source):
    record = _record(source)
    with cli_server([record]) as (address, _), socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(2)
        _, bound = _bind(peer, address, selector=1, key=GENERIC_KEY)
        key = bound["key"].encode("ascii")
        outer = {"t": "pack", "i": 0, "uid": 7, "cid": PEER, "tcid": MAC}
        _, changed = _exchange(peer, address, {
            "t": "cmd", "mac": MAC, "opt": ["Pow"], "p": [7],
        }, key)
        assert changed["p"] == [7]

        _no_reply(peer, address, packet(outer, {
            "t": "status", "mac": MAC, "cols": ["Pow"],
        }, b"0000000000000000"))
        _no_reply(peer, address, packet({**outer, "i": 1}, {
            "t": "bind", "mac": MAC,
        }, b"0000000000000000"))
        _no_reply(peer, address, packet(outer, {
            "t": "status", "mac": MAC, "cols": ["Pow"],
        }, key, gcm=True))
        _no_reply(peer, address, json.dumps({**outer, "pack": "%%%"}).encode("ascii"))
        _no_reply(peer, address, packet({**outer, "i": 2}, {
            "t": "status", "mac": MAC, "cols": ["Pow"],
        }, key))
        _no_reply(peer, address, packet(outer, {
            "t": "cmd", "mac": MAC, "opt": ["Pow"], "p": [],
        }, key))
        _no_reply(peer, address, packet(outer, {
            "t": "cmd", "mac": MAC, "opt": ["host"], "p": ["forged"],
        }, key))
        _no_reply(peer, address, packet(outer, {
            "t": "cmd", "mac": MAC, "opt": ["Pow"], "p": [-1],
        }, key))
        _no_reply(peer, address, packet(outer, {
            "t": "cmd", "mac": MAC, "opt": ["Pow"], "p": [12.9],
        }, key))
        _no_reply(peer, address, packet(outer, {
            "t": "cmd", "mac": MAC, "opt": ["Pow"], "p": ["1"],
        }, key))
        _no_reply(peer, address, packet(outer, {
            "t": "cmd", "mac": MAC, "opt": ["Pow"], "p": [True],
        }, key))
        _no_reply(peer, address, packet(outer, {
            "t": "cmd", "mac": MAC, "opt": ["Pow"], "p": [None],
        }, key))
        _no_reply(peer, address, packet(outer, {
            "t": "status", "mac": MAC, "cols": ["Pow"] * 65,
        }, key))
        _no_reply(peer, address, packet(outer, {
            "t": "setT", "id": 1, "name": "bad", "enable": 1,
            "week": [1], "hr": 1, "min": 2, "sec": 3,
            "cmd": [{"opt": ["Pow"], "p": [1]}],
        }, key))
        _no_reply(peer, address, b"{invalid JSON")

        at_limit = packet(outer, {"t": "status", "mac": MAC, "cols": ["Pow"]}, key)
        assert len(at_limit) < MAX_DATAGRAM
        peer.sendto(at_limit + b" " * (MAX_DATAGRAM - len(at_limit)), address)
        _, accepted = _wire_reply(peer, address, key)
        assert accepted["dat"] == [7]
        oversized = at_limit + b" " * (MAX_DATAGRAM + 1 - len(at_limit))
        _no_reply(peer, address, oversized)
        _, recovered = _exchange(peer, address, {
            "t": "status", "mac": MAC, "cols": ["Pow"],
        }, key)
        assert recovered["dat"] == [7]


@pytest.mark.parametrize("source", CLI_SOURCES, ids=lambda row: row["id"])
def test_mf4_actual_cli_clean_restart_reseeds_private_key_and_raw_state(source):
    record = _record(source, logical_id=f"mf4-restart-{source['assessment_index']}")
    old_key = None
    for restart in range(2):
        with cli_server([record]) as (address, identities), socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.settimeout(2)
            identity = identities[record["id"]]
            assert identity["profile"] == source["id"]
            assert identity["mid"] == "10001" and identity["mac"] == MAC
            _, bound = _bind(peer, address, selector=1, key=GENERIC_KEY)
            key = bound["key"].encode("ascii")
            assert old_key is None or key == old_key
            old_key = key
            _, initial = _exchange(peer, address, {
                "t": "status", "mac": MAC, "cols": ["Pow", "SetTem"],
            }, key)
            assert initial["dat"] == [0, 24]
            if restart == 0:
                _exchange(peer, address, {
                    "t": "cmd", "mac": MAC, "opt": ["Pow"], "p": [7],
                }, key)
                _, changed = _exchange(peer, address, {
                    "t": "status", "mac": MAC, "cols": ["Pow"],
                }, key)
                assert changed["dat"] == [7]


@pytest.mark.parametrize("source", CLI_SOURCES, ids=lambda row: row["id"])
async def test_mf4_unmodified_device_cipher_v1_and_native_ragged_limit(source):
    record = _record(source)
    with cli_server([record]) as (address, identities):
        mac = identities[record["id"]]["mac"]
        client = Device(DeviceInfo(address[0], address[1], mac, "MF4 CLI consumer",
                                   mid="10001"), timeout=2, bind_timeout=1)
        try:
            await client.bind(cipher=CipherV1())
            await asyncio.wait_for(client._valid_state.wait(), 2)
            assert len(client.device_cipher.key.encode("ascii")) == 16
            client._valid_state.clear()
            await client.update_state(columns=["hid"])
            await asyncio.wait_for(client._valid_state.wait(), 2)
            assert client.hid == source["hid"]

            client._valid_state.clear()
            await client.update_state(columns=["Pow"])
            await asyncio.wait_for(client._valid_state.wait(), 2)
            assert client.raw_properties["Pow"] == 0

            client.set_property("Pow", 7)
            client._valid_state.clear()
            await client.push_state_update()
            await asyncio.wait_for(client._valid_state.wait(), 2)
            assert client.raw_properties["Pow"] == 7
            client._valid_state.clear()
            await client.update_state(columns=["Pow"])
            await asyncio.wait_for(client._valid_state.wait(), 2)
            assert client.raw_properties["Pow"] == 7

            # The source keeps DevID's column but emits no value for it. The
            # unmodified Device cannot accept this unequal native cols/dat pair.
            client._valid_state.clear()
            await client.update_state(columns=["Pow", "DevID"])
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(client._valid_state.wait(), 0.25)
            assert not client.has_valid_state
            assert client.raw_properties["Pow"] == 7
        finally:
            client.close()


class _CaptureTransport:
    """Never owns a socket: the broadcast target is only recorded for assertions."""

    def __init__(self):
        self.sent = []

    def sendto(self, data, address):
        self.sent.append((data, address))

    def close(self):
        pass


def _capture_request(outer, inner, key):
    plain = json.dumps(inner, separators=(",", ":"), allow_nan=False).encode("utf-8")
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(plain, AES.block_size))
    return json.dumps({**outer, "pack": base64.b64encode(encrypted).decode("ascii")},
                      separators=(",", ":")).encode("ascii")


def _capture_exchange(server, transport, source_addr, inner, key, *, selector=0,
                      raw_inner=None, expect_reply=True):
    before = len(transport.sent)
    outer = {"t": "pack", "i": selector, "uid": 7, "cid": PEER, "tcid": MAC}
    request = _capture_request(outer, inner, key) if raw_inner is None else _raw_request(
        raw_inner, selector=selector, key=key)
    server.datagram_received(request, source_addr)
    emitted = transport.sent[before:]
    if not expect_reply:
        assert emitted == []
        return None, None
    assert len(emitted) == 1
    data, destination = emitted[0]
    assert destination == ("255.255.255.255", 5000)
    outer_reply, reply, plaintext = _decrypt_wire(data, GENERIC_KEY if selector else key)
    assert {name: value for name, value in outer_reply.items() if name != "pack"} == {
        "t": "pack", "i": selector, "uid": 7, "cid": MAC, "tcid": PEER,
    }
    assert plaintext.endswith(b"}") and not plaintext.endswith(b"}\n")
    return outer_reply, reply


def _capture_no_reply(server, transport, source_addr, request):
    before = len(transport.sent)
    server.datagram_received(request, source_addr)
    assert transport.sent[before:] == []


def test_mf4_row6_capture_boundary_covers_broadcast_payloads_namespace_and_recovery():
    source = _source(6)
    identities = ("010203040506", "111213141516", "a1a2a3a4a5a6")
    route_word, word2 = 255, 0x87654321
    readouts = [0x101, 0x202, 0x303, 0x404, 0x505]
    record = _record(source, state={
        "mcu_mid_raw": 0x1234abcd,
        "mcu_mode": 2,
        "ubind_lock": 255,
        "report_route_word": route_word,
        "ubind_word2": word2,
        "ubind_readouts": readouts,
        "ubind_identity1": identities[0],
        "ubind_identity2": identities[1],
        "ubind_identity3": identities[2],
        "freq_secondary_ready": True,
    })
    assert source["registered_operations"] == EXPECTED_OPERATIONS[6]

    async def scenario():
        _, _, devices = load_config({"listen": "127.0.0.1", "port": 0,
                                     "seed": "mf4-row6-capture-only", "devices": [record]})
        device = devices[0]
        assert device.mid == "10001"
        server = EmulatorServer(devices)
        transport = _CaptureTransport()
        server.transport = transport
        source_addr = ("192.0.2.44", 7000)
        try:
            before = len(transport.sent)
            server.datagram_received(b'{"t":"scan"}', source_addr)
            assert len(transport.sent) == before + 1
            data, destination = transport.sent[-1]
            assert destination == ("255.255.255.255", 5000)
            outer, tdev, _ = _decrypt_wire(data, GENERIC_KEY)
            assert {name: value for name, value in outer.items() if name != "pack"} == {
                "t": "pack", "i": 1, "uid": 0, "cid": "", "tcid": "",
            }
            assert tdev == {
                "t": "dev", "cid": "", "bc": "", "brand": "gree", "catalog": "gree",
                "mac": MAC, "mid": "1234abcd", "model": "gree", "name": "Synthetic module",
                "lock": 0, "series": "gree", "vender": "", "ver": "V3.4.MF4", "hid": source["hid"],
            }

            # A complete 1460-byte request reaches the actual parser; 1461 bytes
            # is rejected there, while the capture transport prevents any real send.
            generic_status = _capture_request(
                {"t": "pack", "i": 1, "uid": 7, "cid": PEER, "tcid": MAC},
                {"t": "status", "mac": MAC, "cols": ["Pow"]}, GENERIC_KEY)
            assert len(generic_status) < MAX_DATAGRAM
            before = len(transport.sent)
            padded_status = generic_status + b" " * (MAX_DATAGRAM - len(generic_status))
            server.datagram_received(padded_status, source_addr)
            assert len(transport.sent) == before + 1
            assert transport.sent[-1][1] == ("255.255.255.255", 5000)
            padded_outer, padded_inner, _ = _decrypt_wire(transport.sent[-1][0], GENERIC_KEY)
            assert {name: value for name, value in padded_outer.items() if name != "pack"} == {
                "t": "pack", "i": 1, "uid": 7, "cid": MAC, "tcid": PEER,
            }
            assert padded_inner["dat"] == [0]
            before = len(transport.sent)
            oversized = generic_status + b" " * (MAX_DATAGRAM + 1 - len(generic_status))
            server.datagram_received(oversized, source_addr)
            assert transport.sent[before:] == []

            outer_reply, generic_bind = _capture_exchange(
                server, transport, source_addr, {"t": "bind", "mac": MAC},
                GENERIC_KEY, selector=1)
            private_key = generic_bind["key"].encode("ascii")
            assert len(private_key) == 16
            assert generic_bind == {"r": 200, "t": "bindok", "mac": MAC,
                                    "key": device.key.decode("ascii")}
            outer_reply, private_bind = _capture_exchange(
                server, transport, source_addr, {"t": "bind", "mac": MAC},
                private_key, selector=0)
            assert private_bind == generic_bind

            for selector, key in ((0, private_key), (1, GENERIC_KEY)):
                _, status = _capture_exchange(server, transport, source_addr, {
                    "t": "status", "mac": MAC,
                    "cols": ["Pow", "mid", "hid", "ver", "DevID", "MafIdf"],
                }, key, selector=selector)
                assert status == {
                    "t": "dat", "uid": 0, "mac": MAC, "cid": MAC,
                    "cols": ["Pow", "mid", "hid", "ver", "DevID", "MafIdf"],
                    "dat": ["", source["hid"], "V3.4.MF4", 0], "r": 200,
                }
            # Row 6 cannot use the ordinary client facade because every reply
            # is broadcast; query the full native namespace through the capture boundary.
            for start in range(0, len(MA_NAMES), 22):
                columns = MA_NAMES[start:start + 22]
                _, namespace = _capture_exchange(server, transport, source_addr, {
                    "t": "status", "mac": MAC, "cols": columns,
                }, private_key)
                assert namespace == {
                    "t": "dat", "uid": 0, "mac": MAC, "cid": MAC,
                    "dat": _expected_status(source, columns, version="V3.4.MF4"),
                    "cols": list(columns), "r": 200,
                }

            _, ubind = _capture_exchange(server, transport, source_addr,
                                         {"t": "scan"}, private_key)
            assert ubind == {"t": "UBind", "mid": "1234abcd", "ver": "V3.4.MF4",
                             "lock": -1, "devkey": private_key.decode("ascii"),
                             "hid": source["hid"], "GnetID": 0, "scene": 0}

            _, precedence = _capture_exchange(server, transport, source_addr, {
                "t": "cmd", "mac": MAC, "cols": ["Pow"], "opt": ["Mod"], "p": [9],
            }, private_key)
            assert precedence == {"t": "res", "mac": MAC, "opt": ["Pow"],
                                  "p": [9], "r": 200}
            _, precedence_read = _capture_exchange(server, transport, source_addr, {
                "t": "status", "mac": MAC, "cols": ["Pow"],
            }, private_key)
            assert precedence_read == {
                "t": "dat", "uid": 0, "mac": MAC, "cid": MAC,
                "dat": [9], "cols": ["Pow"], "r": 200,
            }
            _, metadata_write = _capture_exchange(server, transport, source_addr, {
                "t": "cmd", "mac": MAC, "opt": ["name", "AppTimer"],
                "p": ["ignored name", "ignored timer"],
            }, private_key)
            assert metadata_write == {
                "t": "res", "mac": MAC, "opt": ["name", "AppTimer"],
                "p": ["Synthetic module", 0], "r": 200,
            }
            _, command = _capture_exchange(server, transport, source_addr, {
                "t": "cmd", "mac": MAC, "opt": ["Pow", "Mod", "SetTem"],
                "p": [65537, 1000, 4294967295],
            }, private_key)
            assert command == {"t": "res", "mac": MAC, "opt": ["Pow", "Mod", "SetTem"],
                               "p": [65537, 1000, -1], "r": 200}
            _, time_ack = _capture_exchange(server, transport, source_addr, {
                "t": "cmd", "mac": MAC, "opt": ["time"], "p": ["ignored time text"],
            }, private_key)
            assert time_ack == {"t": "res", "mac": MAC, "opt": ["time"],
                                "p": ["2026-01-01 00:00:00"], "r": 200}
            _, time_read = _capture_exchange(server, transport, source_addr, {
                "t": "status", "mac": MAC, "cols": ["time"],
            }, private_key)
            assert time_read == {"t": "dat", "uid": 0, "mac": MAC, "cid": MAC,
                                 "dat": ["2026-01-01 00:00:00"], "cols": ["time"], "r": 200}
            _, exponent = _capture_exchange(server, transport, source_addr, {}, private_key,
                                             raw_inner='{"t":"cmd","mac":"020000000001",'
                                                        '"opt":["Pow","Mod"],"p":[1e3,2]}')
            assert exponent == {"t": "res", "mac": MAC, "opt": ["Pow", "Mod"],
                                "p": [1, 2], "r": 200}
            _, state = _capture_exchange(server, transport, source_addr, {
                "t": "status", "mac": MAC, "cols": ["Pow", "Mod", "SetTem"],
            }, private_key)
            assert state == {"t": "dat", "uid": 0, "mac": MAC, "cid": MAC,
                             "dat": [1, 2, 65535],
                             "cols": ["Pow", "Mod", "SetTem"], "r": 200}

            _capture_exchange(server, transport, source_addr, {
                "t": "freqCount", "cols": ["SendFreq", "FreqTime", "Pow"],
                "p": [1, 30, 4],
            }, private_key, expect_reply=False)
            runtime = device.state["_wb_mf4_runtime"]
            assert runtime["request_ready"] is True and runtime["freq_time"] == 30
            assert runtime["freq_secondary_timer"] == 0x4001
            _, freq_read = _capture_exchange(server, transport, source_addr, {
                "t": "status", "mac": MAC, "cols": ["Pow"],
            }, private_key)
            assert freq_read == {"t": "dat", "uid": 0, "mac": MAC, "cid": MAC,
                                 "dat": [4], "cols": ["Pow"], "r": 200}

            _, upgrade = _capture_exchange(server, transport, source_addr,
                                            {"t": "upgrade", "url": "synthetic-firmware"},
                                            private_key)
            assert upgrade == {"t": "ret", "r": 200}
            _, dump = _capture_exchange(server, transport, source_addr,
                                         {"t": "dump", "period": 1, "cnt": 40000}, private_key)
            assert dump == {"t": "ret", "r": 200}
            assert runtime["upgrade_url"] == "synthetic-firmware"
            assert (runtime["dump_period"], runtime["dump_count"]) == (5, 36000)

            _capture_exchange(server, transport, source_addr, {
                "t": "ReportCtrl", "ActiveTime": 2, "ReportInterval": 3,
                "reportAnyway": True,
            }, private_key, expect_reply=False)
            assert runtime["report_state"] == 2
            assert (runtime["report_active"], runtime["report_interval"]) == (2, 3)
            _capture_exchange(server, transport, source_addr, {
                "t": "ReportLimit", "NRA": [[1, 2, 3], [4, 5, 6]],
            }, private_key, expect_reply=False)
            assert runtime["nra"] == [[1, 2, 3, 2], [4, 5, 6, 2]]
            _capture_exchange(server, transport, source_addr, {
                "t": "lifeCycle", "LifeCycleFlag": 0x101, "LifeCycleSwitch": 2,
            }, private_key, expect_reply=False)
            assert runtime["lifecycle"] == {"LifeCycleFlag": 1, "LifeCycleSwitch": 2}
            _capture_exchange(server, transport, source_addr, {"t": "hbok"}, private_key,
                              expect_reply=False)
            assert runtime["heartbeat_ready"] is True
            _capture_exchange(server, transport, source_addr,
                              {"t": "networkInfo", "gnetkey": "ABCDEFGH"}, private_key,
                              expect_reply=False)
            assert runtime["gnet_key"] == b"ABCDEFGH" and runtime["network_ready"] is True
            _capture_exchange(server, transport, source_addr, {
                "t": "loginInfoRes", "r": 200, "loginInfo": {"GnetID": 0},
            }, private_key, expect_reply=False)
            assert runtime["login_result"] == 0

            _, report_client = _capture_exchange(server, transport, source_addr, {
                "t": "cmd", "mac": MAC, "opt": ["ReportClientID"],
                "p": ["source-cli-client"],
            }, private_key)
            assert report_client == {"t": "res", "mac": MAC, "opt": ["ReportClientID"],
                                     "p": [], "r": 200}
            _, binary = _capture_exchange(server, transport, source_addr,
                                          {"t": "UBindok"}, private_key)
            assert binary == _expected_ubind(
                route_word=route_word, word2=word2, readouts=readouts,
                identities=identities, client_text="source-cli-client")
            assert runtime["report_client_pending"] is False

            # This source gate word is a permitted public virtual input. Change it
            # only in capture-backed state to cover binCmd's independent frequency branch.
            device.state["report_route_word"] = 0x13800
            frame = b"~~" + bytes([45]) + bytes(range(44))
            _, binary_ack = _capture_exchange(server, transport, source_addr, {
                "t": "binCmd", "hex01": base64.b64encode(frame).decode("ascii"),
                "ReportFreq": 255, "ReportClientID": "bin-client",
            }, private_key)
            assert binary_ack == {"t": "res", "r": 200}
            assert runtime["report_freq"] == 44 and runtime["report_client_pending"] is True
            _, binary = _capture_exchange(server, transport, source_addr,
                                          {"t": "UBindok"}, private_key)
            # Source ReportFreq frame before UBind copies byte2 + 3 bytes.
            expected_staged_frame = bytes.fromhex(
                "7e7e2d000102030005060708090a0b0c0d0e0f101112131415161718191a"
                "1b1c1d1e1f20212223242526272a292a2b00000000000000000000000000"
            )
            assert len(expected_staged_frame) == 60
            assert binary == _expected_ubind(
                route_word=0x13800, word2=word2, readouts=readouts,
                identities=identities, client_text="bin-client",
                first_frame=expected_staged_frame[:48])

            # The unsafe native branches are rejected atomically; valid traffic still recovers.
            for invalid in ({"t": "reset"}, {"t": "statusCheck"},
                            {"t": "networkInfo", "gnetkey": "short"},
                            {"t": "loginInfoRes", "loginInfo": {"GnetID": 1}},
                            {"t": "cmd", "mac": MAC, "opt": ["host"], "p": ["forged"]},
                            {"t": "status", "mac": MAC, "cols": ["Pow"] * 65}):
                before = copy.deepcopy(device.state)
                _capture_no_reply(server, transport, source_addr,
                                  _capture_request({"t": "pack", "i": 0, "uid": 7,
                                                    "cid": PEER, "tcid": MAC},
                                                   invalid, private_key))
                assert device.state == before
            wrong_key = _capture_request(
                {"t": "pack", "i": 0, "uid": 7, "cid": PEER, "tcid": MAC},
                {"t": "status", "mac": MAC, "cols": ["Pow"]}, b"0000000000000000")
            _capture_no_reply(server, transport, source_addr, wrong_key)
            _capture_no_reply(server, transport, source_addr,
                              json.dumps({"t": "pack", "i": 0, "uid": 7,
                                          "cid": PEER, "tcid": MAC, "pack": "%%%"}).encode())
            gcm_request = packet({"t": "pack", "i": 0, "uid": 7,
                                  "cid": PEER, "tcid": MAC},
                                 {"t": "status", "mac": MAC, "cols": ["Pow"]},
                                 private_key, gcm=True)
            _capture_no_reply(server, transport, source_addr, gcm_request)
            _, recovery = _capture_exchange(server, transport, source_addr, {
                "t": "status", "mac": MAC, "cols": ["Pow", "Mod", "SetTem"],
            }, private_key)
            assert recovery == {"t": "dat", "uid": 0, "mac": MAC, "cid": MAC,
                                "dat": [4, 2, 65535],
                                "cols": ["Pow", "Mod", "SetTem"], "r": 200}

            schedule = _schedule(3, name="row six timer", enable=1, hour=7, minute=8,
                                 week=[1, 0, 1, 0, 1, 0, 1], value=6)
            _, created = _capture_exchange(server, transport, source_addr, schedule, private_key)
            assert created == {"t": "resT", "r": 200}
            _, listed = _capture_exchange(server, transport, source_addr, {
                "t": "queryT", "mac": MAC, "index": 0, "count": 10,
            }, private_key)
            assert listed == {
                "t": "listT", "total": 1, "index": 0,
                "list": [{
                    "id": 3, "name": "row six timer", "enable": 1,
                    "week": [1, 0, 1, 0, 1, 0, 1], "hr": 7, "min": 8, "sec": 0,
                    "cmd": [{"opt": ["Pow"], "p": [6]}],
                    "mac": MAC, "opt": ["Pow"], "Pow": 6, "p": [6],
                }],
            }
            _, update = _capture_exchange(server, transport, source_addr, _schedule(
                3, name="row six updated", enable=0, hour=9, minute=10,
                week=[0, 1, 0, 1, 0, 1, 0], value=8, kind="updateT",
            ), private_key)
            assert update == {"t": "resT", "r": 200}
            _, updated_list = _capture_exchange(server, transport, source_addr, {
                "t": "queryT", "mac": MAC, "index": 0, "count": 10,
            }, private_key)
            assert updated_list == {
                "t": "listT", "total": 1, "index": 0,
                "list": [{
                    "id": 3, "name": "row six updated", "enable": 0,
                    "week": [0, 1, 0, 1, 0, 1, 0], "hr": 9, "min": 10, "sec": 0,
                    "cmd": [{"opt": ["Pow"], "p": [8]}],
                    "mac": MAC, "opt": ["Pow"], "Pow": 8, "p": [8],
                }],
            }
            _, deleted = _capture_exchange(server, transport, source_addr, {
                "t": "deleteT", "mac": MAC, "id": 3,
            }, private_key)
            assert deleted == {"t": "resT", "r": 200}
            _, empty = _capture_exchange(server, transport, source_addr, {
                "t": "queryT", "mac": MAC, "index": 0, "count": 10,
            }, private_key)
            assert empty == {"t": "listT", "total": 0, "index": 0, "list": []}
            assert all(destination == ("255.255.255.255", 5000)
                       for _, destination in transport.sent)
        finally:
            server.transport = None
            server.connection_lost(None)

    asyncio.run(scenario())
