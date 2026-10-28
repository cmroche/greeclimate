"""Hash-qualified MF4 WB runtimes; numeric readouts and MCU identity are virtual inputs.

Only the original standalone AES-ECB LAN paths are admitted here. Numeric cache
writes retain each image's first-match table and low16 storage, while metadata
getters remain separate producers. These profiles do not type an appliance or
claim physical UART, OTA, radio, or schedule-actuator completion.
"""

import base64
import binascii
import json
import re
import math
from datetime import datetime

from ..wire import InvalidPacket, Reply, decode_pack
from . import Profile


# Source payload hashes and embedded HID literals are independent per image.
_BUILDS = {
    5: {
        "id": "sim-realtek-middle-ma170-mf4",
        "sha": "6289946d46d91d750b3694d638abdeecaa9ca3096c65c6336494542409bca43b",
        "hid": "362001065701+U-WB04MAV1.70.bin",
        "dev_mid_buffer": "0x100180bb",
        "metadata_mid_buffer": "0x100012d4",
    },
    6: {
        "id": "sim-realtek-middle-ma183-mf4",
        "sha": "25379aee6b1a67d7def5cdaf48f96dd7d6b2cfcf7decbca992a41a9b76650b80",
        "hid": "362001065701+U-WB04MAV1.83.bin",
        "dev_mid_buffer": "0x10018d3b",
        "metadata_mid_buffer": "0x100012d4",
    },
    16: {
        "id": "sim-realtek-middle-wb05hr-mf4",
        "sha": "39586875ea7bef599afc1dd758405d992615dd9b0b497a28acb63ca06ed26ed4",
        "hid": "362001066962+U-WB05HRV1.27.bin",
        "dev_mid_buffer": "0x10014eff",
        "metadata_mid_buffer": "0x10009d78",
    },
}
_GENERIC_KEYS = {
    5: b"a3K8Bx%2r8Y7#xDh",
    6: b"a3K8Bx%2r8Y7#xDh",
    16: b"a3K8Bx%2r8Y7#xDh",
}
_INDEX_BY_SHA = {source["sha"]: index for index, source in _BUILDS.items()}

# These are the source-ordered unique first-match names, not a family union.
# MA170 and MA183 have identical arrays; HR adds four names in its own table.
_MA_NAMES = tuple("""
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

_HR_NAMES = tuple(
    name for name in _MA_NAMES if name != "Dmod"
)[:_MA_NAMES.index("Dmod")] + (
    "OutEnvTem", "InEvaTem", "CompressorTem", "CompressorFqy",
) + _MA_NAMES[_MA_NAMES.index("Dmod"):]


_STRING_GETTERS = {
    5: frozenset(("host", "name", "time", "vender", "bc", "mid", "hid", "ver")),
    6: frozenset(("host", "name", "time", "vender", "bc", "mid", "hid", "ver")),
    16: frozenset(("ModelType", "FaultDisplay", "host", "name", "time", "vender", "bc", "mid", "hid", "ver")),
}
_EMPTY_GETTERS = {
    5: frozenset(("DevID", "MafIdf")),
    6: frozenset(("DevID", "MafIdf")),
    16: frozenset(("DevID", "MafIdf")),
}

_MIDDLE_METADATA = {
    "host": "synthetic.invalid", "name": "Synthetic module", "time": "2026-01-01 00:00:00",
    "vender": "", "bc": "", "mid": "",
}

_INITIAL_RAW = {"SetTem": 24, "TemSen": 62}


class _NumericToken(str):
    """Raw JSON numeric token retained for the WB-specific numeric ABI."""


def _raw_number(token):
    return _NumericToken(token)


def _number(value):
    """Decode the source's signed decimal token, saturating its int32 result."""
    if type(value) is int:
        number = float(value)
    elif isinstance(value, _NumericToken):
        token = str(value)
        if not re.fullmatch(r"-?[0-9]+(?:\.[0-9]+)?", token):
            raise InvalidPacket("MF4 requires its signed-decimal token form")
        number = float(token)
    else:
        raise InvalidPacket("MF4 numeric fields require JSON number tokens")
    if number >= (1 << 31):
        return (1 << 31) - 1
    if number <= -(1 << 31):
        return -(1 << 31)
    if not math.isfinite(number):
        raise InvalidPacket("MF4 numeric token is not finite")
    return int(number)


def _schedule_integer(text, position=0):
    negative = position < len(text) and text[position] == "-"
    if negative:
        position += 1
    start = position
    value = 0
    while position < len(text) and "0" <= text[position] <= "9":
        value = (value * 10 + ord(text[position]) - 48) & 0xffffffff
        position += 1
    if position == start:
        raise InvalidPacket("MF4 schedule numeric token parse failed")
    if position < len(text) and text[position] == ".":
        position += 1
        fraction_start = position
        while position < len(text) and "0" <= text[position] <= "9":
            position += 1
        if position == fraction_start:
            raise InvalidPacket("MF4 schedule fraction has no digits")
    value = (-value if negative else value) & 0xffffffff
    return (value if value < (1 << 31) else value - (1 << 32)), position


def _schedule_number(value):
    if not isinstance(value, _NumericToken):
        raise InvalidPacket("MF4 schedule fields require JSON number tokens")
    return _schedule_integer(str(value))[0]


def _schedule_array_numbers(values, count):
    if not isinstance(values, list):
        raise InvalidPacket("MF4 schedule arrays require JSON arrays")
    source = "[" + ",".join(
        str(value) if isinstance(value, _NumericToken)
        else json.dumps(value, separators=(",", ":"))
        for value in values
    ) + "]"
    if len(source) > 1460:
        raise InvalidPacket("MF4 schedule array exceeds its request bound")
    result, position = [], 0
    for _ in range(count):
        if position >= len(source) or source[position] == "]":
            raise InvalidPacket("MF4 schedule array ended before its expected values")
        position += 1  # The source skips one assumed '[' or comma byte.
        value, position = _schedule_integer(source, position)
        result.append(value)
    return result


def _command_number(index, value):
    if index not in (5, 6, 16) or not isinstance(value, _NumericToken):
        raise InvalidPacket("MF4 command requires a source numeric token")
    token = str(value)
    if not token or "." in token or not "0" <= token[0] <= "9":
        raise InvalidPacket("MF4 command rejects this numeric token tag")
    result = 0
    for character in token:
        if not "0" <= character <= "9":
            break
        result = (result * 10 + ord(character) - 48) & 0xffffffff
    return result if result < (1 << 31) else result - (1 << 32)

def _text(value, maximum, *, empty=True):
    if (not isinstance(value, str) or "\0" in value or not empty and not value
            or len(value.encode("utf-8")) > maximum):
        raise InvalidPacket("MF4 text exceeds its bounded source field")
    return value

def _source_text(value, maximum):
    if value is None:
        value = "null"
    elif value is True:
        value = "true"
    elif value is False:
        value = "false"
    return _text(value, maximum)


def _identity(inner, fields, fallback):
    for field in fields:
        if field in inner:
            try:
                return _source_text(inner[field], 31)
            except InvalidPacket:
                pass
    return fallback




def _names(index):
    return _MA_NAMES if index in (5, 6) else _HR_NAMES


def _string_fields(index):
    return _STRING_GETTERS[index]


def _empty_fields(index):
    return _EMPTY_GETTERS[index]

def _source_index(device):
    return _INDEX_BY_SHA[device.profile.source_sha256]


def _cache_fields(index):
    return frozenset(_names(index))


def _initial_state(index):
    state = {name: value for name, value in _MIDDLE_METADATA.items()}
    state["hid"] = _BUILDS[index]["hid"]
    state["rssi"] = -55
    state["AppTimer"] = 0
    state["mcu_mid_raw"] = 0
    state["gnet_id"] = 0
    state["mcu_mode"] = 0
    state["ubind_lock"] = 0
    state["ubind_word2"] = 0
    state["ubind_identity1"] = ""
    state["ubind_identity2"] = ""
    state["ubind_identity3"] = ""
    state["ubind_readouts"] = [0, 0, 0, 0, 0]
    state["freq_secondary_ready"] = False
    state["report_route_word"] = 0
    state["report_context"] = "virtual/"
    state["dev_ver"] = "V3.0.0" if index == 16 else "V3.4.M"
    state["companion_ver"] = "V3.4.MF4" if index in (5, 6) else ""
    if index == 16:
        state["ver"] = state["dev_ver"]
        state["hr_persist_gate_word"] = 0
        state["hr_clock_offset_word"] = 0
    state["tdev_brand"] = "gree"
    state["tdev_catalog"] = "gree"
    state["tdev_model"] = "gree"
    state["tdev_series"] = "gree"
    state["_wb_dev_mid_raw"] = 0
    state["_wb_dev_mid_buffer"] = ""
    state["_wb_dev_mid_retry_count"] = 6
    state["_wb_mf4_cache"] = {name: 0 for name in _cache_fields(index)}
    state["_wb_mf4_cache"].update(_INITIAL_RAW)
    # Public editable raw words use the same 16-bit first-match slot as the image.
    for name in _cache_fields(index) - _string_fields(index) - {"rssi", "MidType"}:
        if name not in _empty_fields(index):
            state[name] = _INITIAL_RAW.get(name, 0)
    if index in (5, 6, 16):
        state["MidType"] = 0
    if index == 16:
        state.update(ModelType="", FaultDisplay="")
    return state


def _valid_state(index, state):
    strings = _string_fields(index)
    for name, value in state.items():
        if name in ("_wb_dev_mid_buffer",):
            _text(value, 15)
        elif name == "_wb_dev_mid_raw":
            if type(value) is not int or not 0 <= value <= 0xffffffff:
                raise ValueError("decoded WB MCU MID input must be uint32")
        elif name == "_wb_dev_mid_retry_count":
            if type(value) is not int or not 0 <= value <= 255:
                raise ValueError("WB MCU MID retry count must be uint8")
        elif name == "_wb_mf4_cache":
            if not isinstance(value, dict):
                raise ValueError("MF4 hidden first-match cache must be an object")
            for field, word in value.items():
                if field not in _cache_fields(index) or type(word) is not int or not 0 <= word <= 65535:
                    raise ValueError("MF4 hidden cache contains an invalid first-match word")
        elif name in ("dev_ver", "companion_ver"):
            _text(value, 255)
        elif name in strings and not (name == "ver" and index in (5, 6)):
            _text(value, 255)
            if name == "hid" and value != _BUILDS[index]["hid"]:
                raise ValueError("embedded MF4 HID is fixed by the exact source image")
            if name == "time":
                _clock_value(value)
        elif name in ("hr_persist_gate_word", "hr_clock_offset_word"):
            if (index != 16 or type(value) is not int or not 0 <= value <= 0xffffffff):
                raise ValueError("MF4 virtual HR clock words must be uint32")
        elif name == "mcu_mid_raw":
            if type(value) is not int or not 0 <= value <= 0xffffffff:
                raise ValueError("virtual MCU decoded MID word must be uint32")
        elif name == "gnet_id":
            if type(value) is not int or not 0 <= value <= 255:
                raise ValueError("virtual GnetID must be uint8")
        elif name == "mcu_mode":
            if type(value) is not int or not 0 <= value <= 0xffffffff:
                raise ValueError("virtual MCU mode must be uint32")
        elif name == "ubind_lock":
            if type(value) is not int or not 0 <= value <= 255:
                raise ValueError("virtual UBind lock word must be uint8")
        elif name == "ubind_word2":
            if type(value) is not int or not 0 <= value <= 0xffffffff:
                raise ValueError("virtual UBind second context word must be uint32")
        elif name.startswith("ubind_identity"):
            if not isinstance(value, str) or value and not re.fullmatch(r"[0-9a-fA-F]{12}", value):
                raise ValueError("virtual UBind identities must be empty or exactly twelve hex digits")
        elif name == "ubind_readouts":
            if (not isinstance(value, list) or len(value) != 5
                    or any(type(item) is not int or not 0 <= item <= 65535 for item in value)):
                raise ValueError("virtual UBind readouts require five uint16 values")
        elif name == "freq_secondary_ready":
            if type(value) is not bool:
                raise ValueError("virtual secondary frequency timer flag must be boolean")
        elif name == "report_route_word":
            if type(value) is not int or not 0 <= value <= 0xffffffff:
                raise ValueError("separate source route comparison word must be uint32")
        elif name == "report_context":
            _text(value, 63, empty=False)
            if "/" not in value:
                raise ValueError("virtual ReportCtrl context must include its source slash delimiter")
        elif name in ("AutoUpdate", "lock"):
            if type(value) is not int or not 0 <= value <= 255:
                raise ValueError(f"MF4 {name} metadata getter must be uint8")
        elif name in ("tdev_brand", "tdev_catalog", "tdev_model", "tdev_series"):
            _text(value, 255)
        elif name == "rssi":
            if type(value) is not int or not -128 <= value <= 127:
                raise ValueError("synthetic RSSI must be signed8")
        elif name == "MidType" and index != 17:
            if type(value) is not int or not 0 <= value <= 255:
                raise ValueError("MF4 MidType source byte must be uint8")
        elif name == "AppTimer":
            if type(value) is not int or not 0 <= value <= 255:
                raise ValueError("MF4 AppTimer getter byte must be uint8")
        elif name in _cache_fields(index) and name not in strings:
            if type(value) is not int or not 0 <= value <= 65535:
                raise ValueError("MF4 first-match cache fields must be uint16")
        elif name.startswith("_"):
            continue
        else:
            raise ValueError("only exact-source MF4 raw and synthetic input fields may be configured")


def _primary_version(state, index):
    if ((index == 5 and state["gnet_id"] != 0)
            or (index == 6 and state["mcu_mode"] == 2)):
        return state["companion_ver"]
    return state["dev_ver"]


def _metadata(device):
    state = device.state
    raw = state.get("mcu_mid_raw", 0)
    if raw:
        emitted_mid = f"{raw:x}"
        state["_wb_dev_mid_raw"] = raw
        state["_wb_dev_mid_buffer"] = emitted_mid
    elif state.get("_wb_dev_mid_retry_count", 0) > 5:
        state["_wb_dev_mid_raw"] = 0x10001
        emitted_mid = "10001"
        state["_wb_dev_mid_buffer"] = emitted_mid
    else:
        emitted_mid = state.get("_wb_dev_mid_buffer", "")
    return {"mid": emitted_mid, "hid": device.profile.hid,
            "name": state["name"],
            "dev_ver": _primary_version(state, _source_index(device)),
            "bc": state["bc"], "vender": state["vender"],
            "brand": state["tdev_brand"], "catalog": state["tdev_catalog"],
            "model": state["tdev_model"], "series": state["tdev_series"],
            "lock": 0, "index": _source_index(device)}


def _metadata_value(device, name):
    index = _source_index(device)
    state = device.state
    if name in _empty_fields(index):
        return None
    if name in ("rssi", "AppTimer", "AutoUpdate", "lock"):
        return state.get(name, 0)
    if name == "MidType":
        return (state.get("MidType", 0) >> 7) & 1
    if name == "ver" and index in (5, 6):
        return _primary_version(state, index)
    if name == "hid":
        return device.profile.hid
    if name in _string_fields(index):
        return state.get(name, "")
    return ...


def _raw_value(device, name):
    state = device.state
    index = _source_index(device)
    if (name in _string_fields(index) or name in _empty_fields(index)
            or name in {"rssi", "MidType", "AppTimer", "AutoUpdate", "lock"}):
        return state.get("_wb_mf4_cache", {}).get(name, 0)
    return state.get(name, state.get("_wb_mf4_cache", {}).get(name, 0)) & 0xffff


def _set_raw(device, name, value):
    state = device.state
    value &= 0xffff
    index = _source_index(device)
    if (name in _string_fields(index) or name in _empty_fields(index)
            or name in {"rssi", "MidType", "AppTimer", "AutoUpdate", "lock"}):
        state.setdefault("_wb_mf4_cache", {})[name] = value
    else:
        state[name] = value


def _columns(inner, field, fallback=None, *, maximum=64):
    values = inner.get(field, inner.get(fallback) if fallback else None)
    if not isinstance(values, list) or len(values) > maximum:
        raise InvalidPacket("MF4 property array exceeds its bounded source-local limit")
    names = [_text(value, 255, empty=False) for value in values]
    if sum(len(name.encode("utf-8")) + 1 for name in names) > 512:
        raise InvalidPacket("MF4 property array exceeds its source-local byte bound")
    return names


def _reply(device, inner, index, uid=0, peer=""):
    plain = json.dumps(inner, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    if len(plain) >= 1000:
        raise InvalidPacket("MF4 response exceeds its source-local JSON scratch bound")
    key = _GENERIC_KEYS[_source_index(device)] if index else device.key
    broadcast = _source_index(device) == 6
    return Reply({"t": "pack", "i": index, "uid": uid, "cid": device.mac,
                  "tcid": peer}, inner, key, "aes-ecb-pkcs7",
                 destination_port=5000 if broadcast else None,
                 destination_host="255.255.255.255" if broadcast else None)


def _client_frame(value):
    value = _text(value, 26)
    raw = value.encode("utf-8")
    frame = bytearray(30)
    frame[:4] = b"\x7e\x7e\x12\x6a"
    frame[4:4 + len(raw)] = raw
    return bytes(frame)


def _context(device):
    state = device.state
    if "_wb_mf4_runtime" not in state:
        state["_wb_mf4_runtime"] = {
            "timers": [], "schedule_count": 0, "bitmaps": set(),
            "report_state": 0, "report_active": 0, "report_interval": 0,
            "freq_time": 0, "report_freq": 0, "lifecycle": {},
            "binary_frames": [bytes(60) for _ in range(5)],
            "report_client_frame": None, "report_client_pending": False,
            "pending_client": None, "mode": 2, "clock_time": state["time"],
            "gnet_key": b"", "bound": False, "upgrade_url": None,
            "dump_period": 0, "dump_count": 0,
        }
    return state["_wb_mf4_runtime"]


def _read_values(device, names):
    index = _source_index(device)
    data = []
    for metadata_pass in (True, False):
        for name in names:
            special = _metadata_value(device, name)
            if special is not ...:
                if metadata_pass and special is not None:
                    data.append(special)
            elif name in _names(index) and not metadata_pass:
                data.append(_raw_value(device, name))
    return data


def _clock_value(value):
    value = _text(value, 31, empty=False)
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}", value):
        raise InvalidPacket("MF4 virtual clock requires the source's bounded timestamp spelling")
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
    except ValueError as error:
        raise InvalidPacket("MF4 virtual clock timestamp is out of range") from error
def _clock_seconds(value):
    return sum(int(part) * scale for part, scale in
               zip(value[11:].split(":"), (3600, 60, 1)))




def _command_values(device, names, values):
    index = _source_index(device)
    known = frozenset(_names(index)) | {"MidType", "rssi", "ReportClientID", "allname"}
    if any(name not in known for name in names):
        raise InvalidPacket("unsupported MF4 command selector")
    if not isinstance(values, list) or len(values) != len(names):
        raise InvalidPacket("MF4 command options and p values must match")
    parsed = []
    for name, value in zip(names, values):
        if name == "ReportClientID":
            if type(value) is not str:
                raise InvalidPacket("MF4 ReportClientID command requires source text")
            parsed.append((name, _text(value, 26), "client"))
        elif name == "time":
            if type(value) is not str:
                raise InvalidPacket("MF4 time command requires source text")
            if index in (5, 6):
                parsed.append((name, _text(value, 255), "ma_time"))
            else:
                parsed.append((name, _clock_value(value), "clock"))
        elif (name in ("name", "allname") or (name == "ModelType" and index == 16)
              or (name == "AppTimer" and type(value) is str)) and type(value) is str:
            parsed.append((name, _text(value, 255), "metadata"))
        elif name in ("ReportClientID", "allname"):
            raise InvalidPacket(f"MF4 source requires string input for {name}")
        elif name in _string_fields(index) and type(value) is str:
            raise InvalidPacket(f"MF4 source does not support string setter {name}")
        else:
            parsed.append((name, _command_number(index, value), "numeric"))
    effective = []
    for name, value, kind in parsed:
        if kind == "numeric":
            effective.append(value)
        elif kind == "clock":
            effective.append(value)
        elif kind == "ma_time":
            effective.append(device.state["time"])
        elif kind == "metadata":
            current = _metadata_value(device, name)
            if current is not None and current is not ...:
                effective.append(current)
    return names, effective, parsed


def _apply_command(device, parsed):
    runtime = None
    for name, value, kind in parsed:
        if kind == "numeric":
            _set_raw(device, name, value)
        elif kind == "clock":
            old_time = device.state["time"]
            device.state["time"] = value
            runtime = runtime or _context(device)
            runtime["clock_time"] = value
            current_second = _clock_seconds(value)
            for record in runtime["timers"]:
                if record["enable_byte"] == 1:
                    record["time_delta"] = (
                        record["hr"] * 3600 + record["min"] * 60 + record["sec"]
                        - current_second
                    )
            runtime["time_persist_requested"] = (
                device.state["hr_persist_gate_word"] > 0x5b03b45b
            )
            if runtime["time_persist_requested"]:
                elapsed = (datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
                           - datetime.strptime(old_time, "%Y-%m-%d %H:%M:%S"))
                delta = elapsed.days * 86400 + elapsed.seconds
                device.state["hr_clock_offset_word"] = (
                    device.state["hr_clock_offset_word"] + delta
                ) & 0xffffffff
        elif kind == "ma_time":
            runtime = runtime or _context(device)
            runtime["time_config_persist_requested"] = True
            flags = set(runtime.get("time_flag_bytes_set", ())) | {0, 6}
            if device.state.get("mcu_mid_raw", 0) == 0x11002:
                flags.add(4)
            runtime["time_flag_bytes_set"] = sorted(flags)
            runtime["time_status_bit_0x80_set"] = True
        elif kind == "client":
            runtime = runtime or _context(device)
            runtime["pending_client"] = value
            runtime["report_client_frame"] = _client_frame(value)
            runtime["report_client_pending"] = True



def _timer_record(device, inner):
    timer_id = _schedule_number(inner.get("id")) & 255
    enabled_value = _schedule_number(inner.get("enable"))
    week_values = _schedule_array_numbers(inner.get("week"), 7)
    week_mask = 0
    for position, value in enumerate(week_values):
        week_mask |= value << position
    hour, minute = (_schedule_number(inner.get(name)) & 255 for name in ("hr", "min"))
    _schedule_number(inner.get("sec"))  # Native successful seconds parse stores zero.
    name = _text(inner.get("name"), 31)
    if "tz" in inner:
        _schedule_number(inner["tz"])  # Parsed by the source, but not stored or returned.
    current_clock = _clock_value(device.state.get("time", ""))
    current_second = _clock_seconds(current_clock)
    commands = inner.get("cmd")
    if not isinstance(commands, list) or not commands or not isinstance(commands[0], dict):
        raise InvalidPacket("MF4 timer requires the source's first nested cmd object")
    first = commands[0]
    opts = _columns(first, "opt", maximum=30)
    p = first.get("p")
    parsed_p = _schedule_array_numbers(p, len(opts))
    # This local delta is recomputed from the source's local clock; its parsed tz is ignored.
    time_delta = (hour * 3600 + minute * 60 - current_second) % 86400
    pow_value = next((value & 255 for option, value in zip(opts, parsed_p) if option == "Pow"), 0)
    return {
        "id": timer_id,
        "name": name,
        "enable_byte": 0 if enabled_value == 1 else 1,
        "week_mask": week_mask & 255,
        "hr": hour,
        "min": minute,
        "sec": 0,
        "tz": None,
        "time_delta": time_delta,
        "cmd": [{"opt": opts, "p": parsed_p}],
        "opt": opts,
        "p": parsed_p,
        "Pow": pow_value,
    }


def _timer_item(device, record):
    return {
        "id": record["id"], "name": record["name"],
        "enable": 1 if record["enable_byte"] == 0 else 0,
        "week": [(record["week_mask"] >> bit) & 1 for bit in range(7)],
        "hr": record["hr"], "min": record["min"], "sec": record["sec"],
        "cmd": record["cmd"], "mac": device.mac, "opt": record["opt"],
        "Pow": record["Pow"], "p": record["p"],
    }


def _schedule(device, inner, kind, uid, peer, index):
    runtime = device.state.get("_wb_mf4_runtime")
    if kind == "setT":
        # Native checks capacity before searching for an existing ID.
        if runtime is not None and runtime["schedule_count"] > 9:
            return []
        record = _timer_record(device, inner)
        reply = _reply(device, {"t": "resT", "r": 200}, index, uid, peer)
        runtime = _context(device)
        timers = runtime["timers"]
        for position, existing in enumerate(timers):
            if existing["id"] == record["id"]:
                timers[position] = record
                break
        else:
            timers.insert(0, record)
            runtime["schedule_count"] = (runtime["schedule_count"] + 1) & 255
        return [reply]
    if kind == "updateT":
        record = _timer_record(device, inner)
        reply = _reply(device, {"t": "resT", "r": 200}, index, uid, peer)
        runtime = _context(device)
        for position, existing in enumerate(runtime["timers"]):
            if existing["id"] == record["id"]:
                runtime["timers"][position] = record
                break
        return [reply]
    if kind == "deleteT":
        timer_id = _schedule_number(inner.get("id")) & 255
        reply = _reply(device, {"t": "resT", "r": 200}, index, uid, peer)
        runtime = _context(device)
        runtime["schedule_count"] = (runtime["schedule_count"] - 1) & 255
        for position, record in enumerate(runtime["timers"]):
            if record["id"] == timer_id:
                runtime["bitmaps"].discard(timer_id)
                # Source assigns root.head=matched.next even for a non-head match.
                del runtime["timers"][:position + 1]
                break
        return [reply]
    start, count = (_schedule_number(inner.get(name)) for name in ("index", "count"))
    if start < 0 or count < 0 or start > 255 or count > 10:
        raise InvalidPacket("MF4 schedule pages are bounded and nonnegative")
    runtime = _context(device)
    records = {record["id"]: record for record in runtime["timers"]}
    items = [_timer_item(device, records[timer_id]) for timer_id in range(start, min(10, start + count))
             if timer_id in records]
    return [_reply(device, {"t": "listT", "total": runtime["schedule_count"],
                            "index": start, "list": items}, index, uid, peer)]


def _actual_tdev(device):
    identity = _metadata(device)
    return {"t": "dev", "cid": "", "bc": identity["bc"], "brand": identity["brand"],
            "catalog": identity["catalog"], "mac": device.mac, "mid": identity["mid"],
            "model": identity["model"], "name": identity["name"], "lock": identity["lock"],
            "series": identity["series"], "vender": identity["vender"], "ver": identity["dev_ver"],
            "hid": device.profile.hid}


class MF4Handler:
    def __init__(self, source_index):
        self.source_index = source_index

    def validate_state(self, state):
        _valid_state(self.source_index, state)

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        return None

    def advertise(self, device, outer):
        broadcast = self.source_index == 6
        return [Reply({"t": "pack", "i": 1, "uid": 0, "cid": "", "tcid": ""},
                      _actual_tdev(device), _GENERIC_KEYS[self.source_index], "aes-ecb-pkcs7",
                      destination_port=5000 if broadcast else None,
                      destination_host="255.255.255.255" if broadcast else None)]

    def _gnet_scan(self, device, inner, index, uid, peer):
        source = self.source_index
        if source == 5 and device.state["gnet_id"] == 0:
            return []
        if source == 6 and device.state["mcu_mode"] != 2:
            return []
        values = _metadata(device)
        runtime = _context(device)
        runtime["bound"] = True
        response = {"t": "UBind", "mid": values["mid"], "ver": device.state["companion_ver"],
                    "lock": (device.state["ubind_lock"] ^ 0x80) - 0x80,
                    "devkey": device.key.decode("ascii"),
                    "hid": device.profile.hid, "GnetID": device.state["gnet_id"], "scene": 0}
        return [_reply(device, response, index, uid, peer)]

    def _ubind_ok(self, device, index, uid, peer):
        state = device.state
        identities = tuple(state[f"ubind_identity{number}"] for number in (1, 2, 3))
        if any(not re.fullmatch(r"[0-9a-fA-F]{12}", identity) for identity in identities):
            raise InvalidPacket("UBind requires three separately configured six-byte virtual identities")
        runtime = _context(device)
        mode = runtime["mode"] & 255
        header = bytearray(39)
        header[0:2] = bytes((0x66, 0x69 if mode == 1 else 0x67))
        for offset, identity in zip((4, 10, 16), identities):
            header[offset:offset + 6] = bytes.fromhex(identity)
        header[22:26] = state["report_route_word"].to_bytes(4, "big")
        header[26:30] = (0 if mode == 1 else state["ubind_word2"]).to_bytes(4, "big")
        header[30] = mode
        header[32] = mode + 0x30
        header[33:38] = bytes(value & 255 for value in state["ubind_readouts"])
        header[38] = 2
        encoded_frames = []
        frames = runtime["binary_frames"]
        if len(frames) != 5:
            raise InvalidPacket("MF4 UBind requires its five source frame caches")
        for frame in frames:
            if not isinstance(frame, bytes) or len(frame) != 60:
                raise InvalidPacket("MF4 UBind frame cache must be sixty bytes")
            frame_size = frame[2] + 3
            if frame_size > len(frame):
                raise InvalidPacket("MF4 UBind source frame exceeds its sixty-byte cache")
            encoded_frames.append(frame[:frame_size])
        client_pending = runtime["report_client_pending"]
        if client_pending:
            frame = runtime["report_client_frame"]
            if not isinstance(frame, bytes) or len(frame) != 30:
                raise InvalidPacket("MF4 pending ReportClientID frame is not bounded source storage")
            frame_size = frame[2] + 3
            encoded_frames.append(frame[:frame_size])
        payload = bytes(header) + b"".join(encoded_frames)
        if len(payload) + 9 > 512:
            raise InvalidPacket("MF4 UBind payload exceeds its source-local bound")
        length = len(payload) + 2
        encoded_length = bytearray()
        while length >= 0x80:
            encoded_length.append((length & 0x7f) | 0x80)
            length >>= 7
        encoded_length.append(length)
        packet = b"\x00\x01\x00" + bytes(encoded_length) + b"\x01\x00" + payload
        reply = _reply(device, {"t": "binStatus", "binStatus": base64.b64encode(packet).decode("ascii"),
                               "header": base64.b64encode(header).decode("ascii"),
                               "mac": device.mac}, index, uid, peer)
        runtime["bound"] = True
        runtime["bound_pending"] = True
        if client_pending:
            runtime["report_client_pending"] = False
            runtime["report_client_frame"] = None
            runtime["pending_client"] = None
        return [reply]

    def _bin_cmd(self, device, inner, index, uid, peer):
        client = inner.get("ReportClientID")
        pending_client = None if client is None else _text(client, 26)
        client_frame = None if pending_client is None else _client_frame(pending_client)
        report_freq = inner.get("ReportFreq")
        report_value = None if report_freq is None else _number(report_freq)
        if any(name in inner for name in ("sceneId", "operType", "fragment", "roomId")):
            raise InvalidPacket("unsafe native scene-fragment branch rejected atomically")
        encoded = _text(inner.get("hex01"), 1023, empty=False)
        try:
            frame = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise InvalidPacket("invalid MF4 binCmd base64") from error
        if len(frame) < 3 or frame[:2] != b"~~":
            raise InvalidPacket("MF4 binCmd requires the source 0x7e7e frame marker")
        declared = frame[2] + 2
        if declared + 1 > 60 or len(frame) < declared:
            raise InvalidPacket("MF4 binCmd frame exceeds its 60-byte staging and later-copy bound")
        route = device.state["report_route_word"]
        accept_frequency = report_value is not None and 0x13800 <= route <= 0x138ff
        stage = bytearray(60)
        stage[:declared] = frame[:declared]
        stage[0x2b] |= 2
        stage[7] = 0 if accept_frequency else 0xaf
        reply = _reply(device, {"t": "res", "r": 200}, index, uid, peer)
        runtime = _context(device)
        runtime["binary_frames"][0] = bytes(stage)
        runtime["request_ready"] = True
        runtime["report_timer"] = 0x400a
        if pending_client is not None:
            runtime["pending_client"] = pending_client
            runtime["report_client_frame"] = client_frame
            runtime["report_client_pending"] = True
        if accept_frequency:
            runtime["report_freq"] = 44 if report_value == 255 else report_value & 255
            runtime["report_state"] = 1
        return [reply]

    def _handle_other(self, device, inner, kind, index, uid, peer):
        source = self.source_index
        if kind == "upgrade":
            if "url" not in inner:
                raise InvalidPacket("MF4 upgrade requires a source text URL")
            url = _source_text(inner["url"], 119)
            reply = _reply(device, {"t": "ret", "r": 200}, index, uid, peer)
            _context(device)["upgrade_url"] = url
            return [reply]
        if kind == "dump" and source in (6, 16):
            period, count = (_number(inner.get(name)) for name in ("period", "cnt"))
            period = 60 if period <= 0 else 5 if period < 5 else period
            if source == 16:
                period = min(period, 4096)
            count = max(1, count)
            if source == 6:
                count = min(count, 36000)
            reply = _reply(device, {"t": "ret", "r": 200}, index, uid, peer)
            runtime = _context(device)
            runtime["dump_period"], runtime["dump_count"] = period, count
            runtime["report_state"] = 1
            runtime["lifecycle_status"] = runtime.get("lifecycle_status", 0) | 0x80
            return [reply]
        if kind == "freqCount" and source in (5, 6):
            names = _columns(inner, "cols", "opt", maximum=64)
            values = inner.get("p")
            if not isinstance(values, list) or len(values) != len(names):
                raise InvalidPacket("MF4 freqCount options and p values must match")
            staged, frequency = [], {}
            known = frozenset(_names(source))
            for name, value in zip(names, values):
                if name in ("SendFreq", "FreqTime"):
                    frequency[name] = _number(value)
                elif name in known:
                    if name in _string_fields(source) and isinstance(value, str):
                        _text(value, 255)
                    else:
                        staged.append((name, _number(value)))
                else:
                    raise InvalidPacket("unsupported MF4 freqCount selector")
            runtime = _context(device)
            for name, value in staged:
                _set_raw(device, name, value)
            if frequency.get("SendFreq") == 1:
                runtime["request_ready"] = True
                runtime["report_state"] = 1
                runtime["report_timer"] = 0x400a
            if "FreqTime" in frequency:
                runtime["freq_time"] = frequency["FreqTime"]
                if device.state.get("freq_secondary_ready", False):
                    runtime["freq_secondary_timer"] = 0x4001
            return []
        if kind == "lifeCycle" and source in (5, 6):
            staged = {name: _number(inner[name]) & 255
                      for name in ("LifeCycleFlag", "LifeCycleSwitch") if name in inner}
            runtime = _context(device)
            runtime["lifecycle"].update(staged)
            if staged:
                runtime["lifecycle_status"] = runtime.get("lifecycle_status", 0) | 0x80
            return []
        if kind == "ReportCtrl" and source in (5, 6):
            context = device.state["report_context"]
            prefix, separator, _ = context.partition("/")
            if not separator:
                raise InvalidPacket("unsafe native ReportCtrl context rejected atomically")
            active = _number(inner["ActiveTime"]) if "ActiveTime" in inner else 0
            interval = _number(inner["ReportInterval"]) if "ReportInterval" in inner else 0
            report_anyway = inner.get("reportAnyway") is True
            runtime = _context(device)
            runtime["report_context_prefix"] = prefix
            runtime["report_state"] = 2 if report_anyway else 1
            runtime["report_active"], runtime["report_interval"] = active, interval
            runtime["report_active_timer"] = (60 * active + 0x4000) & 0xffff
            runtime["report_interval_timer"] = (60 * interval + 0x4000) & 0xffff
            return []
        if kind == "ReportLimit" and source in (5, 6):
            if device.state["report_route_word"] > 255:
                return []
            if "CtrlFunc" in inner:
                raise InvalidPacket("unsafe native CtrlFunc decoder rejected atomically")
            staged_records = None
            if "NRA" in inner:
                rows = inner["NRA"]
                if not isinstance(rows, list) or not 1 <= len(rows) <= 16:
                    raise InvalidPacket("MF4 NRA requires one to sixteen bounded rows")
                staged_records = []
                for row in rows:
                    if not isinstance(row, list) or len(row) != 3:
                        raise InvalidPacket("safe MF4 NRA rows require exactly three numeric values")
                    staged_records.append([_number(value) & 255 for value in row] + [len(rows)])
            interval = _number(inner["midReportInterval"]) if "midReportInterval" in inner else None
            runtime = _context(device)
            if staged_records is not None:
                runtime["nra"] = staged_records
            if interval is not None:
                runtime["mid_report_interval"] = interval
            return []
        if kind == "reset" and source in (5, 6):
            raise InvalidPacket("unsafe native reset string constructor rejected atomically")
        if kind == "scan" and source in (5, 6):
            return self._gnet_scan(device, inner, index, uid, peer)
        if kind == "UBindok" and source in (5, 6):
            return self._ubind_ok(device, index, uid, peer)
        if kind == "hbok" and source in (5, 6):
            runtime = _context(device)
            runtime["heartbeat_ready"] = True
            runtime["heartbeat_failed"] = False
            runtime["heartbeat_timer"] = 0x403c
            return []
        if kind == "networkInfo" and source == 6:
            value = _text(inner.get("gnetkey"), 32, empty=False)
            raw = value.encode("utf-8")
            if len(raw) < 8:
                raise InvalidPacket("MF4 networkInfo requires eight available raw key bytes")
            runtime = _context(device)
            runtime["gnet_key"] = raw[:8]
            runtime["mode"] = 2
            runtime["network_ready"] = True
            return []
        if kind == "loginInfoRes" and source == 6:
            result = _number(inner["r"]) if "r" in inner else 200
            login = inner.get("loginInfo", {})
            if not isinstance(login, dict):
                raise InvalidPacket("MF4 loginInfo must be an object")
            gnet = _number(login["GnetID"]) & 255 if "GnetID" in login else None
            if gnet not in (None, 0):
                raise InvalidPacket("unsafe native nonzero loginInfoRes double-delete rejected atomically")
            runtime = _context(device)
            if gnet is not None:
                runtime["login_gnet_id"] = gnet
            runtime["login_result"] = 0 if result == 200 else 1
            return []
        if kind == "statusCheck" and source == 6:
            raise InvalidPacket("unsafe statusCheck timestamp pointer and broadcast send rejected atomically")
        if kind == "binCmd" and source in (5, 6):
            return self._bin_cmd(device, inner, index, uid, peer)
        return None

    def handle(self, device, outer):
        if outer.get("t") != "pack":
            raise InvalidPacket("MF4 request requires a pack envelope")
        index = outer.get("i")
        if type(index) is not int or index not in (0, 1):
            raise InvalidPacket("invalid MF4 packet key selector")
        raw_uid, raw_peer = outer.get("uid", 0), outer.get("cid", "")
        uid = raw_uid if type(raw_uid) is int else 0
        peer = raw_peer if isinstance(raw_peer, str) else ""
        key = _GENERIC_KEYS[self.source_index] if index else device.key
        inner = decode_pack(outer, key, "aes-ecb-pkcs7", number_parser=_raw_number)
        kind = inner.get("t")
        if not isinstance(kind, str):
            raise InvalidPacket("missing MF4 request type")
        if kind in ("setT", "updateT", "deleteT", "queryT"):
            return _schedule(device, inner, kind, uid, peer, index)
        if kind == "bind":
            mac = _identity(inner, ("mac",), device.mac)
            reply = _reply(device, {"r": 200, "t": "bindok", "mac": mac,
                                    "key": device.key.decode("ascii")}, index, uid, peer)
            return [reply]
        if kind == "status":
            names = _columns(inner, "cols", "opt", maximum=64)
            target = _identity(inner, ("mac", "sub"), device.mac)
            values = _read_values(device, names)
            return [_reply(device, {"t": "dat", "uid": 0, "mac": target,
                                    "cid": device.mac, "cols": names, "dat": values, "r": 200},
                           index, uid, peer)]
        if kind == "cmd":
            names = _columns(inner, "cols", "opt", maximum=64)
            target = _identity(inner, ("mac", "sub"), device.mac)
            options, values, parsed = _command_values(device, names, inner.get("p"))
            reply = _reply(device, {"t": "res", "mac": target, "opt": options,
                                    "p": values, "r": 200}, index, uid, peer)
            _apply_command(device, parsed)
            return [reply]
        result = self._handle_other(device, inner, kind, index, uid, peer)
        return [] if result is None else result


PROFILES = (
    Profile(
        id=_BUILDS[5]["id"], mids=("10001",), hid=_BUILDS[5]["hid"],
        source_sha256=_BUILDS[5]["sha"], initial_state=_initial_state(5),
        handler=MF4Handler(5), max_request_bytes=1460,
    ),
    Profile(
        id=_BUILDS[6]["id"], mids=("10001",), hid=_BUILDS[6]["hid"],
        source_sha256=_BUILDS[6]["sha"], initial_state=_initial_state(6),
        handler=MF4Handler(6), max_request_bytes=1460,
    ),
    Profile(
        id=_BUILDS[16]["id"], mids=("10001",), hid=_BUILDS[16]["hid"],
        source_sha256=_BUILDS[16]["sha"], initial_state=_initial_state(16),
        handler=MF4Handler(16), max_request_bytes=1460,
    ),
)
