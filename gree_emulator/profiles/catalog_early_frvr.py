"""Bounded WB05FR/WB65VR root cache controllers; no mainboard physics.

Numeric names are exact finite source tables, not client polling presets.
Source metadata overrides the numeric cache even for identically named slots.
VR UDP receives select GCM2; discovery alone is ECB, independently of tags.
FR selects unprovisioned Gnet0; BLE GnetDev is not a UDP operation.
"""

from copy import deepcopy
from datetime import datetime, timedelta
import base64
import json
import re

from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
GCM_KEY = b"{yxAHAY_Lm6pbC/<"

FR_NUMERIC = (
    'SwhWifi', 'SwhWifiRes', 'SwhWifiConf', 'AutoUpdate', 'AutoConnCloud', 'lock',
    'datDump', 'datRep', 'datFailRep', 'datPeroid', 'subCnt', 'useTCP',
    'vender', 'bc', 'mid', 'model', 'series', 'apssid',
    'appsw', 'brand', 'catalog', 'country', 'hid', 'host',
    'mac', 'name', 'time', 'ver', 'city', 'cnty',
    'cityid', 'lat', 'lon', 'Pow', 'Mod', 'SetTem',
    'WdSpd', 'Tur', 'Quiet', 'SwUpDn', 'SwingLfRig', 'TemUn',
    'TemRec', 'Lig', 'Air', 'Blo', 'Health', 'SvSt',
    'SwhSw', 'HeatCoolType', 'StHt', 'LTemDry', 'Wet', 'SwhSlp',
    'SlpMod', 'HasTmr', 'TmrLpTms', 'TmrOff', 'TmrOn', 'CurTmHor',
    'CurTmMin', 'TmrOnHorLf', 'TmrOnMinLf', 'TmrOffHorLf', 'TmrOffMinLf', 'DsplySt',
    'EnvFun', 'JFErrorCode', 'AssHt', 'FrshAir', 'AllErr', 'Coolmod',
    'MasSub', 'MasIDUMod', 'GetEr', 'CoolSvStTemMin', 'HeatSvStTemMax', 'HumiSvStTemMin',
    'MaeS', 'FanMod', 'ModS', 'VitiGr', 'GasN', 'TemSor',
    'HumSor', 'PM2P5', 'VOC', 'CO2', 'PctCle', 'PctRe',
    'IDUAirQu', 'AirQu', 'ODUViti', 'GasAvail', 'GasLED', 'GasMod',
    'GasMas', 'PM2P5Sta', 'SorErr', 'CommErr', 'GasQ', 'RunMod',
    'Inloop', 'InVitiGr', 'InVitiGrCg', 'IFDtiGr', 'InEffClRes', 'InEffReRes',
    'IFDClRes', 'EffReRes', 'ErrType', 'GoOut', 'AidHeat', 'SetCoolHumi',
    'SetDeciTem', 'SysSta', 'HCHO', 'HCHOEN', 'PM2P5EN', 'MdVitiGr',
    'MdVitGrCg', 'MdEffClRes', 'MdEffReRes', 'InloopEN', 'Tcloud', 'SorSet',
    'Add0.1', 'Add0.5', 'HumiEnable', 'TemBody', 'CleanState', 'AutoClean',
    'CleanTime', 'AutoSetTemEn', 'Light', 'AssHtSet', 'JFerr', 'AntiFreeze',
    'CleanEn', 'ExtraMod', 'InSeries', 'HalfTemEn', 'ActualWdSpd', 'Heat3DSvStTemMax',
    'Heat2SvStTemMax', 'LowDeHumi', 'IDUModSet', 'MasSubEn', 'Can1MasSubEn', 'Can1MasSub',
    'FClTime', 'PlProg', 'FClRes', 'IDURunMod', 'Humi2SvStTemMin', 'AirLevel',
    'Idemand', 'CoolSvStTemMinD', 'HumiSvStTemMinD', 'HeatSvStTemMaxD', 'MIdType', 'AppTimer',
    'rssi', 'ModelType', 'Heat3DSvStTemMaxD', 'Heat2SvStTemMaxD', 'MSysStatus', 'InTem',
    'OutTem', 'InHumi', 'ScheCoolTem', 'ScheHeatTem', 'ScheName', 'ScheEnable',
    'RemoteLock', 'HoldSetTemp', 'Wstate', 'WschTyp', 'Sch1', 'Sch2',
    'Wtmr1StartHr', 'Wtmr1StartMin', 'Wtmr1EndHr', 'Wtmr1EndMin', 'Wtmr2StartHr', 'Wtmr2StartMin',
    'Wtmr2EndHr', 'Wtmr2EndMin', 'SetTemInt', 'SetTemDec', 'SwhBw', 'Wmod',
    'WstpSv', 'WstpH', 'WatTmp', 'Watpercent', 'BwErr', 'BwBoard',
    'ComEqui', 'FlagHeat', 'PowHeat', 'IntelCtrl', 'OrderHeat', 'ErrHeat',
    'HeatTemMax', 'HeatTemInt', 'HeatTemDec', 'Defrost', 'MuteSch1', 'MuteSch2',
    'Mtmr1StartHr', 'Mtmr1StartMin', 'Mtmr1EndHr', 'Mtmr1EndMin', 'Mtmr2StartHr', 'Mtmr2StartMin',
    'Mtmr2EndHr', 'Mtmr2EndMin', 'PoolFunc', 'FlagPool', 'UaeEn', 'Lamp',
    'LigEn', 'ComStatus', 'PumpStatus', 'AuxStatus', 'InTemInt', 'InTemDec',
    'OutTemInt', 'OutTemDec', 'HeatTemMin', 'CoolTemMax', 'CoolTemMin', 'FastHtWter',
    'ColHtWter', 'HetHtWter', 'LefHom', 'SwDisFct', 'CoWatOutTemSet', 'HeWatOutTemSet',
    'CoHomTemSet', 'HeHomTemSet', 'WatBoxTemSet', 'Reset', 'TemRecB', 'Emegcy',
    'AllInWatTemHi', 'AllInWatTemLo', 'AllOutWatTemHi', 'AllOutWatTemLo', 'HepOutWatTemHi', 'HepOutWatTemLo',
    'WatBoxTemHi', 'WatBoxTemLo', 'RmoHomTemHi', 'RmoHomTemLo', 'WatBoxElcHeRunSta', 'SyAnFroRunSta',
    'ElcHe1RunSta', 'ElcHe2RunSta', 'AnFrzzRunSta', 'VersatiSeries', 'WatBoxExt', 'BordTest',
    'RomHomTemExt', 'FocModSwh', 'ColColetSwh', 'EndTemCotSwh', 'HanFroSwh', 'WatSyExhSwh',
    'EVU', 'EleJan', 'EleFeb', 'EleMar', 'EleApr', 'EleMay',
    'EleJun', 'EleJul', 'EleAug', 'EleSep', 'EleOct', 'EleNov',
    'EleDec', 'EleLastYear', 'AddCap', 'AddCapTemMin', 'DREDEn', 'DRED',
    'NewGB', 'CoEnvTemSet', 'DEnvTemSet', 'WdEnvTemSet', 'HeEnvTemSet', 'FheEnvTemSet',
    'CleanData', 'HolidaySwitch', 'HolidayCycle', 'HolidayRemain', 'DisinfectSwitch', 'DisinfectStatus',
    'DisinfectCycle', 'DisinfectHour', 'DisinfectRemain', 'ECO1', 'ECO2', 'ECO1StartHr',
    'ECO1StartMin', 'ECO1EndHr', 'ECO1EndMin', 'ECO2StartHr', 'ECO2StartMin', 'ECO2EndHr',
    'ECO2EndMin', 'ConsumeDisplayEn', 'ACLkg', 'LkgModEN', 'Hum', 'DeHum',
    'AirBoxLgSwt', 'HumSet', 'DeHumSet', 'HECoreCleRes', 'RunModSet', 'AutoModEN',
    'NewWind', 'AssistHeat', 'Rinse', 'TemRecC', 'TemRecH', 'AutoTemFlag',
    'Buzzer_ON_OFF', None, None, None, None, None,
    None, None, None, None, None, None,
    None, None, None, None, None, None,
    None, None,
)

VR_NUMERIC = (
    'Pow', 'Mod', 'SetTem', 'WdSpd', 'Tur', 'Quiet',
    'SwUpDn', 'SwingLfRig', 'Add0.5', 'TemUn', 'TemRec', 'Lig',
    'Air', 'Blo', 'Health', 'SvSt', 'SwhSw', 'HeatCoolType',
    'StHt', 'LTemDry', 'Wet', 'SwhSlp', 'SlpMod', 'HasTmr',
    'TmrLpTms', 'TmrOff', 'TmrOn', 'CurTmHor', 'CurTmMin', 'TmrOnHorLf',
    'TmrOnMinLf', 'TmrOffHorLf', 'TmrOffMinLf', 'DsplySt', 'EnvFun', 'JFErrorCode',
    'AssHt', 'SwhFreAir', 'AllErr', 'Coolmod', 'HeatCool', 'LedLig',
    'SmartMod', 'Add0.1', 'ModelType', 'ElcEn', 'BleON', 'Mesh',
    'Meshota', 'Reota', 'SubOnline', 'Proaddr', 'Random', 'Unbind',
    'Subcount', 'Lpn', 'Meshid', 'NoD', 'AntiDirectBlow', 'Buzzer_ON_OFF',
    'Wind', 'UDFanPort', 'DnPUDSwing', 'DnPLLRSwing', 'DnPRLRSwing', 'AirQ',
    'PM2P5', 'ElcDatHor', 'ElcDatDte', 'ElcDatMth', 'HumSen', 'ElcP',
    'ElcOnKwh', 'ElcAllKwhClr', 'ElcAllKwhH', 'ElcAllKwhL', 'AutoClean', 'TemSen',
    'Emod', 'PctCleOnTm', 'EvapClr', 'NobodySave', 'BlkTemCom', 'HabitLearn',
    'SmartWind', 'HandCtl', 'VocCtl', 'VocIdiom', 'VocRole', 'ImgUpdateCol',
    'EnvArea1St', 'EnvArea2St', 'EnvArea3St', 'EnvArea4St', 'EnvArea5St', 'EnvArea6St',
    'EnvArea7St', 'EnvArea8St', 'EnvArea9St', 'FbidBloPer', 'DIYGra1PoiAmo', 'SwhDIYGra1',
    'Slp1L1', 'Slp1H1', 'Slp1L2', 'Slp1H2', 'Slp1L3', 'Slp1H3',
    'Slp1L4', 'Slp1H4', 'Slp1L5', 'Slp1H5', 'Slp1L6', 'Slp1H6',
    'Slp1L7', 'Slp1H7', 'Slp1L8', 'Slp1H8', 'ImgVerSta', 'VocUpdateCol',
    'VocVerSta', 'LigSen', 'Video', 'PctCleSetTm', 'AppTimer', 'CO2Level',
    'Dazzling', 'NewTimer', 'NewTimerSet', 'UvcControl', 'MasSub', 'MasIDUMod',
    'GetEr', 'HeatSvStTemMax', 'HumiSvStTemMin', 'CoolSvStTemMin', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'Wmod', 'WsetTmp', 'WschOn', 'WschOnMin', 'WschOff',
    'WschOffMin', 'Wtmr1', 'Wtmr1Min', 'Wtmr2', 'Wtmr2Min', 'Wtmr3',
    'Wtmr3Min', 'WsenTmpH', 'WsenTmpM', 'WsenTmpL', 'Werr', 'WsenNub',
    'WstpSv', 'WstpH', 'WatTmp', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'MaeS', 'FanMod', 'ModS', 'VitiGr', 'GasN',
    'TemSor', 'HumSor', 'PM2P5V', 'VOC', 'CO2', 'PctCle',
    'PctRe', 'IDUAirQu', 'AirQu', 'ODUViti', 'GasAvail', 'GasLED',
    'GasMod', 'GasMas', 'PM2P5Sta', 'SorErr', 'CommErr', 'I2CSwitch',
    'AIEnSaveDis', 'EnvTem', 'DFPoint', 'CpsTem', 'TemsSenOut', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'Dmod', 'Dfltr', 'Dpump', 'Dwet', 'DwatFul', 'DwatSen',
    'estateInsta21', 'estateInsta22', 'estateInsta23', 'estateInsta24', 'ChildLock', 'NoD',
    'NoD', 'NoD', 'NoD', 'Smod', 'Sfog', 'RemWarnLig',
    'NoD', 'NoD', 'Security', 'SecurityMode', 'ImageRecovery', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'Srst', 'Swat', 'Swash', 'SrstPP', 'SrstPF', 'SrstCF',
    'SrstRF', 'SrstAF', 'MakeWat', 'WatErr', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'mode', 'wspd', 'light', 'StTmr',
    'fltrst', 'wipm25', 'wopm25', 'estate', 'airQlt', 'Purify',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'ImgUpdateSucs', 'VocUpdateRes',
    'MicroSen', 'ReplaceHEPA', 'UnmanedShutDown', 'UnmanedOffTime', 'PMVComfort', 'Defrost',
    'Antifreeze', 'FavorMode', 'ImgUpdateSta', 'ImgUpdateFail', 'VocUpdateSta', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'SwhWifi', 'SwhWifiRe', 'SwhWifiCo', 'datDump', 'datRep', 'datFailRe',
    'datPeroid', 'subCnt', 'HidDownPer', 'InHidDownPer', 'OEEPHidDownPer', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'ACStupPos',
    'SaveGuid', 'NoiseSet', 'RoomLen', 'RoomWid', 'RoomHigh', 'CoolNoise',
    'HeatNoise', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'ElcErg', 'ElcGear', 'Elc1Kwh', 'AutoUpdate', 'AutoComnCloud',
    'lock', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'apssid', 'appsw', 'host', 'name', 'time',
    'lat', 'lon', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'vender', 'bc',
    'mid', 'model', 'series', 'brand', 'catalog', 'country',
    'hid', 'mac', 'ver', 'HidSvrVer', 'InHid', 'InHidSvrVer',
    'OEEPHid', 'OEEPHidSvrVer', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD',
)


FR_SPECIAL = frozenset((
    "name", "lock", "AutoUpdate", "time", "host", "hid", "mid", "MOta",
    "bc", "DevID", "MafIdf", "AppTimer", "MidType", "ReportClientID",
    "ModelType", "ver", "vender", "rssi",
))
VR_SPECIAL = frozenset((
    "name", "lock", "AutoUpdate", "time", "host", "hid", "BtHid", "mid",
    "MOta", "bc", "DevID", "MafIdf", "AppTimer", "MidType", "BleON",
    "Mesh", "Meshota", "SubOnline", "Proaddr", "Random", "Unbind",
    "Subcount", "Meshid", "lat", "lon", "vender", "mac", "ver",
    "rssi", "ModelType", "ReportClientID", "Onoff",
))
EMPTY_SPECIAL = frozenset((
    "MOta", "DevID", "MafIdf", "MidType", "ReportClientID", "BtHid",
    "Meshota", "Subcount", "Onoff",
))


def _fields(value):
    if (not isinstance(value, list) or len(value) > 64
            or any(not isinstance(name, str) or not name or "\0" in name for name in value)
            or sum(len(name.encode()) + 1 for name in value) > 512):
        raise InvalidPacket("FrVr requires at most64 bounded property names")
    return value


def _reply(device, inner, index, uid, *, discovery=False):
    gcm = device.profile.handler.vr and not discovery
    size = len(json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode())
    encrypted = size if gcm else (size // 16 + 1) * 16
    if (size >= (1000 if gcm else 1460)
            or 4 * ((encrypted + 2) // 3) + 1 > 1460):
        raise InvalidPacket("FrVr reply exceeds source scratch")
    reply = Reply({"t": "pack", "i": index, "uid": uid,
                   "cid": device.mac, "tcid": ""}, inner,
                  (GCM_KEY if gcm else GENERIC_KEY) if index else device.key,
                  "aes-gcm" if gcm else CODEC, trailing_newline=True)
    if len(encode_reply(reply)) > 1460:
        raise InvalidPacket("FrVr outer reply exceeds source scratch")
    return reply


def _runtime(device, state):
    if "_runtime" not in state:
        state["_runtime"] = {
            "clock": "2026-01-01 00:00:00", "clock_origin": device.last_step,
            "host": "dis.gree.com", "mid": "",
            "lat": "", "lon": "", "bc": "gree" if device.profile.handler.vr else "",
            "vender": "", "ver": "V2.0.0" if device.profile.handler.vr else "V3.2.M",
            "ModelType": "" if device.profile.handler.vr else "0", "rssi": 0, "AppTimer": 0,
            "lock": 0, "AutoUpdate": 0, "BleON": "000000000000", "Mesh": 0,
            "Unbind": "000000000000", "Meshid": "0000", "Proaddr": "0000",
            "Random": "00000000", "children": {}, "ReportClientID": "",
            "frames": {}, "raw_pending": False, "dump_period": 60, "dump_count": 1,
            "status_frames": (b"\0\0\0",) * 5 + (b"\0\0",),
            "timers": {},
        }
    return state["_runtime"]


class FrVrController:
    def __init__(self, *, vr=False):
        self.vr = vr
        self.numeric = frozenset(name for name in (VR_NUMERIC if vr else FR_NUMERIC) if name)
        self.special = VR_SPECIAL if vr else FR_SPECIAL
        self.fields = self.numeric | self.special
        self.write_only = frozenset(("ReportClientID", "Onoff")) & self.fields

    def validate_state(self, state):
        for name, value in state.items():
            if name == "_uid" and type(value) is int and -(1 << 31) <= value < (1 << 31):
                continue
            if (name not in self.numeric or name in self.special
                    or type(value) is not int or not 0 <= value <= 65535):
                raise ValueError("FrVr state requires source uint16 cache fields")

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        """All raw sensors remain explicitly synthetic cache readings."""

    def advertise(self, device, outer):
        runtime = _runtime(device, device.state)
        inner = {"t": "dev", "cid": "", "bc": "", "brand": "gree",
                 "catalog": "gree", "mac": device.mac, "mid": device.mid,
                 "model": "gree", "name": device.name, "lock": 0,
                 "series": "gree", "vender": runtime["vender"], "ver": runtime["ver"],
                 "mqttVer": ""}
        if self.vr:
            del inner["mqttVer"]
            inner["hid"] = device.profile.hid
        return [_reply(device, inner, 1, device.state["_uid"], discovery=True)]

    def _get(self, device, state, runtime, name):
        if name not in self.special:
            return [state[name]]
        if name in EMPTY_SPECIAL:
            return []
        if name == "hid":
            return [device.profile.hid]
        if name == "mid":
            return [runtime["mid"]]
        if name == "mac":
            return [device.mac]
        if name == "name":
            return [device.name]
        if name == "bc" and self.vr:
            return [runtime["bc"].encode().hex()]
        if name == "time":
            try:
                clock = datetime.strptime(runtime["clock"], "%Y-%m-%d %H:%M:%S")
                clock += timedelta(seconds=int(device.last_step - runtime["clock_origin"]))
            except (ValueError, OverflowError) as exc:
                raise InvalidPacket("FrVr synthetic clock out of range") from exc
            return [clock.strftime("%Y-%m-%d %H:%M:%S")]
        if name == "SubOnline":
            return [json.dumps([mac for mac, online in runtime["children"].items() if online],
                               separators=(",", ":")) if runtime["children"] else ""]
        return [runtime[name]]

    def _set_special(self, device, state, runtime, name, value):
        if name == "time" and not self.vr:
            runtime["time_sync_pending"] = True
        elif name == "time":
            try:
                clock = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
                if clock.strftime("%Y-%m-%d %H:%M:%S") != value:
                    raise ValueError("noncanonical calendar")
            except ValueError as exc:
                raise InvalidPacket("VR time requires canonical calendar") from exc
            runtime["clock"], runtime["clock_origin"] = value, device.last_step
        elif name == "ReportClientID":
            if len(value.encode()) > 14:
                raise InvalidPacket("FrVr report client exceeds native frame")
            runtime[name] = value
            frame = bytearray(20)
            frame[:4] = b"~~\x12\x6a"
            frame[4:4 + len(value.encode())] = value.encode()
            runtime["frames"]["ReportClientID"] = bytes(frame)
            runtime["raw_pending"] = True
        elif self.vr and name == "Onoff":
            try:
                records = json.loads(value)
            except (ValueError, TypeError) as exc:
                raise InvalidPacket("VR Onoff requires encoded string array") from exc
            if (not isinstance(records, list) or len(records) > 64
                    or any(not isinstance(record, str)
                           or not re.fullmatch(r"[0-9A-Fa-f]{7}", record) for record in records)):
                raise InvalidPacket("VR Onoff requires bounded seven-hex records")
            frames = []
            for record in records:
                tail = [(ord(char) - (0x57 if char >= "A" else 0x30)) & 255
                        for char in record[4:]]
                address = int(record[:4], 16)
                frame = bytes((0, (tail[2] + 2) & 255, address & 255, address >> 8,
                               6, 0, 1, 5, 0x30, 2, tail[0], tail[1]))
                frames.append(frame)
            runtime["onoff_frames"].extend(frames)
            runtime["raw_pending"] = runtime["raw_pending"] or bool(frames)
        elif self.vr and name in ("host", "lat", "lon"):
            if 1 <= len(value.encode()) <= (20 if name == "host" else 10):
                runtime[name] = value
        elif self.vr and name in ("BleON", "Mesh", "Unbind", "Meshid"):
            width = 4 if name == "Meshid" else 12
            if not re.fullmatch(r"[0-9A-Fa-f]{" + str(width) + "}", value):
                raise InvalidPacket("FrVr address requires exact hexadecimal width")
            if name == "Unbind":
                runtime["Unbind"] = value.lower()
                runtime["children"].pop(value.lower(), None)
            elif name == "Meshid":
                runtime[name] = value.lower()
            else:
                # Both setters write the shared address, not the Mesh status byte.
                runtime["BleON"] = value.lower()

    def _binary(self, runtime, inner):
        if not all(isinstance(inner.get(name), str) for name in ("hex01", "hex6B")):
            raise InvalidPacket("FrVr binary command requires hex01 and hex6B")
        frames = {}
        for name, capacity in (("hex01", 60), ("hex6A", 512), ("hex6B", 60)):
            if name not in inner:
                continue
            try:
                raw = base64.b64decode(inner[name], validate=True)
            except (ValueError, TypeError) as exc:
                raise InvalidPacket("FrVr binary frame requires base64") from exc
            length = raw[2] + (3 if name == "hex6A" else 2) if len(raw) >= 3 else 0
            if (len(raw) < 3 or len(raw) > capacity or raw[:2] != b"~~"
                    or length > len(raw)):
                raise InvalidPacket("FrVr binary frame exceeds native declared length")
            frames[name] = raw[:length]
        primary = bytearray(frames["hex01"])
        if len(primary) < 8:
            raise InvalidPacket("FrVr hex01 requires command byte7")
        primary[7] = 0xaf
        frames["hex01"] = bytes(primary)
        runtime["frames"].update(frames)
        if "hex6A" in frames:
            runtime["raw_aux_pending"] = True
        runtime["raw_pending"] = True

    def _binary_status(self, device, runtime):
        payload = b"".join(runtime["status_frames"])
        if runtime.pop("raw_aux_pending", False):
            payload += runtime["frames"]["hex6A"]
        remaining = len(payload) + 2
        length = bytearray()
        while remaining:
            length.append((remaining & 127) | (128 if remaining > 127 else 0))
            remaining >>= 7
        packet = b"\0\x01\0" + bytes(length) + b"\x01\0" + payload
        header = bytearray(39)
        header[:2] = b"fg"
        header[16:22] = bytes.fromhex(device.mac)
        header[22:26] = int(device.mid, 16).to_bytes(4, "big")
        header[32], header[38] = ord("0"), 2
        runtime["lock"] = 1
        return {"t": "binStatus", "binStatus": base64.b64encode(packet).decode(),
                "header": base64.b64encode(header).decode(), "mac": device.mac}

    def _timer(self, device, runtime, inner):
        kind = inner["t"]
        timers = runtime["timers"]
        if kind == "queryT":
            index, count = inner.get("index"), inner.get("count")
            if (type(index) is not int or type(count) is not int
                    or not 0 <= index <= 255 or not 0 <= count <= 256):
                raise InvalidPacket("VR queryT requires bounded index and count")
            records = []
            for timer_id in range(index, min(10, index + count)):
                if timer_id not in timers:
                    continue
                timer = timers[timer_id]
                records.append({
                    "id": timer_id, "name": timer["name"], "enable": timer["enable"],
                    "week": timer["week"], "hr": timer["hr"], "min": timer["min"],
                    "sec": timer["sec"], "cmd": [{
                        "mac": device.mac, "opt": ["Pow"], "p": [timer["power"]],
                    }],
                })
            return {"t": "listT", "total": len(timers), "index": index, "list": records}
        timer_id = inner.get("id")
        if type(timer_id) is not int or not -(1 << 31) <= timer_id < (1 << 31):
            raise InvalidPacket("VR timer requires signed32 id")
        timer_id &= 255
        if kind == "deleteT":
            if timer_id not in timers:
                raise InvalidPacket("VR rejects native missing-ID count underflow")
            del timers[timer_id]
            return {"t": "resT", "r": 200}
        if kind == "setT" and (len(timers) >= 10 or timer_id in timers):
            raise InvalidPacket("VR timer capacity or duplicate id")
        name, week, commands = inner.get("name"), inner.get("week"), inner.get("cmd")
        if (not isinstance(name, str) or "\0" in name or len(name.encode()) > 31
                or not isinstance(week, list) or len(week) != 7
                or any(type(day) is not int or not -(1 << 31) <= day < (1 << 31)
                       for day in week)
                or not isinstance(commands, list) or len(commands) != 1
                or not isinstance(commands[0], dict)):
            raise InvalidPacket("VR timer requires bounded name/week/command")
        fields = {}
        for field in ("enable", "tz", "hr", "min", "sec"):
            value = inner.get(field)
            if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
                raise InvalidPacket("VR timer requires signed32 numeric fields")
            fields[field] = value
        command = commands[0]
        names, values = _fields(command.get("opt")), command.get("p")
        if (not isinstance(values, list) or len(names) != len(values)
                or any(type(value) is not int or not -(1 << 31) <= value < (1 << 31)
                       for value in values)):
            raise InvalidPacket("VR timer requires matching numeric command")
        power = 0
        for name_, value in zip(names, values):
            if name_ == "Pow":
                power = value & 255
        packed_week = 0
        for bit, day in enumerate(week):
            packed_week |= day << bit
        record = {
            "name": name, "enable": int(fields["enable"] == 1),
            "week": [(packed_week >> bit) & 1 for bit in range(7)],
            "hr": fields["hr"] & 255, "min": fields["min"] & 255,
            # Original successful optional sec parse selects zero, not its input.
            "sec": 0, "power": power,
        }
        if kind == "setT" or timer_id in timers:
            timers[timer_id] = record
        return {"t": "resT", "r": 200}

    def handle(self, device, outer):
        if outer.get("t") != "pack" or outer.get("tcid") != device.mac:
            raise InvalidPacket("wrong FrVr root target")
        index, uid = outer.get("i"), outer.get("uid")
        if (type(index) is not int or index not in (0, 1)
                or type(uid) is not int or not -(1 << 31) <= uid < (1 << 31)
                or not isinstance(outer.get("cid", ""), str)):
            raise InvalidPacket("invalid FrVr session selector")
        if not self.vr and "tag" in outer:
            raise InvalidPacket("FR ECB transport rejects authenticated envelopes")
        codec = "aes-gcm" if self.vr else CODEC
        generic = GCM_KEY if self.vr else GENERIC_KEY
        inner = decode_pack(outer, generic if index else device.key, codec)
        identities = (device.mac,) if self.vr else (device.mac, device.mac + "00")
        for selector in ("mac", "sub"):
            if selector in inner and inner[selector] not in identities:
                raise InvalidPacket("conflicting FrVr inner identity")
        target = inner.get("mac", inner.get("sub", device.mac))
        kind = inner.get("t")
        if not isinstance(kind, str) or not kind or "\0" in kind:
            raise InvalidPacket("invalid FrVr request type")
        pending = deepcopy(device.state)
        runtime = _runtime(device, pending)
        if kind == "bind":
            reply = _reply(device, {"r": 200, "t": "bindok",
                                    "mac": device.mac, "key": device.key.decode("ascii")}, 1, uid)
        elif kind == "status":
            names = _fields(inner.get("cols"))
            selected, values = [], []
            for name in names:
                if name in self.fields and name not in self.write_only:
                    selected.append(name)
                    values.extend(self._get(device, pending, runtime, name))
            response = {"t": "dat", "uid": uid, "mac": target, "cid": device.mac,
                        "dat": values, "cols": selected, "r": 200}
            reply = _reply(device, response, 0, uid)
        elif kind == "cmd":
            names, values = _fields(inner.get("opt")), inner.get("p")
            if not isinstance(values, list) or len(names) != len(values):
                raise InvalidPacket("FrVr requires matching command arrays")
            local, numeric = [], []
            for name, value in zip(names, values):
                if name not in self.fields:
                    raise InvalidPacket("FrVr unknown command crosses mainboard boundary")
                if name in self.special:
                    if not isinstance(value, str) or "\0" in value:
                        raise InvalidPacket("FrVr local command requires string scalar")
                    local.append((name, value))
                else:
                    if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
                        raise InvalidPacket("FrVr numeric command requires signed32 integer")
                    pending[name] = value & 65535
                    numeric.append((name, value))
            if any(name == "Onoff" for name, _ in local):
                runtime["onoff_frames"] = []
            for name, value in local:
                self._set_special(device, pending, runtime, name, value)
            selected, applied = [], []
            for name, _ in local:
                if name not in self.write_only:
                    selected.append(name)
                    applied.extend(self._get(device, pending, runtime, name))
            for name, value in numeric:
                selected.append(name)
                applied.append(value)
            reply = _reply(device, {"t": "res", "mac": target,
                                    "p": applied, "opt": selected, "r": 200}, 0, uid)
        elif kind == "binCmd" and not self.vr:
            self._binary(runtime, inner)
            reply = _reply(device, {"t": "res", "r": 200}, 0, uid)
        elif self.vr and kind in ("setT", "queryT", "deleteT", "updateT"):
            reply = _reply(device, self._timer(device, runtime, inner), 0, uid)
        elif kind == "UBindok" and not self.vr:
            reply = _reply(device, self._binary_status(device, runtime), 0, uid)
        elif kind == "dump":
            period, count = inner.get("period"), inner.get("cnt")
            if type(period) is not int or type(count) is not int:
                raise InvalidPacket("FrVr dump requires integer period and count")
            if not self.vr:
                runtime["dump_period"] = 60 if period < 1 else min(4096, max(5, period))
                runtime["dump_count"] = max(1, count)
                runtime["dump_pending"] = True
            reply = _reply(device, {"t": "ret", "r": 200}, 0, uid)
        elif kind == "subDev" and not self.vr:
            page = inner.get("i", 0)
            if type(page) is not int or not -(1 << 31) <= page < (1 << 31):
                raise InvalidPacket("FrVr subDev requires signed32 page")
            child = {"mac": device.mac + "00", "name": "ACUnit", "mid": device.mid,
                     "model": "gree", "lock": 0}
            reply = _reply(device, {"t": "subList", "r": 200, "c": 1,
                                    "i": page, "list": [child] if page == 0 else []}, 0, uid)
        elif kind == "reset" and not self.vr:
            if inner.get("mac") != device.mac:
                raise InvalidPacket("wrong FrVr reset identity")
            # The bounded restart resets synthetic cache, not host configuration.
            pending = dict(device.profile.initial_state)
            reply = _reply(device, {"t": "res", "r": 200}, 0, uid)
        elif kind == "hbok" and not self.vr:
            runtime["dump_pending"] = False
            reply = None
        elif kind == "upgrade":
            raise InvalidPacket("FrVr OTA image execution crosses the companion boundary")
        else:
            return []
        pending["_uid"] = uid
        device.state.clear()
        device.state.update(pending)
        return [] if reply is None else [reply]


PROFILES = (
    Profile(
        id="sim-wb05fr-v1.40-4005", mids=("4005",),
        hid="362001066515+U-WB05FRV1.40.bin",
        source_sha256="e44d45713ebcb469f0c6c5e0e8f2a5ab983eea9e3fc295472bb1125ca677a6df",
        initial_state={**dict.fromkeys(
            (name for name in FR_NUMERIC if name and name not in FR_SPECIAL), 0), "_uid": 0},
        handler=FrVrController(),
    ),
    Profile(
        id="sim-wb65vr-v1.02-11f00", mids=("11f00",),
        hid="362001067427+U-WB65VRV1.02.bin",
        source_sha256="d5b25b99317c224d82674e45965914fb652aa25581a586a765d1e9536286e5e7",
        initial_state={**dict.fromkeys(
            (name for name in VR_NUMERIC if name not in VR_SPECIAL), 0), "_uid": 0},
        handler=FrVrController(vr=True), max_request_bytes=1460,
    ),
)
