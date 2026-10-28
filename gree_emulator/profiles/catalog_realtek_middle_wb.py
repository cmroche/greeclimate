"""Exact source-qualified middle WB LAN cache controllers.

Only canonical sources with actual UDP7000 ingress, a real scan MID producer,
and independently traced packet crypto are admitted. A nonzero configured MCU
0x44 MID is explicit input; no physical MID, same-MID union or AC typing is
inferred. Source34/36 use ECB;38/39/40 use GCM for pack and ECB for discovery.

The original SDK partitions primary/numeric options and parses lexical decimal
prefixes, not Python JSON numbers. This model retains those observable quirks,
known zero-scalar getters, ignored fields, raw ACKs and native counter underflow.
Native buffer overflows, invalid-pointer paths and partial malformed writes are
instead rejected atomically. Clock/queues/flash intents are per-device synthetic
state, not a firmware boot, physical UART/BLE, ROM/MMIO or actual OTA execution.

Source provenance, original instructions and native histories are pinned in
RealtekMiddle/new-metadata-integration.json and wb-new-command-abi.json. The
source tables below contain independently recovered FIRST matches, not unions.
"""

import base64
import binascii
import json
import math
import re
from datetime import datetime, timedelta

from ..wire import InvalidPacket, Reply, _json, _validate_outer, decode_pack
from . import Profile

SCAN_KEY = b"a3K8Bx%2r8Y7#xDh"
GCM_GENERIC_KEY = b"{yxAHAY_Lm6pbC/<"
ECB = "aes-ecb-pkcs7"
GCM = "aes-gcm"

_SOURCE_DATA = {34: {'sha256': 'a53e88d30bf65b3987ff65c362ac8159f63b3f2a36650e816905f2fc4a2cbb85',
      'hid': '362001065811+U-WB63DF(RT)V1.00.bin',
      'ver': 'V3.0.0',
      'advertise_hid': False,
      'numeric': {'SwhWifi': 0,
                  'SwhWifiRes': 1,
                  'SwhWifiConf': 2,
                  'AutoUpdate': 3,
                  'AutoConnCloud': 4,
                  'lock': 5,
                  'datDump': 6,
                  'datRep': 7,
                  'datFailRep': 8,
                  'datPeroid': 9,
                  'subCnt': 10,
                  'useTCP': 11,
                  'vender': 12,
                  'bc': 13,
                  'mid': 14,
                  'model': 15,
                  'series': 16,
                  'apssid': 17,
                  'appsw': 18,
                  'brand': 19,
                  'catalog': 20,
                  'country': 21,
                  'hid': 22,
                  'host': 23,
                  'mac': 24,
                  'name': 25,
                  'time': 26,
                  'ver': 27,
                  'city': 28,
                  'cnty': 29,
                  'cityid': 30,
                  'lat': 31,
                  'lon': 32,
                  'Pow': 33,
                  'Mod': 34,
                  'SetTem': 35,
                  'WdSpd': 36,
                  'Tur': 37,
                  'Quiet': 38,
                  'SwUpDn': 39,
                  'SwingLfRig': 40,
                  'TemUn': 41,
                  'TemRec': 42,
                  'Lig': 43,
                  'Air': 44,
                  'Blo': 45,
                  'Health': 46,
                  'SvSt': 47,
                  'SwhSw': 48,
                  'HeatCoolType': 49,
                  'StHt': 50,
                  'LTemDry': 51,
                  'Wet': 52,
                  'SwhSlp': 53,
                  'SlpMod': 54,
                  'HasTmr': 55,
                  'TmrLpTms': 56,
                  'TmrOff': 57,
                  'TmrOn': 58,
                  'CurTmHor': 59,
                  'CurTmMin': 60,
                  'TmrOnHorLf': 61,
                  'TmrOnMinLf': 62,
                  'TmrOffHorLf': 63,
                  'TmrOffMinLf': 64,
                  'DsplySt': 65,
                  'EnvFun': 66,
                  'JFErrorCode': 67,
                  'AssHt': 68,
                  'FrshAir': 69,
                  'AllErr': 70,
                  'Coolmod': 71,
                  'MasSub': 72,
                  'MasIDUMod': 73,
                  'GetEr': 74,
                  'CoolSvStTemMin': 75,
                  'HeatSvStTemMax': 76,
                  'HumiSvStTemMin': 77,
                  'MaeS': 78,
                  'FanMod': 79,
                  'ModS': 80,
                  'VitiGr': 81,
                  'GasN': 82,
                  'TemSor': 83,
                  'HumSor': 84,
                  'PM2P5': 85,
                  'VOC': 86,
                  'CO2': 87,
                  'PctCle': 88,
                  'PctRe': 89,
                  'IDUAirQu': 90,
                  'AirQu': 91,
                  'ODUViti': 92,
                  'GasAvail': 93,
                  'GasLED': 94,
                  'GasMod': 95,
                  'GasMas': 96,
                  'PM2P5Sta': 97,
                  'SorErr': 98,
                  'CommErr': 99,
                  'GasQ': 100,
                  'RunMod': 101,
                  'Inloop': 102,
                  'InVitiGr': 103,
                  'InVitiGrCg': 104,
                  'IFDtiGr': 105,
                  'InEffClRes': 106,
                  'InEffReRes': 107,
                  'IFDClRes': 108,
                  'EffReRes': 109,
                  'ErrType': 110,
                  'GoOut': 111,
                  'AidHeat': 112,
                  'SetCoolHumi': 113,
                  'SetDeciTem': 114,
                  'SysSta': 115,
                  'HCHO': 116,
                  'HCHOEN': 117,
                  'PM2P5EN': 118,
                  'MdVitiGr': 119,
                  'MdVitGrCg': 120,
                  'MdEffClRes': 121,
                  'MdEffReRes': 122,
                  'InloopEN': 123,
                  'Tcloud': 124,
                  'SorSet': 125,
                  'Add0.1': 126,
                  'Add0.5': 127,
                  'HumiEnable': 128,
                  'TemBody': 129,
                  'CleanState': 130,
                  'AutoClean': 131,
                  'CleanTime': 132,
                  'AutoSetTemEn': 133,
                  'Light': 134,
                  'AssHtSet': 135,
                  'JFerr': 136,
                  'AntiFreeze': 137,
                  'CleanEn': 138,
                  'ExtraMod': 139,
                  'InSeries': 140,
                  'HalfTemEn': 141,
                  'ActualWdSpd': 142,
                  'Heat3DSvStTemMax': 143,
                  'Heat2SvStTemMax': 144,
                  'LowDeHumi': 145,
                  'IDUModSet': 146,
                  'MasSubEn': 147,
                  'Can1MasSubEn': 148,
                  'Can1MasSub': 149,
                  'FClTime': 150,
                  'PlProg': 151,
                  'FClRes': 152,
                  'IDURunMod': 153,
                  'Humi2SvStTemMin': 154,
                  'AirLevel': 155,
                  'Idemand': 156,
                  'CoolSvStTemMinD': 157,
                  'HumiSvStTemMinD': 158,
                  'HeatSvStTemMaxD': 159,
                  'MIdType': 160,
                  'AppTimer': 161,
                  'rssi': 162,
                  'ModelType': 163,
                  'Heat3DSvStTemMaxD': 164,
                  'Heat2SvStTemMaxD': 165,
                  'MSysStatus': 166,
                  'InTem': 167,
                  'OutTem': 168,
                  'InHumi': 169,
                  'ScheCoolTem': 170,
                  'ScheHeatTem': 171,
                  'ScheName': 172,
                  'ScheEnable': 173,
                  'I2CSwitch': 174,
                  'AIEnSaveDis': 175,
                  'NoD': 176},
      'primary': ('name',
                  'lock',
                  'AutoUpdate',
                  'time',
                  'host',
                  'hid',
                  'BtHid',
                  'mid',
                  'MOta',
                  'bc',
                  'DevID',
                  'MafIdf',
                  'AppTimer',
                  'MidType',
                  'BleON',
                  'Mesh',
                  'Meshota',
                  'SubOnline',
                  'Proaddr',
                  'Random',
                  'Unbind',
                  'Subcount',
                  'Meshid',
                  'lat',
                  'lon',
                  'vender',
                  'mac',
                  'ver',
                  'rssi',
                  'ModelType')},
 36: {'sha256': 'd94187356e299bc8df99a237f7fd396bf14d6446ec8a8393b087218951421260',
      'hid': '362001067928+U-WB65AR11V1.00.bin',
      'ver': 'V3.0.0',
      'advertise_hid': True,
      'numeric': {'Pow': 0,
                  'Mod': 1,
                  'SetTem': 2,
                  'WdSpd': 3,
                  'Tur': 4,
                  'Quiet': 5,
                  'SwUpDn': 6,
                  'SwingLfRig': 7,
                  'Add0.5': 8,
                  'TemUn': 9,
                  'TemRec': 10,
                  'Lig': 11,
                  'Air': 12,
                  'Blo': 13,
                  'Health': 14,
                  'SvSt': 15,
                  'SwhSw': 16,
                  'HeatCoolType': 17,
                  'StHt': 18,
                  'LTemDry': 19,
                  'Wet': 20,
                  'SwhSlp': 21,
                  'SlpMod': 22,
                  'HasTmr': 23,
                  'TmrLpTms': 24,
                  'TmrOff': 25,
                  'TmrOn': 26,
                  'CurTmHor': 27,
                  'CurTmMin': 28,
                  'TmrOnHorLf': 29,
                  'TmrOnMinLf': 30,
                  'TmrOffHorLf': 31,
                  'TmrOffMinLf': 32,
                  'DsplySt': 33,
                  'EnvFun': 34,
                  'JFErrorCode': 35,
                  'AssHt': 36,
                  'SwhFreAir': 37,
                  'AllErr': 38,
                  'Coolmod': 39,
                  'HeatCool': 40,
                  'LedLig': 41,
                  'SmartMod': 42,
                  'Add0.1': 43,
                  'ModelType': 44,
                  'ElcEn': 45,
                  'BleON': 46,
                  'Mesh': 47,
                  'Meshota': 48,
                  'Reota': 49,
                  'SubOnline': 50,
                  'Proaddr': 51,
                  'Random': 52,
                  'Unbind': 53,
                  'Subcount': 54,
                  'Lpn': 55,
                  'Meshid': 56,
                  'NoD': 57,
                  'AntiDirectBlow': 58,
                  'Buzzer_ON_OFF': 59,
                  'Wind': 60,
                  'UDFanPort': 61,
                  'DnPUDSwing': 62,
                  'DnPLLRSwing': 63,
                  'DnPRLRSwing': 64,
                  'AirQ': 65,
                  'PM2P5': 66,
                  'ElcDatHor': 67,
                  'ElcDatDte': 68,
                  'ElcDatMth': 69,
                  'HumSen': 70,
                  'ElcP': 71,
                  'ElcOnKwh': 72,
                  'ElcAllKwhClr': 73,
                  'ElcAllKwhH': 74,
                  'ElcAllKwhL': 75,
                  'AutoClean': 76,
                  'TemSen': 77,
                  'Emod': 78,
                  'PctCleOnTm': 79,
                  'EvapClr': 80,
                  'NobodySave': 81,
                  'BlkTemCom': 82,
                  'HabitLearn': 83,
                  'SmartWind': 84,
                  'HandCtl': 85,
                  'VocCtl': 86,
                  'VocIdiom': 87,
                  'VocRole': 88,
                  'ImgUpdateCol': 89,
                  'EnvArea1St': 90,
                  'EnvArea2St': 91,
                  'EnvArea3St': 92,
                  'EnvArea4St': 93,
                  'EnvArea5St': 94,
                  'EnvArea6St': 95,
                  'EnvArea7St': 96,
                  'EnvArea8St': 97,
                  'EnvArea9St': 98,
                  'FbidBloPer': 99,
                  'DIYGra1PoiAmo': 100,
                  'SwhDIYGra1': 101,
                  'Slp1L1': 102,
                  'Slp1H1': 103,
                  'Slp1L2': 104,
                  'Slp1H2': 105,
                  'Slp1L3': 106,
                  'Slp1H3': 107,
                  'Slp1L4': 108,
                  'Slp1H4': 109,
                  'Slp1L5': 110,
                  'Slp1H5': 111,
                  'Slp1L6': 112,
                  'Slp1H6': 113,
                  'Slp1L7': 114,
                  'Slp1H7': 115,
                  'Slp1L8': 116,
                  'Slp1H8': 117,
                  'ImgVerSta': 118,
                  'VocUpdateCol': 119,
                  'VocVerSta': 120,
                  'LigSen': 121,
                  'Video': 122,
                  'PctCleSetTm': 123,
                  'AppTimer': 124,
                  'CO2Level': 125,
                  'Dazzling': 126,
                  'NewTimer': 127,
                  'NewTimerSet': 128,
                  'UvcControl': 129,
                  'MasSub': 130,
                  'MasIDUMod': 131,
                  'GetEr': 132,
                  'HeatSvStTemMax': 133,
                  'HumiSvStTemMin': 134,
                  'CoolSvStTemMin': 135,
                  'Wmod': 145,
                  'WsetTmp': 146,
                  'WschOn': 147,
                  'WschOnMin': 148,
                  'WschOff': 149,
                  'WschOffMin': 150,
                  'Wtmr1': 151,
                  'Wtmr1Min': 152,
                  'Wtmr2': 153,
                  'Wtmr2Min': 154,
                  'Wtmr3': 155,
                  'Wtmr3Min': 156,
                  'WsenTmpH': 157,
                  'WsenTmpM': 158,
                  'WsenTmpL': 159,
                  'Werr': 160,
                  'WsenNub': 161,
                  'WstpSv': 162,
                  'WstpH': 163,
                  'WatTmp': 164,
                  'MaeS': 175,
                  'FanMod': 176,
                  'ModS': 177,
                  'VitiGr': 178,
                  'GasN': 179,
                  'TemSor': 180,
                  'HumSor': 181,
                  'PM2P5V': 182,
                  'VOC': 183,
                  'CO2': 184,
                  'PctCle': 185,
                  'PctRe': 186,
                  'IDUAirQu': 187,
                  'AirQu': 188,
                  'ODUViti': 189,
                  'GasAvail': 190,
                  'GasLED': 191,
                  'GasMod': 192,
                  'GasMas': 193,
                  'PM2P5Sta': 194,
                  'SorErr': 195,
                  'CommErr': 196,
                  'I2CSwitch': 197,
                  'AIEnSaveDis': 198,
                  'EnvTem': 199,
                  'DFPoint': 200,
                  'CpsTem': 201,
                  'TemsSenOut': 202,
                  'Dmod': 210,
                  'Dfltr': 211,
                  'Dpump': 212,
                  'Dwet': 213,
                  'DwatFul': 214,
                  'DwatSen': 215,
                  'estateInsta21': 216,
                  'estateInsta22': 217,
                  'estateInsta23': 218,
                  'estateInsta24': 219,
                  'ChildLock': 220,
                  'Smod': 225,
                  'Sfog': 226,
                  'RemWarnLig': 227,
                  'Security': 230,
                  'SecurityMode': 231,
                  'ImageRecovery': 232,
                  'Srst': 240,
                  'Swat': 241,
                  'Swash': 242,
                  'SrstPP': 243,
                  'SrstPF': 244,
                  'SrstCF': 245,
                  'SrstRF': 246,
                  'SrstAF': 247,
                  'MakeWat': 248,
                  'WatErr': 249,
                  'mode': 260,
                  'wspd': 261,
                  'light': 262,
                  'StTmr': 263,
                  'fltrst': 264,
                  'wipm25': 265,
                  'wopm25': 266,
                  'estate': 267,
                  'airQlt': 268,
                  'Purify': 269,
                  'ImgUpdateSucs': 280,
                  'VocUpdateRes': 281,
                  'MicroSen': 282,
                  'ReplaceHEPA': 283,
                  'UnmanedShutDown': 284,
                  'UnmanedOffTime': 285,
                  'PMVComfort': 286,
                  'Defrost': 287,
                  'Antifreeze': 288,
                  'FavorMode': 289,
                  'ImgUpdateSta': 290,
                  'ImgUpdateFail': 291,
                  'VocUpdateSta': 292,
                  'SwhWifi': 360,
                  'SwhWifiRe': 361,
                  'SwhWifiCo': 362,
                  'datDump': 363,
                  'datRep': 364,
                  'datFailRe': 365,
                  'datPeroid': 366,
                  'subCnt': 367,
                  'HidDownPer': 368,
                  'InHidDownPer': 369,
                  'OEEPHidDownPer': 370,
                  'ACStupPos': 395,
                  'SaveGuid': 396,
                  'NoiseSet': 397,
                  'RoomLen': 398,
                  'RoomWid': 399,
                  'RoomHigh': 400,
                  'CoolNoise': 401,
                  'HeatNoise': 402,
                  'ElcErg': 415,
                  'ElcGear': 416,
                  'Elc1Kwh': 417,
                  'AutoUpdate': 418,
                  'AutoComnCloud': 419,
                  'lock': 420,
                  'apssid': 445,
                  'appsw': 446,
                  'host': 447,
                  'name': 448,
                  'time': 449,
                  'lat': 450,
                  'lon': 451,
                  'vender': 460,
                  'bc': 461,
                  'mid': 462,
                  'model': 463,
                  'series': 464,
                  'brand': 465,
                  'catalog': 466,
                  'country': 467,
                  'hid': 468,
                  'mac': 469,
                  'ver': 470,
                  'HidSvrVer': 471,
                  'InHid': 472,
                  'InHidSvrVer': 473,
                  'OEEPHid': 474,
                  'OEEPHidSvrVer': 475},
      'primary': ('name',
                  'lock',
                  'AutoUpdate',
                  'time',
                  'host',
                  'hid',
                  'BtHid',
                  'mid',
                  'MOta',
                  'bc',
                  'DevID',
                  'MafIdf',
                  'AppTimer',
                  'MidType',
                  'BleON',
                  'Mesh',
                  'Meshota',
                  'SubOnline',
                  'Proaddr',
                  'Random',
                  'Unbind',
                  'Subcount',
                  'Meshid',
                  'lat',
                  'lon',
                  'vender',
                  'mac',
                  'ver',
                  'rssi',
                  'ModelType')},
 38: {'sha256': '841d662cd86bb6f39b5ac10990a6333ecaf9c96afbd6747f0159d2ae2ea07ae9',
      'hid': '362001066300+U-4MWB05DF13V3.05.bin',
      'ver': 'V3.2.M',
      'advertise_hid': True,
      'numeric': {'Pow': 0,
                  'Mod': 1,
                  'SetTem': 2,
                  'WdSpd': 3,
                  'Tur': 4,
                  'Quiet': 5,
                  'SwUpDn': 6,
                  'SwingLfRig': 7,
                  'Add0.5': 8,
                  'TemUn': 9,
                  'TemRec': 10,
                  'Lig': 11,
                  'Air': 12,
                  'Blo': 13,
                  'Health': 14,
                  'SvSt': 15,
                  'SwhSw': 16,
                  'HeatCoolType': 17,
                  'StHt': 18,
                  'LTemDry': 19,
                  'Wet': 20,
                  'SwhSlp': 21,
                  'SlpMod': 22,
                  'HasTmr': 23,
                  'TmrLpTms': 24,
                  'TmrOff': 25,
                  'TmrOn': 26,
                  'CurTmHor': 27,
                  'CurTmMin': 28,
                  'TmrOnHorLf': 29,
                  'TmrOnMinLf': 30,
                  'TmrOffHorLf': 31,
                  'TmrOffMinLf': 32,
                  'DsplySt': 33,
                  'EnvFun': 34,
                  'JFErrorCode': 35,
                  'AssHt': 36,
                  'SwhFreAir': 37,
                  'AllErr': 38,
                  'Coolmod': 39,
                  'HeatCool': 40,
                  'LedLig': 41,
                  'SmartMod': 42,
                  'Add0.1': 43,
                  'ModelType': 44,
                  'ElcEn': 45,
                  'BleON': 46,
                  'Mesh': 47,
                  'Meshota': 48,
                  'Reota': 49,
                  'SubOnline': 50,
                  'Proaddr': 51,
                  'Random': 52,
                  'Unbind': 53,
                  'Subcount': 54,
                  'Lpn': 55,
                  'Meshid': 56,
                  'NoD': 57,
                  'AntiDirectBlow': 58,
                  'Buzzer_ON_OFF': 59,
                  'Wind': 60,
                  'UDFanPort': 61,
                  'DnPUDSwing': 62,
                  'DnPLLRSwing': 63,
                  'DnPRLRSwing': 64,
                  'AirQ': 65,
                  'PM2P5': 66,
                  'ElcDatHor': 67,
                  'ElcDatDte': 68,
                  'ElcDatMth': 69,
                  'HumSen': 70,
                  'ElcP': 71,
                  'ElcOnKwh': 72,
                  'ElcAllKwhClr': 73,
                  'ElcAllKwhH': 74,
                  'ElcAllKwhL': 75,
                  'AutoClean': 76,
                  'TemSen': 77,
                  'Emod': 78,
                  'PctCleOnTm': 79,
                  'EvapClr': 80,
                  'NobodySave': 81,
                  'BlkTemCom': 82,
                  'HabitLearn': 83,
                  'SmartWind': 84,
                  'HandCtl': 85,
                  'VocCtl': 86,
                  'VocIdiom': 87,
                  'VocRole': 88,
                  'ImgUpdateCol': 89,
                  'EnvArea1St': 90,
                  'EnvArea2St': 91,
                  'EnvArea3St': 92,
                  'EnvArea4St': 93,
                  'EnvArea5St': 94,
                  'EnvArea6St': 95,
                  'EnvArea7St': 96,
                  'EnvArea8St': 97,
                  'EnvArea9St': 98,
                  'FbidBloPer': 99,
                  'DIYGra1PoiAmo': 100,
                  'SwhDIYGra1': 101,
                  'Slp1L1': 102,
                  'Slp1H1': 103,
                  'Slp1L2': 104,
                  'Slp1H2': 105,
                  'Slp1L3': 106,
                  'Slp1H3': 107,
                  'Slp1L4': 108,
                  'Slp1H4': 109,
                  'Slp1L5': 110,
                  'Slp1H5': 111,
                  'Slp1L6': 112,
                  'Slp1H6': 113,
                  'Slp1L7': 114,
                  'Slp1H7': 115,
                  'Slp1L8': 116,
                  'Slp1H8': 117,
                  'ImgVerSta': 118,
                  'VocUpdateCol': 119,
                  'VocVerSta': 120,
                  'LigSen': 121,
                  'Video': 122,
                  'PctCleSetTm': 123,
                  'AppTimer': 124,
                  'CO2Level': 125,
                  'Dazzling': 126,
                  'NewTimer': 127,
                  'NewTimerSet': 128,
                  'UvcControl': 129,
                  'MasSub': 130,
                  'MasIDUMod': 131,
                  'GetEr': 132,
                  'HeatSvStTemMax': 133,
                  'HumiSvStTemMin': 134,
                  'CoolSvStTemMin': 135,
                  'Wmod': 145,
                  'WsetTmp': 146,
                  'WschOn': 147,
                  'WschOnMin': 148,
                  'WschOff': 149,
                  'WschOffMin': 150,
                  'Wtmr1': 151,
                  'Wtmr1Min': 152,
                  'Wtmr2': 153,
                  'Wtmr2Min': 154,
                  'Wtmr3': 155,
                  'Wtmr3Min': 156,
                  'WsenTmpH': 157,
                  'WsenTmpM': 158,
                  'WsenTmpL': 159,
                  'Werr': 160,
                  'WsenNub': 161,
                  'WstpSv': 162,
                  'WstpH': 163,
                  'WatTmp': 164,
                  'MaeS': 175,
                  'FanMod': 176,
                  'ModS': 177,
                  'VitiGr': 178,
                  'GasN': 179,
                  'TemSor': 180,
                  'HumSor': 181,
                  'PM2P5V': 182,
                  'VOC': 183,
                  'CO2': 184,
                  'PctCle': 185,
                  'PctRe': 186,
                  'IDUAirQu': 187,
                  'AirQu': 188,
                  'ODUViti': 189,
                  'GasAvail': 190,
                  'GasLED': 191,
                  'GasMod': 192,
                  'GasMas': 193,
                  'PM2P5Sta': 194,
                  'SorErr': 195,
                  'CommErr': 196,
                  'I2CSwitch': 197,
                  'AIEnSaveDis': 198,
                  'EnvTem': 199,
                  'DFPoint': 200,
                  'CpsTem': 201,
                  'TemsSenOut': 202,
                  'OutEnvTem': 203,
                  'InEvaTem': 204,
                  'CompressorTem': 205,
                  'CompressorFqy': 206,
                  'Dmod': 210,
                  'Dfltr': 211,
                  'Dpump': 212,
                  'Dwet': 213,
                  'DwatFul': 214,
                  'DwatSen': 215,
                  'estateInsta21': 216,
                  'estateInsta22': 217,
                  'estateInsta23': 218,
                  'estateInsta24': 219,
                  'ChildLock': 220,
                  'Smod': 225,
                  'Sfog': 226,
                  'RemWarnLig': 227,
                  'Security': 230,
                  'SecurityMode': 231,
                  'ImageRecovery': 232,
                  'Srst': 240,
                  'Swat': 241,
                  'Swash': 242,
                  'SrstPP': 243,
                  'SrstPF': 244,
                  'SrstCF': 245,
                  'SrstRF': 246,
                  'SrstAF': 247,
                  'MakeWat': 248,
                  'WatErr': 249,
                  'mode': 260,
                  'wspd': 261,
                  'light': 262,
                  'StTmr': 263,
                  'fltrst': 264,
                  'wipm25': 265,
                  'wopm25': 266,
                  'estate': 267,
                  'airQlt': 268,
                  'Purify': 269,
                  'ImgUpdateSucs': 280,
                  'VocUpdateRes': 281,
                  'MicroSen': 282,
                  'ReplaceHEPA': 283,
                  'UnmanedShutDown': 284,
                  'UnmanedOffTime': 285,
                  'PMVComfort': 286,
                  'Defrost': 287,
                  'Antifreeze': 288,
                  'FavorMode': 289,
                  'ImgUpdateSta': 290,
                  'ImgUpdateFail': 291,
                  'VocUpdateSta': 292,
                  'SwhWifi': 360,
                  'SwhWifiRe': 361,
                  'SwhWifiCo': 362,
                  'datDump': 363,
                  'datRep': 364,
                  'datFailRe': 365,
                  'datPeroid': 366,
                  'subCnt': 367,
                  'HidDownPer': 368,
                  'InHidDownPer': 369,
                  'OEEPHidDownPer': 370,
                  'ACStupPos': 395,
                  'SaveGuid': 396,
                  'NoiseSet': 397,
                  'RoomLen': 398,
                  'RoomWid': 399,
                  'RoomHigh': 400,
                  'CoolNoise': 401,
                  'HeatNoise': 402,
                  'ElcErg': 415,
                  'ElcGear': 416,
                  'Elc1Kwh': 417,
                  'AutoUpdate': 418,
                  'AutoComnCloud': 419,
                  'lock': 420,
                  'apssid': 445,
                  'appsw': 446,
                  'host': 447,
                  'name': 448,
                  'time': 449,
                  'lat': 450,
                  'lon': 451,
                  'vender': 460,
                  'bc': 461,
                  'mid': 462,
                  'model': 463,
                  'series': 464,
                  'brand': 465,
                  'catalog': 466,
                  'country': 467,
                  'hid': 468,
                  'mac': 469,
                  'ver': 470,
                  'HidSvrVer': 471,
                  'InHid': 472,
                  'InHidSvrVer': 473,
                  'OEEPHid': 474,
                  'OEEPHidSvrVer': 475},
      'primary': ('name',
                  'lock',
                  'AutoUpdate',
                  'time',
                  'host',
                  'hid',
                  'BtHid',
                  'mid',
                  'MOta',
                  'bc',
                  'DevID',
                  'MafIdf',
                  'AppTimer',
                  'MidType',
                  'BleON',
                  'Mesh',
                  'Meshota',
                  'SubOnline',
                  'Proaddr',
                  'Random',
                  'Unbind',
                  'Subcount',
                  'Meshid',
                  'lat',
                  'lon',
                  'vender',
                  'mac',
                  'ver',
                  'rssi',
                  'ModelType',
                  'FaultDisplay')},
 39: {'sha256': '5f14dd184941feebe5e7fc2d53e3d7d48eb452ec8a5e5da1fbc7cb430ffc0cfd',
      'hid': '362001067540+U-WB05WR13V2.06.bin',
      'ver': 'V2.0.0',
      'advertise_hid': True,
      'numeric': {'Pow': 0,
                  'Mod': 1,
                  'SetTem': 2,
                  'WdSpd': 3,
                  'Tur': 4,
                  'Quiet': 5,
                  'SwUpDn': 6,
                  'SwingLfRig': 7,
                  'Add0.5': 8,
                  'TemUn': 9,
                  'TemRec': 10,
                  'Lig': 11,
                  'Air': 12,
                  'Blo': 13,
                  'Health': 14,
                  'SvSt': 15,
                  'SwhSw': 16,
                  'HeatCoolType': 17,
                  'StHt': 18,
                  'LTemDry': 19,
                  'Wet': 20,
                  'SwhSlp': 21,
                  'SlpMod': 22,
                  'HasTmr': 23,
                  'TmrLpTms': 24,
                  'TmrOff': 25,
                  'TmrOn': 26,
                  'CurTmHor': 27,
                  'CurTmMin': 28,
                  'TmrOnHorLf': 29,
                  'TmrOnMinLf': 30,
                  'TmrOffHorLf': 31,
                  'TmrOffMinLf': 32,
                  'DsplySt': 33,
                  'EnvFun': 34,
                  'JFErrorCode': 35,
                  'AssHt': 36,
                  'SwhFreAir': 37,
                  'AllErr': 38,
                  'Coolmod': 39,
                  'HeatCool': 40,
                  'LedLig': 41,
                  'SmartMod': 42,
                  'Add0.1': 43,
                  'ModelType': 44,
                  'ElcEn': 45,
                  'BleON': 46,
                  'Mesh': 47,
                  'Meshota': 48,
                  'Reota': 49,
                  'SubOnline': 50,
                  'Proaddr': 51,
                  'Random': 52,
                  'Unbind': 53,
                  'Subcount': 54,
                  'Lpn': 55,
                  'Meshid': 56,
                  'NoD': 57,
                  'AntiDirectBlow': 58,
                  'Buzzer_ON_OFF': 59,
                  'Wind': 60,
                  'UDFanPort': 61,
                  'DnPUDSwing': 62,
                  'DnPLLRSwing': 63,
                  'DnPRLRSwing': 64,
                  'AirQ': 65,
                  'PM2P5': 66,
                  'ElcDatHor': 67,
                  'ElcDatDte': 68,
                  'ElcDatMth': 69,
                  'HumSen': 70,
                  'ElcP': 71,
                  'ElcOnKwh': 72,
                  'ElcAllKwhClr': 73,
                  'ElcAllKwhH': 74,
                  'ElcAllKwhL': 75,
                  'AutoClean': 76,
                  'TemSen': 77,
                  'Emod': 78,
                  'PctCleOnTm': 79,
                  'EvapClr': 80,
                  'NobodySave': 81,
                  'BlkTemCom': 82,
                  'HabitLearn': 83,
                  'SmartWind': 84,
                  'HandCtl': 85,
                  'VocCtl': 86,
                  'VocIdiom': 87,
                  'VocRole': 88,
                  'ImgUpdateCol': 89,
                  'EnvArea1St': 90,
                  'EnvArea2St': 91,
                  'EnvArea3St': 92,
                  'EnvArea4St': 93,
                  'EnvArea5St': 94,
                  'EnvArea6St': 95,
                  'EnvArea7St': 96,
                  'EnvArea8St': 97,
                  'EnvArea9St': 98,
                  'FbidBloPer': 99,
                  'DIYGra1PoiAmo': 100,
                  'SwhDIYGra1': 101,
                  'Slp1L1': 102,
                  'Slp1H1': 103,
                  'Slp1L2': 104,
                  'Slp1H2': 105,
                  'Slp1L3': 106,
                  'Slp1H3': 107,
                  'Slp1L4': 108,
                  'Slp1H4': 109,
                  'Slp1L5': 110,
                  'Slp1H5': 111,
                  'Slp1L6': 112,
                  'Slp1H6': 113,
                  'Slp1L7': 114,
                  'Slp1H7': 115,
                  'Slp1L8': 116,
                  'Slp1H8': 117,
                  'ImgVerSta': 118,
                  'VocUpdateCol': 119,
                  'VocVerSta': 120,
                  'LigSen': 121,
                  'Video': 122,
                  'PctCleSetTm': 123,
                  'AppTimer': 124,
                  'CO2Level': 125,
                  'Dazzling': 126,
                  'NewTimer': 127,
                  'NewTimerSet': 128,
                  'UvcControl': 129,
                  'MasSub': 130,
                  'MasIDUMod': 131,
                  'GetEr': 132,
                  'HeatSvStTemMax': 133,
                  'HumiSvStTemMin': 134,
                  'CoolSvStTemMin': 135,
                  'Wmod': 145,
                  'WsetTmp': 146,
                  'WschOn': 147,
                  'WschOnMin': 148,
                  'WschOff': 149,
                  'WschOffMin': 150,
                  'Wtmr1': 151,
                  'Wtmr1Min': 152,
                  'Wtmr2': 153,
                  'Wtmr2Min': 154,
                  'Wtmr3': 155,
                  'Wtmr3Min': 156,
                  'WsenTmpH': 157,
                  'WsenTmpM': 158,
                  'WsenTmpL': 159,
                  'Werr': 160,
                  'WsenNub': 161,
                  'WstpSv': 162,
                  'WstpH': 163,
                  'WatTmp': 164,
                  'MaeS': 175,
                  'FanMod': 176,
                  'ModS': 177,
                  'VitiGr': 178,
                  'GasN': 179,
                  'TemSor': 180,
                  'HumSor': 181,
                  'PM2P5V': 182,
                  'VOC': 183,
                  'CO2': 184,
                  'PctCle': 185,
                  'PctRe': 186,
                  'IDUAirQu': 187,
                  'AirQu': 188,
                  'ODUViti': 189,
                  'GasAvail': 190,
                  'GasLED': 191,
                  'GasMod': 192,
                  'GasMas': 193,
                  'PM2P5Sta': 194,
                  'SorErr': 195,
                  'CommErr': 196,
                  'I2CSwitch': 197,
                  'AIEnSaveDis': 198,
                  'EnvTem': 199,
                  'DFPoint': 200,
                  'CpsTem': 201,
                  'TemsSenOut': 202,
                  'OutEnvTem': 203,
                  'InEvaTem': 204,
                  'CompressorTem': 205,
                  'CompressorFqy': 206,
                  'Dmod': 210,
                  'Dfltr': 211,
                  'Dpump': 212,
                  'Dwet': 213,
                  'DwatFul': 214,
                  'DwatSen': 215,
                  'estateInsta21': 216,
                  'estateInsta22': 217,
                  'estateInsta23': 218,
                  'estateInsta24': 219,
                  'ChildLock': 220,
                  'Smod': 225,
                  'Sfog': 226,
                  'RemWarnLig': 227,
                  'Security': 230,
                  'SecurityMode': 231,
                  'ImageRecovery': 232,
                  'Srst': 240,
                  'Swat': 241,
                  'Swash': 242,
                  'SrstPP': 243,
                  'SrstPF': 244,
                  'SrstCF': 245,
                  'SrstRF': 246,
                  'SrstAF': 247,
                  'MakeWat': 248,
                  'WatErr': 249,
                  'mode': 260,
                  'wspd': 261,
                  'light': 262,
                  'StTmr': 263,
                  'fltrst': 264,
                  'wipm25': 265,
                  'wopm25': 266,
                  'estate': 267,
                  'airQlt': 268,
                  'Purify': 269,
                  'ImgUpdateSucs': 280,
                  'VocUpdateRes': 281,
                  'MicroSen': 282,
                  'ReplaceHEPA': 283,
                  'UnmanedShutDown': 284,
                  'UnmanedOffTime': 285,
                  'PMVComfort': 286,
                  'Defrost': 287,
                  'Antifreeze': 288,
                  'FavorMode': 289,
                  'ImgUpdateSta': 290,
                  'ImgUpdateFail': 291,
                  'VocUpdateSta': 292,
                  'SwhWifi': 360,
                  'SwhWifiRe': 361,
                  'SwhWifiCo': 362,
                  'datDump': 363,
                  'datRep': 364,
                  'datFailRe': 365,
                  'datPeroid': 366,
                  'subCnt': 367,
                  'HidDownPer': 368,
                  'InHidDownPer': 369,
                  'OEEPHidDownPer': 370,
                  'ACStupPos': 395,
                  'SaveGuid': 396,
                  'NoiseSet': 397,
                  'RoomLen': 398,
                  'RoomWid': 399,
                  'RoomHigh': 400,
                  'CoolNoise': 401,
                  'HeatNoise': 402,
                  'ElcErg': 415,
                  'ElcGear': 416,
                  'Elc1Kwh': 417,
                  'AutoUpdate': 418,
                  'AutoComnCloud': 419,
                  'lock': 420,
                  'apssid': 445,
                  'appsw': 446,
                  'host': 447,
                  'name': 448,
                  'time': 449,
                  'lat': 450,
                  'lon': 451,
                  'vender': 460,
                  'bc': 461,
                  'mid': 462,
                  'model': 463,
                  'series': 464,
                  'brand': 465,
                  'catalog': 466,
                  'country': 467,
                  'hid': 468,
                  'mac': 469,
                  'ver': 470,
                  'HidSvrVer': 471,
                  'InHid': 472,
                  'InHidSvrVer': 473,
                  'OEEPHid': 474,
                  'OEEPHidSvrVer': 475},
      'primary': ('name',
                  'lock',
                  'AutoUpdate',
                  'time',
                  'host',
                  'hid',
                  'BtHid',
                  'mid',
                  'MOta',
                  'bc',
                  'DevID',
                  'MafIdf',
                  'AppTimer',
                  'MidType',
                  'BleON',
                  'Mesh',
                  'Meshota',
                  'SubOnline',
                  'Proaddr',
                  'Random',
                  'Unbind',
                  'Subcount',
                  'Meshid',
                  'lat',
                  'lon',
                  'vender',
                  'mac',
                  'ver',
                  'rssi',
                  'ModelType',
                  'FaultDisplay')},
 40: {'sha256': 'e8068e5388facaee3820f8d9d893b8c4e7fca2da86d2ee3e8f74e75f766e7892',
      'hid': '362001067541+U-WB05WR11V2.04.bin',
      'ver': 'V2.0.0',
      'advertise_hid': True,
      'numeric': {'Pow': 0,
                  'Mod': 1,
                  'SetTem': 2,
                  'WdSpd': 3,
                  'Tur': 4,
                  'Quiet': 5,
                  'SwUpDn': 6,
                  'SwingLfRig': 7,
                  'Add0.5': 8,
                  'TemUn': 9,
                  'TemRec': 10,
                  'Lig': 11,
                  'Air': 12,
                  'Blo': 13,
                  'Health': 14,
                  'SvSt': 15,
                  'SwhSw': 16,
                  'HeatCoolType': 17,
                  'StHt': 18,
                  'LTemDry': 19,
                  'Wet': 20,
                  'SwhSlp': 21,
                  'SlpMod': 22,
                  'HasTmr': 23,
                  'TmrLpTms': 24,
                  'TmrOff': 25,
                  'TmrOn': 26,
                  'CurTmHor': 27,
                  'CurTmMin': 28,
                  'TmrOnHorLf': 29,
                  'TmrOnMinLf': 30,
                  'TmrOffHorLf': 31,
                  'TmrOffMinLf': 32,
                  'DsplySt': 33,
                  'EnvFun': 34,
                  'JFErrorCode': 35,
                  'AssHt': 36,
                  'SwhFreAir': 37,
                  'AllErr': 38,
                  'Coolmod': 39,
                  'HeatCool': 40,
                  'LedLig': 41,
                  'SmartMod': 42,
                  'Add0.1': 43,
                  'ModelType': 44,
                  'ElcEn': 45,
                  'BleON': 46,
                  'Mesh': 47,
                  'Meshota': 48,
                  'Reota': 49,
                  'SubOnline': 50,
                  'Proaddr': 51,
                  'Random': 52,
                  'Unbind': 53,
                  'Subcount': 54,
                  'Lpn': 55,
                  'Meshid': 56,
                  'NoD': 57,
                  'AntiDirectBlow': 58,
                  'Buzzer_ON_OFF': 59,
                  'Wind': 60,
                  'UDFanPort': 61,
                  'DnPUDSwing': 62,
                  'DnPLLRSwing': 63,
                  'DnPRLRSwing': 64,
                  'AirQ': 65,
                  'PM2P5': 66,
                  'ElcDatHor': 67,
                  'ElcDatDte': 68,
                  'ElcDatMth': 69,
                  'HumSen': 70,
                  'ElcP': 71,
                  'ElcOnKwh': 72,
                  'ElcAllKwhClr': 73,
                  'ElcAllKwhH': 74,
                  'ElcAllKwhL': 75,
                  'AutoClean': 76,
                  'TemSen': 77,
                  'Emod': 78,
                  'PctCleOnTm': 79,
                  'EvapClr': 80,
                  'NobodySave': 81,
                  'BlkTemCom': 82,
                  'HabitLearn': 83,
                  'SmartWind': 84,
                  'HandCtl': 85,
                  'VocCtl': 86,
                  'VocIdiom': 87,
                  'VocRole': 88,
                  'ImgUpdateCol': 89,
                  'EnvArea1St': 90,
                  'EnvArea2St': 91,
                  'EnvArea3St': 92,
                  'EnvArea4St': 93,
                  'EnvArea5St': 94,
                  'EnvArea6St': 95,
                  'EnvArea7St': 96,
                  'EnvArea8St': 97,
                  'EnvArea9St': 98,
                  'FbidBloPer': 99,
                  'DIYGra1PoiAmo': 100,
                  'SwhDIYGra1': 101,
                  'Slp1L1': 102,
                  'Slp1H1': 103,
                  'Slp1L2': 104,
                  'Slp1H2': 105,
                  'Slp1L3': 106,
                  'Slp1H3': 107,
                  'Slp1L4': 108,
                  'Slp1H4': 109,
                  'Slp1L5': 110,
                  'Slp1H5': 111,
                  'Slp1L6': 112,
                  'Slp1H6': 113,
                  'Slp1L7': 114,
                  'Slp1H7': 115,
                  'Slp1L8': 116,
                  'Slp1H8': 117,
                  'ImgVerSta': 118,
                  'VocUpdateCol': 119,
                  'VocVerSta': 120,
                  'LigSen': 121,
                  'Video': 122,
                  'PctCleSetTm': 123,
                  'AppTimer': 124,
                  'CO2Level': 125,
                  'Dazzling': 126,
                  'NewTimer': 127,
                  'NewTimerSet': 128,
                  'UvcControl': 129,
                  'MasSub': 130,
                  'MasIDUMod': 131,
                  'GetEr': 132,
                  'HeatSvStTemMax': 133,
                  'HumiSvStTemMin': 134,
                  'CoolSvStTemMin': 135,
                  'Wmod': 145,
                  'WsetTmp': 146,
                  'WschOn': 147,
                  'WschOnMin': 148,
                  'WschOff': 149,
                  'WschOffMin': 150,
                  'Wtmr1': 151,
                  'Wtmr1Min': 152,
                  'Wtmr2': 153,
                  'Wtmr2Min': 154,
                  'Wtmr3': 155,
                  'Wtmr3Min': 156,
                  'WsenTmpH': 157,
                  'WsenTmpM': 158,
                  'WsenTmpL': 159,
                  'Werr': 160,
                  'WsenNub': 161,
                  'WstpSv': 162,
                  'WstpH': 163,
                  'WatTmp': 164,
                  'MaeS': 175,
                  'FanMod': 176,
                  'ModS': 177,
                  'VitiGr': 178,
                  'GasN': 179,
                  'TemSor': 180,
                  'HumSor': 181,
                  'PM2P5V': 182,
                  'VOC': 183,
                  'CO2': 184,
                  'PctCle': 185,
                  'PctRe': 186,
                  'IDUAirQu': 187,
                  'AirQu': 188,
                  'ODUViti': 189,
                  'GasAvail': 190,
                  'GasLED': 191,
                  'GasMod': 192,
                  'GasMas': 193,
                  'PM2P5Sta': 194,
                  'SorErr': 195,
                  'CommErr': 196,
                  'I2CSwitch': 197,
                  'AIEnSaveDis': 198,
                  'EnvTem': 199,
                  'DFPoint': 200,
                  'CpsTem': 201,
                  'TemsSenOut': 202,
                  'OutEnvTem': 203,
                  'InEvaTem': 204,
                  'CompressorTem': 205,
                  'CompressorFqy': 206,
                  'Dmod': 210,
                  'Dfltr': 211,
                  'Dpump': 212,
                  'Dwet': 213,
                  'DwatFul': 214,
                  'DwatSen': 215,
                  'estateInsta21': 216,
                  'estateInsta22': 217,
                  'estateInsta23': 218,
                  'estateInsta24': 219,
                  'ChildLock': 220,
                  'Smod': 225,
                  'Sfog': 226,
                  'RemWarnLig': 227,
                  'Security': 230,
                  'SecurityMode': 231,
                  'ImageRecovery': 232,
                  'Srst': 240,
                  'Swat': 241,
                  'Swash': 242,
                  'SrstPP': 243,
                  'SrstPF': 244,
                  'SrstCF': 245,
                  'SrstRF': 246,
                  'SrstAF': 247,
                  'MakeWat': 248,
                  'WatErr': 249,
                  'mode': 260,
                  'wspd': 261,
                  'light': 262,
                  'StTmr': 263,
                  'fltrst': 264,
                  'wipm25': 265,
                  'wopm25': 266,
                  'estate': 267,
                  'airQlt': 268,
                  'Purify': 269,
                  'ImgUpdateSucs': 280,
                  'VocUpdateRes': 281,
                  'MicroSen': 282,
                  'ReplaceHEPA': 283,
                  'UnmanedShutDown': 284,
                  'UnmanedOffTime': 285,
                  'PMVComfort': 286,
                  'Defrost': 287,
                  'Antifreeze': 288,
                  'FavorMode': 289,
                  'ImgUpdateSta': 290,
                  'ImgUpdateFail': 291,
                  'VocUpdateSta': 292,
                  'SwhWifi': 360,
                  'SwhWifiRe': 361,
                  'SwhWifiCo': 362,
                  'datDump': 363,
                  'datRep': 364,
                  'datFailRe': 365,
                  'datPeroid': 366,
                  'subCnt': 367,
                  'HidDownPer': 368,
                  'InHidDownPer': 369,
                  'OEEPHidDownPer': 370,
                  'ACStupPos': 395,
                  'SaveGuid': 396,
                  'NoiseSet': 397,
                  'RoomLen': 398,
                  'RoomWid': 399,
                  'RoomHigh': 400,
                  'CoolNoise': 401,
                  'HeatNoise': 402,
                  'ElcErg': 415,
                  'ElcGear': 416,
                  'Elc1Kwh': 417,
                  'AutoUpdate': 418,
                  'AutoComnCloud': 419,
                  'lock': 420,
                  'apssid': 445,
                  'appsw': 446,
                  'host': 447,
                  'name': 448,
                  'time': 449,
                  'lat': 450,
                  'lon': 451,
                  'vender': 460,
                  'bc': 461,
                  'mid': 462,
                  'model': 463,
                  'series': 464,
                  'brand': 465,
                  'catalog': 466,
                  'country': 467,
                  'hid': 468,
                  'mac': 469,
                  'ver': 470,
                  'HidSvrVer': 471,
                  'InHid': 472,
                  'InHidSvrVer': 473,
                  'OEEPHid': 474,
                  'OEEPHidSvrVer': 475},
      'primary': ('name',
                  'lock',
                  'AutoUpdate',
                  'time',
                  'host',
                  'hid',
                  'BtHid',
                  'mid',
                  'MOta',
                  'bc',
                  'DevID',
                  'MafIdf',
                  'AppTimer',
                  'MidType',
                  'BleON',
                  'Mesh',
                  'Meshota',
                  'SubOnline',
                  'Proaddr',
                  'Random',
                  'Unbind',
                  'Subcount',
                  'Meshid',
                  'lat',
                  'lon',
                  'vender',
                  'mac',
                  'ver',
                  'rssi',
                  'ModelType',
                  'FaultDisplay')}}

_CLASSIFIED = frozenset((
    "time", "name", "lock", "AutoUpdate", "host", "hid", "mid", "bc", "DevID",
    "MafIdf", "AppTimer", "MidType", "BleON", "Mesh", "Unbind", "Meshid",
    "lat", "lon", "ReportClientID", "Onoff", "ModelType",
))
_READONLY = frozenset(("lock", "AutoUpdate", "hid", "mid", "bc", "DevID", "MafIdf", "MidType"))
_NOOPS = frozenset(("name", "ModelType", "AppTimer"))
_NO_SCALAR = frozenset(("BtHid", "MOta", "DevID", "MafIdf", "MidType", "Meshota", "Subcount"))
_NO_ACK = frozenset(("ReportClientID", "Onoff"))
_NUMERIC_PREFIX = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?")


class _NumberToken(str):
    __slots__ = ()


def _text(value, maximum=511):
    if type(value) is not str or "\0" in value or len(value.encode()) > maximum:
        raise InvalidPacket("middle WB requires bounded NUL-free text")
    return value


def _names(value):
    if not isinstance(value, list) or len(value) > 64:
        raise InvalidPacket("middle WB name-offset layout holds64 entries")
    result = [_text(name) for name in value]
    if sum(len(name.encode()) + 1 for name in result) > 512:
        raise InvalidPacket("middle WB name pool exceeds512 bytes")
    return result


def _array_text(values):
    if not isinstance(values, list) or len(values) > 64:
        raise InvalidPacket("middle WB value layout holds64 entries")
    pieces = []
    for value in values:
        if isinstance(value, _NumberToken):
            pieces.append(str(value))
        elif type(value) in (str, int, float, bool) or value is None:
            pieces.append(json.dumps(value, ensure_ascii=False, allow_nan=False))
        else:
            raise InvalidPacket("middle WB nested p values cross the bounded SDK layout")
    return "[" + ",".join(pieces) + "]"


def _cast_number(token, source_index):
    number = float(token)
    if math.isnan(number):
        return 0
    if math.isinf(number):
        if source_index != 38:
            return 0
        return -(1 << 31) if number < 0 else (1 << 31) - 1
    return max(-(1 << 31), min((1 << 31) - 1, math.trunc(number)))


def _numbers(values, count, source_index):
    """Original NUM cursor skips ONE byte, even when it is not a comma."""
    text = _array_text(values)
    cursor, parsed = 0, []
    for _ in range(count):
        if cursor >= len(text) or text[cursor] == "]":
            raise InvalidPacket("middle WB numeric array is too short")
        cursor += 1
        while cursor < len(text) and ord(text[cursor]) <= 32:
            cursor += 1
        match = _NUMERIC_PREFIX.match(text, cursor)
        if match is None:
            raise InvalidPacket("middle WB NUM entry rejects string/bool/null values")
        parsed.append(_cast_number(match.group(), source_index))
        cursor = match.end()
        while cursor < len(text) and ord(text[cursor]) <= 32:
            cursor += 1
    return parsed


def _integer(value, source_index):
    if isinstance(value, _NumberToken):
        match = _NUMERIC_PREFIX.match(value)
        if match is None:
            raise InvalidPacket("middle WB expected a source numeric token")
        return _cast_number(match.group(), source_index)
    if type(value) not in (int, float) or not math.isfinite(value):
        raise InvalidPacket("middle WB expected a finite number")
    return _cast_number(str(value), source_index)


def _source_string(value, capacity):
    """Original STR helper: None means lookup/conversion/capacity failure."""
    if type(value) is str:
        value = value.split("\0", 1)[0]
    elif value is None:
        value = "null"
    elif type(value) is bool:
        value = "true" if value else "false"
    else:
        return None
    return value if len(value.encode("utf-8")) < capacity else None


def _outer_identity(value, capacity):
    return _source_string(value, capacity) or ""


def _scan_hex(text, position):
    """Declared standard %2X primitive; conversion failure preserves scratch."""
    while position < len(text) and text[position].isspace():
        position += 1
    field = text[position:position + 2]
    if field.lower() == "0x":
        return 0, position + 2
    match = re.match(r"[+-]?[0-9a-fA-F]+", field)
    if match is None:
        return None, position
    return int(match.group(), 16) & 0xffffffff, position + len(match.group())


def _hex_bytes(value, count):
    value = _text(value)
    if len(value) != count * 2 or re.fullmatch(r"[0-9a-fA-F]+", value) is None:
        raise InvalidPacket("middle WB safely requires complete fixed-size hex input")
    return bytes.fromhex(value)


def _client_packet(value):
    encoded = _text(value).encode()
    if len(encoded) > 26:
        raise InvalidPacket("middle WB ReportClientID would overflow its30-byte packet cache")
    packet = bytearray(30)
    packet[:4] = bytes.fromhex("7e7e126a")
    packet[4:4 + len(encoded)] = encoded
    return packet.hex()


class MiddleWBController:
    """A source-bound cache model, deliberately not an appliance/thermal model."""

    accept_any_target = True

    def __init__(self, source_index, mid):
        self.source_index = source_index
        self.source = _SOURCE_DATA[source_index]
        self.mid = mid
        self.numeric = self.source["numeric"]
        self.primary = frozenset(self.source["primary"])
        self.codec = ECB if source_index in (34, 36) else GCM
        self.generic_key = SCAN_KEY if self.codec == ECB else GCM_GENERIC_KEY
        self.operations = frozenset(("bind", "status", "cmd", "upgrade", "dump"))
        if source_index != 34:
            self.operations |= frozenset(("setT", "queryT", "deleteT", "updateT"))
        if source_index == 38:
            self.operations |= frozenset(("binCmd",))

    def validate_state(self, state):
        result = dict(state)
        for name, value in result.items():
            if name not in self.numeric or name in self.primary:
                raise ValueError("middle WB initial state requires an unshadowed source cache field")
            if type(value) is not int or not 0 <= value <= 65535:
                raise ValueError("middle WB initial cache readouts are uint16")
        return result

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        return None

    def _runtime(self, device, state):
        if "_middle_wb" not in state:
            metadata = {name: "" for name in self.primary - _NO_SCALAR}
            metadata.update(hid=self.source["hid"], ver=self.source["ver"], mac=device.mac,
                            lock=0, AutoUpdate=0, AppTimer=0, Mesh=0, rssi=0,
                            BleON="000000000000", Unbind="000000000000",
                            Meshid="0000", Proaddr="0000", Random="00000000")
            state["_middle_wb"] = {
                "metadata": metadata,
                "numeric": {name: state.get(name, 0) for name in self.numeric},
                "clock": "2026-01-01 00:00:00", "clock_origin": device.last_step,
                "timers": {}, "timer_count": 0,
                "mesh_queue": [], "mesh_queue_index": 0,
                "mesh_pending_mac": "000000000000", "sdk_events": [],
                "report_client_packet": "00" * 30, "report_client_dirty": False,
                "host_requested": "", "host_request_pending": False,
                "ota_buffer": "00" * 120, "ota_task_requested": False,
            }
        return state["_middle_wb"]

    def _clock(self, device, runtime):
        try:
            value = datetime.strptime(runtime["clock"], "%Y-%m-%d %H:%M:%S")
            value += timedelta(seconds=int(device.last_step - runtime["clock_origin"]))
        except (ValueError, OverflowError) as exc:
            raise InvalidPacket("middle WB synthetic clock is out of range") from exc
        return value.strftime("%Y-%m-%d %H:%M:%S")

    def _get(self, device, runtime, name):
        if name in self.primary:
            if name in _NO_SCALAR:
                return []
            if name == "time":
                return [self._clock(device, runtime)]
            return [runtime["metadata"][name]]
        if name in self.numeric:
            return [runtime["numeric"][name]]
        return []

    def _onoff(self, runtime, value):
        data = _text(value).encode()
        position, first, second = 2, 0, 0
        packets = []
        for _ in range(data.count(b",") + 1):
            if position + 7 > len(data):
                raise InvalidPacket("middle WB Onoff fixed-offset token would overread")
            token = data[position:]
            parsed, after = _scan_hex(token.decode("latin1"), 0)
            if parsed is not None:
                first = parsed
                parsed, _ = _scan_hex(token.decode("latin1"), after)
                if parsed is not None:
                    second = parsed
            decoded = []
            for raw in token[4:7]:
                signed = raw if self.source_index == 38 or raw < 128 else raw - 256
                decoded.append((signed - (0x57 if signed >= 0x41 else 0x30)) & 255)
            payload = bytearray.fromhex("010530020000")
            payload[4:6] = bytes(decoded[:2])
            packet = bytes((0, (decoded[2] + 2) & 255))
            packet += ((first * 256 + second) & 65535).to_bytes(2, "little")
            packet += b"\x06\x00" + bytes(payload)
            packets.append(packet.hex())
            comma = data.find(b",", position)
            position = len(data) if comma < 0 else comma + 2
        for packet in packets:
            if len(runtime["mesh_queue"]) < 30:
                runtime["mesh_queue"].append(packet)
                runtime["mesh_queue_index"] = (runtime["mesh_queue_index"] + 1) % 30

    def _set_primary(self, device, runtime, name, value):
        value = _text(value)
        if name in _READONLY:
            raise InvalidPacket("middle WB classified read-only field aborts the original parser")
        if name in _NOOPS:
            return
        metadata = runtime["metadata"]
        if name == "time":
            try:
                parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
            except ValueError as exc:
                raise InvalidPacket("middle WB rejects unsafe malformed native calendar input") from exc
            runtime["clock"] = parsed.strftime("%Y-%m-%d %H:%M:%S")
            runtime["clock_origin"] = device.last_step
        elif name in ("BleON", "Mesh", "Unbind"):
            raw = _hex_bytes(value, 6)
            if name == "Mesh":
                metadata["BleON"] = raw.hex()
                runtime["mesh_pending_mac"] = raw.hex()
                runtime["sdk_events"].append([0x14, 3])
            else:
                metadata[name] = raw.hex()
                if name == "Unbind" and self.source_index != 38:
                    # Declared standard scanf unsigned-int store width overlaps
                    # the first BleON byte in these four ORIGINAL layouts.
                    metadata["BleON"] = "00" + metadata["BleON"][2:]
        elif name == "Meshid":
            first, second = _hex_bytes(value, 2)
            if self.source_index != 38:
                first = first - 256 if first >= 128 else first
                second = second - 256 if second >= 128 else second
            metadata[name] = f"{(first * 256 + second) & 65535:04x}"
        elif name == "host":
            if 0 < len(value.encode()) < 21:
                runtime["host_requested"] = value
                runtime["host_request_pending"] = True
        elif name in ("lat", "lon"):
            if 0 < len(value.encode()) < 11:
                metadata[name] = value
        elif name == "ReportClientID":
            runtime["report_client_packet"] = _client_packet(value)
            runtime["report_client_dirty"] = True
        elif name == "Onoff":
            self._onoff(runtime, value)
        else:
            raise InvalidPacket("middle WB field has no original primary writer")

    def _parse_fields(self, device, runtime, inner):
        if isinstance(inner.get("cols"), list) and all(type(v) is str for v in inner["cols"]):
            names, writing = _names(inner["cols"]), False
        else:
            names, writing = _names(inner.get("opt")), True
        primary = [name for name in names if name in _CLASSIFIED]
        numeric = [name for name in names if name not in _CLASSIFIED]
        numbers = [0] * len(numeric)
        if writing:
            values = inner.get("p")
            _array_text(values)
            strings = [_text(value) for value in values if type(value) is str]
            if sum(len(value.encode()) + 1 for value in strings) > 512:
                raise InvalidPacket("middle WB primary value pool exceeds512 bytes")
            if len(strings) < len(primary):
                raise InvalidPacket("middle WB primary group needs its own quoted p strings")
            for name, value in zip(primary, strings):
                self._set_primary(device, runtime, name, value)
            numbers = _numbers(values, len(numeric), self.source_index)
            for name, value in zip(numeric, numbers):
                if name in self.numeric:
                    runtime["numeric"][name] = value & 65535
                    if self.source_index == 34 and self.numeric[name] == 35:
                        runtime["settem_dirty"] = True
                    if name == "I2CSwitch":
                        runtime["ipc_request"] = value & 65535
        return names, primary, numeric, numbers

    def _record(self, inner):
        number = lambda value: _integer(value, self.source_index)
        identifier = number(inner.get("id")) & 255
        name = _text(inner.get("name"), 31)
        enable = int(number(inner.get("enable")) == 1)
        number(inner.get("tz"))
        hour, minute = (number(inner.get(key)) & 255 for key in ("hr", "min"))
        if "sec" in inner:
            number(inner["sec"])
        second = 0 if "sec" in inner else minute
        week = inner.get("week")
        if not isinstance(week, list) or len(week) < 7:
            raise InvalidPacket("middle WB timer reads seven weekday integers")
        mask = 0
        for bit, value in enumerate(_numbers(week, 7, self.source_index)):
            mask |= (value << bit) & 255
        commands = inner.get("cmd")
        if not isinstance(commands, list) or not commands or not isinstance(commands[0], dict):
            raise InvalidPacket("middle WB timer requires its first command object")
        command = commands[0]
        names = _names(command.get("opt"))
        values = _numbers(command.get("p"), len(names), self.source_index)
        power = 0
        for option, value in zip(names, values):
            if option == "Pow":
                power = value & 255
        return {"id": identifier, "name": name, "enable": enable,
                "week": [(mask >> bit) & 1 for bit in range(7)],
                "hr": hour, "min": minute, "sec": second, "power": power}

    def _bin_command(self, runtime, inner):
        encoded = _text(inner.get("hex01"), 1023)
        runtime["binary_request_flag"] = 0x42
        if type(inner.get("ReportClientID")) is str:
            runtime["bin_client_packet"] = _client_packet(_text(inner["ReportClientID"], 31))
            runtime["bin_client_dirty"] = True
        frequency = inner.get("ReportFreq")
        has_frequency = isinstance(frequency, _NumberToken) or type(frequency) in (int, float)
        if has_frequency:
            frequency = _integer(frequency, self.source_index)
            runtime["binary_report_word"] = 0x405a
            runtime["binary_report_frequency"] = 60 if frequency == 255 else frequency & 255
            if frequency != 255:
                runtime["binary_frequency_timer_word"] = 0x4000 + (frequency & 255)
        try:
            payload = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise InvalidPacket("middle WB hex01 requires valid base64") from exc
        if len(payload) > 60 or not payload.startswith(b"\x7e\x7e"):
            raise InvalidPacket("middle WB binary decoder requires7e7e and at most60 bytes")
        padded = payload + bytes(60 - len(payload))
        length = padded[2] + 2
        if length > 60:
            raise InvalidPacket("middle WB binary frame length would overread or overflow60 bytes")
        buffer = bytearray(60)
        buffer[:length] = padded[:length]
        buffer[0x2b] |= 2
        buffer[7] = 0 if has_frequency else 0xaf
        runtime["binary_frame"] = buffer.hex()
        return {"t": "res", "r": 200}

    def _operation(self, device, runtime, inner, uid):
        kind = inner.get("t")
        if kind not in self.operations:
            raise InvalidPacket("middle WB operation is absent from this exact source registry")
        if kind == "bind":
            mac = _source_string(inner["mac"], 32) if "mac" in inner else None
            if mac is None:
                mac = device.mac
            return {"t": "bindok", "r": 200, "mac": mac, "key": device.key.decode("ascii")}
        if kind in ("status", "cmd"):
            names, primary, numeric, numbers = self._parse_fields(device, runtime, inner)
            if kind == "status":
                selected = [name for name in names if name in self.primary or name in self.numeric]
                values = [value for name in selected for value in self._get(device, runtime, name)]
                target = _source_string(inner["sub"], 32) if "sub" in inner else None
                if target is None:
                    target = _source_string(inner["mac"], 32) if "mac" in inner else None
                if target is None:
                    target = device.mac
                return {"t": "dat", "uid": uid, "mac": target, "cid": device.mac,
                        "dat": values, "cols": selected, "r": 200}
            selected = [name for name in primary + numeric if name not in _NO_ACK]
            values = [value for name in primary for value in self._get(device, runtime, name)]
            return {"t": "res", "mac": device.mac, "p": values + numbers,
                    "opt": selected, "r": 200}
        if kind == "queryT":
            index, count = (_integer(inner.get(key), self.source_index) for key in ("index", "count"))
            if index < 0:
                raise InvalidPacket("middle WB negative timer index crosses unsafe native iteration")
            rows = []
            for identifier in range(index, max(index, min(10, index + max(0, count)))):
                record = runtime["timers"].get(identifier)
                if record is None:
                    continue
                row = {key: record[key] for key in ("id", "name", "enable", "week", "hr", "min", "sec")}
                row["cmd"] = [{"mac": [device.mac], "opt": ["Pow"], "p": [record["power"]]}]
                rows.append(row)
            return {"t": "listT", "total": runtime["timer_count"], "index": index, "list": rows}
        if kind == "deleteT":
            identifier = _integer(inner.get("id"), self.source_index) & 255
            runtime["timer_count"] = (runtime["timer_count"] - 1) & 255
            runtime["timers"].pop(identifier, None)
            return {"t": "resT", "r": 200}
        if kind in ("setT", "updateT"):
            if kind == "setT" and runtime["timer_count"] >= 10:
                return None
            record = self._record(inner)
            identifier = record["id"]
            if kind == "setT" and self.source_index == 36 and identifier in runtime["timers"]:
                return None
            if kind == "setT" or identifier in runtime["timers"]:
                added = identifier not in runtime["timers"]
                runtime["timers"][identifier] = record
                if kind == "setT" and added:
                    runtime["timer_count"] = (runtime["timer_count"] + 1) & 255
            return {"t": "resT", "r": 200}
        if kind == "dump":
            return {"t": "ret", "r": 200}
        if kind == "binCmd":
            return self._bin_command(runtime, inner)
        value = _text(inner.get("url"), 119).encode()
        buffer = bytearray.fromhex(runtime["ota_buffer"])
        buffer[:len(value)] = value
        runtime["ota_buffer"] = buffer.hex()
        runtime["ota_task_requested"] = True
        return {"t": "ret", "r": 200}

    def advertise(self, device, outer=None):
        runtime = self._runtime(device, device.state)
        metadata = runtime["metadata"]
        inner = {"t": "dev", "cid": "", "bc": metadata["bc"], "brand": "", "catalog": "",
                 "mac": device.mac, "mid": self.mid, "model": "", "name": metadata["name"],
                 "lock": 0, "series": "", "vender": metadata["vender"], "ver": self.source["ver"]}
        if self.source["advertise_hid"]:
            inner["hid"] = self.source["hid"]
        if self.source_index in (38, 39, 40):
            inner["ModelType"] = metadata["ModelType"]
        return [Reply({"t": "pack", "i": 1, "uid": 0, "cid": "", "tcid": ""}, inner,
                      SCAN_KEY, ECB)]

    def decode_outer(self, data):
        """Opt-in BEFORE generic integer-header validation; retain NUM lexemes."""
        if len(data) > 1460:
            raise InvalidPacket("middle WB datagram exceeds original receive capacity")
        outer = _json(data, number_parser=_NumberToken)
        if outer.get("t") not in ("scan", "pack"):
            raise InvalidPacket("unsupported middle WB envelope")
        if outer["t"] == "scan":
            # All five original scan branches read only t before dev building.
            # The unused identities/selectors must not acquire generic guards.
            return _validate_outer({"t": "scan"})
        if outer["t"] == "pack":
            selector = _integer(outer.get("i"), self.source_index)
            if selector not in (0, 1) or type(outer.get("pack")) is not str:
                raise InvalidPacket("middle WB requires source i0/i1 and encrypted pack")
            outer["i"] = selector
            try:
                outer["uid"] = _integer(outer.get("uid"), self.source_index)
            except InvalidPacket:
                outer["uid"] = 0
        outer["cid"] = _outer_identity(outer.get("cid", ""), 64)
        outer["tcid"] = _outer_identity(outer.get("tcid", ""), 32)
        return _validate_outer(outer)

    def handle(self, device, outer):
        if outer.get("t") != "pack":
            raise InvalidPacket("middle WB requires an encrypted pack")
        selector = _integer(outer.get("i"), self.source_index)
        if selector not in (0, 1):
            raise InvalidPacket("middle WB envelope requires converted i0/i1")
        try:
            uid = _integer(outer.get("uid"), self.source_index)
        except InvalidPacket:
            uid = 0
        cid = _outer_identity(outer.get("cid", ""), 64)
        tcid = _outer_identity(outer.get("tcid", ""), 32)
        key = device.key if selector == 0 else self.generic_key
        inner = decode_pack(outer, key, self.codec, number_parser=_NumberToken)
        if not isinstance(inner.get("t"), str):
            raise InvalidPacket("middle WB operation type must be a string")
        # Original primary actions happen before later parse/readonly failures.
        # A negative callback suppresses the ACK, never rolls those stores back.
        runtime = self._runtime(device, device.state)
        response = self._operation(device, runtime, inner, uid)
        if response is None:
            return []
        return [Reply({"t": "pack", "i": selector, "uid": uid, "cid": tcid, "tcid": cid},
                      response, key, self.codec)]


def make_middle_wb_profile(source_index, mid):
    """Bind one exact source to a chosen nonzero MCU0x44 input, never a guess."""
    if source_index not in _SOURCE_DATA:
        raise ValueError("middle WB source has no independently qualified dev/UDP model")
    if not isinstance(mid, str) or re.fullmatch(r"[0-9a-f]{1,8}", mid) is None:
        raise ValueError("middle WB configured MID must be lowercase hexadecimal")
    value = int(mid, 16)
    if not value or format(value, "x") != mid:
        raise ValueError("middle WB configured MID must match source nonzero %x output")
    source = _SOURCE_DATA[source_index]
    return Profile(id=f"sim-middle-wb-{source['sha256'][:8]}-{mid}", mids=(mid,),
                   hid=source["hid"], source_sha256=source["sha256"], initial_state={},
                   handler=MiddleWBController(source_index, mid), max_request_bytes=1460)


# Each profile chooses the SAME explicit virtual UART0x44 input (little-endian
# 01000100). It is neither an installed physical MID, a compiled default, nor
# a retry/fallback claim. Profiles remain disjoint by exact source SHA/HID.
PROFILES = tuple(make_middle_wb_profile(index, "10001") for index in (34, 36, 38, 39, 40))
