"""BL3332 raw serial-cache models, not typed ACs or full firmware boots.

Mainboard byte frames, radio strength, persisted storage and UART responses are
explicitly synthetic. Zero byte frames are chosen inputs, not source defaults.
Native partial mutations/unchecked copies become strict atomic transactions.
Surver preserves the native RTC-status-as-length quirk: a real 39-byte
diagnostic header is serialized, without its gathered mainboard payload.
No physical flashing, cloud services, network association or acoustic effects.
"""
from copy import deepcopy
from datetime import datetime, timedelta
import base64
import json
from time import monotonic

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile
from .catalog_realtek_third_tables import _clock, _integer, _members, _text, FiniteTables

KEY = b"a3K8Bx%2r8Y7#xDh"
SPEECH_KEY = b"0000000000000000"  # JDR's empty barcode, padded with ASCII zeroes at startup.
CODEC = "aes-ecb-pkcs7"

GET_BITS = {'ACStupPos': (11, 255, 4, 0),
 'Add0.5': (43, 15, 3, 0),
 'Air': (40, 63, 4, 0),
 'Antifreeze': (60, 63, 5, 0),
 'AutoClean': (40, 7, 2, 0),
 'CoolNoise': (15, 255, 0, 0),
 'Defrost': (60, 127, 6, 0),
 'Dfltr': (70, 63, 5, 0),
 'Dmod': (48, 15, 0, 0),
 'DnPLLRSwing': (77, 255, 4, 0),
 'DnPRLRSwing': (77, 15, 0, 0),
 'DnPUDSwing': (76, 15, 0, 0),
 'DsplySt': (42, 63, 4, 0),
 'DwatFul': (44, 3, 1, 0),
 'Emod': (52, 127, 4, 0),
 'EnvArea1St': (69, 1, 0, 0),
 'EnvArea2St': (69, 3, 1, 0),
 'EnvArea3St': (69, 7, 2, 0),
 'EnvArea4St': (69, 15, 3, 0),
 'EnvArea5St': (69, 31, 4, 0),
 'EnvArea6St': (69, 63, 5, 0),
 'EnvArea7St': (69, 127, 6, 0),
 'EnvArea8St': (69, 255, 7, 0),
 'EnvArea9St': (68, 1, 0, 0),
 'FavorMode': (62, 15, 3, 0),
 'FbidBloPer': (68, 3, 1, 0),
 'HandCtl': (75, 63, 1, 0),
 'Health': (39, 7, 2, 0),
 'HeatCoolType': (399, 3, 1, 0),
 'HeatNoise': (16, 255, 0, 0),
 'HumSen': (386, 255, 0, 0),
 'ImgUpdateSta': (47, 255, 7, 0),
 'ImgUpdateRes': (56, 127, 6, 0),
 'ImgVerSta': (35, 31, 4, 0),
 'MicroSen': (35, 7, 2, 0),
 'Mod': (37, 127, 4, 0),
 'NobodySave': (385, 255, 7, 0),
 'NoiseSet': (4, 1, 0, 0),
 'PMVComfort': (60, 255, 7, 0),
 'Pow': (37, 255, 7, 0),
 'Quiet': (49, 15, 2, 0),
 'ReplaceHEPA': (58, 127, 6, 0),
 'RoomHigh': (14, 255, 0, 0),
 'RoomLen': (12, 255, 0, 0),
 'RoomWid': (13, 255, 0, 0),
 'SaveGuid': (17, 1, 0, 0),
 'Security': (64, 31, 4, 0),
 'SecurityMode': (64, 15, 3, 0),
 'SetTem': (38, 255, 4, 16),
 'SmartWind': (56, 255, 5, 0),
 'StHt': (44, 127, 6, 0),
 'SvSt': (44, 127, 6, 0),
 'SwhSw': (41, 255, 4, 0),
 'SwhWifiRes': (40, 1, 0, 0),
 'SwUpDn': (41, 255, 4, 0),
 'TemRec': (40, 127, 6, 0),
 'TemUn': (40, 255, 7, 0),
 'Tur': (39, 1, 0, 0),
 'UDFanPort': (56, 15, 2, 0),
 'UnmanedOffTime': (58, 31, 3, 0),
 'UnmanedShutDown': (58, 63, 5, 0),
 'VocCtl': (43, 1, 0, 0),
 'VocRole': (49, 127, 5, 0),
 'VocUpdateSta': (68, 7, 2, 0),
 'VocUpdateRes': (56, 63, 5, 0),
 'VocVerSta': (35, 15, 3, 0),
 'Wet': (43, 127, 4, 0),
 'AllErr': (70, 127, 6, 0),
 'ElcAllKwhClr': (40, 15, 3, 0),
 'CZLJC': (71, 255, 7, 0),
 'Buzzer_ON_OFF': (73, 1, 0, 0),
 'AntiDirectBlow': (73, 255, 7, 0),
 'SmartSlpMod': (51, 127, 4, 0),
 'SmartSlpModEx': (327, 255, 0, 0),
 'StSlp1CInc': (331, 255, 0, 0),
 'StSlp1CSp': (333, 255, 0, 0),
 'StSlp1HInc': (332, 255, 0, 0),
 'StSlp1HSp': (334, 255, 0, 0),
 'StSlp2CInc': (338, 255, 0, 0),
 'StSlp2CSp': (340, 255, 0, 0),
 'StSlp2HInc': (339, 255, 0, 0),
 'StSlp2HSp': (341, 255, 0, 0),
 'StSlp3CInc': (345, 255, 0, 0),
 'StSlp3CSp': (347, 255, 0, 0),
 'StSlp3HInc': (346, 255, 0, 0),
 'StSlp3HSp': (348, 255, 0, 0),
 'StSlp4CInc': (352, 255, 0, 0),
 'StSlp4CSp': (354, 255, 0, 0),
 'StSlp4HInc': (353, 255, 0, 0),
 'StSlp4HSp': (355, 255, 0, 0),
 'LigSen': (51, 15, 3, 0),
 'Lig': (39, 3, 1, 0),
 'SwhWifi': (40, 3, 1, 0)}

BOOL_SET = {'Add0.5': (43, 247, 247, 8),
 'Antifreeze': (70, 191, 191, 64),
 'AutoClean': (40, 251, 251, 4),
 'Blo': (39, 247, 247, 8),
 'Defrost': (67, 254, 254, 1),
 'Dfltr': (70, 239, 239, 16),
 'DwatFul': (44, 253, 253, 2),
 'EnvArea1St': (69, 254, 254, 1),
 'EnvArea2St': (69, 253, 253, 2),
 'EnvArea3St': (69, 251, 251, 4),
 'EnvArea4St': (69, 247, 254, 8),
 'EnvArea5St': (69, 239, 239, 16),
 'EnvArea6St': (69, 223, 223, 32),
 'EnvArea7St': (69, 191, 191, 64),
 'EnvArea8St': (69, 127, 127, 128),
 'EnvArea9St': (68, 254, 254, 1),
 'FavorMode': (62, 247, 247, 8),
 'FbidBloPer': (68, 253, 253, 2),
 'Health': (39, 251, 251, 4),
 'ImageRecovery': (72, 254, 254, 1),
 'ImgUpdateCol': (75, 191, 191, 64),
 'Lig': (39, 253, 253, 2),
 'MicroSen': (47, 127, 127, 128),
 'NobodySave': (56, 254, 254, 1),
 'NoiseSet': (4, 254, 254, 1),
 'PMVComfort': (66, 254, 254, 1),
 'Pow': (37, 127, 127, 128),
 'ReplaceHEPA': (58, 191, 191, 64),
 'SaveGuid': (17, 254, 254, 1),
 'Security': (64, 239, 239, 16),
 'SecurityMode': (64, 247, 247, 8),
 'SwhSw': (41, 15, 15, 16),
 'SwhWifiRes': (40, 254, 254, 1),
 'TemRec': (40, 191, 191, 64),
 'TemUn': (40, 127, 127, 128),
 'Tur': (39, 254, 254, 1),
 'UnmanedShutDown': (58, 223, 223, 32),
 'VocCtl': (43, 254, 254, 1),
 'VocUpdateCol': (75, 127, 127, 128),
 'LigSen': (51, 247, 247, 8)}

MASK_SET = {'ACStupPos': (11, 15, 4, 255),
 'Air': (40, 207, 4, 3),
 'CoolNoise': (15, 0, 0, 255),
 'DnPUDSwing': (76, 240, 0, 15),
 'HandCtl': (75, 193, 1, 255),
 'HeatNoise': (16, 0, 0, 255),
 'RoomHigh': (14, 0, 0, 255),
 'RoomLen': (12, 0, 0, 255),
 'RoomWid': (13, 0, 0, 255),
 'SetTem': (38, 15, 4, 255),
 'StHt': (44, 191, 6, 1),
 'SwUpDn': (41, 15, 4, 255),
 'VocIdiom': (60, 135, 3, 255),
 'Wet': (43, 143, 4, 7),
 'ElcAllKwhClr': (40, 247, 3, 1),
 'CZLJC': (73, 127, 7, 255),
 'Buzzer_ON_OFF': (73, 254, 0, 1),
 'AntiDirectBlow': (73, 127, 7, 255),
 'SmartSlpMod': (51, 143, 4, 7),
 'SmartSlpModEx': (327, 0, 0, 255),
 'StSlp1CInc': (331, 0, 0, 255),
 'StSlp1CSp': (333, 0, 0, 255),
 'StSlp1HInc': (332, 0, 0, 255),
 'StSlp1HSp': (334, 0, 0, 255),
 'StSlp2CInc': (338, 0, 0, 255),
 'StSlp2CSp': (340, 0, 0, 255),
 'StSlp2HInc': (339, 0, 0, 255),
 'StSlp2HSp': (341, 0, 0, 255),
 'StSlp3CInc': (345, 0, 0, 255),
 'StSlp3CSp': (347, 0, 0, 255),
 'StSlp3HInc': (346, 0, 0, 255),
 'StSlp3HSp': (348, 0, 0, 255),
 'StSlp4CInc': (352, 0, 0, 255),
 'StSlp4CSp': (354, 0, 0, 255),
 'StSlp4HInc': (353, 0, 0, 255),
 'StSlp4HSp': (355, 0, 0, 255)}

CONSTANTS = ('Null', 'AirQ', 'ImageRecovery', 'ImgUpdateCol', 'PM2P5', 'Purify', 'VocIdiom', 'VocUpdateCol', 'NewTimer', 'NewTimerSet')
NOOP_SET = ('AirQ', 'HeatCoolType', 'HumSen', 'ImgUpdateSta', 'ImgUpdateRes', 'ImgVerSta', 'PM2P5', 'Purify', 'VocUpdateSta', 'VocUpdateRes', 'VocVerSta', 'AllErr', 'ElcEn', 'NewTimer')

PRESETS = {'controller': ('ACStupPos',
                'Add0.5',
                'Air',
                'AirQ',
                'AssHt',
                'AutoClean',
                'Blo',
                'CoolNoise',
                'Dfltr',
                'Emod',
                'EnvArea1St',
                'EnvArea2St',
                'EnvArea3St',
                'EnvArea4St',
                'EnvArea5St',
                'EnvArea6St',
                'EnvArea7St',
                'EnvArea8St',
                'EnvArea9St',
                'FbidBloPer',
                'Health',
                'HeatCoolType',
                'HeatNoise',
                'Lig',
                'Mod',
                'NoiseSet',
                'Pow',
                'Purify',
                'Quiet',
                'RoomHigh',
                'RoomLen',
                'RoomWid',
                'SaveGuid',
                'SetTem',
                'Slp1H1',
                'Slp1H2',
                'Slp1H3',
                'Slp1H4',
                'Slp1H5',
                'Slp1H6',
                'Slp1H7',
                'Slp1H8',
                'Slp1L1',
                'Slp1L2',
                'Slp1L3',
                'Slp1L4',
                'Slp1L5',
                'Slp1L6',
                'Slp1L7',
                'Slp1L8',
                'SlpMod',
                'SvSt',
                'SwhSlp',
                'SwingLfRig',
                'SwUpDn',
                'DsplySt',
                'TemRec',
                'TemSen',
                'TemUn',
                'Tur',
                'WdSpd',
                'Wet',
                'AllErr',
                'ElcAllKwhClr',
                'ElcEn',
                'CZLJC',
                'NewTimer',
                'NewTimerSet',
                'Buzzer_ON_OFF',
                'AntiDirectBlow',
                'SmartSlpMod',
                'SmartSlpModEx',
                'StSlp1C',
                'StSlp1CInc',
                'StSlp1CSp',
                'StSlp1H',
                'StSlp1HInc',
                'StSlp1HSp',
                'StSlp2C',
                'StSlp2CInc',
                'StSlp2CSp',
                'StSlp2H',
                'StSlp2HInc',
                'StSlp2HSp',
                'StSlp3C',
                'StSlp3CInc',
                'StSlp3CSp',
                'StSlp3H',
                'StSlp3HInc',
                'StSlp3HSp',
                'StSlp4C',
                'StSlp4CInc',
                'StSlp4CSp',
                'StSlp4H',
                'StSlp4HInc',
                'StSlp4HSp',
                'LigSen'),
 'dehumidifier': ('Dfltr', 'Dmod', 'DwatFul', 'Dwet', 'HumSen', 'Pow', 'SwhSw', 'WdSpd'),
 'voice': ('ACStupPos',
           'Add0.5',
           'Air',
           'AirQ',
           'AssHt',
           'Antifreeze',
           'AutoClean',
           'Blo',
           'CoolNoise',
           'Defrost',
           'Dfltr',
           'Emod',
           'EnvArea1St',
           'EnvArea2St',
           'EnvArea3St',
           'EnvArea4St',
           'EnvArea5St',
           'EnvArea6St',
           'MicroSen',
           'Lig',
           'EnvArea7St',
           'EnvArea8St',
           'EnvArea9St',
           'FavorMode',
           'FbidBloPer',
           'HandCtl',
           'Health',
           'HeatCoolType',
           'HeatNoise',
           'ImgVerSta',
           'Mod',
           'NobodySave',
           'NoiseSet',
           'PMVComfort',
           'Pow',
           'Purify',
           'Quiet',
           'RoomHigh',
           'RoomLen',
           'RoomWid',
           'SaveGuid',
           'Security',
           'SecurityMode',
           'SetTem',
           'Slp1H1',
           'Slp1H2',
           'Slp1H3',
           'Slp1H4',
           'Slp1H5',
           'Slp1H6',
           'Slp1H7',
           'Slp1H8',
           'Slp1L1',
           'Slp1L2',
           'Slp1L3',
           'Slp1L4',
           'Slp1L5',
           'Slp1L6',
           'VocRole',
           'UnmanedOffTime',
           'Slp1L7',
           'Slp1L8',
           'SlpMod',
           'SmartWind',
           'SvSt',
           'SwhSlp',
           'SwingLfRig',
           'SwUpDn',
           'DsplySt',
           'UnmanedShutDown',
           'TemRec',
           'TemSen',
           'TemUn',
           'Tur',
           'VocCtl',
           'VocVerSta',
           'WdSpd',
           'Wet',
           'ImgUpdateRes',
           'VocUpdateSta',
           'VocUpdateRes',
           'ReplaceHEPA')}

_SET_ALIASES = {name.casefold(): name for name in (
    set(GET_BITS) | set(BOOL_SET) | set(MASK_SET) | set(CONSTANTS)
    | set().union(*PRESETS.values())) if name not in ("Null", "AllErr")}


def _put(cache, offset, keep, value):
    cache[offset] = (cache[offset] & keep | value) & 255


class BlCache:
    """Original finite136 byte packing; V11's independent offsets stay separate."""

    def __init__(self, version):
        self.version = version

    def _offset(self, name, offset):
        return offset + (15 if self.version == 11 and
                         (name.startswith("StSlp") or name == "SmartSlpModEx") else 0)

    def get(self, cache, name, mid="11000", cloud=9, *, energy=(0, 0, 0)):
        if name in CONSTANTS:
            return 0
        if name in GET_BITS:
            offset, mask, shift, bias = GET_BITS[name]
            if self.version == 11:
                if name == "HeatCoolType":
                    return 0
                if name in ("HumSen", "NobodySave"):
                    offset += 15
            return ((cache[self._offset(name, offset)] & mask) >> shift) + bias
        if name == "AssHt":
            if (cache[0x25] >> 4 & 7) == 1:
                return 0
            if cache[0x2c] & 128 and cloud in (0, 9):
                return 2
            return (cache[0x27] ^ 8) >> 3 & 1
        if name == "Blo":
            return 0 if cache[0x25] >> 4 & 7 == 4 else cache[0x27] >> 3 & 1
        if name == "Dwet":
            return max(0, (cache[0x34] & 15)-1)
        if name == "SwhSlp":
            return int(bool(cache[0x25] & 8 or cache[0x31] & 128 or cache[0x31] & 16))
        if name == "SlpMod":
            sleep, flags = bool(cache[0x25] & 8), cache[0x31]
            if not sleep:
                return 2 if flags & 16 and not flags & 128 else 0
            if flags & 16:
                return 0 if flags & 128 else 3
            return 4 if flags & 128 else 1
        if name == "SwingLfRig":
            value = cache[0x29] & 15
            return {12: 7, 13: 8}.get(value, value)
        if name == "TemSen":
            value = cache[0x18f if self.version == 11 else 0x180]
            if value < 40:
                return 0
            return min(value, 90) - (0 if self.version == 13 and cloud == 9 else 40)
        if name == "WdSpd":
            if self.version == 13 and mid == "13000":
                return (0, 1, 3, 5)[cache[0x25] & 3]
            return cache[0x33] & 7
        if name == "ElcEn":
            length, packet_flag, feature_flag = energy
            return packet_flag & feature_flag & 1 if length >= 4 else 0
        if name.startswith("Slp1"):
            ordinal = int(name[-1])-1
            nibble = cache[(0x32, 0x35, 0x36, 0x37)[ordinal//2]]
            nibble = min(14, nibble & 15 if ordinal & 1 else nibble >> 4)
            packed = nibble*10+160
            return packed >> 8 if name[4] == "H" else packed & 255
        if name.startswith("StSlp") and name[-1] in ("C", "H"):
            base = 0x148 + (int(name[5])-1)*7 + (15 if self.version == 11 else 0)
            if name[-1] == "C":
                return cache[base] << 4 | cache[base+1] & 15
            return cache[base+2] | (cache[base+1] >> 4) << 8
        raise KeyError(name)

    def set(self, cache, name, value):
        value = _integer(value)
        if name in NOOP_SET or name == "Null":
            return
        if name in BOOL_SET:
            offset, clear, enabled, bits = BOOL_SET[name]
            if value in (0, 1):
                _put(cache, offset, enabled if value else clear, bits if value else 0)
            return
        if name in MASK_SET:
            offset, keep, shift, mask = MASK_SET[name]
            _put(cache, self._offset(name, offset), keep, (value & mask) << shift)
            return
        if name in ("Dmod", "Dwet", "Emod", "SmartWind", "Quiet", "UDFanPort",
                    "UnmanedOffTime", "VocRole"):
            offset, keep, shift, maximum, bias = {
                "Dmod": (0x30, 0xf0, 0, 7, 0), "Dwet": (0x34, 0xf0, 0, 14, 1),
                "Emod": (0x34, 0x8f, 4, 5, 0), "SmartWind": (0x38, 0x1f, 5, 5, 0),
                "Quiet": (0x31, 0xf3, 2, 2, 0), "UDFanPort": (0x38, 0xf3, 2, 3, 0),
                "UnmanedOffTime": (0x3a, 0xe7, 3, 3, 0),
                "VocRole": (0x31, 0x9f, 5, 3, 0)}[name]
            if 0 <= value <= maximum:
                _put(cache, offset, keep, (value+bias) << shift)
            return
        if name == "DsplySt":
            _put(cache, 0x2a, 0xcf, (value if value in (0, 2, 3) else 1) << 4)
        elif name == "Mod":
            if 0 <= value <= 4:
                _put(cache, 0x25, 0x8f, value << 4)
                if value != 1:
                    _put(cache, 0x2c, 0xbf, 0)
        elif name == "AssHt":
            if value in (0, 1, 2):
                _put(cache, 0x27, 0xf7, 8 if value == 0 else 0)
                _put(cache, 0x2c, 0x7f, 128 if value == 2 else 0)
        elif name in ("SvSt", "SwhWifi"):
            if value in (0, 1):
                _put(cache, 0x2c if name == "SvSt" else 0x28,
                     0xbf if name == "SvSt" else 0xfd, value*(64 if name == "SvSt" else 2))
        elif name == "SwhSlp":
            if value in (0, 1):
                _put(cache, 0x25, 0xf7, value*8)
                if not value:
                    _put(cache, 0x31, 0xef, 0)
        elif name == "SlpMod":
            if 0 <= value <= 4:
                _put(cache, 0x25, 0xf7, 8 if value in (1, 3, 4) else 0)
                _put(cache, 0x31, 0x6f, (0, 0, 16, 16, 128)[value])
        elif name in ("DnPLLRSwing", "DnPRLRSwing", "SwingLfRig"):
            value &= 255
            if name == "SwingLfRig":
                if value > 8:
                    return
                value = {7: 12, 8: 13}.get(value, value)
                offset, keep, shift = 0x29, 0xf0, 0
            else:
                if value > 6 and value not in (12, 13):
                    return
                offset = 0x4d
                keep, shift = (0xf, 4) if name == "DnPLLRSwing" else (0xf0, 0)
            _put(cache, offset, keep, value << shift)
        elif name == "TemSen":
            cache[0x18f if self.version == 11 else 0x180] = (min(value, 50)+40) & 255
        elif name == "WdSpd":
            low = 0 if value == 0 else 1 if value in (1, 2) else 2 if value in (3, 4) else 3 if value > 4 else cache[0x25] & 3
            _put(cache, 0x25, 0xfc, low)
            _put(cache, 0x33, 0xf8, value & 255)
        elif name == "NewTimerSet":
            # Synthetic persisted timer selector; never call a flash primitive.
            cache[0x56f] = value & 255
            _put(cache, 0x49, 0xfd, (value & 1) << 1)
        elif name.startswith("Slp1"):
            ordinal = int(name[-1])-1
            base = 0x4f+ordinal*2
            high = name[4] == "H"
            cache[base+int(high)] = value & 255
            cache[0x170+ordinal*2+int(high)+(15 if self.version == 11 else 0)] = value & 255
            if high:
                encoded = (cache[base]+cache[base+1]*256)//10
                offset = (0x32, 0x35, 0x36, 0x37)[ordinal//2]
                _put(cache, offset, 0xf0 if ordinal & 1 else 15,
                     encoded-16 if ordinal & 1 else encoded << 4)
        elif name.startswith("StSlp") and name[-1] in ("C", "H"):
            base = 0x148+(int(name[5])-1)*7+(15 if self.version == 11 else 0)
            if name[-1] == "C":
                cache[base] = value >> 4 & 255
                _put(cache, base+1, 0xf0, value & 15)
            else:
                cache[base+2] = value & 255
                _put(cache, base+1, 15, (value >> 8) << 4)
        else:
            raise KeyError(name)


JDR_FIELDS = ("Pow", "Wmod", "SetTemInt", "SetTemDec", "WschTyp", "Sch1", "Sch2",
              "Wtmr1StartHr", "Wtmr1StartMin", "Wtmr1EndHr", "Wtmr1EndMin",
              "Wtmr2StartHr", "Wtmr2StartMin", "Wtmr2EndHr", "Wtmr2EndMin",
              "CurrentTemperature", "AllErr", "Wstate", "WstpSv", "WstpH", "WatTmp",
              "Watpercent", "SwhBw", "BwErr", "BwBoard", "TemUn")
JDR_BYTES = dict(zip(JDR_FIELDS[7:15], range(6, 14)))
JDR_BYTES.update(Wmod=14, SetTemInt=15, SetTemDec=16, WstpSv=17, WstpH=18,
                 WatTmp=19, CurrentTemperature=19, Watpercent=20)
JDR_BITS = {"Pow": (5, 1), "WschTyp": (5, 3), "Sch1": (5, 4), "Sch2": (5, 5),
            "AllErr": (5, 6), "Wstate": (5, 2), "SwhBw": (43, 1),
            "BwErr": (43, 5), "BwBoard": (43, 6), "TemUn": (56, 2)}
JDR_WRITABLE = frozenset(JDR_FIELDS[:15]+("TemUn",))


class JdrCache:
    def get(self, cache, name, mid="9100", cloud=9):
        if name in JDR_BYTES:
            return cache[JDR_BYTES[name]]
        offset, shift = JDR_BITS[name]
        return cache[offset] >> shift & 1

    def set(self, cache, name, value):
        value = _integer(value)
        if name not in JDR_WRITABLE:
            return
        if name in JDR_BYTES:
            cache[JDR_BYTES[name]] = value & 255
        else:
            offset, shift = JDR_BITS[name]
            if name == "TemUn":
                # Original serial writer also sets the independent bit zero.
                _put(cache, 43, 0xfd, 1 | (value << 1))
            else:
                _put(cache, offset, 255 ^ (1 << shift), (1 << shift) if value == 1 else 0)

    def joylink_readouts(self, cache):
        """Other registered transport's distinct names/units, not UDP aliases."""
        result = {
            "Power": cache[5] >> 1 & 1, "Mode": cache[14],
            "TemperatureSet": cache[15]+cache[16]//5,
            "Reserve1Type": cache[5] >> 3 & 1, "Reserve2Type": cache[5] >> 3 & 1,
            "Reserve1": cache[5] >> 4 & 1, "Reserve2": cache[5] >> 5 & 1,
            "CurrentTemperature": cache[19]-100, "Error": cache[5] >> 6 & 1,
            "State": 2 if cache[5] & 4 else 3, "Maxsettemp": cache[17]-100,
            "Maxsettemp1": cache[18]-100,
            "CurrentHotWater": 6 if not cache[20] else int((cache[20]-100)/20),
            "Timing": cache[43] >> 6 & 1,
            "BackwaterState": 2 if cache[43] & 32 else cache[43] >> 1 & 1,
            "TemperatureUnit": cache[56] >> 2 & 1,
        }
        for ordinal, name in enumerate(("Reserve1OnTime", "Reserve1OffTime",
                                        "Reserve2OnTime", "Reserve2OffTime")):
            result[name] = cache[6+ordinal*2]*60+cache[7+ordinal*2]
        return result


METADATA = ("name", "lock", "AutoUpdate", "time", "host", "hid", "mid", "MOta", "bc",
            "DevID", "MafIdf", "AppTimer", "MidType")


def _columns(value):
    if not isinstance(value, list) or len(value) > 64:
        raise InvalidPacket("BL request requires at most 64 property names")
    names = [_text(name, 511, empty=False) for name in value]
    if sum(len(name.encode())+1 for name in names) > 512:
        raise InvalidPacket("BL property names exceed the original 512-byte buffer")
    return names


class Broadlink:
    def __init__(self, version, preset):
        self.version, self.preset = version, preset
        self.jdr = version == 3
        self.fields = JDR_FIELDS if self.jdr else PRESETS[preset]
        self.cache = JdrCache() if self.jdr else BlCache(version)
        self.limit = 1460 if self.jdr else 1972

    def validate_state(self, state):
        for name, value in state.items():
            if (name not in self.fields or (self.jdr and name not in JDR_WRITABLE)
                    or (not self.jdr and name in NOOP_SET)):
                raise ValueError("only selected writable source cache fields may be configured")
            try:
                _integer(value)
            except InvalidPacket as error:
                raise ValueError(str(error)) from error

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        return None

    def _runtime(self, device, state):
        if "_bl" not in state:
            cache = bytearray(0x600)
            for name, value in state.items():
                self.cache.set(cache, name, value)
            state["_bl"] = {
                "cache": cache, "name": self._name(device), "lock": 0, "AutoUpdate": 0,
                "time": "1970-01-01 00:00:00", "host": "", "timers": {},
                "speech_seen": 0, "vocmac": "", "token": "",
                "feedid": "synthetic-feed", "accesskey": "synthetic-access-key",
            }
        return state["_bl"]

    def _name(self, device):
        if self.jdr:
            return "GR-Heater_900d_05_"+device.mac[-4:]
        return "GR-AC_"+device.mid+"_05_"+device.mac[-4:]

    def _metadata(self, device, runtime):
        result = {name: runtime[name] for name in ("name", "lock", "AutoUpdate", "time", "host")}
        result.update(hid=device.profile.hid, mid=device.mid, DevID="", MafIdf=0,
                      AppTimer=int(any(not record["enable"] for record in runtime["timers"].values())),
                      MidType="", bc=base64.b64encode(
                          (b"" if self.jdr else b"CHUSHIJITIAOMA")).decode())
        if not self.jdr:
            result.update(rssi=0, ver="V3.0.0", vender="")
        return result

    def _reply(self, device, inner, outer=None):
        if outer is None:
            envelope = {"t": "pack", "i": 1, "uid": 0, "cid": "", "tcid": ""}
            key = KEY
        else:
            index = _integer(outer.get("i"))
            envelope = {"t": "pack", "i": index, "uid": _integer(outer.get("uid", 0)),
                        "cid": outer.get("tcid", ""), "tcid": outer.get("cid", "")}
            key = SPEECH_KEY if self.jdr and index == 3 else KEY if index else device.key
        reply = Reply(envelope, inner, key, CODEC)
        # Chosen safety boundary: serialize/bound before committing the cache.
        if len(encode_reply(reply)) >= self.limit:
            raise InvalidPacket("BL reply exceeds the source transport scratch buffer")
        return reply

    def advertise(self, device, outer):
        state = deepcopy(device.state)
        runtime = self._runtime(device, state)
        inner = {"t": "dev", "cid": "", "bc": "" if self.jdr else "CHUSHIJITIAOMA",
                 "brand": "", "catalog": "", "mac": device.mac, "mid": device.mid,
                 "model": "", "name": runtime["name"], "lock": runtime["lock"],
                 "series": "", "vender": "", "ver": "" if self.jdr else "V3.0.0"}
        return [self._reply(device, inner)]

    def _time(self, runtime, value):
        old, new = _clock(runtime["time"]), _clock(value)
        if new > old and runtime["timers"]:
            if (new-old).days > 366:
                raise InvalidPacket("synthetic timer advance is bounded to one year")
            day = old.replace(hour=0, minute=0, second=0)
            while day <= new:
                for record in runtime["timers"].values():
                    event = day.replace(hour=record["hr"], minute=record["min"], second=record["sec"])
                    repeating = any(record["week"])
                    if (not record["enable"] and old < event <= new
                            and event >= datetime(2018, 5, 22, 6, 10, 36)
                            and (not repeating or record["week"][(event.weekday()+1) % 7])):
                        for command in record["cmd"]:
                            for name, item in zip(command["opt"], command["p"]):
                                if name in self.fields:
                                    self.cache.set(runtime["cache"], name, item)
                        if not repeating:
                            record["enable"] = 1
                day += timedelta(days=1)
        runtime["time"] = value

    def _advance(self, runtime, now):
        elapsed = max(0.0, now-runtime.get("clock_at", now))+runtime.get("fraction", 0.0)
        seconds = int(elapsed)
        if seconds:
            self._time(runtime, (_clock(runtime["time"])+timedelta(seconds=seconds)).strftime(
                "%Y-%m-%d %H:%M:%S"))
        runtime["clock_at"], runtime["fraction"] = now, elapsed-seconds

    def _set_metadata(self, runtime, name, value):
        if name in ("name", "host"):
            runtime[name] = _text(value, 31)
        elif name == "lock":
            runtime[name] = int(_integer(value) != 0)
        elif name == "AutoUpdate":
            runtime[name] = _integer(value) & 255
        elif name == "time":
            self._time(runtime, value)
        elif name == "ReportClientID" and not self.jdr:
            runtime[name] = _text(value, 31)
        else:
            raise InvalidPacket("BL metadata is read-only")

    def surver_payload(self, device, runtime, outer):
        """Complete outer pack carrying the source's non-JSON diagnostic inner."""
        header = bytearray(39)
        if self.jdr:
            # Original control callback echoes this queued request, not the Gree snapshot header.
            header[:14] = b'{"t":"surver"}'
        else:
            header[:2] = b"fg"
            header[30], header[38] = 4, 2
        header[2:4] = b"\0\0"
        header[4:10] = header[16:22] = bytes.fromhex(device.mac)
        when = _clock(runtime["time"])
        header[32:38] = bytes(((when.year+48) & 255, when.month, when.day,
                               when.hour, when.minute, when.second))
        # Native RTC returns status zero; AES's negative length returns zero, so no copy occurs.
        diagnostic = b"!!"+base64.b64encode(header)+b"\n"
        wrapped = AES.new(KEY, AES.MODE_ECB).encrypt(pad(diagnostic, 16))
        envelope = {"t": "pack", "i": 1, "uid": _integer(outer.get("uid", 0)),
                    "cid": outer.get("tcid", ""), "tcid": outer.get("cid", ""),
                    "pack": base64.b64encode(wrapped).decode()}
        result = json.dumps(envelope, separators=(",", ":")).encode()
        if len(result) >= self.limit:
            raise InvalidPacket("BL diagnostic exceeds the source scratch buffer")
        return result

    def _command(self, device, runtime, inner, identity):
        names, values = _columns(inner.get("opt")), inner.get("p")
        if not isinstance(values, list) or len(names) != len(values):
            raise InvalidPacket("BL command arrays must match")
        special = ("dwTsk", "dwRpt")
        if any(name in special for name in names):
            selected = dict(zip(names, (_integer(value) for value in values)))
            columns = [name for name in special if name in selected]
            runtime.update({name: selected[name] for name in columns})
            return {"t": "res", "mac": device.mac, "opt": columns,
                    "p": [selected[name] for name in columns],
                    "val": [selected[name] for name in columns], "r": 200}
        local = tuple(name for name in METADATA if name != "MOta")
        if not self.jdr:
            local += ("rssi", "ver", "vender", "ReportClientID")
        for name, value in zip(names, values):
            canonical = name if self.jdr else _SET_ALIASES.get(name.casefold())
            if canonical is not None and (not self.jdr or canonical in JDR_FIELDS):
                self.cache.set(runtime["cache"], canonical, value)
            elif name in local:
                self._set_metadata(runtime, name, value)
            else:
                _integer(value)
        metadata = self._metadata(device, runtime)
        # Native local metadata groups precede forwarded raw columns.
        columns = [name for name in names if name in local]
        columns += [name for name in names if name in self.fields]
        effective = [metadata[name] if name in metadata else
                     self.cache.get(runtime["cache"], name, device.mid)
                     for name in columns if name not in ("MOta", "ReportClientID")]
        requested = [metadata[name] for name in columns if name in metadata]
        requested += [value for name, value in zip(names, values) if name in self.fields]
        return {"t": "res", "mac": identity, "val": effective, "p": requested,
                "opt": columns, "r": 200}

    def handle(self, device, outer):
        _members(outer)
        if outer.get("t") == "wlan":
            state = deepcopy(device.state)
            runtime = self._runtime(device, state)
            _text(outer.get("ssid"), 32)
            _text(outer.get("psw"), 64)
            runtime["host"] = _text(outer.get("host"), 31)
            reply = Reply({"t": "wlan", "r": 200})
            device.state = state
            return [reply]
        if outer.get("t") != "pack" or outer.get("tcid") != device.mac:
            raise InvalidPacket("BL packet must target this root")
        index = _integer(outer.get("i"))
        if index not in ((0, 1, 3) if self.jdr else (0, 1)):
            raise InvalidPacket("BL has no plaintext-object or unknown key selector")
        key = SPEECH_KEY if self.jdr and index == 3 else KEY if index else device.key
        inner = decode_pack(outer, key, CODEC)
        _members(inner)
        identity = inner.get("sub", inner.get("mac", device.mac))
        aliases = (device.mac, device.mac+"01")
        if identity not in aliases:
            raise InvalidPacket("BL packet has an unknown root/cache alias")
        state = deepcopy(device.state)
        runtime = self._runtime(device, state)
        now = monotonic()
        self._advance(runtime, now)
        kind = inner.get("t")
        if kind == "surver":
            reply = Reply({}, raw_payload=self.surver_payload(device, runtime, outer))
            device.advance(now)
            device.state = state
            return [reply]
        if kind == "bind":
            response = {"r": 200, "t": "bindok", "mac": inner.get("mac", device.mac),
                        "key": device.key.decode("ascii")}
        elif kind == "status":
            names = _columns(inner.get("cols"))
            metadata = self._metadata(device, runtime)
            columns, values = [], []
            for name in names:
                if name in metadata:
                    columns.append(name)
                    values.append(metadata[name])
                elif name == "MOta":
                    columns.append(name)  # Original recognized metadata appends no value.
                elif name in self.fields:
                    columns.append(name)
                    values.append(self.cache.get(runtime["cache"], name, device.mid))
            response = {"t": "dat", "uid": _integer(outer.get("uid", 0)), "mac": identity,
                        "cid": device.mac, "dat": values, "cols": columns, "r": 200}
        elif kind == "cmd":
            response = self._command(device, runtime, inner, identity)
        elif kind in ("setT", "updateT"):
            timer_id, record = FiniteTables._timer(self, inner)
            if timer_id not in runtime["timers"] and len(runtime["timers"]) >= 10:
                return [] if kind == "updateT" else [self._reply(device, {"t": "resT", "r": 500}, outer)]
            runtime["timers"][timer_id] = record
            response = {"t": "resT", "r": 200}
        elif kind == "deleteT":
            runtime["timers"].pop(_integer(inner.get("id")) & 255, None)
            response = {"t": "resT", "r": 200}
        elif kind == "queryT":
            start, count = (_integer(inner.get(field)) & 255 for field in ("index", "count"))
            response = {"t": "listT", "total": count, "index": start}
            if runtime["timers"]:
                response["list"] = [
                    {field: deepcopy(record[field]) for field in
                     ("id", "name", "enable", "hr", "min", "sec", "week", "cmd")}
                    for ordinal, record in enumerate(runtime["timers"].values())
                    if start <= ordinal <= start+count]
        elif kind == "dump":
            runtime["dump"] = (_integer(inner.get("period", 60)), _integer(inner.get("cnt", 1)))
            response = {"t": "res", "mac": device.mac, "r": 200}
        elif kind == "subDev":
            page = _integer(inner.get("i"))
            response = {"r": 200, "t": "subList", "i": page, "list": [], "c": 1}
            if page == 0:
                response["list"] = [{"mac": device.mac+"01", "mid": device.mid+"01",
                                     "name": "GreeHot", "model": "gree", "lock": 0}]
        elif self.jdr and kind in ("ipsearch", "shb", "tokenreq", "token", "rtoken"):
            if kind == "rtoken":
                runtime["speech_seen"] = 0
                # Native void callback returns diagnostic printf's residual length
                # without initializing output. Reject that unsafe response, not fake an ACK.
                device.state = state
                return []
            if kind == "ipsearch":
                if inner.get("mac") != device.mac:
                    return []
                runtime["vocmac"] = _text(inner.get("vocmac"), 31)
                response = {"t": "ripsearch", "module": "iotwifi"}
            elif kind == "shb":
                response = {"t": "rshb", "module": "iotwifi"}
            else:
                _text(inner.get("factory"), 31)
                if kind == "tokenreq":
                    response = {"t": "rtokenreq", "module": "iotwifi", "factory": "jd",
                                "feedid": runtime["feedid"], "acckey": runtime["accesskey"]}
                else:
                    runtime["token"] = _text(inner.get("token"), 63)
                    response = {"t": "rtoken", "module": "iotwifi"}
            # Outer processor consumes the callback marker and remembers the last speech peer.
            runtime["speech_seen"], runtime["speech_peer"] = 0, outer.get("cid", "")
        else:
            return []  # No physical flash/network action or invented upgrade acknowledgement.
        reply = self._reply(device, response, outer)
        device.advance(now)
        device.state = state
        return [reply]


def _profile(version, preset, mids, hid, sha):
    return Profile(id=f"sim-bl3332-{'jdrs' if version == 3 else 'sn'}v{version}-{preset}-cache",
                   mids=mids, hid=hid, source_sha256=sha, initial_state={},
                   handler=Broadlink(version, preset), max_request_bytes=1460 if version == 3 else 1972)


PROFILES = (
    _profile(13, "controller", ("11000", "11001", "11002", "10001", "10002"),
             "362001061381+U-BL3332_SNV13.bin",
             "c38c120c2f125dfc5e90917265860d0efb0bfa8089b8586fa2466b22fe17063b"),
    _profile(13, "dehumidifier", ("13800", "13801"),
             "362001061381+U-BL3332_SNV13.bin",
             "c38c120c2f125dfc5e90917265860d0efb0bfa8089b8586fa2466b22fe17063b"),
    _profile(13, "voice", ("11f00", "11f01", "11f02"),
             "362001061381+U-BL3332_SNV13.bin",
             "c38c120c2f125dfc5e90917265860d0efb0bfa8089b8586fa2466b22fe17063b"),
    _profile(11, "controller", ("11000", "11001", "11002", "10001", "10002"),
             "362001061381+U-BL3332_SNV11.bin",
             "5b050eaef8e0b1e28e47c57cff60f642e9f73eb34ca46f69b3096ac3f6cb4d36"),
    _profile(11, "dehumidifier", ("13800", "13801"),
             "362001061381+U-BL3332_SNV11.bin",
             "5b050eaef8e0b1e28e47c57cff60f642e9f73eb34ca46f69b3096ac3f6cb4d36"),
    _profile(11, "voice", ("11f00", "11f01", "11f02"),
             "362001061381+U-BL3332_SNV11.bin",
             "5b050eaef8e0b1e28e47c57cff60f642e9f73eb34ca46f69b3096ac3f6cb4d36"),
    _profile(3, "heater", ("9100",), "362001061737+U-BL3332_JDRSV3.bin",
             "ea6228d5a32564ccf597bd8cb771fb0fd92e73521fec71c7aa897eb9fa534bf3"),
)
