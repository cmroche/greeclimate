"""MediaTek finite scalar LAN caches with an explicitly synthetic board.

The scratch cache is not mainboard calibration. Writes retain raw byte packing,
shared bits and non-inverse getters. Non-scalar firmware management is excluded.
"""

import json
from datetime import datetime, timedelta
from math import floor
from time import monotonic

from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"

_GETTERS = {'Null': ('const', 0),
 'ACStupPos': ('byte', 11, 255, 4),
 'Add0.5': ('byte', 43, 15, 3),
 'Air': ('byte', 40, 63, 4),
 'AirQ': ('const', 0),
 'Antifreeze': ('byte', 60, 63, 5),
 'AssHt': ('special', 'AssHt', (37, 39)),
 'AutoClean': ('byte', 40, 7, 2),
 'Blo': ('special', 'Blo', (37, 39)),
 'CoolNoise': ('byte', 15, 255, 0),
 'Defrost': ('byte', 60, 127, 6),
 'Dfltr': ('byte', 70, 63, 5),
 'Dmod': ('byte', 48, 15, 0),
 'DnPLLRSwing': ('byte', 77, 255, 4),
 'DnPRLRSwing': ('byte', 77, 15, 0),
 'DnPUDSwing': ('byte', 76, 15, 0),
 'DsplySt': ('byte', 42, 63, 4),
 'DwatFul': ('byte', 44, 3, 1),
 'Dwet': ('special', 'Dwet', (29,)),
 'Emod': ('byte', 52, 127, 4),
 'EnvArea1St': ('byte', 69, 1, 0),
 'EnvArea2St': ('byte', 69, 3, 1),
 'EnvArea3St': ('byte', 69, 7, 2),
 'EnvArea4St': ('byte', 69, 15, 3),
 'EnvArea5St': ('byte', 69, 31, 4),
 'EnvArea6St': ('byte', 69, 63, 5),
 'EnvArea7St': ('byte', 69, 127, 6),
 'EnvArea8St': ('byte', 69, 128, 7),
 'EnvArea9St': ('byte', 68, 1, 0),
 'FavorMode': ('byte', 62, 15, 3),
 'FbidBloPer': ('byte', 68, 3, 1),
 'HandCtl': ('byte', 75, 63, 1),
 'Health': ('byte', 39, 7, 2),
 'HeatCoolType': ('const', 0),
 'HeatNoise': ('byte', 16, 255, 0),
 'HumSen': ('byte', 315, 255, 0),
 'ImageRecovery': ('const', 0),
 'ImgUpdateCol': ('const', 0),
 'ImgUpdateSta': ('byte', 47, 255, 7),
 'ImgUpdateRes': ('byte', 56, 127, 6),
 'ImgVerSta': ('byte', 35, 31, 4),
 'Lig': ('special', 'Lig', (29,)),
 'MicroSen': ('byte', 35, 7, 2),
 'Mod': ('byte', 37, 127, 4),
 'NobodySave': ('byte', 314, 255, 7),
 'NoiseSet': ('byte', 4, 1, 0),
 'PM2P5': ('const', 0),
 'PMVComfort': ('byte', 60, 255, 7),
 'Pow': ('byte', 37, 128, 7),
 'Purify': ('const', 0),
 'Quiet': ('byte', 49, 15, 2),
 'ReplaceHEPA': ('byte', 58, 127, 6),
 'RoomHigh': ('byte', 14, 255, 0),
 'RoomLen': ('byte', 12, 255, 0),
 'RoomWid': ('byte', 13, 255, 0),
 'SaveGuid': ('byte', 17, 1, 0),
 'Security': ('byte', 64, 31, 4),
 'SecurityMode': ('byte', 64, 15, 3),
 'SetTem': ('special', 'SetTem', (38,)),
 'Slp1H1': ('special', 'Slp1H1', (50,)),
 'Slp1H2': ('special', 'Slp1H2', (50,)),
 'Slp1H3': ('special', 'Slp1H3', (53,)),
 'Slp1H4': ('special', 'Slp1H4', (53,)),
 'Slp1H5': ('special', 'Slp1H5', (54,)),
 'Slp1H6': ('special', 'Slp1H6', (54,)),
 'Slp1H7': ('special', 'Slp1H7', (55,)),
 'Slp1H8': ('special', 'Slp1H8', (55,)),
 'Slp1L1': ('special', 'Slp1L1', (50,)),
 'Slp1L2': ('special', 'Slp1L2', (50,)),
 'Slp1L3': ('special', 'Slp1L3', (53,)),
 'Slp1L4': ('special', 'Slp1L4', (53,)),
 'Slp1L5': ('special', 'Slp1L5', (54,)),
 'Slp1L6': ('special', 'Slp1L6', (54,)),
 'Slp1L7': ('special', 'Slp1L7', (55,)),
 'Slp1L8': ('special', 'Slp1L8', (55,)),
 'SlpMod': ('special', 'SlpMod', (49, 37)),
 'SmartWind': ('byte', 56, 255, 5),
 'StHt': ('const', 0),
 'SvSt': ('byte', 44, 127, 6),
 'SwhSlp': ('special', 'SwhSlp', (37, 49)),
 'SwhSw': ('byte', 41, 255, 4),
 'SwhWifi': ('special', 'SwhWifi', (29,)),
 'SwhWifiRes': ('byte', 40, 1, 0),
 'SwingLfRig': ('special', 'SwingLfRig', (41,)),
 'SwUpDn': ('byte', 41, 255, 4),
 'TemRec': ('byte', 40, 127, 6),
 'TemSen': ('special', 'TemSen', (313,)),
 'TemUn': ('byte', 40, 128, 7),
 'Tur': ('byte', 39, 1, 0),
 'UDFanPort': ('byte', 56, 15, 2),
 'UnmanedOffTime': ('byte', 58, 31, 3),
 'UnmanedShutDown': ('byte', 58, 63, 5),
 'VocCtl': ('byte', 43, 1, 0),
 'VocIdiom': ('const', 0),
 'VocRole': ('byte', 49, 127, 5),
 'VocUpdateCol': ('const', 0),
 'VocUpdateSta': ('byte', 68, 7, 2),
 'VocUpdateRes': ('byte', 56, 63, 5),
 'VocVerSta': ('byte', 35, 15, 3),
 'WdSpd': ('byte', 51, 7, 0),
 'Wet': ('byte', 43, 127, 4),
 'AllErr': ('byte', 70, 127, 6),
 'ElcAllKwhClr': ('byte', 40, 15, 3),
 'ElcEn': ('special', 'ElcEn', ()),
 'CZLJC': ('byte', 71, 255, 7),
 'NewTimer': ('const', 0),
 'NewTimerSet': ('const', 0)}

_SETTERS = {'Null': ('noop',),
 'ACStupPos': ('special', 'ACStupPos', (11,)),
 'Add0.5': ('choice', 43, {1: (247, 8), 0: (247, 0)}),
 'Air': ('special', 'Air', (40,)),
 'AirQ': ('noop',),
 'Antifreeze': ('choice', 70, {1: (191, 64), 0: (191, 0)}),
 'AssHt': ('choice', 39, {1: (247, 0), 0: (247, 8)}),
 'AutoClean': ('choice', 40, {1: (251, 4), 0: (251, 0)}),
 'Blo': ('choice', 39, {1: (247, 8), 0: (247, 0)}),
 'CoolNoise': ('byte', 15),
 'Defrost': ('choice', 67, {1: (254, 1), 0: (254, 0)}),
 'Dfltr': ('choice', 70, {1: (239, 16), 0: (239, 0)}),
 'Dmod': ('special', 'Dmod', (48,)),
 'DnPLLRSwing': ('special', 'DnPLLRSwing', (77,)),
 'DnPRLRSwing': ('special', 'DnPRLRSwing', (77,)),
 'DnPUDSwing': ('special', 'DnPUDSwing', (76,)),
 'DsplySt': ('special', 'DsplySt', (42,)),
 'DwatFul': ('choice', 44, {1: (253, 2), 0: (253, 0)}),
 'Dwet': ('special', 'Dwet', (52,)),
 'Emod': ('special', 'Emod', (52,)),
 'EnvArea1St': ('choice', 69, {1: (254, 1), 0: (254, 0)}),
 'EnvArea2St': ('choice', 69, {1: (253, 2), 0: (253, 0)}),
 'EnvArea3St': ('choice', 69, {1: (251, 4), 0: (251, 0)}),
 'EnvArea4St': ('choice', 69, {1: (254, 8), 0: (247, 0)}),
 'EnvArea5St': ('choice', 69, {1: (239, 16), 0: (239, 0)}),
 'EnvArea6St': ('choice', 69, {1: (223, 32), 0: (223, 0)}),
 'EnvArea7St': ('choice', 69, {1: (191, 64), 0: (191, 0)}),
 'EnvArea8St': ('choice', 69, {1: (255, 128), 0: (127, 0)}),
 'EnvArea9St': ('choice', 68, {1: (254, 1), 0: (254, 0)}),
 'FavorMode': ('choice', 62, {1: (247, 8), 0: (247, 0)}),
 'FbidBloPer': ('choice', 68, {1: (253, 2), 0: (253, 0)}),
 'HandCtl': ('special', 'HandCtl', (75,)),
 'Health': ('choice', 39, {1: (251, 4), 0: (251, 0)}),
 'HeatCoolType': ('noop',),
 'HeatNoise': ('byte', 16),
 'HumSen': ('noop',),
 'ImageRecovery': ('choice', 72, {1: (254, 1), 0: (254, 0)}),
 'ImgUpdateCol': ('choice', 75, {1: (191, 64), 0: (191, 0)}),
 'ImgUpdateSta': ('noop',),
 'ImgUpdateRes': ('noop',),
 'ImgVerSta': ('noop',),
 'Lig': ('choice', 39, {1: (253, 2), 0: (253, 0)}),
 'MicroSen': ('choice', 47, {1: (255, 128), 0: (127, 0)}),
 'Mod': ('special', 'Mod', (37, 44)),
 'NobodySave': ('choice', 56, {1: (254, 1), 0: (254, 0)}),
 'NoiseSet': ('choice', 4, {1: (254, 1), 0: (254, 0)}),
 'PM2P5': ('noop',),
 'PMVComfort': ('choice', 66, {1: (254, 1), 0: (254, 0)}),
 'Pow': ('choice', 37, {1: (255, 128), 0: (127, 0)}),
 'Purify': ('noop',),
 'Quiet': ('special', 'Quiet', (49,)),
 'ReplaceHEPA': ('choice', 58, {1: (191, 64), 0: (191, 0)}),
 'RoomHigh': ('byte', 14),
 'RoomLen': ('byte', 12),
 'RoomWid': ('byte', 13),
 'SaveGuid': ('choice', 17, {1: (254, 1), 0: (254, 0)}),
 'Security': ('choice', 64, {1: (239, 16), 0: (239, 0)}),
 'SecurityMode': ('choice', 64, {1: (247, 8), 0: (247, 0)}),
 'SetTem': ('special', 'SetTem', (38,)),
 'Slp1H1': ('special', 'Slp1H1', (80, 50, 79)),
 'Slp1H2': ('special', 'Slp1H2', (82, 50, 81)),
 'Slp1H3': ('special', 'Slp1H3', (84, 53, 83)),
 'Slp1H4': ('special', 'Slp1H4', (86, 53, 85)),
 'Slp1H5': ('special', 'Slp1H5', (88, 54, 87)),
 'Slp1H6': ('special', 'Slp1H6', (90, 54, 89)),
 'Slp1H7': ('special', 'Slp1H7', (92, 55, 91)),
 'Slp1H8': ('special', 'Slp1H8', (94, 55, 93)),
 'Slp1L1': ('byte', 79),
 'Slp1L2': ('byte', 81),
 'Slp1L3': ('byte', 83),
 'Slp1L4': ('byte', 85),
 'Slp1L5': ('byte', 87),
 'Slp1L6': ('byte', 89),
 'Slp1L7': ('byte', 91),
 'Slp1L8': ('byte', 93),
 'SlpMod': ('special', 'SlpMod', (37, 49)),
 'SmartWind': ('special', 'SmartWind', (56,)),
 'StHt': ('noop',),
 'SvSt': ('special', 'SvSt', (29,)),
 'SwhSlp': ('choice', 37, {1: (247, 8), 0: (247, 0)}),
 'SwhSw': ('choice', 41, {1: (15, 16), 0: (15, 0)}),
 'SwhWifi': ('special', 'SwhWifi', (29,)),
 'SwhWifiRes': ('choice', 40, {1: (254, 1), 0: (254, 0)}),
 'SwingLfRig': ('special', 'SwingLfRig', (41,)),
 'SwUpDn': ('special', 'SwUpDn', (41,)),
 'TemRec': ('choice', 40, {1: (191, 64), 0: (191, 0)}),
 'TemSen': ('special', 'TemSen', (313,)),
 'TemUn': ('choice', 40, {1: (255, 128), 0: (127, 0)}),
 'Tur': ('choice', 39, {1: (254, 1), 0: (254, 0)}),
 'UDFanPort': ('special', 'UDFanPort', (56,)),
 'UnmanedOffTime': ('special', 'UnmanedOffTime', (58,)),
 'UnmanedShutDown': ('choice', 58, {1: (223, 32), 0: (223, 0)}),
 'VocCtl': ('choice', 43, {1: (254, 1), 0: (254, 0)}),
 'VocIdiom': ('special', 'VocIdiom', (60,)),
 'VocRole': ('special', 'VocRole', (49,)),
 'VocUpdateCol': ('choice', 75, {1: (255, 128), 0: (127, 0)}),
 'VocUpdateSta': ('noop',),
 'VocUpdateRes': ('noop',),
 'VocVerSta': ('noop',),
 'WdSpd': ('special', 'WdSpd', (37, 51)),
 'Wet': ('special', 'Wet', (43,)),
 'AllErr': ('noop',),
 'ElcAllKwhClr': ('special', 'ElcAllKwhClr', (40,)),
 'ElcEn': ('noop',),
 'CZLJC': ('special', 'CZLJC', (73,)),
 'NewTimer': ('noop',),
 'NewTimerSet': ('special', 'NewTimerSet', (73,))}

_GET_OVERRIDES = {'362001000835': {'ElcEn': ('special', 'ElcEn', (19,))},
 '362001060297': {'Add0.5': ('byte', 33, 15, 3),
                  'Air': ('byte', 30, 63, 4),
                  'Antifreeze': ('byte', 50, 63, 5),
                  'AssHt': ('special', 'AssHt', (27, 29)),
                  'AutoClean': ('byte', 30, 7, 2),
                  'Blo': ('special', 'Blo', (27, 29)),
                  'Defrost': ('byte', 50, 127, 6),
                  'Dfltr': ('byte', 60, 63, 5),
                  'Dmod': ('byte', 38, 15, 0),
                  'DnPLLRSwing': ('byte', 67, 255, 4),
                  'DnPRLRSwing': ('byte', 67, 15, 0),
                  'DnPUDSwing': ('byte', 66, 15, 0),
                  'DsplySt': ('byte', 32, 63, 4),
                  'DwatFul': ('byte', 34, 3, 1),
                  'Dwet': ('special', 'Dwet', (19,)),
                  'Emod': ('byte', 42, 127, 4),
                  'EnvArea1St': ('byte', 59, 1, 0),
                  'EnvArea2St': ('byte', 59, 3, 1),
                  'EnvArea3St': ('byte', 59, 7, 2),
                  'EnvArea4St': ('byte', 59, 15, 3),
                  'EnvArea5St': ('byte', 59, 31, 4),
                  'EnvArea6St': ('byte', 59, 63, 5),
                  'EnvArea7St': ('byte', 59, 127, 6),
                  'EnvArea8St': ('byte', 59, 128, 7),
                  'EnvArea9St': ('byte', 58, 1, 0),
                  'FavorMode': ('byte', 52, 15, 3),
                  'FbidBloPer': ('byte', 58, 3, 1),
                  'HandCtl': ('byte', 65, 63, 1),
                  'Health': ('byte', 29, 7, 2),
                  'HumSen': ('byte', 305, 255, 0),
                  'ImgUpdateSta': ('byte', 37, 255, 7),
                  'ImgUpdateRes': ('byte', 46, 127, 6),
                  'ImgVerSta': ('byte', 25, 31, 4),
                  'Lig': ('special', 'Lig', (19,)),
                  'MicroSen': ('byte', 25, 7, 2),
                  'Mod': ('byte', 27, 127, 4),
                  'NobodySave': ('byte', 304, 255, 7),
                  'PMVComfort': ('byte', 50, 255, 7),
                  'Pow': ('byte', 27, 128, 7),
                  'Quiet': ('byte', 39, 15, 2),
                  'ReplaceHEPA': ('byte', 48, 127, 6),
                  'Security': ('byte', 54, 31, 4),
                  'SecurityMode': ('byte', 54, 15, 3),
                  'SetTem': ('special', 'SetTem', (28,)),
                  'Slp1H1': ('special', 'Slp1H1', (40,)),
                  'Slp1H2': ('special', 'Slp1H2', (40,)),
                  'Slp1H3': ('special', 'Slp1H3', (43,)),
                  'Slp1H4': ('special', 'Slp1H4', (43,)),
                  'Slp1H5': ('special', 'Slp1H5', (44,)),
                  'Slp1H6': ('special', 'Slp1H6', (44,)),
                  'Slp1H7': ('special', 'Slp1H7', (45,)),
                  'Slp1H8': ('special', 'Slp1H8', (45,)),
                  'Slp1L1': ('special', 'Slp1L1', (40,)),
                  'Slp1L2': ('special', 'Slp1L2', (40,)),
                  'Slp1L3': ('special', 'Slp1L3', (43,)),
                  'Slp1L4': ('special', 'Slp1L4', (43,)),
                  'Slp1L5': ('special', 'Slp1L5', (44,)),
                  'Slp1L6': ('special', 'Slp1L6', (44,)),
                  'Slp1L7': ('special', 'Slp1L7', (45,)),
                  'Slp1L8': ('special', 'Slp1L8', (45,)),
                  'SlpMod': ('special', 'SlpMod', (39, 27)),
                  'SmartWind': ('byte', 46, 255, 5),
                  'SvSt': ('byte', 34, 127, 6),
                  'SwhSlp': ('special', 'SwhSlp', (27, 39)),
                  'SwhSw': ('byte', 31, 255, 4),
                  'SwhWifi': ('special', 'SwhWifi', (19,)),
                  'SwhWifiRes': ('byte', 30, 1, 0),
                  'SwingLfRig': ('special', 'SwingLfRig', (31,)),
                  'SwUpDn': ('byte', 31, 255, 4),
                  'TemRec': ('byte', 30, 127, 6),
                  'TemSen': ('special', 'TemSen', (303,)),
                  'TemUn': ('byte', 30, 128, 7),
                  'Tur': ('byte', 29, 1, 0),
                  'UDFanPort': ('byte', 46, 15, 2),
                  'UnmanedOffTime': ('byte', 48, 31, 3),
                  'UnmanedShutDown': ('byte', 48, 63, 5),
                  'VocCtl': ('byte', 33, 1, 0),
                  'VocRole': ('byte', 39, 127, 5),
                  'VocUpdateSta': ('byte', 58, 7, 2),
                  'VocUpdateRes': ('byte', 46, 63, 5),
                  'VocVerSta': ('byte', 25, 15, 3),
                  'WdSpd': ('byte', 41, 7, 0),
                  'Wet': ('byte', 33, 127, 4),
                  'AllErr': ('byte', 60, 127, 6)},
 '362001060498': {'ElcEn': ('special', 'ElcEn', (19,))},
 '362001060499': {'AssHt': ('special', 'AssHt', (37, 44, 39)),
                  'HumSen': ('byte', 401, 255, 0),
                  'NobodySave': ('byte', 400, 255, 7),
                  'StHt': ('byte', 44, 127, 6),
                  'TemSen': ('special', 'TemSen', (399,)),
                  'Buzzer_ON_OFF': ('byte', 73, 1, 0),
                  'AntiDirectBlow': ('byte', 73, 255, 7),
                  'SmartSlpMod': ('byte', 51, 127, 4),
                  'SmartSlpModEx': ('byte', 342, 255, 0),
                  'StSlp1C': ('special', 'StSlp1C', (344, 343)),
                  'StSlp1CInc': ('byte', 346, 255, 0),
                  'StSlp1CSp': ('byte', 348, 255, 0),
                  'StSlp1H': ('special', 'StSlp1H', (344, 345)),
                  'StSlp1HInc': ('byte', 347, 255, 0),
                  'StSlp1HSp': ('byte', 349, 255, 0),
                  'StSlp2C': ('special', 'StSlp2C', (351, 350)),
                  'StSlp2CInc': ('byte', 353, 255, 0),
                  'StSlp2CSp': ('byte', 355, 255, 0),
                  'StSlp2H': ('special', 'StSlp2H', (351, 352)),
                  'StSlp2HInc': ('byte', 354, 255, 0),
                  'StSlp2HSp': ('byte', 356, 255, 0),
                  'StSlp3C': ('special', 'StSlp3C', (358, 357)),
                  'StSlp3CInc': ('byte', 360, 255, 0),
                  'StSlp3CSp': ('byte', 362, 255, 0),
                  'StSlp3H': ('special', 'StSlp3H', (358, 359)),
                  'StSlp3HInc': ('byte', 361, 255, 0),
                  'StSlp3HSp': ('byte', 363, 255, 0),
                  'StSlp4C': ('special', 'StSlp4C', (365, 364)),
                  'StSlp4CInc': ('byte', 367, 255, 0),
                  'StSlp4CSp': ('byte', 369, 255, 0),
                  'StSlp4H': ('special', 'StSlp4H', (365, 366)),
                  'StSlp4HInc': ('byte', 368, 255, 0),
                  'StSlp4HSp': ('byte', 370, 255, 0),
                  'LigSen': ('byte', 51, 15, 3)}}

_SET_OVERRIDES = {'362001000835': {},
 '362001060297': {'Add0.5': ('choice', 33, {1: (247, 8), 0: (247, 0)}),
                  'Air': ('special', 'Air', (30,)),
                  'Antifreeze': ('choice', 60, {1: (191, 64), 0: (191, 0)}),
                  'AssHt': ('choice', 29, {1: (247, 0), 0: (247, 8)}),
                  'AutoClean': ('choice', 30, {1: (251, 4), 0: (251, 0)}),
                  'Blo': ('choice', 29, {1: (247, 8), 0: (247, 0)}),
                  'Defrost': ('choice', 57, {1: (254, 1), 0: (254, 0)}),
                  'Dfltr': ('choice', 60, {1: (239, 16), 0: (239, 0)}),
                  'Dmod': ('special', 'Dmod', (38,)),
                  'DnPLLRSwing': ('special', 'DnPLLRSwing', (67,)),
                  'DnPRLRSwing': ('special', 'DnPRLRSwing', (67,)),
                  'DnPUDSwing': ('special', 'DnPUDSwing', (66,)),
                  'DsplySt': ('special', 'DsplySt', (32,)),
                  'DwatFul': ('choice', 34, {1: (253, 2), 0: (253, 0)}),
                  'Dwet': ('special', 'Dwet', (42,)),
                  'Emod': ('special', 'Emod', (19,)),
                  'EnvArea1St': ('choice', 59, {1: (254, 1), 0: (254, 0)}),
                  'EnvArea2St': ('choice', 59, {1: (253, 2), 0: (253, 0)}),
                  'EnvArea3St': ('choice', 59, {1: (251, 4), 0: (251, 0)}),
                  'EnvArea4St': ('choice', 59, {1: (254, 8), 0: (247, 0)}),
                  'EnvArea5St': ('choice', 59, {1: (239, 16), 0: (239, 0)}),
                  'EnvArea6St': ('choice', 59, {1: (223, 32), 0: (223, 0)}),
                  'EnvArea7St': ('choice', 59, {1: (191, 64), 0: (191, 0)}),
                  'EnvArea8St': ('choice', 59, {1: (255, 128), 0: (127, 0)}),
                  'EnvArea9St': ('choice', 58, {1: (254, 1), 0: (254, 0)}),
                  'FavorMode': ('choice', 52, {1: (247, 8), 0: (247, 0)}),
                  'FbidBloPer': ('choice', 58, {1: (253, 2), 0: (253, 0)}),
                  'HandCtl': ('special', 'HandCtl', (65,)),
                  'Health': ('choice', 29, {1: (251, 4), 0: (251, 0)}),
                  'ImageRecovery': ('choice', 62, {1: (254, 1), 0: (254, 0)}),
                  'ImgUpdateCol': ('choice', 65, {1: (191, 64), 0: (191, 0)}),
                  'Lig': ('choice', 29, {1: (253, 2), 0: (253, 0)}),
                  'MicroSen': ('choice', 37, {1: (255, 128), 0: (127, 0)}),
                  'Mod': ('special', 'Mod', (27, 34)),
                  'NobodySave': ('choice', 46, {1: (254, 1), 0: (254, 0)}),
                  'PMVComfort': ('choice', 56, {1: (254, 1), 0: (254, 0)}),
                  'Pow': ('choice', 27, {1: (255, 128), 0: (127, 0)}),
                  'Quiet': ('special', 'Quiet', (39,)),
                  'ReplaceHEPA': ('choice', 48, {1: (191, 64), 0: (191, 0)}),
                  'Security': ('choice', 54, {1: (239, 16), 0: (239, 0)}),
                  'SecurityMode': ('choice', 54, {1: (247, 8), 0: (247, 0)}),
                  'SetTem': ('special', 'SetTem', (28,)),
                  'Slp1H1': ('special', 'Slp1H1', (70, 40, 69)),
                  'Slp1H2': ('special', 'Slp1H2', (72, 40, 71)),
                  'Slp1H3': ('special', 'Slp1H3', (74, 43, 73)),
                  'Slp1H4': ('special', 'Slp1H4', (76, 43, 75)),
                  'Slp1H5': ('special', 'Slp1H5', (78, 44, 77)),
                  'Slp1H6': ('special', 'Slp1H6', (80, 44, 79)),
                  'Slp1H7': ('special', 'Slp1H7', (82, 45, 81)),
                  'Slp1H8': ('special', 'Slp1H8', (84, 45, 83)),
                  'Slp1L1': ('byte', 69),
                  'Slp1L2': ('byte', 71),
                  'Slp1L3': ('byte', 73),
                  'Slp1L4': ('byte', 75),
                  'Slp1L5': ('byte', 77),
                  'Slp1L6': ('byte', 79),
                  'Slp1L7': ('byte', 81),
                  'Slp1L8': ('byte', 83),
                  'SlpMod': ('special', 'SlpMod', (27, 39)),
                  'SmartWind': ('special', 'SmartWind', (46,)),
                  'SvSt': ('special', 'SvSt', (19,)),
                  'SwhSlp': ('choice', 27, {1: (247, 8), 0: (247, 0)}),
                  'SwhSw': ('choice', 31, {1: (15, 16), 0: (15, 0)}),
                  'SwhWifi': ('special', 'SwhWifi', (19,)),
                  'SwhWifiRes': ('choice', 30, {1: (254, 1), 0: (254, 0)}),
                  'SwingLfRig': ('special', 'SwingLfRig', (31,)),
                  'SwUpDn': ('special', 'SwUpDn', (31,)),
                  'TemRec': ('choice', 30, {1: (191, 64), 0: (191, 0)}),
                  'TemSen': ('special', 'TemSen', (303,)),
                  'TemUn': ('choice', 30, {1: (255, 128), 0: (127, 0)}),
                  'Tur': ('choice', 29, {1: (254, 1), 0: (254, 0)}),
                  'UDFanPort': ('special', 'UDFanPort', (46,)),
                  'UnmanedOffTime': ('special', 'UnmanedOffTime', (48,)),
                  'UnmanedShutDown': ('choice', 48, {1: (223, 32), 0: (223, 0)}),
                  'VocCtl': ('choice', 33, {1: (254, 1), 0: (254, 0)}),
                  'VocIdiom': ('special', 'VocIdiom', (50,)),
                  'VocRole': ('special', 'VocRole', (39,)),
                  'VocUpdateCol': ('choice', 65, {1: (255, 128), 0: (127, 0)}),
                  'WdSpd': ('special', 'WdSpd', (27, 41)),
                  'Wet': ('special', 'Wet', (33,))},
 '362001060498': {},
 '362001060499': {'AssHt': ('special', 'AssHt', (39, 44)),
                  'Emod': ('special', 'Emod', (29,)),
                  'Slp1H1': ('special', 'Slp1H1', (80, 50, 384)),
                  'Slp1H2': ('special', 'Slp1H2', (82, 50, 386)),
                  'Slp1H3': ('special', 'Slp1H3', (84, 53, 388)),
                  'Slp1H4': ('special', 'Slp1H4', (86, 53, 390)),
                  'Slp1H5': ('special', 'Slp1H5', (88, 54, 392)),
                  'Slp1H6': ('special', 'Slp1H6', (90, 54, 394)),
                  'Slp1H7': ('special', 'Slp1H7', (92, 55, 396)),
                  'Slp1H8': ('special', 'Slp1H8', (94, 55, 398)),
                  'Slp1L1': ('special', 'Slp1L1', (29, 383)),
                  'Slp1L2': ('special', 'Slp1L2', (29, 385)),
                  'Slp1L3': ('special', 'Slp1L3', (29, 387)),
                  'Slp1L4': ('special', 'Slp1L4', (29, 389)),
                  'Slp1L5': ('special', 'Slp1L5', (29, 391)),
                  'Slp1L6': ('special', 'Slp1L6', (29, 393)),
                  'Slp1L7': ('special', 'Slp1L7', (29, 395)),
                  'Slp1L8': ('special', 'Slp1L8', (29, 397)),
                  'StHt': ('special', 'StHt', (44,)),
                  'SwhSlp': ('special', 'SwhSlp', (37, 49)),
                  'TemSen': ('special', 'TemSen', (399,)),
                  'Buzzer_ON_OFF': ('special', 'Buzzer_ON_OFF', (73,)),
                  'AntiDirectBlow': ('special', 'AntiDirectBlow', (73,)),
                  'SmartSlpMod': ('special', 'SmartSlpMod', (51,)),
                  'SmartSlpModEx': ('byte', 342),
                  'StSlp1C': ('special', 'StSlp1C', (343, 344)),
                  'StSlp1CInc': ('byte', 346),
                  'StSlp1CSp': ('byte', 348),
                  'StSlp1H': ('special', 'StSlp1H', (345, 344)),
                  'StSlp1HInc': ('byte', 347),
                  'StSlp1HSp': ('byte', 349),
                  'StSlp2C': ('special', 'StSlp2C', (350, 351)),
                  'StSlp2CInc': ('byte', 353),
                  'StSlp2CSp': ('byte', 355),
                  'StSlp2H': ('special', 'StSlp2H', (352, 351)),
                  'StSlp2HInc': ('byte', 354),
                  'StSlp2HSp': ('byte', 356),
                  'StSlp3C': ('special', 'StSlp3C', (357, 358)),
                  'StSlp3CInc': ('byte', 360),
                  'StSlp3CSp': ('byte', 362),
                  'StSlp3H': ('special', 'StSlp3H', (359, 358)),
                  'StSlp3HInc': ('byte', 361),
                  'StSlp3HSp': ('byte', 363),
                  'StSlp4C': ('special', 'StSlp4C', (364, 365)),
                  'StSlp4CInc': ('byte', 367),
                  'StSlp4CSp': ('byte', 369),
                  'StSlp4H': ('special', 'StSlp4H', (366, 365)),
                  'StSlp4HInc': ('byte', 368),
                  'StSlp4HSp': ('byte', 370),
                  'LigSen': ('choice', 51, {1: (247, 8), 0: (247, 0)})}}

_BASE_FIELDS = ('ACStupPos',
 'Add0.5',
 'Air',
 'AirQ',
 'Antifreeze',
 'AssHt',
 'AutoClean',
 'Blo',
 'CoolNoise',
 'Defrost',
 'Dfltr',
 'Dmod',
 'DnPLLRSwing',
 'DnPRLRSwing',
 'DnPUDSwing',
 'DsplySt',
 'DwatFul',
 'Dwet',
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
 'FavorMode',
 'FbidBloPer',
 'HandCtl',
 'Health',
 'HeatCoolType',
 'HeatNoise',
 'HumSen',
 'ImageRecovery',
 'ImgUpdateCol',
 'ImgUpdateSta',
 'ImgUpdateRes',
 'ImgVerSta',
 'Lig',
 'MicroSen',
 'Mod',
 'NobodySave',
 'NoiseSet',
 'PM2P5',
 'PMVComfort',
 'Pow',
 'Purify',
 'Quiet',
 'ReplaceHEPA',
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
 'Slp1L7',
 'Slp1L8',
 'SlpMod',
 'SmartWind',
 'StHt',
 'SvSt',
 'SwhSlp',
 'SwhSw',
 'SwhWifi',
 'SwhWifiRes',
 'SwingLfRig',
 'SwUpDn',
 'TemRec',
 'TemSen',
 'TemUn',
 'Tur',
 'UDFanPort',
 'UnmanedOffTime',
 'UnmanedShutDown',
 'VocCtl',
 'VocIdiom',
 'VocRole',
 'VocUpdateCol',
 'VocUpdateSta',
 'VocUpdateRes',
 'VocVerSta',
 'WdSpd',
 'Wet',
 'ElcAllKwhClr',
 'ElcEn',
 'CZLJC',
 'NewTimer',
 'NewTimerSet')

_FIELD_DIFFS = {'362001000835': (('CZLJC', 'NewTimer', 'NewTimerSet'), ()),
 '362001060200': ((), ()),
 '362001060297': (('ElcAllKwhClr', 'ElcEn', 'CZLJC', 'NewTimer', 'NewTimerSet'), ()),
 '362001060498': (('NewTimer', 'NewTimerSet'), ()),
 '362001060499': ((),
                  ('Buzzer_ON_OFF',
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
                   'LigSen'))}

class MediaTek:
    def __init__(self, code):
        self.code = code
        self.frame = 0x13 if code == "362001060297" else 0x1d
        self.getters = {**_GETTERS, **_GET_OVERRIDES.get(code, {})}
        self.setters = {**_SETTERS, **_SET_OVERRIDES.get(code, {})}
        omitted, extra = _FIELD_DIFFS[code]
        self.fields = frozenset(name for name in (*_BASE_FIELDS, *extra) if name not in omitted)

    @staticmethod
    def _bits(cache, offset, keep, value):
        cache[offset] = (cache[offset] & keep | value) & 255

    def _read(self, cache, name):
        descriptor = self.getters[name]
        if descriptor[0] == "const":
            return descriptor[1]
        if descriptor[0] == "byte":
            _, offset, mask, shift = descriptor
            return (cache[offset] & mask) >> shift
        offsets = descriptor[2]
        start = self.frame
        if name == "SetTem":
            return (cache[offsets[0]] >> 4) + 16
        if name == "TemSen":
            return max(0, min(cache[offsets[0]] - 40, 50))
        if name == "Dwet":
            return max(0, (cache[start + 23] & 15) - 1)
        if name in ("Lig", "SwhWifi"):
            return (cache[start + (10 if name == "Lig" else 11)] >> 1) & 1
        if name in ("AssHt", "Blo"):
            mode = (cache[start + 8] >> 4) & 7
            if name == "AssHt":
                if mode == 1:
                    return 0
                # Chosen platform9 branch, not a persisted physical-device inference.
                if self.code == "362001060499" and cache[start + 15] & 128:
                    return 2
                return ((cache[start + 10] ^ 8) >> 3) & 1
            return 0 if mode == 4 else (cache[start + 10] >> 3) & 1
        if name == "SlpMod":
            first = bool(cache[start + 8] & 8)
            second = bool(cache[start + 20] & 16)
            third = bool(cache[start + 20] & 128)
            return {(False, False, False): 0, (True, False, False): 1,
                    (False, True, False): 2, (True, True, False): 3,
                    (True, False, True): 4}.get((first, second, third), 0)
        if name == "SwhSlp":
            return int(bool(cache[start + 8] & 8 or cache[start + 20] & 144))
        if name == "SwingLfRig":
            value = cache[offsets[0]] & 15
            return {12: 7, 13: 8}.get(value, value)
        if name.startswith("Slp1"):
            slot = int(name[-1]) - 1
            offset = start + (21, 21, 24, 24, 25, 25, 26, 26)[slot]
            nibble = (cache[offset] >> (4 if slot % 2 == 0 else 0)) & 15
            value = min(nibble, 14) * 10 + 160
            return value >> 8 if name[4] == "H" else value & 255
        if name.startswith("StSlp"):
            shared, other = offsets
            if name.endswith("C"):
                return (cache[shared] & 15) | cache[other] << 4
            return ((cache[shared] >> 4) << 8) | cache[other]
        if name == "ElcEn":
            # Synthetic fitted-energy/runtime-enable inputs are both off.
            return 0
        raise ValueError("unknown MediaTek getter descriptor")

    def _write(self, cache, name, value):
        descriptor = self.setters[name]
        if descriptor[0] == "noop":
            return
        if descriptor[0] == "byte":
            cache[descriptor[1]] = value & 255
            return
        if descriptor[0] == "choice":
            choice = descriptor[2].get(value)
            if choice is not None:
                self._bits(cache, descriptor[1], *choice)
            return
        offsets = descriptor[2]
        start = self.frame
        raw = value & 255
        direct = {
            "ACStupPos": (15, 255, 4), "Air": (207, 3, 4),
            "DnPUDSwing": (240, 15, 0), "HandCtl": (193, 255, 1),
            "SetTem": (15, 255, 4), "SwUpDn": (15, 255, 4),
            "VocIdiom": (135, 255, 3), "Wet": (143, 7, 4),
            "ElcAllKwhClr": (247, 1, 3), "CZLJC": (127, 255, 7),
            "AntiDirectBlow": (127, 255, 7), "SmartSlpMod": (143, 7, 4),
            "StHt": (191, 1, 6), "Buzzer_ON_OFF": (254, 1, 0),
        }
        if name in direct:
            keep, mask, shift = direct[name]
            self._bits(cache, offsets[0], keep, (value & mask) << shift)
            return
        enums = {"Dmod": (7, 240, 0), "Dwet": (14, 240, 0),
                 "Emod": (5, 143, 4), "Quiet": (2, 243, 2),
                 "SmartWind": (5, 31, 5), "UDFanPort": (3, 243, 2),
                 "UnmanedOffTime": (3, 231, 3), "VocRole": (3, 159, 5)}
        if name in enums:
            upper, keep, shift = enums[name]
            offset = start + 23 if name == "Emod" else offsets[0]
            if value <= upper:
                self._bits(cache, offset, keep, (value + (name == "Dwet")) << shift)
            return
        if name == "DsplySt":
            self._bits(cache, offsets[0], 207, (value if value in (0, 2, 3) else 1) << 4)
        elif name in ("DnPLLRSwing", "DnPRLRSwing", "SwingLfRig"):
            allowed = value <= (8 if name == "SwingLfRig" else 6)
            if name != "SwingLfRig":
                allowed = allowed or value in (12, 13)
            if allowed:
                encoded = {7: 12, 8: 13}.get(value, value) if name == "SwingLfRig" else value
                high = name == "DnPLLRSwing"
                self._bits(cache, offsets[0], 15 if high else 240, encoded << (4 if high else 0))
        elif name == "Mod":
            if value <= 4:
                self._bits(cache, start + 8, 143, value << 4)
                if value != 1:
                    self._bits(cache, start + 15, 191, 0)
        elif name == "AssHt":
            if value in (0, 1, 2):
                self._bits(cache, start + 10, 247, 8 if value == 0 else 0)
                self._bits(cache, start + 15, 127, 128 if value == 2 else 0)
        elif name == "TemSen":
            signed = value if value < 0x80000000 else value - 0x100000000
            cache[offsets[0]] = (min(signed, 50) + 40) & 255
        elif name == "SlpMod":
            if value <= 4:
                self._bits(cache, start + 8, 247, 8 if value in (1, 3, 4) else 0)
                self._bits(cache, start + 20, 111, 128 if value == 4 else (16 if value in (2, 3) else 0))
        elif name in ("SwhWifi", "SvSt", "SwhSlp"):
            if value in (0, 1):
                offset, bit = {"SwhWifi": (start + 11, 2), "SvSt": (start + 15, 64),
                               "SwhSlp": (start + 8, 8)}[name]
                self._bits(cache, offset, 255 ^ bit, bit if value else 0)
        elif name == "WdSpd":
            signed = value if value < 0x80000000 else value - 0x100000000
            if signed >= 0:
                coarse = 0 if value == 0 else (1 if value <= 2 else (2 if value <= 4 else 3))
                self._bits(cache, start + 8, 252, coarse)
            self._bits(cache, start + 22, 248, raw)
        elif name == "NewTimerSet":
            self._bits(cache, offsets[-1], 253, (value & 1) << 1)
        elif name.startswith("Slp1L"):
            slot = int(name[-1]) - 1
            cache[start + 50 + slot * 2] = raw
            cache[offsets[-1]] = raw
        elif name.startswith("Slp1H"):
            slot = int(name[-1]) - 1
            staging = start + 50 + slot * 2
            cache[staging + 1] = raw
            encoded = ((cache[staging] + raw * 256) // 10) & 255
            packed = start + (21, 21, 24, 24, 25, 25, 26, 26)[slot]
            if slot % 2 == 0:
                self._bits(cache, packed, 15, encoded << 4)
            else:
                self._bits(cache, packed, 240, (encoded - 16) & 255)
            if self.code == "362001060499":
                cache[offsets[-1]] = raw
        elif name.startswith("StSlp"):
            other, shared = offsets
            if name.endswith("C"):
                cache[other] = (value >> 4) & 255
                self._bits(cache, shared, 240, value & 15)
            else:
                cache[other] = raw
                self._bits(cache, shared, 15, ((value >> 8) << 4) & 255)
        else:
            raise ValueError("unknown MediaTek setter descriptor")

    def validate_state(self, state):
        for name, value in state.items():
            if (name not in self.fields or self.setters[name][0] == "noop"
                    or type(value) is not int or not 0 <= value <= 0xffffffff):
                raise ValueError("MediaTek state requires modeled uint32 controls")

    def _cache(self, device):
        if "_board" not in device.state:
            cache = [0] * 0x800
            self._write(cache, "SetTem", 24)
            self._write(cache, "Lig", 1)
            self._write(cache, "TemSen", 26)
            for name, value in device.state.items():
                if name in self.fields:
                    self._write(cache, name, value)
            device.state["_board"] = cache
            device.state["_metadata"] = {"name": device.name, "host": "", "lock": 0,
                                         "AutoUpdate": 0, "time": "2026-01-01 00:00:00",
                                         "_clock_origin": device.last_step}
        return device.state["_board"]

    def thermal_target(self, device):
        if device.mid not in ("10001", "10002", "10014", "10015", "10016", "10017", "11000", "11001", "11002", "11010"):
            return None
        cache = self._cache(device)
        target, mode = self._read(cache, "SetTem"), self._read(cache, "Mod")
        if not self._read(cache, "Pow") or mode == 3:
            return "idle", target
        if mode == 4:
            return "heat", 8 if self._read(cache, "StHt") else target
        return ("auto" if mode == 0 else "cool"), target

    def encode_room(self, device):
        cache = self._cache(device)
        if device.room_c is None:
            return
        offset = self.getters["TemSen"][2][0]
        cache[offset] = max(40, min(90, floor(device.room_c) + 40))

    def _get(self, device, cache, metadata, name):
        if name == "time":
            try:
                clock = datetime.strptime(metadata["time"], "%Y-%m-%d %H:%M:%S")
                clock += timedelta(seconds=int(device.last_step - metadata["_clock_origin"]))
                return (clock.strftime("%Y-%m-%d %H:%M:%S"),)
            except (ValueError, OverflowError) as exc:
                raise InvalidPacket("MediaTek synthetic calendar out of range") from exc
        if name in self.fields:
            return (self._read(cache, name),)
        if name in metadata and not name.startswith("_"):
            return (metadata[name],)
        return {"hid": (device.profile.hid,), "mid": (device.mid,), "bc": ("3030303030",),
                "DevID": ("",), "MafIdf": (0,), "AppTimer": (0,), "MidType": ("",),
                "MOta": ()}.get(name)

    @staticmethod
    def _columns(inner):
        names = inner.get("cols", inner.get("opt"))
        if (not isinstance(names, list) or len(names) > 64
                or any(not isinstance(name, str) or not name or "\0" in name for name in names)
                or sum(len(name.encode()) + 1 for name in names) > 512):
            raise InvalidPacket("invalid MediaTek property array")
        return names

    def _reply(self, outer, inner, key):
        reply = Reply({"t": "pack", "i": outer["i"], "uid": outer.get("uid", 0),
                       "cid": outer.get("tcid", ""), "tcid": outer.get("cid", "")}, inner, key, CODEC)
        if len(encode_reply(reply)) >= (0x7b4 if self.code == "362001060499" else 0x5b4):
            raise InvalidPacket("MediaTek reply exceeds native buffer")
        return reply

    def advertise(self, device, outer):
        if outer.get("t") != "scan":
            return []
        self._cache(device)
        inner = {"t": "dev", "cid": "", "bc": "00000", "brand": "", "catalog": "",
                 "mac": device.mac, "mid": device.mid, "model": "", "name": device.state["_metadata"]["name"],
                 "lock": device.state["_metadata"]["lock"], "series": "", "vender": "", "ver": "V3.0.0"}
        return [self._reply({"i": 1, "uid": 0}, inner, GENERIC_KEY)]

    def handle(self, device, outer):
        if (outer.get("t") != "pack" or outer.get("tcid") != device.mac
                or type(outer.get("i")) is not int or outer["i"] not in (0, 1)
                or not isinstance(outer.get("cid", ""), str)
                or type(outer.get("uid", 0)) is not int
                or not -(1 << 31) <= outer.get("uid", 0) < (1 << 31)):
            raise InvalidPacket("invalid MediaTek target or envelope")
        key = GENERIC_KEY if outer["i"] else device.key
        inner = decode_pack(outer, key, CODEC)
        if "mac" in inner and inner["mac"] != device.mac:
            raise InvalidPacket("conflicting MediaTek identity")
        operation = inner.get("t")
        if operation == "bind":
            return [self._reply(outer, {"r": 200, "t": "bindok", "mac": device.mac,
                                       "key": device.key.decode("ascii")}, key)]
        if operation not in ("status", "cmd"):
            return []
        names = self._columns(inner)
        cache = self._cache(device)
        metadata = device.state["_metadata"]
        if operation == "status":
            self.encode_room(device)
            cols, values = [], []
            for name in names:
                result = self._get(device, cache, metadata, name)
                if result is not None:
                    cols.append(name)
                    values.extend(result)
            return [self._reply(outer, {"t": "dat", "uid": outer.get("uid", 0), "mac": device.mac,
                                       "cid": device.mac, "dat": values, "cols": cols, "r": 200}, key)]
        values = inner.get("p")
        if ("cols" in inner or not names or not isinstance(values, list) or len(names) != len(values)):
            raise InvalidPacket("MediaTek command requires equally sized opt/p")
        for name, value in zip(names, values):
            if name in self.fields:
                if type(value) is not int or not -(1 << 31) <= value <= 0xffffffff:
                    raise InvalidPacket("MediaTek raw control requires integer32")
            elif name in ("name", "host", "time"):
                if not isinstance(value, str) or "\0" in value or len(value.encode()) > 31:
                    raise InvalidPacket("invalid MediaTek metadata string")
                if name == "time":
                    try:
                        datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
                    except ValueError as exc:
                        raise InvalidPacket("invalid MediaTek calendar") from exc
            elif name in ("lock", "AutoUpdate"):
                if type(value) is not int or not 0 <= value <= 255:
                    raise InvalidPacket("invalid MediaTek metadata integer")
            else:
                raise InvalidPacket("unknown MediaTek command property")
        # Safe model: validate/preflight the whole batch before advancing old controls.
        staged = list(cache)
        staged_metadata = dict(metadata)
        for name, value in zip(names, values):
            if name in self.fields:
                self._write(staged, name, value & 0xffffffff)
            else:
                staged_metadata[name] = value
                if name == "time":
                    staged_metadata["_clock_origin"] = device.last_step
        effective = [self._get(device, staged, staged_metadata, name)[0] for name in names]
        reply = self._reply(outer, {"t": "res", "mac": device.mac, "val": effective,
                                    "p": effective, "opt": list(names), "r": 200}, key)
        device.advance(monotonic())
        device.state["_board"] = staged
        device.state["_metadata"] = staged_metadata
        return [reply]


class Broadlink(MediaTek):
    """Exact RTL8710 V18 callbacks with chosen Gree platform9 cache backing.

    The late MTK layout is reused after per-callback source reconciliation;
    identity, envelope and MID-dependent getters remain source-specific.
    Factory/NVS display strings are synthetic, not recovered installed values.
    """

    def __init__(self):
        super().__init__("362001060499")

    @staticmethod
    def _metadata_text(values):
        encoded = json.dumps(values, ensure_ascii=False, separators=(",", ":"))
        buffer, offsets = [], []
        quoted = escaped = False
        for index, char in enumerate(encoded[1:], 1):
            if char == "]":
                break
            if char == "\\" and encoded[index + 1] == '"':
                escaped = True
            elif char == '"':
                if escaped:
                    escaped = False
                    buffer.append(char)
                elif quoted:
                    if buffer:
                        buffer.append("\0")
                    quoted = False
                else:
                    offsets.append(len(buffer))
                    quoted = True
            elif char not in (",", " "):
                buffer.append(char)
        if not offsets:
            return None
        return "".join(buffer[offsets[0]:]).split("\0", 1)[0]

    def _read(self, cache, name):
        if name == "TemSen":
            raw = cache[399]
            return 0 if raw < 40 else min(raw, 90)
        return super()._read(cache, name)

    def _get(self, device, cache, metadata, name):
        if name == "WdSpd" and device.mid == "13000":
            return ((0, 1, 3, 5)[cache[37] & 3],)
        if name in ("ver", "vender", "rssi"):
            return ({"ver": "V3.0.0", "vender": "", "rssi": 0}[name],)
        if name == "ReportClientID":
            return None
        return super()._get(device, cache, metadata, name)

    def advertise(self, device, outer):
        if outer.get("t") != "scan":
            return []
        self._cache(device)
        metadata = device.state["_metadata"]
        inner = {"t": "dev", "cid": "", "bc": "00000", "brand": "",
                 "catalog": "", "mac": device.mac, "mid": device.mid,
                 "model": "", "name": metadata["name"], "lock": metadata["lock"],
                 "series": "", "vender": "", "ver": "V3.0.0"}
        return [self._reply({"i": 1, "uid": 0}, inner, GENERIC_KEY)]

    def handle(self, device, outer):
        if (outer.get("t") != "pack" or outer.get("tcid") != device.mac
                or type(outer.get("i")) is not int or outer["i"] not in (0, 1)
                or not isinstance(outer.get("cid", ""), str)
                or "\0" in outer.get("cid", "")
                or len(outer.get("cid", "").encode()) >= 64
                or type(outer.get("uid", 0)) is not int
                or not -(1 << 31) <= outer.get("uid", 0) < (1 << 31)):
            raise InvalidPacket("invalid Broadlink target or envelope")
        key = GENERIC_KEY if outer["i"] else device.key
        inner = decode_pack(outer, key, CODEC)
        if "mac" in inner and inner["mac"] != device.mac:
            raise InvalidPacket("conflicting Broadlink identity")
        operation = inner.get("t")
        if operation == "bind":
            return [self._reply(outer, {"r": 200, "t": "bindok", "mac": device.mac,
                                       "key": device.key.decode("ascii")}, key)]
        if operation == "subDev":
            start = inner.get("i")
            if type(start) is not int or not -(1 << 31) <= start < (1 << 31):
                raise InvalidPacket("Broadlink self enumeration requires integer i")
            record = {"mac": device.mac, "mid": device.mid, "name": "GreeHot",
                      "model": "gree", "lock": 0}
            return [self._reply(outer, {"t": "subList", "r": 200, "i": start,
                                       "c": 1, "list": [record] if start == 0 else []}, key)]
        if operation not in ("status", "cmd"):
            return []
        names = self._columns(inner)
        cache = self._cache(device)
        metadata = device.state["_metadata"]
        if operation == "status":
            self.encode_room(device)
            columns, values = [], []
            for name in names:
                result = self._get(device, cache, metadata, name)
                if result is not None:
                    columns.append(name)
                    values.extend(result)
            return [self._reply(outer, {"t": "dat", "uid": outer.get("uid", 0),
                                       "mac": device.mac, "cid": device.mac,
                                       "r": 200, "cols": columns, "dat": values}, key)]
        values = inner.get("p")
        if ("cols" in inner or not names or not isinstance(values, list)
                or len(names) != len(values)):
            raise InvalidPacket("Broadlink command requires equally sized opt/p")
        for name, value in zip(names, values):
            if name in self.fields or name in ("lock", "AutoUpdate"):
                if type(value) is not int or not -(1 << 31) <= value <= 0xffffffff:
                    raise InvalidPacket("Broadlink raw control requires integer32")
            elif name in ("name", "host", "time", "ReportClientID"):
                if not isinstance(value, str) or "\0" in value or len(value.encode()) > 31:
                    raise InvalidPacket("invalid Broadlink metadata string")
            elif name == "mid":
                if type(value) is not int and not isinstance(value, str):
                    raise InvalidPacket("invalid Broadlink ignored MID value")
                if isinstance(value, str) and ("\0" in value or len(value.encode()) > 31):
                    raise InvalidPacket("invalid Broadlink ignored MID string")
            else:
                raise InvalidPacket("unknown Broadlink command property")
        staged, staged_metadata = list(cache), dict(metadata)
        # Native metadata callbacks parse the complete p array, not its matching
        # member. Preserve the first-string / final-token behavior explicitly.
        first = values[0]
        text = self._metadata_text(values)
        if any(name in ("name", "host") for name in names) and len(text.encode()) > 31:
            raise InvalidPacket("Broadlink first metadata value exceeds its cache")
        if "AutoUpdate" in names and type(first) is not int:
            raise InvalidPacket("Broadlink AutoUpdate requires a numeric first p item")
        lock_token = json.dumps(values, ensure_ascii=False, separators=(",", ":")).split("]", 1)[0][-1]
        for name, value in zip(names, values):
            if name in self.fields:
                self._write(staged, name, value & 0xffffffff)
            elif name in ("name", "host"):
                staged_metadata[name] = text
            elif name == "lock":
                staged_metadata[name] = int(lock_token != "0")
            elif name == "AutoUpdate":
                staged_metadata[name] = first & 255
            elif name == "time":
                try:
                    calendar = text[:10] + " " + text[10:]
                    datetime.strptime(calendar, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    pass  # Native malformed calendar parsing leaves RTC unchanged.
                else:
                    staged_metadata[name] = calendar
                    staged_metadata["_clock_origin"] = device.last_step
            elif name == "ReportClientID":
                staged_metadata["_report_client_id"] = value
        effective = []
        for name in names:
            result = self._get(device, staged, staged_metadata, name)
            if result is not None:
                effective.extend(result)
        reply = self._reply(outer, {"t": "res", "mac": device.mac, "r": 200,
                                    "opt": list(names), "p": effective, "val": effective}, key)
        device.advance(monotonic())
        device.state["_board"], device.state["_metadata"] = staged, staged_metadata
        return [reply]


PROFILES = (
    Profile('sim-cs532ax-v3', ('10001', '10002', '11000', '11001', '11002', '13800', '13801', '11f00', '11f01', '11f02'),
            '362001000835+U-CS532AX(MTK)V3.bin',
            'aaa27bd9d043dd7395933e91b4fe488504ac809291963ab2a2205ecb7e685de7', {}, MediaTek('362001000835'),
            max_request_bytes=0x5b4),
    Profile('sim-cs849a-v10', ('10001', '10002', '11000', '11001', '11002', '13800', '13801', '11f00', '11f01', '11f02'),
            '362001060200+U-CS849AV10.bin',
            '8541fe62f6b23dc93014f5d4c6aad614c6fb0a8704781f1698e645a2eb4249ef', {}, MediaTek('362001060200'),
            max_request_bytes=0x5b4),
    Profile('sim-cs532af-v4', ('10001', '10002', '11000', '11001', '11002', '13800', '13801', '11f00', '11f01', '11f02'),
            '362001060297+U-CS532AF(MTK)V4.bin',
            '41d9fea87b8bcbd278f7ebca20fec3b87ded84244399439f836674b230f5c23e', {}, MediaTek('362001060297'),
            max_request_bytes=0x5b4),
    Profile('sim-cs845b-v6', ('10001', '10002', '11000', '11001', '11002', '11010', '11f00', '11f01', '11f02', '11f03', '13800', '13801'),
            '362001060498+U-CS845B(MTK2)V6.bin',
            'edb56a3e41eeaba2ca3ea1bca7823d9bfec3037df2b36ca80cce6d924b4182f1', {}, MediaTek('362001060498'),
            max_request_bytes=0x5b4),
    Profile('sim-cs532bh-v5', ('10001', '10002', '10014', '10015', '10016', '10017', '11000', '11001', '11002', '11010', '11f00', '11f01', '11f02', '11f03', '13800', '13801'),
            '362001060499+U-CS532BH(MTK2)V5.bin',
            '69d9c36f87e16629ed1af671a19f58c6f0da6a2b91785eb97b2962d66231d561', {}, MediaTek('362001060499'),
            max_request_bytes=0x7b4),
)

PROFILES += (
    Profile("sim-bl3332-jd-v18",
            ("10001", "10002", "11000", "11001", "11002", "13000",
             "13800", "13801", "11f00", "11f01", "11f02"),
            "362001061383+U-BL3332_JDV18.bin",
            "011996a47ccfcb08370faf09df4c286f18488fd3b5ff87192abfec6df3b1b1ee",
            {}, Broadlink(), max_request_bytes=0x7b4),
)
