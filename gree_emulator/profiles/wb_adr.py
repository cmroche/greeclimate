"""Exact WB ADR1.16 decoded type1 model, not RT13/BLE or a physical board.

The finite tuple schemas also back exact BR1.31. Raw report defaults and immediate
outbound-to-report bridging are chosen synthetic IO, never board confirmation.
Opaque runtime2/3 hex payloads are deliberately outside this semantic model.
"""

from copy import deepcopy

from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
HID = "362001069264+U-WB05ADRV1.16.bin"
SHA256 = "58f46141990b02939b909f01117a8a855a315e4be0047f6b983104b7882e9c4a"
FILTER_MIDS = ("605d", "6079", "6084", "608d", "6091", "6098", "6099", "60a0", "60a4", "60a9")
EMITTED_ALIASES = {"608d": "6079", "6091": "6079", "6099": "6079", "60a9": "6079"}
# name: (read tuple, write tuple, read width, write width, raw default,
#        LAN default, readable, writable). Defaults are synthetic, not boot data.
SCHEMAS = {'BR': {'ac': {'MIdType': (None, None, 0, 0, 0, '', True, False),
               'Pow': ('001f00', '006f00', 1, 1, 0, 0, True, True),
               'Quiet': ('00210d', '00710c', 2, 2, 1, 0, True, True),
               'Mod': ('007100', '007100', 2, 2, 1, 1, True, True),
               'SetTem': ('007300', '007300', 3, 3, 240, 24, True, True),
               'SetDeciTem': ('007300', '007300', 3, 3, 0, 0, True, True),
               'WdSpd': ('007101', '007101', 2, 2, 1, 0, True, True),
               'Tur': ('006f01', '006f01', 1, 1, 0, 0, True, True),
               'Air': ('001f20', '006f16', 1, 1, 0, 0, True, True),
               'Blo': ('001f1e', '006f15', 1, 1, 0, 0, True, True),
               'SvSt': ('001f06', '006f02', 1, 1, 0, 0, True, True),
               'SwhSlp': ('00210f', '00710d', 2, 2, 1, 0, True, True),
               'MasSub': ('001f01', None, 1, 0, 0, 0, True, False),
               'MasIDUMod': (None, None, 0, 0, 0, 0, True, False),
               'CoolSvStTemMin': ('007302', '007302', 3, 3, 0, 0, True, True),
               'HeatSvStTemMax': ('007304', '007304', 3, 3, 0, 0, True, True),
               'HumiSvStTemMin': ('007306', '007306', 3, 3, 0, 0, True, True),
               'GetEr': ('001e00', None, 1, 0, 0, 0, True, False),
               'AllErr': ('001e00', None, 1, 0, 0, 0, True, False),
               'Heat3DSvStTemMax': ('007308', '007308', 3, 3, 0, 0, True, True),
               'Heat2SvStTemMax': ('00730a', '00730a', 3, 3, 0, 0, True, True),
               'AutoClean': ('0871b5', '0871b5', 2, 2, 103, 0, True, True),
               'CleanState': ('081cc8', None, 1, 0, 0, 0, True, False),
               'CleanTime': ('0820df', None, 2, 0, 0, 0, True, False),
               'GoOut': ('001f1b', '006f10', 1, 1, 0, 0, True, True),
               'AidHeat': ('001f24', '006f18', 1, 1, 0, 0, True, True),
               'Add0.1': ('007300', None, 3, 0, 0, 0, True, False),
               'Add0.5': ('007300', None, 3, 0, 0, 0, True, False),
               'SysSta': ('082174', None, 2, 0, 0, 0, True, False),
               'SetCoolHumi': ('002106', '007115', 2, 2, 0, 0, True, True),
               'HumiEnable': ('006d02', None, 1, 0, 0, 0, True, False),
               'TemBody': ('006d01', None, 1, 0, 0, 0, True, False),
               'SwUpDn': ('002102', '007102', 2, 2, 1, 0, True, True),
               'SwingLfRig': ('002103', '007103', 2, 2, 1, 0, True, True),
               'LowDeHumi': ('001f25', '006f17', 1, 1, 0, 0, True, True),
               'ErrType1': ('001e03', None, 1, 0, 0, 0, True, False),
               'ErrType2': ('002208', None, 1, 0, 0, 0, True, False),
               'ExtraMod': ('002111', None, 2, 0, 0, 0, True, False),
               'FIndoorEn': ('001c29', None, 1, 0, 0, 0, True, False),
               'IDURunMod': ('002100', None, 2, 0, 0, 0, True, False),
               'TotalEle': ('081410', None, 3, 0, 0, 0, True, False),
               'ElcEn': (None, None, 0, 0, 0, 1, True, False),
               'IDUID': ('001004', None, 2, 0, 0, '', True, False),
               'ODUID': ('081004', None, 2, 0, 0, '', True, False),
               'IDUBarcode': ('00120d', None, 2, 0, 0, 'SIM', True, False),
               'ODUBarcode': ('08120d', None, 2, 0, 0, 'SIM', True, False),
               'InTem': ('002000', None, 2, 0, 80, 20, True, False),
               'InTemEn': (None, None, 0, 0, 0, 1, True, False),
               'InHumi': ('002009', None, 2, 0, 60, 0, True, False),
               'InHumiEn': ('00111f', None, 2, 0, 0, 0, True, False),
               'UseTime': ('08325e', None, 3, 0, 0, 0, True, False),
               'UseTimeEn': (None, None, 0, 0, 0, 1, True, False),
               'IDURatedCap': ('00100e', None, 2, 0, 0, 0, True, False),
               'FBoxBind': ('001c4d', None, 1, 0, 0, 0, True, False)},
        'filter': {'MIdType': (None, None, 0, 0, 0, '', True, False),
                   'WdSpd': ('007d01', '007d01', 2, 2, 1, 0, True, True),
                   'Tur': ('007b01', '007b01', 1, 1, 0, 0, True, True),
                   'ModS': ('004100', None, 2, 0, 0, 0, True, False),
                   'FanMod': ('004101', '007d00', 2, 2, 0, 0, True, True),
                   'RunMod': ('004110', '007d11', 2, 2, 0, 0, True, True),
                   'Inloop': ('003f18', '007b0f', 1, 1, 0, 0, True, True),
                   'IDUAirQu': ('007d02', '007d02', 2, 2, 0, 0, True, True),
                   'ODUViti': ('004104', '007d03', 2, 2, 0, 0, True, True),
                   'PctCle': ('003f0f', None, 1, 0, 0, 0, True, False),
                   'PctRe': ('003f10', None, 1, 0, 0, 0, True, False),
                   'IFDtiGr': ('004013', None, 2, 0, 0, 0, True, False),
                   'InVitiGr': ('004005', None, 2, 0, 0, 0, True, False),
                   'InVitiGrCg': ('004012', None, 2, 0, 0, 0, True, False),
                   'VitiGr': ('004006', None, 2, 0, 0, 0, True, False),
                   'ErrType': ('003d05', None, 1, 0, 0, 0, True, False),
                   'GasQ': ('00410a', None, 2, 0, 1, 1, True, False),
                   'GasN': (None, None, 0, 0, 0, None, False, False),
                   'TemSor': ('004007', None, 2, 0, 0, [0], True, False),
                   'HumSor': ('00400c', None, 2, 0, 0, [0], True, False),
                   'AirQu': ('004105', None, 2, 0, 0, [0], True, False),
                   'PM2P5': ('004d06', None, 3, 0, 0, [0], True, False),
                   'VOC': ('004d10', None, 3, 0, 0, [0], True, False),
                   'CO2': ('004d1a', None, 3, 0, 0, [0], True, False),
                   'SorErr': ('003e00', None, 1, 0, 0, [0], True, False),
                   'CommErr': ('003e19', None, 1, 0, 0, [0], True, False),
                   'GasAvail': ('00410b', '007d09', 2, 2, 0, [0], True, True),
                   'GasLED': ('00410c', '007d0b', 2, 2, 0, [0], True, True),
                   'GasMod': ('00410d', '007d0c', 2, 2, 0, [0], True, True),
                   'GasMas': ('00410e', '007d0a', 2, 2, 0, [0], True, True),
                   'PM2P5Sta': ('00410f', '007d0d', 2, 2, 0, [0], True, True),
                   'ReportFreq': (None, None, 0, 0, 0, None, False, True),
                   'GetEr': ('003d00', None, 1, 0, 0, 0, True, False),
                   'Pow': ('003f00', '007b00', 1, 1, 0, 0, True, True),
                   'InEffClRes': (None, '007b08', 0, 1, 0, None, False, True),
                   'InEffReRes': (None, '007b09', 0, 1, 0, None, False, True),
                   'IFDClRes': (None, '007b0d', 0, 1, 0, None, False, True),
                   'EffReRes': (None, '007b0e', 0, 1, 0, None, False, True),
                   'Mod': ('007100', '007100', 2, 2, 1, 1, True, True),
                   'SetTem': ('007300', '007300', 3, 3, 240, 24, True, True),
                   'ExWdSpd': ('004111', None, 2, 0, 0, 0, True, False),
                   'TemRec': (None, None, 0, 0, 0, 0, True, False),
                   'TemUn': (None, None, 0, 0, 0, 0, True, False),
                   'TotalEle': ('081410', None, 3, 0, 0, 0, True, False),
                   'ElcEn': (None, None, 0, 0, 0, 1, True, False),
                   'IDUID': ('001004', None, 2, 0, 0, '', True, False),
                   'ODUID': ('081004', None, 2, 0, 0, '', True, False),
                   'IDUBarcode': ('00120d', None, 2, 0, 0, 'SIM', True, False),
                   'ODUBarcode': ('08120d', None, 2, 0, 0, 'SIM', True, False),
                   'IDURatedCap': ('00100e', None, 2, 0, 0, 0, True, False)},
        'water_floor': {'MIdType': (None, None, 0, 0, 0, '', True, False),
                        'SetTem': ('007300', '007300', 3, 3, 240, 24, True, True),
                        'GetEr': ('001e00', None, 1, 0, 0, 0, True, False),
                        'WFConfig': ('002120', None, 2, 0, 0, 0, True, False),
                        'WPow': ('001c00', '006f00', 1, 1, 0, 0, True, True),
                        'Wstate': ('001c02', None, 1, 0, 0, 0, True, False),
                        'Wmod': ('002115', '007118', 2, 2, 0, 0, True, True),
                        'WtmrMin': ('007120', '007120', 2, 2, 0, 0, True, True),
                        'WtmrHr': ('007121', '007121', 2, 2, 0, 0, True, False),
                        'WSetTemMax': ('007310', None, 3, 0, 0, 0, True, False),
                        'Watpercent': ('002117', None, 2, 0, 0, 0, True, False),
                        'WSunEn': ('001c08', '006f1c', 1, 1, 0, 0, True, True),
                        'WAutoSetTemEn': ('001c07', '006f1e', 1, 1, 0, 0, True, True),
                        'WUTHEn': ('006f1f', '006f1f', 1, 1, 0, 0, True, True),
                        'WUTHSetTem': ('007316', '007316', 3, 3, 0, 0, True, True),
                        'WUTHCycle': ('002118', '007119', 2, 2, 0, 0, True, True),
                        'WUTHTmrMin': ('002119', '00711a', 2, 2, 0, 0, True, True),
                        'WUTHTmrHr': ('00211a', '00711b', 2, 2, 0, 0, True, False),
                        'WUTHOngoing': ('001c06', None, 1, 0, 0, 0, True, False),
                        'WFastWat': ('001c05', '006f1d', 1, 1, 0, 0, True, True),
                        'FPow': ('001c01', '006f21', 1, 1, 0, 0, True, True),
                        'Fstate': ('001c02', None, 1, 0, 0, 0, True, False),
                        'FSetTem': ('007326', '007326', 3, 3, 240, 24, True, True),
                        'FSetTemMax': ('007314', '007314', 3, 3, 0, 0, True, True),
                        'FAutoSetTemEn': ('006f23', '006f23', 1, 1, 0, 0, True, True),
                        'FFastHeat': ('001c21', '006f2f', 1, 1, 0, 0, True, True),
                        'FIndoorEn': ('001c29', None, 1, 0, 0, 0, True, False),
                        'FOutHomeEn': ('001c26', '006f30', 1, 1, 0, 0, True, True),
                        'ExtraMod': ('002111', None, 2, 0, 0, 0, True, False),
                        'WCurTem': ('002011', None, 2, 0, 0, 0, True, False),
                        'FCurTem': ('002013', None, 2, 0, 0, 0, True, False),
                        'WatTemWrap': ('001c04', None, 1, 0, 0, 0, True, False),
                        'TotalEle': ('081410', None, 3, 0, 0, 0, True, False),
                        'ElcEn': (None, None, 0, 0, 0, 1, True, False),
                        'IDUID': ('001004', None, 2, 0, 0, '', True, False),
                        'ODUID': ('081004', None, 2, 0, 0, '', True, False),
                        'IDUBarcode': ('00120d', None, 2, 0, 0, 'SIM', True, False),
                        'ODUBarcode': ('08120d', None, 2, 0, 0, 'SIM', True, False),
                        'WIDURatedCap': ('00100e', None, 2, 0, 0, 0, True, False),
                        'FIDURatedCap': ('00101b', None, 2, 0, 0, 0, True, False),
                        'AISvst': ('0821eb', '0871b5', 2, 2, 0, 0, True, True),
                        'ElecPrice': (None, '7e1830', 0, 2, 0, None, False, True)},
        'energy': {'MIdType': ('005962', None, 3, 0, 0, '', True, False),
                   'PvTotEngy': ('005962', None, 3, 0, 0, 0, True, False),
                   'NewGridTotEngy': ('005880', None, 3, 0, 0, 0, True, False),
                   'OldGridTotEngy': (None, None, 0, 0, 0, 0, True, False),
                   'PVGenedPwr': ('00585a', None, 3, 0, 0, 0, True, False),
                   'PSSGoCPwr': ('005858', None, 3, 0, 32768, 0, True, False),
                   'TotalEle': ('081410', None, 3, 0, 0, 0, True, False),
                   'ElcEn': (None, None, 0, 0, 0, 1, True, False),
                   'CalMeth': (None, None, 0, 0, 0, 1, True, False)}},
 'ADR': {'ac': {'MIdType': (None, None, 0, 0, 0, '', True, False),
                'Pow': ('001f00', '006f00', 1, 1, 0, 0, True, True),
                'Quiet': ('00210d', '00710c', 2, 2, 1, 0, True, True),
                'Mod': ('007100', '007100', 2, 2, 1, 1, True, True),
                'SetTem': ('007300', '007300', 3, 3, 240, 24, True, True),
                'SetDeciTem': ('007300', '007300', 3, 3, 0, 0, True, True),
                'WdSpd': ('007101', '007101', 2, 2, 1, 0, True, True),
                'Tur': ('006f01', '006f01', 1, 1, 0, 0, True, True),
                'Air': ('001f20', '006f16', 1, 1, 0, 0, True, True),
                'Blo': ('001f1e', '006f15', 1, 1, 0, 0, True, True),
                'SvSt': ('001f06', '006f02', 1, 1, 0, 0, True, True),
                'SwhSlp': ('00210f', '00710d', 2, 2, 1, 0, True, True),
                'MasSub': ('001f01', None, 1, 0, 0, 0, True, False),
                'MasIDUMod': (None, None, 0, 0, 0, 0, True, False),
                'CoolSvStTemMin': ('007302', '007302', 3, 3, 0, 0, True, True),
                'HeatSvStTemMax': ('007304', '007304', 3, 3, 0, 0, True, True),
                'HumiSvStTemMin': ('007306', '007306', 3, 3, 0, 0, True, True),
                'GetEr': ('001e00', None, 1, 0, 0, 0, True, False),
                'AllErr': ('001e00', None, 1, 0, 0, 0, True, False),
                'Heat3DSvStTemMax': ('007308', '007308', 3, 3, 0, 0, True, True),
                'Heat2SvStTemMax': ('00730a', '00730a', 3, 3, 0, 0, True, True),
                'AutoClean': ('0871b5', '0871b5', 2, 2, 103, 0, True, True),
                'CleanState': ('081cc8', None, 1, 0, 0, 0, True, False),
                'CleanTime': ('0820df', None, 2, 0, 0, 0, True, False),
                'GoOut': ('001f1b', '006f10', 1, 1, 0, 0, True, True),
                'AidHeat': ('001f24', '006f18', 1, 1, 0, 0, True, True),
                'Add0.1': ('007300', None, 3, 0, 0, 0, True, False),
                'Add0.5': ('007300', None, 3, 0, 0, 0, True, False),
                'SysSta': ('082174', None, 2, 0, 0, 0, True, False),
                'SetCoolHumi': ('002106', '007115', 2, 2, 0, 0, True, True),
                'HumiEnable': ('006d02', None, 1, 0, 0, 0, True, False),
                'TemBody': ('006d01', None, 1, 0, 0, 0, True, False),
                'SwUpDn': ('002102', '007102', 2, 2, 1, 0, True, True),
                'SwingLfRig': ('002103', '007103', 2, 2, 1, 0, True, True),
                'LowDeHumi': ('001f25', '006f17', 1, 1, 0, 0, True, True),
                'ErrType1': ('001e03', None, 1, 0, 0, 0, True, False),
                'ErrType2': ('002208', None, 1, 0, 0, 0, True, False),
                'ExtraMod': ('002111', None, 2, 0, 0, 0, True, False),
                'FIndoorEn': ('001c29', None, 1, 0, 0, 0, True, False)},
         'filter': {'MIdType': (None, None, 0, 0, 0, '', True, False),
                    'WdSpd': ('007d01', '007d01', 2, 2, 1, 0, True, True),
                    'Tur': ('007b01', '007b01', 1, 1, 0, 0, True, True),
                    'ModS': ('004100', None, 2, 0, 0, 0, True, False),
                    'FanMod': ('004101', '007d00', 2, 2, 0, 0, True, True),
                    'RunMod': ('004110', '007d11', 2, 2, 0, 0, True, True),
                    'Inloop': ('003f18', '007b0f', 1, 1, 0, 0, True, True),
                    'IDUAirQu': ('007d02', '007d02', 2, 2, 0, 0, True, True),
                    'ODUViti': ('004104', '007d03', 2, 2, 0, 0, True, True),
                    'PctCle': ('003f0f', None, 1, 0, 0, 0, True, False),
                    'PctRe': ('003f10', None, 1, 0, 0, 0, True, False),
                    'IFDtiGr': ('004013', None, 2, 0, 0, 0, True, False),
                    'InVitiGr': ('004005', None, 2, 0, 0, 0, True, False),
                    'InVitiGrCg': ('004012', None, 2, 0, 0, 0, True, False),
                    'VitiGr': ('004006', None, 2, 0, 0, 0, True, False),
                    'ErrType': ('003d05', None, 1, 0, 0, 0, True, False),
                    'GasQ': ('00410a', None, 2, 0, 1, 1, True, False),
                    'GasN': (None, None, 0, 0, 0, None, False, False),
                    'TemSor': ('004007', None, 2, 0, 0, [0], True, False),
                    'HumSor': ('00400c', None, 2, 0, 0, [0], True, False),
                    'AirQu': ('004105', None, 2, 0, 0, [0], True, False),
                    'PM2P5': ('004d06', None, 3, 0, 0, [0], True, False),
                    'VOC': ('004d10', None, 3, 0, 0, [0], True, False),
                    'CO2': ('004d1a', None, 3, 0, 0, [0], True, False),
                    'SorErr': ('003e00', None, 1, 0, 0, [0], True, False),
                    'CommErr': ('003e19', None, 1, 0, 0, [0], True, False),
                    'GasAvail': ('00410b', '007d09', 2, 2, 0, [0], True, True),
                    'GasLED': ('00410c', '007d0b', 2, 2, 0, [0], True, True),
                    'GasMod': ('00410d', '007d0c', 2, 2, 0, [0], True, True),
                    'GasMas': ('00410e', '007d0a', 2, 2, 0, [0], True, True),
                    'PM2P5Sta': ('00410f', '007d0d', 2, 2, 0, [0], True, True),
                    'ReportFreq': (None, None, 0, 0, 0, None, False, True),
                    'GetEr': ('003d00', None, 1, 0, 0, 0, True, False),
                    'Pow': ('003f00', '007b00', 1, 1, 0, 0, True, True),
                    'InEffClRes': (None, '007b08', 0, 1, 0, None, False, True),
                    'InEffReRes': (None, '007b09', 0, 1, 0, None, False, True),
                    'IFDClRes': (None, '007b0d', 0, 1, 0, None, False, True),
                    'EffReRes': (None, '007b0e', 0, 1, 0, None, False, True),
                    'Mod': ('007100', '007100', 2, 2, 1, 1, True, True),
                    'SetTem': ('007300', '007300', 3, 3, 240, 24, True, True),
                    'ExWdSpd': ('004111', None, 2, 0, 0, 0, True, False),
                    'TemRec': (None, None, 0, 0, 0, 0, True, False),
                    'TemUn': (None, None, 0, 0, 0, 0, True, False)},
         'water_floor': {'MIdType': (None, None, 0, 0, 0, '', True, False),
                         'SetTem': ('007300', '007300', 3, 3, 240, 24, True, True),
                         'GetEr': ('001e00', None, 1, 0, 0, 0, True, False),
                         'WFConfig': ('002120', None, 2, 0, 0, 0, True, False),
                         'WPow': ('001c00', '006f00', 1, 1, 0, 0, True, True),
                         'Wstate': ('001c02', None, 1, 0, 0, 0, True, False),
                         'Wmod': ('002115', '007118', 2, 2, 0, 0, True, True),
                         'WtmrMin': ('007120', '007120', 2, 2, 0, 0, True, True),
                         'WtmrHr': ('007121', '007121', 2, 2, 0, 0, True, False),
                         'WSetTemMax': ('007310', None, 3, 0, 0, 0, True, False),
                         'Watpercent': ('002117', None, 2, 0, 0, 0, True, False),
                         'WSunEn': ('001c08', '006f1c', 1, 1, 0, 0, True, True),
                         'WAutoSetTemEn': ('001c07', '006f1e', 1, 1, 0, 0, True, True),
                         'WUTHEn': ('006f1f', '006f1f', 1, 1, 0, 0, True, True),
                         'WUTHSetTem': ('007316', '007316', 3, 3, 0, 0, True, True),
                         'WUTHCycle': ('002118', '007119', 2, 2, 0, 0, True, True),
                         'WUTHTmrMin': ('002119', '00711a', 2, 2, 0, 0, True, True),
                         'WUTHTmrHr': ('00211a', '00711b', 2, 2, 0, 0, True, False),
                         'WUTHOngoing': ('001c06', None, 1, 0, 0, 0, True, False),
                         'WFastWat': ('001c05', '006f1d', 1, 1, 0, 0, True, True),
                         'FPow': ('001c01', '006f21', 1, 1, 0, 0, True, True),
                         'Fstate': ('001c02', None, 1, 0, 0, 0, True, False),
                         'FSetTem': ('007326', '007326', 3, 3, 240, 24, True, True),
                         'FSetTemMax': ('007314', '007314', 3, 3, 0, 0, True, True),
                         'FAutoSetTemEn': ('006f23', '006f23', 1, 1, 0, 0, True, True),
                         'FFastHeat': ('001c21', '006f2f', 1, 1, 0, 0, True, True),
                         'FIndoorEn': ('001c29', None, 1, 0, 0, 0, True, False),
                         'FOutHomeEn': ('001c26', '006f30', 1, 1, 0, 0, True, True),
                         'ExtraMod': ('002111', None, 2, 0, 0, 0, True, False),
                         'WCurTem': ('002011', None, 2, 0, 0, 0, True, False),
                         'FCurTem': ('002013', None, 2, 0, 0, 0, True, False),
                         'WatTemWrap': ('001c04', None, 1, 0, 0, 0, True, False)}}}

UNIT_ROWS = ((16, 0, 161), (17, 0, 166), (17, 1, 172), (18, 0, 177), (18, 1, 183), (19, 0, 188), (19, 1, 194), (20, 0, 200), (21, 0, 205), (21, 1, 211), (22, 0, 216), (22, 1, 222), (23, 0, 227), (23, 1, 233), (24, 0, 238), (24, 1, 244), (25, 0, 250), (26, 0, 255), (26, 1, 261), (27, 0, 266), (27, 1, 272), (28, 0, 277), (28, 1, 283), (29, 0, 288), (29, 1, 294), (30, 0, 300), (16, 0, 160), (17, 1, 170), (18, 0, 180), (19, 0, 190), (21, 1, 210), (22, 1, 220), (23, 0, 230), (24, 0, 240), (26, 1, 260), (27, 1, 270), (28, 0, 280), (29, 0, 290))

ARRAY_FIELDS = ("TemSor", "HumSor", "AirQu", "PM2P5", "VOC", "CO2", "SorErr", "CommErr")
PACKED_FIELDS = ("GasAvail", "GasLED", "GasMod", "GasMas", "PM2P5Sta")
TEMPERATURE_FIELDS = ("SetTem", "CoolSvStTemMin", "HeatSvStTemMax", "HumiSvStTemMin",
                      "Heat3DSvStTemMax", "Heat2SvStTemMax", "WUTHSetTem", "FSetTem", "FSetTemMax",
                      "WSetTemMax")
CONTEXT_FIELDS = ("Add0.1", "Add0.5", "TemUn", "TemRec", "WtmrHr", "WUTHTmrHr")
ERROR_TUPLES = {
    "ErrType1": ("001e03", "001e05", "001e09", "001e0b", "001e0c", "001e0e", "001e0f", "001e13",
                 "001e14", "001e17", "001e21", "001e23", "002200", "002201", "002203", "002205"),
    "ErrType2": ("002208", "00220a", "00220b", "00220d", "00220d", "00220e", "00220f", "002212", "003d13"),
}
FILTER_ANY_ERRORS = ("003d05", "003d06", "003d07", "003d08", "003d19", "003d1a", "003d1b",
                     "003d1c", "003d1d")
FILTER_ERRORS = ("000000", "003d09", "003d0a", "003d0b", "003d10", "003d13", "003d16", "003d18",
                 "003d1e", "003d1f", "003d22", "003d11", "003d20", "003d21", "003d27", "003d28")


def emitted_mid(mid):
    return EMITTED_ALIASES.get(mid, mid)


def category_state(build, category, schema=None):
    raw = {}
    for name, row in (SCHEMAS[build][category] if schema is None else schema).items():
        read, _, _, _, initial, lan, readable, _ = row
        if read and readable:
            raw.setdefault(read, initial)
        elif readable:
            raw["#" + name] = deepcopy(lan)
    for address in (address for table in ERROR_TUPLES.values() for address in table):
        raw.setdefault(address, 0)
    for address in FILTER_ANY_ERRORS + FILTER_ERRORS[1:]:
        raw.setdefault(address, 0)
    # Known getters get chosen identity/barcode reports, not a missing-board fallback.
    return {"reported": raw, "outbound": [], "requested": [], "fraction": 0, "unit": 0,
            "old_energy": 0, "next_energy": 0, "turbo_pending": False}


def _integer(value):
    if type(value) is not int or not -(2**31) <= value < 2**31:
        raise InvalidPacket("WB raw controls require signed32 integers")
    return value


def _mask(value, width):
    return value & {1: 1, 2: 255, 3: 65535}.get(width, 65535)


def _adjacent(address, offset):
    return address[:4] + f"{(int(address[4:], 16) + offset) & 255:02x}"


def raw_value(target, name, state=None):
    """Run a finite source getter over the chosen per-child reported tuple cache."""
    family = target.profile.handler
    category, build = family.category, family.build
    schema = getattr(family, "schema", None)
    if schema is None:
        schema = SCHEMAS[build][category]
    state = target.state if state is None else state
    raw = state["reported"]
    row = schema.get(name)
    if row is None or not row[6]:
        return ""
    read, _, width, _, _, lan, _, _ = row
    value = raw.get(read, 0) if read else raw.get("#" + name, lan)
    def other(field):
        descriptor = schema.get(field)
        return raw.get(descriptor[0], 0) if descriptor else 0
    if name == "MIdType":
        return target.mid
    if name in ("IDUID", "ODUID"):
        return f"{int(target.mid, 16):X}"
    if name in ("IDUBarcode", "ODUBarcode"):
        return str(raw.get("#" + name, "SIM"))[:15].split("\0", 1)[0]
    if name == "ODURatedCap":
        return (value & 255) | (raw.get(_adjacent(read, 1), 0) & 255) << 8
    if name in ARRAY_FIELDS:
        if not 1 <= other("GasQ") <= 31:
            return ""
        count = 2 if other("GasQ") == 3 else 1
        step = 2 if width == 3 else 1
        mask = 65535 if width == 3 else 255
        return [raw.get(_adjacent(read, i * step), 0) & mask for i in range(count)]
    if name in PACKED_FIELDS:
        if not 1 <= other("GasQ") <= 31:
            return ""
        count = 2 if other("GasQ") == 3 else 1
        return [(value >> i) & 1 for i in range(count)]
    if name in TEMPERATURE_FIELDS:
        value &= 65535
        if target.mid == "6098" and getattr(family, "unit_conversion", True):
            if state["unit"] == 1:
                match = next(((degree, fraction) for degree, fraction, code in UNIT_ROWS
                              if code == max(160, min(300, value))), (16, 0))
                # Source getter updates shared fraction state. Callers use a staged copy.
                state["fraction"] = match[1]
                return match[0]
            return value // 10 + int(value % 10 >= 5)
        return value // 10
    if name == "Add0.1":
        return (value & 65535) % 10
    if name == "Add0.5":
        return int((value & 65535) % 10 >= 5)
    if name == "TemRec":
        return state["fraction"] if state["fraction"] in (0, 1) else 0
    if name == "TemUn":
        return state["unit"] if state["unit"] in (0, 1) else 0
    if name == "Mod":
        value &= 255
        return 0 if value == 5 else value if 1 <= value <= 4 else value - 1 if 6 <= value <= 12 else ""
    if name == "Quiet":
        value &= 255
        return 0 if value == 1 else 1 if 2 <= value <= 4 else value
    if name in ("SwhSlp", "SwUpDn"):
        return int((value & 255) >= 2)
    if name == "SwingLfRig":
        value &= 255
        return "" if value == 0 else value - 1 if value <= 2 else value
    if name == "AutoClean":
        return int((value & 255) == 0x66)
    if name == "WdSpd":
        value &= 255
        if other("Tur"):
            return 6
        if category == "filter":
            return 7 if value == 1 else value - 1 if 1 < value < 7 else value
        return 8 if value == 0 else value - 1 if value <= 7 else ""
    if name == "RunMod":
        return 5 if other("Inloop") else value & 255
    if name == "Inloop":
        return 1 if other("RunMod") in (5, 6) else value & 255
    if name in ("PctCle", "PctRe"):
        first, second = ("003f0f", "003f16") if name == "PctCle" else ("003f10", "003f17")
        return (raw.get(first, 0) & 255) | (raw.get(second, 0) & 1) << 1
    if name in ERROR_TUPLES:
        result = 0
        for index, address in enumerate(ERROR_TUPLES[name]):
            if address in raw:
                result |= (raw[address] & 255) << index
            else:
                result &= ~(1 << index)
        return result & 65535
    if name == "ErrType":
        result = int(any(raw.get(address, 0) & 255 for address in FILTER_ANY_ERRORS))
        for index, address in enumerate(FILTER_ERRORS[1:], 1):
            if address in raw:
                result |= (raw[address] & 255) << index
            else:
                result &= ~(1 << index)
        return result & 65535
    if name in ("InTem", "InHumi"):
        return (value & 255) - 60
    if name == "OutQuietMode":
        value = (value & 255) - 1
        return value if 0 <= value <= 12 else ""
    if name in ("PowTimeEn", "ConstWarmDefrostEn"):
        return int(read in raw)
    if name in ("InTemEn", "CalMeth"):
        return 1
    if name in ("ElcEn", "UseTimeEn"):
        return int(("081410" if name == "ElcEn" else "08325e") in raw)
    if name == "MasIDUMod":
        return 0
    if name == "PVGenedPwr":
        return (value & 65535) * 1000
    if name == "PSSGoCPwr":
        return ((value & 65535) - 32768) * 1000
    if name in ("PvTotEngy", "NewGridTotEngy"):
        if name == "NewGridTotEngy":
            state["next_energy"] = value & 0xffffffff
        return value & 0xffffffff
    if name == "OldGridTotEngy":
        previous = state["old_energy"]
        state["old_energy"] = state["next_energy"]
        return previous
    if name == "TotalEle":
        return (value & 0xffffffff) * 10
    return _mask(value, width) if type(value) is int and read else value


SHARED_FIELDS = ("fraction", "unit", "old_energy", "next_energy", "turbo_pending")


def reported_state(root, target):
    state = deepcopy(target.state)
    if target is not root:
        state.update(root.state.get("_wb_shared", {}))
    return state


def commit_state(root, target, state):
    target.state = state
    if target is not root:
        root.state["_wb_shared"] = {name: state[name] for name in SHARED_FIELDS}


def stage_command(target, names, values, shared=None):
    """Validate atomically; stage outbound tuples separately from synthetic reports.

    Source callbacks consume a named JSON object: first repeated member wins for
    lookups, while the original arrays retain all duplicates in the ACK.
    """
    family = target.profile.handler
    schema = getattr(family, "schema", None)
    if schema is None:
        schema = SCHEMAS[family.build][family.category]
    if any(name in ("mac", "mid", "hid", "name", "key", "subList") for name in names):
        raise InvalidPacket("WB route, identity and key metadata are immutable")
    state = deepcopy(target.state)
    if shared is not None:
        state.update(shared)
    # The native res constructor builds this object from opt/p, not packet extras.
    context = {}
    for name, value in zip(names, values):
        context.setdefault(name, value)
    for name, value in zip(names, values):
        row = schema.get(name)
        if row and (row[7] or name in CONTEXT_FIELDS):
            if name == "ElecPrice":
                if not isinstance(value, list) or len(value) < 24:
                    raise InvalidPacket("WB energy prices require at least 24 integer hours")
                for item in value:
                    _integer(item)
            else:
                _integer(value)
    for name in CONTEXT_FIELDS:
        if name in context:
            _integer(context[name])
    outbound = []
    def emit(name, value, address=None, width=None):
        row = schema[name]
        address = row[1] if address is None else address
        if address is None:
            return
        width = row[3] if width is None else width
        value = _mask(value, width)
        outbound.append((address, value))
        # Synthetic immediate report bridge; ACK construction does not use it.
        if row[0]:
            state["reported"][row[0]] = value
    # Named lookups select the first duplicate, but each ordered member dispatches.
    for name in names:
        row = schema.get(name)
        if row is None or not row[7] or name in CONTEXT_FIELDS:
            continue
        value = context[name]
        if name == "Mod":
            if not 0 <= value <= 11:
                raise InvalidPacket("invalid WB mode callback value")
            emit(name, 5 if value == 0 else value if value < 5 else value + 1)
            if getattr(family, "mode_preserves_power", False):
                # The callback rereads the pre-command report, not earlier requested Pow.
                power = target.state["reported"].get("001f00", 0) & 1
                outbound.append(("006f00", power))
                state["reported"]["001f00"] = power
        elif name == "Quiet":
            if value not in (0, 1, 2):
                raise InvalidPacket("invalid WB Quiet callback value")
            encoded = (1, 3, 2)[value]
            if value == 0 and state["turbo_pending"]:
                encoded = 0
                state["turbo_pending"] = False
            emit(name, encoded)
        elif name in ("SwhSlp", "SwUpDn", "AutoClean"):
            if value not in (0, 1):
                raise InvalidPacket("invalid WB binary callback value")
            emit(name, ((1, 4) if name == "SwhSlp" else (1, 2) if name == "SwUpDn" else (0x67, 0x66))[value])
        elif name == "WdSpd":
            allowed = range(1, 8) if family.category == "filter" else range(9)
            if value not in allowed:
                raise InvalidPacket("invalid WB speed callback value")
            if value == 6:
                if family.category == "filter" and target.mid == "605d":
                    emit(name, 6)
                emit("Tur", 1)
                state["turbo_pending"] = True
            else:
                emit("Tur", 0)
                encoded = 1 if family.category == "filter" and value == 7 else 0 if value == 8 else value + 1
                emit(name, encoded)
                state["turbo_pending"] = False
        elif name in TEMPERATURE_FIELDS:
            encoded = value * 10
            if name == "SetTem":
                if 0 <= context.get("Add0.1", -1) <= 9:
                    encoded += context["Add0.1"]
                elif context.get("Add0.5") in (0, 1):
                    encoded = ((5 if (value * 10 + context["Add0.5"]) & 0xffffffff else 0)
                               if getattr(family, "boolean_half_degree", family.build == "ADR")
                               else encoded + context["Add0.5"] * 5)
                elif target.mid == "6098" and getattr(family, "unit_conversion", True):
                    if "TemUn" not in context or "TemRec" not in context:
                        raise InvalidPacket("6098 setpoint requires TemUn and TemRec context")
                    state["unit"] = context["TemUn"] & 255
                    state["fraction"] = context["TemRec"] & 255
                    if state["unit"] == 1:
                        degree = max(16, min(30, value & 65535))
                        fraction = state["fraction"] if state["fraction"] <= 1 else 0
                        encoded = next((code for d, f, code in UNIT_ROWS if (d, f) == (degree, fraction)), 161)
            emit(name, encoded)
        elif name == "WUTHCycle":
            emit(name, value + 1)
        elif name == "Wmod":
            emit(name, value & 255)
            outbound.append((row[0], None))  # Source read/request follows the write.
        elif name in ("WtmrMin", "WUTHTmrMin"):
            hour = "WtmrHr" if name == "WtmrMin" else "WUTHTmrHr"
            if hour not in context:
                raise InvalidPacket("WB timer requires minute/hour context")
            outbound.append((row[1], (value & 255, context[hour] & 255)))
            state["reported"][row[0]] = value & 255
            hour_row = schema[hour]
            state["reported"][hour_row[0]] = context[hour] & 255
            if name == "WtmrMin":
                outbound.append(("006f1b", 1))
        elif name in PACKED_FIELDS:
            emit(name, value)
        elif name == "AISvst":
            if value not in range(4):
                raise InvalidPacket("invalid WB AISvst selector")
            emit(name, value + 0x6c)
        elif name in ("AutoCleanMod", "OutQuietMode", "SysPrio"):
            minimum, maximum, offset = {"AutoCleanMod": (1, 3, 98),
                                        "OutQuietMode": (0, 12, 16),
                                        "SysPrio": (1, 4, 88)}[name]
            if not minimum <= value <= maximum:
                raise InvalidPacket(f"invalid WB {name} selector")
            emit(name, value + offset)
            if name == "OutQuietMode":
                # Synthetic report bridge uses the getter domain, not the UART opcode.
                state["reported"][row[0]] = value + 1
        elif name == "ElecPrice":
            # Chosen synthetic clock hour0; native splits the rotated24hour array7/7/7/3.
            for offset in (0, 7, 14, 21):
                outbound.append((_adjacent(row[1], offset), tuple(v & 255 for v in value[offset:min(offset + 7, 24)])))
        elif name == "ReportFreq":
            if value:
                state["report_requested"] = True
        else:
            emit(name, int(value != 0) if row[3] == 1 else value)
    state["requested"] = list(zip(names, deepcopy(values)))
    state["outbound"] = outbound
    return state


def command_values(target, names, values):
    family = target.profile.handler
    schema = getattr(family, "schema", None)
    if schema is None:
        schema = SCHEMAS[family.build][family.category]
    return [deepcopy(value) if name in schema else None for name, value in zip(names, values)]


def _columns(value):
    if not isinstance(value, list) or any(not isinstance(name, str) or not name or "\0" in name for name in value):
        raise InvalidPacket("WB columns must be nonempty strings")
    return value


def _reply(device, outer, inner, index=None):
    index = outer["i"] if index is None else index
    return Reply({"t": "pack", "cid": device.mac, "tcid": outer["cid"],
                  "uid": outer["uid"], "i": index}, inner,
                 GENERIC_KEY if index == 1 else device.key, CODEC)


def _bounded(reply):
    if len(encode_reply(reply)) > 65507:
        raise InvalidPacket("WB response exceeds the UDP payload limit")
    return reply


class ADRFamily:
    build = "ADR"

    def __init__(self, category=None):
        self.category = category

    def validate_state(self, state):
        expected = category_state("ADR", self.category) if self.category is not None else {}
        if state != expected:
            raise ValueError("ADR raw reports and immutable metadata cannot be configured as LAN controls")

    def validate_topology(self, device):
        if self.category is not None:
            return
        for child in device.children:
            if (child.profile.id not in tuple("sim-wb05adr-v1.16-" + suffix for suffix in ("ac", "filter", "water"))
                    or child.mid not in child.profile.mids):
                raise ValueError("ADR children must use their exact source-qualified category profiles")
            if len(child.mac) != 14 or any(c not in "0123456789abcdef" for c in child.mac):
                raise ValueError("ADR children require complete seven-byte hexadecimal identities")

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        return None

    def advertise(self, device, outer):
        if self.category is not None:
            return []
        return [_reply(device, {"i": 1, "cid": "", "uid": 0}, self.metadata(device, "dev"))]

    def metadata(self, device, kind):
        return {"t": kind, "bc": "", "catalog": "gree", "series": "gree", "model": "gree",
                "lock": 0, "vender": "1", "mid": device.mid, "name": device.name,
                "ver": "V3.2.M", "mac": device.mac, "subCnt": len(device.children)}

    def handle(self, device, outer):
        if self.category is not None:
            return []
        if outer.get("tcid") != device.mac:
            raise InvalidPacket("wrong ADR outer target")
        index, uid, peer = outer.get("i"), outer.get("uid"), outer.get("cid")
        if type(index) is not int or index not in (0, 1):
            raise InvalidPacket("invalid ADR key slot")
        if type(uid) is not int or not -(2**31) <= uid < 2**31:
            raise InvalidPacket("invalid ADR uid")
        if not isinstance(peer, str) or len(peer.encode()) > 14 or "\0" in peer:
            raise InvalidPacket("invalid ADR peer identity")
        if outer.get("t") == "subList":
            inner = outer
        elif outer.get("t") == "pack":
            inner = decode_pack(outer, GENERIC_KEY if index else device.key, CODEC)
        else:
            raise InvalidPacket("unsupported ADR envelope")
        kind = inner.get("t")
        if kind == "bind":
            if index != 1 or inner.get("mac") != device.mac:
                raise InvalidPacket("ADR bind requires root identity and generic key")
            # Chosen null cache when empty, serialized string cache when populated.
            return [_reply(device, outer, {"t": "bindOk" if device.children else "bindok", "r": 200,
                                          "mac": device.mac, "key": device.key.decode("ascii")}, 1)]
        if kind in ("subDev", "subList"):
            offset = inner.get("i")
            if type(offset) is not int or not 0 <= offset < 2**31:
                raise InvalidPacket("ADR list requires a nonnegative child offset")
            if "mac" in inner and inner["mac"] != device.mac:
                raise InvalidPacket("wrong ADR list identity")
            entries = [{"mac": child.mac, "mid": emitted_mid(child.mid)}
                       for child in device.children[offset:offset + 5]]
            return [_bounded(_reply(device, outer, {"t": "subList", "i": offset, "c": len(device.children),
                                                    "r": 200, "list": entries}))]
        if kind in ("status", "cmd", "res"):
            if index != 0:
                raise InvalidPacket("ADR controls/status require device key")
            identity = inner.get("mac") if kind == "status" else inner.get("sub", inner.get("mac"))
            target = device if identity == device.mac else next((c for c in device.children if c.mac == identity), None)
            if target is None:
                raise InvalidPacket("unknown ADR target")
            if kind == "status":
                cols = _columns(inner.get("cols"))
                metadata = self.metadata(device, "dat")
                metadata["hid"] = device.profile.hid
                staged = reported_state(device, target)
                dat = [metadata[name] if name in metadata else raw_value(target, name, staged)
                       if target is not device else "" for name in cols]
                reply = _bounded(_reply(device, outer, {"t": "dat", "mac": target.mac, "cols": cols,
                                                       "dat": dat, "r": 200}))
                commit_state(device, target, staged)
                return [reply]
            if target is device:
                raise InvalidPacket("ADR root has no decoded appliance controls")
            if "sub" in inner and inner.get("mac", device.mac) not in (device.mac, target.mac):
                raise InvalidPacket("conflicting ADR command identity")
            names, values = _columns(inner.get("opt")), inner.get("p")
            if not names or not isinstance(values, list) or len(names) != len(values):
                raise InvalidPacket("ADR command requires equal opt/p arrays")
            staged = stage_command(target, names, values, device.state.get("_wb_shared"))
            # Chosen parameter-IO policy: callbacks stage tuples; ACK retains requests.
            reply = _bounded(_reply(device, outer, {"t": "res", "mac": target.mac, "opt": names,
                                                   "p": values, "val": command_values(target, names, values), "r": 200}))
            commit_state(device, target, staged)
            return [reply]
        return []


PROFILES = (
    Profile(id="sim-wb05adr-v1.16", mids=("6400",), hid=HID, source_sha256=SHA256,
            initial_state={}, handler=ADRFamily(), max_children=100),
    *tuple(Profile(id="sim-wb05adr-v1.16-" + suffix, mids=mids, hid=HID, source_sha256=SHA256,
                   initial_state=category_state("ADR", category), handler=ADRFamily(category),
                   identity_bytes=7, parent_profiles=("sim-wb05adr-v1.16",))
           for suffix, mids, category in (("ac", ("6400",), "ac"),
                                         ("filter", ("6098",) + tuple(mid for mid in FILTER_MIDS if mid != "6098"), "filter"),
                                         ("water", ("6036",), "water_floor"))),
)
