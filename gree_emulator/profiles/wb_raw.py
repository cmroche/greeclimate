"""Exact standalone WB uint16 cache namespaces, independent of appliance presets.

All raw defaults are explicitly synthetic zero reports. Local metadata callbacks
precede the numeric table; null-pointer native faults are safely omitted.
"""

from datetime import datetime

from ..wire import InvalidPacket


_BASE = frozenset("""
Pow Mod SetTem WdSpd Tur Quiet SwUpDn SwingLfRig Add0.5 TemUn TemRec Lig Air Blo Health SvSt
SwhSw HeatCoolType StHt LTemDry Wet SwhSlp SlpMod HasTmr TmrLpTms TmrOff TmrOn CurTmHor CurTmMin
TmrOnHorLf TmrOnMinLf TmrOffHorLf TmrOffMinLf DsplySt EnvFun JFErrorCode AssHt SwhFreAir AllErr
Coolmod HeatCool LedLig SmartMod Add0.1 ModelType NoD Buzzer_ON_OFF ElcEn Wind UDFanPort
DnPUDSwing DnPLLRSwing DnPRLRSwing AirQ PM2P5 ElcDatHor ElcDatDte ElcDatMth HumSen ElcP ElcOnKwh
ElcAllKwhClr ElcAllKwhH ElcAllKwhL AutoClean TemSen Emod PctCleOnTm EvapClr NobodySave BlkTemCom
HabitLearn SmartWind HandCtl VocCtl VocIdiom VocRole ImgUpdateCol EnvArea1St EnvArea2St
EnvArea3St EnvArea4St EnvArea5St EnvArea6St EnvArea7St EnvArea8St EnvArea9St FbidBloPer
DIYGra1PoiAmo SwhDIYGra1 Slp1L1 Slp1H1 Slp1L2 Slp1H2 Slp1L3 Slp1H3 Slp1L4 Slp1H4 Slp1L5 Slp1H5
Slp1L6 Slp1H6 Slp1L7 Slp1H7 Slp1L8 Slp1H8 ImgVerSta VocUpdateCol VocVerSta LigSen Video
PctCleSetTm AppTimer CO2Level Dazzling NewTimer NewTimerSet MasSub MasIDUMod GetEr
HeatSvStTemMax HumiSvStTemMin CoolSvStTemMin Wmod WsetTmp WschOn WschOnMin WschOff WschOffMin
Wtmr1 Wtmr1Min Wtmr2 Wtmr2Min Wtmr3 Wtmr3Min WsenTmpH WsenTmpM WsenTmpL Werr WsenNub WstpSv
WstpH WatTmp MaeS FanMod ModS VitiGr GasN TemSor HumSor PM2P5V VOC CO2 PctCle PctRe IDUAirQu
AirQu ODUViti GasAvail GasLED GasMod GasMas PM2P5Sta SorErr CommErr Dmod Dfltr Dpump Dwet
DwatFul DwatSen estateInsta21 estateInsta22 estateInsta23 estateInsta24 ChildLock Smod Sfog
RemWarnLig Security SecurityMode ImageRecovery Srst Swat Swash SrstPP SrstPF SrstCF SrstRF
SrstAF MakeWat WatErr mode wspd light StTmr fltrst wipm25 wopm25 estate airQlt Purify
ImgUpdateSucs VocUpdateRes MicroSen ReplaceHEPA UnmanedShutDown UnmanedOffTime PMVComfort
Defrost Antifreeze FavorMode ImgUpdateSta ImgUpdateFail VocUpdateSta SmartSlpMod SmartSlpModEx
StSlp1C StSlp1CInc StSlp1CSp StSlp1H StSlp1HInc StSlp1HSp StSlp2C StSlp2CInc StSlp2CSp StSlp2H
StSlp2HInc StSlp2HSp StSlp3C StSlp3CInc StSlp3CSp StSlp3H StSlp3HInc StSlp3HSp StSlp4C
StSlp4CInc StSlp4CSp StSlp4H StSlp4HInc StSlp4HSp AntiDirectBlow SwhWifi SwhWifiRe SwhWifiCo
datDump datRep datFailRe datPeroid subCnt HidDownPer InHidDownPer OEEPHidDownPer ACStupPos
SaveGuid NoiseSet RoomLen RoomWid RoomHigh CoolNoise HeatNoise ElcErg ElcGear Elc1Kwh AutoUpdate
AutoComnCloud lock apssid appsw host name time lat lon vender bc mid model series brand catalog
country hid mac ver HidSvrVer InHid InHidSvrVer OEEPHid OEEPHidSvrVer
""".split())

EARLY_FIELDS = _BASE
WB04_FIELDS = _BASE | frozenset(('CpsTem', 'DFPoint', 'EnergyFlow', 'EnvTem', 'FaultDisplay', 'TemsSenOut', 'UvcControl'))
RT11_FIELDS = _BASE | frozenset(('CompressorFqy', 'CompressorTem', 'CpsTem', 'DFPoint', 'EnergyFlow', 'EnvTem', 'FaultDisplay', 'InEvaTem', 'OutEnvTem', 'TemsSenOut', 'UvcControl'))
RT13_FIELDS = _BASE | frozenset(('CompressorFqy', 'CompressorTem', 'CpsTem', 'DFPoint', 'EnergyFlow', 'EnvTem', 'FaultDisplay', 'InEvaTem', 'OutEnvTem', 'TemsSenOut', 'UvcControl'))
RT13_110_FIELDS = _BASE | frozenset(('CpsTem', 'DFPoint', 'EnergyFlow', 'EnvTem', 'FaultDisplay', 'TemsSenOut'))

# These names are consumed by the local callback, not the halfword cache loop.
LOCAL_FIELDS = frozenset(("name", "lock", "AutoUpdate", "time", "host", "hid",
                          "mid", "bc", "DevID", "MafIdf", "AppTimer", "MidType",
                          "ver", "vender", "rssi", "ModelType"))
EMPTY_FIELDS = frozenset(("DevID", "MafIdf"))
# The parser's local selector is narrower than the getter callback.
LOCAL_COMMAND_FIELDS = LOCAL_FIELDS - {"ver", "vender", "rssi"} | {"ReportClientID"}


def validate_state(state, fields):
    for name, value in state.items():
        if name not in fields - LOCAL_COMMAND_FIELDS or type(value) is not int or not 0 <= value <= 65535:
            raise ValueError("WB raw state requires source-declared unsigned16 fields")


def status(device, names, metadata, fields, staged=None, *, empty=EMPTY_FIELDS):
    # Native successful callbacks can append no dat member but retain the column.
    selected = [name for name in names if name in metadata or name in empty or name in fields]
    values = [metadata[name] if name in metadata else
              staged[name] if staged is not None and name in staged else device.state.get(name, 0)
              for name in selected if name not in empty]
    return selected, values


def stage_command(device, names, values, fields, *, clock=False, local_fields=LOCAL_COMMAND_FIELDS):
    if not isinstance(values, list) or not names or len(names) != len(values):
        raise InvalidPacket("WB command requires matching nonempty property and value arrays")
    staged = {}
    for name, value in zip(names, values):
        if name in ("name", "time", "ReportClientID", "ModelType") or name == "ver" and name in local_fields:
            if not isinstance(value, str) or "\0" in value or len(value.encode()) >= 64:
                raise InvalidPacket("WB local command requires a bounded string")
            if name == "time" and clock:
                try:
                    datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
                except ValueError as exc:
                    raise InvalidPacket("invalid WB synthetic clock") from exc
                staged["_wb_time"] = value
            elif name == "ReportClientID":
                staged["_wb_report_client"] = value
            # name/ModelType and the old WB04 time setters intentionally do not mutate.
        elif name == "AppTimer":
            if type(value) is not int:
                raise InvalidPacket("WB AppTimer command requires an integer")
        elif name in fields - local_fields:
            if type(value) is not int or not -(1 << 31) <= value < (1 << 32):
                raise InvalidPacket("WB raw command requires an integer32 token")
            staged[name] = value & 65535
        else:
            raise InvalidPacket("unsupported WB command field")
    return staged


def command_response(device, names, values, staged, *, fault_display=False, model_type_string=True,
                     local_fields=LOCAL_COMMAND_FIELDS, current=None):
    local = [(name, value) for name, value in zip(names, values)
             if name in local_fields]
    raw = [(name, value) for name, value in zip(names, values)
           if name not in local_fields]
    if current is None:
        current = metadata(device, fault_display=fault_display, model_type_string=model_type_string)
    current["time"] = staged.get("_wb_time", current["time"])
    return ([name for name, value in local + raw],
            [current[name] for name, value in local if name in current]
            + [value for name, value in raw])


def metadata(device, *, fault_display=False, model_type_string=True):
    # Explicit synthetic backing for source mainboard/platform buffers, not scan literals.
    values = {"name": device.name, "lock": 0, "AutoUpdate": 0,
              "time": device.state.get("_wb_time", "2000-01-01 00:00:00"),
              "host": "", "hid": device.profile.hid, "mid": device.mid,
              "bc": "", "AppTimer": 0, "MidType": 0, "ver": "", "vender": "",
              "rssi": -50}
    if model_type_string:
        values["ModelType"] = ""
    if fault_display:
        values["FaultDisplay"] = ""
    return values
