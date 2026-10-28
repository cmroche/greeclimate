"""Source-bounded numeric bridges; all board/radio readouts are synthetic.

Strict atomic validation replaces native unchecked inputs. W05P's past-end
NULL-tail access has no invented acknowledgement; its valid prefix mutation
is modeled atomically. No physical UART, flash upgrade or calibration claim.
"""
from copy import deepcopy
from time import monotonic


from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile
from .catalog_realtek_third_tables import (
    CODEC, KEY, FiniteTables, _clock, _integer, _members, _reply, _text,
)

W05P_FIELDS = tuple("""
Pow Mod SetTem WdSpd Tur Quiet SwUpDn SwingLfRig Add0.5 TemUn TemRec Lig Air Blo Health SvSt
SwhSw HeatCoolType StHt LTemDry Wet SwhSlp SlpMod HasTmr TmrLpTms TmrOff TmrOn CurTmHor
CurTmMin TmrOnHorLf TmrOnMinLf TmrOffHorLf TmrOffMinLf DsplySt EnvFun JFErrorCode AssHt
SwhFreAir AllErr Coolmod HeatCool LedLig SmartMod Add0.1 ModelType NewWind AssistHeat Rinse NoD
TemRecC TemRecH TimerOnT SetTimerOn TimerOffT SetTimerOff AppTimer Wind UDFanPort DnPUDSwing
DnPLLRSwing DnPRLRSwing AirQ PM2P5 ElcDatHor ElcDatDte ElcDatMth HumSen ElcP ElcOnKwh
ElcAllKwhClr ElcAllKwhH ElcAllKwhL AutoClean TemSen Emod PctCleOnTm EvapClr NobodySave
BlkTemCom HabitLearn SmartWind HandCtl VocCtl VocIdiom VocRole ImgUpdateCol EnvArea1St
EnvArea2St EnvArea3St EnvArea4St EnvArea5St EnvArea6St EnvArea7St EnvArea8St EnvArea9St
FbidBloPer DIYGra1PoiAmo SwhDIYGra1 Slp1L1 Slp1H1 Slp1L2 Slp1H2 Slp1L3 Slp1H3 Slp1L4 Slp1H4
Slp1L5 Slp1H5 Slp1L6 Slp1H6 Slp1L7 Slp1H7 Slp1L8 Slp1H8 ImgVerSta VocUpdateCol VocVerSta LigSen
Video PctCleSetTm MasSub MasIDUMod GetEr HeatSvStTemMax HumiSvStTemMin CoolSvStTemMin Wmod
WsetTmp WschOn WschOnMin WschOff WschOffMin Wtmr1 Wtmr1Min Wtmr2 Wtmr2Min Wtmr3 Wtmr3Min
WsenTmpH WsenTmpM WsenTmpL Werr WsenNub WstpSv WstpH WatTmp MaeS FanMod ModS VitiGr GasN TemSor
HumSor PM2P5V VOC CO2 PctCle PctRe IDUAirQu AirQu ODUViti GasAvail GasLED GasMod GasMas
PM2P5Sta SorErr CommErr Dmod Dfltr Dpump Dwet DwatFul DwatSen Smod Sfog RemWarnLig Security
SecurityMode ImageRecovery Srst Swat Swash SrstPP SrstPF SrstCF SrstRF SrstAF MakeWat WatErr
mode wspd light StTmr fltrst wipm25 wopm25 estate airQlt Purify ImgUpdateRes VocUpdateRes
MicroSen ReplaceHEPA UnmanedShutDown UnmanedOffTime PMVComfort Defrost Antifreeze FavorMode
ImgUpdateSta VocUpdateSta SwhWifi SwhWifiRe SwhWifiCo datDump datRep datFailRe datPeroid subCnt
HidDownPer InHidDownPer OEEPHidDownPer ACStupPos SaveGuid NoiseSet RoomLen RoomWid RoomHigh
CoolNoise HeatNoise ElcErg ElcGear Elc1Kwh AutoUpdate AutoComnCloud lock
""".split())

AFJME_FIELDS = tuple("""
Pow Mod SetTem WdSpd Tur Quiet SwUpDn SwingLfRig Add0.5 TemUn TemRec Lig Air Blo Health SvSt
SwhSw HeatCoolType StHt LTemDry Wet SwhSlp SlpMod HasTmr TmrLpTms TmrOff TmrOn CurTmHor
CurTmMin TmrOnHorLf TmrOnMinLf TmrOffHorLf TmrOffMinLf DsplySt EnvFun JFErrorCode AssHt
SwhFreAir AllErr Coolmod HeatCool LedLig SmartMod Add0.1 ModelType NoD Buzzer_ON_OFF Wind
UDFanPort DnPUDSwing DnPLLRSwing DnPRLRSwing AirQ PM2P5 ElcDatHor ElcDatDte ElcDatMth HumSen
ElcP ElcOnKwh ElcAllKwhClr ElcAllKwhH ElcAllKwhL AutoClean TemSen Emod PctCleOnTm EvapClr
NobodySave BlkTemCom HabitLearn SmartWind HandCtl VocCtl VocIdiom VocRole ImgUpdateCol
EnvArea1St EnvArea2St EnvArea3St EnvArea4St EnvArea5St EnvArea6St EnvArea7St EnvArea8St
EnvArea9St FbidBloPer DIYGra1PoiAmo SwhDIYGra1 Slp1L1 Slp1H1 Slp1L2 Slp1H2 Slp1L3 Slp1H3 Slp1L4
Slp1H4 Slp1L5 Slp1H5 Slp1L6 Slp1H6 Slp1L7 Slp1H7 Slp1L8 Slp1H8 ImgVerSta VocUpdateCol VocVerSta
LigSen Video PctCleSetTm AppTimer CO2Level Dazzling ElcEn MasSub MasIDUMod GetEr HeatSvStTemMax
HumiSvStTemMin CoolSvStTemMin Wmod WsetTmp WschOn WschOnMin WschOff WschOffMin Wtmr1 Wtmr1Min
Wtmr2 Wtmr2Min Wtmr3 Wtmr3Min WsenTmpH WsenTmpM WsenTmpL Werr WsenNub WstpSv WstpH WatTmp MaeS
FanMod ModS VitiGr GasN TemSor HumSor PM2P5V VOC CO2 PctCle PctRe IDUAirQu AirQu ODUViti
GasAvail GasLED GasMod GasMas PM2P5Sta SorErr CommErr Dmod Dfltr Dpump Dwet DwatFul DwatSen
estateInsta21 estateInsta22 estateInsta23 estateInsta24 ChildLock Smod Sfog RemWarnLig Security
SecurityMode ImageRecovery Srst Swat Swash SrstPP SrstPF SrstCF SrstRF SrstAF MakeWat WatErr
mode wspd light StTmr fltrst wipm25 wopm25 estate airQlt Purify ImgUpdateSucs VocUpdateRes
MicroSen ReplaceHEPA UnmanedShutDown UnmanedOffTime PMVComfort Defrost Antifreeze FavorMode
ImgUpdateSta ImgUpdateFail VocUpdateSta SmartSlpMod SmartSlpModEx StSlp1C StSlp1CInc StSlp1CSp
StSlp1H StSlp1HInc StSlp1HSp StSlp2C StSlp2CInc StSlp2CSp StSlp2H StSlp2HInc StSlp2HSp StSlp3C
StSlp3CInc StSlp3CSp StSlp3H StSlp3HInc StSlp3HSp StSlp4C StSlp4CInc StSlp4CSp StSlp4H
StSlp4HInc StSlp4HSp AntiDirectBlow SwhWifi SwhWifiRe SwhWifiCo datDump datRep datFailRe
datPeroid subCnt HidDownPer InHidDownPer OEEPHidDownPer ACStupPos SaveGuid NoiseSet RoomLen
RoomWid RoomHigh CoolNoise HeatNoise rssi ElcErg ElcGear Elc1Kwh AutoUpdate AutoComnCloud lock
""".split())

BED_FIELDS = ("ActType", "ActValue", "estate1", "MidType")
MATTRESS_FIELDS = ("AutoLeftLeg", "AutoLeftWai", "AutoRighLeg", "AutoRighWai", "HumLeftLeg",
                   "HumLeftWai", "HumRighLeg", "HumRighWai", "ArrCmd0x22", "MidType")
NUMERIC_METADATA = ("apssid", "appsw", "host", "name", "time", "lat", "lon", "vender", "bc",
                    "mid", "model", "series", "brand", "catalog", "country", "hid", "mac", "ver",
                    "HidSvrVer", "InHid", "InHidSvrVer", "OEEPHid", "OEEPHidSvrVer")
# These native table names append a column but their getter appends no datum.
EMPTY_GETTERS = frozenset(("apssid", "appsw", "brand", "model", "series", "catalog", "country",
                           "HidSvrVer", "InHidSvrVer", "OEEPHidSvrVer"))
HIDS = {
    "w05p": "362001061395+U-W05PV1.1.bin",
    "afjme": "362001065517+U-W05AFJMEV1.25.bin",
    "w05ac": "362001062353+U-W05ACV1.00.bin+362001063014+N-W05ACV0.00.bin",
}
SHAS = {
    "w05p": "8142afc02b0b4a70a65f257c2e0dd32aad634cdc566cca6d9a3a198cf7f0d6be",
    "afjme": "094b8c03181667225f82649d55e899d007d25a7e4f51d18ab4ed2d342609a253",
    "w05ac": "f5ed4e1286d955e0f91a79e85019a91fb0a986143c4dde882be3366afa8a508d",
}


def _columns(value, bound):
    if not isinstance(value, list) or len(value) > bound:
        raise InvalidPacket("bridge column array exceeds source local capacity")
    return [_text(name, 1023) for name in value]


class NumericBridge(FiniteTables):
    def __init__(self, build, companion_mid=None):
        self.build, self.companion_mid = build, companion_mid
        self.descriptors = build == "w05ac"
        self.w05 = True
        self.fields = (BED_FIELDS if companion_mid == "70401" else MATTRESS_FIELDS) if self.descriptors else (
            W05P_FIELDS if build == "w05p" else AFJME_FIELDS)

    def validate_state(self, state):
        for name, value in state.items():
            if name not in self.fields or name in ("rssi", "MidType"):
                raise ValueError("only the exact source-selected bridge fields may be configured")
            try:
                if name == "ArrCmd0x22":
                    if not isinstance(value, list) or len(value) > 255:
                        raise InvalidPacket("bridge array requires at most 255 bytes")
                    for item in value:
                        _integer(item, 0, 255)
                else:
                    _integer(value, -(1 << 31) if self.descriptors else 0,
                             (1 << 31)-1 if self.descriptors else 65535)
            except InvalidPacket as error:
                raise ValueError(str(error)) from error

    def _runtime(self, device, state):
        runtime = super()._runtime(device, state)
        runtime.setdefault("metadata", {})
        runtime.setdefault("report_client", "")
        runtime.setdefault("scalar_array", 0)
        return runtime

    def _metadata(self, device, runtime):
        result = dict.fromkeys(NUMERIC_METADATA, "")
        result.update(name=device.name, mid=device.mid, mac=device.mac,
                      hid=device.profile.hid, host=runtime["host"], time=runtime["time"],
                      ver={"w05p": "V1.2.1", "afjme": "V3.2.M", "w05ac": ""}[self.build])
        if self.build == "w05p":
            result["mid"] = ""  # Synthetic unreported companion MID, distinct from discovery3019.
        result.update(runtime["metadata"])
        if self.descriptors:
            result.update(name=device.name, mid="", mac="")
        return result

    def advertise(self, device, outer):
        state = deepcopy(device.state)
        metadata = self._metadata(device, self._runtime(device, state))
        inner = {"t": "dev", "cid": "", "bc": metadata["bc"] if self.build == "afjme" else "gree",
                 "catalog": "gree", "mid": device.mid, "lock": state.get("lock", 0), "model": "gree",
                 "name": metadata["name"], "series": "gree", "vender": metadata["vender"],
                 "ver": metadata["ver"], "brand": "gree", "mac": device.mac}
        if self.build == "afjme":
            inner["hid"] = device.profile.hid
        # Safe JSON policy collapses native duplicate lock members to the final cache value.
        return [_reply(device, inner, selector=1)]

    def wlan(self, device, outer):
        super().wlan(device, outer)
        return [Reply({"t": "ret", "r": 200, "mac": device.mac}, trailing_newline=True)]

    def _timer(self, inner):
        timer_id, record = super()._timer(inner)
        for command in record["cmd"]:
            for name in command["opt"]:
                if name not in self.fields or name in ("ArrCmd0x22", "MidType"):
                    raise InvalidPacket("timer requires a qualified scalar bridge cache field")
        return timer_id, record

    def _time(self, state, runtime, value):
        super()._time(state, runtime, value)
        if not self.descriptors:
            for name in self.fields:
                if name != "rssi":
                    state[name] &= 65535
        if "rssi" in state:
            runtime["rssi_cache"] = state.pop("rssi") & 65535
        if self.build == "w05p":
            state["AppTimer"] = int(any(not record["enable"] for record in runtime["timers"].values()))

    def _command(self, state, runtime, names, values):
        columns, effective = [], []
        for name, value in zip(names, values):
            if name in self.fields:
                if self.descriptors and name == "ArrCmd0x22":
                    if not isinstance(value, list) or len(value) > 255:
                        raise InvalidPacket("descriptor array requires at most 255 integers")
                    value = [_integer(item) for item in value]
                    previous = state.get(name)
                    if previous is not None and len(value) != len(previous):
                        raise InvalidPacket("existing TLV record fixes the array length")
                    state[name] = [item & 255 for item in value]
                else:
                    value = _integer(value)
                    value = value if self.descriptors else value & 65535
                    if self.descriptors and name == "MidType":
                        value = 0  # Descriptor offset0 is a native no-store branch.
                    elif name != "rssi":
                        state[name] = value
                    else:
                        runtime["rssi_cache"] = value
            elif name == "ReportClientID" and self.build == "afjme":
                runtime["report_client"] = _text(value, 19, empty=False)
                continue
            elif name in NUMERIC_METADATA:
                if self.descriptors and name != "time":
                    continue
                if type(value) is int and not self.descriptors:
                    _integer(value)  # Numeric metadata writes affect hidden u16 slots only.
                    continue
                if name == "time":
                    _clock(value)
                    self._time(state, runtime, value)
                elif name in ("name", "apssid", "appsw", "host", "lat", "lon"):
                    limits = {"name": 95, "apssid": 32, "appsw": 32, "host": 20, "lat": 10, "lon": 10}
                    value = _text(value, limits[name], empty=name == "appsw")
                    if name == "host":
                        runtime["host"] = value
                    else:
                        runtime["metadata"][name] = value
                else:
                    _text(value, 1023)
                    continue
            else:
                raise InvalidPacket("unknown numeric field reaches native NULL table tail")
            columns.append(name)
            effective.append(deepcopy(value))
        return columns, effective

    def _status(self, device, state, runtime, requested):
        bound = 35 if self.descriptors else 30
        columns, values = [], []
        if len(requested) == bound:
            return columns, values
        metadata = self._metadata(device, runtime)
        for position, name in enumerate(requested):
            if not name or len(name.encode()) >= 16:
                break
            if name in self.fields:
                if self.descriptors:
                    if position > len(self.fields):
                        raise InvalidPacket("descriptor request position exceeds selected allocation")
                    if position == len(self.fields):
                        continue  # The copied sentinel descriptor has type0.
                    if self.fields[position] == "ArrCmd0x22":
                        if "ArrCmd0x22" not in state:
                            continue
                        value = state["ArrCmd0x22"][:]
                    else:
                        value = 0 if name == "MidType" else runtime["scalar_array"] if name == "ArrCmd0x22" else state[name]
                else:
                    value = 0 if name == "rssi" else state[name]  # Chosen independent radio input.
                columns.append(name)
                values.append(deepcopy(value))
            elif name in metadata:
                columns.append(name)
                if self.descriptors or name not in EMPTY_GETTERS:
                    values.append(metadata[name])
            elif not self.descriptors:
                raise InvalidPacket("unknown numeric field reaches native NULL table tail")
        return columns, values

    def handle(self, device, outer):
        _members(outer)
        if outer.get("t") != "pack":
            return super().handle(device, outer)
        if outer.get("tcid") != device.mac:
            raise InvalidPacket("bridge request must target this root")
        index, uid = _integer(outer.get("i")), _integer(outer.get("uid", 0))
        inner = decode_pack(outer, KEY if index else device.key, CODEC)
        _members(inner)
        if "sub" in inner or ("mac" in inner and inner["mac"] != device.mac):
            raise InvalidPacket("bridge request targets an unqualified identity")
        kind = inner.get("t")
        if kind not in ("status", "cmd", "bind", "upgrade", "surver"):
            replies = super().handle(device, outer)
            if self.build == "w05p" and kind in ("setT", "updateT", "deleteT"):
                runtime = self._runtime(device, device.state)
                device.state["AppTimer"] = int(any(not record["enable"] for record in runtime["timers"].values()))
            return replies
        state = deepcopy(device.state)
        runtime = self._runtime(device, state)
        now = monotonic()
        self._advance(state, runtime, now)
        if kind == "bind":
            reply = _reply(device, {"t": "bindok", "mac": device.mac, "r": 200,
                                    "key": device.key.decode("ascii")}, uid, 1)
            device.advance(now)
            device.state = state
            return [reply]
        if kind == "surver":
            if self.descriptors:
                return []  # This source's dispatch maps to a missing builder case.
            # Original caller supplies only three arguments to four-argument ROM base64.
            # With declared zero board inputs W05P fails capacity preflight; AFJME
            # supplies residual length0. Preserve these actual effects, not a repaired snapshot.
            reply = Reply({"t": "pack", "i": 1, "uid": uid, "cid": device.mac, "tcid": "",
                           "pack": "fg\u0001" if self.build == "w05p" else "!!"}, trailing_newline=True)
            encode_reply(reply)
            device.advance(now)
            device.state = state
            return [reply]
        if kind == "upgrade":
            runtime["upgrade_url"] = _text(inner.get("url"), 159)
            replies = []
            if self.build == "afjme":
                reply = Reply({"t": "ret", "r": 200, "mac": device.mac}, trailing_newline=True)
                encode_reply(reply)
                replies.append(reply)
            # Record the source request without physical flash/network updates.
            device.advance(now)
            device.state = state
            return replies
        if kind == "status":
            names = _columns(inner.get("cols"), 35 if self.descriptors else 30)
            columns, values = self._status(device, state, runtime, names)
            response = {"t": "dat", "mac": device.mac, "r": 200, "cols": columns, "dat": values}
            reply = _reply(device, response, uid)
        else:
            names = _columns(inner.get("opt"), 30)
            values = inner.get("p")
            if not isinstance(values, list) or len(names) != len(values):
                raise InvalidPacket("bridge command arrays must match")
            columns, effective = self._command(state, runtime, names, values)
            if self.build == "w05p":
                reply = None  # Stop safely at the unchecked NULL tail before the reply builder.
            elif self.build == "afjme" and "ReportClientID" in names:
                reply = None  # Special mutation precedes the native NULL-tail lookup.
            elif self.build == "afjme":
                # Safe ownership policy: never reuse a previous status's freed JSON arrays.
                reply = _reply(device, {"t": "res", "mac": device.mac, "r": 200}, uid)
            else:
                reply = _reply(device, {"t": "res", "mac": device.mac, "r": 200,
                                        "opt": columns, "p": effective}, uid)
        device.advance(now)
        device.state = state
        return [] if reply is None else [reply]


def _profile(build, mids, suffix, companion_mid=None):
    handler = NumericBridge(build, companion_mid)
    state = dict.fromkeys((name for name in handler.fields if name not in ("ArrCmd0x22", "rssi", "MidType")), 0)
    if "TemSen" in state:
        state["TemSen"] = 63  # Chosen synthetic cache; W05P physical encoding remains unknown.
    return Profile("sim-"+suffix, mids, HIDS[build], SHAS[build], state, handler,
                   max_request_bytes=1024)


PROFILES = (
    _profile("w05p", ("3019",), "w05p-v11-numeric"),
    _profile("afjme", ("11f00", "11f01", "11f02", "11f03", "11008", "10010"), "w05afjme-v125-numeric"),
    _profile("w05ac", ("70401",), "w05ac-v100-bedframe", "70401"),
    _profile("w05ac", ("70402", "828211"), "w05ac-v100-mattress-cache", "70402"),
)
