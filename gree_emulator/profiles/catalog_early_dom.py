"""Exact early old-DOM scalar controllers; no calibrated mainboard physics.

Each source keeps its own finite names. Numeric writes use the original uint16
cache; T/K ModelType and network-down RSSI are separate readouts. Native T/K/W
commands retain their inclusive-NULL-tail fault: the safe bounded model commits
a validated finite prefix but emits no fabricated ACK. Unknown names are rejected
atomically instead of allowing native NULL-name-table reads. Five presets use an
explicit producer-qualified synthetic mainboard MID10001; W1.1 emits fixed3019.
"""
from copy import deepcopy
from dataclasses import replace

from ..wire import InvalidPacket
from . import Profile
from .catalog_early_small import SmallScalar, METADATA, _columns, _integer, _reply, _text

FIELDS = {
    7: tuple("""
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
    """.split()),
    8: tuple("""
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
    """.split()),
    14: tuple("""
        Pow Mod SetTem WdSpd Tur Quiet SwUpDn SwingLfRig Add0.5 TemUn TemRec Lig Air Blo Health SvSt
        SwhSw HeatCoolType StHt LTemDry Wet SwhSlp SlpMod HasTmr TmrLpTms TmrOff TmrOn CurTmHor
        CurTmMin TmrOnHorLf TmrOnMinLf TmrOffHorLf TmrOffMinLf DsplySt EnvFun JFErrorCode AssHt
        SwhFreAir AllErr Coolmod HeatCool LedLig SmartMod Add0.1 ModelType Buzzer_ON_OFF NoD Wind
        UDFanPort DnPUDSwing DnPLLRSwing DnPRLRSwing AirQ PM2P5 ElcDatHor ElcDatDte ElcDatMth HumSen
        ElcP ElcOnKwh ElcAllKwhClr ElcAllKwhH ElcAllKwhL AutoClean TemSen Emod PctCleOnTm EvapClr
        NobodySave BlkTemCom HabitLearn SmartWind HandCtl VocCtl VocIdiom VocRole ImgUpdateCol
        EnvArea1St EnvArea2St EnvArea3St EnvArea4St EnvArea5St EnvArea6St EnvArea7St EnvArea8St
        EnvArea9St FbidBloPer DIYGra1PoiAmo SwhDIYGra1 Slp1L1 Slp1H1 Slp1L2 Slp1H2 Slp1L3 Slp1H3 Slp1L4
        Slp1H4 Slp1L5 Slp1H5 Slp1L6 Slp1H6 Slp1L7 Slp1H7 Slp1L8 Slp1H8 ImgVerSta VocUpdateCol VocVerSta
        LigSen Video PctCleSetTm AppTimer CO2Level Dazzling NewTimer NewTimerSet MasSub MasIDUMod GetEr
        HeatSvStTemMax HumiSvStTemMin CoolSvStTemMin Wmod WsetTmp WschOn WschOnMin WschOff WschOffMin
        Wtmr1 Wtmr1Min Wtmr2 Wtmr2Min Wtmr3 Wtmr3Min WsenTmpH WsenTmpM WsenTmpL Werr WsenNub WstpSv
        WstpH WatTmp MaeS FanMod ModS VitiGr GasN TemSor HumSor PM2P5V VOC CO2 PctCle PctRe IDUAirQu
        AirQu ODUViti GasAvail GasLED GasMod GasMas PM2P5Sta SorErr CommErr I2CSwitch AIEnSaveDis Dmod
        Dfltr Dpump Dwet DwatFul DwatSen estateInsta21 estateInsta22 estateInsta23 estateInsta24
        ChildLock Smod Sfog RemWarnLig Security SecurityMode ImageRecovery Srst Swat Swash SrstPP
        SrstPF SrstCF SrstRF SrstAF MakeWat WatErr mode wspd light StTmr fltrst wipm25 wopm25 estate
        airQlt Purify ImgUpdateRes VocUpdateRes MicroSen ReplaceHEPA UnmanedShutDown UnmanedOffTime
        PMVComfort Defrost Antifreeze FavorMode ImgUpdateSta VocUpdateSta SwhWifi SwhWifiRe SwhWifiCo
        datDump datRep datFailRe datPeroid subCnt HidDownPer InHidDownPer OEEPHidDownPer ACStupPos
        SaveGuid NoiseSet RoomLen RoomWid RoomHigh CoolNoise HeatNoise rssi ElcErg ElcGear Elc1Kwh
        AutoUpdate AutoComnCloud lock
    """.split()),
    15: tuple("""
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
    """.split()),
    16: tuple("""
        Pow Mod SetTem WdSpd Tur Quiet SwUpDn SwingLfRig Add0.5 TemUn TemRec Lig Air Blo Health SvSt
        SwhSw HeatCoolType StHt LTemDry Wet SwhSlp SlpMod HasTmr TmrLpTms TmrOff TmrOn CurTmHor
        CurTmMin TmrOnHorLf TmrOnMinLf TmrOffHorLf TmrOffMinLf DsplySt EnvFun JFErrorCode AssHt
        SwhFreAir AllErr Coolmod HeatCool LedLig SmartMod Add0.1 ModelType NoD Wind UDFanPort
        DnPUDSwing DnPLLRSwing DnPRLRSwing AirQ PM2P5 ElcDatHor ElcDatDte ElcDatMth HumSen ElcP
        ElcOnKwh ElcAllKwhClr ElcAllKwhH ElcAllKwhL AutoClean TemSen Emod PctCleOnTm EvapClr NobodySave
        BlkTemCom HabitLearn SmartWind HandCtl VocCtl VocIdiom VocRole ImgUpdateCol EnvArea1St
        EnvArea2St EnvArea3St EnvArea4St EnvArea5St EnvArea6St EnvArea7St EnvArea8St EnvArea9St
        FbidBloPer DIYGra1PoiAmo SwhDIYGra1 Slp1L1 Slp1H1 Slp1L2 Slp1H2 Slp1L3 Slp1H3 Slp1L4 Slp1H4
        Slp1L5 Slp1H5 Slp1L6 Slp1H6 Slp1L7 Slp1H7 Slp1L8 Slp1H8 ImgVerSta VocUpdateCol VocVerSta LigSen
        Video PctCleSetTm AppTimer CO2Level Dazzling NewTimer NewTimerSet MasSub MasIDUMod GetEr
        HeatSvStTemMax HumiSvStTemMin CoolSvStTemMin Wmod WsetTmp WschOn WschOnMin WschOff WschOffMin
        Wtmr1 Wtmr1Min Wtmr2 Wtmr2Min Wtmr3 Wtmr3Min WsenTmpH WsenTmpM WsenTmpL Werr WsenNub WstpSv
        WstpH WatTmp MaeS FanMod ModS VitiGr GasN TemSor HumSor PM2P5V VOC CO2 PctCle PctRe IDUAirQu
        AirQu ODUViti GasAvail GasLED GasMod GasMas PM2P5Sta SorErr CommErr I2CSwitch AIEnSaveDis Dmod
        Dfltr Dpump Dwet DwatFul DwatSen estateInsta21 estateInsta22 estateInsta23 estateInsta24
        ChildLock Smod Sfog RemWarnLig Security SecurityMode ImageRecovery Srst Swat Swash SrstPP
        SrstPF SrstCF SrstRF SrstAF MakeWat WatErr mode wspd light StTmr fltrst wipm25 wopm25 estate
        airQlt Purify ImgUpdateRes VocUpdateRes MicroSen ReplaceHEPA UnmanedShutDown UnmanedOffTime
        PMVComfort Defrost Antifreeze FavorMode ImgUpdateSta VocUpdateSta SwhWifi SwhWifiRe SwhWifiCo
        datDump datRep datFailRe datPeroid subCnt HidDownPer InHidDownPer OEEPHidDownPer ACStupPos
        SaveGuid NoiseSet RoomLen RoomWid RoomHigh CoolNoise HeatNoise rssi ElcErg ElcGear Elc1Kwh
        AutoUpdate AutoComnCloud lock
    """.split()),
    18: tuple("""
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
    """.split()),
}


class OldDom(SmallScalar):
    """Concrete source-selected old-DOM cache and original shared timer dialect."""

    def __init__(self, source_index):
        self.index = source_index
        self.source = "old-dom-" + str(source_index)
        self.fields = FIELDS[source_index]
        self.names = frozenset((*self.fields, *METADATA))

    def validate_state(self, state):
        for name, value in state.items():
            maximum = 0xffffffff if name == "ModelType" and self.index in (14, 16) else 65535
            if name not in self.fields or type(value) is not int or not 0 <= value <= maximum:
                raise ValueError("old-DOM state requires an exact source field and unsigned cache value")

    def _runtime(self, device, state):
        fresh = "_small" not in state
        runtime = super()._runtime(device, state)
        if fresh:
            runtime["time"] = "2036-02-06 06:28:16"
            runtime["mid"] = "" if self.index == 15 else device.mid
            runtime["vender"] = runtime["bc"] = ""
        return runtime

    def _metadata_values(self, runtime):
        values = {name: runtime[name] for name in
                  ("host", "name", "time", "lat", "lon", "vender", "bc", "mid", "ver", "hid", "mac")}
        if self.index not in (14, 16):
            values.update(InHid="", OEEPHid="")
        return values

    def advertise(self, device, outer):
        state = deepcopy(device.state)
        runtime = self._runtime(device, state)
        inner = {"t": "dev", "cid": "", "bc": "gree", "catalog": "gree",
                 "mid": device.mid, "lock": state["lock"], "model": "gree",
                 "name": runtime["name"], "series": "gree", "vender": runtime["vender"],
                 "ver": runtime["ver"], "brand": "gree", "mac": device.mac}
        if self.index != 15:
            inner["mid"] = runtime["mid"]
            if self.index != 16:
                inner["bc"] = runtime["bc"]
            if self.index != 16:
                inner["hid"] = device.profile.hid
        return [_reply(device, inner, runtime["uid"], 1)]

    def _command(self, state, runtime, names, values):
        if any(name not in self.names for name in names):
            raise InvalidPacket("unknown old-DOM property reaches a native NULL table entry")
        # Validate even ignored types/metadata before committing the copied state.
        for value in values:
            if type(value) is int:
                _integer(value)
            elif not isinstance(value, str):
                raise InvalidPacket("old-DOM safe commands require signed32 integers or text")
        ordinary, ordinary_values = [], []
        for name, value in zip(names, values):
            if name == "rssi" or name == "ModelType" and self.index in (14, 16):
                if type(value) is int:
                    runtime["shadow"][name] = value & 65535
            else:
                ordinary.append(name)
                ordinary_values.append(value)
        super()._command(state, runtime, ordinary, ordinary_values)

    def _dispatch(self, device, state, runtime, inner):
        if "sub" in inner or inner.get("mac", device.mac) != device.mac:
            raise InvalidPacket("old-DOM controls target one root, not a child alias")
        kind = inner.get("t")
        if kind == "status":
            requested = _columns(inner.get("cols"))
            selected = []
            if len(requested) != 30 or any(not name or len(name.encode()) >= 16 for name in requested):
                for name in requested:
                    if not name or len(name.encode()) >= 16:
                        break
                    if name not in self.names:
                        raise InvalidPacket("unknown old-DOM property reaches a native NULL table entry")
                    selected.append(name)
            metadata = self._metadata_values(runtime)
            values = []
            for name in selected:
                if name == "rssi":
                    values.append(0)  # Synthetic netif-DOWN input, not a measured radio signal.
                elif name in self.fields:
                    values.append(state[name])
                elif name in metadata:
                    values.append(metadata[name])
            return {"t": "dat", "mac": device.mac, "r": 200, "cols": selected, "dat": values}, 0, True
        if kind == "cmd":
            names, values = _columns(inner.get("opt")), inner.get("p")
            if not isinstance(values, list) or len(names) != len(values):
                raise InvalidPacket("old-DOM command arrays must match")
            if self.index != 18:
                self._command(state, runtime, names, values)
                # No native T/K/W ACK; HME's reused prior-status arrays are unsafe.
                return None, 0, True
            effective = []
            for name, value in zip(names, values):
                self._command(state, runtime, [name], [value])
                metadata = self._metadata_values(runtime)
                if name in self.fields:
                    effective.append(runtime["shadow"].get(name, state[name]))
                elif name in metadata:
                    effective.append(metadata[name])
            return {"t": "res", "mac": device.mac, "r": 200, "opt": names, "p": effective}, 0, True
        if kind == "surver":
            return {"t": "configok", "r": "200", "mac": device.mac}, None, True
        if kind == "upgrade":
            runtime["upgrade"] = _text(inner.get("url"), 159)
            return None, 0, True
        return super()._dispatch(device, state, runtime, inner)

    def handle(self, device, outer):
        replies = super().handle(device, outer)
        if replies and replies[0].outer.get("t") == "configok":
            # Preserve native fixed port without unsolicited subnet broadcasting.
            return [replace(replies[0], destination_port=8001)]
        return replies


W_SHA = "bd7af53fbd800b6a7193ba5028b478cd4fe0f6a91a6e432bfabd8cf5b39a0cd6"
W_HID = "362001061894+U-W05WV1.1.bin"
PROFILES = (
    Profile("sim-w05w-v11", ("3019",), W_HID, W_SHA,
            dict.fromkeys(FIELDS[15], 0), OldDom(15), max_request_bytes=1024),
)
PROFILES += (
    Profile("sim-w04hme-v221", ("10001",), "362001065130+U-W04HMEV2.21.bin",
            "03d476f2c153e6accdc8335916e54f6bf3c477fd565d956ed452357ef2063b1a",
            dict.fromkeys(FIELDS[7], 0), OldDom(7), max_request_bytes=1024),
    Profile("sim-w04hme-v224", ("10001",), "362001065130+U-W04HMEV2.24.bin",
            "1e9b85063d3ca56f167dd5ef42a9d1b9ad5331bad8d46136c4f0a79a1f57bd0c",
            dict.fromkeys(FIELDS[8], 0), OldDom(8), max_request_bytes=1024),
    Profile("sim-w05t-v207", ("10001",), "362001061665+U-W05TV2.07.bin",
            "473069c36c8f11b7c2b75826efb3c038a3b006a328b6b87910633c8cd8e08a3d",
            dict.fromkeys(FIELDS[14], 0), OldDom(14), max_request_bytes=1024),
    Profile("sim-w05k-v201", ("10001",), "362001062293+U-W05KV2.01.bin",
            "e6d18004924ee352a5e82d062a87166cb5f31811ec7437044fd716c6f63d208b",
            dict.fromkeys(FIELDS[16], 0), OldDom(16), max_request_bytes=1024),
    Profile("sim-w05afj-v125", ("10001",), "362001063903+U-W05AFJV1.25.bin",
            "c7f99da45739fc01b42fe569ca08c4709a4991e9e3db7df659c655a7ec9cf302",
            dict.fromkeys(FIELDS[18], 0), OldDom(18), max_request_bytes=1024),
)
