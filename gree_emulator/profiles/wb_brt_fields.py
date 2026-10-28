"""Exact per-build commercial WB tables; duplicate/null records are not merged builds."""

FIELDS = {
    "1.38": frozenset("""
        SwhWifi SwhWifiRes SwhWifiConf AutoUpdate AutoConnCloud lock datDump datRep datFailRep
        datPeroid subCnt useTCP vender bc mid model series apssid appsw brand catalog country hid host
        mac name time ver city cnty cityid lat lon Pow Mod SetTem WdSpd Tur Quiet SwUpDn SwingLfRig
        TemUn TemRec Lig Air Blo Health SvSt SwhSw HeatCoolType StHt LTemDry Wet SwhSlp SlpMod HasTmr
        TmrLpTms TmrOff TmrOn CurTmHor CurTmMin TmrOnHorLf TmrOnMinLf TmrOffHorLf TmrOffMinLf DsplySt
        EnvFun JFErrorCode AssHt FrshAir AllErr Coolmod MasSub MasIDUMod GetEr CoolSvStTemMin
        HeatSvStTemMax HumiSvStTemMin MaeS FanMod ModS VitiGr GasN TemSor HumSor PM2P5 VOC CO2 PctCle
        PctRe IDUAirQu AirQu ODUViti GasAvail GasLED GasMod GasMas PM2P5Sta SorErr CommErr GasQ RunMod
        Inloop InVitiGr InVitiGrCg IFDtiGr InEffClRes InEffReRes IFDClRes EffReRes ErrType GoOut
        AidHeat SetCoolHumi SetDeciTem SysSta HCHO HCHOEN PM2P5EN MdVitiGr MdVitGrCg MdEffClRes
        MdEffReRes InloopEN Tcloud SorSet Add0.1 Add0.5 HumiEnable TemBody CleanState AutoClean
        CleanTime AutoSetTemEn Light AssHtSet JFerr AntiFreeze CleanEn ExtraMod InSeries HalfTemEn
        ActualWdSpd Heat3DSvStTemMax Heat2SvStTemMax LowDeHumi IDUModSet MasSubEn Can1MasSubEn
        Can1MasSub FClTime PlProg FClRes IDURunMod Humi2SvStTemMin AirLevel Idemand CoolSvStTemMinD
        HumiSvStTemMinD HeatSvStTemMaxD MIdType AppTimer rssi ModelType Heat3DSvStTemMaxD
        Heat2SvStTemMaxD MSysStatus InTem OutTem InHumi ScheCoolTem ScheHeatTem ScheName ScheEnable
        RemoteLock HoldSetTemp Wstate WschTyp Sch1 Sch2 Wtmr1StartHr Wtmr1StartMin Wtmr1EndHr
        Wtmr1EndMin Wtmr2StartHr Wtmr2StartMin Wtmr2EndHr Wtmr2EndMin SetTemInt SetTemDec SwhBw Wmod
        WstpSv WstpH WatTmp Watpercent BwErr BwBoard ComEqui FlagHeat PowHeat IntelCtrl OrderHeat
        ErrHeat HeatTemMax HeatTemInt HeatTemDec Defrost MuteSch1 MuteSch2 Mtmr1StartHr Mtmr1StartMin
        Mtmr1EndHr Mtmr1EndMin Mtmr2StartHr Mtmr2StartMin Mtmr2EndHr Mtmr2EndMin PoolFunc FlagPool
        UaeEn Lamp LigEn ComStatus PumpStatus AuxStatus InTemInt InTemDec OutTemInt OutTemDec
        HeatTemMin CoolTemMax CoolTemMin FastHtWter ColHtWter HetHtWter LefHom SwDisFct CoWatOutTemSet
        HeWatOutTemSet CoHomTemSet HeHomTemSet WatBoxTemSet Reset TemRecB Emegcy AllInWatTemHi
        AllInWatTemLo AllOutWatTemHi AllOutWatTemLo HepOutWatTemHi HepOutWatTemLo WatBoxTemHi
        WatBoxTemLo RmoHomTemHi RmoHomTemLo WatBoxElcHeRunSta SyAnFroRunSta ElcHe1RunSta ElcHe2RunSta
        AnFrzzRunSta VersatiSeries WatBoxExt BordTest RomHomTemExt FocModSwh ColColetSwh EndTemCotSwh
        HanFroSwh WatSyExhSwh EVU EleJan EleFeb EleMar EleApr EleMay EleJun EleJul EleAug EleSep EleOct
        EleNov EleDec EleLastYear AddCap AddCapTemMin DREDEn DRED NewGB CoEnvTemSet DEnvTemSet
        WdEnvTemSet HeEnvTemSet FheEnvTemSet CleanData HolidaySwitch HolidayCycle HolidayRemain
        DisinfectSwitch DisinfectStatus DisinfectCycle DisinfectHour DisinfectRemain ECO1 ECO2
        ECO1StartHr ECO1StartMin ECO1EndHr ECO1EndMin ECO2StartHr ECO2StartMin ECO2EndHr ECO2EndMin
        ConsumeDisplayEn ACLkg LkgModEN Hum DeHum AirBoxLgSwt HumSet DeHumSet HECoreCleRes RunModSet
        AutoModEN
    """.split()),
    "1.50": frozenset("""
        SwhWifi SwhWifiRes SwhWifiConf AutoUpdate AutoConnCloud lock datDump datRep datFailRep
        datPeroid subCnt useTCP vender bc mid model series apssid appsw brand catalog country hid host
        mac name time ver city cnty cityid lat lon Pow Mod SetTem WdSpd Tur Quiet SwUpDn SwingLfRig
        TemUn TemRec Lig Air Blo Health SvSt SwhSw HeatCoolType StHt LTemDry Wet SwhSlp SlpMod HasTmr
        TmrLpTms TmrOff TmrOn CurTmHor CurTmMin TmrOnHorLf TmrOnMinLf TmrOffHorLf TmrOffMinLf DsplySt
        EnvFun JFErrorCode AssHt FrshAir AllErr Coolmod MasSub MasIDUMod GetEr CoolSvStTemMin
        HeatSvStTemMax HumiSvStTemMin MaeS FanMod ModS VitiGr GasN TemSor HumSor PM2P5 VOC CO2 PctCle
        PctRe IDUAirQu AirQu ODUViti GasAvail GasLED GasMod GasMas PM2P5Sta SorErr CommErr GasQ RunMod
        Inloop InVitiGr InVitiGrCg IFDtiGr InEffClRes InEffReRes IFDClRes EffReRes ErrType GoOut
        AidHeat SetCoolHumi SetDeciTem SysSta HCHO HCHOEN PM2P5EN MdVitiGr MdVitGrCg MdEffClRes
        MdEffReRes InloopEN Tcloud SorSet Add0.1 Add0.5 HumiEnable TemBody CleanState AutoClean
        CleanTime AutoSetTemEn Light AssHtSet JFerr AntiFreeze CleanEn ExtraMod InSeries HalfTemEn
        ActualWdSpd Heat3DSvStTemMax Heat2SvStTemMax LowDeHumi IDUModSet MasSubEn Can1MasSubEn
        Can1MasSub FClTime PlProg FClRes IDURunMod Humi2SvStTemMin AirLevel Idemand CoolSvStTemMinD
        HumiSvStTemMinD HeatSvStTemMaxD MIdType AppTimer rssi ModelType Heat3DSvStTemMaxD
        Heat2SvStTemMaxD MSysStatus InTem OutTem InHumi ScheCoolTem ScheHeatTem ScheName ScheEnable
        RemoteLock HoldSetTemp Wstate WschTyp Sch1 Sch2 Wtmr1StartHr Wtmr1StartMin Wtmr1EndHr
        Wtmr1EndMin Wtmr2StartHr Wtmr2StartMin Wtmr2EndHr Wtmr2EndMin SetTemInt SetTemDec SwhBw Wmod
        WstpSv WstpH WatTmp Watpercent BwErr BwBoard ComEqui FlagHeat PowHeat IntelCtrl OrderHeat
        ErrHeat HeatTemMax HeatTemInt HeatTemDec Defrost MuteSch1 MuteSch2 Mtmr1StartHr Mtmr1StartMin
        Mtmr1EndHr Mtmr1EndMin Mtmr2StartHr Mtmr2StartMin Mtmr2EndHr Mtmr2EndMin PoolFunc FlagPool
        UaeEn Lamp LigEn ComStatus PumpStatus AuxStatus InTemInt InTemDec OutTemInt OutTemDec
        HeatTemMin CoolTemMax CoolTemMin FastHtWter ColHtWter HetHtWter LefHom SwDisFct CoWatOutTemSet
        HeWatOutTemSet CoHomTemSet HeHomTemSet WatBoxTemSet Reset TemRecB Emegcy AllInWatTemHi
        AllInWatTemLo AllOutWatTemHi AllOutWatTemLo HepOutWatTemHi HepOutWatTemLo WatBoxTemHi
        WatBoxTemLo RmoHomTemHi RmoHomTemLo WatBoxElcHeRunSta SyAnFroRunSta ElcHe1RunSta ElcHe2RunSta
        AnFrzzRunSta VersatiSeries WatBoxExt BordTest RomHomTemExt FocModSwh ColColetSwh EndTemCotSwh
        HanFroSwh WatSyExhSwh EVU EleJan EleFeb EleMar EleApr EleMay EleJun EleJul EleAug EleSep EleOct
        EleNov EleDec EleLastYear AddCap AddCapTemMin DREDEn DRED NewGB CoEnvTemSet DEnvTemSet
        WdEnvTemSet HeEnvTemSet FheEnvTemSet CleanData HolidaySwitch HolidayCycle HolidayRemain
        DisinfectSwitch DisinfectStatus DisinfectCycle DisinfectHour DisinfectRemain ECO1 ECO2
        ECO1StartHr ECO1StartMin ECO1EndHr ECO1EndMin ECO2StartHr ECO2StartMin ECO2EndHr ECO2EndMin
        ConsumeDisplayEn ACLkg LkgModEN Hum DeHum AirBoxLgSwt HumSet DeHumSet HECoreCleRes RunModSet
        AutoModEN NewWind AssistHeat Rinse TemRecC TemRecH AutoTemFlag Buzzer_ON_OFF override DRLevel
        Duration RemainDuration MaxTempRise DRState ElcP ElcAllKwhH ElcAllKwhL DRType DROnline
        TempRiseValid
    """.split()),
    "1.14": frozenset("""
        SwhWifi SwhWifiRes SwhWifiConf AutoUpdate AutoConnCloud lock datDump datRep datFailRep
        datPeroid subCnt useTCP vender bc mid model series apssid appsw brand catalog country hid host
        mac name time ver city cnty cityid lat lon Pow Mod SetTem WdSpd Tur Quiet SwUpDn SwingLfRig
        TemUn TemRec Lig Air Blo Health SvSt SwhSw HeatCoolType StHt LTemDry Wet SwhSlp SlpMod HasTmr
        TmrLpTms TmrOff TmrOn CurTmHor CurTmMin TmrOnHorLf TmrOnMinLf TmrOffHorLf TmrOffMinLf DsplySt
        EnvFun JFErrorCode AssHt FrshAir AllErr Coolmod MasSub MasIDUMod GetEr CoolSvStTemMin
        HeatSvStTemMax HumiSvStTemMin MaeS FanMod ModS VitiGr GasN TemSor HumSor PM2P5 VOC CO2 PctCle
        PctRe IDUAirQu AirQu ODUViti GasAvail GasLED GasMod GasMas PM2P5Sta SorErr CommErr GasQ RunMod
        Inloop InVitiGr InVitiGrCg IFDtiGr InEffClRes InEffReRes IFDClRes EffReRes ErrType GoOut
        AidHeat SetCoolHumi SetDeciTem SysSta HCHO HCHOEN PM2P5EN MdVitiGr MdVitGrCg MdEffClRes
        MdEffReRes InloopEN Tcloud SorSet Add0.1 Add0.5 HumiEnable TemBody CleanState AutoClean
        CleanTime AutoSetTemEn Light AssHtSet JFerr AntiFreeze CleanEn ExtraMod InSeries HalfTemEn
        ActualWdSpd Heat3DSvStTemMax Heat2SvStTemMax LowDeHumi IDUModSet MasSubEn Can1MasSubEn
        Can1MasSub FClTime PlProg FClRes IDURunMod Humi2SvStTemMin AirLevel Idemand CoolSvStTemMinD
        HumiSvStTemMinD HeatSvStTemMaxD MIdType AppTimer rssi ModelType Heat3DSvStTemMaxD
        Heat2SvStTemMaxD MSysStatus InTem OutTem InHumi ScheCoolTem ScheHeatTem ScheName ScheEnable
        RemoteLock HoldSetTemp Wstate WschTyp Sch1 Sch2 Wtmr1StartHr Wtmr1StartMin Wtmr1EndHr
        Wtmr1EndMin Wtmr2StartHr Wtmr2StartMin Wtmr2EndHr Wtmr2EndMin SetTemInt SetTemDec SwhBw Wmod
        WstpSv WstpH WatTmp Watpercent BwErr BwBoard ComEqui FlagHeat PowHeat IntelCtrl OrderHeat
        ErrHeat HeatTemMax HeatTemInt HeatTemDec Defrost MuteSch1 MuteSch2 Mtmr1StartHr Mtmr1StartMin
        Mtmr1EndHr Mtmr1EndMin Mtmr2StartHr Mtmr2StartMin Mtmr2EndHr Mtmr2EndMin PoolFunc FlagPool
        UaeEn Lamp LigEn ComStatus PumpStatus AuxStatus InTemInt InTemDec OutTemInt OutTemDec
        HeatTemMin CoolTemMax CoolTemMin FastHtWter ColHtWter HetHtWter LefHom SwDisFct CoWatOutTemSet
        HeWatOutTemSet CoHomTemSet HeHomTemSet WatBoxTemSet Reset TemRecB Emegcy AllInWatTemHi
        AllInWatTemLo AllOutWatTemHi AllOutWatTemLo HepOutWatTemHi HepOutWatTemLo WatBoxTemHi
        WatBoxTemLo RmoHomTemHi RmoHomTemLo WatBoxElcHeRunSta SyAnFroRunSta ElcHe1RunSta ElcHe2RunSta
        AnFrzzRunSta VersatiSeries WatBoxExt BordTest RomHomTemExt FocModSwh ColColetSwh EndTemCotSwh
        HanFroSwh WatSyExhSwh NoD NoDNoD
    """.split()),
}
