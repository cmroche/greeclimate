"""Recorded status polling presets selected by the reported device MID."""

from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class MidProfile:
    mid: Optional[str]
    status_columns: Tuple[str, ...]


# Unknown device type (fallback for missing or unmatched MID).
FALLBACK_MID_PROFILE = MidProfile(None, (
    "Pow", "Mod", "Dwet", "DwatSen", "Dfltr", "DwatFul", "Dmod", "SetTem", "TemSen", "TemUn",
    "TemRec", "WdSpd", "Air", "Blo", "Health", "SwhSlp", "SlpMod", "Lig", "SwingLfRig", "SwUpDn",
    "Quiet", "Tur", "StHt", "SvSt", "HeatCoolType",
))

# Shared exact source column lists for MIDs with the same polling schema.
_AIR_CLEANER_COLUMNS = (
    "Pow", "wspd", "mode", "PM2P5", "light", "AirChildLock", "FiltUT", "FiltBT", "wipm25",
    "wopm25", "ErrorCode", "FiltUPercent", "FiltUPercent1", "FiltUPercent2", "MeshWarning1",
    "sterilize", "FomadeValue", "TmrOff", "TmrOn", "StTmr", "RemLifePerErr1", "RemLifePerErr2",
    "estate", "estate1", "estate2", "JFerr", "MidType",
)

_EXTENDED_AIR_CLEANER_COLUMNS = (
    "Pow", "wspd", "mode", "PM2P5", "light", "AirChildLock", "FiltUT", "FiltBT", "wipm25",
    "wopm25", "ErrorCode", "FiltUPercent", "FiltUPercent1", "FiltUPercent2", "MeshWarning1",
    "sterilize", "FomadeValue", "TmrOff", "TmrOn", "StTmr", "RemLifePerErr1", "RemLifePerErr2",
    "estate", "estate1", "estate2", "JFerr", "MidType", "LifeTimeMesh1", "LifeTimeMesh2",
    "meshid", "LifeTimeError", "MsgPM", "fltrst", "hid",
)

_WASHER_COLUMNS = (
    "Pow", "PauseStart", "Wash", "Mod", "Disinfect", "Lock", "Lighting", "Purifier", "Dry",
    "LayerWash", "PurifierTime", "WashDone", "RmTmrHour", "RmTmrMin", "WorkStatus", "TmrOn",
    "TmrStatus", "TmrHour", "TmrMin", "SetWaterHard", "WaterHardPram", "SetDetergent",
    "DeterLevel", "estate1", "estate2", "estate3", "JFerr", "MidType",
)

_SMALL_FAN_COLUMNS = (
    "Pow", "WdSpd", "Mod", "Rotate", "Cycle", "SwUpDn", "SwingLfRig", "Wet", "Anion",
    "HotWind", "TmrHour", "TmrMin", "TmrOn", "TmrAction", "SmartMod", "WetLevel", "Light",
    "UpDnAngle", "LRAngle", "Temperature", "PM25", "estate", "estate1", "estate2", "estate3",
    "JFerr", "MidType", "hid", "time",
)

_FAN_COLUMNS = (
    "Pow", "WdSpd", "Mod", "Rotate", "Cycle", "SwUpDn", "SwingLfRig", "Wet", "Anion",
    "HotWind", "TmrHour", "TmrMin", "TmrOn", "TmrAction", "SmartMod", "WetLevel", "Light",
    "UpDnAngle", "LRAngle", "Temperature", "PM25", "estate", "estate1", "estate2", "estate3",
    "JFerr", "MidType", "hid", "time", "rssi", "ver",
)

_PURIFIER_COLUMNS = (
    "WorkStatus", "TotalPureWater", "FilterNum", "LifeTimeFilter1", "LifeTimeFilter2",
    "LifeTimeFilter3", "LifeTimeFilter4", "LifeTimeFilter5", "FilterWarning1",
    "FilterWarning2", "FilterWarning3", "FilterWarning4", "FilterWarning5", "LifeFilterDays1",
    "LifeFilterDays2", "LifeFilterDays3", "LifeFilterDays4", "LifeFilterDays5", "FilterKind1",
    "FilterKind2", "FilterKind3", "FilterKind4", "FilterKind5", "ErrorCode1", "ErrorCode2",
    "JFerr", "MidType", "hid", "time", "rssi", "ver",
)

_COOKER_COLUMNS = (
    "Pow", "mode", "StTmr", "TmrOn", "TmrEn", "SchTmr", "SchOnOff", "SchEn", "Textre", "Rice",
    "sealve", "Prsure", "KpTpTmr", "KpTpOnOff", "KpTpEn", "Lig", "ModeTmr", "StpRic",
    "Runlight", "Volt", "ElcP", "TmpUp", "TmpDn", "estate", "estate2", "estate3", "estate4",
    "JFerr", "MidType",
)

_HEATER_COLUMNS = (
    "Pow", "Humidification", "Swing", "ChildLock", "HeatLevel", "SetTemp", "EnvTemp",
    "WorkTimeHour", "WorkTimeSec", "RealHeatLevel", "FanLevel", "HeatMode", "TmrOn",
    "TmrAction", "TmrHour", "TmrMin", "estate", "estate2", "estate3", "JFerr", "MidType",
    "hid", "time", "rssi", "ver",
)

_HOT_WATER_COLUMNS = (
    "Pow", "Wmod", "WsetTmp", "WsetTmpC", "PrvHeat", "Wout", "SvSt", "WschOn", "HydPrs",
    "SenTmpC", "SenTmp", "UseTime", "UseTimeAll", "TapNum", "TapNumAll", "PersonNum",
    "Machine", "AboveSeaLev", "SvLineType", "SvLine", "TmrOnHour", "TmrOnMin", "TmrOn",
    "TmrOffHour", "TmrOffMin", "TmrOff", "Werr", "estate", "estate1", "estate2", "estate3",
    "estate4", "estate5",
)


_SENSOR_HOST_COLUMNS = (
    "hid", "Pow", "LigPow", "ScrTime", "AutoCtr", "TemSor", "HumSor", "HCHO", "PM2P5", "CO2",
    "VOC", "InAirQuality", "SensorErr", "BatteryWarn",
)


# docs/MIDS.md records polling presets, not exhaustive hardware capabilities.
KNOWN_MID_PROFILES: Tuple[MidProfile, ...] = (
    # Air conditioner.
    MidProfile("0001", (
        "Pow", "HeatCoolType", "Mod", "TemUn", "SetTem", "TemRec", "StHt", "SvSt", "host", "name",
        "AllErr", "ModelType", "Dmod", "Add0.5", "WdSpd", "Quiet", "Tur",
    )),
    # Air conditioner.
    MidProfile("10f01", (
        "Pow", "HeatCoolType", "Mod", "TemUn", "SetTem", "TemRec", "StHt", "SvSt", "host", "name",
        "AllErr", "ModelType", "WdSpd", "Quiet", "Tur",
    )),
    # Air conditioner.
    MidProfile("10f02", (
        "Pow", "Mod", "SetTem", "TemRec", "TemUn", "WdSpd", "Quiet", "Add0.5", "ModelType",
        "TemSen", "Tur",
    )),
    # U-Match air conditioner.
    MidProfile("302b", (
        "Pow", "Mod", "TemUn", "SetTem", "TemRec", "SvSt", "HeatSvStTemMax", "CoolSvStTemMin",
        "TemRecH", "TemRecC", "host", "name", "AllErr", "AutoSetTem", "RemoteLock", "APPNotCtrl",
        "LowDeHumi", "Omod",
    )),
    # U-Match air conditioner.
    MidProfile("3018", (
        "Pow", "Mod", "TemUn", "SetTem", "TemRec", "SvSt", "HeatSvStTemMax", "CoolSvStTemMin",
        "TemRecH", "TemRecC", "host", "name", "AllErr",
    )),
    # U-Match air conditioner.
    MidProfile("3019", (
        "Pow", "Mod", "TemUn", "SetTem", "TemRec", "SvSt", "HeatSvStTemMax", "CoolSvStTemMin",
        "TemRecH", "TemRecC", "host", "name", "AllErr", "hid", "GoOut", "LowDeHumi",
    )),
    # U-Match air conditioner.
    MidProfile("3027", (
        "Mod", "SetDeciTem", "WdSpd", "MSysStatus", "TemUn", "FClRes", "CoolSvStTemMinD",
        "HeatSvStTemMaxD", "GetEr", "InHumi", "ScheEnable", "HoldSetTemp", "InTem", "ERVSw",
        "HumiditySet", "ModelType", "HumidiSw", "ControlMod", "InstallerName", "InstallerTel",
    )),
    # U-Match air conditioner.
    MidProfile("3062", (
        "Pow", "Mod", "TemUn", "SetTem", "TemRec", "SvSt", "HeatSvStTemMax", "CoolSvStTemMin",
        "TemRecH", "TemRecC", "host", "name", "AllErr", "hid", "GoOut", "LowDeHumi",
    )),
    # Commercial air conditioner.
    MidProfile("4005", (
        "Pow", "Mod", "SetTem", "TemRec", "TemUn", "RemoteLock", "WdSpd", "Quiet",
    )),
    # Zone controller.
    MidProfile("5000", (
        "Pow", "Mod", "StTem", "WdSpd", "Dry", "EnSvSt", "StFahFlg", "ColdMod", "HeatSvStTemMax",
        "CoolSvStTemMin", "Dred", "TemUnit", "IndoorType", "OMod", "LowDeHumi", "Quier", "RmType",
        "RmNum", "VavleAllOn", "CSvStTemMinFlg", "HSvStTemMaxFlg", "AllErr", "InProtocol", "Demand",
        "IntProVer", "MainConProVer", "SubConProVer",
    )),
    # Zone controller.
    MidProfile("5001", (
        "Pow", "Mod", "StTem", "WdSpd", "EnSvSt", "StFahFlg", "ColdMod", "HeatSvStTemMax",
        "CoolSvStTemMin", "TemUnit", "IndoorType", "OMod", "LowDeHumi", "Quier", "RmType", "RmNum",
        "VavleAllOn", "CSvStTemMinFlg", "HSvStTemMaxFlg", "AllErr", "InProtocol", "Demand",
        "IntProVer", "MainConProVer", "SubConProVer",
    )),
    # Commercial air conditioner.
    MidProfile("6000", (
        "Pow", "Mod", "SetTem", "SvSt", "HeatSvStTemMax", "HumiSvStTemMin", "CoolSvStTemMin",
        "MasSub", "GetEr", "name", "host", "GcloudHid", "GoOut", "LowDeHumi", "ExtraMod",
        "Heat3DSvStTemMax", "WdSpd", "Quiet",
    )),
    # Commercial air conditioner.
    MidProfile("6400", (
        "Pow", "Mod", "SvSt", "SetTem", "Add0.1", "CleanTime", "CleanState", "CoolSvStTemMin",
        "HeatSvStTemMax", "HumiSvStTemMin", "HumiEnable", "SetCoolHumi", "MasSub", "SetDeciTem",
        "SwhSlp", "Quiet", "WdSpd", "SwUpDn", "SwingLfRig", "Blo", "Air", "AppTimer",
        "AutoSetTemEn", "CleanEn", "AutoClean", "ExtraMod", "InSeries", "HalfTemEn",
        "Heat3DSvStTemMax", "Heat2SvStTemMax", "GoOut", "LowDeHumi", "Idemand", "TemUn",
        "CoolSvStTemMinD", "HeatSvStTemMaxD", "HumiSvStTemMinD", "Heat3DSvStTemMaxD",
        "Heat2SvStTemMaxD", "TemRec", "UaeEn", "LigEn", "Lamp", "DREDEn", "DRED", "ErrType",
    )),
    # Fresh-air fan.
    MidProfile("605d", (
        "Pow", "FanMod", "WdSpd", "GetEr", "GasQ", "PctCle", "PctRe", "IDUAirQu", "ODUViti",
        "VitiGr", "ModS", "GcloudHid",
    )),
    # Fresh-air fan.
    MidProfile("6098", (
        "Pow", "FanMod", "WdSpd", "RunMod", "Inloop", "IDUAirQu", "ModS", "PctCle", "VitiGr",
        "PctRe", "GetEr", "ODUViti", "GasQ", "InVitiGr", "InVitiGrCg", "ErrType", "MIdType",
        "IFDtiGr", "Mod", "SetTem", "TemUn", "TemRec",
    )),
    # Unknown device type.
    MidProfile("9000", (
        "Pow", "Wmod", "WatTmp", "WsetTmp", "WstpSv", "WstpH", "Werr", "host",
    )),
    # Versati air-to-water heat pump.
    MidProfile("9300", (
        "Pow", "Mod", "CoWatOutTemSet", "HeWatOutTemSet", "WatBoxTemSet", "TemUn", "TemRec",
        "AllErr", "host", "name", "ColHtWter", "HetHtWter", "LefHom", "TemRecB", "RomHomTemExt",
        "CoHomTemSet", "HeHomTemSet", "ModelType", "Emegcy", "EndTemCotSwh", "WDTemSet", "SvSt",
        "ZoneCtr",
    )),
    # Hot-water equipment.
    MidProfile("9301", (
        "Pow", "Mod", "CoWatOutTemSet", "HeWatOutTemSet", "WatBoxTemSet", "TemUn", "TemRec",
        "AllErr", "host", "name", "ColHtWter", "HetHtWter", "LefHom", "TemRecB", "RomHomTemExt",
        "CoHomTemSet", "HeHomTemSet",
    )),
    # Pool heater.
    MidProfile("9302", (
        "FlagPool", "Pow", "AllErr", "Wmod", "PoolFunc", "SetTemInt", "SetTemDec", "InTemInt",
        "InTemDec", "OutTemInt", "OutTemDec", "HeatTemMax", "HeatTemMin", "CoolTemMax",
        "CoolTemMin", "TemUn",
    )),
    # Air conditioner.
    MidProfile("10001", (
        "Pow", "HeatCoolType", "Mod", "TemUn", "SetTem", "TemRec", "StHt", "SvSt", "host", "name",
        "AllErr", "ModelType", "Dmod", "Add0.5", "WdSpd", "Quiet", "Tur", "TemSen", "hid",
    )),
    # Air conditioner.
    MidProfile("10002", (
        "Pow", "Mod", "TemUn", "SetTem", "TemRec", "StHt", "SvSt", "host", "name", "Add0.5",
        "ModelType", "TemSen", "WdSpd", "Quiet", "Tur",
    )),
    # Air conditioner.
    MidProfile("10007", (
        "Pow", "HeatCoolType", "Mod", "TemUn", "SetTem", "TemRec", "StHt", "SvSt", "host", "name",
        "AllErr", "ModelType", "Dmod", "Add0.5", "WdSpd", "Quiet", "Tur", "TemSen", "hid",
    )),
    # Unknown device type.
    MidProfile("11000", (
        "Pow", "Mod", "TemUn", "SetTem", "TemRec", "host", "name", "AllErr", "JFErrorCode",
        "Add0.5", "WdSpd", "Quiet", "Tur",
    )),
    # Air conditioner.
    MidProfile("11001", (
        "Pow", "Mod", "TemUn", "SetTem", "TemRec", "host", "name", "WdSpd", "Quiet", "Tur",
    )),
    # Air conditioner.
    MidProfile("11002", (
        "Pow", "Mod", "TemUn", "SetTem", "TemRec", "host", "name", "WdSpd", "Quiet", "Tur",
        "TemSen", "Air", "Blo", "Health", "SwhSlp", "SlpMod", "Lig", "SwingLfRig", "SwUpDn",
        "StHt", "SvSt", "HeatCoolType",
    )),
    # Unknown device type.
    MidProfile("11005", (
        "Pow", "Mod", "SetTem", "WdSpd", "Add0.5", "Air", "name", "TemUn", "TemRec", "StHt",
        "ModelType", "TemSen", "Quiet", "Tur",
    )),
    # Unknown device type.
    MidProfile("11010", (
        "Pow", "Mod", "TemUn", "SetTem", "TemRec", "host", "name", "WdSpd", "Quiet", "Tur",
    )),
    # Window air conditioner.
    MidProfile("12000", (
        "Pow", "HeatCoolType", "Mod", "TemUn", "SetTem", "TemRec", "host", "name",
    )),
    # Window air conditioner.
    MidProfile("12001", (
        "Pow", "HeatCoolType", "Mod", "TemUn", "SetTem", "TemRec", "host", "name", "AllErr",
        "ModelType",
    )),
    # Window air conditioner.
    MidProfile("12002", (
        "Pow", "HeatCoolType", "Mod", "TemUn", "SetTem", "TemRec", "host", "name", "AllErr",
        "ModelType",
    )),
    # Window air conditioner.
    MidProfile("12003", (
        "Pow", "HeatCoolType", "Mod", "TemUn", "SetTem", "TemRec", "host", "name", "AllErr",
    )),
    # Mobile air conditioner.
    MidProfile("13000", (
        "Pow", "HeatCoolType", "Mod", "TemUn", "SetTem", "TemRec", "StHt", "SvSt", "host", "name",
        "AllErr", "ModelType",
    )),
    # Dehumidifier.
    MidProfile("13800", (
        "Pow", "Dmod", "Dwet", "host", "name", "AllErr",
    )),
    # Dehumidifier.
    MidProfile("13802", (
        "Pow", "Dmod", "Dwet", "host", "name", "AllErr", "TemSen",
    )),
    # Dehumidifier.
    MidProfile("13803", (
        "Pow", "Dmod", "Dwet", "host", "name", "AllErr", "TemSen", "DwatFul", "vender",
    )),
    # Dehumidifier.
    MidProfile("13804", (
        "Pow", "Dmod", "Dwet", "host", "name", "AllErr", "TemSen", "DwatFul",
    )),
    # Dehumidifier.
    MidProfile("13805", (
        "Pow", "Dmod", "Dwet", "WdSpd", "DwatFul", "Lig", "SwUpDn", "Health", "Quiet", "PM2P5",
        "airQlt", "DwatSen", "ChildLock", "AppTimer", "AllErr", "ModelType", "Dfltr",
    )),
    # Dehumidifier.
    MidProfile("13806", (
        "Pow", "Dmod", "Dwet", "host", "name", "AllErr", "TemSen", "DwatFul", "vender",
    )),
    # RV air conditioner.
    MidProfile("15000", (
        "Pow", "HeatCoolType", "Mod", "TemUn", "SetTem", "TemRec", "host", "name",
    )),
    # Unknown device type.
    MidProfile("82000", (
        "subSize", "AllPow",
    )),
    # Unknown device type.
    MidProfile("82002", (
        "ver",
    )),
    # Commercial air conditioner.
    MidProfile("807002", (
        "Pow", "Mod", "SetTem", "Add0.1", "TemSetMax", "TemSetMin", "WdSpd", "AllErr", "TemUn",
        "TemRec", "SvSt",
    )),
    # Air conditioner.
    MidProfile("809032", (
        "Pow", "HeatCoolType", "Mod", "TemUn", "SetTem", "TemRec", "StHt", "SvSt", "host", "name",
        "AllErr", "ModelType", "Dmod", "Add0.5", "WdSpd", "Quiet", "Tur",
    )),
    # Air cleaner.
    MidProfile("828100", (
        "Pow", "PM2P5", "mode", "wspd", "light", "wipm25", "wopm25", "estate", "AirChildLock",
        "FiltUT", "FiltBT", "ErrorCode", "FiltUPercent", "LifeTimeMesh1", "LifeTimeMesh2",
        "MeshWarning1", "FomadeValue", "TmrOff", "TmrOn", "StTmr", "RemLifePerErr1",
        "RemLifePerErr2", "estate1", "estate2", "JFerr", "MidType", "meshid", "LifeTimeError",
        "MsgPM", "fltrst", "hid", "time", "rssi", "ver",
    )),
    # Air cleaner.
    MidProfile("828103", _EXTENDED_AIR_CLEANER_COLUMNS),
    # Air cleaner.
    MidProfile("828104", (
        "Pow", "PM2P5", "mode", "wspd", "light", "wipm25", "wopm25", "estate",
    )),
    # Air cleaner.
    MidProfile("828105", _EXTENDED_AIR_CLEANER_COLUMNS),
    # Air cleaner.
    MidProfile("828140", (
        "Pow", "Wspd", "Mode", "EnvHumidity", "SetHumidity", "PM25", "AirChildLock", "FiltUPercent",
        "ReplaceFilter", "RefreshWater", "TmrHour", "TmrMin", "TmrOn", "TmrAction", "Light",
        "estate1", "estate2", "estate3", "MidType", "wifiPermit",
    )),
    # Unknown device type.
    MidProfile("828500", (
        "Pow", "wspd", "estate",
    )),
    # Unknown device type.
    MidProfile("828501", (
        "Pow", "FogLevel", "mode", "UVLight", "WaterTankLight", "TmrHour", "TmrMin", "TmrOn",
        "TmrAction", "estate1",
    )),
    # Hot-water equipment.
    MidProfile("910001", (
        "Pow", "AllErr", "Wmod", "SetTemInt", "SetTemDec", "TemUn", "host", "name", "WstpSv",
        "WstpH", "Wstate", "Watpercent",
    )),
    # Hot-water equipment.
    MidProfile("910004", (
        "Pow", "AllErr", "Wmod", "SetTemInt", "SetTemDec", "WstpSv", "WstpH", "WatTmp",
        "Watpercent", "TemUn", "Wstate", "ModelType",
    )),
    # Hot-water equipment.
    MidProfile("910005", (
        "Pow", "AllErr", "Wmod", "SetTemInt", "SetTemDec", "TemUn", "host", "name", "WstpSv",
        "WstpH", "Wstate", "Watpercent",
    )),
    # Unknown device type.
    MidProfile("gf001", (
        "PSSGoCPwr", "PVGenedPwr",
    )),
    # Fan.
    MidProfile("828214", (
        "Pow", "WdSpd", "Mod", "Rotate", "LRAngle", "TmrHour", "TmrMin", "TmrOn", "TmrAction",
        "JFerr", "LRHeadAngle", "Quiet", "OSD", "estate", "rssi", "StepWdSpd",
    )),
    # Unknown device type.
    MidProfile("80361", (
        "ver", "MGPowCtrlStat",
    )),
    # Unknown device type.
    MidProfile("6036", (
        "WPow", "Wmod", "FPow", "WCurTem", "WtmrMin", "WtmrHr", "Watpercent", "FCurTem", "SetTem",
        "FSetTem", "GetEr", "WFConfig", "IDUID", "MidType", "MIdType",
    )),
    # Multi-unit gateway.
    MidProfile("60", (
        "hid",
    )),

    # Source-qualified direct status columns supported by Device.
    MidProfile("13801", (
        "Pow", "Dmod", "Dwet", "host", "name",
    )),
    MidProfile("809030", (
        "hid", "Pow", "Mod", "Quiet", "SvSt", "TemUn", "Temp", "WtTemp", "HtSetTem",
        "ColSetTem", "HtWtSetTem", "ColWtSetTem", "Er",
    )),
    MidProfile("828101", _AIR_CLEANER_COLUMNS),
    MidProfile("828102", _AIR_CLEANER_COLUMNS),
    MidProfile("828600", (
        "Pow", "wspd", "mode", "light", "gesture", "RightCooker", "LeftCooker",
        "CookerBattery", "estate", "estate2", "JFerr", "MidType",
    )),
    MidProfile("828900", (
        "hid",
    )),
    MidProfile("828901", _WASHER_COLUMNS),
    MidProfile("828902", _WASHER_COLUMNS),
    MidProfile("828903", _WASHER_COLUMNS),
    MidProfile("828b00", _WASHER_COLUMNS),
    MidProfile("828c00", _HOT_WATER_COLUMNS),
    MidProfile("828c01", (
        "Pow", "Mode", "WaterSetTemp", "BurnState", "SelfTestOkState", "Fan", "BurnOffValve2",
        "BurnOffValve1", "WaterRateValve", "GasRateValve", "GasSafeValve", "Firearm",
        "WaterPump", "WaterFlow", "InputWaterInt", "InputWaterFloat", "OutputWaterInt",
        "EnvTempInt", "EnvTempFloat", "WindSensor", "TempLimiter", "Windswitch", "FireNeedle",
        "estate", "estate2", "estate3", "estate4", "estate5", "JFerr", "MidType",
    )),
    MidProfile("828c02", _HOT_WATER_COLUMNS),
    MidProfile("828d04", (
        "Pow", "ChildLock", "RunStat", "Pause", "Mod", "List1", "List2", "List3", "List4",
        "List5", "SetHour", "SetMin", "SetTmp", "TmrHour", "TmrMin", "DisTmp", "DisSetHour",
        "DisSetMin", "DisTmrHour", "DisTmrMin", "TmpCtrl", "MachStat", "estate1", "estate2",
        "estate3", "estate4", "estate5", "JFerr", "MidType", "CloudMenu",
    )),
    MidProfile("8600", _HOT_WATER_COLUMNS),
    # Retains every generic AC climate field; omits only unrelated dehumidifier fallback columns.
    MidProfile("11012", (
        "Pow", "Mod", "TemUn", "SetTem", "TemRec", "TemSen", "WdSpd", "Air", "Blo", "Health",
        "SwhSlp", "SlpMod", "Lig", "SwingLfRig", "SwUpDn", "Quiet", "Tur", "StHt", "SvSt",
        "HeatCoolType",
    )),
    MidProfile("50", (
        "MasterPow", "Mod", "WdSpd",
    )),
    MidProfile("80221", (
        "Pow", "Mod", "SwhSlp", "SwhSw", "WdSpd", "SetTem", "Blo", "Health", "Lig", "Air",
        "SwUpDn", "SwingLfRig", "SvSt", "SlpMod", "Tur", "Quiet", "StHt", "IntradayElect",
        "IntradayElectPow", "IntradayElectLim", "AutoPowDown", "ProTimeReminder", "RealTimePower",
        "AppTimer", "ProTimeLen", "ProTimePow", "Studied", "AddButton", "ConBtnNum", "ConBtnName",
        "DelButton", "SendButton", "Electnumzero", "hid", "time",
    )),
    MidProfile("80241", _SENSOR_HOST_COLUMNS),
    MidProfile("80242", _SENSOR_HOST_COLUMNS),
    MidProfile("80222", (
        "Pow", "Mod", "SwhSlp", "SwhSw", "WdSpd", "SetTem", "Blo", "Health", "Lig", "TemUn",
        "TemRec", "Air", "SwUpDn", "SwingLfRig", "SvSt", "StHt", "Intellblo1", "AirOpen",
        "SlpMod", "Tur", "Quiet", "VoltErr", "CurrErr", "PowerErr", "RelayErr", "ACCntlrShape",
        "AppTimer", "RealTimePower", "Savpow", "ProTimePow", "ProTimeLen", "ProTimeReminder",
        "SendButton", "AddButton", "DelButton", "Studied", "ConBtnNum", "ConBtnName",
        "Electnumzero", "hid", "time", "MidType", "VoiceVolume", "VoiceGate",
    )),
    MidProfile("80260", (
        "Pow", "WorkState", "AlarmCancel", "AlarmTmrEnable", "AlarmTime", "host", "name",
        "rssi", "hid", "InHid", "OEEPHid", "AllErr",
    )),
    MidProfile("80261", (
        "WorkState", "count", "border", "JFerr", "doorenable", "doortotal", "host", "ver",
        "name", "rssi", "hid", "InHid", "OEEPHid", "InHidDownPer", "devinhidownver",
        "induptype",
    )),
    MidProfile("80300", (
        "Mesh", "Meshota", "SubOnline", "Random", "Unbind", "Subcount", "Meshid", "Onoff",
        "Scene", "BleStatus", "AdminRadom", "host", "name", "time", "lat", "lon", "vender",
        "hid", "mac", "ver", "BtHid",
    )),
    MidProfile("80801", (
        "Pow", "CountDownTime", "CountDownState", "CountDownFlag", "RealTimeVoltage",
        "RealTimeEleCurrent", "RealTimePower", "EnergyOfTime", "EnergyOfTimeFlag", "StartTime",
        "EndTime", "hid", "time", "MessagePushFlag", "rssi",
    )),
    MidProfile("828200", (
        "hid",
    )),
    MidProfile("828202", _SMALL_FAN_COLUMNS),
    MidProfile("828203", _SMALL_FAN_COLUMNS),
    MidProfile("828204", _SMALL_FAN_COLUMNS),
    MidProfile("828205", _FAN_COLUMNS),
    MidProfile("828208", _FAN_COLUMNS),
    MidProfile("828209", _FAN_COLUMNS),
    MidProfile("828210", _FAN_COLUMNS),
    MidProfile("828211", _FAN_COLUMNS),
    MidProfile("828212", (
        "Pow", "WdSpd", "Mod", "Rotate", "Cycle", "SwUpDn", "SwingLfRig", "Wet", "Anion",
        "HotwindOnOff", "HotWind", "TmrHour", "TmrMin", "TmrOn", "TmrAction", "SmartMod",
        "WetLevel", "Light", "UpDnAngle", "LRAngle", "Temperature", "PM25", "estate",
        "estate1", "estate2", "estate3", "JFerr", "MidType",
    )),
    MidProfile("828213", _FAN_COLUMNS),
    MidProfile("828a00", _HEATER_COLUMNS),
    MidProfile("828a01", _HEATER_COLUMNS),
    MidProfile("828a02", _HEATER_COLUMNS),
    MidProfile("828a03", _HEATER_COLUMNS),
    MidProfile("828a04", _HEATER_COLUMNS),
    MidProfile("828a05", _HEATER_COLUMNS),
    MidProfile("828301", _PURIFIER_COLUMNS),
    MidProfile("828306", _PURIFIER_COLUMNS),
    MidProfile("828307", _PURIFIER_COLUMNS),
    MidProfile("828308", _PURIFIER_COLUMNS),
    MidProfile("828309", _PURIFIER_COLUMNS),
    MidProfile("828310", _PURIFIER_COLUMNS),
    MidProfile("828401", (
        "mode", "Pow", "Lig", "StTmr", "TmrOn", "TmrEn", "ModeTmr", "SchTmr", "SchOnOff",
        "SchEn", "Rice", "Textre", "Prsure", "sealve", "KpTpTmr", "KpTpOnOFF", "KpTpEn",
        "StpRic", "Volt", "ElcP", "TmpUp", "TmpDn", "estate", "estate2", "estate3", "estate4",
    )),
    MidProfile("828402", _COOKER_COLUMNS),
    MidProfile("828403", _COOKER_COLUMNS),
    MidProfile("828404", _COOKER_COLUMNS),
    MidProfile("828405", _COOKER_COLUMNS),
    MidProfile("829000", (
        "Pow", "Status", "SaltStatus", "RecycleStatus", "MotorStatus", "RecycleRemainT",
        "RecycleTotalT", "InsFlowRate", "CycleFlowRate", "SaltTotalT", "RecycleHour",
        "RecycleMin", "BJHour", "BJMin", "BJSec", "TmrOn", "TmrAction", "TmrHour", "TmrMin",
        "eState", "JFerr", "MidType", "hid", "time", "rssi", "ver",
    )),
    MidProfile("829100", (
        "SetTemp", "Cruise", "Mode", "Pow", "PreBoost", "BurnState", "CruiseState",
        "InWaterTemp", "ErrorCode1", "ErrorCode2", "ErrorCode3", "JFerr", "MidType",
    )),
)


def match_mid_profile(mid: Optional[str]) -> MidProfile:
    """Return an exact MID match or the fallback, without normalizing identifiers."""
    if not isinstance(mid, str):
        return FALLBACK_MID_PROFILE
    for profile in KNOWN_MID_PROFILES:
        if profile.mid == mid:
            return profile
    return FALLBACK_MID_PROFILE
