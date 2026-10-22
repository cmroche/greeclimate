"""Recorded status polling presets selected by the reported device MID."""

from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class MidProfile:
    mid: Optional[str]
    status_columns: Tuple[str, ...]
    family: Optional[str] = None


# Unknown device type (fallback for missing or unmatched MID).
FALLBACK_MID_PROFILE = MidProfile(None, ("hid",))


# docs/MIDS.md records polling presets, not exhaustive hardware capabilities.
KNOWN_MID_PROFILES: Tuple[MidProfile, ...] = (
    # Air conditioner.
    MidProfile("0001", (
        "Pow", "HeatCoolType", "Mod", "TemUn", "SetTem", "TemRec", "StHt", "SvSt", "host", "name",
        "AllErr", "ModelType", "Dmod", "Add0.5", "WdSpd", "Quiet", "Tur",
    ), family="air_conditioner"),
    # Air conditioner.
    MidProfile("10f01", (
        "Pow", "HeatCoolType", "Mod", "TemUn", "SetTem", "TemRec", "StHt", "SvSt", "host", "name",
        "AllErr", "ModelType", "WdSpd", "Quiet", "Tur",
    ), family="air_conditioner"),
    # Air conditioner.
    MidProfile("10f02", (
        "Pow", "Mod", "SetTem", "TemRec", "TemUn", "WdSpd", "Quiet", "Add0.5", "ModelType",
        "TemSen", "Tur",
    ), family="air_conditioner"),
    # U-Match air conditioner.
    MidProfile("302b", (
        "Pow", "Mod", "TemUn", "SetTem", "TemRec", "SvSt", "HeatSvStTemMax", "CoolSvStTemMin",
        "TemRecH", "TemRecC", "host", "name", "AllErr", "AutoSetTem", "RemoteLock", "APPNotCtrl",
        "LowDeHumi", "Omod",
    ), family="air_conditioner"),
    # U-Match air conditioner.
    MidProfile("3018", (
        "Pow", "Mod", "TemUn", "SetTem", "TemRec", "SvSt", "HeatSvStTemMax", "CoolSvStTemMin",
        "TemRecH", "TemRecC", "host", "name", "AllErr",
    ), family="air_conditioner"),
    # U-Match air conditioner.
    MidProfile("3019", (
        "Pow", "Mod", "TemUn", "SetTem", "TemRec", "SvSt", "HeatSvStTemMax", "CoolSvStTemMin",
        "TemRecH", "TemRecC", "host", "name", "AllErr", "hid", "GoOut", "LowDeHumi",
    ), family="air_conditioner"),
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
    ), family="air_conditioner"),
    # Commercial air conditioner.
    MidProfile("4005", (
        "Pow", "Mod", "SetTem", "TemRec", "TemUn", "RemoteLock", "WdSpd", "Quiet",
    ), family="air_conditioner"),
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
    ), family="air_conditioner"),
    # Air conditioner.
    MidProfile("10002", (
        "Pow", "Mod", "TemUn", "SetTem", "TemRec", "StHt", "SvSt", "host", "name", "Add0.5",
        "ModelType", "TemSen", "WdSpd", "Quiet", "Tur",
    ), family="air_conditioner"),
    # Air conditioner.
    MidProfile("10007", (
        "Pow", "HeatCoolType", "Mod", "TemUn", "SetTem", "TemRec", "StHt", "SvSt", "host", "name",
        "AllErr", "ModelType", "Dmod", "Add0.5", "WdSpd", "Quiet", "Tur", "TemSen", "hid",
    ), family="air_conditioner"),
    # Unknown device type.
    MidProfile("11000", (
        "Pow", "Mod", "TemUn", "SetTem", "TemRec", "host", "name", "AllErr", "JFErrorCode",
        "Add0.5", "WdSpd", "Quiet", "Tur",
    )),
    # Air conditioner.
    MidProfile("11001", (
        "Pow", "Mod", "TemUn", "SetTem", "TemRec", "host", "name", "WdSpd", "Quiet", "Tur",
    ), family="air_conditioner"),
    # Air conditioner.
    MidProfile("11002", (
        "Pow", "Mod", "TemUn", "SetTem", "TemRec", "host", "name", "WdSpd", "Quiet", "Tur",
    ), family="air_conditioner"),
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
    ), family="air_conditioner"),
    # Window air conditioner.
    MidProfile("12001", (
        "Pow", "HeatCoolType", "Mod", "TemUn", "SetTem", "TemRec", "host", "name", "AllErr",
        "ModelType",
    ), family="air_conditioner"),
    # Window air conditioner.
    MidProfile("12002", (
        "Pow", "HeatCoolType", "Mod", "TemUn", "SetTem", "TemRec", "host", "name", "AllErr",
        "ModelType",
    ), family="air_conditioner"),
    # Window air conditioner.
    MidProfile("12003", (
        "Pow", "HeatCoolType", "Mod", "TemUn", "SetTem", "TemRec", "host", "name", "AllErr",
    ), family="air_conditioner"),
    # Mobile air conditioner.
    MidProfile("13000", (
        "Pow", "HeatCoolType", "Mod", "TemUn", "SetTem", "TemRec", "StHt", "SvSt", "host", "name",
        "AllErr", "ModelType",
    ), family="air_conditioner"),
    # Dehumidifier.
    MidProfile("13800", (
        "Pow", "Dmod", "Dwet", "host", "name", "AllErr",
    ), family="dehumidifier"),
    # Dehumidifier.
    MidProfile("13802", (
        "Pow", "Dmod", "Dwet", "host", "name", "AllErr", "TemSen",
    ), family="dehumidifier"),
    # Dehumidifier.
    MidProfile("13803", (
        "Pow", "Dmod", "Dwet", "host", "name", "AllErr", "TemSen", "DwatFul", "vender",
    ), family="dehumidifier"),
    # Dehumidifier.
    MidProfile("13804", (
        "Pow", "Dmod", "Dwet", "host", "name", "AllErr", "TemSen", "DwatFul",
    ), family="dehumidifier"),
    # Dehumidifier.
    MidProfile("13805", (
        "Pow", "Dmod", "Dwet", "WdSpd", "DwatFul", "Lig", "SwUpDn", "Health", "Quiet", "PM2P5",
        "airQlt", "DwatSen", "ChildLock", "AppTimer", "AllErr", "ModelType", "Dfltr",
    ), family="dehumidifier"),
    # Dehumidifier.
    MidProfile("13806", (
        "Pow", "Dmod", "Dwet", "host", "name", "AllErr", "TemSen", "DwatFul", "vender",
    ), family="dehumidifier"),
    # RV air conditioner.
    MidProfile("15000", (
        "Pow", "HeatCoolType", "Mod", "TemUn", "SetTem", "TemRec", "host", "name",
    ), family="air_conditioner"),
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
    ), family="air_conditioner"),
    # Air cleaner.
    MidProfile("828100", (
        "Pow", "PM2P5", "mode", "wspd", "light", "wipm25", "wopm25", "estate",
    )),
    # Air cleaner.
    MidProfile("828103", (
        "Pow", "PM2P5", "mode", "wspd", "light", "wipm25", "wopm25", "TmrOn", "TmrStatus",
        "TmrHour", "TmrMin", "FiltUT", "FiltBT", "AirChildLock", "LifeTimeMesh_1", "LifeTimeMesh_2",
        "estate1", "estate2", "MeshWarning_1", "MidType", "StTmr", "TmrOff", "FiltUPercent",
        "estate", "JFerr", "MeshWarning1",
    )),
    # Air cleaner.
    MidProfile("828104", (
        "Pow", "PM2P5", "mode", "wspd", "light", "wipm25", "wopm25", "estate",
    )),
    # Air cleaner.
    MidProfile("828105", (
        "Pow", "mode", "wipm25", "light", "FiltUPercent", "FiltUPercent1", "FiltUPercent2", "JFerr",
        "estate", "estate2", "sterilize", "MidType", "wspd", "TmrOn", "TmrOff", "FomadeValue",
        "wifiPermit",
    )),
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
)


def match_mid_profile(mid: Optional[str]) -> MidProfile:
    """Return an exact MID match or the fallback, without normalizing identifiers."""
    if not isinstance(mid, str):
        return FALLBACK_MID_PROFILE
    for profile in KNOWN_MID_PROFILES:
        if profile.mid == mid:
            return profile
    return FALLBACK_MID_PROFILE
