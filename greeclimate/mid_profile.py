"""Exact MID polling presets and declared protocol feature support."""

from dataclasses import dataclass
from typing import Dict, Optional, Tuple


# Composite features require every field used by their typed encoding/decoder.
_CAPABILITY_COLUMNS = {
    "power": ("Pow",),
    "mode": ("Mod",),
    "target_temperature": ("SetTem", "TemRec", "TemUn"),
    "temperature_units": ("TemUn",),
    "current_temperature": ("TemSen",),
    "fan_speed": ("WdSpd",),
    "fresh_air": ("Air",),
    "xfan": ("Blo",),
    "anion": ("Health",),
    "sleep": ("SwhSlp", "SlpMod"),
    "light": ("Lig",),
    "horizontal_swing": ("SwingLfRig",),
    "vertical_swing": ("SwUpDn",),
    "quiet": ("Quiet",),
    "turbo": ("Tur",),
    "steady_heat": ("StHt",),
    "power_save": ("SvSt",),
    "target_humidity": ("Dwet",),
    "dehumidifier_mode": ("Dmod",),
    "current_humidity": ("DwatSen",),
    "clean_filter": ("Dfltr",),
    "water_full": ("DwatFul",),
    "inlet_water_temperature_c": ("AllInWatTemHi", "AllInWatTemLo", "TemUn"),
    "outlet_water_temperature_c": ("AllOutWatTemHi", "AllOutWatTemLo", "TemUn"),
    "room_temperature_c": ("RmoHomTemHi", "RmoHomTemLo", "TemUn"),
    "tank_temperature_c": ("WatBoxTemHi", "WatBoxTemLo", "TemUn"),
    "heating_room_target_temperature_c": ("HeHomTemSet", "TemUn"),
    "cooling_room_target_temperature_c": ("CoHomTemSet", "TemUn"),
    "heating_water_target_temperature_c": ("HeWatOutTemSet", "TemUn"),
    "cooling_water_target_temperature_c": ("CoWatOutTemSet", "TemUn"),
    "tank_target_temperature_c": ("WatBoxTemSet", "TemUn"),
}


@dataclass(frozen=True)
class MidProfile:
    mid: Optional[str]
    status_columns: Tuple[str, ...]
    family: Optional[str] = None

    @property
    def capabilities(self) -> Dict[str, bool]:
        """Declared fields establish features, not every writable value or hardware effect."""
        if self.mid is None or self.family is None:
            return {}
        columns = frozenset(self.status_columns)
        return {
            name: True for name, required in _CAPABILITY_COLUMNS.items()
            if columns.issuperset(required)
        }


# Unknown device type.
FALLBACK_MID_PROFILE = MidProfile(None, ("hid",))


# Fan.
_FAN_COLUMNS = (
    "Pow", "WdSpd", "Mod", "Rotate", "Cycle", "SwUpDn", "SwingLfRig", "Wet", "Anion",
    "HotWind", "TmrHour", "TmrMin", "TmrOn", "TmrAction", "SmartMod", "WetLevel", "Light",
    "UpDnAngle", "LRAngle", "Temperature", "PM25", "estate", "estate1", "estate2", "estate3",
    "JFerr", "MidType", "hid", "time", "rssi", "ver",
)
# W04R shares these MIDs: exactly 30 names empties its source scan, >30 is unsafe,
# and ver has no datum. Preserve all fan fields; rssi/ver remain explicit reads.
_SMALL_FAN_COLUMNS = tuple(name for name in _FAN_COLUMNS if name not in ("rssi", "ver"))

# Heater.
_HEATER_COLUMNS = (
    "Pow", "Humidification", "Swing", "ChildLock", "HeatLevel", "SetTemp", "EnvTemp",
    "WorkTimeHour", "WorkTimeSec", "RealHeatLevel", "FanLevel", "HeatMode", "TmrOn",
    "TmrAction", "TmrHour", "TmrMin", "estate", "estate2", "estate3", "JFerr", "MidType", "hid",
    "time", "rssi", "ver",
)
# Water purifier.
_PURIFIER_COLUMNS = (
    "WorkStatus", "TotalPureWater", "FilterNum", "LifeTimeFilter1", "LifeTimeFilter2",
    "LifeTimeFilter3", "LifeTimeFilter4", "LifeTimeFilter5", "FilterWarning1",
    "FilterWarning2", "FilterWarning3", "FilterWarning4", "FilterWarning5",
    "LifeFilterDays1", "LifeFilterDays2", "LifeFilterDays3", "LifeFilterDays4",
    "LifeFilterDays5", "FilterKind1", "FilterKind2", "FilterKind3", "FilterKind4",
    "FilterKind5", "ErrorCode1", "ErrorCode2", "JFerr", "MidType", "hid",
    "time", "rssi", "ver",
)

# Fresh-air fan.
_FRESH_AIR_COLUMNS = (
    "MIdType", "WdSpd", "Tur", "ModS", "FanMod", "RunMod", "Inloop", "IDUAirQu", "ODUViti",
    "PctCle", "PctRe", "IFDtiGr", "InVitiGr", "InVitiGrCg", "VitiGr", "ErrType", "GasQ",
    "TemSor", "HumSor", "AirQu", "PM2P5", "VOC", "CO2", "SorErr", "CommErr", "GasAvail",
    "GasLED", "GasMod", "GasMas", "PM2P5Sta", "GetEr", "Pow", "Mod", "SetTem", "ExWdSpd",
    "TemRec", "TemUn",
)
# Photovoltaic energy controller (WB05BR).
_ENERGY_COLUMNS = (
    "MIdType", "PvTotEngy", "NewGridTotEngy", "OldGridTotEngy", "PVGenedPwr", "PSSGoCPwr",
    "TotalEle", "ElcEn", "CalMeth",
)
# W06K selects status mode from the final column; keep HID before the sensors.
_SENSOR_HOST_COLUMNS = (
    "hid", "Pow", "LigPow", "ScrTime", "AutoCtr", "TemSor", "HumSor", "HCHO", "PM2P5", "CO2",
    "VOC", "InAirQuality", "SensorErr", "BatteryWarn",
)

_WASHER_COLUMNS = (
    "Pow", "PauseStart", "Wash", "Mod", "Disinfect", "Lock", "Lighting", "Purifier", "Dry",
    "LayerWash", "PurifierTime", "WashDone", "RmTmrHour", "RmTmrMin", "WorkStatus", "TmrOn",
    "TmrStatus", "TmrHour", "TmrMin", "SetWaterHard", "WaterHardPram", "SetDetergent",
    "DeterLevel", "estate1", "estate2", "estate3", "JFerr", "MidType",
)
_COOKER_COLUMNS = (
    "Pow", "mode", "StTmr", "TmrOn", "TmrEn", "SchTmr", "SchOnOff", "SchEn", "Textre", "Rice",
    "sealve", "Prsure", "KpTpTmr", "KpTpOnOff", "KpTpEn", "Lig", "ModeTmr", "StpRic", "Runlight",
    "Volt", "ElcP", "TmpUp", "TmpDn", "estate", "estate2", "estate3", "estate4", "JFerr", "MidType",
)
_HOT_WATER_COLUMNS = (
    "Pow", "Wmod", "WsetTmp", "WsetTmpC", "PrvHeat", "Wout", "SvSt", "WschOn", "HydPrs",
    "SenTmpC", "SenTmp", "UseTime", "UseTimeAll", "TapNum", "TapNumAll", "PersonNum", "Machine",
    "AboveSeaLev", "SvLineType", "SvLine", "TmrOnHour", "TmrOnMin", "TmrOn", "TmrOffHour",
    "TmrOffMin", "TmrOff", "Werr", "estate", "estate1", "estate2", "estate3", "estate4", "estate5",
)
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
    ), family="air_to_water"),
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
    # Mainboard device.
    MidProfile("13801", (
        "Pow", "Dmod", "Dwet", "host", "name",
    )),
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
    # Hydronic controller.
    MidProfile("809030", (
        "hid", "Pow", "Mod", "Quiet", "SvSt", "TemUn", "Temp", "WtTemp", "HtSetTem",
        "ColSetTem", "HtWtSetTem", "ColWtSetTem", "Er",
    )),
    # Air conditioner.
    MidProfile("809032", (
        "Pow", "HeatCoolType", "Mod", "TemUn", "SetTem", "TemRec", "StHt", "SvSt", "host", "name",
        "AllErr", "ModelType", "Dmod", "Add0.5", "WdSpd", "Quiet", "Tur",
    ), family="air_conditioner"),
    # Air cleaner.
    MidProfile("828100", (
        "Pow", "PM2P5", "mode", "wspd", "light", "wipm25", "wopm25", "estate",
        "AirChildLock", "FiltUT", "FiltBT", "ErrorCode", "FiltUPercent", "LifeTimeMesh1",
        "LifeTimeMesh2", "MeshWarning1", "FomadeValue", "TmrOff", "TmrOn", "StTmr",
        "RemLifePerErr1", "RemLifePerErr2", "estate1", "estate2", "JFerr", "MidType",
        "meshid", "LifeTimeError", "MsgPM", "fltrst", "hid",
        "time", "rssi", "ver",
    )),
    # Air cleaner.
    MidProfile("828101", _AIR_CLEANER_COLUMNS),
    MidProfile("828102", _AIR_CLEANER_COLUMNS),
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
    # Humidifier.
    MidProfile("828503", ("UV", "Mode", "Sleep", "HumiditySet", "hid", "time", "rssi")),
    # Cooking appliance.
    MidProfile("828600", (
        "Pow", "wspd", "mode", "light", "gesture", "RightCooker", "LeftCooker", "CookerBattery",
        "estate", "estate2", "JFerr", "MidType",
    )),
    MidProfile("828900", ("hid",)),
    # Washer.
    MidProfile("828901", ("Wash", "Dry", "hid", "time")),
    # Washer.
    MidProfile("828902", _WASHER_COLUMNS),
    # Washer.
    MidProfile("828903", _WASHER_COLUMNS),
    # Washer.
    MidProfile("828b00", _WASHER_COLUMNS),
    # Hot-water equipment.
    MidProfile("828c00", _HOT_WATER_COLUMNS),
    # Hot-water equipment.
    MidProfile("828c01", (
        "Pow", "Mode", "WaterSetTemp", "BurnState", "SelfTestOkState", "Fan", "BurnOffValve2",
        "BurnOffValve1", "WaterRateValve", "GasRateValve", "GasSafeValve", "Firearm", "WaterPump",
        "WaterFlow", "InputWaterInt", "InputWaterFloat", "OutputWaterInt", "EnvTempInt", "EnvTempFloat",
        "WindSensor", "TempLimiter", "Windswitch", "FireNeedle", "estate", "estate2", "estate3",
        "estate4", "estate5", "JFerr", "MidType",
    )),
    # Hot-water equipment.
    MidProfile("828c02", _HOT_WATER_COLUMNS),
    # Cooking appliance.
    MidProfile("828d04", (
        "Pow", "ChildLock", "RunStat", "Pause", "Mod", "List1", "List2", "List3", "List4", "List5",
        "SetHour", "SetMin", "SetTmp", "TmrHour", "TmrMin", "DisTmp", "DisSetHour", "DisSetMin",
        "DisTmrHour", "DisTmrMin", "TmpCtrl", "MachStat", "estate1", "estate2", "estate3", "estate4",
        "estate5", "JFerr", "MidType", "CloudMenu",
    )),
    # Hot-water equipment.
    MidProfile("8600", _HOT_WATER_COLUMNS),
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
    ), family="gateway"),
    # Unknown device type.
    MidProfile("10014", ("Pow", "Mod", "SetTem", "WdSpd", "TemSen")),
    # Unknown device type.
    MidProfile("10015", ("Pow", "Mod", "SetTem", "WdSpd", "TemSen")),
    # Unknown device type.
    MidProfile("10016", ("Pow", "Mod", "SetTem", "WdSpd", "TemSen")),
    # Unknown device type.
    MidProfile("10017", ("Pow", "Mod", "SetTem", "WdSpd", "TemSen")),
    # Unknown device type.
    MidProfile("11f00", ("Pow", "Mod", "SetTem", "WdSpd", "TemSen")),
    # Unknown device type.
    MidProfile("11f01", ("Pow", "Mod", "SetTem", "WdSpd", "TemSen")),
    # Unknown device type.
    MidProfile("11f02", ("Pow", "Mod", "SetTem", "WdSpd", "TemSen")),
    # Unknown device type.
    MidProfile("11f03", ("Pow", "Mod", "SetTem", "WdSpd", "TemSen")),
    # Unknown device type.
    MidProfile("10f05", ("SetTem", "Pow", "TemSen", "Mod")),
    # Unknown device type.
    MidProfile("10010", ("SetTem", "Pow", "TemSen", "Mod")),
    # Unknown device type.
    MidProfile("10011", ("SetTem", "Pow", "TemSen", "Mod")),
    # Unknown device type.
    MidProfile("11011", ("SetTem", "Pow", "TemSen", "Mod")),
    # Unknown device type.
    MidProfile("11012", ("SetTem", "Pow", "TemSen", "Mod")),
    # Gateway.
    MidProfile("6049", ("Pow", "Mod", "SetTem", "TemBody")),
    # Gateway.
    MidProfile("604a", ("Pow", "Mod", "SetTem", "TemBody")),
    # Gateway.
    MidProfile("604b", ("Pow", "Mod", "SetTem", "TemBody")),
    # Gateway.
    MidProfile("604c", ("Pow", "Mod", "SetTem", "TemBody")),
    # Gateway.
    MidProfile("605c", ("Pow", "Mod", "SetTem", "TemBody")),
    # Gateway.
    MidProfile("608f", ("Pow", "Mod", "SetTem", "TemBody")),
    # Gateway.
    MidProfile("6092", ("Pow", "Mod", "SetTem", "TemBody")),
    # Gateway.
    MidProfile("6045", ("Pow", "Mod", "SetTem", "WdSpd", "InTem")),
    # Gateway.
    MidProfile("609d", ("Pow", "Mod", "SetTem", "WdSpd", "InTem")),
    # Zone Controller.
    MidProfile("50", ("MasterPow", "Mod", "WdSpd")),
    # Fresh-air fan.
    MidProfile("6079", ("Pow", "FanMod", "WdSpd", "GetEr")),
    # Gateway controller.
    MidProfile("70501", ()),
    # Cloud gateway controller.
    MidProfile("70503", ()),
    # Infrared controller.
    MidProfile("80221", (
        "Pow", "Mod", "SwhSlp", "SwhSw", "WdSpd", "SetTem", "Blo", "Health", "Lig", "Air",
        "SwUpDn", "SwingLfRig", "SvSt", "SlpMod", "Tur", "Quiet", "StHt", "IntradayElect",
        "IntradayElectPow", "IntradayElectLim", "AutoPowDown", "ProTimeReminder",
        "RealTimePower", "AppTimer", "ProTimeLen", "ProTimePow", "Studied", "AddButton",
        "ConBtnNum", "ConBtnName", "DelButton", "SendButton", "Electnumzero", "hid", "time",
    )),
    # Air-quality sensor host.
    MidProfile("80241", _SENSOR_HOST_COLUMNS),
    MidProfile("80242", _SENSOR_HOST_COLUMNS),
    # Voice/infrared controller.
    MidProfile("80222", (
        "Pow", "Mod", "SwhSlp", "SwhSw", "WdSpd", "SetTem", "Blo", "Health", "Lig", "TemUn",
        "TemRec", "Air", "SwUpDn", "SwingLfRig", "SvSt", "StHt", "Intellblo1", "AirOpen",
        "SlpMod", "Tur", "Quiet", "VoltErr", "CurrErr", "PowerErr", "RelayErr", "ACCntlrShape",
        "AppTimer", "RealTimePower", "Savpow", "ProTimePow", "ProTimeLen", "ProTimeReminder",
        "SendButton", "AddButton", "DelButton", "Studied", "ConBtnNum", "ConBtnName",
        "Electnumzero", "hid", "time", "MidType", "VoiceVolume", "VoiceGate",
    )),
    # Alarm cache.
    MidProfile("80260", (
        "Pow", "WorkState", "AlarmCancel", "AlarmTmrEnable", "AlarmTime", "host", "name",
        "rssi", "hid", "InHid", "OEEPHid", "AllErr",
    )),
    # People-counting radar.
    MidProfile("80261", (
        "WorkState", "count", "border", "JFerr", "doorenable", "doortotal", "host", "ver",
        "name", "rssi", "hid", "InHid", "OEEPHid", "InHidDownPer", "devinhidownver",
        "induptype",
    )),
    # Gateway.
    MidProfile("80300", (
        "Mesh", "Meshota", "SubOnline", "Random", "Unbind", "Subcount", "Meshid", "Onoff",
        "Scene", "BleStatus", "AdminRadom", "host", "name", "time", "lat", "lon", "vender",
        "hid", "mac", "ver", "BtHid",
    )),
    # BLE provisioning host.
    MidProfile("80305", ()),
    # Power controller.
    MidProfile("80801", (
        "Pow", "CountDownTime", "CountDownState", "CountDownFlag", "RealTimeVoltage",
        "RealTimeEleCurrent", "RealTimePower", "EnergyOfTime", "EnergyOfTimeFlag",
        "StartTime", "EndTime", "hid", "time", "MessagePushFlag", "rssi",
    )),
    # Central controller.
    MidProfile("80901", (
        "Mesh", "Meshota", "SubOnline", "Proaddr", "Random", "Unbind", "Subcount", "Pow",
        "Meshid", "Onoff", "text", "hid", "mac", "InHid", "OEEPHid", "BtHid", "GcloudHid",
        "time",
    )),
    MidProfile("828200", ("hid",)),
    # Fan.
    MidProfile("828202", _SMALL_FAN_COLUMNS),
    MidProfile("828203", _SMALL_FAN_COLUMNS),
    MidProfile("828204", _SMALL_FAN_COLUMNS),
    MidProfile("828205", _FAN_COLUMNS),
    MidProfile("828208", _FAN_COLUMNS),
    MidProfile("828209", _FAN_COLUMNS),
    MidProfile("828210", _FAN_COLUMNS),
    MidProfile("828211", _FAN_COLUMNS),
    # Fan.
    MidProfile("828212", (
        "Pow", "WdSpd", "Mod", "Rotate", "Cycle", "SwUpDn", "SwingLfRig", "Wet", "Anion",
        "HotwindOnOff", "HotWind", "TmrHour", "TmrMin", "TmrOn", "TmrAction", "SmartMod", "WetLevel",
        "Light", "UpDnAngle", "LRAngle", "Temperature", "PM25", "estate", "estate1", "estate2",
        "estate3", "JFerr", "MidType",
    )),
    MidProfile("828213", _FAN_COLUMNS),
    # Heater.
    MidProfile("828a00", _HEATER_COLUMNS),
    MidProfile("828a01", _HEATER_COLUMNS),
    MidProfile("828a02", _HEATER_COLUMNS),
    MidProfile("828a03", _HEATER_COLUMNS),
    MidProfile("828a04", _HEATER_COLUMNS),
    MidProfile("828a05", _HEATER_COLUMNS),
    # Water purifier.
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
    # Cooking appliance.
    MidProfile("828402", _COOKER_COLUMNS),
    # Cooking appliance.
    MidProfile("828403", _COOKER_COLUMNS),
    # Cooking appliance.
    MidProfile("828404", _COOKER_COLUMNS),
    # Cooking appliance.
    MidProfile("828405", _COOKER_COLUMNS),
    # Water softener.
    MidProfile("829000", (
        "Pow", "Status", "SaltStatus", "RecycleStatus", "MotorStatus", "RecycleRemainT",
        "RecycleTotalT", "InsFlowRate", "CycleFlowRate", "SaltTotalT", "RecycleHour",
        "RecycleMin", "BJHour", "BJMin", "BJSec", "TmrOn", "TmrAction", "TmrHour",
        "TmrMin", "eState", "JFerr", "MidType", "hid",
        "time", "rssi", "ver",
    )),
    # Water-treatment equipment.
    MidProfile("829100", (
        "SetTemp", "Cruise", "Mode", "Pow", "PreBoost", "BurnState", "CruiseState", "InWaterTemp",
        "ErrorCode1", "ErrorCode2", "ErrorCode3", "JFerr", "MidType",
    )),
    # Fresh-air fan.
    MidProfile("6084", _FRESH_AIR_COLUMNS),
    MidProfile("608d", _FRESH_AIR_COLUMNS),
    MidProfile("6091", _FRESH_AIR_COLUMNS),
    MidProfile("6099", _FRESH_AIR_COLUMNS),
    MidProfile("60a0", _FRESH_AIR_COLUMNS),
    MidProfile("60a4", _FRESH_AIR_COLUMNS),
    MidProfile("60a9", _FRESH_AIR_COLUMNS),
    # Photovoltaic energy controller.
    MidProfile("6083", _ENERGY_COLUMNS),
    MidProfile("6094", _ENERGY_COLUMNS),
)


def match_mid_profile(mid: Optional[str]) -> MidProfile:
    """Return an exact MID match or the fallback, without normalizing identifiers."""
    if not isinstance(mid, str):
        return FALLBACK_MID_PROFILE
    for profile in KNOWN_MID_PROFILES:
        if profile.mid == mid:
            return profile
    return FALLBACK_MID_PROFILE
