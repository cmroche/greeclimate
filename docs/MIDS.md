# Known MIDs

## Capabilities

| Capability | Typed family | Required MID columns |
| --- | --- | --- |
| `power` | AC, dehumidifier, ATW | `Pow` |
| `mode` | AC, ATW | `Mod` |
| `target_temperature` | AC | `SetTem`, `TemRec`, `TemUn` |
| `temperature_units` | AC, dehumidifier, ATW | `TemUn` |
| `current_temperature` | Both | `TemSen` |
| `fan_speed` | Both | `WdSpd` |
| `fresh_air` | AC | `Air` |
| `xfan` | AC | `Blo` |
| `anion` | Both | `Health` |
| `sleep` | AC | `SwhSlp`, `SlpMod` |
| `light` | Both | `Lig` |
| `horizontal_swing` | AC | `SwingLfRig` |
| `vertical_swing` | Both | `SwUpDn` |
| `quiet` | Both | `Quiet` |
| `turbo` | AC | `Tur` |
| `steady_heat` | AC | `StHt` |
| `power_save` | AC | `SvSt` |
| `lan_buzzer_control` | AC | None: firmware buzzer baseline and explicit overrides |
| `target_humidity` | Dehumidifier | `Dwet` |
| `dehumidifier_mode` | Dehumidifier | `Dmod` |
| `current_humidity` | Dehumidifier | `DwatSen` |
| `clean_filter` | Dehumidifier | `Dfltr` |
| `water_full` | Dehumidifier | `DwatFul` |
| `heating_room_target_temperature_c` | ATW (read-only) | `HeHomTemSet`, `TemUn` |
| `cooling_room_target_temperature_c` | ATW (read-only) | `CoHomTemSet`, `TemUn` |
| `heating_water_target_temperature_c` | ATW | `HeWatOutTemSet`, `TemUn` |
| `cooling_water_target_temperature_c` | ATW | `CoWatOutTemSet`, `TemUn` |
| `tank_target_temperature_c` | ATW | `WatBoxTemSet`, `TemUn` |
| `inlet_water_temperature_c` | ATW | `AllInWatTemHi`, `AllInWatTemLo`, `TemUn` |
| `outlet_water_temperature_c` | ATW | `AllOutWatTemHi`, `AllOutWatTemLo`, `TemUn` |
| `room_temperature_c` | ATW | `RmoHomTemHi`, `RmoHomTemLo`, `TemUn` |
| `tank_temperature_c` | ATW | `WatBoxTemHi`, `WatBoxTemLo`, `TemUn` |

## Catalog

| MID | Device category | Status fields (polling) |
| --- | --- | --- |
| `0001` | Air conditioner | `Pow`, `HeatCoolType`, `Mod`, `TemUn`, `SetTem`, `TemRec`, `StHt`, `SvSt`, `host`, `name`, `AllErr`, `ModelType`, `Dmod`, `Add0.5`, `WdSpd`, `Quiet`, `Tur` |
| `10f01` | Air conditioner | `Pow`, `HeatCoolType`, `Mod`, `TemUn`, `SetTem`, `TemRec`, `StHt`, `SvSt`, `host`, `name`, `AllErr`, `ModelType`, `WdSpd`, `Quiet`, `Tur` |
| `10f02` | Air conditioner | `Pow`, `Mod`, `SetTem`, `TemRec`, `TemUn`, `WdSpd`, `Quiet`, `Add0.5`, `ModelType`, `TemSen`, `Tur` |
| `302b` | U-Match air conditioner | `Pow`, `Mod`, `TemUn`, `SetTem`, `TemRec`, `SvSt`, `HeatSvStTemMax`, `CoolSvStTemMin`, `TemRecH`, `TemRecC`, `host`, `name`, `AllErr`, `AutoSetTem`, `RemoteLock`, `APPNotCtrl`, `LowDeHumi`, `Omod` |
| `3018` | U-Match air conditioner | `Pow`, `Mod`, `TemUn`, `SetTem`, `TemRec`, `SvSt`, `HeatSvStTemMax`, `CoolSvStTemMin`, `TemRecH`, `TemRecC`, `host`, `name`, `AllErr` |
| `3019` | U-Match air conditioner | `Pow`, `Mod`, `TemUn`, `SetTem`, `TemRec`, `SvSt`, `HeatSvStTemMax`, `CoolSvStTemMin`, `TemRecH`, `TemRecC`, `host`, `name`, `AllErr`, `hid`, `GoOut`, `LowDeHumi` |
| `3027` | U-Match air conditioner | `Mod`, `SetDeciTem`, `WdSpd`, `MSysStatus`, `TemUn`, `FClRes`, `CoolSvStTemMinD`, `HeatSvStTemMaxD`, `GetEr`, `InHumi`, `ScheEnable`, `HoldSetTemp`, `InTem`, `ERVSw`, `HumiditySet`, `ModelType`, `HumidiSw`, `ControlMod`, `InstallerName`, `InstallerTel` |
| `3062` | U-Match air conditioner | `Pow`, `Mod`, `TemUn`, `SetTem`, `TemRec`, `SvSt`, `HeatSvStTemMax`, `CoolSvStTemMin`, `TemRecH`, `TemRecC`, `host`, `name`, `AllErr`, `hid`, `GoOut`, `LowDeHumi` |
| `4005` | Commercial air conditioner | `Pow`, `Mod`, `SetTem`, `TemRec`, `TemUn`, `RemoteLock`, `WdSpd`, `Quiet` |
| `5000` | Zone controller | `Pow`, `Mod`, `StTem`, `WdSpd`, `Dry`, `EnSvSt`, `StFahFlg`, `ColdMod`, `HeatSvStTemMax`, `CoolSvStTemMin`, `Dred`, `TemUnit`, `IndoorType`, `OMod`, `LowDeHumi`, `Quier`, `RmType`, `RmNum`, `VavleAllOn`, `CSvStTemMinFlg`, `HSvStTemMaxFlg`, `AllErr`, `InProtocol`, `Demand`, `IntProVer`, `MainConProVer`, `SubConProVer` |
| `5001` | Zone controller | `Pow`, `Mod`, `StTem`, `WdSpd`, `EnSvSt`, `StFahFlg`, `ColdMod`, `HeatSvStTemMax`, `CoolSvStTemMin`, `TemUnit`, `IndoorType`, `OMod`, `LowDeHumi`, `Quier`, `RmType`, `RmNum`, `VavleAllOn`, `CSvStTemMinFlg`, `HSvStTemMaxFlg`, `AllErr`, `InProtocol`, `Demand`, `IntProVer`, `MainConProVer`, `SubConProVer` |
| `6000` | Commercial air conditioner | `Pow`, `Mod`, `SetTem`, `SvSt`, `HeatSvStTemMax`, `HumiSvStTemMin`, `CoolSvStTemMin`, `MasSub`, `GetEr`, `name`, `host`, `GcloudHid`, `GoOut`, `LowDeHumi`, `ExtraMod`, `Heat3DSvStTemMax`, `WdSpd`, `Quiet` |
| `6400` | Commercial air conditioner | `Pow`, `Mod`, `SvSt`, `SetTem`, `Add0.1`, `CleanTime`, `CleanState`, `CoolSvStTemMin`, `HeatSvStTemMax`, `HumiSvStTemMin`, `HumiEnable`, `SetCoolHumi`, `MasSub`, `SetDeciTem`, `SwhSlp`, `Quiet`, `WdSpd`, `SwUpDn`, `SwingLfRig`, `Blo`, `Air`, `AppTimer`, `AutoSetTemEn`, `CleanEn`, `AutoClean`, `ExtraMod`, `InSeries`, `HalfTemEn`, `Heat3DSvStTemMax`, `Heat2SvStTemMax`, `GoOut`, `LowDeHumi`, `Idemand`, `TemUn`, `CoolSvStTemMinD`, `HeatSvStTemMaxD`, `HumiSvStTemMinD`, `Heat3DSvStTemMaxD`, `Heat2SvStTemMaxD`, `TemRec`, `UaeEn`, `LigEn`, `Lamp`, `DREDEn`, `DRED`, `ErrType` |
| `605d` | Fresh-air fan | `Pow`, `FanMod`, `WdSpd`, `GetEr`, `GasQ`, `PctCle`, `PctRe`, `IDUAirQu`, `ODUViti`, `VitiGr`, `ModS`, `GcloudHid` |
| `6098` | Fresh-air fan | `Pow`, `FanMod`, `WdSpd`, `RunMod`, `Inloop`, `IDUAirQu`, `ModS`, `PctCle`, `VitiGr`, `PctRe`, `GetEr`, `ODUViti`, `GasQ`, `InVitiGr`, `InVitiGrCg`, `ErrType`, `MIdType`, `IFDtiGr`, `Mod`, `SetTem`, `TemUn`, `TemRec` |
| `9000` | Unknown | `Pow`, `Wmod`, `WatTmp`, `WsetTmp`, `WstpSv`, `WstpH`, `Werr`, `host` |
| `9300` | Versati air-to-water heat pump | `Pow`, `Mod`, `CoWatOutTemSet`, `HeWatOutTemSet`, `WatBoxTemSet`, `TemUn`, `TemRec`, `AllErr`, `host`, `name`, `ColHtWter`, `HetHtWter`, `LefHom`, `TemRecB`, `RomHomTemExt`, `CoHomTemSet`, `HeHomTemSet`, `ModelType`, `Emegcy`, `EndTemCotSwh`, `WDTemSet`, `SvSt`, `ZoneCtr` |
| `9301` | Hot-water equipment | `Pow`, `Mod`, `CoWatOutTemSet`, `HeWatOutTemSet`, `WatBoxTemSet`, `TemUn`, `TemRec`, `AllErr`, `host`, `name`, `ColHtWter`, `HetHtWter`, `LefHom`, `TemRecB`, `RomHomTemExt`, `CoHomTemSet`, `HeHomTemSet` |
| `9302` | Pool heater | `FlagPool`, `Pow`, `AllErr`, `Wmod`, `PoolFunc`, `SetTemInt`, `SetTemDec`, `InTemInt`, `InTemDec`, `OutTemInt`, `OutTemDec`, `HeatTemMax`, `HeatTemMin`, `CoolTemMax`, `CoolTemMin`, `TemUn` |
| `10001` | Air conditioner | `Pow`, `HeatCoolType`, `Mod`, `TemUn`, `SetTem`, `TemRec`, `StHt`, `SvSt`, `host`, `name`, `AllErr`, `ModelType`, `Dmod`, `Add0.5`, `WdSpd`, `Quiet`, `Tur`, `TemSen`, `hid` |
| `10002` | Air conditioner | `Pow`, `Mod`, `TemUn`, `SetTem`, `TemRec`, `StHt`, `SvSt`, `host`, `name`, `Add0.5`, `ModelType`, `TemSen`, `WdSpd`, `Quiet`, `Tur` |
| `10007` | Air conditioner | `Pow`, `HeatCoolType`, `Mod`, `TemUn`, `SetTem`, `TemRec`, `StHt`, `SvSt`, `host`, `name`, `AllErr`, `ModelType`, `Dmod`, `Add0.5`, `WdSpd`, `Quiet`, `Tur`, `TemSen`, `hid` |
| `11000` | Unknown | `Pow`, `Mod`, `TemUn`, `SetTem`, `TemRec`, `host`, `name`, `AllErr`, `JFErrorCode`, `Add0.5`, `WdSpd`, `Quiet`, `Tur` |
| `11001` | Air conditioner | `Pow`, `Mod`, `TemUn`, `SetTem`, `TemRec`, `host`, `name`, `WdSpd`, `Quiet`, `Tur` |
| `11002` | Air conditioner | `Pow`, `Mod`, `TemUn`, `SetTem`, `TemRec`, `host`, `name`, `WdSpd`, `Quiet`, `Tur` |
| `11005` | Unknown | `Pow`, `Mod`, `SetTem`, `WdSpd`, `Add0.5`, `Air`, `name`, `TemUn`, `TemRec`, `StHt`, `ModelType`, `TemSen`, `Quiet`, `Tur` |
| `11010` | Unknown | `Pow`, `Mod`, `TemUn`, `SetTem`, `TemRec`, `host`, `name`, `WdSpd`, `Quiet`, `Tur` |
| `12000` | Window air conditioner | `Pow`, `HeatCoolType`, `Mod`, `TemUn`, `SetTem`, `TemRec`, `host`, `name` |
| `12001` | Window air conditioner | `Pow`, `HeatCoolType`, `Mod`, `TemUn`, `SetTem`, `TemRec`, `host`, `name`, `AllErr`, `ModelType` |
| `12002` | Window air conditioner | `Pow`, `HeatCoolType`, `Mod`, `TemUn`, `SetTem`, `TemRec`, `host`, `name`, `AllErr`, `ModelType` |
| `12003` | Window air conditioner | `Pow`, `HeatCoolType`, `Mod`, `TemUn`, `SetTem`, `TemRec`, `host`, `name`, `AllErr` |
| `13000` | Mobile air conditioner | `Pow`, `HeatCoolType`, `Mod`, `TemUn`, `SetTem`, `TemRec`, `StHt`, `SvSt`, `host`, `name`, `AllErr`, `ModelType` |
| `13800` | Dehumidifier | `Pow`, `Dmod`, `Dwet`, `host`, `name`, `AllErr` |
| `13802` | Dehumidifier | `Pow`, `Dmod`, `Dwet`, `host`, `name`, `AllErr`, `TemSen` |
| `13803` | Dehumidifier | `Pow`, `Dmod`, `Dwet`, `host`, `name`, `AllErr`, `TemSen`, `DwatFul`, `vender` |
| `13804` | Dehumidifier | `Pow`, `Dmod`, `Dwet`, `host`, `name`, `AllErr`, `TemSen`, `DwatFul` |
| `13805` | Dehumidifier | `Pow`, `Dmod`, `Dwet`, `WdSpd`, `DwatFul`, `Lig`, `SwUpDn`, `Health`, `Quiet`, `PM2P5`, `airQlt`, `DwatSen`, `ChildLock`, `AppTimer`, `AllErr`, `ModelType`, `Dfltr` |
| `13806` | Dehumidifier | `Pow`, `Dmod`, `Dwet`, `host`, `name`, `AllErr`, `TemSen`, `DwatFul`, `vender` |
| `15000` | RV air conditioner | `Pow`, `HeatCoolType`, `Mod`, `TemUn`, `SetTem`, `TemRec`, `host`, `name` |
| `82000` | Unknown | `subSize`, `AllPow` |
| `82002` | Unknown | `ver` |
| `807002` | Commercial air conditioner | `Pow`, `Mod`, `SetTem`, `Add0.1`, `TemSetMax`, `TemSetMin`, `WdSpd`, `AllErr`, `TemUn`, `TemRec`, `SvSt` |
| `809032` | Air conditioner | `Pow`, `HeatCoolType`, `Mod`, `TemUn`, `SetTem`, `TemRec`, `StHt`, `SvSt`, `host`, `name`, `AllErr`, `ModelType`, `Dmod`, `Add0.5`, `WdSpd`, `Quiet`, `Tur` |
| `828100` | Air cleaner | `Pow`, `PM2P5`, `mode`, `wspd`, `light`, `wipm25`, `wopm25`, `estate` |
| `828103` | Air cleaner | `Pow`, `PM2P5`, `mode`, `wspd`, `light`, `wipm25`, `wopm25`, `TmrOn`, `TmrStatus`, `TmrHour`, `TmrMin`, `FiltUT`, `FiltBT`, `AirChildLock`, `LifeTimeMesh_1`, `LifeTimeMesh_2`, `estate1`, `estate2`, `MeshWarning_1`, `MidType`, `StTmr`, `TmrOff`, `FiltUPercent`, `estate`, `JFerr`, `MeshWarning1` |
| `828104` | Air cleaner | `Pow`, `PM2P5`, `mode`, `wspd`, `light`, `wipm25`, `wopm25`, `estate` |
| `828105` | Air cleaner | `Pow`, `mode`, `wipm25`, `light`, `FiltUPercent`, `FiltUPercent1`, `FiltUPercent2`, `JFerr`, `estate`, `estate2`, `sterilize`, `MidType`, `wspd`, `TmrOn`, `TmrOff`, `FomadeValue`, `wifiPermit` |
| `828140` | Air cleaner | `Pow`, `Wspd`, `Mode`, `EnvHumidity`, `SetHumidity`, `PM25`, `AirChildLock`, `FiltUPercent`, `ReplaceFilter`, `RefreshWater`, `TmrHour`, `TmrMin`, `TmrOn`, `TmrAction`, `Light`, `estate1`, `estate2`, `estate3`, `MidType`, `wifiPermit` |
| `828500` | Unknown | `Pow`, `wspd`, `estate` |
| `828501` | Unknown | `Pow`, `FogLevel`, `mode`, `UVLight`, `WaterTankLight`, `TmrHour`, `TmrMin`, `TmrOn`, `TmrAction`, `estate1` |
| `910001` | Hot-water equipment | `Pow`, `AllErr`, `Wmod`, `SetTemInt`, `SetTemDec`, `TemUn`, `host`, `name`, `WstpSv`, `WstpH`, `Wstate`, `Watpercent` |
| `910004` | Hot-water equipment | `Pow`, `AllErr`, `Wmod`, `SetTemInt`, `SetTemDec`, `WstpSv`, `WstpH`, `WatTmp`, `Watpercent`, `TemUn`, `Wstate`, `ModelType` |
| `910005` | Hot-water equipment | `Pow`, `AllErr`, `Wmod`, `SetTemInt`, `SetTemDec`, `TemUn`, `host`, `name`, `WstpSv`, `WstpH`, `Wstate`, `Watpercent` |
| `gf001` | Unknown | `PSSGoCPwr`, `PVGenedPwr` |
| `828214` | Fan | `Pow`, `WdSpd`, `Mod`, `Rotate`, `LRAngle`, `TmrHour`, `TmrMin`, `TmrOn`, `TmrAction`, `JFerr`, `LRHeadAngle`, `Quiet`, `OSD`, `estate`, `rssi`, `StepWdSpd` |
| `80361` | Unknown | `ver`, `MGPowCtrlStat` |
| `6036` | Unknown | `WPow`, `Wmod`, `FPow`, `WCurTem`, `WtmrMin`, `WtmrHr`, `Watpercent`, `FCurTem`, `SetTem`, `FSetTem`, `GetEr`, `WFConfig`, `IDUID`, `MidType`, `MIdType` |
| `60` | Multi-unit gateway | `hid` (observed on a WB05BR gateway; other requested fields were empty) |
| `10014` | Unknown (raw; no typed family) | `Pow`, `Mod`, `SetTem`, `WdSpd`, `TemSen` |
| `10015` | Unknown (raw; no typed family) | `Pow`, `Mod`, `SetTem`, `WdSpd`, `TemSen` |
| `10016` | Unknown (raw; no typed family) | `Pow`, `Mod`, `SetTem`, `WdSpd`, `TemSen` |
| `10017` | Unknown (raw; no typed family) | `Pow`, `Mod`, `SetTem`, `WdSpd`, `TemSen` |
| `11f00` | Unknown (raw; no typed family) | `Pow`, `Mod`, `SetTem`, `WdSpd`, `TemSen` |
| `11f01` | Unknown (raw; no typed family) | `Pow`, `Mod`, `SetTem`, `WdSpd`, `TemSen` |
| `11f02` | Unknown (raw; no typed family) | `Pow`, `Mod`, `SetTem`, `WdSpd`, `TemSen` |
| `11f03` | Unknown (raw; no typed family) | `Pow`, `Mod`, `SetTem`, `WdSpd`, `TemSen` |
| `10f05` | Unknown (raw; no typed family) | `SetTem`, `Pow`, `TemSen`, `Mod` |
| `10010` | Unknown (raw; no typed family) | `SetTem`, `Pow`, `TemSen`, `Mod` |
| `10011` | Unknown (raw; no typed family) | `SetTem`, `Pow`, `TemSen`, `Mod` |
| `11011` | Unknown (raw; no typed family) | `SetTem`, `Pow`, `TemSen`, `Mod` |
| `11012` | Unknown (raw; no typed family) | `SetTem`, `Pow`, `TemSen`, `Mod` |
| `6049` | Gateway (raw; no typed family) | `Pow`, `Mod`, `SetTem`, `TemBody` |
| `604a` | Gateway (raw; no typed family) | `Pow`, `Mod`, `SetTem`, `TemBody` |
| `604b` | Gateway (raw; no typed family) | `Pow`, `Mod`, `SetTem`, `TemBody` |
| `604c` | Gateway (raw; no typed family) | `Pow`, `Mod`, `SetTem`, `TemBody` |
| `605c` | Gateway (raw; no typed family) | `Pow`, `Mod`, `SetTem`, `TemBody` |
| `608f` | Gateway (raw; no typed family) | `Pow`, `Mod`, `SetTem`, `TemBody` |
| `6092` | Gateway (raw; no typed family) | `Pow`, `Mod`, `SetTem`, `TemBody` |
| `6045` | Gateway (raw; no typed family) | `Pow`, `Mod`, `SetTem`, `WdSpd`, `InTem` |
| `609d` | Gateway (raw; no typed family) | `Pow`, `Mod`, `SetTem`, `WdSpd`, `InTem` |
| `50` | Zone controller (raw; no typed family) | `MasterPow`, `Mod`, `WdSpd` |

