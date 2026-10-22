# Known MIDs

### MID required-column mapping

Column names are exact and case-sensitive. This mapping is filtered to the selected family's typed API; for example, `Dmod` in an AC preset does not add a dehumidifier operation. Presence declares feature support under this policy, not independent proof that every corresponding LAN write or value is accepted.

| Capability key(s) | Required status column(s) |
| --- | --- |
| `power`, `mode` | `Pow`, `Mod`, respectively |
| `target_temperature` | All of `SetTem`, `TemRec`, `TemUn` |
| `temperature_units`, `current_temperature`, `fan_speed` | `TemUn`, `TemSen`, `WdSpd`, respectively |
| `fresh_air`, `xfan`, `anion` | `Air`, `Blo`, `Health`, respectively |
| `sleep` | Both `SwhSlp` and `SlpMod` |
| `light`, `horizontal_swing`, `vertical_swing`, `quiet` | `Lig`, `SwingLfRig`, `SwUpDn`, `Quiet`, respectively |
| `turbo`, `steady_heat`, `power_save` | `Tur`, `StHt`, `SvSt`, respectively |
| `target_humidity`, `dehumidifier_mode`, `current_humidity`, `clean_filter`, `water_full` | `Dwet`, `Dmod`, `DwatSen`, `Dfltr`, `DwatFul`, respectively |
| `heating_room_target_temperature_c`, `cooling_room_target_temperature_c` | `HeHomTemSet`, `CoHomTemSet`, respectively, plus `TemUn` |
| `heating_water_target_temperature_c`, `cooling_water_target_temperature_c`, `tank_target_temperature_c` | `HeWatOutTemSet`, `CoWatOutTemSet`, `WatBoxTemSet`, respectively, plus `TemUn` |
| `inlet_water_temperature_c` | `AllInWatTemHi`, `AllInWatTemLo`, `TemUn` |
| `outlet_water_temperature_c` | `AllOutWatTemHi`, `AllOutWatTemLo`, `TemUn` |
| `room_temperature_c` | `RmoHomTemHi`, `RmoHomTemLo`, `TemUn` |
| `tank_temperature_c` | `WatBoxTemHi`, `WatBoxTemLo`, `TemUn` |

MID `9300` owns declarations for power, mode, read-only temperature units and all five target features. Its historical preset lacks the four sensor high/low pairs: the ATW class's automatic polling extension does not promote them to MID evidence. Firmware-code selector evidence can establish those sensor paths. `lan_buzzer_control` is never derived from MID.

## MID catalog

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
| `10014`, `10015`, `10016`, `10017`, `11f00`, `11f01`, `11f02`, `11f03` | W04N native runtime routes; raw-only | `Pow`, `Mod`, `SetTem`, `WdSpd`, `TemSen` |
| `10f05`, `10010`, `10011`, `11011`, `11012` | WB04A native runtime routes; raw-only | `SetTem`, `Pow`, `TemSen`, `Mod` |
| `6049`, `604a`, `604b`, `604c`, `605c`, `608f`, `6092` | W06AV parent-routed indoor units | `Pow`, `Mod`, `SetTem`, `TemBody` |
| `6045`, `609d` | WB04BRT13 parent-routed indoor units | `Pow`, `Mod`, `SetTem`, `WdSpd`, `InTem` |
| `50` | W05SA zone container | `MasterPow`, `Mod`, `WdSpd` |
