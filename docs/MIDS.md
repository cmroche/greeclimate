# Known MIDs

A MID is the `mid` string in discovery metadata or a gateway's `subList`. Keep its case, letters and leading zeros. It is separate from the firmware identifier (`hid`); see [HIDS.md](HIDS.md) and [gateway observations](#gateway-observations-and-sources).

`DeviceInfo.mid` stores the discovery value separately from `model`; missing MID is `None`. At construction, `Device` matches it exactly against `greeclimate/mid_profile.py` and keeps that profile for its lifetime. `create_device()` selects `AirConditionerDevice`, `DehumidifierDevice`, or `AirToWaterDevice` only for explicitly registered families; ATW selection requires exactly `"9300"`. Otherwise it returns neutral `Device`. Matching preserves case and leading zeros without coercion or trimming. Model names and reported HIDs never substitute for a MID or change the selected family.

A matched profile requests its fields in the listed order, even fields outside `Props`. `hid` is appended only while firmware identity is unknown and the preset lacks it. A preset that includes `hid` keeps requesting it: MID `60` always polls `["hid"]`. Missing, malformed, unknown or not-established MIDs use `FALLBACK_MID_PROFILE` (`mid=None`), whose neutral polling list is only `["hid"]`. `match_mid_profile()` always returns a profile. `update_state(columns)` sends explicit columns unchanged, without adding identity fields.

Direct family construction remains available when the caller knows the appliance but its MID is missing or unregistered. `AirConditionerDevice` then polls `Pow`, `Mod`, `SetTem`, `TemUn`, `TemRec`, `TemSen`; `DehumidifierDevice` polls `Pow`, `Dmod`, `Dwet`, `DwatSen`, `Dfltr`, `DwatFul`, `TemSen`, `TemUn`, `TemRec`, `WdSpd`, `Lig`, `SwUpDn`, `Health`, `Quiet`. Both append `hid` until reported. A known MID retains its catalog polling list regardless of direct AC/dehumidifier construction. `AirToWaterDevice` always polls the `9300` preset plus its sensor/status extension, including when constructed directly without MID.

Neutral `Device` exposes no appliance-specific descriptors. Family status-backed getters return `None` for missing required values. Received zero stays valid zero/false, subject to temperature calibration. AC target temperature needs both `SetTem` and `TemRec`; MID does not select temperature encoding. AC `buzzer` and shared `has_valid_state` are non-optional local state. A narrower poll can leave a feature unavailable until its field arrives or is explicitly set; omission does not prove the hardware lacks it. Raw access remains available to every family.

Catalog categories are historical observations, not a promise of a typed implementation. `9301` and `9302` remain neutral raw-status devices with their existing catalog polling lists; their simulator profiles do not opt them into typed ATW controls. The additional raw polling presets below also remain neutral: they have no implemented typed family and do not establish typed controls or sensor calibration.


The PC emulator preserves each family's status ordering, value alignment, and unsupported-field behavior; there is no universal unknown-field rule. See [emulator contracts](#emulator-contracts) for omission, empty-string, safe-rejection, and explicitly simulated appliance policies.

## Capability evidence

[`Device.capabilities`](../greeclimate/device.py) returns a fresh, immutable `Mapping[str, Optional[bool]]` snapshot with exactly the 32 keys below. `True` declares protocol feature support; `False` means outside the constructed family's typed API or explicitly excluded by its firmware profile; `None` means not established. Neutral `Device` reports all `None`, even with a recognized MID or HID. A supported feature need not have a cached reading: getters can still return `None`.

Evidence is applied in this order:

1. The constructed family sets its applicable names to `None` and other schema names to `False`.
2. Its retained construction-time [MID profile](../greeclimate/mid_profile.py) supplies positive evidence only when the profile's family matches. Every required field must occur with exact case. Missing columns leave a feature unknown, not unsupported. `MidProfile.capabilities` is this positive field evidence, not the final device snapshot.
3. AC `lan_buzzer_control` gets its firmware baseline from `buzzer_properties`: `None` or no profile means unknown, `()` means `False`, and a nonempty tuple means `True`. MID columns do not establish this feature.
4. The currently reported [firmware-code profile](../greeclimate/device_profile.py) applies explicit capability overrides after MID evidence and the buzzer baseline, only for matching-family entries within that family's typed API. Foreign-family and unknown names cannot expand the schema or enable excluded controls. Changing or losing the HID recomputes firmware evidence; old snapshots do not change.

The MID profile is fixed for the instance even if discovery metadata changes. Firmware identity never selects or changes the device family. Cached reports, raw writes, model/display-version strings, and connection readiness are not capability evidence. Snapshot reads send no network probe and do not change polling, defaults, validation, or setter behavior: neither `None` nor `False` adds a rejection gate. `True` does not guarantee that every value is writable, a command is accepted, or a physical effect occurs.

The table names the public schema and the exact columns used for positive MID evidence. “Both” means AC and dehumidifier; ATW is air-to-water. The device filters evidence to its own API.

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

For example, MID `10001` declares AC target and current temperature before any HID or sensor reply arrives, but its omitted sleep fields leave `sleep=None`. MID `13805` declares `current_humidity=True` but not current temperature or units. `HumSen`, `InTem`, `TemBody`, `Lamp`, and `Quier` are not aliases for the typed fields above. Firmware exclusions can override positive MID evidence; see [firmware-code traits and limitations](HIDS.md#firmware-code-traits-and-limitations). These are conservative client policies, not a claim that every mainboard has been physically tested. Public behavior is covered by [capability regressions](../tests/test_capabilities.py) and [MID regressions](../tests/test_mid_profile.py); private routing research remains separately labeled below.

MID `9300` declares power, mode, read-only temperature units and all five target features. Its historical preset lacks the four sensor high/low pairs: the ATW polling extension does not promote them to MID evidence. Firmware code `362001066763` establishes those sensor paths; code `362001069999` explicitly excludes all ATW features. Neither code selects an appliance family. Cooling configuration is not a capability key or evidence.

## Air-to-water controls

[`AirToWaterDevice`](../greeclimate/air_to_water.py) exposes `power`, `mode` (`AirToWaterMode`), read-only reported `temperature_units`, four read-only Celsius sensors, two read-only room targets, and three writable integer Celsius targets: heating water 20–60, cooling water 7–25, tank 40–80. Sensor pairs decode as `high - 100 + low / 10`; this consumer convention is not physical calibration of every appliance. Missing/noninteger fields or units other than reported Celsius (`TemUn=0`) yield `None`; target reads are not clipped to setter ranges.

Heat, hot water, cool+hot water and heat+hot water encode as 1–4. Omitted `cooling_mode_value` follows the currently reported firmware-code profile: `362001066763` supplies 5, otherwise cooling is unconfigured. Explicit `cooling_mode_value=0`, `5`, or `None` takes precedence for the instance (`None` disables cooling even with a known HID). No module/version floor or model-string inference is used. A later HID change re-resolves automatic cooling and can invalidate a queued cooling command.

A changed mode requires a **received** integer `Pow=0`; staging power-off does not authorize it. An identical cached mode is a no-op. Mode and power-on cannot share a command: push the mode first, then power on. Power alone can be sent before any report. Target writes require **received** integer `TemUn=0`, not a locally staged unit flag, but do not require power-off. Send-time validation rechecks current received power/units and current cooling configuration, rejects unsupported raw command names or invalid values, and retains staged values on failure. Capability `True` bypasses none of these guards; ATW does not switch units or augment commands with AC fields.

Default ATW polling is the ordered, deduplicated union of the complete `9300` preset and its sensor/status extension, plus `hid` while unknown. It is sent in queries of at most 20 columns to stay below the firmware's encrypted request limit; replies arrive independently, not as an atomic snapshot. Explicit `update_state(columns)` delegates the shared validation and sends **one exact query**, preserving spelling, order and duplicates without appending `hid` or splitting. The caller must keep explicit requests within appliance limits. Other families' polling is unchanged.


## Historical polling catalog

These are default polling lists, not exhaustive hardware capability or temperature-encoding rules. Applicable exact fields provide the positive MID evidence described above; omission alone is not an exclusion. An omitted field may support an explicit query; an unsupported query may return a generic zero, not a sensor reading. Firmware routing evidence is separate from device observations.

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

## Gateway observations and sources

- [PR #148's hardware log](https://github.com/cmroche/greeclimate/pull/148#issuecomment-6173155943): a GR-Gcloud gateway has MID `60`, three indoor units have `608f`, and one has `605c`. A separate standalone air conditioner has `10001`. This log does not establish the indoor units' retail models or polling fields; the raw catalog presets above are separate source records.
- [Issue #101](https://github.com/cmroche/greeclimate/issues/101): a MID `60` gateway advertises six indoor units; its returned five-entry list contains `6049`, `6092` and `604c`.
- PR #148 links to HACS integration PR #508. Its [W06 packet notes](https://github.com/RobHofmann/HomeAssistant-GreeClimateComponent/pull/508#issuecomment-5795667844) associate MID `60` with `362001067012+U-W06AV30.bin` and show indoor MIDs `608f` and `6092`. An [older four-unit capture](https://github.com/RobHofmann/HomeAssistant-GreeClimateComponent/pull/508#issuecomment-5795708142) shows indoor MID `604b` but does not establish its gateway HID.

A gateway HID identifies the gateway firmware, not each indoor unit's firmware. Enumeration does not establish child status fields. Synthetic fixtures are not hardware observations.

Detailed firmware MID inventories and routing evidence are preserved in [private gree-research](https://github.com/cmroche/gree-research/blob/main/docs/MIDS.md). Public polling behavior above and executable conformance vectors do not require that repository. A routed MID does not prove appliance identity or calibrate `TemBody`, `TemSor` or `TemSen`; see the public [firmware traits](HIDS.md#firmware-code-traits-and-limitations).

## Emulator contracts

See [README usage](../README.md#use-gree-emulator), `python -m gree_emulator --help`, and the [mixed-device configuration](../examples/emulator-devices.json). Python 3.10+ and the declared runtime dependencies are sufficient; vendor binaries and research tools are not required. `--list-profiles` lists exact registered profile/MID pairs without opening a socket.

Generated devices require `--profile` and `--mid`; `--count` defaults to 1. Alternatively, `--config` loads a JSON object with a nonempty `devices` array and optional `seed`, `listen`, and `port`. Each device needs `id`, `profile`, and exact `mid`; optional fields are `name`, `mac`, `parent`, `room_c`, `ambient_c`, and writable integer `state`. Unknown/duplicate keys and invalid identities, topology, controls, or ranges are rejected. `--seed`, `--listen`, and `--port` override the configuration; port 0 selects an ephemeral port.

Prefer loopback or an isolated trusted test network: the default listens on `0.0.0.0:7000`, and legacy AES-ECB is unauthenticated. Startup identities/endpoints go to stdout; decoded packet logs go to stderr and can include bind session keys. Scrub logs before sharing. Stable seed and logical IDs preserve identities across reordering/restarts, but operating state resets. Children use their parent's UDP endpoint and bound key, not separate network interfaces.

| Profile | Exact MIDs / role | Sensor model and protocol boundary |
| --- | --- | --- |
| `sim-w04h-v3.55` | `10001` | `TemSen = clamp(floor(C)+40,0,255)`; `bindok`, command `p` only; unknown status names safely reject the packet. |
| `sim-w04n-v17` | `10001`, `10002`, `10014`, `10015`, `10016`, `10017`, `11000`, `11001`, `11002`, `11010`, `11f00`, `11f01`, `11f02`, `11f03`, `13000` | `TemSen = clamp(floor(C),0,50)`; `bindok`; command `p` preserves requested values, `val` reports final duplicate values; unknown status fields omitted. |
| `sim-wb04a-v1.49` | `10f05`, `10010`, `10011`, `11011`, `11012` | `TemSen = clamp(floor(C)+40,0,255)`; `bindok`, command `p` only; unsupported status fields omitted. |
| `sim-w04hb-v1.20` | `302b` | No ambient sensor; `bindok`, command `p` only. |
| `sim-w06dv-v4.01` | `3018` | No ambient sensor; `bindok`, bound-key commands; command reply has `p`/`val` without inner `mac`. |
| `sim-wb04brt13-v1.50-{MID}` | Standalone `3019`, `3027`, `4005`; host `60`; children `6400`, `6045`, `609d` | Appliance `InTem = clamp(floor(C),0,65535)`, not a `TemSen` alias; `bindok`, command `p` only. Host has exactly one child, MAC parent+`00`; root and child share its cache. |
| `sim-w06av-v30`, `sim-w06av-v30-ac` | Host `60`; children `6049`, `604a`, `604b`, `604c`, `605c`, `608f`, `6092` | Synthetic child `TemBody = clamp(floor(C),0,255)`, not proven hardware calibration; `bindOk`; at most 255 children, five per enumeration page; status `mac=child`, command `sub=child`; unknown status fields return empty strings. |
| `sim-w05sa-v1.28`, `-master`, `-zone` | Host `50`; master `5000`; zones `5001` | No ambient sensor; `bindOk`; master slot 0 required with zones, sparse slots 1–8 allowed; child MAC parent+`0`+slot; status uses `mac`, command uses `sub`. |
| `sim-w06a-p3-v6.04-9300`, `-9301`, `-9302` | Exact matching `9300`, `9301`, `9302` | Single-medium simulation: room / tank / inlet+outlet pairs respectively, encoded as `high-100+low/10`; only `9300` selects a typed ATW client. `bindok`, command `p`/`val`; supported status fields preserve order/duplicates, unsupported names omitted. |

These are simulated appliances, not complete firmware/mainboard emulations. Modeled AC targets are integer Celsius 16–30 where present; zones use `16 + StTem`. Powered auto/cool/dry/heat moves toward the target at 1°C/minute (cool/dry downward only, heat upward only); idle drifts toward ambient at 0.1°C/minute. Units flags do not convert model temperatures. Commands validate the entire batch before mutation; unsupported fields reject the batch without success. Check fresh status rather than equating a successful send with accepted control.

All families use AES-ECB, strict base64, and PKCS#7. WB04A/BRT additionally accept one optional terminal JSON NUL before padding; embedded/multiple NULs remain invalid, and replies do not add one. Unsafe native faults and buffer overruns are not reproduced. Exact ordering, duplicate handling, limits, and packet expectations remain in the public [conformance fixtures](../tests/fixtures/emulator) and [tests](../tests/test_emulator.py). Source attribution points to private research, but the tests load only retained public vectors.

The ATW dialect keeps its native-size boundaries: encrypted request `pack` length must be below 700 bytes, property names at most 19 UTF-8 bytes, status at most 50 names (exactly 50 yields empty data), and commands at most 49 equal nonempty `opt`/`p` entries. Oversize replies and invalid batches safely reject before mutation. The simulator accepts eight bounded integer controls, including room targets/units that the conservative typed client leaves read-only; simulator acceptance does not weaken client reported-state guards. Its chosen sensor calibration and thermal model are simulation policy, not firmware-proven hardware behavior. Public [ATW client tests](../tests/test_atw.py), [ATW emulator tests](../tests/test_emulator_atw.py), and [vectors](../tests/fixtures/emulator/atw-9300.json) run without private research.


