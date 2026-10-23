# Known MIDs

A MID is the `mid` string in discovery metadata or a gateway's `subList`. Keep its case, letters and leading zeros. It is separate from the firmware identifier (`hid`); see [HIDS.md](HIDS.md) and [gateway observations](#gateway-observations-and-sources).

`DeviceInfo.mid` stores the discovery value separately from `model`; missing MID is `None`. At construction, `Device` matches it exactly against `greeclimate/mid_profile.py` and keeps that profile for its lifetime. `create_device()` selects `AirConditionerDevice` or `DehumidifierDevice` only for explicitly registered families; otherwise it returns neutral `Device`. Matching preserves case and leading zeros without coercion or trimming. Model names and reported HIDs never substitute for a MID or change the selected family.

A matched profile requests its fields in the listed order, even fields outside `Props`. `hid` is appended only while firmware identity is unknown and the preset lacks it. A preset that includes `hid` keeps requesting it: MID `60` always polls `["hid"]`. Missing, malformed, unknown or not-established MIDs use `FALLBACK_MID_PROFILE` (`mid=None`), whose neutral polling list is only `["hid"]`. `match_mid_profile()` always returns a profile. `update_state(columns)` sends explicit columns unchanged, without adding identity fields.

Direct family construction remains available when the caller knows the appliance but its MID is missing or unregistered. `AirConditionerDevice` then polls `Pow`, `Mod`, `SetTem`, `TemUn`, `TemRec`, `TemSen`; `DehumidifierDevice` polls `Pow`, `Dmod`, `Dwet`, `DwatSen`, `Dfltr`, `DwatFul`, `TemSen`, `TemUn`, `TemRec`, `WdSpd`, `Lig`, `SwUpDn`, `Health`, `Quiet`. Both append `hid` until reported. A known MID retains its catalog polling list regardless of direct family construction.

Neutral `Device` exposes no appliance-specific descriptors. Family status-backed getters return `None` for missing required values. Received zero stays valid zero/false, subject to temperature calibration. AC target temperature needs both `SetTem` and `TemRec`; MID does not select temperature encoding. AC `buzzer` and shared `has_valid_state` are non-optional local state. A narrower poll can leave a feature unavailable until its field arrives or is explicitly set; omission does not prove the hardware lacks it. Raw access remains available to every family.

Catalog categories are historical observations, not a promise of a typed implementation. In particular, `9300`, `9301`, and `9302` remain neutral devices with their existing catalog polling lists. The raw polling presets restored from source revision `661896f` below also remain neutral: they have no implemented typed family and do not establish typed controls or sensor calibration.


The PC emulator preserves each family's status ordering, value alignment, and unsupported-field behavior; there is no universal unknown-field rule. See [emulator contracts](#emulator-contracts) for omission, empty-string, safe-rejection, and explicitly simulated appliance policies.

## Historical polling catalog

These are default polling lists, not complete capability or temperature-encoding rules. An omitted field may support an explicit query; an unsupported query may return a generic zero, not a sensor reading. Firmware routing evidence is separate from device observations.

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

These are simulated appliances, not complete firmware/mainboard emulations. Modeled AC targets are integer Celsius 16–30 where present; zones use `16 + StTem`. Powered auto/cool/dry/heat moves toward the target at 1°C/minute (cool/dry downward only, heat upward only); idle drifts toward ambient at 0.1°C/minute. Units flags do not convert model temperatures. Commands validate the entire batch before mutation; unsupported fields reject the batch without success. Check fresh status rather than equating a successful send with accepted control.

All families use AES-ECB, strict base64, and PKCS#7. WB04A/BRT additionally accept one optional terminal JSON NUL before padding; embedded/multiple NULs remain invalid, and replies do not add one. Unsafe native faults and buffer overruns are not reproduced. Exact ordering, duplicate handling, limits, and packet expectations remain in the public [conformance fixtures](../tests/fixtures/emulator) and [tests](../tests/test_emulator.py). Source attribution points to private research, but the tests load only retained public vectors.


