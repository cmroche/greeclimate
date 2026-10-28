"""M26S V3.05 source-selected raw UART cache roots, not calibrated appliances.

Every numeric readout starts at explicit synthetic raw zero. Commands retain
signed32 cache values, independently of UART masking; no automatic board ACK,
physical output, flash/network upgrade or thermal behavior is fabricated.
Strict atomic validation replaces native unchecked arrays and stack copies.
"""
from copy import deepcopy
from time import monotonic

from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile
from .catalog_realtek_third_tables import CODEC, KEY, FiniteTables, _clock, _integer, _members, _reply, _text

SHA = "7be5a21d861a0bcc1045d72a49dfab91e527b74e6f0bf8e16dd4b096dbf9b19e"
HID = "362001063147+U-M26SV3.05.bin"
TABLES = (
    tuple('Pow Wmod WsetTmp WsetTmpC PrvHeat Wout SvSt WschOn HydPrs SenTmpC SenTmp UseTime UseTimeAll TapNum TapNumAll PersonNum Machine AboveSeaLev SvLineType SvLine TmrOnHour TmrOnMin TmrOn TmrOffHour TmrOffMin TmrOff Werr estate estate1 estate2 estate3 estate4 estate5 estate6 MidType JFerr'.split()),
    tuple('Pow WdSpd StepWdSpd Mod Rotate Cycle SwUpDn SwingLfRig Wet Anion HotwindOnOff HotWind TmrHour TmrMin TmrOn TmrAction SmartMod WetLevel Light UpDnAngle LRAngle Quiet OSD LRHeadAngle UpDuHeadAngle Temperature PM25 estate estate1 estate2 estate3 JFerr MidType'.split()),
    tuple('Pow wspd mode PM2P5 light AirChildLock FiltUT FiltBT wipm25 wopm25 ErrorCode FiltUPercent FiltUPercent1 FiltUPercent2 MeshWarning1 sterilize FomadeValue TmrOff TmrOn StTmr RemLifePerErr1 RemLifePerErr2 estate estate1 estate2 JFerr MidType'.split()),
    tuple('Pow mode StTmr TmrOn TmrEn SchTmr SchOnOff SchEn Textre Rice sealve Prsure KpTpTmr KpTpOnOff KpTpEn Lig ModeTmr StpRic Runlight AddMark Volt ElcP TmpUp TmpDn estate estate2 estate3 estate4 JFerr MidType'.split()),
    tuple('Pow Mode WaterSetTemp WaterValueSelect BurnState SelfTestOkState Fan BurnOffValve2 BurnOffValve1 WaterRateValve GasRateValve GasSafeValve Firearm WaterPump WaterFlow InputWaterInt InputWaterFloat OutputWaterInt OutputWaterFloat EnvTempInt EnvTempFloat WindSensor TempLimiter Windswitch FireNeedle estate estate2 estate3 estate4 estate5 JFerr MidType'.split()),
    tuple('Pow Humidification Swing ChildLock HeatLevel Anion SetTemp EnvTemp WorkTimeHour WorkTimeSec RealHeatLevel FanLevel HeatMode TmrOn TmrAction TmrHour TmrMin estate estate2 estate3 JFerr MidType'.split()),
    tuple('Pow PauseStart Wash Mod Disinfect Lock Lighting Purifier Dry LayerWash PurifierTime WashDone RmTmrHour RmTmrMin WorkStatus TmrOn TmrStatus TmrHour TmrMin SetWaterHard WaterHardPram SetDetergent DeterLevel estate1 estate2 estate3 JFerr MidType'.split()),
    tuple('Pow PauseStart Wash Mod Loading Lock Clean Disinfect Sterilize Dry PurifierTime TmrOn TmrStatus TmrHour TmrMin DIY SetTemp RinsSetTemp SetWaterHard WaterHardPram SetDetergent DeterLevel WashDone RmTmrHour RmTmrMin WorkStatus estate1 estate2 estate3 JFerr MidType'.split()),
    tuple('Pow ChildLock RunStat Pause Mod List1 List2 List3 List4 List5 SetHour SetMin SetTmp TmrHour TmrMin DisTmp DisSetHour DisSetMin DisTmrHour DisTmrMin TmpCtrl MachStat estate1 estate2 estate3 estate4 estate5 JFerr MidType CloudMenu'.split()),
    tuple('Pow Wspd Mode PM25 PM25Level Light SetHumidity EnvHumidity ReplaceFilter RefreshWater AirChildLock FiltUPercent TmrHour TmrMin TmrOn TmrAction estate estate1 estate2 estate3 JFerr MidType'.split()),
    tuple('Pow wspd mode light gesture RightCooker LeftCooker CookerBattery estate estate2 JFerr MidType'.split()),
    tuple('WorkStatus TotalPureWater FilterNum LifeTimeFilter1 LifeTimeFilter2 LifeTimeFilter3 LifeTimeFilter4 LifeTimeFilter5 FilterWarning1 FilterWarning2 FilterWarning3 FilterWarning4 FilterWarning5 LifeFilterDays1 LifeFilterDays2 LifeFilterDays3 LifeFilterDays4 LifeFilterDays5 OriginTDS PurifyTDS FilterKind1 FilterKind2 FilterKind3 FilterKind4 FilterKind5 ErrorCode1 ErrorCode2 JFerr MidType'.split()),
    tuple('SetTemp Cruise Mode HotMode Pow PreBoost CruiseState BurnState FirstAntif SecAntif PreBacter AddOxygen EnvironmentTemp KitRecomTemp BathRecomTemp BathtubTemp HotBacKValue OutWaterTemp InWaterTemp MaximumTime UsedTime GasSafeLife CasSafeTimes BatWatVolume MaxSPATemp MinSPATemp SPASetTime BatRealVol GasSum CurrentGas ErrorCode1 ErrorCode2 ErrorCode3 JFerr MidType'.split()),
    tuple('Pow Status SaltStatus LifeTimeFilter MotorStatus RecycleTotalT InsFlowRate CycleFlowRate SaltTotalT FilterWarning NextClean TotalWater TodayWater RemainWater RecycleHour RecycleMin CleanCycle TmrOn TmrAction TmrHour TmrMin estate JFerr MidType'.split()),
    tuple('Heat ChildLock Filter1 Filter2 Filter3 Filter4 TakeWaterID SetTempValue SetTemp CapTime WaterSwitch TakeWaterID WorkStatus FilterWarning1 FilterWarning2 FilterWarning3 FilterWarning4 LifeTimeFilter1 LifeTimeFilter2 LifeTimeFilter3 LifeTimeFilter4 LifeFilterDays1 LifeFilterDays2 LifeFilterDays3 LifeFilterDays4 InWaterTemp OrigionTDS PurifierTDS PretreatWater1 PretreatWater2 TotalPureWater ROPurifySpeed ROFlushSpeed TakeWaterSpeed FilterNum FilterKind1 FilterKind2 FilterKind3 FilterKind4 Temp1 Temp2 Temp3 Temp4 Temp5 Temp6 ErrorCode1 ErrorCode2 ErrorCode3 JFerr MidType'.split()),
    tuple('Pow Humidification Swing AirChildLock Anion HeatLevel SetTemp EnvTemp WorkTimeHour WorkTimeSec RealHeatLevel FanLevel HeatMod TimeStart TmrAction TmrHour TmrMin estate estate2 estate3 JFerr MidType'.split()),
)
MIDS = (
    ('8600', '828c00', '828c02'),
    ('828205', '828204', '828203', '828202', '828208', '828209', '828210', '828211', '828212', '828214'),
    ('828103', '828102', '828101', '828105'),
    ('828402', '828403', '828404', '828405'),
    ('828c01',),
    ('828a00', '828a01', '828a02', '828a03'),
    ('828901', '828902', '828903', '828b00'),
    ('828904',),
    ('828d04',),
    ('828140',),
    ('828600',),
    ('828301', '828306', '828307'),
    ('829100',),
    ('829000', '828309'),
    ('828308',),
    ('828a04',),
)
METADATA = ('apssid', 'appsw', 'host', 'name', 'time', 'lat', 'lon', 'vender', 'bc', 'mid', 'model', 'series', 'brand', 'catalog', 'country', 'hid', 'mac', 'rssi', 'ver', 'HidSvrVer', 'InHid', 'InHidSvrVer', 'OEEPHid', 'OEEPHidSvrVer', 'YCode1', 'YCode2', 'YCode3', 'YCode4', 'YCode5')


def _columns(value):
    if not isinstance(value, list) or len(value) > 45:
        raise InvalidPacket("M26S permits at most45 status/command names")
    return [_text(name, 1023) for name in value]


class M26S(FiniteTables):
    def __init__(self, selector):
        self.selector = selector
        self.fields = TABLES[selector]
        self.w05 = False

    def validate_state(self, state):
        for name, value in state.items():
            if name not in self.fields:
                raise ValueError("only the source-selected numeric cache may be configured")
            try:
                _integer(value)
            except InvalidPacket as error:
                raise ValueError(str(error)) from error

    def _runtime(self, device, state):
        if "_tables" not in state:
            state["_tables"] = {"time": "2026-01-01 00:00:00", "timers": {},
                                "host": "", "name": device.name, "svline": [0]*24,
                                "cloud_menu": [0]*45, "report_client": "", "uid": 0,
                                "mid": device.mid, "fan_mode": 0}
        return state["_tables"]

    def _metadata(self, device, runtime):
        result = dict.fromkeys(METADATA, "")
        result.update(hid=HID, name=runtime["name"], host=runtime["host"],
                      time=runtime["time"], rssi=0)
        return result

    def advertise(self, device, outer):
        runtime = self._runtime(device, deepcopy(device.state))
        inner = {"t": "dev", "cid": "", "bc": "gree", "catalog": "gree",
                 "mid": device.mid, "lock": 0, "model": "gree", "name": runtime["name"],
                 "series": "gree", "vender": "", "ver": "", "brand": "gree", "mac": device.mac}
        return [_reply(device, inner, runtime["uid"], selector=1)]

    def _status(self, device, state, runtime, requested):
        columns, values = [], []
        if len(requested) == 45:
            return columns, values
        metadata = self._metadata(device, runtime)
        for name in requested:
            if not name or len(name.encode()) >= 16:
                break
            if name in self.fields:
                value = state[name]
                if name == "SvLine" and runtime["mid"] in ("828c00", "828c02"):
                    value = runtime["svline"][:]
            elif name in metadata:
                value = metadata[name]
            elif name == "ReportClientID":
                value = runtime["report_client"]
            else:
                continue
            columns.append(name)
            values.append(deepcopy(value))
        return columns, values

    def _store(self, state, runtime, name, value):
        value = _integer(value)
        if name == "WsetTmpC" and value == 10:
            return
        if self.selector in (2, 3) and name in ("StTmr", "SchTmr", "KpTpTmr", "ModeTmr"):
            value = min(value, 1440)
        if self.selector == 1:
            if name == "Mod":
                runtime["fan_mode"] = value & 7
            elif name == "WdSpd" and runtime["mid"] == "828214" and runtime["fan_mode"] == 7:
                value = min(value, 3)
        if name == "WschOn" and runtime["mid"] == "828c02":
            if value == 1 and not any(not timer["enable"] for timer in runtime["timers"].values()):
                value = 0
            elif value == 0:
                for timer in runtime["timers"].values():
                    timer["enable"] = 1
        state[name] = value
        if name == "SvLineType":
            runtime["line_type"] = value & 255

    def _command(self, state, runtime, names, values):
        for name, value in zip(names, values):
            if name in self.fields:
                if isinstance(value, list):
                    if name == "SvLine" and runtime["mid"] in ("828c00", "828c02"):
                        if len(value) > 24:
                            raise InvalidPacket("M26S synthetic SvLine cache holds24 bytes")
                        runtime["svline"][:len(value)] = [_integer(item) & 255 for item in value]
                    elif name == "CloudMenu" and runtime["mid"] == "828d04":
                        if len(value) > 45:
                            raise InvalidPacket("M26S CloudMenu payload holds45 bytes")
                        runtime["cloud_menu"] = [_integer(item) & 255 for item in value]+[0]*(45-len(value))
                    else:
                        raise InvalidPacket("array has no source-selected M26S encoder")
                else:
                    self._store(state, runtime, name, value)
            elif name == "time":
                _clock(value)
                self._time(state, runtime, value)
            elif name == "ReportClientID":
                value = _text(value, 18)
                if value:
                    runtime["report_client"] = value
            # Read-only metadata and unknown names are omitted without mutation.

    def _time(self, state, runtime, value):
        from datetime import datetime, timedelta
        old, new = _clock(runtime["time"]), _clock(value)
        if new >= old and runtime["timers"]:
            if (new-old).days > 366:
                raise InvalidPacket("synthetic M26S timer advance is bounded to one year")
            day = old.replace(hour=0, minute=0, second=0)
            while day <= new:
                for record in runtime["timers"].values():
                    event = day.replace(hour=record["hr"], minute=record["min"], second=record["sec"])
                    repeating = any(record["week"])
                    if (not record["enable"] and old < event <= new
                            and event >= datetime(2018, 5, 22, 6, 10, 36)
                            and (not repeating or record["week"][(event.weekday()+1) % 7])):
                        for command in record["cmd"]:
                            for name, item in zip(command["opt"], command["p"]):
                                if name in self.fields:
                                    self._store(state, runtime, name, item)
                        if not repeating:
                            record["enable"] = 1
                day += timedelta(days=1)
        runtime["time"] = value

    def wlan(self, device, outer):
        _members(outer)
        for name, limit in (("ssid",31),("psw",31),("lat",11),("lon",11)):
            _text(outer.get(name), limit)
        host = _text(outer.get("host"), 31)
        state = deepcopy(device.state)
        runtime = self._runtime(device, state)
        runtime["wlan_host"] = host
        # Provisioning/reset is synthetic in-memory state, never real credentials or reboot.
        reply = Reply({"t": "ret", "mac": device.mac, "r": 200}, trailing_newline=True)
        encode_reply(reply)
        device.advance(monotonic())
        device.state = state
        return [reply]

    def handle(self, device, outer):
        _members(outer)
        if outer.get("t") == "wlan":
            return self.wlan(device, outer)
        if outer.get("t") != "pack" or outer.get("tcid") != device.mac:
            raise InvalidPacket("M26S request must target this root")
        index, uid = _integer(outer.get("i")), _integer(outer.get("uid", 0))
        inner = decode_pack(outer, KEY if index else device.key, CODEC)
        _members(inner)
        if "sub" in inner or ("mac" in inner and inner["mac"] != device.mac):
            raise InvalidPacket("M26S has no child or mismatched identity route")
        state = deepcopy(device.state)
        runtime = self._runtime(device, state)
        now = monotonic()
        self._advance(state, runtime, now)
        runtime["uid"] = uid
        kind, selector, newline = inner.get("t"), 0, True
        if kind == "bind":
            response = {"t": "bindok", "mac": device.mac, "r": 200, "key": device.key.decode("ascii")}
            selector = 1
        elif kind in ("status", "cmd"):
            names = _columns(inner.get("cols" if kind == "status" else "opt"))
            if kind == "cmd":
                values = inner.get("p")
                if not isinstance(values, list) or len(names) != len(values):
                    raise InvalidPacket("M26S command arrays must match")
                self._command(state, runtime, names, values)
            columns, values = self._status(device, state, runtime, names)
            response = {"t": "dat" if kind == "status" else "res", "mac": device.mac, "r": 200,
                        "cols" if kind == "status" else "opt": columns,
                        "dat" if kind == "status" else "p": values}
        elif kind in ("setT", "updateT"):
            timer_id, record = self._timer(inner)
            if timer_id not in runtime["timers"] and len(runtime["timers"]) >= 10:
                response = {"t": "resT", "r": 500}
            else:
                runtime["timers"][timer_id] = record
                response = {"t": "resT", "r": 200}
            newline = False
        elif kind == "deleteT":
            runtime["timers"].pop(_integer(inner.get("id")) & 255, None)
            response, newline = {"t": "resT", "r": 200}, False
        elif kind == "queryT":
            start, count = (_integer(inner.get(field)) & 255 for field in ("index", "count"))
            response = {"t": "listT", "total": count, "index": start}
            if runtime["timers"]:
                response["list"] = [{field:deepcopy(record[field]) for field in
                                    ("id","name","enable","hr","min","sec","week","cmd")}
                                    for ordinal, record in enumerate(runtime["timers"].values())
                                    if start <= ordinal <= start+count]
            newline = False
        elif kind in ("upgrade", "surver"):
            if kind == "upgrade":
                runtime["upgrade_url"] = _text(inner.get("url"), 159)
            device.advance(now)
            device.state = state
            return []
        else:
            return []
        reply = _reply(device, response, uid, selector, newline=newline)
        device.advance(now)
        device.state = state
        return [reply]


PROFILES = tuple(Profile("sim-m26s-v305-s"+str(selector).zfill(2), mids, HID, SHA,
                         dict.fromkeys(TABLES[selector], 0), M26S(selector), max_request_bytes=1024)
                 for selector, mids in enumerate(MIDS))
