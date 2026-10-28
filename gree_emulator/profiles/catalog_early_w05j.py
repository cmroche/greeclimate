"""Exact W05J V2.74 source-selected raw UART-cache LAN models.

Every selected numeric field has a synthetic signed32 cache, initially zero.
No AC temperature conversion, calibrated mainboard, real UART, flash or cloud is
claimed. Native command cache mutations and refreshed response order are kept;
strict atomic validation replaces unchecked copies and malformed-input faults.
"""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta
from time import monotonic

from ..wire import InvalidPacket, decode_pack
from . import Profile
from .catalog_realtek_third_tables import (
    CODEC, KEY, FiniteTables, _clock, _columns, _integer, _members, _reply, _text,
)

SHA = "7772ce7985ad0ce3feabdf7b8ab4beb1e12220b64a866a9818f8134b427894f8"
HID = "362001061331+U-W05JV2.74.bin"
FIELDS = {
    0: tuple("""
        Pow Wmod WsetTmp WsetTmpC PrvHeat Wout SvSt WschOn
        HydPrs SenTmpC SenTmp UseTime UseTimeAll TapNum TapNumAll PersonNum
        Machine AboveSeaLev SvLineType SvLine TmrOnHour TmrOnMin TmrOn TmrOffHour
        TmrOffMin TmrOff Werr estate estate1 estate2 estate3 estate4
        estate5 estate6 MidType JFerr
    """.split()),
    1: tuple("""
        Pow WdSpd Mod Rotate Cycle SwUpDn SwingLfRig Wet
        Anion HotwindOnOff HotWind TmrHour TmrMin TmrOn TmrAction SmartMod
        WetLevel Light UpDnAngle LRAngle Temperature PM25 estate estate1
        estate2 estate3 JFerr MidType
    """.split()),
    2: tuple("""
        Pow wspd mode PM2P5 light AirChildLock FiltUT FiltBT
        wipm25 wopm25 ErrorCode FiltUPercent FiltUPercent1 FiltUPercent2 MeshWarning1 sterilize
        FomadeValue TmrOff TmrOn StTmr RemLifePerErr1 RemLifePerErr2 estate estate1
        estate2 JFerr MidType
    """.split()),
    3: tuple("""
        Pow mode StTmr TmrOn TmrEn SchTmr SchOnOff SchEn
        Textre Rice sealve Prsure KpTpTmr KpTpOnOff KpTpEn Lig
        ModeTmr StpRic Runlight Volt ElcP TmpUp TmpDn estate
        estate2 estate3 estate4 JFerr MidType
    """.split()),
    4: tuple("""
        Pow Mode WaterSetTemp WaterValueSelect BurnState SelfTestOkState Fan BurnOffValve2
        BurnOffValve1 WaterRateValve GasRateValve GasSafeValve Firearm WaterPump WaterFlow InputWaterInt
        InputWaterFloat OutputWaterInt OutputWaterFloat EnvTempInt EnvTempFloat WindSensor TempLimiter Windswitch
        FireNeedle estate estate2 estate3 estate4 estate5 JFerr MidType
    """.split()),
    5: tuple("""
        Pow Humidification Swing ChildLock HeatLevel SetTemp EnvTemp WorkTimeHour
        WorkTimeSec RealHeatLevel FanLevel HeatMode TmrOn TmrAction TmrHour TmrMin
        estate estate2 estate3 JFerr MidType
    """.split()),
    6: tuple("""
        Pow PauseStart Wash Mod Disinfect Lock Lighting Purifier
        Dry LayerWash PurifierTime WashDone RmTmrHour RmTmrMin WorkStatus TmrOn
        TmrStatus TmrHour TmrMin SetWaterHard WaterHardPram SetDetergent DeterLevel estate1
        estate2 estate3 JFerr MidType
    """.split()),
    7: tuple("""
        Pow ChildLock RunStat Pause Mod List1 List2 List3
        List4 List5 SetHour SetMin SetTmp TmrHour TmrMin DisTmp
        DisSetHour DisSetMin DisTmrHour DisTmrMin TmpCtrl MachStat estate1 estate2
        estate3 estate4 estate5 JFerr MidType CloudMenu
    """.split()),
    8: tuple("""
        Pow Wspd Mode PM25 PM25Level Light SetHumidity EnvHumidity
        ReplaceFilter RefreshWater AirChildLock FiltUPercent TmrHour TmrMin TmrOn TmrAction
        estate estate1 estate2 estate3 JFerr MidType
    """.split()),
    9: tuple("""
        Pow wspd mode light gesture RightCooker LeftCooker CookerBattery
        estate estate2 JFerr MidType
    """.split()),
    10: tuple("""
        WorkStatus TotalPureWater FilterNum LifeTimeFilter1 LifeTimeFilter2 LifeTimeFilter3 LifeTimeFilter4 LifeTimeFilter5
        FilterWarning1 FilterWarning2 FilterWarning3 FilterWarning4 FilterWarning5 LifeFilterDays1 LifeFilterDays2 LifeFilterDays3
        LifeFilterDays4 LifeFilterDays5 FilterKind1 FilterKind2 FilterKind3 FilterKind4 FilterKind5 ErrorCode1
        ErrorCode2 JFerr MidType
    """.split()),
    11: tuple("""
        SetTemp Cruise Mode Pow PreBoost BurnState CruiseState InWaterTemp
        ErrorCode1 ErrorCode2 ErrorCode3 JFerr MidType
    """.split()),
}
MIDS = {0: ('828c00', '828c02', '8600'), 1: ('828205', '828204', '828203', '828202', '828208', '828209', '828210', '828211', '828212'), 2: ('828103', '828102', '828101', '828105'), 3: ('828402', '828403', '828404', '828405'), 4: ('828c01',), 5: ('828a00', '828a01', '828a02', '828a03'), 6: ('828901', '828902', '828903', '828b00'), 7: ('828d04',), 8: ('828140',), 9: ('828600',), 10: ('828301', '828306', '828307', '828308', '828309', '828310'), 11: ('829100',)}
METADATA = ('apssid', 'appsw', 'host', 'name', 'time', 'lat', 'lon', 'vender', 'bc', 'mid', 'model', 'series', 'brand', 'catalog', 'country', 'hid', 'mac', 'rssi', 'ver', 'HidSvrVer', 'InHid', 'InHidSvrVer', 'OEEPHid', 'OEEPHidSvrVer')


class W05J(FiniteTables):
    def __init__(self, selector):
        self.selector = selector
        self.table = f"w05j-{selector}"
        self.fields = FIELDS[selector]
        self.w05 = False

    def _runtime(self, device, state):
        runtime = super()._runtime(device, state)
        runtime.setdefault("mid", device.mid)
        runtime.setdefault("hotwind_byte", 0)
        runtime.setdefault("fan_report", 0)
        runtime.setdefault("cloud_menu", [0] * 45)
        return runtime

    def _metadata(self, device, runtime):
        values = dict.fromkeys(METADATA, "")
        values.update(hid=HID, name=runtime["name"], host=runtime["host"],
                      time=runtime["time"], rssi=0)
        return values

    def advertise(self, device, outer):
        state = deepcopy(device.state)
        runtime = self._runtime(device, state)
        inner = {"t": "dev", "cid": "", "bc": "gree", "catalog": "gree",
                 "mid": device.mid, "lock": 0, "model": "gree",
                 "name": runtime["name"], "series": "gree", "vender": "",
                 "ver": "", "brand": "gree", "mac": device.mac}
        return [_reply(device, inner, selector=1)]

    def wlan(self, device, outer):
        reply, = super().wlan(device, outer)
        return [replace(reply, outer={**reply.outer, "r": 200})]

    def _assign(self, state, runtime, name, value):
        value = _integer(value)
        if self.selector == 0 and name == "WsetTmpC" and value == 10:
            return
        if self.selector == 0 and name == "WschOn" and runtime["mid"] == "828c02":
            if value == 1 and not any(not record["enable"] for record in runtime["timers"].values()):
                value = 0
            elif value == 0:
                for record in runtime["timers"].values():
                    record["enable"] = 1
        if name in ("StTmr", "SchTmr", "KpTpTmr", "ModeTmr") and self.selector in (2, 3):
            value = min(value, 1440)
        if self.selector == 1:
            mid = runtime["mid"]
            if name == "HotWind":
                runtime["hotwind_byte"] = value & 255
            elif name == "WdSpd" and mid != "828210" and runtime["hotwind_byte"] == 1:
                return
            elif name == "Mod":
                old = state["Mod"]
                speed = state["WdSpd"]
                if mid == "828212":
                    if old in (0, 2) and value == 1 and 1 <= speed <= 22:
                        state["WdSpd"] = min((speed - 1) // 6 + 1, 4)
                    elif old == 1 and value in (0, 2) and speed in (1, 2, 3, 4):
                        state["WdSpd"] = 1 + (speed - 1) * 6
                    elif old == 3 and 0 <= value < 3:
                        state["WdSpd"] = runtime["fan_report"]
                elif mid != "828210" and runtime["hotwind_byte"] == 1:
                    value = 0
        state[name] = value

    def _status(self, device, state, runtime, requested):
        metadata = self._metadata(device, runtime)
        columns, values = [], []
        for name in requested:
            if not name or len(name.encode()) >= 16:
                break
            if name in self.fields:
                value = state[name]
                if name == "SvLine" and runtime["mid"] in ("828c00", "828c02"):
                    value = runtime["svline"][:]
                columns.append(name)
                values.append(value)
            elif name in metadata:
                columns.append(name)
                values.append(metadata[name])
        return columns, values

    def _command(self, state, runtime, names, values):
        for name, value in zip(names, values):
            if name == "time":
                self._time(state, runtime, value)
            elif name == "ReportClientID":
                client = _text(value, 16)
                if client:
                    runtime["report_client"] = client
            elif name == "SvLine" and isinstance(value, list) and runtime["mid"] in ("828c00", "828c02"):
                if len(value) > 24:
                    raise InvalidPacket("SvLine has twenty-four byte entries")
                runtime["svline"][:len(value)] = [_integer(item) & 255 for item in value]
            elif name == "CloudMenu" and isinstance(value, list) and self.selector == 7:
                if len(value) > 45:
                    raise InvalidPacket("CloudMenu has forty-five byte entries")
                runtime["cloud_menu"] = [_integer(item) & 255 for item in value] + [0] * (45 - len(value))
            elif name in self.fields:
                self._assign(state, runtime, name, value)

    def _time(self, state, runtime, value):
        old, new = _clock(runtime["time"]), _clock(value)
        if new >= old and runtime["timers"]:
            if (new - old).days > 366:
                raise InvalidPacket("synthetic timer advance is bounded to one year")
            day = old.replace(hour=0, minute=0, second=0)
            while day <= new:
                for record in runtime["timers"].values():
                    event = day.replace(hour=record["hr"], minute=record["min"], second=record["sec"])
                    repeating = any(record["week"])
                    weekday = (event.weekday() + 1) % 7
                    if (not record["enable"] and old < event <= new
                            and event >= datetime(2018, 5, 22, 6, 10, 36)
                            and (not repeating or record["week"][weekday])):
                        for command in record["cmd"]:
                            for name, number in zip(command["opt"], command["p"]):
                                if name in self.fields:
                                    self._assign(state, runtime, name, number)
                        if not repeating:
                            record["enable"] = 1
                day += timedelta(days=1)
        runtime["time"] = value

    def handle(self, device, outer):
        if outer.get("t") == "wlan":
            return self.wlan(device, outer)
        _members(outer)
        if outer.get("t") != "pack":
            raise InvalidPacket("W05J request must target this root")
        index = _integer(outer.get("i"))
        uid = _integer(outer.get("uid", 0))
        inner = decode_pack(outer, KEY if index else device.key, CODEC)
        _members(inner)
        if "sub" in inner:
            raise InvalidPacket("W05J does not route child identities")
        kind = inner.get("t")
        # Native command and status channels gate different identity fields.
        if kind == "cmd":
            if outer.get("tcid") != device.mac:
                return []
        elif kind == "status":
            if "mac" not in inner:
                raise InvalidPacket("W05J operation requires the local MAC")
            if inner["mac"] != device.mac:
                return []
        else:
            if outer.get("tcid") != device.mac:
                raise InvalidPacket("W05J request must target this root")
            if "mac" in inner and inner["mac"] != device.mac:
                raise InvalidPacket("W05J does not route child identities")
            if kind in ("bind", "surver") and inner.get("mac") != device.mac:
                raise InvalidPacket("W05J operation requires the local MAC")
        if kind not in ("bind", "status", "cmd", "upgrade"):
            return super().handle(device, outer)
        state = deepcopy(device.state)
        runtime = self._runtime(device, state)
        now = monotonic()
        self._advance(state, runtime, now)
        selector = 0
        if kind == "bind":
            response = {"t": "bindok", "mac": device.mac, "r": 200,
                        "key": device.key.decode("ascii")}
            selector = 1
        elif kind == "status":
            columns, values = self._status(device, state, runtime, _columns(inner.get("cols")))
            response = {"t": "dat", "mac": device.mac, "r": 200, "cols": columns, "dat": values}
        elif kind == "cmd":
            names, values = _columns(inner.get("opt")), inner.get("p")
            if not isinstance(values, list) or len(names) != len(values):
                raise InvalidPacket("W05J command arrays must match")
            self._command(state, runtime, names, values)
            columns, effective = self._status(device, state, runtime, names)
            response = {"t": "res", "mac": device.mac, "r": 200, "opt": columns, "p": effective}
        else:
            runtime["upgrade"] = _text(inner.get("url"), 159)
            device.advance(now)
            device.state = state
            return []  # Native queues the URL and has no synchronous upgrade ACK.
        reply = _reply(device, response, uid, selector)
        device.advance(now)
        device.state = state
        return [reply]


PROFILES = tuple(
    Profile(id=f"sim-w05j-v274-{selector}", mids=MIDS[selector], hid=HID,
            source_sha256=SHA, initial_state=dict.fromkeys(FIELDS[selector], 0),
            handler=W05J(selector), max_request_bytes=1024)
    for selector in range(12)
)
