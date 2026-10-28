"""Early source-qualified raw controllers, not calibrated air conditioners.

Raw caches, metadata and software timers are synthetic per-device RAM.
No UART companion, flash update, cloud connection or measured sensor is implied.
SDK callback models assume initialized OS context; this is not RTOS execution.
Strict atomic validation replaces unchecked input. Commands retain their finite
mutation prefix but send no ACK: the original inclusive loop faults at its NULL
tail before the reply builder. The server stays alive for independent status.
"""
from copy import deepcopy
from datetime import datetime, timedelta
import json
import re
from time import monotonic

from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile

KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
N_SHA = "275c49f07eeca3d3108376e7e1a1f6af891e1898521adb1c504388ceb629e3c6"
W_SHA = "03d7d3fe6486dff69a7283b79dbb585a16ee9c9977324cfce42e09ff7f622d4a"
XF_SHA = "02a696d3067afadf5460417d8c21a85a49ea8eb3dd870ca81f58e0829ce4c77a"
N_HID = "362001061394+U-W05NV1.03.bin"
W_HID = "362001061895+U-W05WV1.2.bin"
XF_HID = "362001062992+U-W05XFV1.1.bin"
COMMON = tuple("""
Pow Mod SetTem WdSpd Tur Quiet SwUpDn SwingLfRig Add0.5 TemUn TemRec Lig Air Blo
Health SvSt SwhSw HeatCoolType StHt LTemDry Wet SwhSlp SlpMod HasTmr TmrLpTms
TmrOff TmrOn CurTmHor CurTmMin TmrOnHorLf TmrOnMinLf TmrOffHorLf TmrOffMinLf
DsplySt EnvFun JFErrorCode AssHt SwhFreAir AllErr Coolmod HeatCool LedLig SmartMod
Add0.1 ModelType Wind UDFanPort DnPUDSwing DnPLLRSwing DnPRLRSwing AirQ PM2P5
ElcDatHor ElcDatDte ElcDatMth HumSen ElcP ElcOnKwh ElcAllKwhClr ElcAllKwhH
ElcAllKwhL AutoClean TemSen Emod PctCleOnTm EvapClr NobodySave BlkTemCom
HabitLearn SmartWind HandCtl VocCtl VocIdiom VocRole ImgUpdateCol EnvArea1St
EnvArea2St EnvArea3St EnvArea4St EnvArea5St EnvArea6St EnvArea7St EnvArea8St
EnvArea9St FbidBloPer DIYGra1PoiAmo SwhDIYGra1 Slp1L1 Slp1H1 Slp1L2 Slp1H2
Slp1L3 Slp1H3 Slp1L4 Slp1H4 Slp1L5 Slp1H5 Slp1L6 Slp1H6 Slp1L7 Slp1H7
Slp1L8 Slp1H8 ImgVerSta VocUpdateCol VocVerSta LigSen Video PctCleSetTm NoD
MasSub MasIDUMod GetEr HeatSvStTemMax HumiSvStTemMin CoolSvStTemMin Wmod
WsetTmp WschOn WschOnMin WschOff WschOffMin Wtmr1 Wtmr1Min Wtmr2 Wtmr2Min
Wtmr3 Wtmr3Min WsenTmpH WsenTmpM WsenTmpL Werr WsenNub WstpSv WstpH WatTmp
MaeS FanMod ModS VitiGr GasN TemSor HumSor PM2P5V VOC CO2 PctCle PctRe IDUAirQu
AirQu ODUViti GasAvail GasLED GasMod GasMas PM2P5Sta SorErr CommErr Dmod Dfltr
Dpump Dwet DwatFul DwatSen Smod Sfog RemWarnLig Security SecurityMode
ImageRecovery Srst Swat Swash SrstPP SrstPF SrstCF SrstRF SrstAF MakeWat WatErr
mode wspd light StTmr fltrst wipm25 wopm25 estate airQlt Purify ImgUpdateRes
VocUpdateRes MicroSen ReplaceHEPA UnmanedShutDown UnmanedOffTime PMVComfort
Defrost Antifreeze FavorMode ImgUpdateSta VocUpdateSta SwhWifi SwhWifiCo datDump
datRep datFailRe datPeroid subCnt HidDownPer InHidDownPer OEEPHidDownPer ACStupPos
SaveGuid NoiseSet RoomLen RoomWid RoomHigh CoolNoise HeatNoise ElcErg ElcGear
Elc1Kwh AutoUpdate AutoComnCloud lock
""".split())
N_FIELDS = COMMON + tuple("""
Wstate WschTyp Sch1 Sch2 Wtmr1StartHr Wtmr1StartMin Wtmr1EndHr Wtmr1EndMin
Wtmr2StartHr Wtmr2StartMin Wtmr2EndHr Wtmr2EndMin SetTemInt SetTemDec SwhBw
Watpercent BwErr BwBoard SwhWifiRes
""".split())
W_FIELDS = COMMON + tuple("""
NewWind AssistHeat Rinse TemRecC TemRecH TimerOnT SetTimerOn TimerOffT SetTimerOff
AppTimer AutoTemFlag SwhWifiRe
""".split())
XF_FIELDS = tuple("""
Pow Mod SetTem WdSpd Blo SvSt Humi TemUn OutHome LoopMod OutEnvTem InAirTem
InAirHumi WdSupTem ActualElec WdSupPM AirCO2 SieveState ErrCode1 ErrCode2 JFerr
NoD ElcErg ElcGear Elc1Kwh AutoUpdate AutoComnCloud lock
""".split())
METADATA = tuple("""
apssid appsw host name time lat lon vender bc mid model series brand catalog country
hid mac ver HidSvrVer InHid InHidSvrVer OEEPHid OEEPHidSvrVer
""".split())


def _integer(value):
    if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
        raise InvalidPacket("small-controller value requires a signed32 integer")
    return value


def _text(value, maximum):
    if (not isinstance(value, str) or len(value.encode()) > maximum
            or any(ord(character) < 32 for character in value)):
        raise InvalidPacket("small-controller text is invalid or too long")
    return value


def _columns(value):
    if not isinstance(value, list) or len(value) > 30:
        raise InvalidPacket("small-controller request permits at most thirty columns")
    return [_text(name, 127) for name in value]


def _members(value):
    if isinstance(value, dict):
        names = [name.casefold() for name in value]
        if len(names) != len(set(names)):
            raise InvalidPacket("ambiguous case-insensitive JSON member")
        for item in value.values():
            _members(item)
    elif isinstance(value, list):
        for item in value:
            _members(item)


def _clock(value):
    value = _text(value, 19)
    try:
        year, suffix = value.split("-", 1)
        return datetime.strptime(f"{year.zfill(4)}-{suffix}", "%Y-%m-%d %H:%M:%S")
    except ValueError as error:
        raise InvalidPacket("small-controller time requires a valid year1..9999 date and HH:MM:SS") from error


def _reply(device, inner, uid=0, selector=0, *, newline=True):
    plain = json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode()
    encrypted = (len(plain) // 16 + 1) * 16
    if encrypted > 1024 or 4 * ((encrypted + 2) // 3) + 1 > 1024:
        raise InvalidPacket("small-controller reply exceeds native 1024-byte scratch")
    reply = Reply({"t": "pack", "i": selector, "uid": uid, "cid": device.mac, "tcid": ""},
                  inner, KEY if selector else device.key, CODEC, trailing_newline=newline)
    encode_reply(reply)
    return reply


class SmallScalar:
    """One exact source namespace; N child aliases deliberately share its cache."""
    plaintext_types = ("wlan",)

    def __init__(self, source):
        self.source = source
        self.fields = {"n": N_FIELDS, "w": W_FIELDS, "xf": XF_FIELDS}[source]
        self.names = frozenset((*self.fields, *METADATA, *(["rssi"] if source == "xf" else [])))

    def validate_state(self, state):
        for name, value in state.items():
            if name not in self.fields or type(value) is not int or not 0 <= value <= 65535:
                raise ValueError("small-controller state requires source-qualified uint16 cache fields")

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        """Raw cache readouts have no established Celsius calibration."""

    def _runtime(self, device, state):
        if "_small" not in state:
            # Synthetic configured board identity, not a recovered boot default.
            state["_small"] = {"time": "1970-01-01 00:00:00", "at": device.last_step,
                               "fraction": 0.0, "timers": {}, "uid": 0, "shadow": {},
                               "host": "", "lat": "", "lon": "", "name": device.name,
                               "mid": "910001" if self.source == "n" else device.mid,
                               "vender": "0", "bc": "0" * 32, "ver": "", "pending": {},
                               "ssid": "", "psw": "", "upgrade": "",
                               "hid": device.profile.hid, "mac": device.mac}
        return state["_small"]

    def _metadata(self, device, runtime):
        return self._metadata_values(runtime)

    def advertise(self, device, outer):
        state = deepcopy(device.state)
        runtime = self._runtime(device, state)
        label = "gree"
        inner = {"t": "dev", "cid": device.mac,
                 "bc": runtime["bc"] if self.source == "n" else label,
                 "catalog": label, "mid": device.mid, "lock": 0,
                 "model": label, "name": runtime["name"], "series": label,
                 "vender": runtime["vender"], "ver": runtime["ver"], "brand": label, "mac": device.mac}
        if self.source == "n":
            inner["subCnt"] = 1
        else:
            inner["lock"] = state["lock"]
        return [_reply(device, inner, runtime["uid"], 1)]

    def _time(self, state, runtime, value):
        old, new = _clock(runtime["time"]), _clock(value)
        if (new - old).days > 366 and runtime["timers"]:
            raise InvalidPacket("synthetic timer advance is bounded to one year")
        day = old.replace(hour=0, minute=0, second=0)
        while runtime["timers"] and day <= new:
            for timer in runtime["timers"].values():
                event = day.replace(hour=timer["hr"], minute=timer["min"], second=timer["sec"])
                repeating = any(timer["week"])
                if (not timer["enable"] and old < event <= new
                        and (not repeating or timer["week"][(event.weekday() + 1) % 7])):
                    for command in timer["cmd"]:
                        self._command(state, runtime, command["opt"], command["p"])
                    if not repeating:
                        timer["enable"] = 1
            day += timedelta(days=1)
        runtime["time"] = f"{new.year}-{new:%m-%d %H:%M:%S}"

    def _advance(self, state, runtime, now):
        elapsed = max(0.0, now - runtime["at"]) + runtime["fraction"]
        seconds = int(elapsed)
        if seconds:
            self._time(state, runtime, (_clock(runtime["time"]) + timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S"))
        runtime["at"], runtime["fraction"] = now, elapsed - seconds

    def _command(self, state, runtime, names, values):
        for name, value in zip(names, values):
            if type(value) is int:
                value = _integer(value) & 65535
                if name in self.fields:
                    state[name] = value
                elif name in self.names:
                    runtime["shadow"][name] = value
            elif isinstance(value, str):
                _text(value, 127)
                if name == "time":
                    self._time(state, runtime, value)
                elif self.source != "n" and name in ("apssid", "appsw", "host", "name", "lat", "lon"):
                    limits = {"apssid": 32, "appsw": 32, "host": 20, "name": 127, "lat": 10, "lon": 10}
                    _text(value, limits[name])
                    if name == "name":
                        runtime["pending"][name] = value
                    elif name in ("apssid", "appsw"):
                        runtime["pending"][name] = value
                    else:
                        runtime[name] = value
                if self.source == "n" and name in self.names:
                    # Native cJSON strings leave the numeric valueint slot zero.
                    if name in self.fields:
                        state[name] = 0
                    else:
                        runtime["shadow"][name] = 0
            else:
                raise InvalidPacket("small-controller commands require integer or string values")

    def _metadata_values(self, runtime):
        values = {name: runtime[name] for name in
                  ("host", "name", "time", "vender", "bc", "mid", "ver", "hid", "mac")}
        if self.source != "n":
            values.update(lat=runtime["lat"], lon=runtime["lon"])
        if self.source == "w":
            values.update(InHid="", OEEPHid="")
        if self.source == "xf":
            values["rssi"] = 0  # Synthetic radio readout, not measured RSSI.
        return values

    def _timer(self, inner):
        timer_id = _integer(inner.get("id")) & 255
        hour, minute, second = (_integer(inner.get(field)) for field in ("hr", "min", "sec"))
        if not 0 <= hour < 24 or not 0 <= minute < 60 or not 0 <= second < 60:
            raise InvalidPacket("small-controller timer requires a valid time of day")
        week = inner.get("week")
        if not isinstance(week, list) or len(week) > 7:
            raise InvalidPacket("small-controller timer requires at most seven weekdays")
        week = [_integer(value) for value in week] + [0] * (7 - len(week))
        commands = inner.get("cmd")
        if not isinstance(commands, list) or len(commands) > 10:
            raise InvalidPacket("small-controller timer permits ten command records")
        parsed = []
        for command in commands:
            if not isinstance(command, dict):
                raise InvalidPacket("invalid small-controller timer command")
            macs = command.get("mac")
            if not isinstance(macs, list) or len(macs) > 10:
                raise InvalidPacket("invalid small-controller timer identity array")
            names, values = _columns(command.get("opt")), command.get("p")
            if not names or not isinstance(values, list) or len(values) != len(names):
                raise InvalidPacket("small-controller timer command arrays must match and be nonempty")
            values = [_integer(value) for value in values]
            if self.source in ("n", "w", "xf"):
                # These three original parsers hardcode descriptor opt-count one.
                names, values = names[:1], values[:1]
            parsed.append({"mac": [_text(mac, 19) for mac in macs], "opt": names, "p": values})
        return timer_id, {"id": timer_id, "name": _text(inner.get("name"), 19),
                          "enable": int(bool(_integer(inner.get("enable")))), "hr": hour,
                          "min": minute, "sec": second, "tz": _integer(inner.get("tz")) & 255,
                          "week": week, "cmd": parsed}

    def _dispatch(self, device, state, runtime, inner):
        kind = inner.get("t")
        response_mac = device.mac
        if self.source == "n":
            alias = inner.get("sub", inner.get("mac", device.mac))
            if not isinstance(alias, str) or not re.fullmatch(r"[0-9a-f]{12}(?:[0-9a-f]{2})?", alias):
                raise InvalidPacket("N cache alias requires a bounded synthetic MAC")
            response_mac = alias
        elif "sub" in inner or inner.get("mac", device.mac) != device.mac:
            raise InvalidPacket("small-controller request targets a different root")
        if kind == "bind":
            if inner.get("mac") != device.mac:
                raise InvalidPacket("small-controller bind must target the root")
            return {"t": "bindok", "mac": device.mac, "r": 200, "key": device.key.decode("ascii")}, 1, True
        if kind == "status":
            requested = _columns(inner.get("cols"))
            metadata = self._metadata(device, runtime)
            columns, values = [], []
            # The native exact-capacity first-hole scan resets the count to zero at thirty.
            if len(requested) == 30 and all(name and len(name.encode()) < 16 for name in requested):
                requested = []
            for name in requested:
                if not name or len(name.encode()) >= 16:
                    break
                if name in self.names:
                    columns.append(name)
                    if name in self.fields:
                        values.append(state[name])
                    elif name in metadata:
                        values.append(metadata[name])
            return {"t": "dat", "mac": response_mac, "r": 200, "cols": columns, "dat": values}, 0, True
        if kind == "cmd":
            names, values = _columns(inner.get("opt")), inner.get("p")
            if not isinstance(values, list) or len(names) != len(values):
                raise InvalidPacket("small-controller command arrays must match")
            self._command(state, runtime, names, values)
            return None, 0, True
        if kind == "subDev" and self.source == "n":
            start = _integer(inner.get("i")) & 65535
            response = {"t": "subList", "c": 1, "i": start, "r": 200, "list": []}
            if start == 0:
                response["list"] = [{"mac": device.mac + "01", "mid": "910001",
                                     "name": "GreeHot", "model": "gree", "lock": 0}]
            return response, 0, True
        if kind in ("setT", "updateT"):
            timer_id, timer = self._timer(inner)
            if timer_id not in runtime["timers"] and len(runtime["timers"]) >= 10:
                return ({"t": "resT", "r": 500}, 0, False) if kind == "setT" else (None, 0, False)
            runtime["timers"][timer_id] = timer
            return {"t": "resT", "r": 200}, 0, False
        if kind == "deleteT":
            runtime["timers"].pop(_integer(inner.get("id")) & 255, None)
            return {"t": "resT", "r": 200}, 0, False
        if kind == "queryT":
            start, count = (_integer(inner.get(field)) & 255 for field in ("index", "count"))
            response = {"t": "listT", "total": count, "index": start}
            if runtime["timers"]:
                response["list"] = [{name: deepcopy(timer[name]) for name in
                                     ("id", "name", "enable", "hr", "min", "sec", "week", "cmd")}
                                    for ordinal, timer in enumerate(runtime["timers"].values())
                                    if start <= ordinal <= start + count]
            return response, 0, False
        if kind == "surver" and self.source != "n":
            return {"t": "ret", "r": 200, "mac": device.mac}, None, True
        if kind == "upgrade":
            runtime["upgrade"] = _text(inner.get("url"), 159)
            return ((None, 0, True) if self.source == "n" else
                    ({"t": "ret", "r": 200, "mac": device.mac}, None, True))
        return None, 0, True

    def handle(self, device, outer):
        _members(outer)
        state = deepcopy(device.state)
        runtime = self._runtime(device, state)
        now = monotonic()
        if outer.get("t") == "wlan":
            ssid, psw, host, lat, lon = (_text(outer.get(name), maximum) for name, maximum in
                                        (("ssid", 31), ("psw", 31), ("host", 19), ("lat", 11), ("lon", 11)))
            self._advance(state, runtime, now)
            runtime.update(ssid=ssid, psw=psw, host=host, lat=lat, lon=lon)
            reply = Reply({"t": "ret", "r": 200, "mac": device.mac}, trailing_newline=True)
            encode_reply(reply)
        else:
            if self.source == "r-descriptor":
                if outer.get("t") != "pack":
                    raise InvalidPacket("small-controller request must be packed")
                tcid = outer.get("tcid")
                # Limit replay to the TCID buffer; native strcpy overflow is out of scope.
                if (not isinstance(tcid, str) or len(tcid) > 12
                        or not tcid.isascii() or "\0" in tcid):
                    raise InvalidPacket("W04R TCID exceeds the normal-operation boundary")
            elif outer.get("t") != "pack" or outer.get("tcid") != device.mac:
                raise InvalidPacket("small-controller request must target this root")
            index = _integer(outer.get("i"))
            uid = _integer(outer.get("uid", runtime["uid"]))
            inner = decode_pack(outer, KEY if index else device.key, CODEC)
            _members(inner)
            if (self.source == "r-descriptor"
                    and inner.get("mac", outer.get("tcid")) != device.mac):
                raise InvalidPacket("W04R request must target this MAC")
            self._advance(state, runtime, now)
            response, selector, newline = self._dispatch(device, state, runtime, inner)
            runtime["uid"] = uid
            if response is None:
                reply = None
            elif selector is None:
                reply = Reply(response, trailing_newline=newline)
                encode_reply(reply)
            else:
                reply = _reply(device, response, uid, selector, newline=newline)
        device.advance(now)
        device.state = state
        return [] if reply is None else [reply]


PROFILES = (
    Profile("sim-w05n-v103", ("9100",), N_HID, N_SHA, dict.fromkeys(N_FIELDS, 0), SmallScalar("n")),
    Profile("sim-w05w-v12", ("3019",), W_HID, W_SHA, dict.fromkeys(W_FIELDS, 0), SmallScalar("w")),
    Profile("sim-w05xf-v11", ("3020",), XF_HID, XF_SHA, dict.fromkeys(XF_FIELDS, 0), SmallScalar("xf")),
)


R_SHA = "37d3a80eb74a476996763ff458a0b528518b6e09ead2abd43f497bedf452974d"
RW_SHA = "7ce72a73489d3f8a44f57351cfdf939d208d855c6b2e0a59dc0e84514d8d1fad"
R_HID = "362001061329+U-W04RV2.03.bin"
RW_HID = "362001061704+U-W04WV1.25.bin"
# These are separately selected source tables, not a union of polling presets.
DESCRIPTORS = {
    "r-air": ("Pow Wspd Mode PM25 PM25Level Light SetHumidity EnvHumidity ReplaceFilter "
              "RefreshWater AirChildLock FiltUPercent TmrHour TmrMin TmrOn TmrAction "
              "estate estate1 estate2 estate3 MidType").split(),
    "r-sdk-air": ("WindSpeed WorkMode PowerSwitch ChildLockSwitch PM25 PM25Level LightSwitch "
                  "HumiditySetting CurrentHumidity TimeMeter WaterTankMin WaterTankHour "
                  "FilterScreen1 ReplaceFilterReminder RefreshWaterReminder").split(),
    "r-fan": ("Pow WdSpd Mod Rotate Cycle TmrHour TmrMin TmrOn TmrAction SwUpDn SwingLfRig "
              "Wet Anion HotWind estate estate1 estate2 estate3 MidType").split(),
    "r-sdk-fan": ("WindSpeed Humidification WorkMode OscillatingSwitch PowerSwitch WaterShortage "
                  "VerticalAngle HorizontalAngle SmartMode").split(),
    "w-air": ("Pow Wspd Mode PM25 PM25Level Light SetHumidity EnvHumidity ReplaceFilter "
              "RefreshWater AirChildLock FiltUPercent TmrHour TmrMin TmrOn TmrAction "
              "estate estate1 estate2 estate3 MidType").split(),
    "w-sdk-air": ("WindSpeed WorkMode PowerSwitch ChildLockSwitch PM25 PM25Level LightSwitch "
                  "HumiditySetting CurrentHumidity FilterScreen1 ReplaceFilterReminder "
                  "RefreshWaterReminder").split(),
    "w-fan": ("Pow WdSpd Mod Rotate Cycle TmrHour TmrMin TmrOn TmrAction SwUpDn SwingLfRig "
              "UpDnAngle LRAngle Wet Anion HotWind estate estate1 estate2 estate3 JFerr MidType").split(),
    "w-sdk-fan-basic": ("WindSpeed Humidification WorkMode OscillatingSwitch PowerSwitch WaterShortage "
                        "VerticalAngle HorizontalAngle SmartMode").split(),
    "w-sdk-fan": ("powerstate windspeed mode angleAutoLROnOff angleAutoUDOnOff angleLR errorCode").split(),
    "w-humidifier": "Pow Mode FogLevel WaterTankLight Humidity Estate1 Estate2 Estate3 MidType".split(),
    "w-sdk-humidifier": "powerstate mode fog illumination humidity errorCode".split(),
    "w-heater": ("Pow Humidification Swing ChildLock Anion HeatLevel SetTemp EnvTemp WorkTimeHour "
                 "WorkTimeSec RealHeatLevel FanLevel HeatMode TmrOn TmrAction TmrHour TmrMin "
                 "estate estate2 estate3 JFerr MidType").split(),
    "w-heater-04": ("Pow Humidification Swing AirChildLock Anion HeatLevel SetTemp EnvTemp WorkTimeHour "
                    "WorkTimeSec RealHeatLevel FanLevel HeatMod TimeStart TmrAction TmrHour TmrMin "
                    "estate estate2 estate3 JFerr MidType").split(),
    "w-sdk-heater": "powerstate angleAutoLROnOff childLockOnOff anionOnOff targetTemperature mode errorCode".split(),
    "w-gas": ("SetTemp Cruise Mode HotMode Pow PreBoost CruiseState BurnState EnvironmentTemp KitRecomTemp "
              "BathRecomTemp BathtubTemp HotBacKValue OutWaterTemp InWaterTemp MaximumTime UsedTime "
              "GasSafeLife CasSafeTimes ErrorCode1 ErrorCode2 ErrorCode3 JFerr MidType").split(),
    "w-sdk-gas": ("singleCycle stepActionOnOff allDay noneColdWater mode waterHeaterCondition turboMode "
                  "targetTemperature powerstate errorCode").split(),
    "w-fridge": ("intel fastFrz fastCool deepFrz coldSto coldStoSetTem freezeSetTem temVarSetTem "
                 "ErrorCode1 ErrorCode2 ErrorCode3 JFerr MidType").split(),
    "w-sdk-fridge": "mode fridgeSwitch fridgeTargetTemperature freezerTargetTemperature errorCode".split(),
}
_TIMER_ZERO = dict.fromkeys(("TmrHour", "TmrMin", "TmrOn", "TmrAction"), 0)
_BOARD_ZERO = dict.fromkeys(("estate", "estate1", "estate2", "estate3", "MidType", "JFerr"), 0)
# Changed-cache callbacks consume frozen zero companion frames, not Celsius.
# Native LAN status itself only serializes the mutable descriptor value word.
RELOAD = {
    "r-air": {**_TIMER_ZERO, **_BOARD_ZERO, "PM25": 0, "PM25Level": 1},
    "r-sdk-air": {"PM25": 0, "PM25Level": 1},
    "r-fan": {**_TIMER_ZERO, **_BOARD_ZERO},
    "r-sdk-fan": {"WorkMode": 1, "WaterShortage": 0, "SmartMode": 0},
    "w-air": {**_TIMER_ZERO, **_BOARD_ZERO, "PM25": 0, "PM25Level": 1},
    "w-sdk-air": {"PM25": 0, "PM25Level": 1},
    "w-fan": {**_TIMER_ZERO, **_BOARD_ZERO},
    "w-sdk-fan-basic": {"WorkMode": 1, "WaterShortage": 0, "SmartMode": 0},
    "w-sdk-fan": {"mode": 39, "angleAutoLROnOff": 0, "angleAutoUDOnOff": 0, "errorCode": 149},
    "w-humidifier": {"Estate1": 0, "Estate2": 0, "Estate3": 0, "MidType": 0},
    "w-sdk-humidifier": {"mode": 39, "errorCode": 149},
    "w-heater": {**_TIMER_ZERO, **_BOARD_ZERO},
    "w-heater-04": {**_TIMER_ZERO, **_BOARD_ZERO, "TimeStart": 0},
    "w-sdk-heater": {"errorCode": 149},
    "w-gas": {**_BOARD_ZERO, "GasSafeLife": 0, "CasSafeTimes": 0,
              "ErrorCode1": 0, "ErrorCode2": 0, "ErrorCode3": 0},
    "w-sdk-gas": {"singleCycle": 0, "stepActionOnOff": 0, "allDay": 0, "noneColdWater": 0,
                  "mode": 39, "waterHeaterCondition": 0, "targetTemperature": -100, "errorCode": 149},
    "w-fridge": {**_BOARD_ZERO, "ErrorCode1": 0, "ErrorCode2": 0, "ErrorCode3": 0},
    "w-sdk-fridge": {"mode": 16, "fridgeSwitch": 1, "fridgeTargetTemperature": -50,
                     "freezerTargetTemperature": -50, "errorCode": 149},
}


class SmallDescriptor(SmallScalar):
    """Mutable int32 descriptor cache with explicitly frozen companion inputs."""
    def __init__(self, table):
        self.table = table
        self.source = "r-descriptor" if table.startswith("r-") else "w-descriptor"
        self.fields = tuple(DESCRIPTORS[table])
        self.accept_any_target = self.source == "r-descriptor"
        self.names = frozenset((*self.fields, *METADATA,
                                *(("rssi",) if self.source == "w-descriptor" else ())))

    def validate_state(self, state):
        for name, value in state.items():
            if name not in self.fields or type(value) is not int or not -(1 << 31) <= value < (1 << 31):
                raise ValueError("descriptor state requires source-qualified signed32 cache fields")

    def _runtime(self, device, state):
        runtime = super()._runtime(device, state)
        if "tx_mode" not in runtime:
            runtime.update(tx_mode=0, gas_mode=39, angle_lr_raw=0, heat_mode=0)
        return runtime

    def _metadata_values(self, runtime):
        values = {name: runtime[name] for name in ("host", "name", "time", "hid")}
        if self.source == "w-descriptor":
            values["rssi"] = 0
        return values

    def advertise(self, device, outer):
        state = deepcopy(device.state)
        runtime = self._runtime(device, state)
        inner = {"t": "dev", "cid": "", "bc": "gree", "catalog": "gree",
                 "mid": device.mid, "lock": 0, "model": "gree", "name": runtime["name"],
                 "series": "gree", "vender": runtime["vender"], "ver": runtime["ver"],
                 "brand": "gree", "mac": device.mac}
        return [_reply(device, inner, runtime["uid"], 1)]

    def _command(self, state, runtime, names, values):
        for name, value in zip(names, values):
            if name == "ReportClientID" and self.source == "w-descriptor":
                value = _text(value, 127)
                if value:
                    runtime["pending"][name] = value
                continue
            if name == "time":
                self._time(state, runtime, value)
                continue
            value = _integer(value)
            if name not in self.fields:
                continue
            previous = state[name]
            state[name] = value
            if self.table in ("r-sdk-fan", "w-sdk-fan-basic"):
                if name == "WorkMode":
                    runtime["tx_mode"] = (value - 1) & 7
                elif name == "SmartMode":
                    if runtime["tx_mode"] in (2, 6):
                        if value == 1:
                            runtime["tx_mode"] = 6
                    else:
                        state[name] = 0
            if self.table == "w-sdk-gas" and name == "mode" and value in (39, 245, 246, 890):
                runtime["gas_mode"] = value
            if self.table == "w-sdk-fan":
                if name == "mode" and value in (39, 21, 166):
                    runtime["heat_mode"] = int(value == 166)
                    if value == 166:
                        runtime["angle_lr_raw"] = 20
                elif name == "angleAutoLROnOff":
                    runtime["angle_lr_raw"] = (20 if runtime["heat_mode"] else 12) if value == 1 else 0
                    runtime["heat_mode"] = 0
                elif name == "angleLR" and value in (60, 80, 100):
                    runtime["angle_lr_raw"] = {60: 12, 80: 16, 100: 20}[value]
            # Default masked serial writes do not clamp the LAN int32 value.
            # Only a changed cache invokes the source's explicit read callback.
            if state[name] != previous:
                if self.table == "w-sdk-gas" and name == "mode":
                    state[name] = runtime["gas_mode"]
                elif self.table == "w-sdk-fan" and name == "angleLR":
                    state[name] = {12: 60, 16: 80, 20: 100}.get(runtime["angle_lr_raw"], state[name])
                elif name in RELOAD[self.table]:
                    state[name] = RELOAD[self.table][name]

    def _dispatch(self, device, state, runtime, inner):
        kind = inner.get("t")
        if "sub" in inner or inner.get("mac", device.mac) != device.mac:
            raise InvalidPacket("descriptor cache has no child identity aliases")
        if kind == "status":
            requested = _columns(inner.get("cols"))
            metadata = self._metadata_values(runtime)
            columns, values = [], []
            if len(requested) == 30 and all(name and len(name.encode()) < 30 for name in requested):
                requested = []
            for name in requested:
                if not name or len(name.encode()) >= 30:
                    break
                if name in self.names:
                    columns.append(name)
                    if name in self.fields:
                        values.append(state[name])
                    elif name in metadata:
                        values.append(metadata[name])
            return {"t": "dat", "mac": device.mac, "r": 200, "cols": columns, "dat": values}, 0, True
        if kind == "surver":
            return {"t": "configok", "r": "200", "mac": device.mac}, None, True
        if kind == "upgrade":
            runtime["upgrade"] = _text(inner.get("url"), 159)
            return None, 0, True
        return super()._dispatch(device, state, runtime, inner)


def _descriptor_profile(table, mids):
    old = table.startswith("r-")
    return Profile("sim-" + ("w04r-v203-" if old else "w04w-v125-") + table.split("-", 1)[1],
                   mids, R_HID if old else RW_HID, R_SHA if old else RW_SHA,
                   dict.fromkeys(DESCRIPTORS[table], 0), SmallDescriptor(table))


PROFILES += (
    _descriptor_profile("r-air", ("828140",)),
    _descriptor_profile("r-sdk-air", ("828140",)),
    _descriptor_profile("r-fan", ("828202", "828203", "828204")),
    _descriptor_profile("r-sdk-fan", ("828202", "828203", "828204")),
    _descriptor_profile("w-air", ("828140",)),
    _descriptor_profile("w-sdk-air", ("828140",)),
    _descriptor_profile("w-fan", ("828202", "828203", "828204", "828209")),
    _descriptor_profile("w-sdk-fan", ("828209",)),
    _descriptor_profile("w-humidifier", ("828502",)),
    _descriptor_profile("w-sdk-humidifier", ("828502",)),
    _descriptor_profile("w-heater", ("828a00", "828a01")),
    _descriptor_profile("w-heater-04", ("828a04",)),
    _descriptor_profile("w-sdk-heater", ("828a00", "828a01", "828a04")),
    _descriptor_profile("w-gas", ("829100",)),
    _descriptor_profile("w-sdk-gas", ("829100",)),
    _descriptor_profile("w-fridge", ("28c96",)),
    _descriptor_profile("w-sdk-fridge", ("28c96",)),
    _descriptor_profile("w-sdk-fan-basic", ("828202", "828203", "828204")),
)
