"""Exact historical WB raw roots, with explicitly synthetic report/RTC inputs.

These are module-cache wire models, not typed ACs or mainboard boots. Initial
raw reports are zero, RSSI is -50 and RTC starts at the Unix epoch. Commands
update evidenced low16 caches, never calibrated appliance physics. The safe
parser is strict/atomic and omits unknown status names instead of entering
native NULL-tail strcmp. MAJD additionally uses first-match cache selection
instead of its ROM-dependent scan through NULL pointers. Unsafe reset/binCmd paths are
rejected, never converted into fabricated successful acknowledgements.

ART definitions remain reusable source-bounded models, but PROFILES excludes
ART and SR: their original final senders do not provide native UDP replies.
"""

import base64
import binascii
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import re
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from ..wire import InvalidPacket, Reply, decode_outer, decode_pack, encode_reply
from . import Profile

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _clock_challenge(value, key):
    value = _text(value, "encrypt", 32)
    try:
        encrypted = base64.b64decode(value, validate=True)
        if not encrypted or len(encrypted) % 16:
            raise ValueError("invalid AES block length")
        plain = unpad(AES.new(key, AES.MODE_ECB).decrypt(encrypted), 16)
    except (ValueError, binascii.Error) as exc:
        raise InvalidPacket("invalid WB clock challenge") from exc
    if not plain.startswith(b"key is ok"):
        raise InvalidPacket("WB clock challenge does not match")


ART_NAMES = tuple((
    'SwhWifi SwhWifiRes SwhWifiConf AutoUpdate AutoConnCloud lock datDump datRep datFailRep datPeroid '
    'subCnt useTCP vender bc mid model series apssid appsw brand catalog country hid host mac name time '
    'ver city cnty cityid lat lon Pow Mod SetTem WdSpd Tur Quiet SwUpDn SwingLfRig TemUn TemRec Lig Air '
    'Blo Health SvSt SwhSw HeatCoolType StHt LTemDry Wet SwhSlp SlpMod HasTmr TmrLpTms TmrOff TmrOn '
    'CurTmHor CurTmMin TmrOnHorLf TmrOnMinLf TmrOffHorLf TmrOffMinLf DsplySt EnvFun JFErrorCode AssHt '
    'FrshAir AllErr Coolmod MasSub MasIDUMod GetEr CoolSvStTemMin HeatSvStTemMax HumiSvStTemMin MaeS '
    'FanMod ModS VitiGr GasN TemSor HumSor PM2P5 VOC CO2 PctCle PctRe IDUAirQu AirQu ODUViti GasAvail '
    'GasLED GasMod GasMas PM2P5Sta SorErr CommErr GasQ RunMod Inloop InVitiGr InVitiGrCg IFDtiGr '
    'InEffClRes InEffReRes IFDClRes EffReRes ErrType GoOut AidHeat SetCoolHumi SetDeciTem SysSta HCHO '
    'HCHOEN PM2P5EN MdVitiGr MdVitGrCg MdEffClRes MdEffReRes InloopEN Tcloud SorSet Add0.1 Add0.5 '
    'HumiEnable TemBody CleanState AutoClean CleanTime AutoSetTemEn Light AssHtSet JFerr AntiFreeze '
    'CleanEn ExtraMod InSeries HalfTemEn ActualWdSpd Heat3DSvStTemMax Heat2SvStTemMax LowDeHumi IDUModSet '
    'MasSubEn Can1MasSubEn Can1MasSub FClTime PlProg FClRes IDURunMod Humi2SvStTemMin AirLevel Idemand '
    'CoolSvStTemMinD HumiSvStTemMinD HeatSvStTemMaxD MIdType AppTimer rssi ModelType Heat3DSvStTemMaxD '
    'Heat2SvStTemMaxD MSysStatus InTem OutTem InHumi ScheCoolTem ScheHeatTem ScheName ScheEnable '
    'RemoteLock HoldSetTemp Wstate WschTyp Sch1 Sch2 Wtmr1StartHr Wtmr1StartMin Wtmr1EndHr Wtmr1EndMin '
    'Wtmr2StartHr Wtmr2StartMin Wtmr2EndHr Wtmr2EndMin SetTemInt SetTemDec SwhBw Wmod WstpSv WstpH WatTmp '
    'Watpercent BwErr BwBoard ComEqui FlagHeat PowHeat IntelCtrl OrderHeat ErrHeat HeatTemMax HeatTemInt '
    'HeatTemDec Defrost MuteSch1 MuteSch2 Mtmr1StartHr Mtmr1StartMin Mtmr1EndHr Mtmr1EndMin Mtmr2StartHr '
    'Mtmr2StartMin Mtmr2EndHr Mtmr2EndMin PoolFunc FlagPool UaeEn Lamp LigEn ComStatus PumpStatus '
    'AuxStatus InTemInt InTemDec OutTemInt OutTemDec HeatTemMin CoolTemMax CoolTemMin FastHtWter '
    'ColHtWter HetHtWter LefHom SwDisFct CoWatOutTemSet HeWatOutTemSet CoHomTemSet HeHomTemSet '
    'WatBoxTemSet Reset TemRecB Emegcy AllInWatTemHi AllInWatTemLo AllOutWatTemHi AllOutWatTemLo '
    'HepOutWatTemHi HepOutWatTemLo WatBoxTemHi WatBoxTemLo RmoHomTemHi RmoHomTemLo WatBoxElcHeRunSta '
    'SyAnFroRunSta ElcHe1RunSta ElcHe2RunSta AnFrzzRunSta VersatiSeries WatBoxExt BordTest RomHomTemExt '
    'FocModSwh ColColetSwh EndTemCotSwh HanFroSwh WatSyExhSwh EVU EleJan EleFeb EleMar EleApr EleMay '
    'EleJun EleJul EleAug EleSep EleOct EleNov EleDec EleLastYear AddCap AddCapTemMin DREDEn DRED NewGB '
    'CoEnvTemSet DEnvTemSet WdEnvTemSet HeEnvTemSet FheEnvTemSet CleanData HolidaySwitch HolidayCycle '
    'HolidayRemain DisinfectSwitch DisinfectStatus DisinfectCycle DisinfectHour DisinfectRemain ECO1 ECO2 '
    'ECO1StartHr ECO1StartMin ECO1EndHr ECO1EndMin ECO2StartHr ECO2StartMin ECO2EndHr ECO2EndMin '
    'ConsumeDisplayEn ACLkg LkgModEN Hum DeHum AirBoxLgSwt HumSet DeHumSet HECoreCleRes RunModSet '
    'AutoModEN NewWind AssistHeat Rinse TemRecC TemRecH AutoTemFlag Buzzer_ON_OFF override DRLevel '
    'Duration RemainDuration MaxTempRise DRState ElcP ElcAllKwhH ElcAllKwhL DRType DROnline TempRiseValid '
).split())

MARJ_NAMES = tuple((
    'Pow Mod SetTem WdSpd Tur Quiet SwUpDn SwingLfRig Add0.5 TemUn TemRec Lig Air Blo Health SvSt SwhSw '
    'HeatCoolType StHt LTemDry Wet SwhSlp SlpMod HasTmr TmrLpTms TmrOff TmrOn CurTmHor CurTmMin '
    'TmrOnHorLf TmrOnMinLf TmrOffHorLf TmrOffMinLf DsplySt EnvFun JFErrorCode AssHt SwhFreAir AllErr '
    'Coolmod HeatCool LedLig SmartMod Add0.1 ModelType NoD NoD NoD NoD NoD Buzzer_ON_OFF ElcEn EnvTem '
    'DFPoint CpsTem TemsSenOut FaultDisplay NoD NoD NoD Wind UDFanPort DnPUDSwing DnPLLRSwing DnPRLRSwing '
    'AirQ PM2P5 ElcDatHor ElcDatDte ElcDatMth HumSen ElcP ElcOnKwh ElcAllKwhClr ElcAllKwhH ElcAllKwhL '
    'AutoClean TemSen Emod PctCleOnTm EvapClr NobodySave BlkTemCom HabitLearn SmartWind HandCtl VocCtl '
    'VocIdiom VocRole ImgUpdateCol EnvArea1St EnvArea2St EnvArea3St EnvArea4St EnvArea5St EnvArea6St '
    'EnvArea7St EnvArea8St EnvArea9St FbidBloPer DIYGra1PoiAmo SwhDIYGra1 Slp1L1 Slp1H1 Slp1L2 Slp1H2 '
    'Slp1L3 Slp1H3 Slp1L4 Slp1H4 Slp1L5 Slp1H5 Slp1L6 Slp1H6 Slp1L7 Slp1H7 Slp1L8 Slp1H8 ImgVerSta '
    'VocUpdateCol VocVerSta LigSen Video PctCleSetTm AppTimer CO2Level Dazzling NewTimer NewTimerSet '
    'UvcControl MasSub MasIDUMod GetEr HeatSvStTemMax HumiSvStTemMin CoolSvStTemMin NoD NoD NoD NoD NoD '
    'NoD NoD NoD NoD Wmod WsetTmp WschOn WschOnMin WschOff WschOffMin Wtmr1 Wtmr1Min Wtmr2 Wtmr2Min Wtmr3 '
    'Wtmr3Min WsenTmpH WsenTmpM WsenTmpL Werr WsenNub WstpSv WstpH WatTmp NoD NoD NoD NoD NoD NoD NoD NoD '
    'NoD NoD MaeS FanMod ModS VitiGr GasN TemSor HumSor PM2P5V VOC CO2 PctCle PctRe IDUAirQu AirQu '
    'ODUViti GasAvail GasLED GasMod GasMas PM2P5Sta SorErr CommErr EnergyFlow NoD NoD NoD NoD NoD NoD NoD '
    'NoD NoD NoD NoD NoD Dmod Dfltr Dpump Dwet DwatFul DwatSen estateInsta21 estateInsta22 estateInsta23 '
    'estateInsta24 ChildLock NoD NoD NoD NoD Smod Sfog RemWarnLig NoD NoD Security SecurityMode '
    'ImageRecovery NoD NoD NoD NoD NoD NoD NoD Srst Swat Swash SrstPP SrstPF SrstCF SrstRF SrstAF MakeWat '
    'WatErr NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD mode wspd light StTmr fltrst wipm25 wopm25 estate '
    'airQlt Purify NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD ImgUpdateSucs VocUpdateRes MicroSen '
    'ReplaceHEPA UnmanedShutDown UnmanedOffTime PMVComfort Defrost Antifreeze FavorMode ImgUpdateSta '
    'ImgUpdateFail VocUpdateSta NoD NoD SmartSlpMod SmartSlpModEx StSlp1C StSlp1CInc StSlp1CSp StSlp1H '
    'StSlp1HInc StSlp1HSp StSlp2C StSlp2CInc StSlp2CSp StSlp2H StSlp2HInc StSlp2HSp StSlp3C StSlp3CInc '
    'StSlp3CSp StSlp3H StSlp3HInc StSlp3HSp StSlp4C StSlp4CInc StSlp4CSp StSlp4H StSlp4HInc StSlp4HSp '
    'AntiDirectBlow NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD '
    'NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD SwhWifi SwhWifiRe SwhWifiCo '
    'datDump datRep datFailRe datPeroid subCnt HidDownPer InHidDownPer OEEPHidDownPer NoD NoD NoD NoD NoD '
    'NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD ACStupPos SaveGuid '
    'NoiseSet RoomLen RoomWid RoomHigh CoolNoise HeatNoise NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD '
    'NoD ElcErg ElcGear Elc1Kwh AutoUpdate AutoComnCloud lock NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD '
    'NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD apssid appsw host name time lat lon NoD NoD NoD '
    'NoD NoD NoD NoD NoD vender bc mid model series brand catalog country hid mac ver HidSvrVer InHid '
    'InHidSvrVer OEEPHid OEEPHidSvrVer '
).split())

ART138_NAMES = ART_NAMES[:324]
MAJD_NAMES = tuple("NoD" if index in (52, 53, 54, 55, 56, 129) else name
                   for index, name in enumerate(MARJ_NAMES))
BUILDS = (
    ("sim-wb05art11-v1.48-raw", "ART", "1.48",
     "362001065567+U-WB05ART11V1.48.bin",
     "66c6e0462045a25ea3a1f7a4aff7396da7d2109b15f106600b2b82255c81e16c"),
    ("sim-wb05art11-v1.38-raw", "ART", "1.38",
     "362001065567+U-WB05ART11V1.38.bin",
     "7d1b5ae267193fd149461770f94272b3ddf76ba6e29e7a553f95219f71205032"),
    ("sim-wb05marj-v1.25-raw", "MARJ", "1.25",
     "362001066140+U-WB05MARJV1.25.bin",
     "8b852ca289c8609daec94c5bba9369959e006b4ebb0bd86078ae534e0e61dd12"),
    ("sim-wb05marj-v1.31-raw", "MARJ", "1.31",
     "362001066140+U-WB05MARJV1.31.bin",
     "2a5d355b244b143a674ad07e1ff20fecae311a9f328e1872b9720ee09237a48e"),
    ("sim-wb05majd-v1.03-raw", "MAJD", "1.03",
     "362001066140+U-WB05MAJDV1.03.bin",
     "883262273da14a437516207d8f99964668f3db69e9eb9e84839a83ec372a64a6"),

)
LOCAL_NAMES = frozenset(("time", "name", "lock", "AutoUpdate", "host", "hid", "mid",
                         "bc", "DevID", "MafIdf", "AppTimer", "MidType", "ReportClientID"))
NO_VALUE = frozenset(("DevID", "MafIdf"))


def _integer(value, name):
    if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
        raise InvalidPacket(f"WB {name} requires signed int32")
    return value


def _text(value, name, maximum):
    if not isinstance(value, str) or "\0" in value or len(value.encode()) > maximum:
        raise InvalidPacket(f"WB {name} exceeds its bounded string buffer")
    return value


def _names(value):
    if not isinstance(value, list) or len(value) > 64:
        raise InvalidPacket("WB property arrays are bounded to 64 entries")
    for name in value:
        if not _text(name, "property", 511):
            raise InvalidPacket("WB property names cannot be empty")
    if sum(len(name.encode()) + 1 for name in value) > 512:
        raise InvalidPacket("WB property names exceed the 512-byte text buffer")
    return value


def _calendar(value):
    _text(value, "time", 19)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", value):
        raise InvalidPacket("WB time requires YYYY-MM-DD HH:MM:SS")
    try:
        return (datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc) - EPOCH).total_seconds()
    except ValueError as exc:
        raise InvalidPacket("invalid WB calendar time") from exc


def _clock(state, now):
    previous = state.get("_clock_at")
    if previous is not None:
        state["_clock"] = min(253402300799, state["_clock"] + max(0, now - previous))
    state["_clock_at"] = now


def _clock_text(state):
    value = EPOCH + timedelta(seconds=int(state["_clock"]))
    return f"{value.year:04d}-{value:%m-%d %H:%M:%S}"


def _initial(names):
    return {"reported": dict.fromkeys(names, 0), "outbound": [], "timers": [],
            "_clock": 0, "_clock_at": None, "_rssi": -50, "_app_timer": 0,
            "_lock": 0, "_auto_update": 0, "_mid_type": 0,
            "_report_client": "", "_active_time": 0, "_report_interval": 0,
            "_report_anyway": 0, "_time_valid": 0, "_send_freq": 0}


class WBRemainingFamily:
    plaintext_types = ("wlan", "tm", "hbok")

    def wlan(self, device, outer):
        config = {name: _text(outer.get(name, ""), name, bound)
                  for name, bound in (("host", 19), ("ssid", 32), ("psw", 64))}
        state = deepcopy(device.state)
        state["_network"] = config
        state["outbound"].append(("wlan-config", config.copy()))
        device.state.update(state)
        return [Reply({"t": "ret", "r": 200, "mac": device.mac})]

    def _plaintext(self, device, outer):
        kind = outer.get("t")
        if kind == "wlan":
            return self.wlan(device, outer)
        state = deepcopy(device.state)
        if kind == "tm":
            if self.flavor == "MARJ" and "encrypt" in outer:
                _clock_challenge(outer["encrypt"], device.key)
            if "time" in outer:
                state["_clock"] = _calendar(outer["time"])
                state["_clock_at"] = time.monotonic()
            if self.flavor == "MARJ":
                if "homeId" in outer:
                    state["_home_id"] = _integer(outer["homeId"], "homeId")
                if "reportAnyway" in outer:
                    state["_report_anyway"] = 2 if outer["reportAnyway"] else 1
        elif kind == "hbok":
            state["_heartbeat_ok"] = True
        device.state.update(state)
        return []

    def __init__(self, flavor, version):
        self.flavor = flavor
        self.version = version
        self.art = flavor == "ART"
        self.names = (ART138_NAMES if version == "1.38" else ART_NAMES) if self.art else (
            MAJD_NAMES if flavor == "MAJD" else MARJ_NAMES)
        self.local = LOCAL_NAMES | ({"ModelType", "ver"} if self.art else set())

    def validate_state(self, state):
        if state != _initial(self.names):
            raise ValueError("WB raw reports have fixed explicitly synthetic initialization")

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        # Raw readings are declared synthetic cache values, not an unavailable sensor timeout.
        return None

    def _metadata(self, device, state):
        return {"name": device.name, "host": "dis.gree.com", "mid": device.mid,
                "hid": device.profile.hid, "bc": "0" * 32, "vender": "",
                "ver": "V2.0.0" if self.art else "V3.4.M",
                "time": _clock_text(state), "rssi": state["_rssi"],
                "lock": state["_lock"], "AutoUpdate": state["_auto_update"],
                "AppTimer": state["_app_timer"], "ModelType": "0",
                "MidType": state["_mid_type"]}

    def _read(self, device, state, name):
        if name in NO_VALUE or self.art and name in ("MOta", "MidType"):
            return []
        metadata = self._metadata(device, state)
        if name in metadata and (name != "ModelType" or self.art):
            return [metadata[name]]
        return [state["reported"][name]] if name in state["reported"] else None

    def _reply(self, device, outer, inner):
        index = outer["i"]
        reply = Reply({"t": "pack", "i": index, "uid": outer["uid"] & 0xffffffff,
                       "cid": device.mac, "tcid": outer["cid"]}, inner,
                      GENERIC_KEY if index else device.key, CODEC)
        if len(json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode()) >= 0x5b4:
            raise InvalidPacket("WB inner reply exceeds the source builder buffer")
        if len(encode_reply(reply)) > 65507:
            raise InvalidPacket("WB reply exceeds the UDP payload limit")
        return reply

    def advertise(self, device, outer):
        inner = {"t": "dev", "cid": "", "bc": "0" * 32,
                 "brand": "gree", "catalog": "gree", "mac": device.mac,
                 "mid": device.mid, "model": "gree", "name": device.name,
                 "lock": 0, "series": "gree", "vender": "",
                 "ver": "V2.0.0" if self.art else "V3.4.M"}
        if self.art:
            inner["mqttVer"] = "V3.2.M"
        elif self.flavor == "MARJ":
            inner["hid"] = device.profile.hid
        return [self._reply(device, {"i": 1, "uid": 0, "cid": ""}, inner)]

    def _command(self, device, state, inner):
        names, values = _names(inner.get("opt")), inner.get("p")
        if not isinstance(values, list) or len(names) != len(values):
            raise InvalidPacket("WB commands require matching opt and p arrays")
        for name, value in zip(names, values):
            if name in self.local:
                if name == "time":
                    _calendar(value)
                elif name == "ReportClientID":
                    _text(value, name, 63)
                elif name not in ("name", "AppTimer", "ModelType", "ver"):
                    raise InvalidPacket("WB local metadata is read-only")
                elif not isinstance(value, str) and type(value) is not int:
                    raise InvalidPacket("WB local command requires a scalar")
            elif name not in state["reported"]:
                raise InvalidPacket("WB unknown command would enter a native NULL-tail search")
            else:
                _integer(value, name)
        selected, output = [], []
        for local in (True, False):
            for name, value in zip(names, values):
                if (name in self.local) != local:
                    continue
                selected.append(name)
                if local:
                    if name == "time":
                        state["_clock"] = _calendar(value)
                    elif name == "ReportClientID":
                        state["_report_client"] = value
                    output.extend(self._read(device, state, name) or [])
                else:
                    state["reported"][name] = value & 65535
                    state["outbound"].append((name, value))
                    output.append(value)
        return {"t": "res", "mac": inner.get("mac", inner.get("sub", device.mac)),
                "p": output, "opt": selected, "r": 200}

    def _timer(self, inner):
        for name in ("id", "enable", "tz", "hr", "min", "sec"):
            _integer(inner.get(name), name)
        name = _text(inner.get("name"), "timer name", 31)
        week = inner.get("week")
        if not isinstance(week, list) or len(week) != 7:
            raise InvalidPacket("WB timers require seven weekday integers")
        mask = 0
        for index, value in enumerate(week):
            mask |= _integer(value, "weekday") << index
        commands = inner.get("cmd")
        if not isinstance(commands, list) or not commands or not isinstance(commands[0], dict):
            raise InvalidPacket("WB timers require the first command object")
        names, values = _names(commands[0].get("opt")), commands[0].get("p")
        if not isinstance(values, list) or len(names) != len(values):
            raise InvalidPacket("WB timer commands require matching arrays")
        power = 0
        for field, value in zip(names, values):
            _integer(value, "timer value")
            if field == "Pow":
                power = value & 255
        return {"id": inner["id"] & 255, "name": name,
                "enable": int(inner["enable"] == 1),
                "week": [(mask >> index) & 1 for index in range(7)],
                "hr": inner["hr"] & 255, "min": inner["min"] & 255,
                "sec": 0, "power": power}

    def _timers(self, device, state, inner):
        kind, timers = inner["t"], state["timers"]
        if kind == "queryT":
            start = _integer(inner.get("index"), "timer index")
            count = _integer(inner.get("count"), "timer count")
            if start < 0 or count < 0:
                raise InvalidPacket("WB safe timer pagination requires nonnegative bounds")
            entries = []
            for timer in timers[start:min(10, start + count)]:
                item = {key: value for key, value in timer.items() if key != "power"}
                item["cmd"] = [{"mac": [device.mac], "opt": ["Pow"], "p": [timer["power"]]}]
                entries.append(item)
            return {"t": "listT", "total": len(timers), "index": start, "list": entries}
        if kind == "deleteT":
            identifier = _integer(inner.get("id"), "timer id") & 255
            state["timers"] = [item for item in timers if item["id"] != identifier]
        else:
            timer = self._timer(inner)
            position = next((index for index, item in enumerate(timers)
                             if item["id"] == timer["id"]), None)
            if kind == "setT":
                if len(timers) >= 10 or self.flavor == "MAJD" and position is not None:
                    raise InvalidPacket("WB timer list is full or duplicate ID is rejected")
                if position is None:
                    timers.append(timer)
                else:
                    timers[position] = timer
            elif position is not None:
                timers[position] = timer
        return {"t": "resT", "r": 200}

    def _binary(self, state, inner):
        if self.art:
            raise InvalidPacket("ART hex6B path consumes uninitialized stack bytes; no fake ACK")
        value = _text(inner.get("hex01"), "hex01", 1023)
        try:
            frame = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise InvalidPacket("WB hex01 must be base64") from exc
        if len(frame) < 8 or frame[:2] != b"~~" or not 8 <= frame[2] + 2 <= min(60, len(frame)):
            raise InvalidPacket("WB binary frame exceeds its 60-byte native buffer")
        report_client = inner.get("ReportClientID")
        if report_client is not None:
            state["_report_client"] = _text(report_client, "ReportClientID", 63)
        copied = bytearray(60)
        copied[:frame[2] + 2] = frame[:frame[2] + 2]
        copied[7] = 0xaf
        copied[0x2b] |= 2
        state["outbound"].append(bytes(copied).hex())
        return {"t": "res", "r": 200}

    def handle(self, device, outer):
        if outer.get("t") in self.plaintext_types:
            return self._plaintext(device, outer)
        if outer.get("t") != "pack" or outer.get("tcid") != device.mac:
            raise InvalidPacket("wrong WB envelope or target")
        index, uid = outer.get("i"), outer.get("uid")
        if type(index) is not int or index not in (0, 1):
            raise InvalidPacket("invalid WB key selector")
        _integer(uid, "uid")
        _text(outer.get("cid"), "peer identity", 31)
        inner = decode_pack(outer, GENERIC_KEY if index else device.key, CODEC)
        kind = inner.get("t")
        if not isinstance(kind, str):
            raise InvalidPacket("WB operation type must be a string")
        if kind == "bind":
            mac = _text(inner.get("mac", device.mac), "bind identity", 31)
            return [self._reply(device, outer, {"r": 200, "t": "bindok", "mac": mac,
                                                "key": device.key.decode("ascii")})]
        for field in ("mac", "sub"):
            if field in inner:
                _text(inner[field], field, 31)
        registered = {"status", "cmd", "upgrade", "binCmd"}
        registered.update(("subDev", "reset") if self.art else (
            "setT", "queryT", "updateT", "deleteT"))
        if self.art and self.version == "1.38":
            registered.discard("reset")
        if self.flavor == "MARJ":
            registered.update(("reset", "ReportCtrl", "ReportLimit", "freqCount"))
        elif self.flavor == "MAJD":
            registered.add("dump")
        if kind not in registered:
            return []
        state = deepcopy(device.state)
        _clock(state, time.monotonic())
        reply = None
        if kind == "status":
            columns, data = [], []
            for name in _names(inner.get("cols")):
                value = self._read(device, state, name)
                if value is not None:
                    columns.append(name)
                    data.extend(value)
            reply = {"t": "dat", "uid": uid & 0xffffffff, "mac": inner.get("mac", device.mac),
                     "cid": device.mac, "dat": data, "cols": columns, "r": 200}
        elif kind == "cmd":
            reply = self._command(device, state, inner)
        elif kind == "subDev":
            offset = _integer(inner.get("i"), "companion index")
            entries = [{"mac": device.mac + "00", "name": "ACUnit", "mid": device.mid,
                        "model": "gree", "lock": 0}] if offset == 0 else []
            reply = {"t": "subList", "r": 200, "c": 1, "i": offset, "list": entries}
        elif kind in ("setT", "queryT", "updateT", "deleteT"):
            reply = self._timers(device, state, inner)
        elif kind == "binCmd":
            reply = self._binary(state, inner)
        elif kind == "upgrade":
            state["_upgrade_url"] = _text(inner.get("url"), "upgrade URL", 119)
            reply = {"t": "ret", "r": 200}
        elif kind == "reset":
            if not self.art:
                raise InvalidPacket("MARJ reset serializes pointer0xc8 as a string; no fake ACK")
            state["_reset_requested"] = True
            reply = {"t": "res", "r": 200}
        elif kind == "dump":
            period = _integer(inner.get("period"), "dump period")
            count = _integer(inner.get("cnt"), "dump count")
            state["_dump"] = (60 if period < 1 else max(5, min(4096, period)), max(1, count))
            reply = {"t": "ret", "r": 200}
        elif kind == "freqCount":
            names, values = _names(inner.get("opt")), inner.get("p")
            if not isinstance(values, list) or len(names) != len(values):
                raise InvalidPacket("WB frequency request requires matching arrays")
            for name, value in zip(names, values):
                _integer(value, name)
            if names and names[0] == "SendFreq" and values[0] == 1:
                state["_send_freq"] = 1
        elif kind == "ReportCtrl":
            active = _integer(inner.get("ActiveTime", 5), "ActiveTime")
            interval = _integer(inner.get("ReportInterval", 10), "ReportInterval")
            state["_active_time"] = (active * 60 + 0x4000) & 65535
            state["_report_interval"] = (interval * 60 + 0x4000) & 65535
            state["_report_anyway"] = 1 if not inner.get("reportAnyway", False) else 2
        elif kind == "ReportLimit":
            if "timeValid" in inner:
                state["_time_valid"] = _integer(inner["timeValid"], "timeValid") & 255
        replies = [] if reply is None else [self._reply(device, outer, reply)]
        device.state.clear()
        device.state.update(state)
        return replies


PROFILES = tuple(
    Profile(id=identifier, mids=("910001",) if flavor == "ART" else ("11008",),
            hid=hid, source_sha256=digest,
            initial_state=_initial((ART138_NAMES if version == "1.38" else ART_NAMES)
                                   if flavor == "ART" else MAJD_NAMES if flavor == "MAJD" else MARJ_NAMES),
            handler=WBRemainingFamily(flavor, version))
    # ART final senders accept MQTT conn3 only; UDP7000 ingress is not UDP reply admission.
    for identifier, flavor, version, hid, digest in BUILDS if flavor != "ART"
)


DRA_SHA256 = "2f61d5a8abaf52955e7c2c063f1fe97b9e4a23acb074ebeae1d8429eaeea0100"
DRA_HID = "362001068796+U-WB05DRAV2.05.bin"
DRA_OPERATIONS = (
    "pack", "dis", "bind", "wlan", "subBDev", "subBList", "wlan", "CP", "svr",
    "status", "binCmd", "binStatus", "binEvent", "jsonStatus", "reset", "tm",
    "upgrade", "GnetDev", "bleinfo", "wlanchk", "blekey", "bleCheck", "GnetOK",
    "ReportCtrl", "freqCount", "ReportLimit", "metadatapub", "metadata", "connect",
    "Ackup", "scan", "UBindok", "ret", "hbok", "networkInfo", "loginInfoRes",
    "statusCheck",
)


class WBDraFamily:
    """DRA's UDP5001 coordinator namespace, not an ordinary dev advertisement.

    Source 37-entry dispatch and UDP thread 0x0e022918. Physics, coordinator IDs,
    WLAN state and generated metadata inputs are labeled synthetic state. No
    UART/flash/cloud/BLE work is performed or reported as completed.

    The four libc-backed callbacks use the source's substring matching, not
    exact property equality. ``outbound`` is an in-memory work queue: ACKs do
    not claim UART delivery, flash writes, WLAN changes, or timer execution.
    The synthetic storage backend records source scene-buffer overwrite
    behavior, but zeroes its otherwise uninitialized allocation tail.
    """

    plaintext_types = tuple(dict.fromkeys(DRA_OPERATIONS[1:]))
    source_port = 5001

    @staticmethod
    def validate_state(state):
        if type(state["outbound"]) is not list or state["outbound"]:
            raise ValueError("DRA outbound work must start as an empty list")

    @staticmethod
    def thermal_target(device):
        return None

    @staticmethod
    def encode_room(device):
        # No room-temperature channel exists in this coordinator namespace.
        return None

    @staticmethod
    def _reply(device, state, inner, index):
        if index == -1:
            return Reply(inner, destination_port=5001)
        # Native role2 routing uses remembered UBindok peer, never request uid/cid.
        return Reply({"t": "pack", "i": index, "uid": 0, "msgId": state["_msg_id"],
                      "cid": device.mac, "tcid": state["_peer"]}, inner,
                     GENERIC_KEY if index else device.key, CODEC, destination_port=5001)

    @staticmethod
    def _metadata(device, state):
        return {"host": state["_host"], "ver": "V3.5.MF4", "hid": DRA_HID,
                "mid": "10001" if state["_alias"] else device.mid, "bc": "0" * 32}

    @staticmethod
    def _binary(value, name, maximum=765, *, allow_empty=False):
        _text(value, name, 1024)
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, TypeError) as exc:
            raise InvalidPacket("invalid DRA base64 " + name) from exc
        if (not decoded and not allow_empty) or len(decoded) > maximum:
            raise InvalidPacket("DRA binary field exceeds its source buffer")
        return bytearray(decoded)

    @staticmethod
    def _atoi(value):
        # The array scanner passes JSON scalar tokens to _stratoi.
        token = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        match = re.match(r"\s*([+-]?[0-9]+)", token)
        return int(match[1]) if match else 0

    @staticmethod
    def _number(value, name):
        if type(value) not in (int, float) or not -(1 << 31) <= value < (1 << 31):
            raise InvalidPacket("DRA " + name + " requires a finite int32 number")
        return int(value)

    @staticmethod
    def _timer(state, name, period, repeat, callback):
        # Mode1 stores (period * 10) as uint16 in its native 100ms counter.
        if period:
            state["_native_timers"][name] = {
                "ticks": (period * 10) & 65535, "repeat": repeat,
                "callback": callback, "started": time.monotonic(),
            }
            state["outbound"].append(("timer", name, period, repeat, callback))

    @staticmethod
    def _state_event(state, event):
        if state["_native_mode"] in (1, 4, 7):
            state["outbound"].append(("state-event", event))

    def _bin_command(self, device, state, inner):
        frames = []
        for name, value in inner.items():
            if "hex6" not in name and "hex" in name and isinstance(value, str):
                frame = self._binary(value, name)
                if len(frame) < 4 or len(frame) < frame[2] + 3:
                    raise InvalidPacket("DRA command reads beyond its decoded frame")
                frames.append(frame)
        for name in ("hex6A", "hex6B", "hex6C", "hex6D", "hex6E"):
            if name not in inner or not isinstance(inner[name], str):
                continue
            value = self._binary(inner[name], name, 60, allow_empty=True)
            previous = state["_binary_cache"].get(name, bytes(60))
            state["_binary_cache"][name] = bytes(value) + previous[len(value):]
        if "hex6B" in inner and isinstance(inner["hex6B"], str):
            frame = state["_binary_cache"]["hex6B"]
            end = frame[2] + 7
            if end > 60:
                raise InvalidPacket("DRA time frame exceeds its cached buffer")
            try:
                stamp = datetime.strptime(frame[4:end].split(b"\0", 1)[0].decode("ascii"),
                                          "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except (ValueError, UnicodeError):
                stamp = None
            if stamp is not None:
                target = int((stamp - EPOCH).total_seconds())
                delta = -1
                _clock(state, time.monotonic())
                if state["_clock"] > 0x675942e4:
                    delta = target - state["_clock"]
                    if delta > 0:
                        hours, remainder = divmod(delta, 3600)
                        delta = hours * 3600 + (3600 if remainder > 45 else
                                                1800 if remainder > 15 else 0)
                else:
                    state["_clock"] = target
                state["_time_valid"] = 1
                if delta > 60 or delta == -1:
                    state["_default_timer"] = delta
                    state["outbound"].append(("default-timer-store", delta))
                state["outbound"].append(("UartEvent", 5))
            if state["_sleeping"]:
                return None
        if "hex6C" in inner and isinstance(inner["hex6C"], str):
            count = state["_binary_cache"]["hex6C"][4]
            if count:
                if state["_default_countdown"] in (0, 60):
                    state["outbound"].append(("UartEvent", 8))
                self._timer(state, "reDefaultTimer", 90, 1, "0x0e016b34")
                state["_default_countdown"] = min(count, 60)
        if "hex6D" in inner and isinstance(inner["hex6D"], str):
            frame = state["_binary_cache"]["hex6D"]
            count = max(frame[2] - 2, 0)
            if count > 55:
                raise InvalidPacket("DRA weather frame exceeds its text buffer")
            state["_weather"] = frame[4:4 + count].split(b"\0", 1)[0]
            state["outbound"].append(("weather-store", state["_weather"]))
        if "hex6E" in inner and isinstance(inner["hex6E"], str):
            frame = state["_binary_cache"]["hex6E"]
            if frame[2] > 8:
                state["_binary_flag"] = frame[6] & 1
                self._state_event(state, 4)
        fragment = inner.get("fragment")
        fragment_selected = any("fragment" in name for name in inner)
        if fragment_selected:
            if not isinstance(fragment, list) or len(fragment) > 64:
                raise InvalidPacket("DRA fragment requires a bounded array")
            timer = state["_native_timers"].get("fragmentTimer")
            active = timer and (time.monotonic() - timer["started"]) * 10 < timer["ticks"]
            if active:
                ids = {self._atoi(row[0]) & 255 for row in fragment
                       if isinstance(row, list) and row}
                for frame in frames:
                    if frame[3] in ids:
                        cached = next((value for value, _ in state["_uart_status"]
                                       if len(value) > 3 and value[3] == frame[3]), None)
                        if cached is not None:
                            if len(cached) < cached[2] or cached[2] > len(frame):
                                raise InvalidPacket("DRA cached fragment copy exceeds frame")
                            frame[:cached[2]] = cached[:cached[2]]
            for row in fragment:
                if not isinstance(row, list) or len(row) < 4:
                    raise InvalidPacket("DRA fragment requires four scalar entries")
                code, offset, mask, value = map(self._atoi, row[:4])
                offset = (offset & 255) + 3
                mask &= 255
                shift = (mask & -mask).bit_length() - 1 if mask else 16
                for frame in frames:
                    if frame[3] == (code & 255):
                        if offset >= len(frame):
                            raise InvalidPacket("DRA fragment writes beyond its frame")
                        frame[offset] = ((frame[offset] & ~mask) + (value << shift)) & 255
        room = inner.get("roomId", 0)
        if type(room) in (int, float) and room:
            state["_room_id"] = self._number(room, "roomId") & 255
            state["outbound"].append(("room-store", state["_room_id"]))
        scene = inner.get("sceneId", 0)
        operation = inner.get("operType", 0)
        scene = self._number(scene, "sceneId") if type(scene) in (int, float) else 0
        operation = self._number(operation, "operType") if type(operation) in (int, float) else 0
        result = 200
        if scene and operation:
            if operation == 2:
                state["_scenes"].pop(scene, None)
                state["outbound"].append(("scene-delete", scene))
            elif operation == 1:
                def store(identifier):
                    if not frames or identifier in state["_scene_store_fails"]:
                        return False
                    first_length = frames[0][2] + 3
                    if any(len(frame) < first_length for frame in frames):
                        raise InvalidPacket("DRA scene copy reads beyond its frame")
                    size = sum(frame[2] + 3 for frame in frames)
                    payload = bytes(frames[-1][:first_length]) + bytes(size - first_length)
                    state["_scenes"][identifier] = payload
                    state["outbound"].append(("scene-store", identifier, payload))
                    return True
                if not store(scene) and scene == 1:
                    result = 501
                if scene == 1:
                    if fragment_selected:
                        for row in fragment:
                            code, offset, mask, value = map(self._atoi, row[:4])
                            mask &= 255
                            shift = (mask & -mask).bit_length() - 1 if mask else 16
                            for frame in frames:
                                if frame[3] == (code & 255):
                                    position = (offset & 255) + 3
                                    frame[position] = ((frame[position] & ~mask)
                                                       + ((value == 0) << shift)) & 255
                    if not store(2):
                        result = 501
        else:
            for frame in frames:
                if frame[2] > 2 and frame[3] == 0x82:
                    if len(frame) <= 6:
                        raise InvalidPacket("DRA command type reads beyond frame")
                    state["_command_type"] = (frame[6] & 0x7f) >> 5
                self._timer(state, "fragmentTimer", 3, 1, None)
                self._timer(state, "hex6ATimer", 5, 1, "0x0e016af8")
                state["outbound"].append(("UartEvent", 9, bytes(frame[:frame[2] + 3])))
        return {"t": "res", "r": result, "mac": device.mac}

    def advertise(self, device, outer):
        if _integer(outer.get("allRange", 0), "allRange") == 0 and device.state["_scan_gate"]:
            return []
        state = deepcopy(device.state)
        state["_msg_id"] = (state["_msg_id"] + 1) & 0xffffffff
        inner = {"t": "UBind", "scene": 1, "mid": self._metadata(device, state)["mid"],
                 "ver": "V3.5.MF4", "lock": state["_lock"],
                 "devkey": device.key.decode("ascii"), "hid": DRA_HID}
        reply = self._reply(device, state, inner, 1)
        device.state.update(state)
        return [reply]

    def _operate(self, device, state, inner, index, depth=0, raw=None):
        kind = inner.get("t")
        if kind not in DRA_OPERATIONS:
            return []
        if kind == "binCmd":
            output = self._bin_command(device, state, inner)
            return [] if output is None else [self._reply(device, state, output, 0)]
        if kind == "freqCount":
            names = _names(inner.get("opt"))
            values = inner.get("p")
            if not isinstance(values, list) or len(values) < len(names):
                raise InvalidPacket("DRA frequency values do not cover opt")
            for name, value in zip(names, values):
                if "SendFreq" in name:
                    state["outbound"].append(("UartEvent", 8))
                if "FreqTime" in name:
                    state["_freq_time"] = self._number(value, name)
                    # Original instructions load this callback pointer as the period.
                    self._timer(state, "activeTime", 0x4c29, 0, "0x0e016ad8")
                    state["outbound"].append(("UartEvent", 14))
            return []
        if kind == "ReportLimit":
            for name, value in inner.items():
                if "CtrlFunc" in name and isinstance(value, str):
                    state["_ctrl_func"] = bytes(self._binary(value, name))
            if any("NRA" in name for name in inner):
                rows = inner.get("NRA")
                if not isinstance(rows, list) or len(rows) > 64:
                    raise InvalidPacket("DRA NRA requires a bounded row array")
                if rows:
                    if any(not isinstance(row, list) or len(row) < 3 for row in rows):
                        raise InvalidPacket("DRA NRA row requires three scalar entries")
                    state["_nra"] = [tuple(self._atoi(value) & 255 for value in row[:3])
                                     for row in rows]
                    self._state_event(state, 8)
            if type(inner.get("midReportInterval")) in (int, float):
                state["_mid_report_interval"] = self._number(inner["midReportInterval"],
                                                            "midReportInterval")
            return []
        if kind == "networkInfo":
            for name, value in inner.items():
                if "gnetkey" not in name:
                    continue
                if any(state["_gnet_key"]):
                    break
                if isinstance(value, str):
                    encoded = value.encode()
                    if len(encoded) < 8:
                        raise InvalidPacket("DRA gnetkey reads eight source bytes")
                    nibbles = [int(chr(byte), 16) if chr(byte) in "0123456789abcdefABCDEF" else 0
                               for byte in encoded[:8]]
                    state["_gnet_key"] = bytes(nibbles[i] * 16 + nibbles[i + 1]
                                                for i in range(0, 8, 2))
                    state["outbound"].append(("gnet-key-store", state["_gnet_key"]))
                state["_gnet_key_ready"] = 1
                self._state_event(state, 4)
                if state["_network_state"] == 0 and state["_native_mode"] == 1 and state["_network_type"] == 4:
                    state["outbound"].append(("network-restart",))
            return []
        if kind == "loginInfoRes":
            if inner.get("r") == 200:
                info = inner.get("loginInfo")
                if isinstance(info, dict) and "GnetID" in info:
                    state["_gnet_id"] = _integer(info["GnetID"], "GnetID") & 255
            return []
        if kind == "statusCheck":
            frames = state["_uart_status"]
            if len(frames) > 20:
                raise InvalidPacket("DRA native UART cache has twenty slots")
            packed = bytearray()
            for frame, disabled in frames:
                if not isinstance(frame, bytes) or len(frame) < 3 or len(frame) != frame[2] + 3:
                    raise InvalidPacket("invalid synthetic DRA cached UART frame")
                if not disabled:
                    packed.extend(frame)
            if len(packed) > 765:
                raise InvalidPacket("DRA cached status exceeds its base64 builder")
            state["_msg_id"] = (state["_msg_id"] + 1) & 0xffffffff
            output = {"t": "statusCheckRes", "binStatus": base64.b64encode(packed).decode("ascii")}
            return [self._reply(device, state, output, 0)]
        output, slot = None, 0
        metadata = self._metadata(device, state)
        if kind == "pack":
            raise InvalidPacket("nested encrypted DRA packets are not accepted")
        if kind == "CP":
            if depth >= 4:
                raise InvalidPacket("DRA CP nesting limit")
            count = _integer(inner.get("pins"), "pins")
            part = _integer(inner.get("pin"), "pin")
            tag = _text(inner.get("tag"), "CP tag", 11)
            text = inner.get("CP")
            if not 1 <= count <= 32 or not 1 <= part <= count or not isinstance(text, str):
                raise InvalidPacket("invalid bounded DRA CP fragment")
            assembly = state["_fragments"]
            if not assembly or assembly["tag"] != tag:
                assembly = {"tag": tag, "count": count, "parts": {}}
            if assembly["count"] != count:
                raise InvalidPacket("inconsistent DRA CP fragment count")
            if part != len(assembly["parts"]) + 1:
                raise InvalidPacket("DRA CP fragments must arrive in native append order")
            assembly["parts"][part] = text
            if sum(len(value.encode()) for value in assembly["parts"].values()) > 1024:
                raise InvalidPacket("DRA CP assembled input exceeds model bound")
            state["_fragments"] = assembly
            if len(assembly["parts"]) != count:
                return []
            assembled = "".join(assembly["parts"][i] for i in range(1, count + 1)).encode()
            nested = decode_outer(assembled, plaintext_types=self.plaintext_types)
            state["_fragments"] = {}
            nested_index, nested_inner, nested_raw = self._decode(device, nested, raw=assembled)
            if "msgId" in nested:
                state["_msg_id"] = _integer(nested["msgId"], "msgId") & 0xffffffff
            return self._operate(device, state, nested_inner, nested_index, depth + 1, nested_raw)
        if kind in ("binStatus", "binEvent"):
            if raw is None or len(raw) > 765:
                raise InvalidPacket("DRA raw serialization exceeds its 1024-byte base64 builder")
            output = {"t": kind, "mac": device.mac,
                      kind: base64.b64encode(raw).decode("ascii")}
            return [self._reply(device, state, output, index)]
        if kind == "status":
            columns = [name for name in _names(inner.get("cols")) if name in metadata]
            output = {"t": "dat", "r": 200, "cols": columns,
                      "dat": [metadata[name] for name in columns], "mac": device.mac}
        elif kind == "jsonStatus":
            columns = ["AppTimer", "ver", "host", "name", "bc", "mac", "mid", "hid"]
            data = [0, metadata["ver"], metadata["host"], "", metadata["bc"],
                    device.mac, metadata["mid"], DRA_HID]
            if state["_extended"]:
                columns += ["BuzzerCtrl", "ElcEn"]
                data += [state["_buzzer"], state["_electricity"]]
            output = {"t": "dat", "r": 200, "mac": device.mac, "cols": columns, "dat": data}
            slot = index
        elif kind in ("bind", "blekey"):
            output = {"t": "blekey", "mac": device.mac, "Gnet": 1, "IsCP": 1}
            if inner.get("oldkey") != 1:
                output["key"] = device.key.decode("ascii")
            if metadata["mid"] in ("6400", "6045", "609d"):
                output["subCnt"] = 1
            slot = 1
        elif kind == "bleinfo":
            output = {"t": "bleinfo", "wificon": 0, "mac": device.mac,
                      "mid": metadata["mid"], "ver": metadata["ver"]}
            slot = index
        elif kind in ("bleCheck", "wlanchk"):
            output = {"t": kind, "mac": device.mac, "num": state["_wlan_num"]}
            if kind == "wlanchk":
                output["code"] = state["_wlan_code"]
        elif kind == "GnetOK":
            output = {"t": "GnetOK", "GnetID": state["_gnet_id"], "mac": device.mac,
                      "mid": metadata["mid"], "ver": "V3.5.MF4"}
        elif kind in ("subBDev", "subBList"):
            output = {"t": "subBList", "i": 0,
                      "list": (state["_sub_id"] if state["_sub_id"] is not None else "(null)")
                      + "|" + metadata["mid"]}
        elif kind == "connect":
            output = {"t": "connect", "mac": device.mac, "online": 1,
                      "sleep": 0, "onlineSub": [] if state["_sub_id"] is None else [state["_sub_id"]]}
            slot = 1
        elif kind == "metadatapub":
            output = {"t": "metadata", "mac": device.mac,
                      "opt": ["permitStatus"], "p": [state["_permit"]]}
            slot = index
        elif kind == "metadata":
            values = inner.get("p")
            if not isinstance(values, list) or not values:
                raise InvalidPacket("missing DRA metadata p")
            state["_permit"] = _integer(values[0], "permitStatus") & 255
            state["outbound"].append(("UartEvent", 0x82))
        elif kind in ("reset", "upgrade"):
            matches = inner.get("mac") == device.mac
            if kind == "reset":
                if not matches:
                    return []
                state["outbound"].append(("reset", 2))
            elif matches:
                url = inner.get("url")
                if not isinstance(url, str) or len(url.encode()) >= 120:
                    raise InvalidPacket("invalid bounded DRA upgrade URL")
                state["outbound"].append(("upgrade", url))
            output = {"t": "res", "r": 200, "mac": device.mac}
        elif kind == "Ackup":
            output = {"t": "res", "r": 200, "mac": device.mac}
            state["_ota_ack"] = inner.get("OTAMac") == device.mac
        elif kind == "UBindok":
            peer = inner.get("mac")
            if not isinstance(peer, str) or len(peer.encode()) >= 30:
                raise InvalidPacket("invalid bounded DRA coordinator mac")
            state["_peer"] = peer
            state["_msg_id"] = (state["_msg_id"] + 1) & 0xffffffff
            reply = self._reply(device, state, {"t": "Utm", "mac": device.mac}, 0)
            state["_msg_id"] = (state["_msg_id"] + 2) & 0xffffffff
            return [reply]
        elif kind in ("ret", "hbok"):
            state["_msg_id"] = (state["_msg_id"] + 1) & 0xffffffff
        elif kind == "tm":
            if "timestamp" in inner:
                value = inner["timestamp"]
                if type(value) not in (int, float) or not -2147483648000 <= value < 2147483648000:
                    raise InvalidPacket("DRA timestamp requires bounded finite milliseconds")
                # Original softfloat helper0x0e093db4 divides by1000 before int32 conversion.
                state["_clock"] = int(value / 1000)
                state["_clock_at"] = time.monotonic()
            if "homeId" in inner:
                state["_home_id"] = _integer(inner["homeId"], "homeId")
            if "reportAnyway" in inner:
                state["_report_anyway"] = 2 if inner["reportAnyway"] else 1
        elif kind == "ReportCtrl":
            for field, key in (("ActiveTime", "_active_time"), ("ReportInterval", "_report_interval")):
                if field in inner:
                    state[key] = _integer(inner[field], field) & 0xffffffff
                    if field == "ActiveTime":
                        state["_report_anyway"] = 1
            if "reportAnyway" in inner:
                state["_report_anyway"] = 2 if inner["reportAnyway"] else 1
        elif kind in ("wlan", "GnetDev"):
            config = {}
            for field, limit in (("ssid", 33), ("psw", 65), ("host", 65)):
                value = inner.get(field)
                if not isinstance(value, str) or len(value.encode()) >= limit:
                    raise InvalidPacket("invalid bounded DRA WLAN " + field)
                config[field] = value
            if "num" in inner:
                state["_wlan_num"] = _integer(inner["num"], "num") & 255
            if kind == "GnetDev":
                state["_gnet_id"] = _integer(inner.get("GnetID"), "GnetID") & 255
                gnet_key = inner.get("GnetKey")
                if not isinstance(gnet_key, str) or not re.fullmatch(r"[0-9a-fA-F]{8}", gnet_key):
                    raise InvalidPacket("DRA GnetKey requires the source's eight hex digits")
                state["_gnet_key"] = bytes.fromhex(gnet_key)
            state["_network"] = config
            if kind == "GnetDev":
                state["outbound"].append(("network-config", config.copy()))
                return self._operate(device, state, {"t": "GnetOK"}, index, depth)
        elif kind == "svr":
            config = inner.get("mqttInfo")
            if not isinstance(config, dict):
                raise InvalidPacket("missing DRA mqttInfo")
            for field in ("host", "username", "password"):
                if not isinstance(config.get(field), str) or len(config[field].encode()) >= 128:
                    raise InvalidPacket("invalid bounded DRA MQTT " + field)
            port = _integer(config.get("port"), "port")
            if not 0 < port <= 65535:
                raise InvalidPacket("invalid DRA MQTT port")
            state["_mqtt"] = {field: config[field] for field in ("host", "port", "username", "password")}
        elif kind == "dis":
            return [Reply({"t": "dis", "mac": device.mac, "needMqtt": 1},
                          trailing_newline=True, destination_port=5001)]
        return [] if output is None else [self._reply(device, state, output, slot)]

    @staticmethod
    def _decode(device, outer, *, raw=None):
        index = outer.get("i", -1)
        if index not in (-1, 0, 1) or isinstance(index, bool):
            raise InvalidPacket("invalid DRA key selector")
        if outer.get("t") == "pack":
            if outer.get("tcid") != device.mac:
                raise InvalidPacket("DRA packet is addressed to another module")
            key = GENERIC_KEY if index else device.key
            if index == -1:
                raw = outer["pack"].encode()
                inner = decode_outer(raw, plaintext_types=WBDraFamily.plaintext_types)
            else:
                inner = decode_pack(outer, key, CODEC)
                raw = None
                if inner.get("t") in ("binStatus", "binEvent"):
                    raw = unpad(AES.new(key, AES.MODE_ECB).decrypt(
                        base64.b64decode(outer["pack"], validate=True)), 16)
        else:
            inner = outer
            # shortcut: plaintext transport callbacks expose parsed JSON, not token bytes;
            # canonicalize only that path until the server passes original datagrams.
            if raw is None:
                raw = json.dumps(outer, ensure_ascii=False, separators=(",", ":")).encode()
        return index, inner, raw

    def handle(self, device, outer):
        index, inner, raw = self._decode(device, outer)
        if inner.get("t") == "scan":
            return self.advertise(device, inner)
        state = deepcopy(device.state)
        replies = self._operate(device, state, inner, index, raw=raw)
        if any(len(encode_reply(reply)) > 1024 for reply in replies):
            raise InvalidPacket("DRA reply exceeds bounded source UDP buffer")
        device.state.clear()
        device.state.update(state)
        return replies


PROFILES += (
    Profile(id="sim-wb05dra-v2.05-coordinator", mids=("10001",), hid=DRA_HID,
            source_sha256=DRA_SHA256, handler=WBDraFamily(), max_request_bytes=1024,
            initial_state={"outbound": [], "_msg_id": 0, "_peer": "", "_alias": True,
                           "_host": "synthetic.invalid", "_lock": 0, "_scan_gate": 0, "_sub_id": None,
                           "_extended": True, "_buzzer": 0, "_electricity": 0,
                           "_wlan_num": 0, "_wlan_code": 0, "_gnet_id": 0, "_permit": 0,
                           "_ota_ack": False, "_fragments": {}, "_clock": 0,
                           "_clock_at": None, "_home_id": 0, "_report_anyway": 0,
                           "_active_time": 0, "_report_interval": 0,
                           "_network": {}, "_mqtt": {}, "_gnet_key": b"", "_uart_status": [],
                           "_native_mode": 4, "_network_state": 0, "_network_type": 4,
                           "_native_timers": {}, "_binary_cache": {}, "_ctrl_func": b"",
                           "_nra": [], "_mid_report_interval": 0, "_freq_time": 0,
                           "_gnet_key_ready": 0, "_scenes": {}, "_scene_store_fails": [],
                           "_room_id": 0, "_command_type": 0, "_binary_flag": 0,
                           "_time_valid": 0, "_default_timer": 0, "_default_countdown": 0,
                           "_weather": b"", "_sleeping": False}),
)
