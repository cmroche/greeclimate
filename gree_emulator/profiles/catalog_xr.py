"""Exact XR 063967 bounded raw cache; no mainboard or physical AC simulation.

MID10001 is the explicit synthetic mainboard input0x10001 formatted with %x.
Zero u16 slots, epoch UTC, progress0 and RSSI-50 are chosen synthetic inputs.
AES ECB/PKCS7 uses the library substitute, not native hardware CE execution.
Native sequential mutation/faults become bounded atomic InvalidPacket rejection;
discovery emits one effective lock instead of native duplicate lock members.
"""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import re
import time

from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile
from . import catalog_xr_timers

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
SELECTORS = (
    'Pow', 'Mod', 'SetTem', 'WdSpd', 'Tur', 'Quiet', 'SwUpDn',
    'SwingLfRig', 'Add0.5', 'TemUn', 'TemRec', 'Lig', 'Air', 'Blo',
    'Health', 'SvSt', 'SwhSw', 'HeatCoolType', 'StHt', 'LTemDry', 'Wet',
    'SwhSlp', 'SlpMod', 'HasTmr', 'TmrLpTms', 'TmrOff', 'TmrOn', 'CurTmHor',
    'CurTmMin', 'TmrOnHorLf', 'TmrOnMinLf', 'TmrOffHorLf', 'TmrOffMinLf', 'DsplySt', 'EnvFun',
    'JFErrorCode', 'AssHt', 'SwhFreAir', 'AllErr', 'Coolmod', 'HeatCool', 'LedLig',
    'SmartMod', 'Add0.1', 'ModelType', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'Buzzer_ON_OFF', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'Wind', 'UDFanPort', 'DnPUDSwing',
    'DnPLLRSwing', 'DnPRLRSwing', 'AirQ', 'PM2P5', 'ElcDatHor', 'ElcDatDte', 'ElcDatMth',
    'HumSen', 'ElcP', 'ElcOnKwh', 'ElcAllKwhClr', 'ElcAllKwhH', 'ElcAllKwhL', 'AutoClean',
    'TemSen', 'Emod', 'PctCleOnTm', 'EvapClr', 'NobodySave', 'BlkTemCom', 'HabitLearn',
    'SmartWind', 'HandCtl', 'VocCtl', 'VocIdiom', 'VocRole', 'ImgUpdateCol', 'EnvArea1St',
    'EnvArea2St', 'EnvArea3St', 'EnvArea4St', 'EnvArea5St', 'EnvArea6St', 'EnvArea7St', 'EnvArea8St',
    'EnvArea9St', 'FbidBloPer', 'DIYGra1PoiAmo', 'SwhDIYGra1', 'Slp1L1', 'Slp1H1', 'Slp1L2',
    'Slp1H2', 'Slp1L3', 'Slp1H3', 'Slp1L4', 'Slp1H4', 'Slp1L5', 'Slp1H5',
    'Slp1L6', 'Slp1H6', 'Slp1L7', 'Slp1H7', 'Slp1L8', 'Slp1H8', 'ImgVerSta',
    'VocUpdateCol', 'VocVerSta', 'LigSen', 'Video', 'PctCleSetTm', 'AppTimer', 'CO2Level',
    'Dazzling', 'ElcEn', 'NoD', 'NoD', 'MasSub', 'MasIDUMod', 'GetEr',
    'HeatSvStTemMax', 'HumiSvStTemMin', 'CoolSvStTemMin', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'Wmod', 'WsetTmp',
    'WschOn', 'WschOnMin', 'WschOff', 'WschOffMin', 'Wtmr1', 'Wtmr1Min', 'Wtmr2',
    'Wtmr2Min', 'Wtmr3', 'Wtmr3Min', 'WsenTmpH', 'WsenTmpM', 'WsenTmpL', 'Werr',
    'WsenNub', 'WstpSv', 'WstpH', 'WatTmp', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'MaeS', 'FanMod', 'ModS', 'VitiGr', 'GasN', 'TemSor', 'HumSor',
    'PM2P5V', 'VOC', 'CO2', 'PctCle', 'PctRe', 'IDUAirQu', 'AirQu',
    'ODUViti', 'GasAvail', 'GasLED', 'GasMod', 'GasMas', 'PM2P5Sta', 'SorErr',
    'CommErr', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'Dmod', 'Dfltr', 'Dpump', 'Dwet', 'DwatFul', 'DwatSen', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'Smod', 'Sfog', 'RemWarnLig', 'NoD', 'NoD', 'Security',
    'SecurityMode', 'ImageRecovery', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'Srst', 'Swat', 'Swash', 'SrstPP', 'SrstPF',
    'SrstCF', 'SrstRF', 'SrstAF', 'MakeWat', 'WatErr', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'mode', 'wspd', 'light', 'StTmr', 'fltrst', 'wipm25',
    'wopm25', 'estate', 'airQlt', 'Purify', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'ImgUpdateRes', 'VocUpdateRes', 'MicroSen', 'ReplaceHEPA', 'UnmanedShutDown', 'UnmanedOffTime', 'PMVComfort',
    'Defrost', 'Antifreeze', 'FavorMode', 'ImgUpdateSta', 'NoD', 'VocUpdateSta', 'NoD',
    'NoD', 'SmartSlpMod', 'SmartSlpModEx', 'StSlp1C', 'StSlp1CInc', 'StSlp1CSp', 'StSlp1H',
    'StSlp1HInc', 'StSlp1HSp', 'StSlp2C', 'StSlp2CInc', 'StSlp2CSp', 'StSlp2H', 'StSlp2HInc',
    'StSlp2HSp', 'StSlp3C', 'StSlp3CInc', 'StSlp3CSp', 'StSlp3H', 'StSlp3HInc', 'StSlp3HSp',
    'StSlp4C', 'StSlp4CInc', 'StSlp4CSp', 'StSlp4H', 'StSlp4HInc', 'StSlp4HSp', 'AntiDirectBlow',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'SwhWifi', 'SwhWifiRe', 'SwhWifiCo', 'datDump',
    'datRep', 'datFailRe', 'datPeroid', 'subCnt', 'HidDownPer', 'InHidDownPer', 'OEEPHidDownPer',
    'voiceHidPer', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'ACStupPos', 'SaveGuid', 'NoiseSet', 'RoomLen',
    'RoomWid', 'RoomHigh', 'CoolNoise', 'HeatNoise', 'rssi', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'ElcErg', 'ElcGear', 'Elc1Kwh', 'AutoUpdate', 'AutoComnCloud',
    'lock', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'apssid', 'appsw', 'host',
    'name', 'time', 'lat', 'lon', 'voicehid', 'NoD', 'NoD',
    'NoD', 'NoD', 'NoD', 'NoD', 'NoD', 'vender', 'bc',
    'mid', 'model', 'series', 'brand', 'catalog', 'country', 'hid',
    'mac', 'ver', 'HidSvrVer', 'InHid', 'InHidSvrVer', 'OEEPHid', 'OEEPHidSvrVer',
    None, None, None, None, None, None, None,
    None, None, None, None, None, None, None,
    None, None, None, None, None,
)
FIRST_INDEX = {}
for _index, _name in enumerate(SELECTORS):
    if _name is not None:
        FIRST_INDEX.setdefault(_name, _index)
ORDINARY = frozenset(SELECTORS[:445])
INITIAL_STATE = {**dict.fromkeys(ORDINARY, 0), "_uid": 0}
STRING_LIMITS = {"apssid": (1, 32), "appsw": (0, 32), "host": (1, 20),
                 "name": (0, 31), "lat": (1, 10), "lon": (1, 10)}


def _clock_value(value):
    # Safe calendar validation replaces native atoi-at-fixed-offset normalization.
    if not isinstance(value, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", value):
        raise InvalidPacket("XR time requires YYYY-MM-DD HH:MM:SS")
    try:
        seconds = int((datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc) - EPOCH).total_seconds())
    except ValueError as exc:
        raise InvalidPacket("invalid XR calendar") from exc
    if not 0 <= seconds <= 0x7fffffff:
        raise InvalidPacket("XR safe clock requires nonnegative int32 epoch")
    return seconds


def _prepare(device):
    state = deepcopy(device.state)
    if "_cache" not in state:
        state["_cache"] = [0] * 495
        for name in ORDINARY:
            state["_cache"][FIRST_INDEX[name]] = state[name]
    state.setdefault("_name", device.name)
    state.setdefault("_clock", 0)
    return state


def _read(device, state, index, *, command=False):
    if index < 445:
        if not command and index == 371:
            return [state.get("_voice_progress", 0)]
        if not command and index == 403:
            return [state.get("_rssi", -50)]
        return [state["_cache"][index]]
    if index == 449:
        clock = EPOCH + timedelta(seconds=int(state["_clock"]))
        return [f"{clock.year}-{clock:%m-%d %H:%M:%S}"]
    if index == 468:
        state["_cache"][368] = state.get("_hid_progress", 0)
        state["HidDownPer"] = state["_cache"][368]
        return [device.profile.hid]
    values = {447: state.get("_host", ""), 448: state["_name"],
              450: state.get("_lat", ""), 451: state.get("_lon", ""),
              452: "", 460: "2", 461: "", 462: device.mid,
              469: device.mac, 470: "V3.0.0", 472: "", 474: ""}
    return [values[index]] if index in values else []


def _names(value, *, status=False):
    if not isinstance(value, list) or len(value) > 30:
        raise InvalidPacket("XR requires at most30 property slots")
    result = []
    for name in value:
        if (not isinstance(name, str) or not name or "\0" in name
                or (status and len(name.encode("utf-8")) >= 16)):
            if status:
                break
            raise InvalidPacket("invalid XR property name")
        result.append(name)
    if status and len(result) == 30:
        return []
    if any(name not in FIRST_INDEX for name in result):
        raise InvalidPacket("unknown XR name reaches native null strcmp")
    return result


def _validate_command(names, values):
    if not isinstance(values, list) or len(names) != len(values):
        raise InvalidPacket("XR command requires equal opt/p arrays")
    for name, value in zip(names, values):
        if isinstance(value, str):
            if "\0" in value or len(value.encode("utf-8")) > 1023:
                raise InvalidPacket("unsafe XR string")
            if name == "time":
                _clock_value(value)
            elif name in STRING_LIMITS:
                lower, upper = STRING_LIMITS[name]
                if not lower <= len(value.encode("utf-8")) <= upper:
                    raise InvalidPacket("XR mutable string exceeds safe source bound")
        elif type(value) is not int or not -(1 << 31) <= value < (1 << 31):
            # Source other JSON types can no-op/ACK; strict int32/string is safety policy.
            raise InvalidPacket("XR safe commands require int32 or string")


def _command(device, state, names, values, now):
    applied = []
    for name, value in zip(names, values):
        index = FIRST_INDEX[name]
        if type(value) is int:
            state["_cache"][index] = value & 65535
            if index < 445:
                state[name] = value & 65535
        elif name == "time":
            state.update(_clock=_clock_value(value), _tick_at=now)
            catalog_xr_timers.refresh_clock(state, state["_clock"])
        elif name in STRING_LIMITS:
            state["_" + name] = value
            if name == "host":
                state["_reconnect"] = True
        applied.extend(_read(device, state, index, command=True))
    # UART composer changes transmit bytes, not the ordinary u16 cache.
    return applied


def _advance(device, state, now):
    previous = state["_clock"]
    current = min(0x7fffffff, previous + max(0, now - state.get("_tick_at", now)))
    state.update(_clock=current, _tick_at=now)
    for names, values in catalog_xr_timers.advance(device, state, previous, current):
        names = _names(names)
        _validate_command(names, values)
        _command(device, state, names, values, now)


def _reply(device, inner, index, uid, *, timer=False):
    size = len(json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode())
    encrypted_size = (size // 16 + 1) * 16
    if size >= 1024 or 4 * ((encrypted_size + 2) // 3) >= 1024:
        raise InvalidPacket("XR reply exceeds native plaintext/base64 scratch")
    reply = Reply({"t": "pack", "i": index, "uid": uid,
                   "cid": device.mac, "tcid": ""}, inner,
                  device.key if timer or index == 0 else GENERIC_KEY,
                  CODEC, trailing_newline=True)
    # This is a safe model datagram bound, not an established UDP receive capacity.
    if len(encode_reply(reply)) > 1400:
        raise InvalidPacket("XR reply exceeds safe model datagram bound")
    return reply


class XrRawController:
    def validate_state(self, state):
        for name, value in state.items():
            if name == "_uid" and type(value) is int and -(1 << 31) <= value < (1 << 31):
                continue
            if name not in ORDINARY or type(value) is not int or not 0 <= value <= 65535:
                raise ValueError("XR configurable state requires named ordinary uint16 slots")

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        """Raw mainboard/cache fields have no invented ambient calibration."""

    def tick(self, device, now):
        state = _prepare(device)
        _advance(device, state, now)
        device.state.clear()
        device.state.update(state)
        return []

    def wlan(self, device, outer):
        if outer.get("t") != "wlan":
            raise InvalidPacket("invalid XR provisioning request")
        limits = {"host": 19, "ssid": 64, "psw": 63, "lat": 10, "lon": 10}
        for name, limit in limits.items():
            value = outer.get(name)
            if (not isinstance(value, str) or "\0" in value
                    or len(value.encode("utf-8")) > limit):
                raise InvalidPacket("unsafe XR provisioning string")
        pending = _prepare(device)
        pending.update(_host=outer["host"], _apssid=outer["ssid"], _appsw=outer["psw"],
                       _lat=outer["lat"], _lon=outer["lon"], _reconnect=True)
        # Source persists the existing device key then reboots; no host/network boot.
        reply = Reply({"t": "ret", "r": 200, "mac": device.mac}, trailing_newline=True)
        device.state.clear()
        device.state.update(pending)
        return [reply]

    def advertise(self, device, outer):
        state = _prepare(device)
        inner = {"t": "dev", "cid": "", "bc": "gree", "catalog": "gree",
                 "mid": device.mid, "lock": state["_cache"][420], "model": "gree",
                 "name": state["_name"], "series": "gree", "vender": "2",
                 "ver": "V3.0.0", "brand": "gree", "mac": device.mac}
        reply = _reply(device, inner, 1, state["_uid"])
        device.state["_sourceflag"] = 1
        return [reply]

    def handle(self, device, outer):
        if outer.get("t") != "pack" or outer.get("tcid") != device.mac:
            raise InvalidPacket("wrong XR root target")
        index, uid = outer.get("i"), outer.get("uid")
        if (type(index) is not int or not -(1 << 31) <= index < (1 << 31)
                or type(uid) is not int or not -(1 << 31) <= uid < (1 << 31)
                or not isinstance(outer.get("cid", ""), str)):
            raise InvalidPacket("invalid XR key selector or route")
        inner = decode_pack(outer, device.key if index == 0 else GENERIC_KEY, CODEC)
        for selector in ("mac", "sub"):
            if selector in inner and inner[selector] != device.mac:
                raise InvalidPacket("conflicting XR inner identity (safe model policy)")
        kind = inner.get("t")
        if not isinstance(kind, str) or "\0" in kind:
            raise InvalidPacket("XR inner operation requires a string")
        state = _prepare(device)
        now = time.monotonic()
        if kind == "bind":
            if inner.get("mac") != device.mac:
                raise InvalidPacket("XR bind requires root mac")
            response = {"t": "bindok", "mac": device.mac, "r": 200,
                        "key": device.key.decode("ascii")}
            reply = _reply(device, response, 1, uid)
            state["_sourceflag"] = 1
        elif kind == "status":
            names = _names(inner.get("cols"), status=True)
            _advance(device, state, now)
            response = {"t": "dat", "mac": device.mac, "r": 200, "cols": names,
                        "dat": [value for name in names
                                for value in _read(device, state, FIRST_INDEX[name])]}
            reply = _reply(device, response, 0, uid)
            state["_sourceflag"] = 0
        elif kind == "cmd":
            names = _names(inner.get("opt"))
            values = inner.get("p")
            _validate_command(names, values)
            _advance(device, state, now)
            response = {"t": "res", "mac": device.mac, "r": 200, "opt": names,
                        "p": _command(device, state, names, values, now)}
            reply = _reply(device, response, 0, uid)
            state["_sourceflag"] = 0
        elif kind in ("setT", "updateT", "deleteT", "queryT"):
            # Timer validation and mutation occur only on this private pending copy.
            _advance(device, state, now)
            response = catalog_xr_timers.handle_timer(device, state, inner)
            reply = None if response is None else _reply(
                device, response, state.get("_sourceflag", 0), uid, timer=True)
        else:
            # Original upgrade dispatch starts external OTA and emits no local ACK.
            # No host network, flash, filesystem or invented download success.
            reply = None
        state["_uid"] = uid
        device.state.clear()
        device.state.update(state)
        return [] if reply is None else [reply]


PROFILES = (Profile(
    id="sim-xr-u-wfxr-v1.2-raw-10001", mids=("10001",),
    hid="362001063967+U-WFXRV1.2.bin",
    source_sha256="074938b9fd37de4f2392b110450d5e0c64e37d32af9b810f72c1fd95cb6f46d8",
    initial_state=INITIAL_STATE, handler=XrRawController(), max_request_bytes=1400,
),)
