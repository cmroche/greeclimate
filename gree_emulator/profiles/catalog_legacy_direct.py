"""Exact W06MV1.03 local UDP raw cache, not a calibrated AC or full boot.

Original UDP business/reply instructions qualify this bounded model. Strict
JSON/PKCS7, retained request ownership, bounded copies and atomic validation are
chosen safety policies: the original cJSON double-delete remains a source fault.
Numeric readouts and binary report banks start at synthetic stationary zero;
source initialized identity/key/time are separate from those model defaults.
"""

from copy import deepcopy
from datetime import datetime, timedelta
import json
from time import monotonic

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile
from .catalog_legacy_direct_schedule import OPERATIONS, due, schedule

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
DEVICE_KEY = b"a3K8Bx%2r8Y7GREE"
CODEC = "aes-ecb-pkcs7"
HID = "362001062071+U-W06MV1.03.bin"
SOURCE_SHA256 = "65da0894f3b78fe801519c2145b9f429daf036d5d3f42ded0fa037fc0a9edaba"

# Original 495 pointers at 0x4501f0, including duplicate and placeholder names.
NAMES = tuple("""
Pow Mod SetTem WdSpd Tur Quiet SwUpDn SwingLfRig Add0.5 TemUn
TemRec Lig Air Blo Health SvSt SwhSw HeatCoolType StHt LTemDry
Wet SwhSlp SlpMod HasTmr TmrLpTms TmrOff TmrOn CurTmHor CurTmMin TmrOnHorLf
TmrOnMinLf TmrOffHorLf TmrOffMinLf DsplySt EnvFun JFErrorCode AssHt SwhFreAir AllErr Coolmod
HeatCoolType LedLig SmartMod WetGrade ErrorCode1 LifeTimeFilter1 LifeTimeFilter2 LifeTimeFilter3 LifeTimeFilter4 TotalPureWater
FilterWarning1 FilterWarning2 FilterWarning3 FilterWarning4 WorkStatus LifeFilterDays1 LifeFilterDays2 LifeFilterDays3 LifeFilterDays4 ErrorCode2
Wind UDFanPort DnPUDSwing DnPLLRSwing DnPRLRSwing AirQ PM2P5 ElcDatHor ElcDatDte ElcDatMth
HumSen ElcP ElcOnKwh ElcAllKwhClr ElcAllKwhH ElcAllKwhL AutoClean TemSen Emod NoD
NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD
EnvArea1St EnvArea2St EnvArea3St EnvArea4St EnvArea5St EnvArea6St EnvArea7St EnvArea8St EnvArea9St FbidBloPer
DIYGra1PoiAmo SwhDIYGra1 Slp1L1 Slp1H1 Slp1L2 Slp1H2 Slp1L3 Slp1H3 Slp1L4 Slp1H4
Slp1L5 Slp1H5 Slp1L6 Slp1H6 Slp1L7 Slp1H7 Slp1L8 Slp1H8 NoD NoD
NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD
MasSub MasIDUMod GetEr HeatSvStTemMax HumiSvStTemMin CoolSvStTemMin NoD NoD NoD NoD
NoD NoD NoD NoD NoD Wmod WsetTmp WschOn WschOnMin WschOff
WschOffMin Wtmr1 Wtmr1Min Wtmr2 Wtmr2Min Wtmr3 Wtmr3Min WsenTmpH WsenTmpM WsenTmpL
Werr WsenNub WstpSv WstpH WatTmp NoD NoD NoD NoD NoD
NoD NoD NoD NoD NoD MaeS FanMod ModS VitiGr GasN
TemSor HumSor PM2P5V VOC CO2 PctCle PctRe IDUAirQu AirQu ODUViti
GasAvail GasLED GasMod GasMas PM2P5Sta SorErr CommErr NoD NoD NoD
NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD
Dmod Dfltr Dpump Dwet DwatFul DwatSen NoD NoD NoD NoD
NoD NoD NoD NoD NoD Smod Sfog RemWarnLig NoD NoD
Wash PauseStart LayerWash Dry Hard StHard WashTmr TmrStatus NoD NoD
GetWat Cool Heat Stasis Srst SrstPP SrstPF SrstCF SrstRF SrstAF
PPlif PFlif CFlif RFlif AFlif WatInTmp WatTds ClnTds VolCln AtoCln
UseTmp Percent TmpSt Vol WatLine NoD NoD NoD NoD NoD
mode wspd light StTmr fltrst wipm25 wopm25 airQlt Purify FiltUT
FiltBT estate estate2 MsgPM FiltUPercent estate3 estate4 NoD NoD NoD
Rice Textre Sealve WshRic Prsure Fog StpRic SchTmr SchOnOff SchEn
TmrEn SchTmr2 SchOnOff2 SchEn2 KpTpEn KpTpOnOff KpTpTmr ModeTmr NoD NoD
AtoMod ChildLock DnMod UpMod HumUp HumDn TmpUp TmpDn UpTmr DnTmr
NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD
holiday union Volt RightCooker LeftCooker CookerBattery NoD NoD NoD NoD
Rotate TmrHour TmrMin TmrAction MidType Anion NoD NoD SoakSTime SoakSTem
HeatSTime HeatSTem BoilSTime BoilSTem BraizSTim BraizSTem WarmSTime WarmSTem FinalSTim FinalSTem
SwhWifi SwhWifiRe SwhWifiCo datDump datRep datFailRe datPeroid subCnt NoD NoD
UVLight FogLevel WaterTankLight NoD NoD NoD NoD NoD NoD NoD
NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD
NoD NoD NoD NoD NoD ACStupPos SaveGuid NoiseSet RoomLen RoomWid
RoomHigh CoolNoise HeatNoise NoD NoD NoD NoD NoD NoD NoD
NoD NoD NoD NoD NoD ElcErg ElcGear Elc1Kwh AutoUpdate AutoComnCloud
lock NoD NoD NoD NoD NoD NoD NoD NoD NoD
NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD
NoD NoD NoD NoD NoD apssid appsw host name time
NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD
vender bc mid model series brand catalog country hid mac
ver NoD NoD NoD NoD NoD NoD NoD NoD NoD
NoD NoD NoD NoD NoD NoD NoD NoD NoD NoD
NoD NoD NoD NoD NoD
""".split())
_FIRST = {}
for _slot, _name in enumerate(NAMES):
    _FIRST.setdefault(_name, _slot)
RAW_SLOTS = {name: slot for name, slot in _FIRST.items() if slot < 445}
METADATA = ("apssid", "appsw", "host", "name", "time", "vender", "bc", "mid",
            "model", "series", "brand", "catalog", "hid", "mac", "ver")
_SETTABLE = {"apssid": 31, "appsw": 31, "host": 19, "name": 79, "time": 19}
_LOCAL = ("scan", "bind", "status", "cmd", "setT", "updateT", "deleteT", "queryT", "upgrade")


def _integer(value):
    if type(value) is not int or not -(1 << 31) <= value < 1 << 31:
        raise InvalidPacket("W06M requires signed 32-bit integers")
    return value


def _text(value, maximum):
    if not isinstance(value, str) or "\0" in value:
        raise InvalidPacket("W06M requires bounded strings without NUL")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError as error:
        raise InvalidPacket("invalid W06M string") from error
    if size > maximum:
        raise InvalidPacket("unsafe W06M string length")
    return value


def _members(value):
    if not isinstance(value, dict) or not 1 <= len(value) <= 20:
        raise InvalidPacket("W06M requires one to twenty object members")
    for key in value:
        _text(key, 31)


def _clock(value):
    _text(value, 19)
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError as error:
        raise InvalidPacket("W06M safe clock requires YYYY-MM-DD HH:MM:SS") from error
    if parsed.strftime("%Y-%m-%d %H:%M:%S") != value:
        raise InvalidPacket("W06M safe clock requires fixed-width fields")
    return parsed


def _runtime(device, state):
    if "_legacy_direct" not in state:
        metadata = dict.fromkeys(METADATA, "")
        metadata.update(name=_text(device.name, 79), mid="0", mac=device.mac,
                        vender="1", ver="V1.0", hid=HID, time="2016-12-22 00:00:00")
        state["_legacy_direct"] = {
            "metadata": metadata, "index": 0, "peer": "", "incoming_uid": 0,
            "_clock": _clock(metadata["time"]), "_clock_at": device.last_step,
            "reports": {"energy": bytes(157), "water": bytes(24)},
        }
    return state["_legacy_direct"]


def _names(value):
    if isinstance(value, str):
        return False, [_text(value, 31)]
    if not isinstance(value, list) or not 1 <= len(value) <= 30:
        raise InvalidPacket("W06M requires a scalar name or one to thirty slots")
    for name in value:
        _text(name, 15)
    # The original scans to the first empty slot, resetting count to zero at 30.
    count = next((index for index, name in enumerate(value) if not name), len(value))
    return True, value[:count] if count < 30 else []


def _read(state, runtime, name):
    return state[name] if name in RAW_SLOTS else runtime["metadata"][name]


def _response(device, state, runtime, names, array, command=False):
    response = {"t": "res" if command else "dat", "mac": device.mac, "r": 200}
    accepted = [name for name in names if name in _FIRST]
    field = "opt" if command else "cols"
    values = [_read(state, runtime, name) for name in accepted if name != "country"]
    if array:
        response[field] = accepted
        response["p" if command else "dat"] = values
        if command:
            response["val"] = values.copy()
    elif accepted:
        response[field] = accepted[0]
        if values:
            response["p" if command else "dat"] = values[0]
            if command:
                response["val"] = values[0]
    return response


def _reply(device, runtime, inner):
    length = len(json.dumps(inner, ensure_ascii=False, separators=(",", ":"),
                            allow_nan=False).encode("utf-8"))
    padded = (length // 16 + 1) * 16
    # Both native scratch banks are 1024 bytes; base64 also needs its NUL.
    if padded > 1024 or 4 * ((padded + 2) // 3) >= 1024:
        raise InvalidPacket("W06M response exceeds original scratch banks")
    index = runtime["index"]
    reply = Reply({"t": "pack", "i": index, "uid": 0, "cid": device.mac,
                   "tcid": runtime["peer"]}, inner,
                  DEVICE_KEY if index & 255 == 0 else GENERIC_KEY, CODEC)
    encode_reply(reply)
    return reply


def _binary_reply(device, runtime, kind):
    # Original a0d700: independent raw banks, never inferred from numeric cache.
    encrypted = AES.new(GENERIC_KEY, AES.MODE_ECB).encrypt(pad(runtime["reports"][kind], 16))
    header = bytearray(39)
    header[:4] = b"fg" + len(encrypted).to_bytes(2, "big")
    header[4:10] = header[16:22] = bytes.fromhex(device.mac)
    # Source 45f490 peer identity remains a separate synthetic zero bank.
    header[26:30] = (1).to_bytes(4, "big")
    now = runtime["_clock"]
    header[30:39] = bytes((1, 0, (now.year + 0x30) & 255, now.month, now.day,
                           now.hour, now.minute, now.second, 2))
    return Reply({}, raw_payload=bytes(header) + encrypted)


def _advertisement(device, state, runtime):
    # Discovery uses literals; similarly named getters serialize different RAM.
    return {"t": "dev", "cid": device.mac, "bc": "gree", "brand": "gree",
            "catalog": "gree", "mac": device.mac, "mid": "0", "model": "gree",
            "name": runtime["metadata"]["name"], "series": "gree", "vender": "1",
            "ver": "V1.0", "lock": state["lock"], "endpoint_id": ""}


class LegacyDirect:
    plaintext_types = tuple(kind for kind in _LOCAL if kind != "scan")
    accept_any_target = True

    def validate_state(self, state):
        for name, value in state.items():
            if name not in RAW_SLOTS or type(value) is not int or not 0 <= value <= 65535:
                raise ValueError("W06M state permits only named unsigned 16-bit raw slots")

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        # Source startup initializes this key, rather than a seed-generated key.
        device.key = DEVICE_KEY
        return None

    def advertise(self, device, outer):
        return self.handle(device, outer)

    def handle(self, device, outer):
        _members(outer)
        candidate = deepcopy(device.state)
        runtime = _runtime(device, candidate)
        if "i" in outer:
            runtime["index"] = _integer(outer["i"])
        if "uid" in outer:
            runtime["incoming_uid"] = _integer(outer["uid"])
        if "cid" in outer:
            runtime["peer"] = _text(outer["cid"], 19)
        if "tcid" in outer:
            _text(outer["tcid"], 19)
        packed = outer.get("t") == "pack"
        if packed:
            _text(outer.get("pack"), 1023)
            inner = decode_pack(outer, DEVICE_KEY if runtime["index"] & 255 == 0
                                else GENERIC_KEY, CODEC)
        else:
            inner = outer
        _members(inner)
        operation = _text(inner.get("t"), 31)
        if operation not in _LOCAL:
            raise InvalidPacket("unsupported W06M local operation")
        for target in ("mac", "sub"):
            if target in inner:
                _text(inner[target], 19)
        response = None
        binary = None
        if operation == "scan":
            response = _advertisement(device, candidate, runtime)
        elif operation == "bind":
            if inner.get("mac") != device.mac:
                raise InvalidPacket("wrong W06M bind target")
            if candidate["lock"] == 0:
                response = {"t": "bindok", "mac": device.mac,
                            "key": DEVICE_KEY.decode("ascii"), "r": 200}
        elif runtime["index"] != 0:
            # The full signed word gates operations; decryption used only low8.
            pass
        elif operation == "status":
            if not packed and isinstance(inner.get("cols"), list):
                response = {"t": "dat", "mac": device.mac, "r": 200}
            else:
                array, names = _names(inner.get("cols"))
                if array:
                    for name in names:
                        if name in ("ElcDatHor", "ElcDatDte", "ElcDatMth"):
                            binary = "energy"
                        elif name == "WatLine":
                            binary = "water"
                if binary is None:
                    response = _response(device, candidate, runtime, names, array)
        elif operation == "cmd":
            if inner.get("sub", inner.get("mac")) != device.mac:
                raise InvalidPacket("wrong W06M command target")
            if not packed and (isinstance(inner.get("opt"), list)
                               or isinstance(inner.get("p"), list)):
                names = []
            else:
                array, names = _names(inner.get("opt"))
                values = inner.get("p")
                if array:
                    if not isinstance(values, list) or len(values) != len(inner["opt"]):
                        raise InvalidPacket("W06M command arrays must match atomically")
                    requested = values
                else:
                    if isinstance(values, list):
                        raise InvalidPacket("W06M scalar command requires a scalar value")
                    requested = [values]
                # Validate the entire input, including slots after a source first hole.
                for value in requested:
                    _text(value, 80) if isinstance(value, str) else _integer(value)
                for name, value in zip(names, requested):
                    if name in RAW_SLOTS:
                        candidate[name] = _integer(value) & 65535
                    elif array and name in _SETTABLE and isinstance(value, str):
                        value = _text(value, _SETTABLE[name])
                        if name in ("apssid", "host", "time") and not value:
                            continue
                        if name == "time":
                            runtime["_clock"] = _clock(value)
                            runtime["_clock_at"] = monotonic()
                        runtime["metadata"][name] = value
                if any(name in _FIRST for name in names):
                    response = _response(device, candidate, runtime, names, array, True)
        elif operation in OPERATIONS:
            # The outer parser never extracts nested arrays; no invented plaintext alias.
            if not packed and operation in ("setT", "updateT"):
                raise InvalidPacket("W06M timer nested commands require encrypted ingress")
            response = schedule(inner, runtime, device.mac, runtime["index"])
        elif operation == "upgrade":
            url = _text(inner.get("url"), 159)
            if not url:
                raise InvalidPacket("W06M upgrade requires a nonempty URL")
            runtime["upgrade_url"] = url
            # Native kind5 acknowledges local staging, not external download completion.
            response = {"t": "ret", "r": 200, "mac": device.mac}
        replies = ([_binary_reply(device, runtime, binary)] if binary is not None
                   else [] if response is None else [_reply(device, runtime, response)])
        device.state = candidate
        device.key = DEVICE_KEY
        return replies

    def tick(self, device, now):
        runtime = _runtime(device, device.state)
        elapsed = int(now - runtime["_clock_at"])
        if elapsed > 0:
            runtime["_clock"] += timedelta(seconds=elapsed)
            runtime["_clock_at"] += elapsed
            runtime["metadata"]["time"] = runtime["_clock"].strftime("%Y-%m-%d %H:%M:%S")
        clock = runtime["_clock"]
        due(runtime, clock.hour, clock.minute, clock.second, (clock.weekday() + 1) % 7)
        return []


PROFILES = (
    Profile("sim-w06m-v1.03", ("0",), HID, SOURCE_SHA256,
            dict.fromkeys(RAW_SLOTS, 0), LegacyDirect(), max_request_bytes=1024),
)
