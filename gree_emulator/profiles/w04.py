"""W04H LAN framing around an explicitly synthetic, model-limited appliance."""

import json

from ..wire import InvalidPacket, Reply, decode_pack
from . import Profile, simulated


GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
HID = "362001061060+U-W04HV3.55.bin"
SOURCE_SHA256 = "17b1c7812a3f98fa1e800e786b37606d842ebbf0b38a25c0ec5c173fcaaa9f2e"
# The firmware's finite lookup table distinguishes omitted model fields from unsafe unknowns.
KNOWN_FIELDS = frozenset("""
Pow Mod SetTem WdSpd Tur Quiet SwUpDn SwingLfRig Add0.5 TemUn TemRec Lig Air Blo
Health SvSt SwhSw HeatCoolType StHt LTemDry Wet SwhSlp SlpMod HasTmr TmrLpTms
TmrOff TmrOn CurTmHor CurTmMin TmrOnHorLf TmrOnMinLf TmrOffHorLf TmrOffMinLf
DsplySt EnvFun JFErrorCode AssHt SwhFreAir AllErr Coolmod HeatCool LedLig SmartMod
Add0.1 ModelType NoD Buzzer_ON_OFF Wind UDFanPort DnPUDSwing DnPLLRSwing DnPRLRSwing
AirQ PM2P5 ElcDatHor ElcDatDte ElcDatMth HumSen ElcP ElcOnKwh ElcAllKwhClr
ElcAllKwhH ElcAllKwhL AutoClean TemSen Emod PctCleOnTm EvapClr NobodySave BlkTemCom
HabitLearn SmartWind HandCtl VocCtl VocIdiom VocRole ImgUpdateCol EnvArea1St
EnvArea2St EnvArea3St EnvArea4St EnvArea5St EnvArea6St EnvArea7St EnvArea8St
EnvArea9St FbidBloPer DIYGra1PoiAmo SwhDIYGra1 Slp1L1 Slp1H1 Slp1L2 Slp1H2
Slp1L3 Slp1H3 Slp1L4 Slp1H4 Slp1L5 Slp1H5 Slp1L6 Slp1H6 Slp1L7 Slp1H7 Slp1L8
Slp1H8 ImgVerSta VocUpdateCol VocVerSta LigSen Video PctCleSetTm AppTimer CO2Level
Dazzling ElcEn MasSub MasIDUMod GetEr HeatSvStTemMax HumiSvStTemMin CoolSvStTemMin
Wmod WsetTmp WschOn WschOnMin WschOff WschOffMin Wtmr1 Wtmr1Min Wtmr2 Wtmr2Min
Wtmr3 Wtmr3Min WsenTmpH WsenTmpM WsenTmpL Werr WsenNub WstpSv WstpH WatTmp MaeS
FanMod ModS VitiGr GasN TemSor HumSor PM2P5V VOC CO2 PctCle PctRe IDUAirQu AirQu
ODUViti GasAvail GasLED GasMod GasMas PM2P5Sta SorErr CommErr Dmod Dfltr Dpump
Dwet DwatFul DwatSen estateInsta21 estateInsta22 estateInsta23 estateInsta24
ChildLock Smod Sfog RemWarnLig Security SecurityMode ImageRecovery Srst Swat
Swash SrstPP SrstPF SrstCF SrstRF SrstAF MakeWat WatErr mode wspd light StTmr
fltrst wipm25 wopm25 estate airQlt Purify ImgUpdateSucs VocUpdateRes MicroSen
ReplaceHEPA UnmanedShutDown UnmanedOffTime PMVComfort Defrost Antifreeze FavorMode
ImgUpdateSta ImgUpdateFail VocUpdateSta SmartSlpMod SmartSlpModEx StSlp1C
StSlp1CInc StSlp1CSp StSlp1H StSlp1HInc StSlp1HSp StSlp2C StSlp2CInc StSlp2CSp
StSlp2H StSlp2HInc StSlp2HSp StSlp3C StSlp3CInc StSlp3CSp StSlp3H StSlp3HInc
StSlp3HSp StSlp4C StSlp4CInc StSlp4CSp StSlp4H StSlp4HInc StSlp4HSp
AntiDirectBlow SwhWifi SwhWifiRe SwhWifiCo datDump datRep datFailRe datPeroid subCnt
HidDownPer InHidDownPer OEEPHidDownPer ACStupPos SaveGuid NoiseSet RoomLen RoomWid
RoomHigh CoolNoise HeatNoise rssi ElcErg ElcGear Elc1Kwh AutoUpdate AutoComnCloud
lock apssid appsw host name time lat lon vender bc mid model series brand catalog
country hid mac ver HidSvrVer InHid InHidSvrVer OEEPHid OEEPHidSvrVer
""".split())


def _envelope(device, index, uid, peer):
    return {"t": "pack", "i": index, "uid": uid,
            "cid": device.mac, "tcid": peer}


def _metadata(device):
    return {"hid": HID, "mid": device.mid, "ver": "V3.0.0", "vender": "2",
            "name": device.name, "mac": device.mac, "host": "", "bc": "00000"}


def _reply(device, inner, index, uid, peer):
    # The firmware uses fixed 1024-byte buffers; do not reproduce buffer corruption.
    if len(json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode()) >= 1024:
        raise InvalidPacket("W04H reply exceeds the firmware buffer")
    return Reply(_envelope(device, index, uid, peer), inner,
                 GENERIC_KEY if index else device.key, CODEC)


class W04H:
    def validate_state(self, state):
        simulated.validate_state(state)

    def thermal_target(self, device):
        return simulated.thermal_target(device)

    def encode_room(self, device):
        simulated.encode_room(device, 40, 255)

    def advertise(self, device, outer):
        metadata = _metadata(device)
        inner = {"t": "dev", "cid": "", "bc": metadata["bc"], "hid": HID,
                 "catalog": "gree", "mid": device.mid, "lock": 0,
                 "model": "gree", "name": device.name, "series": "gree",
                 "vender": metadata["vender"], "ver": metadata["ver"],
                 "brand": "gree", "mac": device.mac}
        return [_reply(device, inner, 1, device.state["_uid"], device.state["_peer"])]

    def handle(self, device, outer):
        if outer.get("tcid") != device.mac:
            raise InvalidPacket("wrong W04H target")
        index = outer.get("i")
        if type(index) is not int:
            raise InvalidPacket("missing W04H key selector")
        inner = decode_pack(outer, GENERIC_KEY if index else device.key, CODEC)
        for selector in ("mac", "sub"):
            if selector in inner and inner[selector] != device.mac:
                raise InvalidPacket("conflicting W04H inner identity")
        uid = outer.get("uid", device.state["_uid"])
        peer = outer.get("cid", device.state["_peer"])
        kind = inner.get("t")
        if kind == "bind":
            if inner.get("mac") != device.mac:
                raise InvalidPacket("missing W04H bind identity")
            reply = _reply(device, {"t": "bindok", "mac": device.mac, "r": 200,
                                    "key": device.key.decode("ascii")}, 1, uid, peer)
        elif kind == "status":
            columns = inner.get("cols")
            if not isinstance(columns, list) or len(columns) > 30:
                raise InvalidPacket("invalid W04H status columns")
            if any(not isinstance(field, str) for field in columns):
                raise InvalidPacket("W04H status columns must be strings")
            requested = []
            for field in columns:
                if not field or len(field.encode()) >= 16:
                    break
                requested.append(field)
            if len(requested) == 30:
                requested.clear()
            if any(field not in KNOWN_FIELDS for field in requested):
                raise InvalidPacket("unsafe unknown W04H field")
            metadata = _metadata(device)
            values = {**metadata, **{key: value for key, value in device.state.items()
                                     if not key.startswith("_")}}
            selected = [field for field in requested if field in values]
            reply = _reply(device, {"t": "dat", "mac": device.mac, "r": 200,
                                    "cols": selected, "dat": [values[field] for field in selected]},
                           0, uid, peer)
        elif kind == "cmd":
            options, values = inner.get("opt"), inner.get("p")
            if not isinstance(options, list) or not isinstance(values, list) or len(options) != len(values):
                raise InvalidPacket("invalid W04H command arrays")
            if len(options) > 30:
                raise InvalidPacket("simulated W04H command batch exceeds 30 fields")
            if any(not isinstance(field, str) or field not in KNOWN_FIELDS for field in options):
                raise InvalidPacket("unsafe unknown W04H command field")
            reply = _reply(device, {"t": "res", "mac": device.mac, "r": 200,
                                    "opt": options, "p": values}, 0, uid, peer)
            simulated.apply_command(device, options, values)
        else:
            return []
        device.state["_uid"], device.state["_peer"] = uid, peer
        return [reply]


HANDLER = W04H()
PROFILES = (Profile(
    id="sim-w04h-v3.55", mids=("10001",), hid=HID, source_sha256=SOURCE_SHA256,
    initial_state={**{name: value for name, value in simulated.INITIAL_STATE.items()
                      if name in KNOWN_FIELDS}, "_uid": 0, "_peer": ""}, handler=HANDLER,
    max_request_bytes=1024,
),)
