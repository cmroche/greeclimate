"""W06AV30 gateway LAN protocol around explicitly synthetic indoor AC models.

The physical TemBody encoding and mainboard transitions remain unverified. The
sim-* models deliberately report floor(Celsius), not a claimed vendor encoding.
"""

import json
from math import floor

from ..wire import InvalidPacket, Reply, decode_pack
from . import Profile, simulated


GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
HID = "362001067012+U-W06AV30.bin"
SOURCE_SHA256 = "6b52f31a74a74c5a88f3d8b68f8b4afc89fcd8d59e3d11a287a4ec37825bf79b"
CHILD_MIDS = ("6049", "604a", "604b", "604c", "605c", "608f", "6092")
CONTROL_FIELDS = frozenset((
    "Pow", "Mod", "SetTem", "WdSpd", "Air", "Blo", "SwhSlp", "SwingLfRig",
    "SwUpDn", "Quiet", "Tur", "SvSt",
))
# Exact finite networking namespace at0x44f840; this is not a capability list.
KNOWN_FIELDS = frozenset("""
SwhWifi SwhWifiRes SwhWifiConf AutoUpdate AutoConnCloud lock datDump datRep datFailRep datPeroid
subCnt useTCP vender bc mid model series apssid appsw brand catalog country hid host mac name
time ver city cnty cityid lat lon Pow Mod SetTem WdSpd Tur Quiet SwUpDn SwingLfRig TemUn TemRec
Lig Air Blo Health SvSt SwhSw HeatCoolType StHt LTemDry Wet SwhSlp SlpMod HasTmr TmrLpTms TmrOff
TmrOn CurTmHor CurTmMin TmrOnHorLf TmrOnMinLf TmrOffHorLf TmrOffMinLf DsplySt EnvFun JFErrorCode
AssHt FrshAir AllErr Coolmod MasSub MasIDUMod GetEr CoolSvStTemMin HeatSvStTemMax HumiSvStTemMin
MaeS FanMod ModS VitiGr GasN TemSor HumSor PM2P5 VOC CO2 PctCle PctRe IDUAirQu AirQu ODUViti
GasAvail GasLED GasMod GasMas PM2P5Sta SorErr CommErr GasQ RunMod Inloop InVitiGr InVitiGrCg
IFDtiGr InEffClRes InEffReRes IFDClRes EffReRes ErrType GoOut AidHeat SetCoolHumi SetDeciTem
SysSta No MIdType AppTimer GcloudHid OEEPHid InHid HidDownPer OEEPHidDownPer InHidDownPer
GcldHidDownPer inUpStat outUpStat gcldUpStat gcldhidownver devinhidownver deveephidownver rssi
OutHome Add0.5 Heat3DSvStTemMax Heat2SvStTemMax TemBody HumiEnable Add0.1 LowDeHumi CleanTime
CleanState AutoClean ErrType1 ErrType2 WFConfig WPow Wstate Wmod WtmrMin WtmrHr WSetTemMax
Watpercent WSunEn WAutoSetTemEn WUTHEn WUTHSetTem WUTHCycle WUTHTmrMin WUTHTmrHr WUTHOngoing
WFastWat FPow Fstate FSetTem FSetTemMax FAutoSetTemEn FFastHeat FIndoorEn FOutHomeEn ExtraMod
WCurTem FCurTem WatTemWrap
""".split())
INITIAL_STATE = {name: value for name, value in simulated.INITIAL_STATE.items()
                 if name in CONTROL_FIELDS}


def _size(value):
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode())


def _reply(device, inner, index, uid, peer):
    envelope = {"t": "pack", "i": index, "uid": uid, "cid": device.mac, "tcid": peer}
    encrypted_size = 16 * (_size(inner) // 16 + 1)
    outer_size = _size({**envelope, "pack": ""}) + 4 * ((encrypted_size + 2) // 3)
    if outer_size >= 1500:
        raise InvalidPacket("gateway reply exceeds firmware buffers")
    return Reply(envelope, inner, GENERIC_KEY if index else device.key, CODEC)


def _metadata(device):
    return {"mac": device.mac, "mid": device.mid, "hid": HID,
            "name": device.name, "vender": "1", "ver": "V1.1.0.0",
            "bc": "", "host": "", "lock": 0}


def _columns(columns):
    if not isinstance(columns, list) or len(columns) > 49:
        raise InvalidPacket("gateway status requires at most49 columns")
    if any(not isinstance(name, str) or not name or len(name.encode()) >= 20
           for name in columns):
        raise InvalidPacket("invalid gateway status field")
    return columns


def _child(device, mac):
    for child in device.children:
        if child.mac == mac:
            return child
    raise InvalidPacket("unknown gateway child selector")


class GatewayFamily:
    def __init__(self, child=False):
        self.child = child

    def validate_state(self, state):
        if not self.child:
            if state:
                raise ValueError(f"gateway state field {next(iter(state))!r} is not configurable")
            return
        for name in state:
            if name not in CONTROL_FIELDS:
                raise ValueError(f"state field {name!r} is not a simulated gateway AC control")
        simulated.validate_state(state)

    def thermal_target(self, device):
        return simulated.thermal_target(device) if device.profile.parent_profiles else None

    def encode_room(self, device):
        if device.profile.parent_profiles:
            device.state["TemBody"] = max(0, min(255, floor(device.room_c)))

    def advertise(self, device, outer):
        if device.profile.parent_profiles:
            return []
        inner = {"t": "dev", "cid": device.mac, "bc": "gree", "brand": "gree",
                 "catalog": "gree", "mac": device.mac, "mid": device.mid,
                 "model": "gree", "name": device.name, "series": "gree",
                 "vender": "1", "ver": "V1.1.0.0", "lock": 0,
                 "hid": HID, "subCnt": len(device.children)}
        return [_reply(device, inner, 1, 0, "")]

    def handle(self, device, outer):
        # Children have no independent LAN endpoint or binding key.
        if device.profile.parent_profiles:
            return []
        if outer.get("tcid") != device.mac or len(outer) > 20:
            raise InvalidPacket("invalid gateway outer target or envelope")
        index, uid, peer = outer.get("i"), outer.get("uid"), outer.get("cid")
        if type(index) is not int or not 0 <= index < 2**31:
            raise InvalidPacket("missing gateway key selector")
        if type(uid) is not int or not -(2**31) <= uid < 2**31:
            raise InvalidPacket("missing gateway uid")
        if not isinstance(peer, str) or len(peer.encode()) >= 20:
            raise InvalidPacket("missing gateway cid")
        if len(outer.get("pack", "")) >= 700:
            raise InvalidPacket("gateway encrypted request exceeds firmware buffer")
        inner = decode_pack(outer, GENERIC_KEY if index else device.key, CODEC)
        if len(inner) > 20:
            raise InvalidPacket("gateway request has too many fields")
        kind = inner.get("t")
        if kind == "bind":
            if inner.get("mac") != device.mac:
                raise InvalidPacket("wrong gateway bind identity")
            return [_reply(device, {"t": "bindOk", "mac": device.mac,
                                    "key": device.key.decode("ascii"), "r": 200}, 1, uid, peer)]
        if kind == "subDev":
            start = inner.get("i")
            if inner.get("mac") != device.mac or type(start) is not int or not -(2**31) <= start < 2**31:
                raise InvalidPacket("enumeration requires gateway mac and integer i")
            start &= 255
            children = [{"mac": child.mac, "mid": child.mid}
                        for child in device.children[start:start + 5]]
            return [_reply(device, {"t": "subList", "c": len(device.children),
                                    "i": start, "r": 200, "list": children}, 0, uid, peer)]
        if kind == "status":
            mac = inner.get("mac")
            target = device if mac == device.mac else _child(device, mac)
            columns = _columns(inner.get("cols"))
            if target is not device and not columns:
                return []
            metadata = _metadata(device)
            available = {**metadata, **target.state}
            selected, values = [], []
            for name in columns:
                if name in available:
                    selected.append(name)
                    values.append(available[name])
                elif name not in KNOWN_FIELDS:
                    selected.append(name)
                    values.append("")
            return [_reply(device, {"t": "dat", "mac": target.mac, "r": 200,
                                    "cols": selected, "dat": values}, 0, uid, peer)]
        if kind == "cmd":
            if "mac" in inner and inner["mac"] != device.mac:
                raise InvalidPacket("conflicting gateway command identity")
            target = _child(device, inner.get("sub"))
            names, values = inner.get("opt"), inner.get("p")
            if (not isinstance(names, list) or not isinstance(values, list)
                    or not names or len(names) > 49 or len(names) != len(values)
                    or any(not isinstance(name, str) or name not in CONTROL_FIELDS for name in names)):
                raise InvalidPacket("gateway command requires modeled opt and p arrays")
            # 0xa13f24 receives p; 0xa13608 emits distinct p and val arrays.
            reply = _reply(device, {"t": "res", "mac": target.mac, "r": 200,
                                    "opt": names, "p": values, "val": values}, 0, uid, peer)
            simulated.apply_command(target, names, values)
            return [reply]
        return []


PROFILES = (
    Profile(id="sim-w06av-v30", mids=("60",), hid=HID, source_sha256=SOURCE_SHA256,
            initial_state={}, handler=GatewayFamily(), max_children=255, max_request_bytes=1024),
    Profile(id="sim-w06av-v30-ac", mids=CHILD_MIDS, hid=HID, source_sha256=SOURCE_SHA256,
            initial_state=INITIAL_STATE, handler=GatewayFamily(child=True), identity_bytes=7,
            parent_profiles=("sim-w06av-v30",)),
)
