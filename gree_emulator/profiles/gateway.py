"""Exact W06AV builds around explicitly synthetic indoor AC models.

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
# V7's 0x447ce0 table ends before the water-heater namespace. V16/V20/V30
# retain the same finite names (at different addresses), not shared capabilities.
V7_FIELDS = KNOWN_FIELDS - frozenset("""
WFConfig WPow Wstate Wmod WtmrMin WtmrHr WSetTemMax Watpercent WSunEn WAutoSetTemEn
WUTHEn WUTHSetTem WUTHCycle WUTHTmrMin WUTHTmrHr WUTHOngoing WFastWat FPow Fstate
FSetTem FSetTemMax FAutoSetTemEn FFastHeat FIndoorEn FOutHomeEn ExtraMod WCurTem
FCurTem WatTemWrap
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
    return {"mac": device.mac, "mid": device.mid, "hid": device.profile.hid,
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
    def __init__(self, child=False, *, five_field_children=False, known_fields=KNOWN_FIELDS):
        self.child = child
        self.five_field_children = five_field_children
        self.known_fields = known_fields

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

    def _child_metadata(self, child):
        record = {"mac": child.mac, "mid": child.mid}
        if self.five_field_children:
            # Configured names represent the populated native child-name cache.
            record.update(name=child.name, model="gree", lock=0)
        return record

    def advertise(self, device, outer):
        if device.profile.parent_profiles:
            return []
        inner = {"t": "dev", "cid": device.mac, "bc": "gree", "brand": "gree",
                 "catalog": "gree", "mac": device.mac, "mid": device.mid,
                 "model": "gree", "name": device.name, "series": "gree",
                 "vender": "1", "ver": "V1.1.0.0", "lock": 0,
                 "hid": device.profile.hid, "subCnt": len(device.children)}
        # This model selects the count-enabled source branch. Native alias-MID
        # rewrites/gf001 branches do not apply to the admitted CHILD_MIDS.
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
            children = [self._child_metadata(child)
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
                # Unknown-empty / known-omitted rendering is safe model policy;
                # native final dat serialization has not been replayed.
                elif name not in self.known_fields:
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
            # Native res echoes p/val without mainboard confirmation. The model
            # instead validates and applies controls atomically; never replay
            # the native unsupported-field staging/uninitialized GetEr slot.
            reply = _reply(device, {"t": "res", "mac": target.mac, "r": 200,
                                    "opt": names, "p": values, "val": values}, 0, uid, peer)
            simulated.apply_command(target, names, values)
            return [reply]
        return []


# Identities are embedded payload HIDs, not the regional OTA filenames.
BUILDS = (
    ("v7", "362001061433+U-W06AV7.bin",
     "954010b17a5bd2c27008164a638aad633a0798137863bea07767a950d2143924", True, V7_FIELDS),
    ("v16", "362001067012+U-W06AV16.bin",
     "0187ddc8c6f8f151319cb100a8b2bf15a9f63526ef84cf7ea95412248d37eb21", True, KNOWN_FIELDS),
    ("v16-eu", "362001067012+U-W06AV16.bin",
     "5bfd8e251fe74905685eb32b41dcf941be0fa78ee60ddc5b26160f7b15ede644", True, KNOWN_FIELDS),
    ("v16-kf", "362001067012+U-W06AV16.bin",
     "31b02d6c8388d1ed2b96b9037abe9ea93e867100497627d1ac687e55dcd45469", True, KNOWN_FIELDS),
    ("v20", "362001067012+U-W06AV20.bin",
     "654fa6509d50345568887f5843dc07af6c19112bb995bd8bdfa52ff9ad9ae862", False, KNOWN_FIELDS),
    ("v30", HID, SOURCE_SHA256, False, KNOWN_FIELDS),
)
PROFILES = tuple(
    profile
    for version, hid, sha256, five_fields, fields in BUILDS
    for profile in (
        Profile(id=f"sim-w06av-{version}", mids=("60",), hid=hid, source_sha256=sha256,
                initial_state={}, handler=GatewayFamily(
                    five_field_children=five_fields, known_fields=fields),
                max_children=255, max_request_bytes=1024),
        Profile(id=f"sim-w06av-{version}-ac", mids=CHILD_MIDS, hid=hid, source_sha256=sha256,
                initial_state=INITIAL_STATE, handler=GatewayFamily(child=True),
                identity_bytes=7, parent_profiles=(f"sim-w06av-{version}",)),
    )
)
