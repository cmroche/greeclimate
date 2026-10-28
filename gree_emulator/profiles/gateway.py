"""Exact W06AV/W06BV LAN caches with explicitly synthetic board state.

Raw cache readouts are not calibrated appliance temperatures. V7 and V16
metadata and descriptor differences are kept separate from later builds.
"""

import json
from base64 import b64decode
from binascii import Error as Base64Error
from datetime import datetime

from ..wire import InvalidPacket, Reply, _json, decode_pack
from . import Profile


GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
HID = "362001067012+U-W06AV30.bin"
SOURCE_SHA256 = "6b52f31a74a74c5a88f3d8b68f8b4afc89fcd8d59e3d11a287a4ec37825bf79b"
CHILD_MIDS = ("6049", "604a", "604b", "604c", "605c", "608f", "6092")
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
INITIAL_STATE = {
    "Pow": 0, "Mod": 0, "SetTem": 24, "WdSpd": 0, "Air": 0, "Blo": 0,
    "SwhSlp": 0, "SwingLfRig": 0, "SwUpDn": 0, "Quiet": 0, "Tur": 0, "SvSt": 0,
}

# Independently decoded AV16-EU/AV20/AV30/BV20 descriptor records:
# selector, byte offset, width/mask. Shared offsets are real cache aliases.
ORDINARY = {
    "GetEr": (0, 5, 255), "Pow": (1, 6, 255), "MasSub": (2, 7, 255),
    "SvSt": (3, 8, 255), "Blo": (4, 9, 255), "Air": (5, 10, 255),
    "Mod": (6, 11, 255), "Quiet": (7, 12, 255), "SwhSlp": (8, 13, 255),
    "WdSpd": (9, 15, 255), "SetTem": (10, 16, 65535),
    "CoolSvStTemMin": (11, 18, 65535), "HeatSvStTemMax": (12, 20, 65535),
    "HumiSvStTemMin": (13, 22, 65535), "MasIDUMod": (14, 28, 255),
    "GoOut": (15, 29, 255), "AidHeat": (16, 31, 255), "SetCoolHumi": (17, 32, 255),
    "SetDeciTem": (18, 16, 65535), "SysSta": (19, 33, 65535),
    "AllErr": (20, 5, 255), "OutHome": (21, 29, 255), "AssHt": (22, 31, 255),
    "Add0.5": (23, 44, 255), "Tur": (24, 14, 255),
    "Heat3DSvStTemMax": (25, 24, 65535), "Heat2SvStTemMax": (26, 26, 65535),
    "TemBody": (27, 35, 255), "HumiEnable": (28, 36, 255),
    "SwUpDn": (29, 37, 255), "SwingLfRig": (30, 38, 255),
    "Add0.1": (31, 39, 255), "LowDeHumi": (32, 40, 255),
    "CleanTime": (33, 41, 255), "CleanState": (34, 42, 255), "AutoClean": (35, 43, 255),
    "ErrType1": (36, 50, 65535), "ErrType2": (37, 52, 65535),
    "WFConfig": (38, 54, 255), "WPow": (39, 55, 255), "Wstate": (40, 56, 255),
    "Wmod": (41, 57, 255), "WtmrMin": (42, 58, 255), "WtmrHr": (43, 59, 255),
    "WSetTemMax": (44, 60, 65535), "Watpercent": (45, 62, 255),
    "WSunEn": (46, 63, 255), "WAutoSetTemEn": (47, 64, 255), "WUTHEn": (48, 65, 255),
    "WUTHSetTem": (49, 66, 65535), "WUTHCycle": (50, 68, 255),
    "WUTHTmrMin": (51, 69, 255), "WUTHTmrHr": (52, 70, 255),
    "WUTHOngoing": (53, 71, 255), "WFastWat": (54, 72, 255),
    "FPow": (55, 73, 255), "Fstate": (56, 74, 255), "FSetTem": (57, 75, 65535),
    "FSetTemMax": (58, 77, 65535), "FAutoSetTemEn": (59, 79, 255),
    "FFastHeat": (60, 80, 255), "FIndoorEn": (61, 81, 255),
    "FOutHomeEn": (62, 82, 255), "ExtraMod": (63, 83, 255),
    "WCurTem": (64, 84, 255), "FCurTem": (65, 85, 255), "WatTemWrap": (66, 86, 255),
}
ALTERNATE = {
    "GetEr": (0, 0, 255), "Pow": (1, 5, 255), "Tur": (2, 6, 255),
    "ModS": (3, 7, 255), "FanMod": (4, 8, 255), "WdSpd": (5, 9, 255),
    "RunMod": (6, 10, 255), "IDUAirQu": (7, 11, 255), "ODUViti": (8, 12, 255),
    "Inloop": (9, 13, 255), "InVitiGr": (10, 15, 255), "InVitiGrCg": (11, 16, 255),
    "IFDtiGr": (12, 17, 255), "VitiGr": (13, 18, 255), "TemSor": (14, 19, 255),
    "HumSor": (15, 24, 255), "InEffClRes": (16, 29, 255), "InEffReRes": (17, 30, 255),
    "AirQu": (18, 31, 255), "PM2P5": (19, 36, 65535), "VOC": (20, 46, 65535),
    "CO2": (21, 56, 65535), "PctCle": (22, 66, 255), "PctRe": (23, 67, 255),
    "IFDClRes": (24, 68, 255), "EffReRes": (25, 69, 255),
    "GasAvail": (26, 71, 255), "GasLED": (27, 72, 255), "GasMod": (28, 73, 255),
    "GasMas": (29, 74, 255), "PM2P5Sta": (30, 75, 255),
    "SorErr": (31, 76, 255), "CommErr": (32, 77, 255), "ErrType": (33, 83, 65535),
    "Mod": (34, 88, 255), "SetTem": (35, 89, 65535), "ExWdSpd": (36, 91, 255),
    "TemRec": (37, 92, 255), "TemUn": (38, 93, 255),
}
TEMPERATURE_FIELDS = frozenset((
    "SetTem", "CoolSvStTemMin", "HeatSvStTemMax", "HumiSvStTemMin",
    "WSetTemMax", "WUTHSetTem", "FSetTem", "FSetTemMax",
))
MODE_MAP = (5, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12)
V7_ORDINARY = {name: descriptor for name, descriptor in ORDINARY.items()
               if descriptor[0] < 38}
# V7's ordinary selector accidentally overlaps metadata with numeric records.
V7_METADATA_ALIASES = dict(zip(
    ("host", "hid", "lock", "name", "time", "GcloudHid", "OEEPHid", "InHid",
     "HidDownPer", "GcldHidDownPer", "OEEPHidDownPer", "InHidDownPer",
     "gcldUpStat", "inUpStat", "outUpStat", "gcldhidownver", "devinhidownver"),
    ("AllErr", "OutHome", "AssHt", "Add0.5", "Heat3DSvStTemMax",
     "Heat2SvStTemMax", "TemBody", "HumiEnable", "SwUpDn", "SwingLfRig",
     "Add0.1", "LowDeHumi", "CleanTime", "CleanState", "AutoClean",
     "ErrType1", "ErrType2"),
))
CHILD_METADATA = frozenset("""
SwhWifi SwhWifiRes SwhWifiConf AutoUpdate AutoConnCloud lock datDump datRep datFailRep
datPeroid subCnt useTCP vender bc mid model series apssid appsw brand catalog country
hid host mac name time ver city cnty cityid lat lon AppTimer GcloudHid OEEPHid InHid
HidDownPer OEEPHidDownPer InHidDownPer GcldHidDownPer inUpStat outUpStat gcldUpStat
gcldhidownver devinhidownver deveephidownver rssi
No MIdType
""".split())


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
    def __init__(self, *, five_field_children=False, known_fields=KNOWN_FIELDS,
                 low_byte_key=False, old_build=None, empty_status_hid=False, timers=False,
                 clock_echo=True):
        self.five_field_children = five_field_children
        self.known_fields = known_fields
        self.low_byte_key = low_byte_key
        self.old_build = old_build
        self.empty_status_hid = empty_status_hid
        self.timers = old_build is not None or timers
        self.rules = old_build is not None
        # AV20/AV30/BV30 stage clock writes in a different buffer from reads.
        self.clock_echo = clock_echo

    def validate_state(self, state):
        if state:
            raise ValueError(f"gateway state field {next(iter(state))!r} is not configurable")

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        pass

    def _child_metadata(self, child):
        record = {"mac": child.mac, "mid": child.mid}
        if self.old_build:
            record["mid"] = {"6099": "6079", "608d": "6079", "6091": "6079",
                             "6035": "6036"}.get(child.mid, child.mid)
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
        inner["lock"] = device.state.get("_metadata", {}).get("lock", 0)
        if self.old_build:
            # These original dev builders predate the HID discovery member.
            del inner["hid"]
        # This model selects the count-enabled source branch. Native alias-MID
        # rewrites/gf001 branches do not apply to the admitted CHILD_MIDS.
        return [_reply(device, inner, 1, 0, "")]

    @staticmethod
    def _integer(value):
        if type(value) is not int or not -(2**31) <= value < 2**31:
            raise InvalidPacket("schedule requires int32 values")
        return value

    @staticmethod
    def _text(value, maximum):
        if not isinstance(value, str) or "\0" in value or len(value.encode()) > maximum:
            raise InvalidPacket("schedule string exceeds its source cache")
        return value

    def _array(self, value, maximum):
        if not isinstance(value, list) or len(value) > maximum:
            raise InvalidPacket("schedule array exceeds its source cache")
        return [self._integer(item) for item in value] + [0] * (maximum - len(value))

    def _rule_command(self, device, encoded):
        self._text(encoded, 331)
        try:
            payload = b64decode(encoded, validate=True)
        except (Base64Error, ValueError) as exc:
            raise InvalidPacket("invalid IFTTT command base64") from exc
        # Source rules store a JSON i/pack object, not a LAN t=pack envelope.
        outer = _json(payload)
        selector = self._integer(outer.get("i"))
        packed = outer.get("pack")
        if not isinstance(packed, str):
            raise InvalidPacket("IFTTT command requires an encrypted pack string")
        if len(outer) > 20 or len(packed) >= 300:
            raise InvalidPacket("IFTTT command exceeds source JSON buffers")
        command = decode_pack(outer, GENERIC_KEY if selector & 255 else device.key, CODEC)
        target = _child(device, command.get("sub"))
        names, values = command.get("opt"), command.get("p")
        fields = V7_ORDINARY if self.old_build == "v7" else ORDINARY
        if (not isinstance(names, list) or not isinstance(values, list)
                or not 1 <= len(names) <= 5 or len(names) != len(values)
                or any(not isinstance(name, str) or name not in fields
                       or len(name.encode()) >= 16 for name in names)):
            raise InvalidPacket("IFTTT command requires at most five ordinary selectors")
        staged = []
        for name, value in zip(names, values):
            self._integer(value)
            selector = fields[name][0]
            # Original rule staging converts only these selectors, unlike cmd.
            if selector in (1, 2, 3, 4, 7, 8, 9, 17) and name in ("Pow", "WdSpd"):
                value = RawChild()._converted(name, value)
            staged.append((selector, value & 65535))
        return target.mac, staged

    def _schedule(self, device, inner, uid, peer):
        kind = inner["t"]
        rule = kind.endswith("IFTTT")
        key = "_ifttt" if rule else "_timers"
        records = device.state.get(key, {}).copy()
        maximum = 16 if rule else 10
        if kind.startswith("query"):
            index = self._integer(inner.get("index"))
            count = self._integer(inner.get("count"))
            if rule:
                count &= 255
            if not 0 <= index < maximum or not 1 <= count <= maximum - index:
                raise InvalidPacket("invalid schedule query window")
            if rule:
                # Native queryIFTTT repeats the same index, then serializes once.
                record = records.get(index)
                body = {"t": "listIFTTT", "total": len(records),
                        "index": index if records else 0,
                        "list": [{name: value for name, value in record.items()
                                  if not name.startswith("_")}] if record else []}
                return [_reply(device, body, 0, uid, peer)]
            # Each response is one explicitly synthetic mainboard timer report.
            return [_reply(device, {"t": "listT", "total": len(records), "index": index,
                                    "list": [records[slot]] if slot in records else []},
                           0, uid, peer) for slot in range(index, index + count)]
        identifier = self._integer(inner.get("id"))
        if kind.startswith("delete"):
            if rule:
                slot = next((slot for slot, record in records.items()
                             if record["id"] == identifier), None)
                if slot is None:
                    raise InvalidPacket("unknown IFTTT id")
                del records[slot]
                records = dict(enumerate(records.values()))
            else:
                if not 0 <= identifier < 10:
                    raise InvalidPacket("timer id requires 0..9")
                records.pop(identifier, None)
        elif rule:
            if inner.get("mac") != device.mac:
                raise InvalidPacket("IFTTT metadata targets the gateway")
            record = {name: self._integer(inner.get(name))
                      for name in ("id", "enable", "type", "devtype")}
            record.update({name: self._text(inner.get(name), limit) for name, limit in (
                ("name", 31), ("mac", 15), ("sMac", 15), ("tMac", 15), ("cmd", 331),
            )})
            record["week"] = self._array(inner.get("week"), 7)
            conditions = inner.get("condit")
            if (not isinstance(conditions, list) or len(conditions) > 5
                    or any(not isinstance(item, list) or len(item) != 3 for item in conditions)):
                raise InvalidPacket("IFTTT requires at most five condition triples")
            record["condit"] = [self._array(item, 3) for item in conditions]
            if "start" in inner:
                record["start"] = self._array(inner["start"], 3)
                record["end"] = self._array(inner.get("end", []), 3)
            elif "end" in inner:
                self._array(inner["end"], 3)
            record["_command"] = self._rule_command(device, record["cmd"])
            if kind == "updateIFTTT":
                slot = next((slot for slot, old in records.items()
                             if old["id"] == identifier), None)
                if slot is None:
                    raise InvalidPacket("unknown IFTTT id")
            else:
                if len(records) == 16:
                    raise InvalidPacket("IFTTT source list is full")
                slot = next(slot for slot in range(16) if slot not in records)
                if records:
                    ids = {old["id"] for old in records.values()}
                    record["id"] = next(value for value in range(17) if value not in ids)
            records[slot] = record
        else:
            if not 0 <= identifier < 10:
                raise InvalidPacket("timer id requires 0..9")
            command = inner.get("cmd")
            if not isinstance(command, list) or len(command) != 1 or not isinstance(command[0], dict):
                raise InvalidPacket("timer requires one command record")
            command = command[0]
            macs, names, values = command.get("mac"), command.get("opt"), command.get("p")
            fields = V7_ORDINARY if self.old_build == "v7" else ORDINARY
            if (not isinstance(macs, list) or len(macs) != 1
                    or not isinstance(names, list) or len(names) != 1
                    or not isinstance(names[0], str) or names[0] not in fields
                    or not isinstance(values, list) or len(values) != 1):
                raise InvalidPacket("timer requires one mac, selector and integer value")
            target = _child(device, macs[0])
            requested = self._integer(values[0])
            week = self._array(inner.get("week"), 7)[0] & 127
            if not inner["week"]:
                # The original shared staging buffer retains an omitted mask.
                week = device.state.get("_timer_week", 0)
            self._integer(inner.get("tz"))
            record = {"id": identifier, "name": self._text(inner.get("name"), 19),
                      **{name: self._integer(inner.get(name)) & 255
                         for name in ("enable", "hr", "min", "sec")},
                      "week": [(week >> bit) & 1 for bit in range(7)],
                      "cmd": [{"mac": [target.mac], "opt": ["Pow"],
                               "p": [int((requested & 255) == 1)]}]}
            record["enable"] &= 1
            records[identifier] = record
        # Atomic safe ownership/cache policy, not native cJSON/mainboard success.
        reply = _reply(device, {"t": "resT", "r": 200}, 2 if rule else 0, uid, peer)
        device.state[key] = records
        if not rule and not kind.startswith("delete"):
            device.state["_timer_week"] = week
        return [reply]

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
        key_index = index & 255 if self.low_byte_key else index
        inner = decode_pack(outer, GENERIC_KEY if key_index else device.key, CODEC)
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
            metadata = {name: "" for name in self.known_fields}
            metadata.update(_metadata(device), time="", rssi=219)
            metadata.update({name: 0 for name in (
                "HidDownPer", "GcldHidDownPer", "OEEPHidDownPer", "InHidDownPer",
                "gcldUpStat", "inUpStat", "outUpStat",
            )})
            metadata.update(device.state.get("_metadata", {}))
            if self.empty_status_hid:
                metadata["hid"] = ""
            if self.old_build:
                metadata.update(name=device.mac, time="2017-6-15 00:00:00",
                                host="dis.gree.com", appsw="12345678")
                metadata.update(device.state.get("_metadata", {}))
                metadata["name"] = device.mac
                if self.old_build == "v7":
                    # Synthetic version zero for the source-initialized companion code.
                    metadata["GcloudHid"] = "362001061734+U-ZTS15V0.bin"
            metadata.update({name: 0 for name in self.known_fields - CHILD_METADATA})
            metadata["name"] = device.mac
            if target is device:
                return [_reply(device, {"t": "dat", "mac": device.mac, "r": 200,
                                        "cols": columns,
                                        "dat": [metadata.get(name, "") for name in columns]},
                               0, uid, peer)]
            handler = target.profile.handler
            gas_index = inner.get("GasN", 0)
            if type(gas_index) is not int or not 0 <= gas_index < 5:
                raise InvalidPacket("gateway GasN requires a synthetic cache channel in 0..4")
            cache, values = handler.read_fields(target, columns, metadata, gas_index)
            body = {"t": "dat", "mac": target.mac, "r": 200,
                    "cols": columns, "dat": values}
            if handler.alternate and "GasN" in inner:
                body["GasN"] = gas_index
            reply = _reply(device, body, 0, uid, peer)
            target.state["_cache"] = cache
            return [reply]
        if ((self.timers and kind in ("setT", "updateT", "queryT", "deleteT"))
                or (self.rules and kind in ("setIFTTT", "updateIFTTT", "queryIFTTT", "deleteIFTTT"))):
            return self._schedule(device, inner, uid, peer)
        if kind == "cmd":
            if "mac" in inner and inner["mac"] != device.mac:
                raise InvalidPacket("conflicting gateway command identity")
            names, values = inner.get("opt"), inner.get("p")
            if (not isinstance(names, list) or not isinstance(values, list)
                    or not names or len(names) > 49 or len(names) != len(values)):
                raise InvalidPacket("gateway command requires equally sized opt and p arrays")
            target = device if inner.get("sub") == device.mac else _child(device, inner.get("sub"))
            metadata = device.state.get("_metadata", {}).copy()
            controls, control_values = [], []
            child_name = None
            clock_write = False
            for name, value in zip(names, values):
                if not isinstance(name, str):
                    raise InvalidPacket("gateway command requires string fields")
                if target is not device and name in ("lock", "host", "apssid", "appsw"):
                    raise InvalidPacket("network metadata writes require the gateway target")
                if name == "lock":
                    self._integer(value)
                    metadata[name] = value
                elif name in ("name", "host", "time", "apssid", "appsw"):
                    lower = 0 if name == "appsw" else 1
                    upper = 32 if name in ("apssid", "appsw") else 20
                    if (not isinstance(value, str) or "\0" in value
                            or not lower <= len(value.encode()) <= upper):
                        raise InvalidPacket("invalid gateway metadata string")
                    if name == "time":
                        try:
                            datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
                        except ValueError as exc:
                            raise InvalidPacket("gateway time requires a complete calendar timestamp") from exc
                        if self.clock_echo:
                            metadata[name] = value
                        clock_write = True
                    elif name in ("apssid", "appsw") and self.old_build == "v7":
                        metadata[name] = value
                    elif name == "name" and self.old_build and target is not device:
                        child_name = value
                    # Root name/host and later Wi-Fi writes are native no-ops.
                elif target is not device and name in target.profile.handler.control_fields:
                    controls.append(name)
                    control_values.append(value)
                else:
                    raise InvalidPacket("gateway command requires routed raw fields")
            cache = None
            if controls:
                cache = target.profile.handler.prepare_command(target, controls, control_values)
            if target is not device and "name" in names and not self.old_build and not clock_write:
                raise InvalidPacket("this build cannot rename children")
            submitted_name = next((value for name, value in zip(reversed(names), reversed(values))
                                   if name == "name"), "")
            readouts = {"name": device.mac, "host": "dis.gree.com" if self.old_build else "",
                        "apssid": "", "appsw": "12345678" if self.old_build else "",
                        "time": "2017-6-15 00:00:00" if self.old_build else ""}
            readouts.update(metadata)
            # Descriptor admission is separate from the network serializer's names.
            # V7 omits unknown slots; later builds retain empty-string slots.
            response_fields = [(name, value) for name, value in zip(names, values)
                               if self.old_build != "v7" or name in self.known_fields]
            response_names = [name for name, _ in response_fields]
            ack = [readouts.get(name, value if name in self.known_fields else "")
                   for name, value in response_fields]
            effective = [(submitted_name if self.old_build else "") if name == "name" else value
                         for name, value in zip(response_names, ack)]
            reply = _reply(device, {"t": "res", "mac": target.mac, "r": 200,
                                    "opt": response_names, "p": ack, "val": effective}, 0, uid, peer)
            if metadata:
                device.state["_metadata"] = metadata
            # The source clock path wins over child rename, which in turn
            # suppresses ordinary control staging for that transaction.
            if not clock_write:
                if child_name is not None:
                    target.name = child_name
                elif cache is not None:
                    target.state["_cache"] = cache
            return [reply]
        return []


class RawChild(GatewayFamily):
    """Synthetic persistent board cache; raw readouts have no calibrated physics."""

    def __init__(self, *, alternate=False, old_build=None):
        super().__init__(known_fields=V7_FIELDS if old_build == "v7" else KNOWN_FIELDS)
        self.alternate = alternate
        self.old_build = old_build
        self.control_fields = (ALTERNATE if alternate else
                               V7_ORDINARY if old_build == "v7" else ORDINARY)

    def validate_state(self, state):
        for name, value in state.items():
            if name not in self.control_fields or type(value) is not int or not -(2**31) <= value < 2**31:
                raise ValueError(f"state field {name!r} must be a routed int32 raw control")
        try:
            self._stage([0] * 96, list(state), list(state.values()))
        except InvalidPacket as exc:
            raise ValueError(f"state: {exc}") from exc

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        if "_cache" not in device.state:
            cache = self._stage([0] * 96, list(device.state), list(device.state.values()))
            device.state.clear()
            device.state["_cache"] = cache

    def _converted(self, name, value):
        if name == "Pow":
            if value not in (0, 1):
                raise InvalidPacket("raw Pow converter requires 0 or 1")
            return (0x55, 0xaa)[value]
        if name == "Mod":
            if not 0 <= value < len(MODE_MAP):
                raise InvalidPacket("raw Mod converter requires 0..11")
            return MODE_MAP[value]
        if not self.alternate and name == "WdSpd":
            if not 0 <= value <= 7:
                raise InvalidPacket("raw WdSpd converter requires 0..7")
            return value + 1
        if not self.alternate and name == "SwUpDn":
            if value not in (0, 1):
                raise InvalidPacket("raw SwUpDn converter requires 0 or 1")
            return value + 1
        if name in (("SetTem",) if self.alternate else TEMPERATURE_FIELDS):
            return value * 10
        return value

    @staticmethod
    def _store(cache, offset, mask, value):
        cache[offset] = value & (255 if mask in (255, 65535) else 1 << (mask & 31))
        if mask == 65535:
            cache[offset + 1] = (value >> 8) & 255

    def _stage(self, cache, names, values):
        # Validate the entire batch before even changing the temporary bank.
        for name, value in zip(names, values):
            if name not in self.control_fields or type(value) is not int or not -(2**31) <= value < 2**31:
                raise InvalidPacket("raw command requires routed int32 values")
            self._converted(name, value)
        temperature = fraction = None
        temperature_after_fraction = fraction_after_temperature = False
        for name, value in zip(names, values):
            _, offset, mask = self.control_fields[name]
            converted = self._converted(name, value)
            self._store(cache, offset, mask, converted)
            if self.alternate:
                # The source converter selects unit/half only from the first
                # command slot, not from the previously cached unit.
                if name == "SetTem":
                    unit = values[0] & 255 if names[0] == "TemUn" else 0
                    half = values[0] & 255 if names[0] == "TemRec" else 0
                    cache[92], cache[93] = half, unit
                    if unit == 1:
                        requested = min(30, max(16, value & 65535))
                        converted = next((raw for whole, bit, raw in ALT_TEMPERATURES
                                          if whole == requested and bit == (half if half <= 1 else 0)), 161)
                    elif unit != 0:
                        converted = value
                    self._store(cache, offset, mask, converted)
                continue
            if name in ("SetTem", "SetDeciTem"):
                temperature_after_fraction |= fraction is not None
                temperature = (offset, converted & 65535)
            elif name in ("Add0.5", "Add0.1"):
                fraction_after_temperature |= temperature is not None
                fraction = ((value & 255) * (5 if name == "Add0.5" else 1)) & 255
            if temperature_after_fraction and name in ("SetTem", "SetDeciTem"):
                self._store(cache, offset, 65535, converted + fraction)
            elif fraction_after_temperature and name in ("Add0.5", "Add0.1"):
                # This source branch adds the original fraction, even for Add0.5.
                self._store(cache, temperature[0], 65535, value + temperature[1])
        return cache

    def prepare_command(self, device, names, values):
        return self._stage(device.state["_cache"].copy(), names, values)

    def read_fields(self, device, columns, metadata, gas_index=0):
        cache = device.state["_cache"].copy()
        fraction = 0
        values = []
        for name in columns:
            original_name = name
            if self.alternate and name == "GasQ":
                values.append(cache[70])
                continue
            if self.old_build == "v7" and not self.alternate:
                if name == "deveephidownver":
                    values.append(metadata.get(name, ""))
                    continue  # Safe model avoids V7's out-of-table metadata read.
                name = V7_METADATA_ALIASES.get(name, name)
            if name not in self.control_fields:
                values.append(metadata.get(name, "") if name in CHILD_METADATA
                              else (0 if name in self.known_fields else ""))
                continue
            selector, offset, mask = self.control_fields[name]
            if self.alternate:
                if name in ("TemSor", "HumSor", "AirQu"):
                    offset += gas_index
                elif name in ("PM2P5", "VOC", "CO2"):
                    offset += 2 * gas_index
            value = cache[offset]
            if mask == 65535:
                value |= cache[offset + 1] << 8
            elif mask != 255:
                value &= 1 << (mask & 31)
            if name == "Pow":
                value = int(value == 0xaa)
            elif name == "Mod":
                value = MODE_MAP.index(value) if value in MODE_MAP else 0
            elif self.alternate:
                if name == "GetEr" and (cache[83] or cache[84]):
                    value = 1
                elif name in ("GasAvail", "GasLED", "GasMod", "GasMas", "PM2P5Sta", "SorErr", "CommErr"):
                    value = (value >> gas_index) & 1
                elif name == "SetTem":
                    if cache[93] == 0:
                        value = (value + 5) // 10
                        cache[92] = 0
                    elif cache[93] == 1:
                        whole, half = next(((whole, half) for whole, half, raw in ALT_TEMPERATURES
                                            if raw == min(300, max(160, value))), (16, 0))
                        value, cache[92] = whole, half
            elif name in ("SetTem", "SetDeciTem"):
                fraction = value % 10
                if name == "SetTem":
                    value //= 10
            elif name in TEMPERATURE_FIELDS:
                value //= 10
            elif name == "WdSpd":
                if value > 7:
                    raise InvalidPacket("native WdSpd inverse cannot serialize this raw byte")
                value = value - 1 if value else 8
            elif name == "SwUpDn":
                value = int(2 <= value <= 12)
            elif name in ("Add0.5", "Add0.1"):
                value = int(fraction > 0) if name == "Add0.5" else fraction
                cache[offset] = value
            values.append(metadata.get(original_name, "") if original_name in CHILD_METADATA else
                          "" if original_name not in self.known_fields else value)
        return cache, values


# Exact AV20 table0x4566b0..0x456748; same literal table is qualified below
# per source in the research matrix. Raw tenths are protocol, not calibration.
ALT_TEMPERATURES = (
    (16, 0, 161), (17, 0, 166), (17, 1, 172), (18, 0, 177), (18, 1, 183),
    (19, 0, 188), (19, 1, 194), (20, 0, 200), (21, 0, 205), (21, 1, 211),
    (22, 0, 216), (22, 1, 222), (23, 0, 227), (23, 1, 233), (24, 0, 238),
    (24, 1, 244), (25, 0, 250), (26, 0, 255), (26, 1, 261), (27, 0, 266),
    (27, 1, 272), (28, 0, 277), (28, 1, 283), (29, 0, 288), (29, 1, 294),
    (30, 0, 300), (16, 0, 160), (17, 1, 170), (18, 0, 180), (19, 0, 190),
    (21, 1, 210), (22, 1, 220), (23, 0, 230), (24, 0, 240), (26, 1, 260),
    (27, 1, 270), (28, 0, 280), (29, 0, 290),
)


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
                    five_field_children=five_fields, known_fields=fields,
                    old_build=version if version in ("v7", "v16", "v16-eu", "v16-kf") else None,
                    empty_status_hid=version.startswith("v16"), timers=version == "v20",
                    clock_echo=version not in ("v20", "v30")),
                max_children=255, max_request_bytes=1024),
        Profile(id=f"sim-w06av-{version}-ac", mids=CHILD_MIDS, hid=hid, source_sha256=sha256,
                initial_state=INITIAL_STATE,
                handler=RawChild(old_build=version if five_fields else None),
                identity_bytes=7, parent_profiles=(f"sim-w06av-{version}",)),
    )
)
PROFILES += (
    Profile(id="sim-w06bv-v20", mids=("60",), hid="362001067524+U-W06BV20.bin",
            source_sha256="c449e08599008f5250e96d5c77c24a0d10ac9e1a495c45c62526bfa9e8ecaadb",
            initial_state={}, handler=GatewayFamily(low_byte_key=True, timers=True),
            max_children=100, max_request_bytes=1024),
    Profile(id="sim-w06bv-v20-ac", mids=CHILD_MIDS, hid="362001067524+U-W06BV20.bin",
            source_sha256="c449e08599008f5250e96d5c77c24a0d10ac9e1a495c45c62526bfa9e8ecaadb",
            initial_state=INITIAL_STATE, handler=RawChild(),
            identity_bytes=7, parent_profiles=("sim-w06bv-v20",)),
    Profile(id="sim-w06bv-v20-fan", mids=("6079",), hid="362001067524+U-W06BV20.bin",
            source_sha256="c449e08599008f5250e96d5c77c24a0d10ac9e1a495c45c62526bfa9e8ecaadb",
            initial_state={"Pow": 0, "FanMod": 0, "WdSpd": 0}, handler=RawChild(alternate=True),
            identity_bytes=7, parent_profiles=("sim-w06bv-v20",)),
)
PROFILES += tuple(
    Profile(id=f"sim-w06av-{version}-fan",
            mids=("6079", "6099", "608d", "6091") if version in ("v7", "v16", "v16-eu", "v16-kf") else ("6079",),
            hid=hid, source_sha256=sha256,
            initial_state={"Pow": 0, "FanMod": 0, "WdSpd": 0},
            handler=RawChild(alternate=True, old_build=version if version.startswith("v16") or version == "v7" else None),
            identity_bytes=7,
            parent_profiles=(f"sim-w06av-{version}",))
    for version, hid, sha256, _, _ in BUILDS
)
PROFILES += tuple(
    Profile(id=f"sim-w06av-{version}-water", mids=("6036", "6035"), hid=hid,
            source_sha256=sha256, initial_state=INITIAL_STATE,
            handler=RawChild(old_build=version), identity_bytes=7,
            parent_profiles=(f"sim-w06av-{version}",))
    for version, hid, sha256, _, _ in BUILDS if version.startswith("v16")
)

# BV9/16/30 have separately recovered descriptors and routing; the strings here
# select only their proved metadata/cache contracts, not hardware equivalence.
BV_BUILDS = (
    ("v9", "362001061437+U-W06BV9.bin",
     "00f96017514514c9cab4599229fb2a6db133e60c36a962e70f3d3bbd2865b933", "v7"),
    ("v16", "362001067524+U-W06BV16.bin",
     "8644e2e7d6f2b68dec8f79ac88bc4ea1e92f7bd2f41c5caf4f07627bf8230ebf", "v16"),
    ("v30", "362001067524+U-W06BV30.bin",
     "5592577b21f2769fafe54c0a01d5c264a1b9402f8e4c8286931ba7311efec1cc", None),
)
PROFILES += tuple(
    profile
    for version, hid, sha256, old_build in BV_BUILDS
    for profile in (
        Profile(id=f"sim-w06bv-{version}", mids=("60",), hid=hid, source_sha256=sha256,
                initial_state={}, handler=GatewayFamily(
                    five_field_children=old_build is not None,
                    known_fields=V7_FIELDS if version == "v9" else KNOWN_FIELDS,
                    low_byte_key=True, old_build=old_build,
                    empty_status_hid=version == "v16", clock_echo=version != "v30"),
                max_children=100, max_request_bytes=1024),
        Profile(id=f"sim-w06bv-{version}-ac", mids=CHILD_MIDS, hid=hid, source_sha256=sha256,
                initial_state=INITIAL_STATE, handler=RawChild(old_build=old_build),
                identity_bytes=7, parent_profiles=(f"sim-w06bv-{version}",)),
        Profile(id=f"sim-w06bv-{version}-fan",
                mids=("6079", "6099", "608d", "6091") if old_build else ("6079",),
                hid=hid, source_sha256=sha256,
                initial_state={"Pow": 0, "FanMod": 0, "WdSpd": 0},
                handler=RawChild(alternate=True, old_build=old_build),
                identity_bytes=7, parent_profiles=(f"sim-w06bv-{version}",)),
    )
)
PROFILES += (
    Profile(id="sim-w06bv-v16-water", mids=("6036", "6035"),
            hid="362001067524+U-W06BV16.bin",
            source_sha256="8644e2e7d6f2b68dec8f79ac88bc4ea1e92f7bd2f41c5caf4f07627bf8230ebf",
            initial_state=INITIAL_STATE, handler=RawChild(old_build="v16"),
            identity_bytes=7, parent_profiles=("sim-w06bv-v16",)),
)
