"""Exact W06DV LAN framing, raw caches and explicitly synthetic readouts."""

from datetime import datetime, timedelta
import re
from time import monotonic

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from ..wire import InvalidPacket, decode_pack
from . import Profile, simulated
from .gateway import CODEC, GENERIC_KEY, _reply

HID = "362001067592+U-W06DV4.01.bin"
SOURCE_SHA256 = "eabd04d49c518699f2800805bd4f6085ff3b2092b8a2394fb1e22c04fb7f7c9f"
# Synthetic internal thermal controls; raw wire caches are not calibrated temperatures.
CONTROL_FIELDS = frozenset((
    "Pow", "Blo", "SwhSlp", "Air", "SvSt", "Quiet", "Tur", "Mod", "SetTem",
    "WdSpd", "SwUpDn", "SwingLfRig", "TemUn", "TemRec", "SlpMod",
))
INITIAL_STATE = {name: value for name, value in simulated.INITIAL_STATE.items()
                 if name in CONTROL_FIELDS}

# DV3.02 exposes raw cache bytes, not calibrated climate controls.
DV302_LIMITS = {
    **{name: 1 for name in ("Pow", "Blo", "SwhSlp", "Air", "SvSt", "Quiet", "Tur",
                           "HeatCoolType")},
    "Mod": 4, "WdSpd": 6,
    **{name: 2**31 - 1 for name in (
        "SetTem", "HeatSvStTemMax", "CoolSvStTemMin", "SwUpDn", "SwingLfRig",
        "AllErr", "TemUn", "TemRec", "SlpMod", "TemRecH", "TemRecC")},
}
DV302_NO_STORE = frozenset(("HeatCoolType", "AllErr"))
DV302_EMPTY_METADATA = frozenset("""
SwhWifi SwhWifiRes SwhWifiConf AutoConnCloud datDump datRep datFailRep datPeroid
subCnt useTCP country city cnty cityid lat lon
""".split())
DV302_INITIAL_STATE = {**{name: 0 for name in DV302_LIMITS}, **INITIAL_STATE}

# Both exact images dispatch this finite table before the scalar selector.
DV_RAW_READOUTS = frozenset("""
Lig Health SwhSw StHt LTemDry Wet HasTmr TmrLpTms TmrOff TmrOn CurTmHor
CurTmMin TmrOnHorLf TmrOnMinLf TmrOffHorLf TmrOffMinLf DsplySt EnvFun
JFErrorCode AssHt FrshAir Coolmod MasSub MasIDUMod GetEr HumiSvStTemMin
MaeS FanMod ModS VitiGr GasN TemSor HumSor PM2P5 VOC CO2 PctCle PctRe
IDUAirQu AirQu ODUViti GasAvail GasLED GasMod GasMas PM2P5Sta SorErr CommErr GasQ
""".split())


def _dv302_time(value):
    # Complete assignments replace native sscanf's unsafe partially initialized locals.
    match = re.match(
        r"\s*([0-9]{1,4}|[+-][0-9]{1,3})-\s*([0-9]{1,2}|[+-][0-9])-"
        r"\s*([0-9]{1,2}|[+-][0-9])\s*([0-9]{1,2}|[+-][0-9]):"
        r"\s*([0-9]{1,2}|[+-][0-9]):\s*([0-9]{1,2}|[+-][0-9])", value,
        flags=re.ASCII)
    if match is None:
        raise InvalidPacket("controller time requires six complete calendar integers")
    year, month, day, hour, minute, second = map(int, match.groups())
    month -= 2
    if month < 1:
        month += 12
        year -= 1
    # Source0xa04fdc calendar arithmetic, including uint32 epoch wrap.
    days = (day + int(month * 367 / 12) + int(year / 400)
            + int(year / 4) - int(year / 100) + year * 365 - 719499)
    epoch = (second + (minute + (days * 24 + hour) * 60) * 60) & 0xffffffff
    return (datetime(1970, 1, 1) + timedelta(seconds=epoch)).strftime("%Y-%m-%d %H:%M:%S")


def _fields(value, limit=49):
    if (not isinstance(value, list) or len(value) > limit
            or any(not isinstance(name, str) or not name or len(name.encode()) >= 16
                   for name in value)):
        raise InvalidPacket(f"controller requires at most{limit} fields shorter than16 bytes")
    return value


def _metadata(device, include_hid):
    return {"mac": device.mac, "mid": device.mid,
            **({"hid": device.profile.hid} if include_hid else {}), "name": device.name,
            "vender": "1", "ver": "V1.0.0.0", "bc": "", "host": "", "lock": 0}


class ControllerFamily:
    def __init__(self, *, include_hid=True, roomless=False, host_writable=False):
        self.include_hid = include_hid
        self.roomless = roomless
        self.host_writable = host_writable

    def validate_state(self, state):
        for name, value in state.items():
            if name not in DV302_LIMITS or type(value) is not int or not 0 <= value <= 255:
                raise ValueError(f"state field {name!r} must be a raw controller byte")

    def thermal_target(self, device):
        return None if self.roomless else simulated.thermal_target(device)

    def encode_room(self, device):
        # No ambient scalar selector exists; synthetic room temperature stays internal.
        pass

    def advertise(self, device, outer):
        inner = {"t": "dev", "cid": device.mac, "bc": "gree", "brand": "gree",
                 "catalog": "gree", "mac": device.mac, "mid": device.mid,
                 **({"hid": device.profile.hid} if self.include_hid else {}),
                 "model": "gree", "name": device.name, "series": "gree",
                 "vender": "1", "ver": "V1.0.0.0", "lock": 0}
        return [_reply(device, inner, 1, 0, "")]

    def handle(self, device, outer):
        if outer.get("tcid") != device.mac or len(outer) > 20:
            raise InvalidPacket("invalid controller target or envelope")
        index, uid, peer = outer.get("i"), outer.get("uid"), outer.get("cid")
        if type(index) is not int or not 0 <= index < 2**31:
            raise InvalidPacket("missing controller key selector")
        if type(uid) is not int or not -(2**31) <= uid < 2**31:
            raise InvalidPacket("missing controller uid")
        if not isinstance(peer, str) or len(peer.encode()) >= 20:
            raise InvalidPacket("missing controller cid")
        pack = outer.get("pack")
        if not isinstance(pack, str) or len(pack) >= 700:
            raise InvalidPacket("controller encrypted request exceeds firmware buffer")
        # Both DV images mask decrypt selection; control permission requires exact zero.
        selector = index & 0xff
        inner = decode_pack(outer, GENERIC_KEY if selector else device.key, CODEC)
        if len(inner) > 20:
            raise InvalidPacket("controller request has too many fields")
        for selector in ("mac", "sub"):
            if selector in inner and inner[selector] != device.mac:
                raise InvalidPacket("conflicting controller inner identity")
        kind = inner.get("t")
        if kind == "bind":
            if inner.get("mac") != device.mac:
                raise InvalidPacket("wrong controller bind identity")
            return [_reply(device, {"t": "bindok", "mac": device.mac,
                                    "key": device.key.decode("ascii"), "r": 200}, 1, uid, peer)]
        if kind not in ("status", "cmd"):
            return []
        if index:
            raise InvalidPacket("controller controls require the bound key")
        if kind == "status":
            if inner.get("mac") != device.mac:
                raise InvalidPacket("wrong controller status identity")
            columns = _fields(inner.get("cols"), 50)
            available = {
                **_metadata(device, True), **device.state, "AutoUpdate": 0,
                **{name: "" for name in (
                    "model", "series", "apssid", "appsw", "brand", "catalog")},
                # Source reads cache[-1] for these names. Never expose adjacent memory:
                # the bounded model supplies a frozen synthetic prefix byte, not a sensor.
                **{name: 0 for name in DV_RAW_READOUTS},
                "time": device.state.get("time", "1970-01-01 00:00:00"),
            }
            # Native count is only committed on a NUL slot; 50 filled slots report zero.
            selected = ([] if len(columns) == 50 else [
                name for name in columns
                if name in available or name in DV302_EMPTY_METADATA])
            reply = _reply(device, {
                "t": "dat", "r": 200, "mac": device.mac, "cols": selected,
                "dat": [available[name] for name in selected if name in available],
            }, 0, uid, peer)
            device.advance(monotonic())
            return [reply]
        names = _fields(inner.get("opt"), 50)
        values = inner.get("p")
        # Safe policy: no cJSON valueint coercion or partial mutation on failure.
        if not isinstance(values, list) or not names or len(names) != len(values):
            raise InvalidPacket("controller command requires matching opt and p")
        metadata = {}
        for name, value in zip(names, values):
            if name in ("host", "name", "time") and isinstance(value, str):
                limit = 90 if name == "name" else 20
                if not value or "\0" in value or len(value.encode()) > limit:
                    raise InvalidPacket("invalid controller metadata string")
                metadata[name] = _dv302_time(value) if name == "time" else value
            elif not (name in DV302_LIMITS and type(value) is int
                      and 0 <= value <= DV302_LIMITS[name]):
                raise InvalidPacket("controller command requires safe raw controls")
        # V4.01 validates host text but never copies it into the getter's cache.
        if "host" in metadata and not self.host_writable:
            metadata["host"] = device.state.get("host", "")
        response_names = [] if len(names) == 50 else names
        echoed = [metadata[name] if name in metadata else value
                  for name, value in zip(names, values)] if response_names else []
        reply = _reply(device, {"t": "res", "r": 200, "opt": response_names,
                                "p": echoed, "val": echoed}, 0, uid, peer)
        device.advance(monotonic())
        for name, value in zip(names, values):
            if name == "name":
                device.name = metadata[name]
            elif name in ("host", "time"):
                device.state[name] = metadata[name]
            elif name not in DV302_NO_STORE:
                device.state[name] = value & 255
        return [reply]


PROFILES = (
    Profile(id="sim-w06dv-v4.01", mids=("3018",), hid=HID, source_sha256=SOURCE_SHA256,
            initial_state=DV302_INITIAL_STATE, handler=ControllerFamily(), max_request_bytes=1024),
    Profile(id="sim-w06dv-v3.02", mids=("3018",),
            hid="362001067592+U-W06DV3.02.bin",
            source_sha256="0deb40c2057cdd348e98194ecf9bfae70dfdd190204d7235ef6376e0146ff25b",
            initial_state=DV302_INITIAL_STATE,
            handler=ControllerFamily(include_hid=False, roomless=True, host_writable=True),
            max_request_bytes=1024),
)


# Independently equivalent instruction-qualified callback tables, not MID aliases.
LEGACY_CONTROLLER_SOURCES = (
    "3b62bc10d437e5ed533f158b70b9ee7f80a729eb9060a97e286d01e8619e0f00",
    "b101a70528bf9519a6d887c64f87ebaf3597a9ea918258633b87ac6e4917d7d7",
)
LEGACY_CONTROLLER_HID = "362001000968+U-CS532BJ(MTK)V0.0.bin"
_LEGACY_BITS = {
    "ACStupPos": (11, 4, 4), "Add0.5": (33, 3, 1), "Air": (30, 4, 2),
    "AssHt": (29, 3, 1), "Blo": (29, 3, 1), "CoolNoise": (15, 0, 8),
    "DnPLLRSwing": (67, 4, 4), "DnPRLRSwing": (67, 0, 4),
    "DnPUDSwing": (66, 0, 4), "DsplySt": (32, 4, 2), "Emod": (42, 4, 3),
    **{f"EnvArea{n + 1}St": (59, n, 1) for n in range(8)},
    "EnvArea9St": (58, 0, 1), "FbidBloPer": (58, 1, 1),
    "Health": (29, 2, 1), "HeatNoise": (16, 0, 8), "Lig": (29, 1, 1),
    "Mod": (27, 4, 3), "NoiseSet": (4, 0, 1), "Pow": (27, 7, 1),
    "Quiet": (39, 2, 2), "RoomHigh": (14, 0, 8), "RoomLen": (12, 0, 8),
    "RoomWid": (13, 0, 8), "SaveGuid": (17, 0, 1), "SetTem": (28, 4, 4),
    "SvSt": (34, 6, 1), "SwhSlp": (27, 3, 1), "SwhWifi": (30, 1, 1),
    "SwhWifiRes": (30, 0, 1), "SwingLfRig": (31, 0, 4),
    "SwUpDn": (31, 4, 4), "TemRec": (30, 6, 1), "TemSen": (85, 0, 8),
    "TemUn": (30, 7, 1), "Tur": (29, 0, 1), "UDFanPort": (46, 2, 2),
    "WdSpd": (41, 0, 3), "Wet": (33, 4, 3),
}
_LEGACY_ZERO = frozenset(("Null", "AirQ", "HeatCoolType", "HumSen", "PM2P5",
                          "Purify", "StHt"))
_LEGACY_SLEEP_BYTES = (40, 40, 43, 43, 44, 44, 45, 45)
_LEGACY_SLEEP = {
    f"Slp1{part}{n + 1}": (n, part)
    for n in range(8) for part in ("L", "H")
}
LEGACY_CONTROLLER_FIELDS = frozenset(
    (*_LEGACY_BITS, *_LEGACY_ZERO, *_LEGACY_SLEEP, "SlpMod"))
LEGACY_CLOUD_COLUMNS = (
    "Lig", "AssHt", "SwhSlp", "SlpMod", "WdSpd", "SetTem", "TemSen", "Pow",
    "Blo", "Emod", "Mod", "Quiet", "SwingLfRig", "SwUpDn", "Tur",
)


class LegacyControllerCache:
    """Complete 70-callback raw bank and actual QCOM flat-cloud adapter.

    RAM starts at synthetic zero; byte offsets, aliases, no-op callbacks and
    stored-value replies are source semantics. No network session is invented.
    """

    def __init__(self, source_sha256, raw=None):
        if source_sha256 not in LEGACY_CONTROLLER_SOURCES:
            raise ValueError("an exact legacy controller source is required")
        if raw is not None and (type(raw) is not bytes or len(raw) != 87):
            raise ValueError("legacy controller cache requires exactly 87 bytes")
        self.source_sha256 = source_sha256
        self.raw = bytearray(87) if raw is None else bytearray(raw)

    def read(self, name):
        if name in _LEGACY_ZERO:
            return 0
        if name == "SlpMod":
            pattern = ((self.raw[27] >> 3 & 1), (self.raw[39] >> 4 & 1),
                       (self.raw[39] >> 7 & 1))
            return {(0, 0, 0): 0, (1, 0, 0): 1, (0, 1, 0): 2,
                    (1, 1, 0): 3, (1, 0, 1): 4}.get(pattern, 0)
        if name in _LEGACY_SLEEP:
            n, part = _LEGACY_SLEEP[name]
            encoded = self.raw[_LEGACY_SLEEP_BYTES[n]] >> (4 if n % 2 == 0 else 0) & 15
            value = min(encoded, 14) * 10 + 160
            return value & 255 if part == "L" else value >> 8
        field = _LEGACY_BITS.get(name)
        if field is None:
            return None
        offset, shift, width = field
        value = self.raw[offset] >> shift & ((1 << width) - 1)
        if name == "SetTem":
            return value + 16
        if name == "TemSen":
            return max(0, min(50, value - 40))
        if name == "AssHt":
            return int(not value) if self.read("Mod") != 1 else 0
        if name == "Blo":
            return value if self.read("Mod") != 4 else 0
        if name == "SwingLfRig":
            return {12: 7, 13: 8}.get(value, value)
        if name == "SwhSlp":
            return int(bool(value or self.raw[39] & 0x90))
        return value

    def _store(self, offset, shift, width, value):
        mask = ((1 << width) - 1) << shift
        self.raw[offset] = (self.raw[offset] & ~mask | value << shift & mask)

    def _write(self, name, value):
        if name in _LEGACY_ZERO:
            return
        if name in _LEGACY_SLEEP:
            n, part = _LEGACY_SLEEP[name]
            low = 69 + n * 2
            self.raw[low + (part == "H")] = value & 255
            if part == "H":
                packed = ((self.raw[low] | (value & 255) << 8) // 10) - 16
                offset = _LEGACY_SLEEP_BYTES[n]
                shift = 4 if n % 2 == 0 else 0
                mask = 15 << shift
                # Source OR deliberately does not mask packed before the byte store.
                self.raw[offset] = (self.raw[offset] & ~mask | packed << shift) & 255
            return
        if name == "SlpMod":
            if value in range(5):
                self._store(27, 3, 1, int(value in (1, 3, 4)))
                self.raw[39] = self.raw[39] & 0x6f | (0x10 if value in (2, 3) else
                                                    0x80 if value == 4 else 0)
            return
        offset, shift, width = _LEGACY_BITS[name]
        if name == "TemSen":
            self.raw[offset] = (min(value, 50) + 40) & 255
            return
        if name == "Mod":
            if value not in range(5):
                return
            self._store(offset, shift, width, value)
            if value != 1:
                self._store(34, 6, 1, 0)
            return
        if name == "WdSpd":
            if value in range(4):
                self._store(27, 0, 2, min(value, 2))
            elif value in range(4, 8):
                self._store(27, 0, 2, 3)
            self.raw[offset] = (self.raw[offset] & 0xf8 | value) & 255
            return
        if name in ("DnPLLRSwing", "DnPRLRSwing", "SwingLfRig"):
            value &= 255
            accepted = (*range(7), 7, 8) if name == "SwingLfRig" else (*range(7), 12, 13)
            if value not in accepted:
                return
            if name == "SwingLfRig":
                value = {7: 12, 8: 13}.get(value, value)
        elif name == "SetTem":
            value -= 16
        elif name == "DsplySt":
            value = value if value in range(4) else 1
        elif name == "Emod" and value not in range(6):
            return
        elif name == "UDFanPort" and value not in range(4):
            return
        elif name == "Quiet" and value not in range(3):
            return
        elif width == 1:
            if value not in (0, 1):
                return
            if name == "AssHt":
                value = 1 - value
            elif name == "EnvArea4St" and value:
                self.raw[offset] &= 0xfe  # Original setter also clears EnvArea1St.
        self._store(offset, shift, width, value)

    def dat(self, columns):
        columns = _fields(columns, 100)
        return {"t": "dat", "cols": columns.copy(),
                "dat": [self.read(name) for name in columns]}

    def command(self, names, values):
        names = _fields(names, 100)
        if (not names or not isinstance(values, list) or len(names) != len(values)
                or any(name not in LEGACY_CONTROLLER_FIELDS for name in names)
                or any(type(value) is not int or not -(1 << 31) <= value < 1 << 31
                       for value in values)):
            raise InvalidPacket("legacy controls require matching known names and int32 values")
        # Safe atomic validation; source callback mutation itself remains sequential.
        for name, value in zip(names, values):
            self._write(name, value)
        return {"t": "res", "opt": names.copy(),
                "val": [self.read(name) for name in names]}

    def cloud_report(self):
        if self.source_sha256 != LEGACY_CONTROLLER_SOURCES[1]:
            raise InvalidPacket("flat cloud reports belong only to the exact QCOM source")
        return {name: str(self.read(name)) for name in LEGACY_CLOUD_COLUMNS}

    def cloud_command(self, properties):
        if self.source_sha256 != LEGACY_CONTROLLER_SOURCES[1]:
            raise InvalidPacket("flat cloud commands belong only to the exact QCOM source")
        if not isinstance(properties, dict) or not properties:
            raise InvalidPacket("QCOM cloud command requires a flat property object")
        self.command(list(properties), list(properties.values()))
        return self.cloud_report()


def encode_mt2_frame(opcode, options=b"", *, payload=None, sequence=0, key=None, iv=None):
    """Exact JBL MT2 UDP frame primitive, with supplied session key/IV.

    This does not invent the enrollment/authentication exchange or admit JSON UDP.
    Source 0xa0e104 uses CBC, an encrypted big-endian sequence, and the checksum
    of plaintext plus encrypted length and all option bytes.
    """
    if (type(opcode) is not int or not 0 <= opcode <= 31 or type(options) is not bytes
            or len(options) > 255):
        raise InvalidPacket("invalid MT2 opcode or option bytes")
    if opcode == 1:
        if options or payload is not None:
            raise InvalidPacket("MT2 heartbeat has exactly three bytes")
        return b"\xaa\xbb\x01"
    checksum = sum(options)
    ciphertext = b""
    if payload is not None:
        if (type(payload) is not bytes or type(sequence) is not int or not 0 <= sequence <= 65535
                or type(key) is not bytes or len(key) != 16
                or type(iv) is not bytes or len(iv) != 16):
            raise InvalidPacket("MT2 payload requires bytes, uint16 sequence and 16-byte key/IV")
        plaintext = sequence.to_bytes(2, "big") + payload
        ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))
        checksum += sum(plaintext) + len(ciphertext) // 256 + len(ciphertext) % 256
    frame = (b"\xaa\xbb" + bytes((opcode, len(options), checksum & 255))
             + len(ciphertext).to_bytes(2, "big") + options + ciphertext)
    if len(frame) > 1024:
        raise InvalidPacket("MT2 frame exceeds original UDP receive capacity")
    return frame


def decode_mt2_frame(frame, *, key=None, iv=None):
    """Return (opcode, options, sequence, payload); strict bounds/padding are model policy."""
    if type(frame) is not bytes or not 3 <= len(frame) <= 1024 or frame[:2] != b"\xaa\xbb":
        raise InvalidPacket("invalid MT2 frame magic or size")
    opcode = frame[2] & 31
    if opcode == 1:
        if len(frame) != 3:
            raise InvalidPacket("MT2 heartbeat has exactly three bytes")
        return opcode, b"", None, None
    if len(frame) < 7:
        raise InvalidPacket("truncated MT2 header")
    option_length = frame[3]
    encrypted_length = int.from_bytes(frame[5:7], "big")
    if len(frame) != 7 + option_length + encrypted_length:
        raise InvalidPacket("MT2 lengths do not match datagram")
    options = frame[7:7 + option_length]
    checksum = sum(options)
    sequence = payload = None
    if encrypted_length:
        if (encrypted_length % 16 or type(key) is not bytes or len(key) != 16
                or type(iv) is not bytes or len(iv) != 16):
            raise InvalidPacket("invalid MT2 encrypted block/key/IV")
        try:
            plaintext = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(
                frame[7 + option_length:]), 16)
        except ValueError as error:
            raise InvalidPacket("invalid MT2 CBC padding") from error
        if len(plaintext) < 2:
            raise InvalidPacket("MT2 encrypted payload lacks sequence")
        checksum += sum(plaintext) + encrypted_length // 256 + encrypted_length % 256
        sequence, payload = int.from_bytes(plaintext[:2], "big"), plaintext[2:]
    if frame[4] != checksum & 255:
        raise InvalidPacket("MT2 plaintext checksum does not match")
    return opcode, options, sequence, payload
