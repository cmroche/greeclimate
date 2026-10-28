"""W04N/JD raw callbacks and LAN framing; appliance physics is synthetic."""

import json
from datetime import datetime
from math import floor
from time import monotonic

from ..wire import InvalidPacket, Reply, decode_pack
from . import Profile, simulated

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
HID = "362001064973+U-W04NV17.bin"
SOURCE_SHA256 = "b0b7f5d428858ca5e5ad29a8afcfaa0da4063fe36e98fae7c447047163112727"

# Getter byte, shift, mask. These are N callbacks, not the shared AC union.
# V19's extended cache moves by fifteen bytes; these private logical indices
# preserve the equivalent field couplings without copying firmware RAM layouts.
_FIELDS = {
    "ACStupPos": (0x0b, 4, 15), "Add0.5": (0x2b, 3, 1),
    "Air": (0x28, 4, 3), "AirQ": None, "Antifreeze": (0x3c, 5, 1),
    "AssHt": None, "AutoClean": (0x28, 2, 1), "Blo": (0x27, 3, 1),
    "CoolNoise": (0x0f, 0, 255), "Defrost": (0x3c, 6, 1),
    "Dfltr": (0x46, 5, 1), "Dmod": (0x30, 0, 15),
    "DnPLLRSwing": (0x4d, 4, 15), "DnPRLRSwing": (0x4d, 0, 15),
    "DnPUDSwing": (0x4c, 0, 15), "DsplySt": (0x2a, 4, 3),
    "DwatFul": (0x2c, 1, 1), "Dwet": None, "Emod": (0x34, 4, 7),
    **{f"EnvArea{i + 1}St": (0x45, i, 1) for i in range(8)},
    "EnvArea9St": (0x44, 0, 1), "FavorMode": (0x3e, 3, 1),
    "FbidBloPer": (0x44, 1, 1), "HandCtl": (0x4b, 1, 31),
    "Health": (0x27, 2, 1), "HeatCoolType": (0x18f, 1, 1),
    "HeatNoise": (0x10, 0, 255), "HumSen": (0x182, 0, 255),
    "ImageRecovery": None, "ImgUpdateCol": None, "ImgUpdateSta": (0x2f, 7, 1),
    "ImgUpdateRes": (0x38, 6, 1), "ImgVerSta": (0x23, 4, 1),
    "Lig": (0x27, 1, 1), "MicroSen": (0x23, 2, 1), "Mod": (0x25, 4, 7),
    "NobodySave": (0x181, 7, 1), "NoiseSet": (0x04, 0, 1), "PM2P5": None,
    "PMVComfort": (0x3c, 7, 1), "Pow": (0x25, 7, 1), "Purify": None,
    "Quiet": (0x31, 2, 3), "ReplaceHEPA": (0x3a, 6, 1),
    "RoomHigh": (0x0e, 0, 255), "RoomLen": (0x0c, 0, 255),
    "RoomWid": (0x0d, 0, 255), "SaveGuid": (0x11, 0, 1),
    "Security": (0x40, 4, 1), "SecurityMode": (0x40, 3, 1), "SetTem": None,
    **{f"Slp1{half}{i}": None for half in ("H", "L") for i in range(1, 9)},
    "SlpMod": None, "SmartWind": (0x38, 5, 7), "StHt": (0x2c, 6, 1),
    "SvSt": (0x2c, 6, 1), "SwhSlp": None, "SwhSw": (0x29, 4, 15),
    "SwhWifi": (0x28, 1, 1), "SwhWifiRes": (0x28, 0, 1),
    "SwingLfRig": None, "SwUpDn": (0x29, 4, 15), "TemRec": (0x28, 6, 1),
    "TemSen": None, "TemUn": (0x28, 7, 1), "Tur": (0x27, 0, 1),
    "UDFanPort": (0x38, 2, 3), "UnmanedOffTime": (0x3a, 3, 3),
    "UnmanedShutDown": (0x3a, 5, 1), "VocCtl": (0x2b, 0, 1),
    "VocIdiom": None, "VocRole": (0x31, 5, 3), "VocUpdateCol": None,
    "VocUpdateSta": (0x44, 2, 1), "VocUpdateRes": (0x38, 5, 1),
    "VocVerSta": (0x23, 3, 1), "WdSpd": (0x33, 0, 7), "Wet": (0x2b, 4, 7),
    "AllErr": (0x46, 6, 1), "ElcAllKwhClr": (0x28, 3, 1), "ElcEn": None,
    "CZLJC": (0x47, 7, 1), "NewTimer": None, "NewTimerSet": None,
    "Buzzer_ON_OFF": (0x49, 0, 1), "AntiDirectBlow": (0x49, 7, 1),
    "SmartSlpMod": (0x33, 4, 7), "SmartSlpModEx": (0x147, 0, 255),
    **{f"StSlp{i}{mode}{suffix}": None for i in range(1, 5)
       for mode in ("C", "H") for suffix in ("", "Inc", "Sp")},
    "LigSen": (0x33, 3, 1),
}
_BOOL_WRITES = {
    "Add0.5": (0x2b, 3), "Antifreeze": (0x46, 6), "AutoClean": (0x28, 2),
    "Blo": (0x27, 3), "Defrost": (0x43, 0), "Dfltr": (0x46, 4),
    "DwatFul": (0x2c, 1),
    **{f"EnvArea{i + 1}St": (0x45, i) for i in range(8)},
    "EnvArea9St": (0x44, 0), "FavorMode": (0x3e, 3), "FbidBloPer": (0x44, 1),
    "Health": (0x27, 2), "ImageRecovery": (0x48, 0), "ImgUpdateCol": (0x4b, 6),
    "Lig": (0x27, 1), "MicroSen": (0x2f, 7), "NobodySave": (0x38, 0),
    "NoiseSet": (0x04, 0), "PMVComfort": (0x42, 0), "Pow": (0x25, 7),
    "ReplaceHEPA": (0x3a, 6), "SaveGuid": (0x11, 0), "Security": (0x40, 4),
    "SecurityMode": (0x40, 3), "SvSt": (0x2c, 6), "SwhWifi": (0x28, 1),
    "SwhWifiRes": (0x28, 0), "TemRec": (0x28, 6), "TemUn": (0x28, 7),
    "Tur": (0x27, 0), "UnmanedShutDown": (0x3a, 5), "VocCtl": (0x2b, 0),
    "VocUpdateCol": (0x4b, 7), "LigSen": (0x33, 3),
}
# Byte, preserved bits, shift, input mask. Unmasked writes can affect neighbors.
_RAW_WRITES = {
    "ACStupPos": (0x0b, 0x0f, 4, 255), "Air": (0x28, 0xcf, 4, 3),
    "DnPUDSwing": (0x4c, 0xf0, 0, 15), "HandCtl": (0x4b, 0xc1, 1, 255),
    "SetTem": (0x26, 0x0f, 4, 255), "StHt": (0x2c, 0xbf, 6, 1),
    "SwUpDn": (0x29, 0x0f, 4, 255), "VocIdiom": (0x3c, 0x87, 3, 255),
    "Wet": (0x2b, 0x8f, 4, 7), "ElcAllKwhClr": (0x28, 0xf7, 3, 1),
    "CZLJC": (0x49, 0x7f, 7, 255), "Buzzer_ON_OFF": (0x49, 0xfe, 0, 1),
    "AntiDirectBlow": (0x49, 0x7f, 7, 255), "SmartSlpMod": (0x33, 0x8f, 4, 7),
}
_BYTE_WRITES = {name: spec[0] for name, spec in _FIELDS.items()
                if spec is not None and spec[2] == 255 and name != "HumSen"}
_ENUM_WRITES = {
    "Mod": (0x25, 4, 7, 4), "Dmod": (0x30, 0, 15, 7),
    "Emod": (0x34, 4, 7, 5), "Quiet": (0x31, 2, 3, 2),
    "SmartWind": (0x38, 5, 7, 5), "UDFanPort": (0x38, 2, 3, 3),
    "UnmanedOffTime": (0x3a, 3, 3, 3), "VocRole": (0x31, 5, 3, 3),
}
_NOOP_WRITES = frozenset((
    "AirQ", "HeatCoolType", "HumSen", "ImgUpdateSta", "ImgUpdateRes", "ImgVerSta",
    "PM2P5", "Purify", "VocUpdateSta", "VocUpdateRes", "VocVerSta", "AllErr",
    "ElcEn", "NewTimer",
))
INITIAL_STATE = {name: 0 for name in _FIELDS}
INITIAL_STATE.update({f"Slp1L{i}": 160 for i in range(1, 9)})
INITIAL_STATE.update(SetTem=24, Lig=1, AssHt=1)


def _put(cache, offset, preserve, value):
    cache[offset] = ((cache[offset] & preserve) | value) & 255


def _set(cache, name, value):
    value &= 0xffffffff
    if name in _BOOL_WRITES:
        if value in (0, 1):
            offset, bit = _BOOL_WRITES[name]
            preserve = 254 if name == "EnvArea4St" and value else 255 ^ (1 << bit)
            _put(cache, offset, preserve, value << bit)
    elif name in _RAW_WRITES:
        offset, preserve, shift, mask = _RAW_WRITES[name]
        _put(cache, offset, preserve, (value & mask) << shift)
    elif name in _BYTE_WRITES:
        cache[_BYTE_WRITES[name]] = value & 255
    elif name in _ENUM_WRITES:
        offset, shift, mask, maximum = _ENUM_WRITES[name]
        if value <= maximum:
            _put(cache, offset, 255 ^ (mask << shift), value << shift)
            if name == "Mod" and value != 1:
                cache[0x2c] &= 0xbf
    elif name in _NOOP_WRITES:
        return
    elif name in ("DnPLLRSwing", "DnPRLRSwing", "SwingLfRig"):
        if value <= 6 or (name == "SwingLfRig" and value in (7, 8)) or (
                name != "SwingLfRig" and value in (12, 13)):
            if name == "SwingLfRig":
                value = {7: 12, 8: 13}.get(value, value)
            offset, shift = (0x29, 0) if name == "SwingLfRig" else (
                0x4d, 4 if name == "DnPLLRSwing" else 0)
            _put(cache, offset, 255 ^ (15 << shift), value << shift)
    elif name == "DsplySt":
        _put(cache, 0x2a, 0xcf, (value if value in (0, 2, 3) else 1) << 4)
    elif name == "Dwet":
        if value <= 14:
            _put(cache, 0x34, 0xf0, value + 1)
    elif name == "AssHt":
        if value <= 2:
            _put(cache, 0x27, 0xf7, 8 if value == 0 else 0)
            _put(cache, 0x2c, 0x7f, 128 if value == 2 else 0)
    elif name == "WdSpd":
        signed = value if value < 0x80000000 else value - 0x100000000
        coarse = 0 if value == 0 else 1 if value in (1, 2) else 2 if value in (3, 4) else 3
        if signed >= 0:
            _put(cache, 0x25, 0xfc, coarse)
        _put(cache, 0x33, 0xf8, value & 255)
    elif name == "SlpMod":
        if value <= 4:
            _put(cache, 0x25, 0xf7, 8 if value in (1, 3, 4) else 0)
            _put(cache, 0x31, 0x6f, (0, 0, 16, 16, 128)[value])
    elif name == "SwhSlp":
        if value in (0, 1):
            _put(cache, 0x25, 0xf7, value << 3)
            if value == 0:
                cache[0x31] &= 0xef
    elif name == "SwhSw":
        if value in (0, 1):
            _put(cache, 0x29, 0x0f, value << 4)
    elif name == "TemSen":
        signed = value if value < 0x80000000 else value - 0x100000000
        cache[0x180] = (min(signed, 50) + 40) & 255
    elif name == "NewTimerSet":
        cache[0x1ef] = value & 255  # Explicit synthetic platform context byte +0x6f.
        _put(cache, 0x49, 0xfd, (value & 1) << 1)
    elif name.startswith("StSlp"):
        start = 0x148 + (int(name[5]) - 1) * 7
        heat = name[6] == "H"
        suffix = name[7:]
        if suffix:
            cache[start + (4 if heat else 3) + (2 if suffix == "Sp" else 0)] = value & 255
        elif heat:
            cache[start + 2] = value & 255
            _put(cache, start + 1, 15, (value >> 8) << 4)
        else:
            cache[start] = (value >> 4) & 255
            _put(cache, start + 1, 240, value & 15)
    elif name.startswith("Slp1"):
        index = int(name[5]) - 1
        offset = 0x4f + index * 2
        cache[offset + (name[4] == "H")] = value & 255
        cache[0x170 + index * 2 + (name[4] == "H")] = value & 255
        if name[4] == "H":
            temperature = (cache[offset] + ((value & 255) << 8)) // 10 - 16
            target = (0x32, 0x35, 0x36, 0x37)[index // 2]
            if index % 2:
                _put(cache, target, 240, temperature)
            else:
                _put(cache, target, 15, temperature << 4)


def _get(cache, name, mid, platform_class=0, version=17):
    if name == "SetTem":
        return (cache[0x26] >> 4) + 16
    if name == "TemSen":
        raw = cache[0x180]
        if raw < 40:
            return 0
        return min(90, raw) if version != 17 and platform_class == 9 else min(50, raw - 40)
    if name == "AssHt":
        if (cache[0x25] >> 4) & 7 == 1:
            return 0
        return 2 if cache[0x2c] & 128 and platform_class in (0, 9) else int(not cache[0x27] & 8)
    if name == "Blo" and (cache[0x25] >> 4) & 7 == 4:
        return 0
    if name == "Dwet":
        return max(0, (cache[0x34] & 15) - 1)
    if name == "HeatCoolType" and version == 19:
        return 0
    if name == "WdSpd" and mid == "13000":
        return (0, 1, 3, 5)[cache[0x25] & 3]
    if name == "SwingLfRig":
        raw = cache[0x29] & 15
        return {12: 7, 13: 8}.get(raw, raw)
    if name == "SlpMod":
        sleep, mode = bool(cache[0x25] & 8), cache[0x31]
        if mode & 16:
            return 0 if mode & 128 else 3 if sleep else 2
        return (4 if mode & 128 else 1) if sleep else 0
    if name == "SwhSlp":
        return int(bool(cache[0x25] & 8 or cache[0x31] & 0x90))
    if name.startswith("Slp1"):
        index = int(name[5]) - 1
        raw = cache[(0x32, 0x35, 0x36, 0x37)[index // 2]]
        step = (raw & 15) if index % 2 else min(14, raw >> 4)
        temperature = step * 10 + 160
        return temperature >> 8 if name[4] == "H" else temperature & 255
    if name.startswith("StSlp"):
        start = 0x148 + (int(name[5]) - 1) * 7
        heat, suffix = name[6] == "H", name[7:]
        if suffix:
            return cache[start + (4 if heat else 3) + (2 if suffix == "Sp" else 0)]
        if heat:
            return cache[start + 2] | (cache[start + 1] >> 4) << 8
        return cache[start] << 4 | cache[start + 1] & 15
    spec = _FIELDS[name]
    if spec is None:
        return 0
    offset, shift, mask = spec
    return (cache[offset] >> shift) & mask


def _refresh(state, mid, version=17):
    cache = state["_cache"]
    state.update((name, _get(cache, name, mid, state.get("_platform_class", 0), version))
                 for name in _FIELDS)


def _integer(value):
    return int(max(-(1 << 31), min((1 << 31) - 1, value)))


class _LockNumber(int):
    def __new__(cls, value, lock):
        number = super().__new__(cls, value)
        number.lock = lock
        return number


def _source_number(token):
    # The native reader consumes only the leading decimal integer and saturates it.
    value = _integer(int(token.split(".", 1)[0].split("e", 1)[0].split("E", 1)[0]))
    # lock reads the raw token's last byte, independently of numeric conversion.
    if (token[-1] == "0") != (value % 10 == 0):
        return _LockNumber(value, int(token[-1] != "0"))
    return value


def _reply(outer, inner, key):
    envelope = {"t": "pack", "i": outer["i"],
                "uid": _integer(outer.get("uid", 0)) & 0xffffffff,
                "cid": outer.get("tcid", ""), "tcid": outer.get("cid", "")}
    plain_size = len(json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode())
    cipher_size = 16 * (plain_size // 16 + 1)
    envelope_size = len(json.dumps({**envelope, "pack": ""}, ensure_ascii=False,
                                   separators=(",", ":")).encode())
    if envelope_size + 4 * ((cipher_size + 2) // 3) >= 0x7b4:
        raise InvalidPacket("W04N reply exceeds the firmware buffer")
    return Reply(envelope, inner, key, CODEC)


def _columns(inner):
    names = inner.get("cols", inner.get("opt"))
    if (not isinstance(names, list) or len(names) > 64
            or any(not isinstance(name, str) or "\0" in name for name in names)
            or sum(len(name.encode("utf-8")) + 1 for name in names) > 512):
        raise InvalidPacket("invalid W04N column array")
    return names


_METADATA_NAMES = frozenset((
    "time", "name", "lock", "AutoUpdate", "host", "hid", "mid", "bc",
    "DevID", "MafIdf", "AppTimer", "MidType", "rssi", "ReportClientID", "ver", "vender",
))
_METADATA_WRITES = frozenset(("name", "host", "lock", "AutoUpdate", "time", "ReportClientID"))


def _metadata(device, state=None):
    state = device.state if state is None else state
    return {
        "name": state.get("_name", device.name), "host": state.get("_host", ""),
        "lock": state.get("_lock", 0), "AutoUpdate": state.get("_auto_update", 0),
        "time": state.get("_time", "2000-01-01 00:00:00"),
        "hid": device.profile.hid, "mid": device.mid, "bc": "3030303030", "DevID": "",
        "MafIdf": 0, "MidType": "", "ver": "V3.0.0", "vender": "",
        "AppTimer": 0, "rssi": -50,
    }


def _prepare_command(device, names, values):
    if (not isinstance(values, list) or len(values) > 64
            or any(not isinstance(value, str) and type(value) not in (int, _LockNumber) for value in values)):
        raise InvalidPacket("invalid W04N scalar p array")
    local = [name for name in names if name in _METADATA_NAMES]
    numeric = [name for name in names if name not in _METADATA_NAMES]
    if any(name not in _FIELDS or name == "AllErr" for name in numeric) or any(
            name not in _METADATA_WRITES for name in local):
        raise InvalidPacket("unsupported or read-only W04N command property")
    if (len(values) < len(numeric) or (not local and len(values) != len(numeric))
            or any(type(value) not in (int, _LockNumber) for value in values[:len(numeric)])):
        raise InvalidPacket("invalid W04N raw command values")
    numeric_values = [_integer(value) for value in values[:len(numeric)]]
    cache = bytearray(device.state["_cache"])
    changes = {}
    for name in local:
        if not values:
            raise InvalidPacket("W04N metadata requires p")
        value = values[0]
        if name in ("name", "host", "ReportClientID", "time"):
            if not isinstance(value, str) or "\0" in value:
                raise InvalidPacket("W04N metadata requires a string")
            if name == "time":
                if len(value) == 18:
                    value = value[:10] + " " + value[10:]
                try:
                    if datetime.strptime(value, "%Y-%m-%d %H:%M:%S").strftime(
                            "%Y-%m-%d %H:%M:%S") != value:
                        raise ValueError("noncanonical time")
                except ValueError as error:
                    raise InvalidPacket("invalid W04N synthetic clock value") from error
            elif len(value.encode("utf-8")) > (127 if name == "ReportClientID" else 31):
                raise InvalidPacket("W04N metadata string exceeds its bounded buffer")
        elif type(value) not in (int, _LockNumber):
            raise InvalidPacket("W04N metadata requires an integer")
        elif type(value) is _LockNumber:
            value = int(value)
        if name == "lock":
            # The original getter scans the final token before the p array's ']'.
            last = values[-1]
            value = last.lock if type(last) is _LockNumber else int(str(last)[-1] != "0")
        elif name == "AutoUpdate":
            value = _integer(value) & 255
        changes[{"AutoUpdate": "_auto_update", "ReportClientID": "_report_client_id"}.get(
            name, "_" + name)] = value
    return cache, changes, local, numeric, numeric_values


class W04N:
    version = 17

    def validate_state(self, state):
        for name, value in state.items():
            if name == "_platform_class":
                if type(value) is not int or not 0 <= value < (1 << 32):
                    raise ValueError("invalid W04N source platform class")
                continue
            if name not in _FIELDS or type(value) is not int or not -(1 << 31) <= value < (1 << 32):
                raise ValueError(f"invalid W04N raw state field {name!r}")
            if name in _NOOP_WRITES and value != INITIAL_STATE[name]:
                raise ValueError(f"W04N state field {name!r} is read-only")
        cache = bytearray(512)
        _set(cache, "SetTem", 24)
        _set(cache, "Lig", 1)
        for name, value in state.items():
            if name in _FIELDS and value != INITIAL_STATE[name]:
                _set(cache, name, value)
        state["_cache"] = cache
        _refresh(state, "", self.version)

    def thermal_target(self, device):
        return simulated.thermal_target(device)

    def encode_room(self, device):
        if "_cache" not in device.state:
            self.validate_state(device.state)
        _set(device.state["_cache"], "TemSen", max(0, min(50, floor(device.room_c))))
        _refresh(device.state, device.mid, self.version)

    def advertise(self, device, outer):
        if outer.get("t") != "scan":
            return []
        inner = {
            "t": "dev", "cid": device.mac, "bc": "00000", "brand": "",
            "catalog": "", "mac": device.mac, "mid": device.mid, "model": "",
            "name": device.state.get("_name", device.name),
            "lock": device.state.get("_lock", 0), "series": "", "vender": "",
            "ver": "V3.0.0",
        }
        if self.version == 19:
            inner["cid"] = ""
        else:
            inner["hid"] = device.profile.hid
        return [_reply({"i": 1, "uid": 0, "cid": "", "tcid": ""}, inner, GENERIC_KEY)]

    def handle(self, device, outer):
        if (outer.get("t") != "pack" or outer.get("tcid") != device.mac
                or type(outer.get("i")) is not int or outer["i"] not in (0, 1)
                or not isinstance(outer.get("cid", ""), str)
                or type(outer.get("uid", 0)) is not int):
            raise InvalidPacket("invalid W04N target or envelope")
        key = GENERIC_KEY if outer["i"] == 1 else device.key
        inner = decode_pack(outer, key, CODEC, number_parser=_source_number,
                            strip_ascii_spaces=True)
        for selector in ("mac", "sub"):
            if selector in inner and inner[selector] != device.mac:
                raise InvalidPacket("conflicting W04N inner identity")
        operation = inner.get("t")
        if operation == "bind":
            reply = {"r": 200, "t": "bindok", "mac": device.mac,
                     "key": device.key.decode("ascii")}
        elif operation == "status":
            names = _columns(inner)
            changes = {}
            if "cols" not in inner:
                _, changes, _, _, _ = _prepare_command(device, names, inner.get("p"))
            self.encode_room(device)
            values = {**device.state, **_metadata(device, {**device.state, **changes})}
            cols = [name for name in names if (name in values and not name.startswith("_"))
                    or name == "MOta"]
            # MOta succeeds without a serialization call in the original local getter.
            reply = _reply(outer, {
                "t": "dat", "uid": _integer(outer.get("uid", 0)) & 0xffffffff,
                "mac": device.mac, "cid": device.mac,
                "dat": [values[name] for name in cols if name != "MOta"],
                "cols": cols, "r": 200,
            }, key)
            device.state.update(changes)
            return [reply]
        elif operation == "cmd":
            names, values = inner.get("opt"), inner.get("p")
            names = _columns({"cols": names})
            if "cols" in inner:
                raise InvalidPacket("ambiguous W04N command columns")
            if any(name in ("dwTsk", "dwRpt") for name in names):
                if (not isinstance(values, list) or len(values) != len(names)
                        or any(type(value) not in (int, _LockNumber) for value in values)):
                    raise InvalidPacket("invalid W04N scheduler values")
                requested = {name: _integer(value) for name, value in zip(names, values)}
                ordered = [name for name in ("dwTsk", "dwRpt") if name in requested]
                selected = [requested[name] for name in ordered]
                reply = _reply(outer, {"t": "res", "mac": device.mac, "opt": ordered,
                                       "p": selected, "val": selected, "r": 200}, key)
                device.state.update(("_" + name, requested[name] & 0xffffffff) for name in ordered)
                return [reply]
            cache, changes, local, numeric, numeric_values = _prepare_command(device, names, values)
            # Native numeric lookup is by name: the first duplicate wins.
            requested = {}
            for name, value in zip(numeric, numeric_values):
                requested.setdefault(name, value)
            for name, value in requested.items():
                _set(cache, name, value)
            metadata = _metadata(device, {**device.state, **changes})
            local = [name for name in local if name != "ReportClientID"]
            ack_values = [metadata[name] for name in local]
            ack_values.extend(numeric_values)
            val_values = ack_values
            if len(requested) != len(numeric):
                val_values = ack_values[:len(local)]
                val_values.extend(requested[name] for name in numeric)
            # Metadata precedes numeric controls; val uses the named request, not the getter.
            reply = _reply(outer, {"t": "res", "mac": device.mac,
                                   "val": val_values, "p": ack_values,
                                   "opt": local + numeric, "r": 200}, key)
            device.advance(monotonic())
            cache[0x180] = device.state["_cache"][0x180]
            device.state["_cache"] = cache
            device.state.update(changes)
            _refresh(device.state, device.mid, self.version)
            return [reply]
        else:
            return []
        return [_reply(outer, reply, key)]


class W04NV19(W04N):
    version = 19


class JDV12(W04N):
    version = 12


_MIDS = (
    "10001", "10002", "10014", "10015", "10016", "10017", "11000", "11001",
    "11002", "11010", "11f00", "11f01", "11f02", "11f03", "13000",
)
PROFILES = (
    Profile("sim-w04n-v17", _MIDS, HID, SOURCE_SHA256, INITIAL_STATE, W04N()),
    Profile("sim-w04n-v19", _MIDS[:-1], "362001064973+U-W04NV19.bin",
            "0b01a0d0fd25651b81bf435e46428987a3b43b905b2ee6bdc0714c6030452d92",
            INITIAL_STATE, W04NV19()),
    Profile("sim-w04n-jd-v12", _MIDS, "362001064270+U-BL3332_JDNEWV12.bin",
            "c83eb36cb6c285a30611cd44b6d2f9394bfdd2be6333e4a886ecf00ac2ebb256",
            INITIAL_STATE, JDV12()),
)
