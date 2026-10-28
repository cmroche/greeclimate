"""Exact W06A(P3)/W06AQ11 raw LAN tables with explicit synthetic mainboard state."""

import json
import time
from datetime import datetime
from math import floor

from ..wire import InvalidPacket, Reply, decode_pack
from . import Profile

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
HID = "362001066763+U-W06A(P3)V6.04.bin"
SOURCE_SHA256 = "37ab39b75436448b7153fbbd781a21c93b83f74a236354c93aafcf9b10ed039a"
INITIAL_STATE = {
    "Pow": 0, "TemUn": 0, "Mod": 1, "CoWatOutTemSet": 18,
    "HeWatOutTemSet": 35, "WatBoxTemSet": 50, "CoHomTemSet": 24, "HeHomTemSet": 24,
}
_SENSOR_PAIRS = {
    "9300": (("RmoHomTemHi", "RmoHomTemLo"),),
    "9301": (("WatBoxTemHi", "WatBoxTemLo"),),
    "9302": (("AllInWatTemHi", "AllInWatTemLo"),
             ("AllOutWatTemHi", "AllOutWatTemLo")),
}

# Exact 250-record table is byte-identical in all six sources; two append EVU.
_NETWORK_NAMES = frozenset((
    'SwhWifi', 'SwhWifiRes', 'SwhWifiConf', 'AutoUpdate', 'AutoConnCloud', 'lock',
    'datDump', 'datRep', 'datFailRep', 'datPeroid', 'subCnt', 'useTCP',
    'vender', 'bc', 'mid', 'model', 'series', 'apssid',
    'appsw', 'brand', 'catalog', 'country', 'hid', 'host',
    'mac', 'name', 'time', 'ver', 'city', 'cnty',
    'cityid', 'lat', 'lon', 'Pow', 'Mod', 'SetTem',
    'WdSpd', 'Tur', 'Quiet', 'SwUpDn', 'SwingLfRig', 'TemUn',
    'TemRec', 'Lig', 'Air', 'Blo', 'Health', 'SvSt',
    'SwhSw', 'HeatCoolType', 'StHt', 'LTemDry', 'Wet', 'SwhSlp',
    'SlpMod', 'HasTmr', 'TmrLpTms', 'TmrOff', 'TmrOn', 'CurTmHor',
    'CurTmMin', 'TmrOnHorLf', 'TmrOnMinLf', 'TmrOffHorLf', 'TmrOffMinLf', 'DsplySt',
    'EnvFun', 'JFErrorCode', 'AssHt', 'FrshAir', 'AllErr', 'Coolmod',
    'MasSub', 'MasIDUMod', 'GetEr', 'CoolSvStTemMin', 'HeatSvStTemMax', 'HumiSvStTemMin',
    'MaeS', 'FanMod', 'ModS', 'VitiGr', 'GasN', 'TemSor',
    'HumSor', 'PM2P5', 'VOC', 'CO2', 'PctCle', 'PctRe',
    'IDUAirQu', 'AirQu', 'ODUViti', 'GasAvail', 'GasLED', 'GasMod',
    'GasMas', 'PM2P5Sta', 'SorErr', 'CommErr', 'GasQ', 'TemRecH',
    'TemRecC', 'FastHtWter', 'ColHtWter', 'HetHtWter', 'TemRecB', 'LefHom',
    'SwDisFct', 'DisFctWD', 'DisFctStaHr', 'DisFctStaMin', 'SwTmr1', 'SwTmr2',
    'SwTmr3', 'SwTmr4', 'SwTmr5', 'ModTmr1', 'ModTmr2', 'ModTmr3',
    'ModTmr4', ' ModTmr5', 'Tmr1StaHr', 'Tmr1StaMin', 'Tmr1EndHr', 'Tmr1EndMin',
    'Tmr2StaHr', 'Tmr2StaMin', 'Tmr2EndHr', 'Tmr2EndMin', 'Tmr3StaHr', 'Tmr3StaMin',
    'Tmr3EndHr', 'Tmr3EndMin', 'Tmr4StaHr', 'Tmr4StaMin', 'Tmr4EndHr', 'Tmr4EndMin',
    'Tmr5StaHr', 'Tmr5StaMin', 'Tmr5EndHr', 'Tmr5EndMin', 'Tmr1Tem', 'Tmr2Tem',
    'Tmr3Tem', 'Tmr4Tem', 'Tmr5Tem', 'CoWatOutTemSet', 'HeWatOutTemSet', 'CoHomTemSet',
    'HeHomTemSet', 'WatBoxTemSet', 'HeSvsEvoTemMin', 'HeSvsEvoTemMax', 'HeSvsHomTemMax',
    'HeSvsWatOutTemMax', 'HeSvsWatOutTemMin', 'CoSvsEvoTemMin', 'CoSvsEvoTemMax', 'CoSvsHomTemMax',
    'CoSvsWatOutTemMax', 'CoSvsWatOutTemMin', 'Reset', 'HeWatOutTemSetFloor', 'FactoryTest', 'EvoTemHi',
    'EvoTemLo', 'SckTemHi', 'SckTemLo', 'PuGsTemHi', 'PuGsTemLo', 'AnFroTemHi',
    'AnFroTemLo', 'EcoPutInTemHi', 'EcoPutInTemLo', 'EcoPutOutTemHi', 'EcoPutOutTemLo',
    'AllInWatTemHi', 'AllInWatTemLo', 'AllOutWatTemHi', 'AllOutWatTemLo', 'HepOutWatTemHi',
    'HepOutWatTemLo', 'LiqPipTemHi', 'LiqPipTemLo', 'GasPipTemHi', 'GasPipTemLo',
    'WatBoxTemHi', 'WatBoxTemLo', 'RmoHomTemHi', 'RmoHomTemLo', 'OutGasPreHi', 'OutGasPreLo',
    'HomTemCtrHi', 'HomTemCtrLo', 'FloTarTemHi', 'FloTarTemLo', 'FloTexTimHi', 'FloTexTimLo',
    'EndTemCtrMod', 'CmpRunSta', 'Win1RunSta', 'Win2RunSta', 'WatPmpRunSta', 'Elc3Val1RunSta',
    'Elc3Val2RunSta', 'CmperElcHeRunSta', 'CmpBoxElcHeRunSta', 'FlorElcHeRunSta', 'SyAnFroRunSta',
    'SyRecOlRunSta', 'HepHeSorRunSta', 'Elc2ValRunSta', 'AssCtrRunSta', 'Elc4ValRunSta',
    'ElcHe1RunSta', 'ElcHe2RunSta', 'AnFrzzRunSta', 'WatBoxExt', 'BordTest', 'RomHomTemExt',
    'FocModSwh', 'ColColetSwh', 'EndTemCotSwh', 'Emegcy', 'HanFroSwh', 'WatSyExhSwh',
    'WatBoxElcHeRunSta', 'VersatiSeries', 'EnvironmentTem', 'AirInTem', 'AirOutTem', 'DefrostTem',
    'AllInWatTem', 'AllOutWatTem', 'AntifreezeTem', 'CodeCoalGasTem', 'CodeCoalLiquidTem',
    'HighPressureTem', 'FloorHeat', 'ModelType', 'rssi', 'LowPressureTem', 'DryContact',
))
_TIMER_CONTROLS = frozenset((
    "Pow", "Blo", "SwhSlp", "Air", "SvSt", "Quiet", "Tur", "HeatCoolType",
    "Mod", "SetTem", "HeatSvStTemMax", "CoolSvStTemMin", "WdSpd", "SwUpDn",
    "SwingLfRig", "AllErr", "TemUn", "TemRec", "SlpMod", "TemRecH", "TemRecC",
    "host", "name", "time",
))


def _members(value, maximum):
    if not isinstance(value, dict) or len(value) > maximum:
        raise InvalidPacket("invalid ATW object size")
    normalized = {}
    for name, item in value.items():
        if not isinstance(name, str) or name.lower() in normalized:
            raise InvalidPacket("ambiguous ATW JSON field")
        normalized[name.lower()] = item
    return normalized


def _text_size(value):
    if not isinstance(value, str) or "\0" in value:
        raise InvalidPacket("invalid ATW text")
    try:
        return len(value.encode("utf-8"))
    except UnicodeError as exc:
        raise InvalidPacket("invalid ATW UTF-8") from exc


def _names(value, maximum):
    if (not isinstance(value, list) or len(value) > maximum
            or any(_text_size(name) > 19 for name in value)):
        raise InvalidPacket("invalid ATW property names")
    return value


def _reply(device, outer, inner, *, generic=False):
    plain_size = len(json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    # Bound encrypted base64 to 1496 bytes before a command can mutate state.
    if plain_size > 1119:
        raise InvalidPacket("ATW reply exceeds the safe firmware buffer")
    envelope = {"t": "pack", "i": 1 if generic else 0,
                "uid": outer["uid"], "cid": device.mac, "tcid": outer["cid"]}
    return Reply(envelope, inner, GENERIC_KEY if generic else device.key, CODEC)


class Atw:
    def __init__(self, *, version="V5.0.0.0", include_hid=True):
        self.version = version
        self.include_hid = include_hid

    def validate_state(self, state):
        for name, value in state.items():
            if name not in self.control_ranges:
                raise ValueError(f"state field {name!r} is not a configurable ATW control")
            lower, upper = self.control_ranges[name]
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError(f"state field {name!r} must be an integer in {lower}..{upper}")

    def thermal_target(self, device):
        state = device.state
        mode = state["Mod"]
        if device.mid == "9301":
            target = state["WatBoxTemSet"]
            action = "heat" if mode in (2, 3, 4) else "idle"
        else:
            heating = mode in (1, 4)
            cooling = mode in (3, 5)
            suffix = "HomTemSet" if device.mid == "9300" else "WatOutTemSet"
            target = state[("He" if heating else "Co") + suffix]
            action = "heat" if heating else "cool" if cooling else "idle"
        return (action if state["Pow"] else "idle"), target

    def _sensors(self, device):
        # Consumer-compatible chosen calibration, not established by firmware bytes.
        tenths = floor(max(-100.0, min(155.9, device.room_c)) * 10) + 1000
        high, low = divmod(tenths, 10)
        return {name: value for pair in _SENSOR_PAIRS[device.mid]
                for name, value in zip(pair, (high, low))}

    def encode_room(self, device):
        device.state.update(self._sensors(device))

    def advertise(self, device, outer):
        outer = _members(outer, 20)
        if outer.get("t") != "scan":
            return []
        inner = {
            "t": "dev", "cid": device.mac, "bc": "gree", "brand": "gree",
            "catalog": "gree", "mac": device.mac, "mid": device.mid,
            **({"hid": device.profile.hid} if self.include_hid else {}),
            "ModelType": self._model_type(device), "model": "gree", "name": device.name,
            "series": "gree", "vender": "1", "ver": self.version,
            "lock": device.state.get("_atw_lock", 0),
        }
        return [_reply(device, {"uid": 0, "cid": ""}, inner, generic=True)]

    def handle(self, device, outer):
        # Shared UDP routing still requires lowercase t/pack/tcid; inner lookup is native-style.
        outer = _members(outer, 20)
        if (outer.get("t") != "pack"
                or not {"pack", "i", "uid", "cid", "tcid"} <= outer.keys()
                or outer["tcid"] != device.mac
                or type(outer["i"]) is not int or not 0 <= outer["i"] <= 2147483647
                or type(outer["uid"]) is not int or not -2147483648 <= outer["uid"] <= 2147483647
                or _text_size(outer["cid"]) > 19):
            raise InvalidPacket("invalid ATW target or envelope")
        pack = outer["pack"]
        if not isinstance(pack, str) or not pack.isascii() or len(pack) >= 700:
            raise InvalidPacket("ATW encrypted pack exceeds the firmware buffer")
        key = GENERIC_KEY if outer["i"] & 255 else device.key
        inner = _members(decode_pack(outer, key, CODEC), 30)
        for selector in ("mac", "sub"):
            if selector in inner and inner[selector] != device.mac:
                raise InvalidPacket("conflicting ATW inner target")
        operation = inner.get("t")
        if operation == "bind":
            if inner.get("mac") != device.mac:
                raise InvalidPacket("ATW bind requires matching mac")
            reply = {"t": "bindok", "mac": device.mac,
                     "key": device.key.decode("ascii"), "r": 200}
            return [_reply(device, outer, reply, generic=True)]
        if operation in ("setT", "updateT", "queryT", "deleteT"):
            return self._schedule(device, outer, inner)
        if operation == "upgrade":
            if outer["i"] != 0 or _text_size(inner.get("url")) > 159:
                raise InvalidPacket("invalid ATW upgrade acceptance request")
            reply = _reply(device, outer, {"t": "ret", "r": 200, "mac": device.mac},
                           generic=True)
            # Source ACK accepts a queued URL, not a completed transfer or flash.
            device.state["_atw_upgrade_url"] = inner["url"]
            device.state["_atw_upgrade_pending"] = True
            return [reply]
        if operation not in ("status", "cmd"):
            return []
        if outer["i"] != 0:
            raise InvalidPacket("ATW controls require bound selector zero")
        if operation == "status":
            if inner.get("mac") != device.mac:
                raise InvalidPacket("ATW status requires matching mac")
            names = _names(inner.get("cols"), 50)
            values = self._status_values(device)
            cols = self._status_columns(names, values)
            reply = {"t": "dat", "r": 200, "mac": device.mac,
                     "cols": cols, "dat": [values[name] for name in cols if name in values]}
            return [_reply(device, outer, reply)]
        names = _names(inner.get("opt"), 49)
        values = inner.get("p")
        if (not names or not isinstance(values, list) or len(names) != len(values)
                or "cols" in inner):
            raise InvalidPacket("ATW command requires unambiguous equal nonempty opt/p arrays")
        metadata = {}
        for name, value in zip(names, values):
            if name in self.control_ranges:
                lower, upper = self.control_ranges[name]
                if type(value) is not int or not lower <= value <= upper:
                    raise InvalidPacket(f"invalid simulated ATW value for {name}")
            elif name == "lock":
                if type(value) is not int or not -2147483648 <= value <= 2147483647:
                    raise InvalidPacket("ATW lock requires a signed32 integer")
                metadata[name] = value
            elif name == "name":
                if not 1 <= _text_size(value) <= 79:
                    raise InvalidPacket("ATW name requires1..79 UTF-8 bytes")
                metadata[name] = value
            elif name in ("apssid", "appsw") and self.credentials:
                if not (1 if name == "apssid" else 0) <= _text_size(value) <= 31:
                    raise InvalidPacket("ATW credential exceeds safe32-byte storage")
                metadata[name] = value
            elif name == "time":
                if _text_size(value) != 19:
                    raise InvalidPacket("ATW time requires YYYY-MM-DD HH:MM:SS")
                try:
                    parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
                    if parsed.isoformat(sep=" ", timespec="seconds") != value:
                        raise ValueError("noncanonical timestamp")
                except ValueError as exc:
                    raise InvalidPacket("invalid canonical ATW clock") from exc
                metadata[name] = value
            else:
                raise InvalidPacket("unsupported or read-only ATW control")
        # Metadata arrays serialize final cache values, unlike requested raw controls.
        echoed = [metadata.get(name, value) for name, value in zip(names, values)]
        reply = _reply(device, outer, {"t": "res", "r": 200, "opt": list(names),
                                       "p": echoed, "val": list(echoed)})
        device.advance(time.monotonic())
        self._apply_commands(device, names, values)
        self.encode_room(device)
        return [reply]


# Exact 5.08 descriptors: slot order, board byte offset, decoder operation.
# Operation 7 is an unscaled byte; the remaining report operations select one bit.
_QCA_CONTROLS = (
    "FastHtWter", "ColHtWter", "HetHtWter", "TemUn", "SvSt", "Quiet",
    "Emegcy", "LefHom", "Mod", "SwDisFct", "CoWatOutTemSet", "HeWatOutTemSet",
    "CoHomTemSet", "HeHomTemSet", "WatBoxTemSet", "Reset", "AllErr", "Pow",
    "TemRec", "TemRecB",
)
_QCA_SENSORS = (
    ("AllInWatTemHi", 4, 7), ("AllInWatTemLo", 5, 7),
    ("AllOutWatTemHi", 6, 7), ("AllOutWatTemLo", 7, 7),
    ("HepOutWatTemHi", 8, 7), ("HepOutWatTemLo", 9, 7),
    ("WatBoxTemHi", 10, 7), ("WatBoxTemLo", 11, 7),
    ("RmoHomTemHi", 12, 7), ("RmoHomTemLo", 13, 7),
    ("WatBoxElcHeRunSta", 14, 0), ("SyAnFroRunSta", 14, 11),
    ("ElcHe1RunSta", 15, 0), ("ElcHe2RunSta", 15, 11), ("AnFrzzRunSta", 15, 22),
    ("VersatiSeries", 16, 7), ("WatBoxExt", 17, 7), ("BordTest", 18, 7),
    ("RomHomTemExt", 19, 7), ("FocModSwh", 20, 7), ("ColColetSwh", 21, 7),
    ("EndTemCotSwh", 22, 7), ("Emegcy", 23, 7), ("HanFroSwh", 24, 7),
    ("WatSyExhSwh", 25, 7),
)
_ALTERNATE_CONTROLS = (
    "SvSt", "Quiet", "LefHom", "Mod", "Pow", "HeWatOutTemSet",
    "HeWatOutTemSetFloor", "CoWatOutTemSet", "Reset", "FactoryTest",
)
_ALTERNATE_SENSORS = (
    ("EnvironmentTem", 4, 88), ("AirInTem", 6, 88), ("AirOutTem", 8, 88),
    ("DefrostTem", 10, 88), ("AllInWatTem", 12, 88), ("AllOutWatTem", 14, 88),
    ("AntifreezeTem", 16, 88), ("CodeCoalGasTem", 18, 88),
    ("CodeCoalLiquidTem", 20, 88), ("HighPressureTem", 22, 88),
    ("FloorHeat", 31, 0), ("TemUn", 31, 11), ("AllErr", 31, 22),
    ("LowPressureTem", 24, 88), ("DryContact", 31, 33),
)
_QCA_EMPTY_METADATA = frozenset((
    "SwhWifi", "SwhWifiRes", "SwhWifiConf", "AutoUpdate", "AutoConnCloud",
    "datDump", "datRep", "datFailRep", "datPeroid", "subCnt", "useTCP",
    "country", "city", "cnty", "cityid", "lat", "lon",
))


class QcaAtw(Atw):
    """Exact descriptor staging/report semantics with synthetic unreported channels."""

    def __init__(self, *, version="V5.0.0.0", include_hid=False, evu=False,
                 alternate=False, credentials=False):
        super().__init__(version=version, include_hid=include_hid)
        self.alternate = alternate
        self.credentials = credentials
        self.controls = _ALTERNATE_CONTROLS if alternate else _QCA_CONTROLS + (("EVU",) if evu else ())
        self.sensor_fields = _ALTERNATE_SENSORS if alternate else _QCA_SENSORS
        self.control_ranges = dict.fromkeys(self.controls, (0, 2147483647))
        self.known_names = _NETWORK_NAMES | ({"EVU"} if evu else set())

    def _model_type(self, device):
        # Board-reported model type is independent of the compiled HID.
        return ""

    def validate_state(self, state):
        super().validate_state(state)
        for name, value in state.items():
            if value > 255:
                raise ValueError(f"state field {name!r} must be a staged byte in 0..255")

    def _control_values(self, device):
        return {name: device.state[name] for name in self.controls}

    def thermal_target(self, device):
        return None if self.alternate else super().thermal_target(device)

    def _sensors(self, device):
        report = device.state.get("_atw_report", (0,) * len(self.sensor_fields))
        return {field[0]: value for field, value in zip(self.sensor_fields, report)}

    def encode_room(self, device):
        if self.alternate:
            device.state.setdefault("_atw_report", (0,) * len(self.sensor_fields))
            return
        # Preserve existing typed-client calibration only for the selected medium.
        generated = super()._sensors(device)
        device.state.update(generated)
        report = list(device.state.get("_atw_report", (0,) * 25))
        for index, (name, _, _) in enumerate(_QCA_SENSORS):
            if name in generated:
                report[index] = generated[name]
        device.state["_atw_report"] = tuple(report)

    def receive_report(self, device, frame):
        """Chosen synthetic mainboard IO: raw reports last until the next thermal step."""
        minimum = 32 if self.alternate else 26
        if not isinstance(frame, bytes) or len(frame) < minimum:
            raise ValueError(f"ATW sensor report requires at least {minimum} bytes")
        device.state["_atw_report"] = tuple(
            int.from_bytes(frame[offset:offset + 2], "big") if operation == 88 else
            frame[offset] if operation == 7 else (frame[offset] >> (operation // 11)) & 1
            for _, offset, operation in self.sensor_fields
        )

    def _status_values(self, device):
        return {
            # Stationary synthetic prefix/fallback readout, not absent firmware getters.
            **dict.fromkeys(self.known_names - _QCA_EMPTY_METADATA, 0),
            "mid": device.mid, "hid": device.profile.hid, "mac": device.mac,
            "name": device.name, "vender": "1", "ver": self.version,
            **self._control_values(device),
            **self._sensors(device),
            "lock": device.state.get("_atw_lock", 0), "bc": "", "model": "", "series": "",
            "apssid": device.state.get("_atw_apssid", ""),
            "appsw": device.state.get("_atw_appsw", ""), "brand": "", "catalog": "",
            "host": "dis.gree.com",
            "ModelType": self._model_type(device),
            # Synthetic epoch and disconnected Wi-Fi input, not live wall clock/dBm.
            "time": device.state.get("_atw_time", "1970-01-01 00:00:00"), "rssi": -1,
        }

    def _status_columns(self, names, values):
        if len(names) == 50:
            return []
        return [name for name in names if name in values or name in _QCA_EMPTY_METADATA]

    def _apply_commands(self, device, names, values):
        for name, value in zip(names, values):
            if name == "name":
                device.name = value
            elif name in ("lock", "time", "apssid", "appsw"):
                device.state["_atw_" + name] = value
            else:
                device.state[name] = value & 255

    def _schedule(self, device, outer, inner):
        def integer(value, lower=-2147483648, upper=2147483647):
            if type(value) is not int or not lower <= value <= upper:
                raise InvalidPacket("invalid ATW timer integer")
            return value

        operation = inner["t"]
        records = device.state.get("_atw_timers", {}).copy()
        if operation == "queryT":
            index = integer(inner.get("index"), 0, 9)
            integer(inner.get("count"), 1, 10 - index)
            # Original loop repeatedly selects index, not index + iteration.
            body = {"t": "listT", "total": 10, "index": index,
                    "list": [records[index]] if index in records else []}
            return [_reply(device, outer, body)]
        identifier = integer(inner.get("id"), 0, 9)
        if operation in ("updateT", "deleteT") and identifier not in records:
            raise InvalidPacket("unknown ATW timer id")
        if operation == "deleteT":
            del records[identifier]
        else:
            name = inner.get("name", "")
            # Native accepts40 bytes into32-byte storage; chosen safe bound is31.
            if _text_size(name) > 31:
                raise InvalidPacket("ATW timer name exceeds safe record storage")
            values = {field: integer(inner.get(field), 0, maximum)
                      for field, maximum in (("enable", 1), ("hr", 23), ("min", 59), ("sec", 60))}
            integer(inner.get("tz"))
            week = inner.get("week")
            if not isinstance(week, list) or len(week) != 7:
                raise InvalidPacket("ATW timer requires seven week integers")
            week = [integer(value) & 0xffffffff for value in week]
            commands = inner.get("cmd")
            if not isinstance(commands, list) or len(commands) != 1:
                raise InvalidPacket("ATW timer requires one command")
            command = _members(commands[0], 3)
            macs, names, requested = command.get("mac"), command.get("opt"), command.get("p", [0])
            if (not isinstance(macs, list) or len(macs) != 1 or _text_size(macs[0]) > 19
                    or not isinstance(names, list) or len(names) != 1
                    or not isinstance(names[0], str) or names[0] not in _TIMER_CONTROLS
                    or not isinstance(requested, list) or len(requested) != 1):
                raise InvalidPacket("invalid ATW timer command schema")
            value = integer(requested[0]) & 0xffffffff
            records[identifier] = {"id": identifier, "name": name, **values,
                                   "week": week,
                                   "cmd": [{"mac": list(macs), "opt": ["Pow"], "p": [value]}]}
        reply = _reply(device, outer, {"t": "resT", "r": 200})
        # Persistent synthetic RAM only; no wall-clock execution or flash IO.
        device.state["_atw_timers"] = records
        return [reply]


_BUILDS = (
    ("v5.07", "V5.0.0.0", "362001066763+W06A(P3)V5.07.bin",
     "98931d02d022bb4c435c7202bbae71a0b987ca1b1a06a08e592701c93ba4b647", False, False, True),
    ("v5.08", "V5.0.0.0", "362001066763+W06A(P3)V5.08.bin",
     "07cfbe377aadee70b1bf4576bdd3a4013f7b2d4b014e9757ec036bc1dbcfe1fb", False, False, True),
    ("v6.0", "V5.0.0.0", "362001066763+W06A(P3)V6.0.bin",
     "b15e7350fbc3699e1fbb48a66423a23ffc6f4e69854a0f2f36d886fe117c5c2a", True, False, False),
    ("v6.04", "V5.0.0.0", HID, SOURCE_SHA256, True, True, False),
    ("v6.05", "V5.0.0.0", "362001066763+U-W06A(P3)V6.05.bin",
     "075e1090f8df33a5699af9812d1ac6fe5a76334b7cbaf59c051c5df8cdd8cca8", True, True, False),
)
PROFILES = tuple(
    Profile(f"sim-w06a-p3-{build}-{mid}", (mid,), hid, sha,
            {**dict.fromkeys(handler.controls, 0), **INITIAL_STATE,
             "Mod": 2 if mid == "9301" else 1},
            handler, max_request_bytes=1024)
    for build, version, hid, sha, include_hid, evu, credentials in _BUILDS
    for handler in (QcaAtw(version=version, include_hid=include_hid, evu=evu,
                           credentials=credentials),)
    for mid in ("9300", "9301", "9302")
)
PROFILES += tuple(
    Profile(f"sim-w06aq11-v1.01-{mid}", (mid,), "362001067139+U-W06AQ11V1.01.bin",
            "8a1b2de448c789172809e5ee2610c1e47fc938d6242ac36596bc4a0da109b6b6",
            {**dict.fromkeys(_QCA_CONTROLS, 0), **INITIAL_STATE,
             "Mod": 2 if mid == "9301" else 1},
            QcaAtw(version="V1.0.0.0", include_hid=True), max_request_bytes=1024)
    for mid in ("9300", "9301", "9302")
)
PROFILES += tuple(
    Profile(profile.id.rsplit("-", 1)[0] + "-raw-806004", ("806004",),
            profile.hid, profile.source_sha256, dict.fromkeys(_ALTERNATE_CONTROLS, 0),
            QcaAtw(version=profile.handler.version, include_hid=profile.handler.include_hid,
                   evu="EVU" in profile.handler.known_names, alternate=True,
                   credentials=profile.handler.credentials),
            max_request_bytes=1024)
    for profile in PROFILES if profile.mids == ("9300",)
)
