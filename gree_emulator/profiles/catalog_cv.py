"""CV2/V7 gateway wire caches with synthetic stationary mainboard reports.

All 139 nonempty network names are covered. A recognized metadata name can emit
no value; a name outside a child's selector reads a declared synthetic prefix
byte instead of pretending the native cache[-1] access is calibrated data.
Strict parsing, atomic validation and safe string capacities intentionally do
not reproduce the native unchecked copies or defective base64/unpadding paths.
"""
from copy import deepcopy
from datetime import datetime, timezone
from time import monotonic

from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile
from .catalog_cv_schedule import due_queue, handle as schedule

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
NAMES = ('SwhWifi', 'SwhWifiRes', 'SwhWifiConf', 'AutoUpdate', 'AutoConnCloud', 'lock', 'datDump', 'datRep', 'datFailRep', 'datPeroid', 'subCnt', 'useTCP', 'vender', 'bc', 'mid', 'model', 'series', 'apssid', 'appsw', 'brand', 'catalog', 'country', 'hid', 'host', 'mac', 'name', 'time', 'ver', 'city', 'cnty', 'cityid', 'lat', 'lon', 'Pow', 'Mod', 'SetTem', 'WdSpd', 'Tur', 'Quiet', 'SwUpDn', 'SwingLfRig', 'TemUn', 'TemRec', 'Lig', 'Air', 'Blo', 'Health', 'SvSt', 'SwhSw', 'HeatCoolType', 'StHt', 'LTemDry', 'Wet', 'SwhSlp', 'SlpMod', 'HasTmr', 'TmrLpTms', 'TmrOff', 'TmrOn', 'CurTmHor', 'CurTmMin', 'TmrOnHorLf', 'TmrOnMinLf', 'TmrOffHorLf', 'TmrOffMinLf', 'DsplySt', 'EnvFun', 'JFErrorCode', 'AssHt', 'FrshAir', 'AllErr', 'Coolmod', 'MasSub', 'MasIDUMod', 'GetEr', 'CoolSvStTemMin', 'HeatSvStTemMax', 'HumiSvStTemMin', 'MaeS', 'FanMod', 'ModS', 'VitiGr', 'GasN', 'TemSor', 'HumSor', 'PM2P5', 'VOC', 'CO2', 'PctCle', 'PctRe', 'IDUAirQu', 'AirQu', 'ODUViti', 'GasAvail', 'GasLED', 'GasMod', 'GasMas', 'PM2P5Sta', 'SorErr', 'CommErr', 'GasQ', 'WtmrType', 'Wtmr1', 'Wtmr2', 'Wtmr1StartHr', 'Wtmr1StartMin', 'Wtmr1EndHr', 'Wtmr1EndMin', 'Wtmr2StartHr', 'Wtmr2StartMin', 'Wtmr2EndHr', 'Wtmr2EndMin', 'Wmod', 'SetTemInt', 'SetTemDec', 'WstpSv', 'WstpH', 'WatTmp', 'Watpercent', 'AcPctCle', 'ForceMode', 'EnvTem', 'Htem', 'SwhBw', 'BwBoard', 'BwErr', 'Wstate', 'WschTyp', 'Htmr1StartHr', 'Htmr1StartMin', 'Htmr1EndHr', 'Htmr1EndMin', 'Htmr2StartHr', 'Htmr2StartMin', 'Htmr2EndHr', 'Htmr2EndMin', 'HtMod', 'Sch1', 'Sch2')
METADATA = frozenset(NAMES[:33])
SELECTORS = ({'Pow': 0, 'Wstate': 1, 'WschTyp': 2, 'Sch1': 3, 'Sch2': 4, 'AllErr': 5, 'Wtmr1StartHr': 6, 'Wtmr1StartMin': 7, 'Wtmr1EndHr': 8, 'Wtmr1EndMin': 9, 'Wtmr2StartHr': 10, 'Wtmr2StartMin': 11, 'Wtmr2EndHr': 12, 'Wtmr2EndMin': 13, 'Wmod': 14, 'SetTemInt': 15, 'SetTemDec': 16, 'WstpSv': 17, 'WstpH': 18, 'WatTmp': 19, 'Watpercent': 20, 'SwhBw': 21, 'BwErr': 22, 'BwBoard': 23, 'SwhWifi': 24, 'SwhWifiRes': 25, 'TemUn': 26}, {'Pow': 0, 'HeatCoolType': 1, 'AcPctCle': 2, 'AllErr': 3, 'Mod': 4, 'ForceMode': 5, 'WdSpd': 6, 'SetTemInt': 7, 'SetTemDec': 8, 'EnvTem': 9, 'SwUpDn': 10, 'SwingLfRig': 11, 'TemUn': 12}, {'Pow': 0, 'Sch1': 1, 'Sch2': 2, 'AllErr': 3, 'Htmr1StartHr': 4, 'Htmr1StartMin': 5, 'Htmr1EndHr': 6, 'Htmr1EndMin': 7, 'Htmr2StartHr': 8, 'Htmr2StartMin': 9, 'Htmr2EndHr': 10, 'Htmr2EndMin': 11, 'SetTemInt': 12, 'SetTemDec': 13, 'Htem': 14, 'HtMod': 15, 'TemUn': 16})
RANGES = ({'Pow': (0, 1), 'Wstate': (0, 255), 'WschTyp': (0, 1), 'Sch1': (0, 1), 'Sch2': (0, 1), 'AllErr': (0, 255), 'Wtmr1StartHr': (0, 23), 'Wtmr1StartMin': (0, 59), 'Wtmr1EndHr': (0, 23), 'Wtmr1EndMin': (0, 59), 'Wtmr2StartHr': (0, 23), 'Wtmr2StartMin': (0, 59), 'Wtmr2EndHr': (0, 23), 'Wtmr2EndMin': (0, 59), 'Wmod': (0, 3), 'SetTemInt': (35, 85), 'SetTemDec': (0, 9), 'WstpSv': (0, 255), 'WstpH': (0, 255), 'WatTmp': (0, 255), 'Watpercent': (0, 255), 'SwhBw': (0, 1), 'BwErr': (0, 255), 'BwBoard': (0, 255), 'SwhWifi': (0, 255), 'SwhWifiRes': (0, 255), 'TemUn': (0, 1)}, {'Pow': (0, 1), 'HeatCoolType': (0, 255), 'AcPctCle': (0, 1), 'AllErr': (0, 255), 'Mod': (0, 4), 'ForceMode': (0, 3), 'WdSpd': (0, 6), 'SetTemInt': (16, 30), 'SetTemDec': (0, 9), 'EnvTem': (0, 255), 'SwUpDn': (0, 1), 'SwingLfRig': (0, 1), 'TemUn': (0, 1)}, {'Pow': (0, 1), 'Sch1': (0, 255), 'Sch2': (0, 255), 'AllErr': (0, 255), 'Htmr1StartHr': (0, 255), 'Htmr1StartMin': (0, 255), 'Htmr1EndHr': (0, 255), 'Htmr1EndMin': (0, 255), 'Htmr2StartHr': (0, 255), 'Htmr2StartMin': (0, 255), 'Htmr2EndHr': (0, 255), 'Htmr2EndMin': (0, 255), 'SetTemInt': (35, 85), 'SetTemDec': (0, 9), 'Htem': (0, 255), 'HtMod': (0, 1), 'TemUn': (0, 1)})
CHILD_MIDS = ("910001", "910002", "910003")


def _members(value):
    if not isinstance(value, dict) or len(value) > 20:
        raise InvalidPacket("CV requires an object with at most20 members")
    result = {}
    for name, item in value.items():
        result.setdefault(name.lower(), item)
    return result


def _integer(value):
    if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
        raise InvalidPacket("CV requires signed32 integers")
    return value


def _text(value, maximum):
    if (not isinstance(value, str) or "\0" in value
            or len(value.encode()) > maximum):
        raise InvalidPacket("invalid CV bounded text")
    return value


def _runtime(device):
    if "_cv" not in device.state:
        device.state["_cv"] = {
            "lock": device.state.get("lock", 0), "host": "dis.gree.com",
            "apssid": "", "appsw": "12345678", "ssid": "", "psw": "",
            "epoch": 0, "clock_at": monotonic(), "due_minute": -1,
            "schedules": [], "queue": 0, "uid": 0, "peer": "null",
            "child_names": {child.id: child.name for child in device.children},
            "pending_upgrade": None,
        }
    return device.state["_cv"]


def _epoch(runtime, now):
    return runtime["epoch"] + max(0, int(now - runtime["clock_at"]))


def _clock_value(runtime, now):
    value = datetime.fromtimestamp(_epoch(runtime, now), timezone.utc)
    text = value.strftime("%Y-%m-%d %H:%M:%S")
    # Native formatter tests zero-based month<10, including October.
    return text[:5] + "0" + text[6:] if value.month <= 10 else text


def _set_clock(runtime, value, now):
    value = _text(value, 19)
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise InvalidPacket("invalid CV calendar") from error
    runtime["epoch"] = int(parsed.timestamp())
    runtime["clock_at"] = now
    runtime["due_minute"] = runtime["epoch"] // 60 - 1


def _due(runtime, now):
    current = _epoch(runtime, now) // 60
    # One day's minute boundaries is sufficient: source schedules recur unchanged.
    start = max(runtime["due_minute"] + 1, current - 1439)
    for minute in range(start, current + 1):
        value = datetime.fromtimestamp(minute * 60, timezone.utc)
        runtime["queue"] = due_queue(runtime["schedules"], value.hour,
                                     value.minute, 0, runtime["queue"])
    runtime["due_minute"] = current


def _metadata(root, target, runtime, name, now):
    values = {
        "lock": runtime["lock"], "vender": "1", "bc": "gree", "mid": root.mid,
        "model": "gree", "series": "gree", "apssid": runtime["apssid"],
        "appsw": runtime["appsw"], "brand": "gree", "catalog": "gree",
        "hid": root.profile.hid, "host": runtime["host"], "mac": root.mac,
        "time": _clock_value(runtime, now), "ver": "V1.0.0.0",
    }
    if name == "name":
        return [] if target is root else [runtime["child_names"].get(target.id, target.name)]
    return [values[name]] if name in values else []


def _read(root, target, runtime, state, name, now):
    if name in METADATA:
        return _metadata(root, target, runtime, name, now)
    if target is root:
        return []
    role = CHILD_MIDS.index(target.mid)
    return [state.get(name, 0) if name in SELECTORS[role] else 0]


def _reply(root, inner, index, uid, peer):
    reply = Reply({"t": "pack", "i": index, "uid": uid,
                   "cid": root.mac, "tcid": peer}, inner,
                  root.key if index == 0 else GENERIC_KEY, CODEC)
    if len(encode_reply(reply)) >= 1024:
        raise InvalidPacket("CV response exceeds source output capacity")
    return reply


def _names(value):
    if not isinstance(value, list) or len(value) > 50:
        raise InvalidPacket("CV requires at most50 property names")
    result = []
    for name in value:
        name = _text(name, 255)
        result.append(name if len(name.encode()) < 16 else "")
    return result


def _visible(names):
    if len(names) == 50:
        return []
    stop = names.index("") if "" in names else len(names)
    return [(i, name) for i, name in enumerate(names[:stop]) if name in NAMES]


class CvFamily:
    plaintext_types = ("hbok", "tm", "wlan")

    def __init__(self, role=None):
        self.role = role

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        return None

    def validate_state(self, state):
        allowed = {"lock"} if self.role is None else SELECTORS[self.role]
        for name, value in state.items():
            if name not in allowed or type(value) is not int:
                raise ValueError("invalid CV raw initial state")
            if self.role is None:
                if not -(1 << 31) <= value < (1 << 31):
                    raise ValueError("CV lock must fit signed32")
            elif not 0 <= value <= 255:
                raise ValueError("CV reports are unsigned bytes")

    def validate_topology(self, root):
        seen = []
        for child in root.children:
            if child.mid not in CHILD_MIDS or child.mid in seen:
                raise ValueError("CV permits one child per physical role")
            suffix = CHILD_MIDS.index(child.mid) + 1
            if child.mac != root.mac + f"{suffix:02x}":
                raise ValueError("CV child identity must be root MAC plus physical suffix")
            seen.append(child.mid)
        if seen and tuple(sorted(seen)) not in (("910001",), ("910001", "910002"),
                                       ("910001", "910003"), CHILD_MIDS):
            raise ValueError("CV children must follow original mainboard topology order")
        root.children.sort(key=lambda child: CHILD_MIDS.index(child.mid))

    def advertise(self, root, outer):
        if self.role is not None:
            return []
        runtime = _runtime(root)
        inner = {"t": "dev", "cid": root.mac, "bc": "gree", "brand": "gree",
                 "catalog": "gree", "mac": root.mac, "mid": root.mid,
                 "model": "gree", "name": root.name, "series": "gree",
                 "vender": "1", "ver": "V1.0.0.0", "lock": runtime["lock"],
                 "subCnt": len(root.children)}
        return [_reply(root, inner, 1, runtime["uid"], runtime["peer"])]

    def handle(self, root, outer):
        if self.role is not None:
            return []
        outer = _members(outer)
        runtime = _runtime(root)
        now = monotonic()
        if outer.get("t") == "scan":
            return self.advertise(root, outer)
        if outer.get("t") == "hbok":
            runtime["heartbeat_at"] = now
            return []
        if outer.get("t") == "tm":
            staged = deepcopy(runtime)
            _set_clock(staged, outer.get("time"), now)
            root.state["_cv"] = staged
            return []
        if outer.get("t") == "wlan":
            staged = deepcopy(runtime)
            for name, field in (("ssid", "ssid"), ("psw", "psw"), ("host", "host")):
                staged[field] = _text(outer.get(name), 63)
            staged["host"] = staged["host"] or "dis.gree.com"
            reply = _reply(root, {"t": "ret", "r": 200, "mac": root.mac},
                           2, runtime["uid"], runtime["peer"])
            # Local acceptance/cache only: no Wi-Fi connection is claimed.
            root.state["_cv"] = staged
            return [reply]
        if outer.get("t") != "pack":
            return []
        index = _integer(outer.get("i"))
        uid = _integer(outer.get("uid"))
        peer = _text(outer.get("cid"), 19)
        if index < 0 or outer.get("tcid") != root.mac:
            raise InvalidPacket("invalid CV index or root target")
        if not isinstance(outer.get("pack"), str) or len(outer["pack"]) >= 700:
            raise InvalidPacket("CV requires a bounded encrypted string pack")
        inner = _members(decode_pack(outer, root.key if index & 255 == 0 else GENERIC_KEY, CODEC))
        staged = deepcopy(runtime)
        staged["uid"], staged["peer"] = uid, peer
        operation = inner.get("t")
        if operation == "bind":
            if inner.get("mac") != root.mac or staged["lock"]:
                return []
            reply = _reply(root, {"t": "bindok", "mac": root.mac,
                                  "key": root.key.decode("ascii"), "r": 200}, 1, uid, peer)
        elif operation == "subDev":
            if inner.get("mac") != root.mac:
                raise InvalidPacket("invalid CV enumeration target")
            page = _integer(inner.get("i")) & 255
            entries = [{"mac": child.mac, "mid": child.mid,
                        "name": staged["child_names"].get(child.id, child.name),
                        "model": "gree", "lock": 0}
                       for child in root.children[page:]]
            reply = _reply(root, {"t": "subList", "c": len(root.children),
                                  "i": page, "r": 200, "list": entries}, 0, uid, peer)
        elif operation in ("setT", "updateT", "queryT", "deleteT"):
            response = schedule(staged["schedules"], inner, root.mac)
            reply = _reply(root, response, 0, uid, peer)
        elif operation == "upgrade":
            staged["pending_upgrade"] = _text(inner.get("url"), 159)
            # This is the source's request acceptance, never upgrade completion.
            reply = _reply(root, {"t": "ret", "r": 200, "mac": root.mac}, 1, uid, peer)
        elif operation in ("status", "cmd"):
            selector = inner.get("mac") if operation == "status" else inner.get("sub")
            target = root if selector == root.mac else next(
                (child for child in root.children if child.mac == selector), None)
            if target is None:
                raise InvalidPacket("unknown CV inner target")
            names = _names(inner.get("cols") if operation == "status" else inner.get("opt"))
            visible = _visible(names)
            state = dict(target.state)
            if operation == "status":
                _due(staged, now)
                response = {"t": "dat", "r": 200, "mac": target.mac,
                            "cols": [name for _, name in visible], "dat": []}
                for _, name in visible:
                    response["dat"].extend(_read(root, target, staged, state, name, now))
            else:
                values = inner.get("p")
                if not isinstance(values, list) or len(values) != len(names):
                    raise InvalidPacket("CV command arrays must match")
                for name, value in zip(names, values):
                    if name in ("host", "name", "time", "apssid", "appsw"):
                        limit = 39 if name == "name" else 31 if name in ("apssid", "appsw") else 20
                        text = _text(value, limit)
                        if name != "appsw" and not text:
                            raise InvalidPacket("empty CV metadata command")
                        if name == "time":
                            _set_clock(staged, text, now)
                        elif name == "name":
                            owner = target if target is not root else next(iter(root.children), None)
                            if owner is not None:
                                staged["child_names"][owner.id] = text
                        else:
                            staged[name] = text
                    else:
                        value = _integer(value)
                        if name == "lock":
                            staged["lock"] = value
                        elif target is not root and name in SELECTORS[self._role(target)]:
                            low, high = RANGES[self._role(target)][name]
                            if not low <= value <= high and (low, high) != (0, 255):
                                raise InvalidPacket("CV raw setter rejects this integer")
                            state[name] = value & 255
                response = {"t": "res", "r": 200, "mac": target.mac,
                            "opt": [name for _, name in visible], "p": [], "val": []}
                for position, name in visible:
                    data = (_metadata(root, target, staged, name, now) if name in METADATA
                            else [values[position]])
                    response["p"].extend(data)
                    response["val"].extend(data)
            reply = _reply(root, response, 0, uid, peer)
            if operation == "cmd" and target is not root:
                target.state.update(state)
        else:
            return []
        root.state["_cv"] = staged
        root.state["lock"] = staged["lock"]
        for child in root.children:
            child.name = staged["child_names"].get(child.id, child.name)
        return [reply]

    @staticmethod
    def _role(device):
        return CHILD_MIDS.index(device.mid)


PROFILES = tuple(
    profile
    for version, hid, sha in (
        ("v2", "362001060709+W06CV2.bin", "1c9a4b6a2757cde0dd396253f7aaa75eff44ab70e826d64e1bff49ca5cfb3000"),
        ("v7", "362001060709+W06CV7.bin", "50c838cbec0ff1751ea4cc80734fba7c6901054437b933c5670f2f1e9a223a85"),
    )
    for profile in (
        Profile(f"sim-w06c-{version}", ("9100",), hid, sha, {"lock": 0},
                CvFamily(), max_children=3, max_request_bytes=1024),
        *(Profile(f"sim-w06c-{version}-{mid}", (mid,), hid, sha,
                  dict.fromkeys(SELECTORS[role], 0), CvFamily(role), identity_bytes=7,
                  parent_profiles=(f"sim-w06c-{version}",), max_request_bytes=1024,
                  identity_suffix=bytes([role + 1]), identity_from_parent=True)
          for role, mid in enumerate(CHILD_MIDS)),
    )
)
