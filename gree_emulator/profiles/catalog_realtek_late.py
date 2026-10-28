"""W06KV host board, not any of its independently bound downstream appliances.

The synthetic board supplies the evidenced 19-byte sensor cache and three timer
records. MCU completion is immediate in memory; it is not a captured board ACK.
The separate devs/scan/bind/dat/res relay does not create child appliance aliases.
"""

from copy import deepcopy
import json
from time import monotonic

from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
SENSORS = {
    "Pow": 255, "LigPow": 255, "ScrTime": 255, "AutoCtr": 255,
    "TemSor": 65535, "HumSor": 65535, "HCHO": 65535, "PM2P5": 65535,
    "CO2": 65535, "VOC": 65535, "InAirQuality": 255,
    "SensorErr": 255, "BatteryWarn": 255,
}
METADATA = (
    "host", "hid", "lock", "bc", "name", "InHid", "OEEPHid", "HidDownPer",
    "OEEPHidDownPer", "InHidDownPer", "induptype", "outduptype",
    "devinhidownver", "deveephidownver", "time", "rssi",
)
STATUS = frozenset((*SENSORS, *METADATA))
TIMER_OPTIONS = (
    "GetEr", "Pow", "Mod", "SetTem", "WdSpd", "SwUpdn", "SwingLfRig",
    "CoolSvStTemMin", "HeatSvStTemMax", "HumiSvStTemMin", "SvSt", "Blo",
    "SwhSlp", "Quiet", "Air", "LTemDry", "StHt", "Health", "MasSub",
    "MasIDUMod", "OutMID", "host", "hid", "lock", "name", "time",
)


def _integer(value, low=-(1 << 31), high=(1 << 31) - 1):
    if type(value) is not int or not low <= value <= high:
        raise InvalidPacket("W06KV requires a bounded integer")
    return value


def _string(value, maximum, *, empty=True):
    if (not isinstance(value, str) or (not empty and not value)
            or len(value.encode()) > maximum or any(ord(c) < 32 for c in value)):
        raise InvalidPacket("W06KV requires a bounded printable string")
    return value


def _columns(value):
    if (not isinstance(value, list) or len(value) > 50
            or any(not isinstance(v, str) or not v or len(v.encode()) >= 16
                   or "\0" in v for v in value)):
        raise InvalidPacket("W06KV requires at most50 property names under16 bytes")
    return value


def _reply(device, inner, selector, uid, peer):
    size = len(json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode())
    encrypted = (size // 16 + 1) * 16
    if size >= 1500 or 4 * ((encrypted + 2) // 3) + 1 > 1500:
        raise InvalidPacket("W06KV response exceeds the native scratch buffer")
    reply = Reply({"t": "pack", "i": selector, "uid": uid,
                   "cid": device.mac, "tcid": peer}, inner,
                  GENERIC_KEY if selector else device.key, CODEC)
    encode_reply(reply)
    return reply


def _runtime(device, state):
    if "_host" not in state:
        state["_host"] = {
            "host": "dis.gree.com", "name": device.name, "lock": 0,
            "time": "2017-6-15 00:00:00", "city": "", "timers": {},
        }
    return state["_host"]


def _metadata(device, runtime):
    return {"host": runtime["host"], "hid": device.profile.hid,
            "lock": runtime["lock"], "bc": "", "name": device.mac,
            "InHid": "", "OEEPHid": "000000000000+OutEepV0.bin",
            "HidDownPer": 0, "OEEPHidDownPer": 0, "InHidDownPer": 0,
            "induptype": 0, "outduptype": 0, "devinhidownver": "",
            "deveephidownver": 0, "time": runtime["time"], "rssi": -1}


def _timer(inner, update=False):
    if not update:
        _integer(inner.get("ManageType"))
    timer_id = _integer(inner.get("id"), 0, 9 if update else 2)
    record = {"id": timer_id}
    for name in ("enable", "hr", "min", "sec", "tz"):
        record[name] = _integer(inner.get(name)) & 255
    week = inner.get("week")
    if not isinstance(week, list) or len(week) > 7:
        raise InvalidPacket("W06KV requires at most7 weekday values")
    record["week"] = [_integer(v) & 255 for v in week] + [0] * (7 - len(week))
    commands = inner.get("cmd")
    if not isinstance(commands, list) or len(commands) > 1:
        raise InvalidPacket("W06KV timer requires at most1 board command")
    if not commands:
        if update:
            raise InvalidPacket("W06KV update requires a command")
        record["cmd"] = []
        return timer_id, record
    command = commands[0]
    if not isinstance(command, dict):
        raise InvalidPacket("invalid W06KV timer command")
    macs = command.get("mac")
    if not isinstance(macs, list) or len(macs) != 1:
        raise InvalidPacket("W06KV timer requires one board identity")
    mac = _string(macs[0], 20)
    if update:
        options, values = command.get("opt"), command.get("p")
        if (not isinstance(options, list) or len(options) != 1
                or not isinstance(values, list) or len(values) != 1
                or options[0] not in TIMER_OPTIONS):
            raise InvalidPacket("invalid W06KV update command")
        record["cmd"] = [{"mac": [mac], "opt": options[:],
                           "p": [_integer(values[0]) & 255]}]
    else:
        content = command.get("BrdContent")
        if not isinstance(content, list) or len(content) > 3:
            raise InvalidPacket("W06KV board command exceeds3 bytes")
        record["cmd"] = [{"mac": [mac], "BrdNum": _integer(command.get("BrdNum")) & 255,
                           "BrdContent": [_integer(v) & 255 for v in content]}]
    return timer_id, record


class W06KVHost:
    plaintext_types = ("tm", "hbok")

    def validate_state(self, state):
        for name, value in state.items():
            if name not in SENSORS or type(value) is not int or not 0 <= value <= SENSORS[name]:
                raise ValueError("W06KV state requires evidenced raw board readouts")

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        return None

    def advertise(self, device, outer):
        runtime = _runtime(device, device.state)
        inner = {"t": "dev", "cid": device.mac, "bc": "gree", "brand": "gree",
                 "catalog": "gree", "mac": device.mac, "mid": device.mid,
                 "model": "gree", "name": runtime["name"], "series": "gree",
                 "vender": "1", "ver": "V1.1.0.0", "lock": runtime["lock"]}
        return [_reply(device, inner, 1, 0, "")]

    def wlan(self, device, outer):
        return self._plain(device, outer)

    def tm(self, device, outer):
        return self._plain(device, outer)

    def hbok(self, device, outer):
        return self._plain(device, outer)

    def _plain(self, device, outer):
        kind = outer.get("t")
        if kind == "hbok":
            return []
        candidate = deepcopy(device.state)
        runtime = _runtime(device, candidate)
        if kind == "tm":
            runtime["time"] = _string(outer.get("time"), 19, empty=False)
            replies = []
        elif kind == "wlan":
            runtime["ssid"] = _string(outer.get("ssid"), 32)
            _string(outer.get("psw"), 63)
            runtime["host"] = _string(outer.get("host"), 19) or "dis.gree.com"
            # Native ret precedes the network join; no credentials or radio are needed.
            replies = [Reply({"t": "ret", "r": 200, "mac": device.mac})]
        else:
            raise InvalidPacket("unsupported W06KV plaintext operation")
        device.advance(monotonic())
        device.state = candidate
        return replies

    def handle(self, device, outer):
        if outer.get("t") != "pack" or outer.get("tcid") != device.mac:
            raise InvalidPacket("wrong W06KV target")
        selector = _integer(outer.get("i")) & 255
        uid = _integer(outer.get("uid"))
        peer = _string(outer.get("cid"), 19)
        inner = decode_pack(outer, GENERIC_KEY if selector else device.key, CODEC)
        if "mac" in inner and inner["mac"] != device.mac:
            raise InvalidPacket("W06KV child identity is not a root alias")
        if "sub" in inner:
            raise InvalidPacket("W06KV downstream appliance contract is not configured")
        kind = inner.get("t")
        if kind == "subDev":
            # Native request kind7 deliberately has no reply builder.
            _integer(inner.get("i"))
            return []
        candidate = deepcopy(device.state)
        runtime = _runtime(device, candidate)
        if kind == "bind":
            response = {"t": "bindok", "mac": device.mac,
                        "key": device.key.decode("ascii"), "r": 200}
            reply_selector = 1
        elif kind == "status":
            columns = _columns(inner.get("cols"))
            if any(name not in STATUS for name in columns):
                raise InvalidPacket("unknown W06KV status property")
            if not columns:
                return []
            if len(columns) == 50:
                columns = []
            values = {**candidate, **_metadata(device, runtime)}
            if columns and columns[-1] in METADATA:
                # The source chooses its local-only flag from the last requested selector.
                values.update(dict.fromkeys(SENSORS, 0))
            response = {"t": "dat", "r": 200, "cols": columns,
                        "dat": [values[name] for name in columns], "mac": device.mac}
            reply_selector = 0
        elif kind == "cmd":
            options = _columns(inner.get("opt"))
            values = inner.get("p")
            if not isinstance(values, list) or len(options) != len(values):
                raise InvalidPacket("W06KV command arrays must match")
            for name, value in zip(options, values):
                if name in SENSORS:
                    candidate[name] = _integer(value) & SENSORS[name]
                elif name == "lock":
                    runtime[name] = _integer(value)
                elif name in ("host", "name", "time"):
                    runtime[name] = _string(value, 20 if name in ("host", "time") else 100,
                                            empty=name == "name")
                else:
                    raise InvalidPacket("unsupported W06KV host command")
            if len(options) == 50:
                options = []
            reported = _metadata(device, runtime)
            response = {"t": "res", "r": 200, "opt": options,
                        # The original helper mistakenly serializes root MAC for name.
                        "p": [value if name in SENSORS else reported[name]
                              for name, value in zip(options, values)],
                        "val": [value if name in SENSORS else runtime[name]
                                for name, value in zip(options, values)],
                        "mac": device.mac}
            reply_selector = 0
        elif kind == "setT":
            timer_id, record = _timer(inner)
            runtime["timers"][timer_id] = record
            response, reply_selector = {"t": "resT", "r": 200}, 0
        elif kind == "updateT":
            _timer(inner, True)
            raise InvalidPacket("W06KV updateT requires an unqualified mainboard timer response")
        elif kind == "deleteT":
            runtime["timers"].pop(_integer(inner.get("id"), 0, 9), None)
            response, reply_selector = {"t": "resT", "r": 200}, 0
        elif kind == "queryT":
            start, count = _integer(inner.get("index"), 0, 2), _integer(inner.get("count"), 1, 3)
            if start + count >= 4:
                raise InvalidPacket("invalid W06KV timer query window")
            records = [
                {name: record[name] for name in ("id", "enable", "hr", "min", "week", "cmd")}
                for key in sorted(runtime["timers"])
                if start <= key < start + count
                for record in [runtime["timers"][key]]
            ]
            content = (records[0]["cmd"][0]["BrdContent"] if records and records[0]["cmd"] else [])
            content = (content + [0, 0, 0])[:3]
            for record in records:
                # The native list builder reads one shared board-content buffer for every row.
                record["cmd"] = [
                    {"mac": [device.mac], "BrdNum": command["BrdNum"],
                     "BrdContent": content[:command["BrdNum"] if command["BrdNum"] in (1, 2, 3) else 1]}
                    for command in record["cmd"]
                ]
            response = {"t": "listT", "total": len(records), "index": start, "list": records}
            reply_selector = 0
        else:
            return []
        reply = _reply(device, response, reply_selector, uid, peer)
        device.advance(monotonic())
        device.state = candidate
        return [reply]


HANDLER = W06KVHost()
PROFILES = (Profile(id="sim-w06k-v4.4-host", mids=("80241", "80242"),
                    hid="362001061649+U-W06KV4.4.bin",
                    source_sha256="6ac3db6c6b5d72d327171d2bc16223c626301a194511a44931ad86de4135abd8",
                    initial_state={name: 0 for name in SENSORS}, handler=HANDLER,
                    max_request_bytes=1024),)
