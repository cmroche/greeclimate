"""Source-qualified W05R V2.35/W05G V4.3 raw root controllers, not ACs.

R's original command NULL tail and numeric ConBtnName NULL-string precondition
remain native faults. This model validates/executes a finite batch atomically.
RTC, flash, IR learning/sending and BLE queues have explicit in-memory backing;
no physical waveform, calibrated meter, BLE delivery or full boot is claimed.
"""

from copy import deepcopy
from datetime import datetime, timedelta
import json
import re

from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile


GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"
W05R_FIELDS = (
    "Pow", "Mod", "SwhSlp", "SwhSw", "WdSpd", "SetTem", "Blo", "Health",
    "Lig", "Air", "SwUpDn", "SwingLfRig", "SvSt", "SlpMod", "Tur", "Quiet", "StHt",
    "IntradayElect", "IntradayElectPow", "IntradayElectLim", "AutoPowDown",
    "ProTimeReminder", "RealTimePower", "AppTimer", "ProTimeLen", "ProTimePow",
    "Studied", "AddButton", "ConBtnNum", "ConBtnName", "DelButton", "SendButton",
    "Electnumzero", "hid", "RefBtnList", "time",
)
W05R_CONTROLS = frozenset(W05R_FIELDS[:33])
# Tuples preserve callbacks emitting zero or two dat items for one requested name.
W05G_STATUS = {
    "BleLink": ("000000000000",), "Mesh": (0,), "Meshota": ("",), "Reota": (),
    "SubOnline": ("[]",), "Proaddr": ("0000",), "Random": ("00000000",),
    "Unbind": ("000000000000",), "Subcount": (0,), "Pow": (), "Lpn": (),
    "Meshid": ("0000",), "Onoff": ("OK",), "Sceneid": (0,), "Scene": ("FAIL",),
    "Scenecontrol": (0,), "BleKey": ("", 0), "BleStatus": (0,), "AdminRadom": ("",),
    "NoD": (), "apssid": (), "appsw": (), "host": ("",), "name": ("",),
    "lat": ("",), "lon": ("",), "vender": ("",), "bc": (), "mid": (),
    "model": (), "series": (), "brand": (), "catalog": (), "country": (),
    "ver": ("",), "HidSvrVer": (), "InHid": (), "InHidSvrVer": (),
    "OEEPHid": (), "OEEPHidSvrVer": (), "BtHid": ("",),
}
W05G_FIELDS = (
    "BleLink", "Mesh", "Meshota", "Reota", "SubOnline", "Proaddr", "Random",
    "Unbind", "Subcount", "Pow", "Lpn", "Meshid", "Onoff", "Sceneid", "Scene",
    "Scenecontrol", "BleKey", "BleStatus", "AdminRadom", *("NoD",) * 6,
    "apssid", "appsw", "host", "name", "time", "lat", "lon", *("NoD",) * 8,
    "vender", "bc", "mid", "model", "series", "brand", "catalog", "country",
    "hid", "mac", "ver", "HidSvrVer", "InHid", "InHidSvrVer", "OEEPHid",
    "OEEPHidSvrVer", "BtHid", *("NoD",) * 3,
)


def _reply(device, inner, index, uid):
    size = len(json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode())
    encrypted_size = (size // 16 + 1) * 16
    if encrypted_size > 1024 or 4 * ((encrypted_size + 2) // 3) + 1 > 1024:
        raise InvalidPacket("Realtek reply exceeds native crypto/base64 scratch")
    reply = Reply({"t": "pack", "i": index, "uid": uid,
                   "cid": device.mac, "tcid": ""}, inner,
                  GENERIC_KEY if index else device.key, CODEC, trailing_newline=True)
    encode_reply(reply)
    return reply


def _fields(value):
    if (not isinstance(value, list) or len(value) > 128
            or any(not isinstance(name, str) or not name or "\0" in name for name in value)):
        raise InvalidPacket("Realtek requires at most128 nonempty property names")
    return value


def _runtime(device, state):
    if "_runtime" not in state:
        state["_runtime"] = {
            # Epoch begins at the first accepted LAN transaction; elapsed uses the
            # server's monotonic device clock, not host wall-clock/RTC calibration.
            "clock_origin": device.last_step, "clock": "2026-01-01 00:00:00",
            "scratch": {}, "refs": [0] * 25, "labels": [""] * 25,
            "flash_word": 0xffffffff, "learning": 0, "learn_pending": False,
            "send_pending": False, "energy": 0, "timer": None, "persisted": {},
            "address": "000000000000", "unbind": "000000000000", "meshid": "0000",
            "ble_link": "000000000000", "ble_status": 0, "mesh_status": 0,
            "host": "", "lat": "", "lon": "", "host_reconnect": False,
            "registry": [], "children": {}, "current_scene": 0, "scene_result": 0,
            "descriptor_flags": {},
            "selected": 0, "pending": [0] * 32,
            "onoff_queue": [0] * 603, "scene_queue": [0] * 1003,
            "control_header": [0] * 4, "control_frames": [0] * 1250,
            "power_queue": [0] * 43,
        }
    return state["_runtime"]


def _clock(device, runtime):
    try:
        value = datetime.strptime(runtime["clock"], "%Y-%m-%d %H:%M:%S")
        value += timedelta(seconds=int(device.last_step - runtime["clock_origin"]))
    except (ValueError, OverflowError) as exc:
        raise InvalidPacket("Realtek synthetic calendar out of range") from exc
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _records(value, limit):
    try:
        records = json.loads(value)
    except (ValueError, TypeError) as exc:
        raise InvalidPacket("Realtek scene requires encoded JSON array") from exc
    if (not isinstance(records, list) or len(records) > limit
            or any(not isinstance(item, str) or not re.fullmatch(r"[0-9a-fA-F]{7}", item)
                   for item in records)):
        raise InvalidPacket("Realtek scene requires bounded seven-hex records")
    return [[int(item[:2], 16), int(item[2:4], 16),
             *((ord(char) - (0x30 if char < "A" else 0x57)) & 255 for char in item[4:])]
            for item in records]


def _ring(queue, frame, capacity, width, *, deduplicate=False, absolute=False):
    if deduplicate:
        for index in range(queue[0]):
            start = 3 + ((queue[2] + index) % capacity) * width
            if queue[start:start + width] == frame:
                return
    start = queue[1] * width + (0 if absolute else 3)
    # Scene records use absolute base+12, unlike Onoff base+3+9.
    offset = 12 if absolute else 0
    queue[start + offset:start + width] = frame[offset:]
    queue[1] = (queue[1] + 1) % capacity
    if queue[0] < capacity:
        queue[0] += 1
    else:
        queue[2] = (queue[2] + 1) % capacity


def _control(runtime, slot, operation):
    header = runtime["control_header"]
    if not slot or header[0] >= 5:
        return
    start = header[2] * 250
    frame = [0] * 250
    frame[:4] = [0xaa, 0xaa, 0xff, 0xff]
    frame[8:15] = [3, 6, slot & 255, 4, 0x34, operation, slot & 255]
    runtime["control_frames"][start:start + 250] = frame
    header[0] += 1
    header[2] = (header[2] + 1) % 5


def _decimal(value):
    if not re.fullmatch(r"[0-9]+", value) or len(value) > 10 or int(value) > 0x7fffffff:
        raise InvalidPacket("Realtek scene ID requires nonnegative signed32 decimal")
    return int(value) & 65535


class RealtekController:
    routed_selectors = ()

    def __init__(self, *, gateway=False):
        self.gateway = gateway
        self.controls = frozenset(W05G_FIELDS) if gateway else W05R_CONTROLS
        self.fields = W05G_FIELDS if gateway else W05R_FIELDS

    def validate_state(self, state):
        for name, value in state.items():
            if name == "_uid" and type(value) is int and -(1 << 31) <= value < (1 << 31):
                continue
            if name not in self.controls or type(value) is not int or not 0 <= value <= 65535:
                raise ValueError("Realtek state requires modeled uint16 cache fields")

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        """No qualified ambient field or physical thermal model."""

    def advertise(self, device, outer):
        inner = {"t": "dev", "cid": "", "bc": "gree", "catalog": "gree",
                 "mid": device.mid, "lock": 0, "model": "gree", "name": device.name,
                 "series": "gree", "vender": "1" if self.gateway else "2",
                 "ver": "V1.1.13" if self.gateway else "V1.2.1",
                 "brand": "gree", "mac": device.mac}
        return [_reply(device, inner, 1, device.state["_uid"])]

    def _get(self, device, state, runtime, name, *, command=False):
        if name == "hid":
            return [device.profile.hid]
        if name == "time":
            return [_clock(device, runtime)]
        if not self.gateway:
            if name == "RefBtnList":
                return [[item for item in runtime["refs"] if item not in (0, 65535)],
                        [label for item, label in zip(runtime["refs"], runtime["labels"])
                         if item not in (0, 65535)]]
            return [state[name]]
        if name == "mac":
            return [device.mac]
        if command and name in ("BleLink", "Mesh"):
            return [runtime["address"]]
        if name == "BleLink":
            return [runtime["ble_link"]]
        if name == "Mesh":
            return [runtime["mesh_status"]]
        if name == "BleStatus":
            return [runtime["ble_status"]]
        if name == "BleKey":
            return ["", runtime["ble_status"]]
        if name in ("host", "lat", "lon", "Unbind", "Meshid"):
            return [runtime[{"Unbind": "unbind", "Meshid": "meshid"}.get(name, name)]]
        if name in ("Sceneid", "Scenecontrol"):
            return [runtime["current_scene"]]
        if name == "Scene":
            return ["OK" if runtime["scene_result"] != 0 else "FAIL"]
        if name == "SubOnline":
            return [json.dumps([mac for mac, active in runtime["children"].items() if active],
                               separators=(",", ":"))]
        if name == "Subcount":
            return [sum(bool(active) for active in runtime["children"].values())]
        return list(W05G_STATUS[name])

    def _r_command(self, device, state, runtime, name, value):
        if name == "ConBtnName":
            if not isinstance(value, str) or len(value.encode("utf-8")) > 15:
                raise InvalidPacket("Realtek button name requires at most15 UTF8 bytes")
            slot = state["ConBtnNum"]
            if not 1 <= slot <= 25:
                raise InvalidPacket("Realtek button ID requires1..25 before reference access")
            accepted = runtime["refs"][slot - 1] in (0, 65535) and state["AddButton"] == slot
            if accepted:
                runtime["refs"][slot - 1] = slot
                runtime["labels"][slot - 1] = value
            return [slot if accepted else 26, value]
        if type(value) is int:
            if name in W05R_CONTROLS:
                state[name] = value & 65535
            else:
                runtime["scratch"][name] = value & 65535
        cached = state.get(name, runtime["scratch"].get(name, 0))
        if name in W05R_FIELDS[:17] or name == "SendButton":
            runtime["send_pending"] = True
        if name == "ProTimePow":
            state["ProTimeReminder"] = 0
            runtime["timer"] = ({"requested_at": device.last_step,
                                 "duration": state["ProTimeLen"], "power": cached}
                                if cached else None)
            runtime["persisted"] = {field: state.get(field, runtime["scratch"].get(field, 0))
                                    for field in W05R_FIELDS}
        elif name == "Studied" and cached == 2:
            state["Studied"] = 0
            runtime["learning"] = 2
        elif name == "AddButton":
            state["Studied"] = 0
            runtime["learning"], runtime["learn_pending"] = 1, True
            return [26]
        elif name == "DelButton":
            if not 1 <= cached <= 25:
                raise InvalidPacket("Realtek delete button ID requires1..25")
            if runtime["flash_word"] == 0xffffffff:
                runtime["refs"][cached - 1], runtime["labels"][cached - 1] = 0, ""
                return [26]
            return [27]
        elif name == "Electnumzero":
            if cached == 1:
                state[name], runtime["energy"] = 0, 0
            return [0]
        elif name in ("hid", "time"):
            return self._get(device, state, runtime, name)
        return [cached]

    def _g_string(self, device, state, runtime, name, value):
        if name in ("BleLink", "Mesh", "Unbind", "Meshid"):
            width = 4 if name == "Meshid" else 12
            if not re.fullmatch(r"[0-9a-fA-F]{" + str(width) + r"}", value):
                raise InvalidPacket("Realtek address requires exact hexadecimal width")
            field = "meshid" if name == "Meshid" else "unbind" if name == "Unbind" else "address"
            runtime[field] = value.lower()
            if name == "Unbind" and value.lower() in runtime["children"]:
                # Secondary descriptor+8 is independent of its online byte+24.
                runtime["descriptor_flags"][value.lower()] = 0
        elif name in ("host", "lat", "lon"):
            if 1 <= len(value.encode("utf-8")) <= (20 if name == "host" else 10):
                runtime[name] = value
                if name == "host":
                    runtime["host_reconnect"] = True
        elif name == "time":
            try:
                parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
                if parsed.strftime("%Y-%m-%d %H:%M:%S") != value:
                    raise ValueError("noncanonical calendar")
            except ValueError as exc:
                raise InvalidPacket("Realtek time requires real YYYY-MM-DD HH:MM:SS") from exc
            runtime["clock"], runtime["clock_origin"] = value, device.last_step
        elif name in ("Sceneid", "Scenecontrol"):
            scene_id = _decimal(value)
            runtime["current_scene"] = scene_id
            registry = runtime["registry"]
            if name == "Sceneid":
                if scene_id not in registry and len(registry) < 30:
                    registry.append(scene_id)  # Explicit synthetic flash persistence.
                runtime["scene_result"] = 1 if scene_id in registry else -1
                if scene_id in registry:
                    runtime["selected"] = registry.index(scene_id) + 1
            elif scene_id in registry:
                slot = registry.index(scene_id) + 1
                pending = runtime["pending"]
                timer = pending[22] | pending[23] << 8
                if runtime["selected"] != slot or not 0 < timer < 32768:
                    runtime["selected"] = slot
                    _control(runtime, slot, 2)
                    pending[22:24] = [5, 0x40]
        elif name == "Onoff":
            pending = runtime["pending"]
            timer = pending[22] | pending[23] << 8
            slot = runtime["selected"] if 0 < timer < 32768 else 0
            for record in _records(value, 128):
                frame = [0] * 20
                frame[:2] = [0xaa, 0xaa]
                frame[9:17] = [8, 0x20, slot, *record]
                _ring(runtime["onoff_queue"], frame, 30, 20, deduplicate=True)
        elif name == "Scene":
            records = _records(value, 37)
            frame = [0] * 200
            frame[12:15] = [5 * len(records) + 3, 0x21, runtime["selected"]]
            frame[15:15 + 5 * len(records)] = [byte for record in records for byte in record]
            queue = runtime["scene_queue"]
            # Native assembles even when result==0, but advances only if nonzero.
            start = queue[1] * 200
            queue[start + 12:start + 200] = frame[12:]
            if runtime["scene_result"] != 0:
                timer = runtime["pending"][18] | runtime["pending"][19] << 8
                if not 0 < timer < 32768:
                    _control(runtime, runtime["selected"], 3)
                _ring(queue, frame, 5, 200, absolute=True)
            runtime["pending"][18:20] = [3, 0x40]
            runtime["selected"] = 0
        return self._get(device, state, runtime, name, command=True)

    def _g_action(self, device, state, runtime, name):
        if name == "Pow":
            queue = runtime["power_queue"]
            if queue[0] < 10:
                start = 3 + queue[1] * 4
                # Source uses Pow/Lpn low8 and two supplied action words (zero here).
                queue[start:start + 4] = [state["Pow"] & 255, state["Lpn"] & 255, 0, 0]
                queue[0] += 1
                queue[1] = (queue[1] + 1) % 10
            runtime["pending"][26] = 0x45
        elif name in ("BleLink", "Mesh", "Meshota", "Reota"):
            queue = runtime["scene_queue"]
            start = queue[1] * 200
            frame = queue[start:start + 200]
            kind = {"BleLink": 3, "Mesh": 4, "Meshota": 11, "Reota": 12}[name]
            frame[12:14] = [12 if kind == 3 else 8 if kind == 4 else 2, kind]
            if kind in (3, 4):
                address = bytes.fromhex(runtime["address"])
                frame[14:20] = address
                if kind == 3:
                    runtime["ble_link"], runtime["ble_status"] = runtime["address"], 0xfd
                    seconds = int((datetime.strptime(_clock(device, runtime), "%Y-%m-%d %H:%M:%S")
                                   - datetime(1970, 1, 1)).total_seconds()) & 0xffffffff
                    frame[20:24] = list(seconds.to_bytes(4, "big"))
                else:
                    runtime["mesh_status"] = 2
                    runtime["pending"][25] = 0x4a
            _ring(queue, frame, 5, 200, absolute=True)

    def handle(self, device, outer):
        if outer.get("t") != "pack" or outer.get("tcid") != device.mac:
            raise InvalidPacket("wrong Realtek root target")
        index, uid = outer.get("i"), outer.get("uid")
        if (type(index) is not int or not -(1 << 31) <= index < (1 << 31)
                or type(uid) is not int or not -(1 << 31) <= uid < (1 << 31)
                or not isinstance(outer.get("cid", ""), str)):
            raise InvalidPacket("invalid Realtek key selector or route")
        inner = decode_pack(outer, GENERIC_KEY if index else device.key, CODEC)
        # Source R status checks inner.mac, G outer.tcid; cmds use outer.tcid.
        # Additional outer/conflicting-inner guards are explicit safe policy.
        for selector in ("mac", "sub"):
            if (selector in inner and inner[selector] != device.mac
                    and (inner.get("t"), selector) not in self.routed_selectors):
                raise InvalidPacket("conflicting Realtek inner identity")
        kind = inner.get("t")
        if not isinstance(kind, str) or not kind or "\0" in kind:
            raise InvalidPacket("invalid Realtek request type")
        return self._handle(device, inner, uid)

    def _handle(self, device, inner, uid):
        kind = inner["t"]
        pending = deepcopy(device.state)
        runtime = _runtime(device, pending)
        if kind == "bind":
            if inner.get("mac") != device.mac:
                raise InvalidPacket("wrong Realtek bind identity")
            reply = _reply(device, {"t": "bindok", "mac": device.mac, "r": 200,
                                    "key": device.key.decode("ascii")}, 1, uid)
        elif kind == "status":
            if not self.gateway and inner.get("mac") != device.mac:
                raise InvalidPacket("wrong W05R status identity")
            names = _fields(inner.get("cols"))
            selected, values = [], []
            for name in names:
                if name not in self.fields:
                    continue
                selected.extend([name] * (17 if self.gateway and name == "NoD" else 1))
                values.extend(self._get(device, pending, runtime, name))
            reply = _reply(device, {"t": "dat", "mac": device.mac, "r": 200,
                                    "cols": selected, "dat": values}, 0, uid)
        elif kind == "cmd":
            names, values = _fields(inner.get("opt")), inner.get("p")
            if (not isinstance(values, list) or len(names) != len(values)
                    or any(type(value) not in (int, str, list, dict, type(None))
                           or type(value) is int and not -(1 << 31) <= value < (1 << 31)
                           or isinstance(value, str) and "\0" in value for value in values)):
                raise InvalidPacket("Realtek requires bounded signed32/JSON values")
            selected, applied = [], []
            position = 0
            while position < len(names):
                name, value = names[position], values[position]
                if name not in self.fields:
                    position += 1
                    continue
                if self.gateway:
                    if type(value) is int:
                        pending[name] = value & 65535
                        result = [value]
                    elif isinstance(value, str):
                        if name == "Onoff":
                            if (position + 1 >= len(names) or names[position + 1] != "Scenecontrol"
                                    or not isinstance(values[position + 1], str)):
                                raise InvalidPacket("Realtek Onoff requires Scenecontrol string companion")
                            result = self._g_string(device, pending, runtime, "Scenecontrol", values[position + 1])
                            selected.append("Scenecontrol")
                            applied.extend(result)
                            position += 1
                        result = self._g_string(device, pending, runtime, name, value)
                    else:
                        result = []  # Source selects name, invokes no scalar/string callback.
                else:
                    result = self._r_command(device, pending, runtime, name, value)
                selected.append(name)
                applied.extend(result)
                position += 1
            if self.gateway and names and not (names[0] == "Onoff" and isinstance(values[0], str)):
                self._g_action(device, pending, runtime, names[0])
            reply = _reply(device, {"t": "res", "mac": device.mac, "r": 200,
                                    "opt": selected, "p": applied}, 0, uid)
        else:
            device.state["_uid"] = uid
            return []
        pending["_uid"] = uid
        device.state.clear()
        device.state.update(pending)
        return [reply]


PROFILES = (
    Profile(id="sim-w05r-v2.35", mids=("80221",),
            hid="362001061917+W05RV2.35.bin",
            source_sha256="91d53e5611049c71460df61f2a92705a58c67ee4e211bd202dad20da5958a149",
            initial_state={**dict.fromkeys(W05R_FIELDS[:33], 0), "_uid": 0},
            handler=RealtekController(), max_request_bytes=1024),
    Profile(id="sim-w05g-v4.3", mids=("80300",),
            hid="362001061996+U-W05G(RELT)V4.3.bin",
            source_sha256="ddd432e41527e8380a1596bdad85fc0555e9e8ddb253cd5d272e7cfd7fc29d8f",
            initial_state={**dict.fromkeys(W05G_FIELDS, 0), "_uid": 0},
            handler=RealtekController(gateway=True), max_request_bytes=1024),
)
