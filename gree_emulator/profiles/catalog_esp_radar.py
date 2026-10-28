"""Exact ESP32_GR radar LAN caches with explicitly synthetic board readouts.

Zero occupancy/coordinates are chosen raw values, not physical measurements.
The synthetic UART supplies valid-frame flags, zero raw points and no occupants;
cache refresh is synchronous, not a physical sensor/calibration or RTOS model.
Queue timeouts and modes without a producer retain r404. Strict atomic validation
also bounds the five native door records and ten measurement slots.
"""

from datetime import datetime
import re

from ..wire import InvalidPacket, Reply, _json, decode_pack, encode_reply
from . import Profile

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7"

COMMON_COLUMNS = (
    "WorkState", "count", "border", "JFerr", "doorenable", "doortotal", "borderlist",
    "host", "ver", "name", "rssi", "hid", "InHid", "OEEPHid", "InHidDownPer",
    "devinhidownver", "induptype",
)
LATE_COLUMNS = (
    "WorkState", "count", "NumPerson", "Rule", "Week", "timeStatus", "alarmMethod",
    "recStatus", "alarmInterval", "time_range", "border", "JFerr", "doorenable",
    "doortotal", "borderlist", "installtype", "setinstalltype", "host", "ver", "name",
    "rssi", "hid", "InHid", "OEEPHid", "InHidDownPer", "devinhidownver", "induptype",
)
_STRING_COMMANDS = frozenset(("ReportClientID", "time_range", "time", "host", "Week"))


class Radar:
    plaintext_types = ("hbok", "tm")

    def __init__(self, late):
        self.late = late
        self.fields = LATE_COLUMNS if late else COMMON_COLUMNS

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        """Radar intentionally has no room-temperature LAN field."""

    def validate_state(self, state):
        writable = {"doortotal", "installtype"}
        if self.late:
            writable.update(("WorkState", "timeStatus", "alarmMethod", "recStatus", "alarmInterval"))
        for name, value in state.items():
            if name not in writable or type(value) is not int or not 0 <= value <= 255:
                raise ValueError("radar state requires an evidenced writable uint8 field")
            if name == "doortotal" and value > 5:
                raise ValueError("radar board has five door records")

    def _boundary(self, state):
        if not self.late and not state.get("border", 0):
            return [" "]
        doors = [{"x": 0.0, "y": 0.0, "doorposition": 0}
                 for _ in range(state.get("doortotal", 0))]
        result = {}
        install = state.get("installtype", 0)
        if install == 1:
            result.update(left=0.0, right=0.0, farthest=0.0)
        elif install == 2:
            result.update(right=0.0, farthest=0.0)
        result["list"] = doors or [""]
        return result

    def _read(self, device, name):
        if name not in self.fields:
            return 0
        if name == "hid":
            return device.profile.hid
        if name == "name":
            return device.name
        if name == "ver":
            return "V3.0.0"
        if name == "InHid":
            return "362001062639+U-MSTWB8000AV1.0.bin"
        if name in ("induptype", "OEEPHid", "devinhidownver"):
            return ""
        if name == "host":
            return "dis.gree.com" if self.late else "ts.dis.gree.com"
        if name == "borderlist":
            if name in device.state:
                return device.state[name]
            return self._boundary(device.state)
        if name == "WorkState" and not self.late:
            return 1
        if name == "setinstalltype":
            name = "installtype"
        return device.state.get(name, "" if name in ("host", "Week", "time_range") else 0)

    @staticmethod
    def _outer(device, outer, index):
        uid = outer.get("uid", device.state.get("_uid", 0))
        if type(uid) is not int or not -(1 << 31) <= uid < (1 << 31):
            raise InvalidPacket("radar uid requires int32")
        cid = outer.get("cid", device.state.get("_peer_cid", ""))
        if not isinstance(cid, str) or len(cid.encode("utf-8")) > 12:
            raise InvalidPacket("radar peer identity exceeds native 12 bytes")
        return {"t": "pack", "i": index, "uid": uid, "cid": device.mac, "tcid": cid}

    def _reply(self, device, outer, inner, index=0):
        reply = Reply(self._outer(device, outer, index), inner,
                      GENERIC_KEY if index else device.key, CODEC)
        if len(encode_reply(reply)) >= 1024:
            raise InvalidPacket("radar reply exceeds native work buffer")
        return [reply]

    def advertise(self, device, outer):
        return self._reply(device, outer if outer.get("t") == "pack" else {}, {
            "t": "dev", "cid": device.mac, "bc": "gree", "brand": "gree", "catalog": "gree",
            "mac": device.mac, "mid": "80261", "model": "gree", "series": "gree",
            "name": device.name, "vender": "1", "ver": "V3.0.0", "lock": 0,
        }, 1)

    @staticmethod
    def _names(value):
        # shortcut: 32 entries is a chosen safe bound; increase only with buffer qualification.
        if (not isinstance(value, list) or len(value) > 32
                or any(not isinstance(name, str) or not name or len(name.encode("utf-8")) > 63
                       or "\0" in name for name in value)):
            raise InvalidPacket("radar requires a bounded property-name array")
        return value

    def _validate_command(self, name, value):
        string = name in _STRING_COMMANDS and (self.late or name != "Week")
        if string:
            if type(value) is int and -(1 << 31) <= value < (1 << 31):
                value = str(value)
            if not isinstance(value, str) or "\0" in value or len(value.encode("utf-8")) > 31:
                raise InvalidPacket("radar string command exceeds safe bound")
            if name == "time_range":
                if self.late:
                    if not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]-(?:[01][0-9]|2[0-3]):[0-5][0-9]", value):
                        raise InvalidPacket("radar time_range requires HH:MM-HH:MM")
                elif not re.fullmatch(r"[0-9]{1,4}", value):
                    raise InvalidPacket("early radar time_range requires a minute duration string")
            if name == "Week" and not re.fullmatch(r"[1-7](?:,[1-7]){0,6}|", value):
                raise InvalidPacket("radar Week requires at most seven day indices 1..7")
            return value
        if type(value) is int and -(1 << 31) <= value < (1 << 31):
            return value
        if isinstance(value, str) and re.fullmatch(r"[+-]?[0-9]{1,10}", value):
            number = int(value)
            if -(1 << 31) <= number < (1 << 31):
                return number
        raise InvalidPacket("radar scalar command requires int32 or decimal string")

    def _command(self, device, outer, inner):
        names = self._names(inner.get("opt"))
        values = inner.get("p")
        if not isinstance(values, list) or len(names) != len(values):
            raise InvalidPacket("radar command arrays must have equal lengths")
        values = [self._validate_command(name, value) for name, value in zip(names, values)]
        if any(name == "doortotal" and value & 255 > 5 for name, value in zip(names, values)):
            raise InvalidPacket("radar board has five door records")
        state = dict(device.state)
        measure_index = None
        set_install = False
        go_back = 0
        boundary_refresh = False
        for name, value in zip(names, values):
            if name == "ReportClientID":
                state["_report_client"] = value
            elif name == "track":
                state["_track"] = value & 255 if self.late else int(value == 1)
            elif name == "time_range":
                state["_time_range"] = value
                if self.late:
                    state["time_range"] = value
            elif self.late and name == "Week":
                state["Week"] = value
            elif self.late and name in ("WorkState", "timeStatus", "alarmMethod", "recStatus", "alarmInterval"):
                state[name] = value & 255
            elif name == "bordertype":
                state["_border_type"] = value & 7
                measure_index = (measure_index or 0) + (value & 7)
                boundary_refresh = True
            elif name == "doorindex":
                state["_door_index"] = (value - 1) & 7
                measure_index = (measure_index or 0) + ((value - 1) & 7)
                boundary_refresh = True
            elif name == "installtype" or self.late and name == "setinstalltype":
                state["installtype"] = value & 255
                set_install |= name == "setinstalltype"
                boundary_refresh = True
            elif name == "doortotal":
                state["doortotal"] = value & 255
                if self.late or len(names) < 3:
                    state["_border_type"] = 5
                boundary_refresh = True
            elif name == "reset":
                state["_border_type"] = 6
                state["border"] = 0
                boundary_refresh = self.late
                if not self.late:
                    state.update(border=0, installtype=0, doortotal=0, borderlist="")
            elif self.late and name == "border":
                state["_border_type"] = 7
                state["border"] = 1
                boundary_refresh = True
            elif self.late and name == "GoBack":
                go_back = value & 255
            # All remaining names are echoed source no-ops, not supported setters.
        if measure_index is not None and measure_index >= 10:
            raise InvalidPacket("radar measurement index exceeds ten board records")
        if (boundary_refresh and state.get("_border_type", 0) < 6
                and state.get("_border_type", 0) + state.get("_door_index", 0) >= 10):
            raise InvalidPacket("radar UART measurement index exceeds ten board records")
        waiting = measure_index is not None or set_install
        rollback = self.late and go_back == 1
        mode = state.get("_border_type", 0)
        no_completion = measure_index is not None and (mode == 6 or not self.late and mode == 7)
        if measure_index is not None and mode == 6:
            state["border"] = 0
        timeout = waiting and not rollback and (no_completion or not state.get("_queue_complete", True))
        ack_names = list(names)
        ack_values = list(values)
        if waiting and not rollback and not timeout:
            if self.late:
                state["doorenable"] = 1
            if not self.late or state.get("_border_type") != 7 and not set_install:
                ack_names.extend(("borderout", "x", "y"))
                # The source promotes raw float32 coordinates; no unit conversion is inferred.
                ack_values.extend((0, 0.0, 0.0))
                if measure_index is not None and measure_index > 4:
                    ack_names.append("doorposition")
                    ack_values.append(0)
            if measure_index is not None:
                if self.late and mode == 7:
                    state["border"] = 1
                elif not self.late and state.get("_border_type") == 5:
                    state["doorenable"] = 1
                    if state.get("doortotal", 0) == state.get("_door_index", 0) + 1:
                        state["border"] = 1
        if timeout:
            state["doorenable"] = 0
        elif self.late and waiting and (rollback or measure_index is not None and not set_install and mode != 7):
            border_type = state.get("_border_type", 0)
            install_type = state.get("installtype", 0)
            if border_type == 1:
                state["doorenable"] = 0
            if border_type != 1:
                if install_type == 1:
                    border_type = {0: 2, 2: 1}.get(border_type, border_type)
                elif install_type == 2:
                    border_type = {0: 3, 3: 4, 4: 1}.get(border_type, border_type)
                state["_border_type"] = border_type
        if boundary_refresh and not timeout:
            state["borderlist"] = self._boundary(state)
        if self.late and state.get("WorkState", 1) > 1 and any(
                name in ("WorkState", "timeStatus", "alarmMethod", "recStatus",
                         "alarmInterval", "Week", "time_range") for name in names):
            # Normal source record scheduling with the declared zero-occupancy board.
            state["WorkState"] = 3
        response = {"t": "res", "r": 404 if timeout else 200, "mac": device.mac,
                    "opt": ack_names if names else "", "p": ack_values if names else ""}
        replies = self._reply(device, outer, response)
        state["_uid"] = replies[0].outer["uid"]
        state["_peer_cid"] = replies[0].outer["tcid"]
        device.state.update(state)
        return replies

    def handle(self, device, outer):
        if outer.get("t") == "scan":
            return self.advertise(device, outer)
        if outer.get("t") != "pack":
            if outer.get("t") not in ("hbok", "tm"):
                return []
            inner, index, outer = outer, 2, {}
        else:
            if outer.get("tcid", device.mac) != device.mac:
                raise InvalidPacket("radar wrong outer target")
            index = outer.get("i", 2)
            if type(index) is not int:
                raise InvalidPacket("radar key index requires an integer")
            if index == 2:
                payload = outer.get("pack")
                if not isinstance(payload, str):
                    raise InvalidPacket("radar plaintext pack must be a JSON string")
                inner = _json(payload.encode("utf-8"))
            else:
                inner = decode_pack(outer, device.key if index == 0 else GENERIC_KEY, CODEC)
        if "mac" in inner and inner["mac"] != device.mac:
            raise InvalidPacket("radar wrong inner target")
        operation = inner.get("t")
        if operation == "scan" and index == 2:
            replies = self.advertise(device, outer)
            device.state.update(_uid=replies[0].outer["uid"], _peer_cid=replies[0].outer["tcid"])
            return replies
        if operation == "bind" and index == 1:
            replies = self._reply(device, outer, {"t": "bindok", "mac": device.mac,
                                                "key": device.key.decode("ascii"), "r": 200}, 1)
            device.state.update(_uid=replies[0].outer["uid"], _peer_cid=replies[0].outer["tcid"])
            return replies
        if operation == "wlan" and index == 1:
            for name, maximum in (("ssid", 31), ("psw", 63), ("host", 63)):
                value = inner.get(name, "")
                if not isinstance(value, str) or "\0" in value or len(value.encode("utf-8")) > maximum:
                    raise InvalidPacket("radar WLAN field exceeds safe native buffer bound")
            metadata = self._outer(device, outer, 1)
            device.state.update(_uid=metadata["uid"], _peer_cid=metadata["tcid"])
            return [Reply({"t": "ret", "r": 200, "mac": device.mac})]
        if (operation == "loginRes" and index == 1
                or operation in ("hbok", "tm") and index == 2):
            if operation == "loginRes" and "r" in inner and type(inner["r"]) is not int:
                raise InvalidPacket("radar login response requires integer result")
            if operation == "tm":
                value = inner.get("time")
                try:
                    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d", value):
                        raise ValueError("invalid time string")
                    datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
                except ValueError as exc:
                    raise InvalidPacket("radar module time requires a valid calendar timestamp") from exc
            metadata = self._outer(device, outer, index)
            device.state.update(_uid=metadata["uid"], _peer_cid=metadata["tcid"])
            if operation == "tm":
                device.state["_module_time"] = value
            return []
        if index != 0:
            return []
        if operation == "upgrade":
            raise InvalidPacket("radar OTA flashing/cloud downloads are not emulated")
        if operation == "dump" and self.late:
            if "period" in inner and type(inner["period"]) not in (int, float):
                raise InvalidPacket("radar dump period requires a number")
            if "cnt" in inner and type(inner["cnt"]) is not bool:
                self._validate_command("cnt", inner["cnt"])
            metadata = self._outer(device, outer, 0)
            device.state.update(_uid=metadata["uid"], _peer_cid=metadata["tcid"])
            return [Reply({"t": "ret", "r": 200, "mac": device.mac})]
        if operation == "status":
            names = self._names(inner.get("cols"))
            if "track" in inner and type(inner["track"]) is not int:
                raise InvalidPacket("radar track requires integer")
            response = {"t": "dat", "r": 200, "mac": device.mac, "cols": names,
                        "dat": [self._read(device, name) for name in names]}
            replies = self._reply(device, outer, response)
            device.state.update(_uid=replies[0].outer["uid"], _peer_cid=replies[0].outer["tcid"])
            if "track" in inner and (not self.late or inner["track"] == 1):
                if self.late or device.state.get("_track") != 1:
                    device.state["_track"] = int(inner["track"] == 1)
            return replies
        if operation == "cmd":
            return self._command(device, outer, inner)
        return []


PROFILES = (
    Profile("sim-esp32-gr-v1.1", ("80261",), "362001061890+U-ESP32_GRV1.1.bin",
            "cfb8b5e7d3c2646307384c41661ffb46eafe23ec35c7773cc657311120e0abf7",
            {"installtype": 0, "doortotal": 0}, Radar(False), max_request_bytes=1024),
    Profile("sim-esp32-gr-v2.5", ("80261",), "362001061898+U-ESP32_GRV2.5.bin",
            "e28d1233512b289e626c8ff9ade6a47e8a2b074fcd7e198938aae6632ba94ac9",
            {"WorkState": 1, "installtype": 0, "doortotal": 0, "timeStatus": 0,
             "alarmMethod": 0, "recStatus": 0, "alarmInterval": 0},
            Radar(True), max_request_bytes=1024),
)
