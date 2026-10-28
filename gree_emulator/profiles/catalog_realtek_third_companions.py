"""Raw W05AN IR controller and W05G mesh root; no typed AC or physical radio.

Board readings, learned-button storage and mesh state are explicitly synthetic.
Strict atomic validation replaces unchecked native writes. AN's inclusive command
tail dereferences a missing JSON item; chosen no-ACK policy is not a full-ROM claim.
"""
from copy import deepcopy
from time import monotonic

from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile
from .catalog_realtek_third_tables import (
    CODEC, KEY, FiniteTables, _clock, _integer, _members, _reply, _text,
)

AN_FIELDS = tuple("""
Pow Mod SwhSlp SwhSw WdSpd SetTem Blo Health Lig Air SwUpDn SwingLfRig SvSt SlpMod Tur Quiet
StHt IntradayElect IntradayElectPow IntradayElectLim AutoPowDown ProTimeReminder RealTimePower
AppTimer ProTimeLen ProTimePow Studied AddButton ConBtnNum ConBtnName DelButton SendButton
Electnumzero hid RefBtnList time
""".split())
G_FIELDS = tuple("""
Ble BleStatus Mesh Mesh_t Meshota Reota SubOnline Random Unbind Subcount Pow Lpn Meshid Onoff
Sceneid Scene Scenecontrol BleKey AdminRadom HfvRadom NoD apssid appsw host name time lat lon
vender bc mid model series brand catalog country hid mac ver HidSvrVer InHid InHidSvrVer OEEPHid
OEEPHidSvrVer BtHid
""".split())
G_READOUTS = {"Ble": "000000000000", "BleStatus": 0, "Mesh": "000000000000", "Mesh_t": 0,
              "Meshota": "", "SubOnline": "[]", "Random": "00000000", "Unbind": "000000000000",
              "Subcount": 0, "Meshid": "0000", "Onoff": "OK", "Scene": "FAIL",
              "BleKey": "", "AdminRadom": "", "HfvRadom": ""}
HIDS = {"an": "362001064472+W05ANV1.08.bin", "g": "362001066542+U-W05G(RELT)V1.3.bin"}
SHAS = {"an": "f45077d6a23c52e52a244bfc35fb2e5ec46b9be817779731df21aa15d1822b3f",
        "g": "de187be0f0ad5bf1100c31831124ac385c4a90d7d725fb01a2908966523ea7ac"}


def _columns(value):
    if not isinstance(value, list) or len(value) > 341:
        raise InvalidPacket("companion column array cannot fit the original 1024-byte request")
    return [_text(name, 1023) for name in value]


def _hex(value, length):
    value = _text(value, length, empty=False)
    if len(value) != length or any(c not in "0123456789abcdefABCDEF" for c in value):
        raise InvalidPacket("companion hexadecimal field has invalid width or digits")
    return value.lower()


class CompanionController(FiniteTables):
    def __init__(self, build):
        self.build = build
        self.w05 = build == "an"
        self.fields = AN_FIELDS if self.w05 else G_FIELDS

    def validate_state(self, state):
        try:
            for name, value in state.items():
                if self.w05 and name in AN_FIELDS[:33]:
                    _integer(value, 0, 65535)
                elif not self.w05 and name in G_READOUTS:
                    if type(G_READOUTS[name]) is int:
                        _integer(value, 0, 255)
                        if name == "Subcount" and value != 0:
                            raise InvalidPacket("empty synthetic mesh topology has zero online children")
                    elif name in ("Ble", "Mesh", "Unbind", "Random", "Meshid"):
                        _hex(value, len(G_READOUTS[name]))
                    elif value != G_READOUTS[name]:
                        raise InvalidPacket("derived mesh readout cannot be overridden")
                else:
                    raise InvalidPacket("only qualified synthetic companion readouts may be configured")
        except InvalidPacket as error:
            raise ValueError(str(error)) from error

    def _runtime(self, device, state):
        runtime = super()._runtime(device, state)
        runtime.setdefault("buttons", {})
        runtime.setdefault("slots", {})
        runtime.setdefault("lat", "")
        runtime.setdefault("lon", "")
        return runtime

    def wlan(self, device, outer):
        coordinates = None
        if not self.w05:
            coordinates = {name: _text(outer.get(name), 10) for name in ("lat", "lon")}
        replies = super().wlan(device, outer)
        replies[0].outer["r"] = 200
        if coordinates is not None:
            self._runtime(device, device.state).update(coordinates)
        return replies

    def advertise(self, device, outer):
        runtime = self._runtime(device, deepcopy(device.state))
        inner = {"t": "dev", "cid": "", "bc": "gree", "catalog": "gree", "mid": device.mid,
                 "model": "gree", "name": runtime["name"], "series": "gree",
                 "vender": "2" if self.w05 else "1", "ver": "V1.2.1" if self.w05 else "V3.4.M",
                 "brand": "gree", "mac": device.mac, "lock": 0}
        return [_reply(device, inner, selector=1)]

    def _status(self, device, state, runtime, names):
        columns, values = [], []
        position = 0
        while position < len(names):
            name = names[position]
            position += 1
            if not self.w05 and (not name or len(name.encode()) >= 16):
                continue
            if name not in self.fields:
                if self.w05:
                    continue
                raise InvalidPacket("unknown mesh property reaches native NULL table tail")
            columns.append(name)
            if self.w05:
                if name in AN_FIELDS[:33]:
                    values.append(state[name])
                elif name == "RefBtnList":
                    if position > 26:
                        raise InvalidPacket("late RefBtnList would repeat the native request loop")
                    buttons = sorted(runtime["buttons"].items())
                    values.extend(([number for number, _ in buttons], [label for _, label in buttons]))
                    position = 26  # Original getter reuses the outer request index for its 25 records.
                elif name == "hid":
                    values.append(HIDS["an"])
                else:
                    values.append(runtime["time"])
            elif name in G_READOUTS:
                values.append(state[name])
            elif name in ("host", "name", "time", "lat", "lon"):
                values.append(runtime[name])
            elif name == "vender":
                values.append("")
            elif name == "hid":
                values.append(HIDS["g"])
            elif name == "mac":
                values.append(device.mac)
            elif name == "ver":
                values.append("")
            elif name == "BtHid":
                values.append("")
            # Other recognized mesh table entries append a column, but no datum.
        return columns, values

    def _command(self, state, runtime, names, values, device=None):
        columns, output = [], []
        for name, value in zip(names, values):
            if name not in self.fields:
                if self.w05:
                    continue
                raise InvalidPacket("unknown mesh property reaches native NULL table tail")
            columns.append(name)
            if type(value) is int:
                _integer(value)
                runtime["slots"][name] = value & 65535
                if self.w05 and name in AN_FIELDS[:33]:
                    state[name] = value & 65535
                    if name == "WdSpd" and state["Mod"] == 2:
                        state[name] = 1
                    if name == "ProTimePow":
                        state["ProTimeReminder"] = 0
                    elif name == "Studied" and state[name] == 2:
                        state[name] = 0
                    elif name == "Electnumzero" and state[name] == 1:
                        state[name] = 0
                output.append(value)
            elif isinstance(value, str):
                if self.w05 and name == "ConBtnName":
                    value = _text(value, 15)
                    number = state["ConBtnNum"]
                    if number == state["AddButton"] and 1 <= number <= 25:
                        runtime["buttons"][number] = value
                elif name == "time" and not self.w05:
                    _clock(value)
                    self._time(state, runtime, value)
                elif not self.w05 and name in ("host", "lat", "lon"):
                    runtime[name] = _text(value, 20 if name == "host" else 10, empty=False)
                elif not self.w05 and name in ("Ble", "Mesh", "Unbind", "Meshid"):
                    state[name] = _hex(value, 4 if name == "Meshid" else 12)
                else:
                    _text(value, 31)
                if not self.w05:
                    _, datum = self._status(device, state, runtime, [name])
                    output.extend(datum)
            else:
                raise InvalidPacket("companion command requires int32 or qualified text")
            if self.w05 and name == "DelButton" and state[name] in runtime["buttons"]:
                del runtime["buttons"][state[name]]
        return columns, output

    def _time(self, state, runtime, value):
        super()._time(state, runtime, value)
        if self.w05:
            for name in AN_FIELDS[:33]:
                state[name] &= 65535

    def handle(self, device, outer):
        _members(outer)
        if outer.get("t") != "pack":
            return super().handle(device, outer)
        if outer.get("tcid") != device.mac:
            raise InvalidPacket("companion request must target this root")
        index, uid = _integer(outer.get("i")), _integer(outer.get("uid", 0))
        inner = decode_pack(outer, KEY if index else device.key, CODEC)
        _members(inner)
        if "sub" in inner or ("mac" in inner and inner["mac"] != device.mac):
            raise InvalidPacket("no companion schema authorizes a typed child route")
        kind = inner.get("t")
        if self.w05 and kind in ("setT", "updateT", "deleteT", "queryT"):
            return super().handle(device, outer)
        state = deepcopy(device.state)
        runtime = self._runtime(device, state)
        now = monotonic()
        self._advance(state, runtime, now)
        reply = None
        if kind == "bind":
            reply = _reply(device, {"t": "bindok", "mac": device.mac, "r": 200,
                                    "key": device.key.decode("ascii")}, uid, 1)
        elif kind == "status":
            columns, values = self._status(device, state, runtime, _columns(inner.get("cols")))
            reply = _reply(device, {"t": "dat", "mac": device.mac, "r": 200,
                                    "cols": columns, "dat": values}, uid)
        elif kind == "cmd":
            names, values = _columns(inner.get("opt")), inner.get("p")
            if not isinstance(values, list) or len(names) != len(values):
                raise InvalidPacket("companion command arrays must match")
            columns, data = self._command(state, runtime, names, values, device)
            if not self.w05:
                reply = _reply(device, {"t": "res", "mac": device.mac, "r": 200,
                                        "opt": columns, "p": data}, uid)
        elif kind == "subDev" and not self.w05:
            page = _integer(inner.get("i", 0))
            reply = _reply(device, {"t": "subList", "r": 200, "c": 0, "i": page, "list": []}, uid)
        elif kind == "meshstatus" and not self.w05:
            addresses, lengths = _columns(inner.get("meshmac")), inner.get("len")
            if not isinstance(lengths, list) or len(addresses) != len(lengths):
                raise InvalidPacket("meshstatus requires matching identity and length arrays")
            for address, length in zip(addresses, lengths):
                _hex(address, 12)
                _integer(length, 0, 24)
            reply = _reply(device, {"t": "substatus", "mac": device.mac,
                                    "meshmac": [], "status": []}, uid)
        elif kind == "surver" and self.w05:
            raise InvalidPacket("original diagnostic reply copies uninitialized serial stack bytes")
        elif kind == "upgrade":
            runtime["upgrade_url"] = _text(inner.get("url"), 159)
            # Exact immediate receipt ACK; physical flash/network upgrade is not simulated.
            reply = Reply({"t": "ret", "r": 200, "mac": device.mac}, trailing_newline=True)
            encode_reply(reply)
        elif kind in ("bin", "dump") and not self.w05:
            # Companion responses need real WB05 serial schema/input, not a fake ACK.
            return []
        else:
            return []
        device.advance(now)
        device.state = state
        return [] if reply is None else [reply]


PROFILES = (
    Profile("sim-w05an-v108-controller", ("80221",), HIDS["an"], SHAS["an"],
            dict.fromkeys(AN_FIELDS[:33], 0) | {"Mod": 1, "WdSpd": 1, "SetTem": 26, "Lig": 1},
            CompanionController("an"), max_request_bytes=1024),
    Profile("sim-w05g-v13-mesh-root", ("80300",), HIDS["g"], SHAS["g"],
            G_READOUTS, CompanionController("g"), max_request_bytes=1024),
)
