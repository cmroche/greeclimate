"""Commercial WB dialects with complete raw tables and labelled synthetic backing."""

import json
import base64
import binascii
from math import floor
from time import monotonic

from ..wire import InvalidPacket, Reply, decode_pack
from . import Profile, simulated, wb_raw
from .wb_brt_fields import FIELDS

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7-nul-input"
HID = "362001065634+U-WB04BRT13V1.50.bin"
SOURCE_SHA256 = "44c79dc1a2dba15123f4ae9cc9a90a14234459ba6aa04df8eee2e98ef406e660"
PACKET_LIMIT = 1460  # Native packet builders0x9b02dee8/0x9b02dd40 use0x5b4.
# The original AC defaults are policy, not a restriction on the native U16 table.
_CONTROL_NAMES = frozenset((
    "Pow", "Mod", "SetTem", "WdSpd", "TemUn", "TemRec", "Air", "Blo",
    "Health", "SwhSlp", "SlpMod", "Lig", "SwingLfRig", "SwUpDn", "Quiet",
    "Tur", "StHt", "SvSt", "Buzzer_ON_OFF",
))
INITIAL_STATE = {name: value for name, value in simulated.INITIAL_STATE.items()
                 if name in _CONTROL_NAMES}


def _columns(names):
    if (not isinstance(names, list) or len(names) > 64
            or any(not isinstance(name, str) or not name.isascii() or "\0" in name
                   for name in names)
            or sum(len(name) + 1 for name in names) > 512):
        raise InvalidPacket("invalid commercial property array")
    return names


def _size(value):
    try:
        return len(json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                              allow_nan=False).encode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise InvalidPacket("invalid commercial text or number") from exc


def _reply(outer, inner, key):
    padded_size = 16 * (_size(inner) // 16 + 1)
    packet_size = _size({**outer, "pack": ""}) + 4 * ((padded_size + 2) // 3)
    if packet_size >= PACKET_LIMIT:
        raise InvalidPacket("commercial reply exceeds native packet buffer")
    return Reply(outer, inner, key, CODEC)


class Commercial:
    def __init__(self, version="1.50", gateway=False, child=False):
        self.version = version
        self.fields = FIELDS[version]
        self.local_fields = wb_raw.LOCAL_COMMAND_FIELDS | ({"ver"} if version != "1.14" else set())
        self.empty_fields = wb_raw.EMPTY_FIELDS | {"MOta", "MidType"}
        self.gateway = gateway
        self.child = child

    def validate_state(self, state):
        if self.gateway:
            if state:
                raise ValueError("commercial host60 has no independent AC state")
            return
        wb_raw.validate_state(state, self.fields)

    def validate_topology(self, device):
        if not self.gateway:
            return
        if len(device.children) != 1:
            raise ValueError(f"commercial host {device.mac} requires exactly one AC child")
        child = device.children[0]
        if child.profile.id != f"sim-wb04brt13-v{self.version}-{child.mid}" or child.mid not in ("6400", "6045", "609d"):
            raise ValueError(f"commercial child {child.mac} requires an evidenced AC child profile")
        if child.mac != device.mac + "00":
            raise ValueError(f"commercial child MAC {child.mac} must be {device.mac}00")

    def thermal_target(self, device):
        return None if self.gateway else simulated.thermal_target(device)

    def encode_room(self, device):
        if self.gateway:
            return
        # InTem is an unsigned16-bit cache field. Celsius here is simulation policy,
        # not a claim about the physical mainboard's uncalibrated sensor encoding.
        device.state["InTem"] = max(0, min(65535, floor(device.room_c)))

    def advertise(self, device, outer):
        if self.child or outer.get("t") != "scan":
            return []
        inner = {
            "t": "dev", "cid": "", "bc": "00000", "brand": "gree",
            "catalog": "gree", "mac": device.mac, "mid": device.mid,
            "model": "Commercial Simulator", "name": device.name, "lock": 0,
            "series": "", "vender": "", "ver": f"V{self.version}", "mqttVer": "",
        }
        if self.gateway:
            inner["subCnt"] = 1
        return [_reply({"t": "pack", "i": 1, "uid": 0, "cid": "", "tcid": ""},
                       inner, GENERIC_KEY)]

    def metadata(self, device, target):
        values = wb_raw.metadata(device)
        values["mid"] = target.mid
        values.pop("MidType")
        if self.version == "1.14":
            values["mqttver"] = ""
        return values

    def local_operation(self, device, inner):
        # Receipts enqueue local work only; no network update, reset or UART hardware runs.
        operation = inner["t"]
        if operation == "upgrade":
            url = inner.get("url")
            if not isinstance(url, str) or "\0" in url or len(url.encode()) >= 120:
                raise InvalidPacket("commercial upgrade requires a bounded url")
            return {"t": "ret", "r": 200}, {"_brt_upgrade_url": url}
        if operation == "reset" and self.version == "1.50":
            if inner.get("mac", "")[:12] != device.mac:
                return None, {}
            return {"t": "res", "r": 200}, {"_brt_reset_pending": True}
        if operation != "binCmd":
            return None, {}
        staged = {}
        keys = ["hex01"] if self.version == "1.14" else ["hex01", "hex6B"]
        keys += [name for name in ("hex6A",) if name in inner and self.version != "1.14"]
        decoded = {}
        for name in keys:
            value = inner.get(name)
            if not isinstance(value, str):
                raise InvalidPacket("commercial binary command requires its source frame fields")
            try:
                decoded[name] = base64.b64decode(value, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise InvalidPacket("invalid commercial base64 frame") from exc
            if len(decoded[name]) > (60 if name in ("hex01", "hex6B") else 512):
                raise InvalidPacket("commercial frame exceeds source storage")
        raw = decoded["hex01"]
        if raw[:2] != b"~~":
            raise InvalidPacket("commercial UART frame requires source header")
        length = (raw[2] if len(raw) > 2 else 0) + 2
        if length > 60:
            raise InvalidPacket("commercial UART frame exceeds source storage")
        frame = bytearray(60)
        frame[:length] = raw[:length].ljust(length, b"\0")
        frame[7] = 175
        staged["_wb_uart_frame"] = bytes(frame)
        for name in ("hex6A", "hex6B"):
            if name in decoded:
                staged["_brt_" + name] = decoded[name]
        if self.version == "1.14" and "ReportClientID" in inner:
            value = inner["ReportClientID"]
            if not isinstance(value, str) or "\0" in value or len(value.encode()) >= 64:
                raise InvalidPacket("invalid commercial report client")
            staged["_wb_report_client"] = value
        return {"t": "res", "r": 200}, staged

    def handle(self, device, outer):
        if self.child:
            return []
        if (outer.get("t") != "pack" or outer.get("tcid") != device.mac
                or type(outer.get("i")) is not int or outer["i"] not in (0, 1)
                or not isinstance(outer.get("cid", ""), str)
                or type(outer.get("uid", 0)) is not int):
            raise InvalidPacket("invalid commercial target or envelope")
        key = GENERIC_KEY if outer["i"] == 1 else device.key
        inner = decode_pack(outer, key, CODEC)
        target = device.children[0] if self.gateway else device
        target_mac = inner.get("mac", inner.get("sub", device.mac))
        allowed_macs = (device.mac, target.mac) if self.gateway else (device.mac,)
        if (target_mac not in allowed_macs
                or ("mac" in inner and inner["mac"] not in allowed_macs)
                or ("sub" in inner and inner["sub"] != target.mac)):
            raise InvalidPacket("conflicting commercial inner identity")
        envelope = {"t": "pack", "i": outer["i"], "uid": outer.get("uid", 0),
                    "cid": outer.get("tcid", ""), "tcid": outer.get("cid", "")}
        operation = inner.get("t")
        if operation == "bind":
            if target_mac != device.mac or "sub" in inner:
                raise InvalidPacket("only the commercial LAN host may bind")
            reply = {"r": 200, "t": "bindok", "mac": device.mac,
                     "key": device.key.decode("ascii")}
        elif operation == "subDev" and self.gateway:
            start = inner.get("i")
            if (target_mac != device.mac or type(start) is not int
                    or not -(2**31) <= start < 2**31):
                raise InvalidPacket("commercial enumeration requires host mac and integer i")
            children = [{"mac": target.mac, "name": "ACUnit", "mid": target.mid,
                         "model": "gree", "lock": 0}] if start == 0 else []
            reply = {"t": "subList", "r": 200, "c": 1, "i": start, "list": children}
        elif operation == "status":
            names = _columns(inner.get("cols", inner.get("opt")))
            staged = (wb_raw.stage_command(target, names, inner.get("p"), self.fields,
                                           clock=True, local_fields=self.local_fields)
                      if "cols" not in inner else {})
            target.profile.handler.encode_room(target)
            cols, values = wb_raw.status(target, names, self.metadata(device, target),
                                         self.fields, staged, empty=self.empty_fields)
            reply = {"t": "dat", "uid": 0, "mac": target_mac,
                     "cid": device.mac, "dat": values, "cols": cols, "r": 200}
            response = _reply(envelope, reply, key)
            target.state.update(staged)
            return [response]
        elif operation == "cmd":
            names = _columns(inner.get("cols", inner.get("opt")))
            values = [0] * len(names) if "cols" in inner else inner.get("p")
            staged = ({} if "cols" in inner else
                      wb_raw.stage_command(target, names, values, self.fields, clock=True,
                                           local_fields=self.local_fields))
            cols, values = wb_raw.command_response(
                target, names, values, staged, local_fields=self.local_fields,
                current=self.metadata(device, target))
            reply = {"t": "res", "mac": target_mac, "p": values, "opt": cols, "r": 200}
            response = _reply(envelope, reply, key)
            target.advance(monotonic())
            target.state.update(staged)
            return [response]
        else:
            reply, staged = self.local_operation(device, inner)
            if reply is None:
                return []
            response = _reply(envelope, reply, key)
            device.state.update(staged)
            return [response]
        return [_reply(envelope, reply, key)]


PROFILES = tuple(
    Profile(f"sim-wb04brt13-v1.50-{mid}", (mid,), HID, SOURCE_SHA256,
            INITIAL_STATE, Commercial(), max_request_bytes=PACKET_LIMIT - 1)
    for mid in ("3019", "3027", "4005")
) + (
    Profile("sim-wb04brt13-v1.50-60", ("60",), HID, SOURCE_SHA256,
            {}, Commercial(gateway=True), max_children=1, max_request_bytes=PACKET_LIMIT - 1),
) + tuple(
    Profile(f"sim-wb04brt13-v1.50-{mid}", (mid,), HID, SOURCE_SHA256,
            INITIAL_STATE, Commercial(child=True), identity_bytes=7,
            parent_profiles=("sim-wb04brt13-v1.50-60",))
    for mid in ("6400", "6045", "609d")
)

# These older builds retain 3027/4005 in their own original mainboard producer.
# No 3019 alias is carried backwards from V1.50's normalization branch.
PROFILES += tuple(
    Profile(f"sim-wb04brt13-v{version}-{mid}", (mid,),
            f"362001065634+U-WB04BRT13V{version}.bin", source,
            {name: value for name, value in INITIAL_STATE.items() if name in FIELDS[version]},
            Commercial(version), max_request_bytes=PACKET_LIMIT - 1)
    for version, source in (
        ("1.14", "62d0760f0f71986517309e71dcf777418d6815550f4558a9e4ddfe8dfb7a4be8"),
        ("1.38", "61b99017a2c1ac759a521548681737d48421be98f8e6d3bcb1c00de52ae79558"),
    )
    for mid in ("3027", "4005")
)

PROFILES += tuple(
    Profile(f"sim-wb04brt13-v{version}-60", ("60",),
            f"362001065634+U-WB04BRT13V{version}.bin", source,
            {}, Commercial(version, gateway=True), max_children=1,
            max_request_bytes=PACKET_LIMIT - 1)
    for version, source in (
        ("1.14", "62d0760f0f71986517309e71dcf777418d6815550f4558a9e4ddfe8dfb7a4be8"),
        ("1.38", "61b99017a2c1ac759a521548681737d48421be98f8e6d3bcb1c00de52ae79558"),
    )
)

PROFILES += tuple(
    Profile(f"sim-wb04brt13-v{version}-{mid}", (mid,),
            f"362001065634+U-WB04BRT13V{version}.bin", source,
            {name: value for name, value in INITIAL_STATE.items() if name in FIELDS[version]},
            Commercial(version, child=True), identity_bytes=7,
            parent_profiles=(f"sim-wb04brt13-v{version}-60",))
    for version, source, mids in (
        ("1.14", "62d0760f0f71986517309e71dcf777418d6815550f4558a9e4ddfe8dfb7a4be8", ("6400",)),
        ("1.38", "61b99017a2c1ac759a521548681737d48421be98f8e6d3bcb1c00de52ae79558",
         ("6400", "6045", "609d")),
    )
    for mid in mids
)
