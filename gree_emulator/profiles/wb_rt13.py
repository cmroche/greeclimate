"""WB05RT13 complete standalone raw cache with a synthetic AC/mainboard.

UDP uses authenticated GCM; discovery alone uses the separate ECB wrapper.
The source transports TemSen's unsigned UART byte unchanged. Celsius+40 below
is a chosen common-UART simulation policy, not same-mainboard calibration.
"""

import json
from time import monotonic

from ..wire import InvalidPacket, Reply, decode_pack
from . import Profile, simulated, wb_operations, wb_raw
from .wb_rt13_legacy import source_number, source_values


SCAN_KEY = b"a3K8Bx%2r8Y7#xDh"
GENERIC_KEY = b"{yxAHAY_Lm6pbC/<"
CODEC = "aes-gcm"
CONTROLS = wb_raw.RT13_FIELDS - wb_raw.LOCAL_FIELDS - {"FaultDisplay"}
INITIAL_STATE = {name: value for name, value in simulated.INITIAL_STATE.items()
                 if name in CONTROLS}
IDENTITY_STATE = frozenset(("_wb_dev_mid_raw", "_wb_dev_mid_buffer",
                           "_wb_dev_mid_retry_count"))
# The standalone V1.45 baseline is post-CASE4 retry fallback.
V145_INITIAL_STATE = INITIAL_STATE | {
    "_wb_dev_mid_raw": 0x10001, "_wb_dev_mid_buffer": "10001",
    "_wb_dev_mid_retry_count": 6,
}
BUILDS = (
    ("1.45", "2f12c03c97e4e7302acbc8ee72cda18e31e7d9843519d5a3fb1bdcb1a4f2ffec", 1460),
    ("1.54", "86799311e40abaa97be624e11d8e16c45cafb7dd113b8b690728d075d77c8a39", 1536),
    ("1.64", "c4b744a28a5a6b2d2d7ace4a0a2845a336ce629a72367af41bde708f0bd1dbc1", 1536),
)


def _metadata(device):
    # Identity inputs differ by build; other advertisement fields are explicit synthetic choices.
    mid = device.mid
    if device.profile.source_sha256 == BUILDS[0][1]:
        raw = device.state.get("_wb_dev_mid_raw", 0)
        if raw:
            mid = f"{raw:x}"
            device.state["_wb_dev_mid_buffer"] = mid
        elif device.state.get("_wb_dev_mid_retry_count", 0) > 5:
            raw = 0x10001
            mid = f"{raw:x}"
            device.state["_wb_dev_mid_raw"] = raw
            device.state["_wb_dev_mid_buffer"] = mid
        else:
            # Cold-start contents are unresolved; the empty value is only the model boundary.
            mid = device.state.get("_wb_dev_mid_buffer", "")
    return {"hid": device.profile.hid, "mid": mid, "ver": "V3.4.M",
            "vender": "1", "name": device.name, "bc": "0000000000000",
            "host": "", "ModelType": "0", "lock": 0}


def _status_metadata(device):
    metadata = wb_raw.metadata(device, fault_display=True)
    if device.profile.source_sha256 == BUILDS[0][1]:
        # The getter points at a separate zero-filled RAM target; indirect writes are unresolved.
        metadata["mid"] = ""
    return metadata


def _reply(device, inner, index, uid, peer):
    # The LAN serializer stages authenticated output in a 1000-byte scratch buffer.
    if len(json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode()) >= 1000:
        raise InvalidPacket("WB05RT13 reply exceeds the firmware scratch buffer")
    return Reply({"t": "pack", "i": index, "uid": uid,
                  "cid": device.mac, "tcid": peer}, inner,
                 GENERIC_KEY if index else device.key, CODEC)


def _columns(value):
    # Reject unsafe native buffer overflow rather than reproducing memory corruption.
    if (not isinstance(value, list) or len(value) > 64
            or any(not isinstance(name, str) or not name or "\0" in name for name in value)
            or sum(len(name.encode()) + 1 for name in value) >= 512):
        raise InvalidPacket("invalid WB05RT13 property array")
    return value


class WB05RT13:
    def validate_state(self, state):
        identity = {name: value for name, value in state.items() if name in IDENTITY_STATE}
        if ("_wb_dev_mid_raw" in identity
                and (type(identity["_wb_dev_mid_raw"]) is not int
                     or not 0 <= identity["_wb_dev_mid_raw"] <= 0xffffffff)):
            raise ValueError("WB discovery MID raw value must be uint32")
        if ("_wb_dev_mid_buffer" in identity
                and (not isinstance(identity["_wb_dev_mid_buffer"], str)
                     or "\0" in identity["_wb_dev_mid_buffer"]
                     or len(identity["_wb_dev_mid_buffer"].encode()) > 15)):
            raise ValueError("WB discovery MID buffer exceeds its source capacity")
        if ("_wb_dev_mid_retry_count" in identity
                and (type(identity["_wb_dev_mid_retry_count"]) is not int
                     or not 0 <= identity["_wb_dev_mid_retry_count"] <= 255)):
            raise ValueError("WB discovery MID retry count must be uint8")
        wb_raw.validate_state({name: value for name, value in state.items()
                               if name not in IDENTITY_STATE}, wb_raw.RT13_FIELDS)

    def thermal_target(self, device):
        return simulated.thermal_target(device)

    def encode_room(self, device):
        simulated.encode_room(device, 40, 255)

    def advertise(self, device, outer):
        metadata = _metadata(device)
        inner = {"t": "dev", "cid": device.mac, "bc": metadata["bc"],
                 "brand": "gree", "catalog": "gree", "mac": device.mac,
                 "mid": metadata["mid"], "model": "gree", "name": device.name,
                 "lock": 0, "series": "gree", "vender": metadata["vender"],
                 "ver": metadata["ver"], "ModelType": metadata["ModelType"],
                 "hid": device.profile.hid}
        return [Reply({"t": "pack", "i": 1, "uid": 0, "cid": "", "tcid": ""},
                      inner, SCAN_KEY, "aes-ecb-pkcs7")]

    def handle(self, device, outer):
        if outer.get("t") != "pack" or outer.get("tcid") != device.mac:
            raise InvalidPacket("wrong WB05RT13 target")
        index = outer.get("i")
        uid, peer = outer.get("uid", 0), outer.get("cid", "")
        if (type(index) is not int or index not in (0, 1)
                or type(uid) is not int or not isinstance(peer, str)):
            raise InvalidPacket("invalid WB05RT13 key selector or route")
        v145 = device.profile.source_sha256 == wb_operations.RT13_V145_SHA256
        inner = decode_pack(outer, GENERIC_KEY if index else device.key, CODEC,
                            number_parser=source_number if v145 else None)
        if v145 and "p" in inner:
            inner["p"] = source_values(inner["p"])
        kind = inner.get("t")
        for selector in ("mac", "sub"):
            if selector not in inner or inner[selector] == device.mac:
                continue
            v145_mac = (selector == "mac"
                        and device.profile.source_sha256 == wb_operations.RT13_V145_SHA256)
            invalid_bind_mac = (kind == "bind" and v145_mac
                                and (not isinstance(inner[selector], str)
                                     or not inner[selector]
                                     or "\0" in inner[selector]
                                     or len(inner[selector].encode()) > 31))
            if not (v145_mac and kind == "reset" or invalid_bind_mac):
                raise InvalidPacket("conflicting WB05RT13 inner identity")
        if kind == "bind":
            return [_reply(device, {"r": 200, "t": "bindok", "mac": device.mac,
                                    "key": device.key.decode("ascii")}, index, uid, peer)]
        if kind == "status":
            columns = _columns(inner.get("cols", inner.get("opt")))
            staged = ({} if "cols" in inner else wb_raw.stage_command(
                device, columns, inner.get("p"), wb_raw.RT13_FIELDS, clock=True))
            wb_operations.stage_v145_report_client(device, staged)
            metadata = _status_metadata(device)
            metadata["time"] = staged.get("_wb_time", metadata["time"])
            selected, values = wb_raw.status(
                device, columns, metadata, wb_raw.RT13_FIELDS, staged)
            reply = _reply(device, {"t": "dat", "uid": 0, "mac": device.mac,
                                    "cid": device.mac, "dat": values,
                                    "cols": selected, "r": 200}, index, uid, peer)
            if staged:
                device.advance(monotonic())
                device.state.update(staged)
            return [reply]
        if kind == "cmd":
            options = _columns(inner.get("cols", inner.get("opt")))
            values = inner.get("p")
            if "cols" in inner:
                if any(name not in wb_raw.RT13_FIELDS | wb_raw.LOCAL_FIELDS for name in options):
                    raise InvalidPacket("unsupported WB05RT13 command field")
                staged, values = {}, [0] * len(options)
            else:
                staged = wb_raw.stage_command(device, options, values, wb_raw.RT13_FIELDS,
                                              clock=True)
            wb_operations.stage_v145_report_client(device, staged)
            options, values = wb_raw.command_response(
                device, options, values, staged, fault_display=True,
                current=_status_metadata(device))
            reply = _reply(device, {"t": "res", "mac": device.mac,
                                    "p": values, "opt": options, "r": 200}, index, uid, peer)
            # This immediate synthetic report is not an independent UART confirmation.
            device.advance(monotonic())
            device.state.update(staged)
            return [reply]
        if wb_operations.supports(device.profile.source_sha256, kind):
            response, staged = wb_operations.operation(device, inner)
            reply = _reply(device, response, index, uid, peer) if response is not None else None
            if kind == "freqCount" and staged:
                device.advance(monotonic())
            device.state.update(staged)
            return [reply] if reply is not None else []
        return []


HANDLER = WB05RT13()
PROFILES = tuple(Profile(id=f"sim-wb05rt13-v{version}", mids=("10001",),
                         hid=f"362001065279+U-WB05RT13V{version}.bin", source_sha256=sha,
                         initial_state=(V145_INITIAL_STATE if sha == BUILDS[0][1]
                                        else INITIAL_STATE), handler=HANDLER,
                         max_request_bytes=limit)
                 for version, sha, limit in BUILDS)

# Independently verified historical images: identical ARM code/RAM descriptors to
# c4b744, with only build/version/HID strings changed in read-only data.
PROFILES += tuple(
    Profile(id=profile_id, mids=("10001",),
            hid=f"362001065279+U-WB05RT13V{version}.bin", source_sha256=sha,
            initial_state=INITIAL_STATE, handler=HANDLER, max_request_bytes=1536)
    for profile_id, version, sha in (
        ("sim-wb05rt13-v1.57", "1.57",
         "e1d186072abfd51e71874fe6904cca132f22e6ebaaef9a0cac39f59de7194105"),
        ("sim-wb05rt13-v1.54-c9e8d4b563f7", "1.54",
         "c9e8d4b563f7573c553d5004809080ed53b66d5d1533c76f7c877fcc79242b46"),
    )
)
