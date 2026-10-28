"""Exact-source WB05RT13 V1.04 legacy ECB runtime with bounded backing."""

from ..wire import InvalidPacket, decode_pack
from . import Profile, simulated, wb_raw
from .wb_rt13_legacy import (BUFFER_BYTES, CODEC, GENERIC_KEY, SCAN_KEY,
                             LegacyRT13Handler, packed_reply, source_number)
from .wb_rt13_v110 import legacy_operation


OPERATIONS = frozenset(("bind", "status", "cmd", "upgrade", "setT", "queryT",
                        "deleteT", "updateT", "dump"))


SOURCE_SHA256 = "bc7c2add630e86d938995cc3dd0d1a8094025b15a9b4f5627c302d9fbed4c756"
MID_PRESET = "10001"
HID = "362001065279+U-WB05RT13V1.04.bin"
CONTROLS = wb_raw.EARLY_FIELDS - wb_raw.LOCAL_FIELDS
INITIAL_STATE = {name: value for name, value in simulated.INITIAL_STATE.items()
                 if name in CONTROLS}
EMPTY_FIELDS = wb_raw.EMPTY_FIELDS | {"MOta"}
# MOta is a successful empty status getter, not a command-field classifier.
LOCAL_READ_FIELDS = wb_raw.LOCAL_COMMAND_FIELDS


class WB05RT13V104(LegacyRT13Handler):
    fields = wb_raw.EARLY_FIELDS

    def advertise(self, device, outer):
        inner = {"t": "dev", "cid": device.mac, "bc": "", "brand": "gree", "catalog": "gree",
                 "mac": device.mac, "mid": device.mid, "model": "gree",
                 "name": device.name, "lock": 0, "series": "gree",
                 "vender": "1", "ver": "V1.04"}
        return [packed_reply({"t": "pack", "i": 1, "uid": 0, "cid": "", "tcid": ""},
                             inner, SCAN_KEY)]

    def handle(self, device, outer):
        if outer.get("t") != "pack" or outer.get("tcid") != device.mac:
            raise InvalidPacket("wrong WB05RT13 V1.04 target")
        if any(name not in outer for name in ("i", "uid", "cid", "pack")):
            raise InvalidPacket("incomplete WB05RT13 V1.04 pack route")
        index, uid, peer = outer["i"], outer["uid"], outer["cid"]
        if (type(index) is not int or index not in (0, 1)
                or type(uid) is not int or not -(1 << 31) <= uid < (1 << 32)
                or not isinstance(peer, str)):
            raise InvalidPacket("invalid WB05RT13 V1.04 key selector or route")
        try:
            peer_size = len(peer.encode("utf-8"))
        except UnicodeError as exc:
            raise InvalidPacket("invalid WB05RT13 V1.04 peer identity") from exc
        if peer_size >= 0x40 or "\0" in peer:
            raise InvalidPacket("invalid WB05RT13 V1.04 peer identity")
        uid &= 0xffffffff
        inner = decode_pack(outer, GENERIC_KEY if index else device.key, CODEC,
                            number_parser=source_number)
        kind = inner.get("t")
        if not isinstance(kind, str) or kind not in OPERATIONS:
            return []
        return legacy_operation(
            device, inner, kind, index, uid, peer,
            fields=wb_raw.EARLY_FIELDS, include_timer_name=False,
            fault_display=False, empty_fields=EMPTY_FIELDS,
            local_read_fields=LOCAL_READ_FIELDS)


HANDLER = WB05RT13V104()
PROFILES = (Profile(id="sim-wb05rt13-v1.04", mids=(MID_PRESET,), hid=HID,
                    source_sha256=SOURCE_SHA256, initial_state=INITIAL_STATE,
                    handler=HANDLER, max_request_bytes=BUFFER_BYTES),)
