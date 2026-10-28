"""Source-bounded ZTS31A3.10 host, not an appliance/plugin or vendor flash.

The synthetic host cache and absent-mid_config fallback registry reset on restart.
Peer roles follow the original adapter, not appliance support or emitted MIDs.
Downstream binary/scene/board work never receives an invented companion ACK.
"""

from copy import deepcopy
import json
from time import monotonic

from ..wire import InvalidPacket, Reply, _json, decode_pack, encode_reply
from . import Profile

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"
CODEC = "aes-ecb-pkcs7-lf"
HID = "362001068423+ZTS31AV3.10.img"
SOURCE_SHA256 = "e90804f455d9c6a93e9c56e6b3da6f78f4f64a5ab960bf6fb3b0d9b6bff295a1"
METADATA = ("host", "ver", "hid", "mid", "rssi", "time", "active")
UBIND_FIELDS = (
    "mid", "ver", "devkey", "lock", "hid", "homeId", "devCnt", "roomList",
    "dis", "scene", "Gnetkey", "province", "city", "domain", "lng", "lat",
    "GnetID", "idSync", "pairMod", "soVer", "orderID", "nluHost", "nluPort",
)
# Original39-entry table, not a list of appliance capabilities.
DISPATCH = {
    "ubind": 1, "syncdev": 0, "syncdevlist": 0, "status": 0,
    "binstatus": 0, "dat": 2, "connect": 2, "cmd": 2, "jsoncmd": 2,
    "hb": 1, "utm": 0, "ret": 0, "res": 0, "devcheck": 0,
    "upgrade": 2, "updevlist": 0, "jsonstatus": 0, "configstatus": 0,
    "addtiming": 2, "deletetiming": 2, "updatetiming": 2,
    "uproominfo": 2, "checksub": 2, "devlistpush": 0, "roomlistpush": 0,
    "devonlineres": 0, "devonlinedone": 0, "checkresres": 0,
    "checkresdone": 0, "binsubstatus": 1, "binsubevent": 1,
    "syncpersistent": 0, "devlistpushres": 0, "485configure": 0,
    "scenesinglepush": 0, "switchbindpush": 2, "activation": 0,
    "checksceneexe": 0, "updownflag": 0,
}


def _integer(value):
    if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
        raise InvalidPacket("ZTS requires a signed32 integer")
    return value


def _text(value, capacity):
    if (not isinstance(value, str) or len(value.encode()) >= capacity
            or any(ord(char) < 32 for char in value)):
        raise InvalidPacket("ZTS requires a bounded printable string")
    return value


def _members(value):
    # cJSON's ordinary lookup is case-insensitive. Reject ambiguous case aliases.
    result = {}
    for key, item in value.items():
        folded = key.lower()
        if folded in result:
            raise InvalidPacket("ambiguous ZTS member casing")
        result[folded] = item
    return result


def _names(value):
    if not isinstance(value, list) or len(value) > 128:
        raise InvalidPacket("ZTS requires a bounded column array")
    return [_text(item, 128) for item in value]


def _rooms(value, *, ids=True):
    if not isinstance(value, list):
        raise InvalidPacket("ZTS roomList must be an array")
    rooms = []
    for item in value[:200]:
        if not isinstance(item, dict):
            raise InvalidPacket("ZTS room must be an object")
        fields = _members(item)
        rooms.append({"id": (_integer(fields.get("id")) & 0xffffffff) if ids else 0,
                      "sId": _integer(fields.get("sid")) & 0xffffffff,
                      "name": _text(fields.get("name"), 128)})
    return rooms


def _role(mid):
    # Original product_get_subdev_type0x378ea, only when mid_config is absent.
    if mid in ("70205", "70601", "80405"):
        return {"70205": 5, "70601": 6, "80405": 8}[mid]
    if mid in ("809031", "6400"):
        return 2
    if (mid == "70314" or mid.startswith("80")) and mid != "807001":
        return 4
    if mid.startswith(("82", "28")) or mid == "807001":
        return 3
    if mid.startswith("60") or mid in ("6200", "6301"):
        return 1
    return 0


def _adapt(peer, state):
    config = state["mid_config"]
    if config is None:
        peer["role"] = _role(peer["mid"])
    else:
        entry = next((value for mid, value in config.items() if mid.lower() == peer["mid"].lower()), {})
        if "type_value" in entry:
            peer["role"] = entry["type_value"]


def _switch_name(action):
    if not isinstance(action, dict):
        return None
    options = _members(action).get("opt")
    if not isinstance(options, list):
        return None
    encoded = json.dumps(options, ensure_ascii=False, separators=(",", ":"))
    start = encoded.find("Sw")
    if start < 0:
        return None
    end = encoded.find(",", start)
    if end < 0:
        end = encoded.find("]", start)
    return _text(encoded[start:end], 64) if end >= 0 else None


def _peer(mac):
    return {"mac": mac, "role": 0, "key": "", "mid": "", "ver": "", "hid": "",
            "lock": 0, "scene": 0, "roomId": 0, "macId": 0, "name": "", "vender": "",
            "online": 0, "RSSI": 0}


def _put_peer(state, peer):
    peers = state.setdefault("_peers", {})
    new = peer["mac"] not in peers
    if new and len(peers) >= 999:
        raise InvalidPacket("ZTS native peer registry is full")
    # Original insertion swaps the last registered miniApp, not every role5 peer.
    if new and any(item["role"] == 5 for item in peers.values()):
        last = peers.pop(next(reversed(peers)))
        peers[peer["mac"]] = peer
        peers[last["mac"]] = last
    else:
        peers[peer["mac"]] = peer


def _import_record(item, state, *, adapt):
    if not isinstance(item, dict):
        raise InvalidPacket("ZTS device record must be an object")
    fields = _members(item)
    mac = _text(fields.get("mac"), 17)
    if not mac:
        raise InvalidPacket("ZTS device record requires an identity")
    peer = state.get("_peers", {}).get(mac, _peer(mac))
    for name, capacity in (("mid", 16), ("hid", 40), ("key", 17), ("ver", 16),
                           ("vender", 16), ("name", 128)):
        peer[name] = _text(fields.get(name), capacity)
    if len(peer["key"]) not in (0, 16) or not peer["key"].isascii():
        raise InvalidPacket("ZTS imported key must be empty or contain16 ASCII bytes")
    peer["roomId"] = _integer(fields.get("roomid")) & 0xffffffff
    if "macid" in fields:
        peer["macId"] = _integer(fields["macid"]) & 65535
    if adapt and peer["role"] not in (1, 2):
        _adapt(peer, state)
    _put_peer(state, peer)
    return peer


def _reply(device, inner, peer, selector, msg_id):
    port = None if peer["role"] == 5 else 5001
    if selector == 2:
        reply = Reply(inner, destination_port=port)
    else:
        if selector == 0 and len(peer["key"]) != 16:
            raise InvalidPacket("ZTS response has no registered private key")
        outer = {"t": "pack", "i": selector, "cid": device.mac,
                 "tcid": peer["mac"], "msgId": msg_id}
        if peer["role"] == 3:
            # Explicit synthetic connected-network state, not an actual cloud link.
            outer["enNet"] = 0
        reply = Reply(outer, inner, GENERIC_KEY if selector == 1 else peer["key"].encode(),
                      CODEC, destination_port=port)
    # Deliberate safe model bound, not the source's expanding response buffer.
    if len(encode_reply(reply)) > 65507:
        raise InvalidPacket("ZTS reply exceeds UDP payload capacity")
    return reply


def _persist_page(state, selector, index):
    records = list(state.get("_peers", {}).values())
    if selector in (0, 1, 2, 12):
        # Separate CAN/485 linking lists require companion enumeration input.
        selected = []
    else:
        selected = [item for item in records if (
            (0 <= selector < 15 and item["role"] == selector)
            or (selector == 50 and item["role"] in (3, 6))
            or (selector == 52 and item["role"] in (3, 6, 9))
            or (selector == 70 and item["role"] == 4 and item["mid"] == "80501"))]
    if index >= len(selected):
        return None, len(selected)
    page = [{name: item[name] for name in
             ("mac", "macId", "name", "roomId", "mid", "hid", "key", "ver", "vender")}
            for item in selected[index:index + 10]]
    return {"t": "devListPush", "i": index, "sum": len(selected), "devList": page}, len(selected)


def _arm_retry(state, cid):
    state.update(_retry=cid, _retry_remaining=10, _retry_next=monotonic() + 1)


class ZtsHost:
    accept_empty_target = True

    def handle_from(self, device, outer, address):
        return self.handle(device, outer, address=address)

    def tick(self, device, now):
        state = device.state
        result = []
        if now >= state.setdefault("_hb_next", now + 46):
            # Synthetic Linux times() clock at100Hz; original threshold9001 ticks.
            for peer in state.get("_peers", {}).values():
                if peer["role"] in (3, 8, 9, 11):
                    elapsed = (int(now * 100) - int(peer.get("hb_ticks", 0) * 100)) & 0xffffffff
                    peer["online"] = int(elapsed < 9001)
            state["_hb_next"] = now + 46
        sync_cid = state.get("_sync_retry")
        if sync_cid is not None and now >= state["_sync_next"]:
            count = state.get("_miniprocurCnt", 0)
            if count < state.get("_miniproCnt", 0) and state.get("_sync_repeats", 0) < 5:
                if count == state.get("_sync_previous", -1):
                    state["_sync_repeats"] = state.get("_sync_repeats", 0) + 1
                else:
                    state["_sync_previous"], state["_sync_repeats"] = count, 0
                peer = state.get("_peers", {}).get(sync_cid)
                if peer is not None and "_address" in peer:
                    reply = _reply(device, {"t": "syncDev", "cid": device.mac, "i": count},
                                   peer, 0, state.get("_msgId", 0))
                    result.append((reply, peer["_address"]))
                state["_sync_next"] = now + 1
            else:
                state.update(_sync_retry=None, _sync_previous=-1, _sync_repeats=0)
        cid = state.get("_retry")
        if cid is None or now < state["_retry_next"]:
            return result
        peer = state.get("_peers", {}).get(cid)
        if peer is None or "_address" not in peer:
            state["_retry"] = None
            return result
        reply = _reply(device, peer["data"], peer, 0, state.get("_msgId", 0))
        state["_retry_next"] = now + 1
        state["_retry_remaining"] -= 1
        if not state["_retry_remaining"]:
            state["_retry"] = None
        return result + [(reply, peer["_address"])]

    def validate_state(self, state):
        for name, value in state.items():
            try:
                if name in ("host", "time", "Gnetkey", "orderID", "nluHost"):
                    capacity = {"host": 33, "time": 256, "Gnetkey": 9, "orderID": 64, "nluHost": 33}[name]
                    _text(value, capacity)
                elif name in ("nluPort", "nluinfo_flag"):
                    _integer(value)
                    if not 0 <= value <= (65535 if name == "nluPort" else 1):
                        raise InvalidPacket("ZTS NLU cache exceeds its source width")
                elif name in ("active", "matching", "activation"):
                    _integer(value)
                    if name == "matching" and not 0 <= value <= 255:
                        raise InvalidPacket("ZTS match cache requires uint8")
                    if name == "activation" and value not in (0, 1, 2):
                        raise InvalidPacket("ZTS activation requires0/1/2")
                elif name == "mid_config":
                    if value is not None:
                        if not isinstance(value, dict) or len(value) > 999:
                            raise InvalidPacket("ZTS mid_config must be null or a bounded object")
                        for mid, entry in value.items():
                            _text(mid, 16)
                            if not isinstance(entry, dict) or set(entry) - {"type_value", "timers_max"}:
                                raise InvalidPacket("ZTS modeled MID configuration fields are type_value/timers_max")
                            for field, number in entry.items():
                                _integer(number)
                                if field == "type_value" and not 0 <= number <= 14:
                                    raise InvalidPacket("ZTS configured peer role requires0..14")
                else:
                    raise InvalidPacket("unsupported ZTS initial cache field")
            except InvalidPacket as exc:
                raise ValueError(str(exc)) from exc

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        return None

    def advertise(self, device, outer):
        # scan exists only in DATA_TYPE_ONLY_SEND, never as an inbound request.
        return []

    def _ubind(self, device, state, fields, peer):
        preserve_online = peer["role"] == 6
        if peer["role"] == 3 and peer.get("released") and "devkey" in fields:
            if fields["devkey"] == peer["key"]:
                return None
            peer["released"] = False
        if peer["mac"] == "miniApp":
            peer["role"] = 5
        mini_input = peer["role"] == 5
        authorized = peer["role"] == 5 and (
            state["matching"] in (2, 3)
            or bool(state["Gnetkey"]) and fields.get("gnetkey") == state["Gnetkey"])
        strings = {"mid": 16, "ver": 16, "devkey": 17, "hid": 40,
                   "dis": 33, "Gnetkey": 9, "province": 64, "city": 64,
                   "domain": 64, "lng": 64, "lat": 64, "soVer": 128,
                   "orderID": 64, "nluHost": 33}
        values = {}
        for name in UBIND_FIELDS:
            key = name.lower()
            if key not in fields:
                continue
            value = fields[key]
            if name == "roomList":
                values[name] = _rooms(value)
            elif name in strings:
                values[name] = _text(value, strings[name])
            else:
                values[name] = _integer(value)
        for name in ("mid", "ver", "hid"):
            if name in values:
                peer[name] = values[name]
        if "devkey" in values:
            peer["key"] = values["devkey"]
        for name in ("lock", "scene"):
            if name in values:
                peer[name] = values[name] & 255
        if "devCnt" in values:
            state["_miniproCnt"] = values["devCnt"] & 0xffffffff
            state["_miniprocurCnt"] = 0
        if state["nluinfo_flag"] != 1:
            if "nluPort" in values:
                # Original passes NULL to strcmp before its NULL guard.
                raise InvalidPacket("unsafe native NLU port-only setter")
            if "nluHost" in values:
                state["nluHost"] = values["nluHost"]
        if authorized:
            for name in ("homeId", "roomList", "Gnetkey", "province", "city", "domain",
                         "lng", "lat", "GnetID", "orderID"):
                if name in ("province", "city", "domain", "lng", "lat", "orderID") and values.get(name) == "":
                    continue
                if name in values:
                    state[name] = values[name] & 0xffffffff if name in ("homeId", "GnetID") else values[name]
            if "dis" in values:
                state["host"] = values["dis"]
        if peer["role"] != 5:
            _adapt(peer, state)
        if not peer["role"] or ("GnetID" in values and mini_input and not authorized):
            return None
        if "GnetID" in values and not mini_input:
            peer["macId"] = values["GnetID"] & 65535
        if authorized and "GnetID" in values and state["matching"] in (2, 3):
            state["matching"] = 1
            state["activation"] = 1
        if peer["role"] == 5:
            peer["key"] = device.key.decode("ascii")
        if len(peer["key"]) != 16 or not peer["key"].isascii():
            raise InvalidPacket("ZTS peer requires an explicit16-byte ASCII devkey")
        if not preserve_online:
            peer["online"] = 1
        peer["hb_ticks"] = monotonic()
        _put_peer(state, peer)
        peers = state["_peers"]
        response = {"t": "UBindok", "mac": device.mac, "mid": "70501", "hid": HID,
                    "ver": "V3.2.MF"}
        if peer["role"] == 5:
            response.update(orderID=state["orderID"], fastconMac=device.mac,
                            key=peer["key"], devCnt=len(peers) - 1, Gnetkey=state["Gnetkey"])
            if values.get("idSync") == 1:
                response["fIdList"] = [state.get("GnetID", 0)] + [
                    item["macId"] for item in peers.values() if item["role"] in (4, 6)]
                response["bIdList"] = [
                    item["macId"] for item in peers.values() if item["role"] == 3 and item["macId"]]
            if not state["activation"] and state["Gnetkey"] and state["matching"] in (2, 3):
                response["enable"] = 1
            response["mappVer"] = 0
        else:
            response["roomId"] = peer["roomId"]
            if peer["role"] == 6:
                response["key"] = device.key.decode("ascii")
                if state["Gnetkey"]:
                    response["Gnetkey"] = state["Gnetkey"]
                response["devCnt"] = len(peers) - any(item["role"] == 5 for item in peers.values()) - 1
                if state.get("nluHost"):
                    response["nluInfo"] = {"nluHost": state["nluHost"], "nluPort": state.get("nluPort", 0)}
                for name in ("province", "city"):
                    if state.get(name):
                        response[name] = state[name]
                response["homeId"] = state.get("homeId", 0)
        return response

    def _timer(self, device, state, fields, sender):
        mac = _text(fields.get("mac"), 17)
        tid = _integer(fields.get("timeid"))
        target = state.get("_peers", {}).get(mac)
        kind = fields["t"]
        result = 500
        if target is not None:
            multi = target["role"] == 6
            records = state.get("_timers", {}).get(mac, [])
            if kind == "DeleteTiming":
                if not multi:
                    # Original ordinary delete succeeds even when the node is absent.
                    state.setdefault("_timers", {})[mac] = [
                        record for record in records if record["timeid"] != tid]
                    result = 200
                # Original multi-switch caller passes NULL, rejected by its callee.
            elif kind in ("AddTiming", "UpdateTiming"):
                if all(name in fields for name in ("mday", "hour", "min", "action", "enable")):
                    values = {name: _integer(fields[name]) for name in ("mday", "hour", "min", "enable")}
                    action = deepcopy(fields["action"])
                    switch = _switch_name(action) if multi else None
                    match = next((record for record in records
                                  if record["timeid"] == tid and record["switch"] == switch), None)
                    if not multi or switch is not None:
                        if kind == "UpdateTiming":
                            if match is not None:
                                match.update(values, action=action)
                                result = 200
                        else:
                            config = state["mid_config"]
                            entry = next((value for mid, value in (config or {}).items()
                                          if mid.lower() == target["mid"].lower()), None)
                            limit = -1 if entry is None else entry.get("timers_max", 5)
                            if values["mday"] < 128 and limit > 0:
                                if match is not None:
                                    result = 501
                                elif sum(record["switch"] == switch for record in records) >= state.get("_timer_limits", {}).get(mac, limit):
                                    result = 503
                                elif state.get("_timer_multi", {}).get(mac, multi) == multi:
                                    state.setdefault("_timer_limits", {}).setdefault(mac, limit)
                                    state.setdefault("_timer_multi", {})[mac] = multi
                                    state.setdefault("_timers", {}).setdefault(mac, []).append({
                                        "timeid": tid, **values, "action": action, "switch": switch})
                                    result = 200
        plain = {"t": "tres", "r": result, "timeid": tid, "mac": mac}
        return {"type": 0, "topic": f"TimerRsp/{device.mac}/{sender}",
                "payload": {"mac": device.mac, "plaintext": plain},
                "source": "host", "cmd": "data", "retain": False}

    def _status(self, device, state, request, fields, peer):
        target = fields.get("mac", fields.get("sub"))
        if target is None and "list" in fields:
            listing = fields["list"]
            if not isinstance(listing, list) or len(listing) > 128:
                raise InvalidPacket("ZTS status list must be bounded")
            result = []
            for item in listing:
                if not isinstance(item, dict):
                    raise InvalidPacket("ZTS status list entries must be objects")
                item = _members(item)
                cached = state.get("_peers", {}).get(item.get("mac"))
                if cached is None or "data" not in cached:
                    continue
                data = cached["data"]
                if "cols" in item:
                    # Original converter fills its object but still returns-1.
                    continue
                record = {"mac": cached["mac"]}
                if "cols" in data:
                    record["cols"] = deepcopy(data["cols"])
                    if "dat" in data:
                        record["dat"] = deepcopy(data["dat"])
                elif "opt" in data:
                    record["cols"] = deepcopy(data["opt"])
                    if "p" in data:
                        record["dat"] = deepcopy(data["p"])
                result.append(record)
            return {"mac": device.mac, "list": result, "t": "dat", "r": 200 if result else 500}
        if target is None:
            raise InvalidPacket("ZTS status requires mac/sub or list")
        _text(target, 17)
        values = {"host": state["host"], "ver": peer["ver"], "hid": peer["hid"],
                  "mid": peer["mid"], "time": state["time"], "active": state["active"]}
        if target == device.mac:
            values.update(ver="V3.2.MF", hid=HID, mid="70501")
        if peer["role"] == 3:
            values["rssi"] = peer.get("RSSI", 0)
        # Source cols lookup is case-sensitive, unlike ordinary object members.
        columns = [name for name in _names(request.get("cols", [])) if name in values]
        return {"mac": device.mac if target == device.mac else peer["mac"],
                "cols": columns, "dat": [values[name] for name in columns], "t": "dat", "r": 200}

    def handle(self, device, outer, *, address=None):
        if outer.get("t") != "pack":
            return []
        fields = _members(outer)
        cid = _text(fields.get("cid"), 17)
        if not cid or cid == device.mac or fields.get("tcid") not in ("", device.mac):
            raise InvalidPacket("wrong ZTS sender/target")
        selector = _integer(fields.get("i"))
        if selector not in (0, 1, 2):
            raise InvalidPacket("unsupported ZTS key selector")
        msg_id = _integer(fields.get("msgid")) & 0xffffffff
        state = deepcopy(device.state)
        stored = state.get("_peers", {}).get(cid)
        if selector == 0 and stored is None:
            raise InvalidPacket("unregistered ZTS private-key sender")
        peer = stored if stored is not None and selector != 2 else _peer(cid)
        if selector == 0 and len(peer["key"]) != 16:
            raise InvalidPacket("ZTS imported metadata has no usable private key")
        if selector == 2:
            payload = outer.get("pack")
            if not isinstance(payload, str):
                raise InvalidPacket("ZTS plaintext pack must be a JSON string")
            request = _json(payload.encode())
        else:
            request = decode_pack(outer, peer["key"].encode() if selector == 0 else GENERIC_KEY, CODEC)
        members = _members(request)
        kind = _text(members.get("t"), 64).lower()
        if kind not in DISPATCH or selector > DISPATCH[kind]:
            return []
        response = None
        reply_selector = 0
        repeat = 1
        extra = []
        if kind == "ubind":
            response = self._ubind(device, state, members, peer)
            reply_selector = 1 if peer["role"] == 5 else 0
        elif kind == "hb":
            if not peer["mid"] or members.get("cid") != cid or peer.get("released"):
                return []
            if "rssi" in members:
                peer["RSSI"] = _integer(members["rssi"])
            peer["hb_ticks"] = monotonic()
            response, reply_selector = {"t": "hbok"}, 1
        elif kind in ("cmd", "jsoncmd"):
            if members["t"] not in ("cmd", "jsonCmd"):
                return []
            target = peer if members["t"] == "cmd" else state.get("_peers", {}).get(members.get("mac"))
            if target is None or not 1 <= target["role"] <= 14:
                return []
            options = _names(request.get("opt"))
            values = request.get("p")
            if not isinstance(values, list) or len(values) != len(options):
                raise InvalidPacket("ZTS forwarded opt/p arrays must match")
            # Original host ignores the downstream controller's return value.
            # This receipt cannot establish companion acceptance or mutate its cache.
            if members["t"] == "jsonCmd":
                response = {"t": "res", "r": 200, "mac": target["mac"]}
            else:
                response = {"t": "res", "r": 200 if target["online"] == 1 else 405,
                            "opt": options, "p": deepcopy(values)}
                if "mac" in members:
                    response["mac"] = _text(members["mac"], 17)
                elif "sub" in members:
                    response["sub"] = _text(members["sub"], 17)
                else:
                    response["mac"] = target["mac"]
        elif kind == "scenesinglepush":
            if peer["role"] != 5:
                return []
            request_id = _text(request.get("requestId"), 31)
            oper, scene_type = _integer(request.get("oper")), _integer(request.get("type"))
            if "scene" not in request or oper not in (0, 1) or scene_type not in (0, 1):
                raise InvalidPacket("ZTS scene receipt requires scene,oper0/1,type0/1")
            if oper == 1:
                _integer(members.get("sceneid"))
            state["_scene_request_id"] = request_id
            # Source acknowledges submission before any external scene result.
            response = {"t": "sceneSinglepushRes", "res": 200}
        elif kind == "updownflag":
            if peer["role"] != 5:
                return []
            request_id = _text(members.get("requestid"), 50)
            if request_id == state.get("_updown_request_id", ""):
                return []
            config = members.get("config")
            if not isinstance(config, list) or len(config) > 128:
                raise InvalidPacket("ZTS updown config must be a bounded array")
            results = []
            for item in config:
                if not isinstance(item, dict):
                    raise InvalidPacket("ZTS updown entry must be an object")
                item = _members(item)
                if "sub" in item:
                    results.append({"mac": _text(item["sub"], 17), "r": 200,
                                    "reqId": _text(item.get("reqid"), 64)})
            state["_updown_request_id"] = request_id
            peer["data"] = {"t": "updownFlagRes", "r": results}
            response = peer["data"]
            _arm_retry(state, cid)
        elif kind == "binstatus":
            if members.get("mac") != cid:
                return []
            if peer["role"] == 3:
                peer["hb_ticks"] = monotonic()
            if isinstance(request.get("binStatus"), str):
                value = _text(request["binStatus"], 5120)
                peer["binParam"] = {"base64Param": value, "originLength": len(value.encode()) & 65535}
            # Receipt ACK is source-local, not a fabricated plugin conversion/board ACK.
            response = {"t": "ret", "r": 200, "mac": device.mac}
        elif kind == "status":
            response = self._status(device, state, request, members, peer)
        elif kind == "utm":
            response = {"t": "resUtm", "time": state["time"]}
        elif kind in ("addtiming", "deletetiming", "updatetiming"):
            if members["t"] not in ("AddTiming", "DeleteTiming", "UpdateTiming"):
                return []
            response = self._timer(device, state, members, "" if selector == 2 else cid)
            reply_selector = 2
        elif kind == "485configure":
            if "configure" not in members:
                raise InvalidPacket("ZTS485Configure requires configure")
            state["_485_config"] = deepcopy(members["configure"])
            peer["data"] = {"t": "485ConfigureAck", "r": 200}
            if peer["role"] == 5:
                response = peer["data"]
                _arm_retry(state, cid)
        elif kind == "activation":
            if members["t"] != "activation" or state["activation"] != 0 or not state["Gnetkey"]:
                return []
            peer["data"] = {"t": "activationRes", "Gnetkey": state["Gnetkey"]}
            state["activation"] = 2
            if peer["role"] == 5:
                response = peer["data"]
                _arm_retry(state, cid)
        elif kind == "configstatus":
            if members["t"] != "configStatus":
                return []
            oper = members.get("oper")
            response = {"t": "configStatusAck"}
            if oper == "w":
                value = members.get("data")
                if not isinstance(value, str) or "\0" in value or len(value.encode()) >= 32768:
                    raise InvalidPacket("ZTS config buffer must be a bounded NUL-free string")
                state["_config_buffer"] = value
            elif oper == "r":
                response["data"] = state.get("_config_buffer", "")
            else:
                raise InvalidPacket("ZTS configStatus requires r/w")
        elif kind == "jsonstatus":
            peer["data"] = deepcopy(request)
            response = {"t": "ret", "r": 200}
        elif kind == "dat":
            columns, values = request.get("opt"), request.get("p")
            if columns is None or values is None:
                columns, values = request.get("cols"), request.get("dat")
            if columns is not None and values is not None:
                columns = _names(columns)
                if not isinstance(values, list) or len(values) != len(columns):
                    raise InvalidPacket("ZTS cache columns/values must match")
                peer["data"] = {"opt": columns, "p": deepcopy(values), "t": "dat"}
        elif kind == "syncdevlist":
            if peer["role"] != 5:
                return []
            index = _integer(request.get("i"))
            listing = request.get("devList")
            if not isinstance(listing, list) or len(listing) > 999:
                raise InvalidPacket("ZTS synchronization requires a bounded devList")
            if index != state.get("_miniprocurCnt", 0):
                return []
            for item in listing:
                if not isinstance(item, dict):
                    raise InvalidPacket("ZTS synchronized device must be an object")
                if item.get("mac") == device.mac:
                    continue
                old_role = state.get("_peers", {}).get(item.get("mac"), {}).get("role", 0)
                imported = _import_record(item, state, adapt=True)
                if old_role not in (1, 2, 8):
                    imported["online"] = 1
            state["_miniprocurCnt"] = index + len(listing)
            count = state["_miniprocurCnt"]
            if count < state.get("_miniproCnt", 0):
                response = {"t": "syncDev", "cid": device.mac, "i": count}
                state.update(_sync_retry=cid, _sync_next=monotonic() + 1)
            else:
                response = {"t": "syncDone", "mac": device.mac, "sum": count}
                repeat = 10
                state.update(_sync_retry=None, _sync_previous=-1, _sync_repeats=0)
        elif kind == "devlistpush":
            if peer["role"] != 5:
                return []
            index = _integer(request.get("i"))
            listing = request.get("devList")
            if not isinstance(listing, list) or len(listing) > 999:
                raise InvalidPacket("ZTS device push requires a bounded devList")
            if index == state.get("_miniprocurCnt", 0):
                state["_devlist_size"] = len(listing)
                for item in listing:
                    if not isinstance(item, dict):
                        raise InvalidPacket("ZTS device push record must be an object")
                    if item.get("mac") == device.mac or "_" in _text(item.get("mid"), 16):
                        # Virtual records are external event inputs, not host peers.
                        continue
                    record = dict(item)
                    if request.get("pairMod") == 1:
                        room_id = _integer(record.get("roomId")) & 0xffffffff
                        record["roomId"] = -1
                        for room in state.get("roomList", []):
                            if not room["name"]:
                                break
                            if room["id"] == room_id:
                                sid = room["sId"]
                                record["roomId"] = sid if sid < (1 << 31) else sid - (1 << 32)
                                break
                    old_role = state.get("_peers", {}).get(record.get("mac"), {}).get("role", 0)
                    imported = _import_record(record, state, adapt=True)
                    if old_role not in (1, 2, 6, 8):
                        imported["online"] = 1
                    imported.update(registered=True, released=False, hb_ticks=monotonic())
                    if "devExt" in item:
                        imported["devExt"] = _text(item["devExt"], 4096).replace("\\", "")
                    if "devNoteName" in item:
                        imported["noteName"] = _text(item["devNoteName"], 128)
                    if not imported["role"]:
                        del state["_peers"][imported["mac"]]
                state["_miniprocurCnt"] = index + len(listing)
            count, total = state.get("_miniprocurCnt", 0), state.get("_miniproCnt", 0)
            if count < total:
                response = {"t": "devListPushRes", "i": index,
                            "num": state.get("_devlist_size", 0), "sum": total}
            else:
                response = {"t": "syncDone", "mac": device.mac, "sum": count}
                # Direct response plus the original event loop's ten syncDone sends.
                repeat = 11
        elif kind == "updevlist":
            if "t" not in request:
                return []
            oper = _integer(request.get("operType"))
            listing = request.get("upList")
            if not isinstance(listing, list) or len(listing) > 128:
                raise InvalidPacket("ZTS upList must be a bounded array")
            for group in listing:
                if not isinstance(group, dict) or group.get("mac") != device.mac:
                    raise InvalidPacket("ZTS upList target differs from host")
                _integer(group.get("roomId"))
                records = group.get("devList")
                if not isinstance(records, list) or len(records) > 999:
                    raise InvalidPacket("ZTS device list must be bounded")
                for item in records:
                    if not isinstance(item, dict):
                        raise InvalidPacket("ZTS device record must be an object")
                    mac = _text(item.get("mac"), 17)
                    if mac == device.mac:
                        raise InvalidPacket("ZTS host cannot register itself")
                    if oper in (0, 1):
                        record = {"key": "", "name": "", "roomId": 0, **item}
                        imported = _import_record(record, state, adapt=False)
                        imported["registered"] = True
                        imported["released"] = False
                        if "devNoteName" in item:
                            imported["noteName"] = _text(item["devNoteName"], 128)
                    elif oper == 2:
                        registered = state.get("_peers", {}).get(mac)
                        if registered is not None:
                            if registered["role"] == 3:
                                registered.update(released=True, name="", macId=65535)
                            else:
                                del state["_peers"][mac]
            response = {"t": "upDevListAck", "r": 200}
        elif kind == "syncdev":
            if members.get("cid") != cid:
                return []
            index = _integer(request.get("i"))
            if not 0 <= index <= 255:
                raise InvalidPacket("ZTS safe sync index is uint8")
            records = list(state.get("_peers", {}).values())
            result = []
            for item in records[index:]:
                if item["mac"] == cid or item["role"] == 5:
                    continue
                result.append({name: item.get(name, "") for name in
                               ("mac", "macId", "name", "roomId", "mid", "hid", "key", "ver", "vender", "online")})
                if len(result) == 10:
                    break
            response = {"t": "syncDevList", "i": index,
                        "sum": (len(records) - 1 if peer["role"] == 5 else
                                len(records) - any(item["role"] == 5 for item in records) - 1),
                        "devList": result}
        elif kind == "roomlistpush":
            if peer["role"] != 5 or members["t"] != "roomListPush":
                return []
            index, total = _integer(members.get("i")), _integer(members.get("sum"))
            if not 0 <= index < total <= 200:
                raise InvalidPacket("ZTS room page exceeds bounded room cache")
            rooms = _rooms(members.get("roomlist"), ids=False)
            if index == 0:
                state["roomList"], state["_room_count"] = [], 0
            count = state.get("_room_count", 0)
            if index == count:
                rooms = rooms[:200 - count]
                state.setdefault("roomList", []).extend(rooms)
                count += len(rooms)
                state["_room_count"] = count
                accepted = len(rooms)
            else:
                accepted = count - index
            if count < total:
                response = {"t": "roomListPushRes", "i": index, "num": accepted, "sum": total}
            else:
                response = {"t": "syncRoomListDone", "sum": total, "mac": device.mac}
                state["_room_count"] = 0
        elif kind == "uproominfo":
            rooms = _rooms(members.get("roomlist"))
            if not rooms:
                raise InvalidPacket("ZTS upRoomInfo requires rooms")
            state["roomList"] = rooms
            if len(rooms) < 200 and not any(room["id"] == room["sId"] == 0 for room in rooms):
                state["roomList"].append({"id": 0, "sId": 0, "name": "全屋"})
        elif kind == "connect":
            for name, online in (("offlineSub", 0), ("onlineSub", 1)):
                for mac in _names(request.get(name)):
                    if mac in state.get("_peers", {}):
                        state["_peers"][mac]["online"] = online
            records = [item for item in state.get("_peers", {}).values()
                       if item["role"] not in (0, 3, 5, 9, 11)]
            response = {"t": "connect", "online": 0, "mac": device.mac,
                        "onlineSub": [item["mac"] for item in records if item.get("online") == 1],
                        "offlineSub": [item["mac"] for item in records if item.get("online") != 1]}
            reply_selector = 1
        elif kind == "syncpersistent":
            oper = _integer(members.get("oper"))
            if oper == 0:
                state["_sync_type"], state["_retry"] = 15, None
            elif oper == 1:
                selected_type = _integer(members.get("type"))
                state["_sync_type"] = selected_type
                page, total = _persist_page(state, selected_type, 0)
                response = {"t": "syncPersistentAck", "mac": device.mac, "sum": total}
                if page is not None:
                    peer["data"] = page
                    if peer["role"] == 5:
                        _arm_retry(state, cid)
                        extra.append(page)
            else:
                raise InvalidPacket("ZTS syncPersistent oper requires0/1")
        elif kind == "devlistpushres":
            index, number, total = (_integer(members.get(name)) for name in ("i", "num", "sum"))
            if index < 0 or number < 0 or total < 0:
                raise InvalidPacket("ZTS synchronization indices must be nonnegative")
            if index + number >= total:
                state["_retry"] = None
            else:
                page, _ = _persist_page(state, state.get("_sync_type", 15), index + number)
                if page is not None:
                    peer["data"] = page
                    if peer["role"] == 5:
                        response = page
                        _arm_retry(state, cid)
        elif kind in ("devonlineres", "checkresres"):
            if members["t"] != {"devonlineres": "DevOnlineRes", "checkresres": "CheckResRes"}[kind]:
                return []
            index = _integer(members.get("i")) + _integer(members.get("num"))
            previous = state.get("_online_index" if kind == "devonlineres" else "_check_index", 0)
            if index < previous or index < 0:
                return []
            if kind == "devonlineres":
                state["_online_index"] = index
                records = list(state.get("_peers", {}).values())
                if index < len(records) - 1:
                    page = [item for item in records[index:index + 100] if item["role"] not in (0, 5)]
                    response = {"t": "DevOnlinePush",
                                "online": [item["mac"] for item in page if item["online"] == 1],
                                "offline": [item["mac"] for item in page if item["online"] != 1],
                                "sum": len(records) - 1, "i": index}
            else:
                state["_check_index"] = index
                failed = state.get("_check_failed", [])
                if index < len(failed) or not failed:
                    response = {"t": "CheckResPush", "failDev": failed[index:index + 100],
                                "i": index, "sum": len(failed), "checkId": state.get("_check_id", 0)}
            if response is not None:
                peer["data"] = response
                if peer["role"] == 5:
                    _arm_retry(state, cid)
                else:
                    response = None
        elif kind in ("devonlinedone", "checkresdone"):
            if members["t"] != {"devonlinedone": "DevOnlineDone", "checkresdone": "CheckResDone"}[kind]:
                return []
            _integer(members.get("sum"))
            state["_retry"] = None
        elif kind in ("ret", "res"):
            if _integer(request.get("r")) == 200:
                if kind == "ret" and peer["role"] == 5:
                    state["_retry"] = None
                elif kind == "res" and peer["role"] == 3:
                    peer["hb_ticks"] = monotonic()
        elif kind in ("devcheck", "checksub"):
            # devCheck is a source no-op; checksub publishes external UDS requests.
            return []
        else:
            # Remaining operations require selected plugins, scene/board services
            # or vendor OTA work; never substitute a companion success.
            return []
        replies = [] if response is None else [
            _reply(device, response, peer, reply_selector, msg_id) for _ in range(repeat)]
        replies.extend(_reply(device, item, peer, 0, msg_id) for item in extra)
        if (address is not None and selector != 2 and cid in state.get("_peers", {})
                and (kind != "ubind" or response is not None)):
            peer["_address"] = address
        state["_msgId"] = msg_id
        device.advance(monotonic())
        device.state = state
        return replies


PROFILES = (Profile(
    "sim-zts31a-v310-host", ("70501",), HID, SOURCE_SHA256,
    {"host": "synthetic.invalid", "time": "2026-01-01 00:00:00", "active": 0,
     "matching": 2, "activation": 0, "Gnetkey": "", "orderID": "synthetic-zts31a", "mid_config": None,
     "nluHost": "", "nluPort": 0, "nluinfo_flag": 0},
    ZtsHost(), max_request_bytes=5120,
),)
