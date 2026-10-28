"""Independent raw-peer ZTS host contract; no public-client helpers/expectations."""

import base64
from copy import deepcopy
import json
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles import catalog_zts
from gree_emulator.wire import InvalidPacket, encode_reply

VECTORS = json.loads((Path(__file__).parent / "fixtures/emulator/catalog-zts-vectors_research.json").read_text())
GENERIC = b"a3K8Bx%2r8Y7#xDh"


@pytest.fixture
def device():
    profile = catalog_zts.PROFILES[0]
    return EmulatedDevice("host", VECTORS["mac"], "synthetic host", "70501",
                          VECTORS["host_key"].encode(), profile,
                          deepcopy(dict(profile.initial_state)), room_c=None, ambient_c=None)


def packet(device, payload, *, cid="miniApp", selector=0, key=None, msg_id=37):
    plain = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
    if selector == 2:
        packed = plain.decode()
    else:
        selected_key = GENERIC if selector == 1 else (key or device.key)
        packed = base64.b64encode(AES.new(selected_key, AES.MODE_ECB).encrypt(pad(plain, 16))).decode()
    return {"t": "pack", "cid": cid, "tcid": device.mac,
            "i": selector, "msgId": msg_id, "pack": packed}


def exchange(device, payload, **kwargs):
    replies = device.profile.handler.handle(device, packet(device, payload, **kwargs))
    if not replies:
        return None, None
    assert all(reply.inner == replies[0].inner for reply in replies)
    reply = replies[0]
    encoded = encode_reply(reply)
    assert not encoded.endswith(b"\n")
    outer = json.loads(encoded)
    assert outer["cid"] == device.mac
    assert outer["tcid"] == kwargs.get("cid", "miniApp")
    assert "uid" not in outer
    ciphertext = base64.b64decode(outer["pack"], validate=True)
    plain = unpad(AES.new(reply.key, AES.MODE_ECB).decrypt(ciphertext), 16)
    assert plain.endswith(b"}\n") and not plain.endswith(b"\n\n")
    return reply, json.loads(plain)


def bind_mini(device, **values):
    return exchange(device, {**VECTORS["miniApp_UBind"], **values}, selector=1)


def bind_peer(device, *, cid=None, key=None, **values):
    return exchange(device, {**VECTORS["peer_UBind"], "devkey": key or VECTORS["peer_key"], **values},
                    cid=cid or VECTORS["peer"], selector=1)


def test_identity_and_39_entry_auth_table(device):
    assert device.profile.mids == ("70501",)
    assert device.profile.hid == VECTORS["hid"]
    assert device.profile.source_sha256 == VECTORS["source_sha256"]
    assert len(catalog_zts.DISPATCH) == 39
    assert len(catalog_zts.UBIND_FIELDS) == 23
    assert catalog_zts.METADATA == ("host", "ver", "hid", "mid", "rssi", "time", "active")
    assert device.profile.handler.thermal_target(device) is None


def test_miniapp_registration_key_and_sender_port(device):
    reply, inner = bind_mini(device)
    assert inner == VECTORS["miniApp_UBindok"]
    assert reply.destination_port is None
    assert reply.outer["i"] == 1
    assert reply.key == GENERIC
    assert device.state["_peers"]["miniApp"]["key"] == VECTORS["host_key"]
    reply, status = exchange(device, {"t": "status", "mac": device.mac,
                                      "cols": VECTORS["root_columns"]})
    assert reply.outer["i"] == 0 and reply.key == device.key
    assert status == {"mac": device.mac, "cols": VECTORS["miniApp_root_columns"],
                      "dat": VECTORS["miniApp_root_values"], "t": "dat", "r": 200}


def test_ordinary_ubind_uses_original_adapter_and_supplied_peer_key(device):
    reply, inner = bind_peer(device)
    assert inner == VECTORS["peer_UBindok"]
    assert reply.destination_port == 5001
    assert reply.key == VECTORS["peer_key"].encode()
    assert reply.outer["i"] == 0 and reply.outer["enNet"] == 0
    peer = device.state["_peers"][VECTORS["peer"]]
    assert (peer["role"], peer["lock"], peer["scene"], peer["macId"]) == (3, 255, 2, 1)
    assert "key" not in inner


@pytest.mark.parametrize("rssi", VECTORS["rssi_values"])
def test_all_signed32_rssi_values_and_duplicates_are_peer_owned(device, rssi):
    bind_peer(device)
    reply, inner = exchange(device, {"t": "hb", "cid": VECTORS["peer"], "RSSI": rssi},
                            cid=VECTORS["peer"], selector=1)
    assert inner == {"t": "hbok"} and reply.outer["i"] == 1
    _, inner = exchange(device, {"t": "status", "mac": VECTORS["peer"],
                                "cols": ["rssi", "rssi", "mid", "unknown"]},
                        cid=VECTORS["peer"], key=VECTORS["peer_key"].encode())
    assert inner == {"mac": VECTORS["peer"], "cols": ["rssi", "rssi", "mid"],
                     "dat": [rssi, rssi, "807001"], "t": "dat", "r": 200}
    bind_peer(device, cid=VECTORS["second_peer"], key=VECTORS["second_key"])
    _, second = exchange(device, {"t": "status", "mac": VECTORS["second_peer"], "cols": ["rssi"]},
                         cid=VECTORS["second_peer"], key=VECTORS["second_key"].encode())
    assert second["dat"] == [0]  # Labelled synthetic cache initialization, not measured RSSI.


def test_rebind_changes_peer_key_but_not_other_peer(device):
    bind_peer(device)
    bind_peer(device, cid=VECTORS["second_peer"], key=VECTORS["second_key"])
    new_key = "0011223344556677"
    bind_peer(device, key=new_key)
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "Utm"}, cid=VECTORS["peer"], key=VECTORS["peer_key"].encode())
    _, response = exchange(device, {"t": "Utm"}, cid=VECTORS["peer"], key=new_key.encode())
    assert response == {"t": "resUtm", "time": "2026-01-01 00:00:00"}
    assert device.state["_peers"][VECTORS["second_peer"]]["key"] == VECTORS["second_key"]


def test_config_roundtrip_multiline_empty_and_no_real_file_io(device):
    bind_mini(device)
    assert exchange(device, {"t": "configStatus", "oper": "r"})[1] == {"t": "configStatusAck", "data": ""}
    config = '{\n"raw": [1, "two"]\n}'
    assert exchange(device, {"t": "configStatus", "oper": "w", "data": config})[1] == {"t": "configStatusAck"}
    assert exchange(device, {"t": "configStatus", "oper": "r"})[1] == {"t": "configStatusAck", "data": config}


def test_dat_cache_list_getter_is_independent_and_preserves_raw_values(device):
    bind_peer(device)
    bind_mini(device)
    payload = {"t": "dat", "cols": ["raw", "str", "array"], "dat": [1, "two", [3, 4]]}
    assert exchange(device, payload, cid=VECTORS["peer"], key=VECTORS["peer_key"].encode())[0] is None
    _, status = exchange(device, {"t": "status", "list": [
        {"mac": VECTORS["peer"]},
        {"mac": "not-registered"}]})
    assert status == {"mac": device.mac, "list": [{"mac": VECTORS["peer"],
                      "cols": ["raw", "str", "array"], "dat": [1, "two", [3, 4]]}], "t": "dat", "r": 200}
    assert exchange(device, {"t": "status", "list": []})[1] == {"mac": device.mac, "list": [], "t": "dat", "r": 500}


def test_room_page_order_replay_and_default_room(device):
    bind_mini(device)
    first = {"t": "roomListPush", "i": 0, "sum": 2, "roomList": [{"sId": 10, "name": "one"}]}
    assert exchange(device, first)[1] == {"t": "roomListPushRes", "i": 0, "num": 1, "sum": 2}
    assert exchange(device, {"t": "roomListPush", "i": 1, "sum": 2,
                             "roomList": [{"sId": 11, "name": "two"}]})[1] == {"t": "syncRoomListDone", "sum": 2, "mac": device.mac}
    assert device.state["roomList"] == [{"id": 0, "sId": 10, "name": "one"}, {"id": 0, "sId": 11, "name": "two"}]
    assert exchange(device, {"t": "upRoomInfo", "roomList": [{"id": 8, "sId": 9, "name": "room"}]})[0] is None
    assert device.state["roomList"][-1] == {"id": 0, "sId": 0, "name": "全屋"}


def test_ubind_configuration_authorization_and_widths(device):
    bind_mini(device, Gnetkey="syn-gnet", GnetID=7, homeId=12, dis="new.invalid",
              province="province", city="city", domain="api.invalid", lng="1.25", lat="2.5",
              nluHost="nlu.invalid", orderID="synthetic-order", soVer="1", pairMod=1)
    assert device.state["matching"] == 1 and device.state["activation"] == 1
    assert device.state["active"] == 0  # Separate original getter and activation state.
    assert device.state["nluHost"] == "nlu.invalid" and device.state["nluPort"] == 0
    assert device.state["host"] == "new.invalid"
    before = deepcopy(device.state)
    assert bind_mini(device, Gnetkey="wrong", GnetID=8, homeId=99)[0] is None
    assert device.state["homeId"] == before["homeId"]
    bind_mini(device, Gnetkey="syn-gnet", homeId=13)
    assert device.state["homeId"] == 13


@pytest.mark.parametrize("mutation", [
    {"tcid": "020000000099"}, {"cid": "020000000001"}, {"msgId": None}, {"i": 3},
])
def test_malformed_envelope_is_atomic(device, mutation):
    before = deepcopy(device.state)
    outer = packet(device, VECTORS["miniApp_UBind"], selector=1)
    outer.update(mutation)
    with pytest.raises(InvalidPacket):
        device.profile.handler.handle(device, outer)
    assert device.state == before


def test_generic_scan_bind_and_plugin_route_are_not_appliances(device):
    assert device.profile.handler.advertise(device, {"t": "scan"}) == []
    for kind in ("scan", "bind", "subDev"):
        assert exchange(device, {"t": kind}, selector=1)[0] is None
    assert catalog_zts._role("807002") == 4  # Configured Fastcon route, not an emitted appliance.
    assert catalog_zts._role("82000") == 3  # Original prefix ordering, not unreachable CAN branch.
    assert exchange(device, {"t": "UBind", "mid": "unknown", "devkey": VECTORS["peer_key"]},
                    cid=VECTORS["peer"], selector=1)[0] is None


def test_wrong_key_and_invalid_batch_preserve_state_and_clock(device):
    bind_mini(device)
    before, clock = deepcopy(device.state), device.last_step
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "status", "mac": device.mac, "cols": ["hid"]}, key=b"0000000000000000")
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "roomListPush", "i": 0, "sum": 2,
                          "roomList": [{"sId": 1, "name": "ok"}, {"sId": True, "name": "bad"}]})
    assert device.state == before and device.last_step == clock


def test_restart_clears_peers_and_config_and_caches_are_isolated(device):
    bind_mini(device)
    exchange(device, {"t": "configStatus", "oper": "w", "data": "synthetic"})
    fresh = EmulatedDevice("new", device.mac, device.name, device.mid, device.key,
                           device.profile, deepcopy(dict(device.profile.initial_state)), room_c=None, ambient_c=None)
    with pytest.raises(InvalidPacket):
        exchange(fresh, {"t": "Utm"})
    bind_mini(fresh)
    assert exchange(fresh, {"t": "configStatus", "oper": "r"})[1]["data"] == ""
    assert device.state["_config_buffer"] == "synthetic"


@pytest.mark.parametrize(("mid", "role"), [
    ("70205", 5), ("70601", 6), ("80405", 8), ("809031", 2), ("6400", 2),
    ("70314", 4), ("807002", 4), ("807001", 3), ("82000", 3), ("28000", 3),
    ("6001", 1), ("6200", 1), ("6301", 1), ("unknown", 0),
])
def test_exact_original_fallback_role_branch_order(mid, role):
    assert catalog_zts._role(mid) == role


def test_message_id_uint32_and_case_sensitive_columns(device):
    bind_mini(device)
    reply, inner = exchange(device, {"T": "StAtUs", "MAC": device.mac, "cols": ["HID", "hid", "hid"]},
                            msg_id=-1)
    assert reply.outer["msgId"] == 4294967295
    assert inner["cols"] == ["hid", "hid"]
    assert inner["dat"] == [VECTORS["hid"], VECTORS["hid"]]
    assert exchange(device, {"t": "status", "mac": device.mac, "cols": []})[1]["dat"] == []
    assert exchange(device, {"t": "status", "mac": device.mac, "cols": ["hid"]}, selector=1)[0] is None


def test_unresolved_companion_route_never_fabricates_a_companion_ack(device):
    bind_mini(device)
    before = deepcopy(device.state)
    for kind in ("jsonCmd", "binSubStatus", "binSubEvent", "switchBindPush"):
        assert exchange(device, {"t": kind, "mac": "020000000099", "opt": ["Pow"], "p": [1]})[0] is None
    assert device.state == before


def test_filtered_raw_cache_preserves_original_failure_return_not_invented_success(device):
    bind_peer(device)
    bind_mini(device)
    exchange(device, {"t": "dat", "opt": ["Number", "number", "bool", "null", "object"],
                      "p": [1.75, 99, True, None, {"raw": 3}]},
             cid=VECTORS["peer"], key=VECTORS["peer_key"].encode())
    _, inner = exchange(device, {"t": "status", "list": [{
        "mac": VECTORS["peer"], "cols": ["NUMBER", "bool", "null", "object"]}]})
    assert inner == {"mac": device.mac, "list": [], "t": "dat", "r": 500}
    _, complete = exchange(device, {"t": "status", "list": [{"mac": VECTORS["peer"]}]})
    assert complete["list"] == [{"mac": VECTORS["peer"],
                                 "cols": ["Number", "number", "bool", "null", "object"],
                                 "dat": [1.75, 99, True, None, {"raw": 3}]}]


def test_release_and_rebind_do_not_reuse_stale_peer_authorization(device):
    bind_peer(device)
    bind_mini(device)
    payload = {"t": "upDevList", "operType": 2, "upList": [
        {"mac": device.mac, "roomId": 0, "devList": [{"mac": VECTORS["peer"]}]}]}
    assert exchange(device, payload)[1] == {"t": "upDevListAck", "r": 200}
    assert device.state["_peers"][VECTORS["peer"]]["released"] is True
    assert exchange(device, {"t": "hb", "cid": VECTORS["peer"]},
                    cid=VECTORS["peer"], selector=1)[0] is None
    assert bind_peer(device)[0] is None
    assert bind_peer(device, key="0011223344556677")[1] == VECTORS["peer_UBindok"]
    assert not device.state["_peers"][VECTORS["peer"]]["released"]


def test_device_push_pagination_imports_complete_raw_peer_metadata(device):
    bind_mini(device, devCnt=2)
    one = {"mac": VECTORS["peer"], "macId": 7, "name": "peer one", "roomId": 8,
           "mid": "807001", "hid": "synthetic-peer", "key": VECTORS["peer_key"],
           "ver": "V1", "vender": "synthetic", "devExt": "{\\\"raw\\\":1}",
           "devNoteName": "note"}
    assert exchange(device, {"t": "devListPush", "i": 0, "sum": 2, "devList": [one]})[1] == {
        "t": "devListPushRes", "i": 0, "num": 1, "sum": 2}
    assert device.state["_peers"][VECTORS["peer"]]["devExt"] == '{"raw":1}'
    _, listing = exchange(device, {"t": "syncDev", "cid": "miniApp", "i": 0})
    assert listing == {"t": "syncDevList", "i": 0, "sum": 1, "devList": [{
        "mac": VECTORS["peer"], "macId": 7, "name": "peer one", "roomId": 8,
        "mid": "807001", "hid": "synthetic-peer", "key": VECTORS["peer_key"],
        "ver": "V1", "vender": "synthetic", "online": 1}]}
    two = {**one, "mac": VECTORS["second_peer"], "key": VECTORS["second_key"]}
    assert exchange(device, {"t": "devListPush", "i": 1, "sum": 2, "devList": [two]})[1] == {
        "t": "syncDone", "mac": device.mac, "sum": 2}
    assert list(device.state["_peers"])[-1] == "miniApp"


def test_native_udp_capacity_and_safe_initial_cache_validation(device):
    assert device.profile.max_request_bytes == 5120
    for state in ({"matching": 256}, {"activation": 3}, {"orderID": "x" * 64},
                  {"_peers": {}}, {"active": True}):
        with pytest.raises(ValueError):
            device.profile.handler.validate_state(state)
    rooms = [{"id": index, "sId": index, "name": f"room {index}"} for index in range(201)]
    assert len(catalog_zts._rooms(rooms)) == 200
    state = {}
    for index in range(999):
        catalog_zts._put_peer(state, catalog_zts._peer(f"{index:012x}"))
    with pytest.raises(InvalidPacket):
        catalog_zts._put_peer(state, catalog_zts._peer("ffffffffffff"))


def timer_result(device, kind, *, expected, timeid=1, mac=None, **values):
    target = mac or VECTORS["peer"]
    replies = device.profile.handler.handle(device, packet(device, {
        "t": kind, "mac": target, "timeid": timeid, **values}))
    assert len(replies) == 1 and replies[0].inner is None
    assert replies[0].destination_port is None
    encoded = encode_reply(replies[0])
    assert not encoded.endswith(b"\n")
    assert json.loads(encoded) == {
        "type": 0, "topic": f"TimerRsp/{device.mac}/miniApp",
        "payload": {"mac": device.mac, "plaintext": {
            "t": "tres", "r": expected, "timeid": timeid, "mac": target}},
        "source": "host", "cmd": "data", "retain": False}


def test_timer_absent_configuration_has_actual_error_reply_not_timeout(device):
    bind_peer(device)
    bind_mini(device)
    values = {"mday": 127, "hour": 23, "min": 59, "enable": 1, "action": {"opt": ["Pow"], "p": [1]}}
    timer_result(device, "AddTiming", expected=500, **values)
    timer_result(device, "DeleteTiming", expected=200)
    timer_result(device, "UpdateTiming", expected=500, **values)
    assert not device.state.get("_timers", {}).get(VECTORS["peer"])


def test_timer_complete_add_duplicate_capacity_update_delete_cache(device):
    device.state["mid_config"] = {"807001": {"type_value": 3, "timers_max": 2}}
    device.profile.handler.validate_state(device.state)
    bind_peer(device)
    bind_mini(device)
    values = {"mday": 127, "hour": 23, "min": 59, "enable": 1, "action": {"opt": ["Pow"], "p": [1]}}
    timer_result(device, "AddTiming", expected=200, **values)
    timer_result(device, "AddTiming", expected=501, **values)
    timer_result(device, "AddTiming", expected=200, timeid=2, **values)
    timer_result(device, "AddTiming", expected=503, timeid=3, **values)
    timer_result(device, "UpdateTiming", expected=200, **{**values, "mday": 300, "hour": -5,
                                                      "min": 99, "action": [1, "raw"]})
    node = device.state["_timers"][VECTORS["peer"]][0]
    assert (node["mday"], node["hour"], node["min"], node["action"]) == (300, -5, 99, [1, "raw"])
    timer_result(device, "DeleteTiming", expected=200)
    timer_result(device, "DeleteTiming", expected=200)
    timer_result(device, "AddTiming", expected=200, timeid=3, **values)
    assert [node["timeid"] for node in device.state["_timers"][VECTORS["peer"]]] == [2, 3]
    timer_result(device, "AddTiming", expected=500, timeid=4, **{**values, "mday": 128})


def test_timer_multiswitch_keeps_original_quote_and_delete_null_fault_boundary(device):
    device.state["mid_config"] = {"70601": {"type_value": 6, "timers_max": 1}}
    bind_peer(device, mid="70601")
    bind_mini(device)
    values = {"mday": -1, "hour": 0, "min": 0, "enable": 0, "action": {"opt": ["Sw1"], "p": [1]}}
    timer_result(device, "AddTiming", expected=200, **values)
    assert device.state["_timers"][VECTORS["peer"]][0]["switch"] == 'Sw1"'
    timer_result(device, "AddTiming", expected=501, **values)
    timer_result(device, "AddTiming", expected=200, **{**values, "action": {"opt": ["Sw2"], "p": [0]}})
    timer_result(device, "DeleteTiming", expected=500)
    timer_result(device, "UpdateTiming", expected=500, **{**values, "action": {"opt": ["Pow"]}})


def test_synchronization_emits_original_fixed_syncdone_bursts(device):
    bind_mini(device, devCnt=0)
    replies = device.profile.handler.handle(device, packet(device, {"t": "syncDevList", "i": 0, "devList": []}))
    assert len(replies) == 10
    assert all(reply.inner == {"t": "syncDone", "mac": device.mac, "sum": 0} for reply in replies)
    replies = device.profile.handler.handle(device, packet(device, {"t": "devListPush", "i": 0, "sum": 0, "devList": []}))
    assert len(replies) == 11
    assert all(reply.inner == {"t": "syncDone", "mac": device.mac, "sum": 0} for reply in replies)


def test_persistent_and_online_lifecycle_pages_and_retry_ack(device):
    bind_peer(device)
    bind_peer(device, cid=VECTORS["second_peer"], key=VECTORS["second_key"])
    bind_mini(device)
    replies = device.profile.handler.handle(device, packet(device, {"t": "syncPersistent", "oper": 1, "type": 3}))
    assert len(replies) == 2
    assert replies[0].inner == {"t": "syncPersistentAck", "mac": device.mac, "sum": 2}
    assert replies[1].inner == {"t": "devListPush", "i": 0, "sum": 2, "devList": [
        {"mac": VECTORS["peer"], "macId": 1, "name": "", "roomId": 0, "mid": "807001",
         "hid": "synthetic-peer", "key": VECTORS["peer_key"], "ver": "V1", "vender": ""},
        {"mac": VECTORS["second_peer"], "macId": 1, "name": "", "roomId": 0, "mid": "807001",
         "hid": "synthetic-peer", "key": VECTORS["second_key"], "ver": "V1", "vender": ""}]}
    assert exchange(device, {"t": "devListPushRes", "i": 0, "num": 2, "sum": 2})[0] is None
    assert device.state["_retry"] is None
    assert exchange(device, {"t": "DevOnlineRes", "i": 0, "num": 0})[1] == {
        "t": "DevOnlinePush", "online": [VECTORS["peer"], VECTORS["second_peer"]],
        "offline": [], "sum": 2, "i": 0}
    assert exchange(device, {"t": "CheckResRes", "i": 0, "num": 0})[1] == {
        "t": "CheckResPush", "failDev": [], "i": 0, "sum": 0, "checkId": 0}
    assert exchange(device, {"t": "ret", "r": 200})[0] is None
    assert device.state["_retry"] is None


def test_485_storage_and_activation_are_host_ack_not_companion_ack(device):
    bind_mini(device, Gnetkey="syn-gnet")
    config = {"baud": 9600, "raw": [1, "two"]}
    assert exchange(device, {"t": "485Configure", "configure": config})[1] == {"t": "485ConfigureAck", "r": 200}
    assert device.state["_485_config"] == config
    assert exchange(device, {"t": "activation"})[1] == {"t": "activationRes", "Gnetkey": "syn-gnet"}
    assert device.state["activation"] == 2 and device.state["active"] == 0
    assert exchange(device, {"t": "activation"})[0] is None


def test_miniapp_periodic_retry_count_and_atomic_sender_address_capture(device):
    bind_mini(device)
    handler = device.profile.handler
    original, attacker = ("127.0.0.1", 43001), ("127.0.0.1", 43002)
    request = packet(device, {"t": "485Configure", "configure": [1, "raw"]})
    handler.handle_from(device, request, original)
    before = deepcopy(device.state)
    for bad in (
        packet(device, {"t": "Utm"}, key=b"0000000000000000"),
        packet(device, {"t": "status", "mac": device.mac, "cols": [True]}),
        {**packet(device, {"t": "Utm"}), "tcid": "wrong"},
    ):
        with pytest.raises(InvalidPacket):
            handler.handle_from(device, bad, attacker)
    assert handler.handle_from(device, packet(device, {"t": "cmd"}, selector=2), attacker) == []
    assert device.state == before
    now = device.state["_retry_next"]
    assert handler.tick(device, now - 0.01) == []
    for index in range(10):
        replies = handler.tick(device, now + index)
        assert len(replies) == 1 and replies[0][1] == original
        assert replies[0][0].inner == {"t": "485ConfigureAck", "r": 200}
    assert handler.tick(device, now + 10) == []
    handler.handle_from(device, request, original)
    assert handler.handle_from(device, packet(device, {"t": "ret", "r": 200}), original) == []
    assert handler.tick(device, device.state["_retry_next"]) == []


def test_synchronization_retry_progress_and_heartbeat_online_cache(device):
    bind_mini(device, devCnt=1)
    handler = device.profile.handler
    address = ("127.0.0.1", 43001)
    response = handler.handle_from(device, packet(device, {"t": "syncDevList", "i": 0, "devList": []}), address)
    assert [reply.inner for reply in response] == [{"t": "syncDev", "cid": device.mac, "i": 0}]
    now = device.state["_sync_next"]
    for index in range(6):
        replies = handler.tick(device, now + index)
        assert len(replies) == 1 and replies[0][1] == address
        assert replies[0][0].inner == {"t": "syncDev", "cid": device.mac, "i": 0}
    assert handler.tick(device, now + 6) == []
    bind_peer(device)
    peer = device.state["_peers"][VECTORS["peer"]]
    start = peer["hb_ticks"]
    device.state["_hb_next"] = start + 46
    handler.tick(device, start + 46)
    assert peer["online"] == 1
    handler.tick(device, start + 92)
    assert peer["online"] == 0
    exchange(device, {"t": "hb", "cid": VECTORS["peer"]}, cid=VECTORS["peer"], selector=1)
    peer = device.state["_peers"][VECTORS["peer"]]
    handler.tick(device, peer["hb_ticks"] + 1)
    assert peer["online"] == 0  # Recovery happens on the next periodic host check.
    device.state["_hb_next"] = peer["hb_ticks"] + 46
    handler.tick(device, peer["hb_ticks"] + 46)
    assert peer["online"] == 1


def test_binary_status_receipt_preserves_opaque_input_without_companion_conversion(device):
    bind_peer(device)
    reply, inner = exchange(device, {"t": "binStatus", "mac": VECTORS["peer"], "binStatus": "AAAA"},
                            cid=VECTORS["peer"], key=VECTORS["peer_key"].encode())
    assert inner == {"t": "ret", "r": 200, "mac": device.mac}
    assert reply.destination_port == 5001
    assert device.state["_peers"][VECTORS["peer"]]["binParam"] == {"base64Param": "AAAA", "originLength": 4}


def test_command_receipt_is_not_effective_appliance_or_companion_state(device):
    bind_peer(device)
    bind_mini(device)
    exchange(device, {"t": "dat", "opt": ["Pow"], "p": [0]},
             cid=VECTORS["peer"], key=VECTORS["peer_key"].encode())
    _, receipt = exchange(device, {"t": "cmd", "opt": ["Pow", "unknown"], "p": [1, "raw"]},
                          cid=VECTORS["peer"], key=VECTORS["peer_key"].encode())
    assert receipt == {"t": "res", "r": 200, "mac": VECTORS["peer"],
                       "opt": ["Pow", "unknown"], "p": [1, "raw"]}
    _, cached = exchange(device, {"t": "status", "list": [{"mac": VECTORS["peer"]}]})
    assert cached["list"] == [{"mac": VECTORS["peer"], "cols": ["Pow"], "dat": [0]}]
    exchange(device, {"t": "connect", "offlineSub": [VECTORS["peer"]], "onlineSub": []})
    assert exchange(device, {"t": "cmd", "opt": ["Pow"], "p": [1]},
                    cid=VECTORS["peer"], key=VECTORS["peer_key"].encode())[1]["r"] == 405
    assert exchange(device, {"t": "jsonCmd", "mac": VECTORS["peer"], "opt": ["Pow"], "p": [1]})[1] == {
        "t": "res", "r": 200, "mac": VECTORS["peer"]}


def test_scene_and_updown_local_receipts_do_not_fake_external_scene_results(device):
    bind_mini(device)
    assert exchange(device, {"t": "sceneSinglepush", "scene": {"raw": []},
                            "oper": 0, "type": 1, "requestId": "synthetic-scene"})[1] == {
        "t": "sceneSinglepushRes", "res": 200}
    request = {"t": "updownFlag", "requestId": "synthetic-updown",
               "config": [{"sub": VECTORS["peer"], "reqId": "synthetic-item"}]}
    assert exchange(device, request)[1] == {"t": "updownFlagRes", "r": [
        {"mac": VECTORS["peer"], "r": 200, "reqId": "synthetic-item"}]}
    assert exchange(device, request)[0] is None


def test_nlu_unsafe_port_only_path_rejects_atomically_and_configured_flag_ignores_updates(device):
    bind_mini(device)
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket, match="NLU port-only"):
        bind_mini(device, homeId=10, nluHost="changed.invalid", nluPort=65537)
    assert device.state == before
    device.state.update(nluinfo_flag=1, nluHost="configured.invalid", nluPort=4444)
    assert bind_mini(device, nluHost="ignored.invalid", nluPort=65537)[1]["t"] == "UBindok"
    assert (device.state["nluHost"], device.state["nluPort"]) == ("configured.invalid", 4444)
    bind_mini(device, province="province", city="city", orderID="synthetic-order")
    bind_mini(device, province="", city="", orderID="")
    assert (device.state["province"], device.state["city"], device.state["orderID"]) == (
        "province", "city", "synthetic-order")


def test_exact_config_widths_and_new_minipro_role_do_not_invent_host_authorization(device):
    for field, value in (("Gnetkey", "x" * 9), ("host", "x" * 33), ("nluHost", "x" * 33)):
        with pytest.raises(ValueError):
            device.profile.handler.validate_state({field: value})
    _, response = bind_peer(device, mid="70205", GnetID=65537, homeId=99)
    assert response["t"] == "UBindok" and "homeId" not in device.state
    assert device.state["_peers"][VECTORS["peer"]]["macId"] == 1
