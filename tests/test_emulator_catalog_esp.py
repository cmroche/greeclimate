"""Literal expectations from original ESP-1 CAN read/write instruction probes."""
import base64
from copy import deepcopy
from datetime import datetime
import json
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import pytest

from gree_emulator.profiles.catalog_esp import CanCache, SCHEMAS, _emitted_mid, _format_time, _schema
from gree_emulator.wire import InvalidPacket, encode_reply


VECTORS = json.loads((Path(__file__).parent / 'fixtures/emulator/catalog-esp-can-native-read_research.json').read_text())


@pytest.mark.parametrize('vector', VECTORS['vectors'])
def test_original_literal_getter_vectors(vector):
    cache = CanCache()
    cache.system[:] = [vector['raw']] * 112
    assert cache.read(vector['schema'], [vector['raw']] * 112, vector['name']) == vector['expected']


WRITE_VECTORS = json.loads((Path(__file__).parent / 'fixtures/emulator/catalog-esp-can-native-write_research.json').read_text())


@pytest.mark.parametrize('vector', WRITE_VECTORS['vectors'])
def test_original_literal_setter_vectors_and_native_loop_boundary(vector):
    cache, board = CanCache(), [0] * 112
    if vector['steps'] == 2000:
        with pytest.raises(InvalidPacket):
            cache.write(vector['schema'], board, vector['name'], vector['input'])
        assert board == [0] * 112
        return
    cache.write(vector['schema'], board, vector['name'], vector['input'])
    assert bytes(board[12:]).hex() == vector['unit']
    descriptor = SCHEMAS[vector['schema']].get(vector['name'])
    if descriptor is not None:
        assert cache.values[vector['schema']][descriptor[0]] == int.from_bytes(
            bytes.fromhex(vector['record'])[:2], 'little')


def test_raw_request_is_not_replaced_by_outgoing_can_enumeration():
    cache, board = CanCache(), [0] * 112
    cache.write(0, board, 'Mod', 0)
    assert cache.values[0][SCHEMAS[0]['Mod'][0]] == 5
    assert cache.read(0, board, 'Mod') == 0
    cache.write(0, board, 'SwhSlp', 1)
    assert cache.values[0][SCHEMAS[0]['SwhSlp'][0]] == 4
    assert cache.read(0, board, 'SwhSlp') == 1


def test_shared_descriptor_cache_retains_cross_child_decimal_effect():
    cache, first, second = CanCache(), [0] * 112, [0] * 112
    cache.write(0, first, 'SetTem', 24)
    assert first[28:30] == [240, 0]
    cache.write(0, second, 'Add0.1', 3)
    assert second[28:30] == [243, 0]
    assert cache.read(0, first, 'SetTem') == 24
    cache.write(0, second, 'Add0.1', 0)
    assert second[28:30] == [20, 0]


def test_system_owner_is_shared_and_mask_store_preserves_original_xor():
    cache, first, second = CanCache(), [0] * 112, [0] * 112
    cache.write(0, first, 'CleanTime', 19)
    assert cache.read(0, second, 'CleanTime') == 19
    assert first[18] == second[18] == 0
    cache.write(0, first, 'TemBody', 0)
    assert cache.read(0, first, 'TemBody') == 1
    cache.write(0, first, 'TemBody', 0)
    assert cache.read(0, first, 'TemBody') == 0
    cache.write(1, first, 'MIdType', 0x1234)
    assert first[11:13] == [0x34, 0x12]


@pytest.mark.parametrize('physical,expected', [(0x6079, 1), (0x605d, 1),
    (0x608d, 1), (0x6091, 1), (0x6099, 1), (0x6084, 7)])
def test_exact_physical_type_fan_selector(physical, expected):
    board = [0] * 112
    board[2:4] = [physical & 255, physical >> 8]
    board[21] = 1
    assert CanCache().read(1, board, 'WdSpd') == expected


def test_sensor_channel_and_safe_zero_mask_rejection():
    cache, board = CanCache(), [0] * 112
    board[31:36] = [10, 20, 30, 40, 50]
    assert [cache.read(1, board, 'TemSor', channel) for channel in range(5)] == [10, 20, 30, 40, 50]
    before = deepcopy((cache.values, board))
    with pytest.raises(InvalidPacket):
        cache.write(0, board, 'MidType', 1)
    assert (cache.values, board) == before
    for bad in (True, 1.5, '1', None, 1 << 32):
        with pytest.raises(InvalidPacket):
            cache.write(0, board, 'Pow', bad)
    copied = cache.copy()
    copied.system[18] = 99
    assert cache.system[18] == 0


@pytest.mark.parametrize('physical_type', [
    0x605d, 0x6079, 0x6084, 0x608d, 0x608e, 0x6091, 0x6099, 0x60a0,
])
def test_internal_alternate_types_share_only_actual_emitted_mid(physical_type):
    assert _schema(physical_type) == 1
    assert _emitted_mid(physical_type) == '6079'


@pytest.mark.parametrize('physical_type', [0x6049, 0x604a, 0x604b, 0x604c, 0x605c, 0x6080])
def test_default_schema_does_not_invent_normalized_aliases(physical_type):
    assert _schema(physical_type) == 0
    assert _emitted_mid(physical_type) == f'{physical_type:04x}'


def test_half_degree_callback_uses_setdecitem_sibling_not_settem_cache():
    cache, board = CanCache(), [0] * 112
    cache.write(0, board, 'SetTem', 24)
    cache.write(0, board, 'Add0.5', 1)
    assert board[28:30] == [5, 0]
    assert cache.values[0][SCHEMAS[0]['SetTem'][0]] == 240
    assert cache.values[0][SCHEMAS[0]['SetDeciTem'][0]] == 5
    cache.read(0, board, 'SetDeciTem')
    cache.write(0, board, 'Add0.5', 0)
    assert board[28:30] == [0, 0]


def test_actual_can_config_generated_identity_suffix_and_reorder():
    from gree_emulator.__main__ import load_config

    records = [
        {'id': 'first', 'profile': 'sim-esp32-gr-can-v2.01-6079',
         'mid': '6079', 'parent': 'root'},
        {'id': 'root', 'profile': 'sim-esp32-gr-can-v2.01', 'mid': '60'},
        {'id': 'second', 'profile': 'sim-esp32-gr-can-v2.01-6049',
         'mid': '6049', 'parent': 'root'},
    ]
    first = {device.id: device for device in load_config({'seed': 'can-identities', 'devices': records})[2]}
    reordered = {device.id: device for device in load_config({
        'seed': 'can-identities', 'devices': list(reversed(records)),
    })[2]}
    assert len(first['root'].mac) == 12
    for name in ('first', 'second'):
        assert len(first[name].mac) == 14 and first[name].mac.endswith('00')
        assert first[name].mac == reordered[name].mac
        assert first[name].key == first['root'].key
        assert first[name].profile.identity_suffix == b'\0'
    explicit = deepcopy(records)
    explicit[0]['mac'] = '02ABCDEF123400'
    configured = load_config({'devices': explicit})[2]
    assert configured[0].mac == '02abcdef123400'
    explicit[0]['mac'] = '02abcdef123401'
    with pytest.raises(ValueError, match=r'\.mac: expected suffix 00'):
        load_config({'devices': explicit})


@pytest.mark.parametrize('month,expected', [(1, '01'), (9, '09'), (10, '00'), (11, '11')])
def test_native_zero_based_month_padding_is_not_silently_corrected(month, expected):
    assert _format_time(datetime(2026, month, 2, 3, 4, 5)) == f'2026-{expected}-02 03:04:05'


@pytest.fixture
def can_device(monkeypatch):
    from gree_emulator.__main__ import load_config

    clock = [1000.0]
    monkeypatch.setattr('gree_emulator.profiles.catalog_esp.monotonic', lambda: clock[0])
    root, child = load_config({'seed': 'can-wire', 'devices': [
        {'id': 'root', 'profile': 'sim-esp32-gr-can-v2.01', 'mid': '60',
         'mac': '02000000c000', 'name': 'CAN'},
        {'id': 'child', 'profile': 'sim-esp32-gr-can-v2.01-6079', 'mid': '6079',
         'parent': 'root', 'mac': '02000000c00100'},
    ]})[2]
    return root, child, clock


def can_packet(root, inner, index=0, uid=37, cid='app', key=None):
    from gree_emulator.profiles.catalog_esp import GENERIC_KEY

    plain = json.dumps(inner, separators=(',', ':')).encode()
    selected = key if key is not None else root.key if index & 255 == 0 else GENERIC_KEY
    payload = plain.decode() if index & 255 == 2 else base64.b64encode(
        AES.new(selected, AES.MODE_ECB).encrypt(pad(plain, 16))).decode()
    return {'t': 'pack', 'i': index, 'uid': uid, 'cid': cid, 'tcid': root.mac, 'pack': payload}


def can_reply(root, inner, index=0, **kwargs):
    from gree_emulator.profiles.catalog_esp import GENERIC_KEY

    result, = root.profile.handler.handle(root, can_packet(root, inner, index, **kwargs))
    wire = encode_reply(result)
    assert not wire.endswith(b'\n')
    outer = json.loads(wire)
    if 'pack' not in outer:
        return outer
    assert outer['tcid'] == kwargs.get('cid', 'app')
    assert outer['uid'] == kwargs.get('uid', 37)
    selected = root.key if outer['i'] == 0 else GENERIC_KEY
    return json.loads(unpad(AES.new(selected, AES.MODE_ECB).decrypt(base64.b64decode(outer['pack'])), 16))


def test_actual_can_contexts_plaintext_wlan_and_cipher_peer_routing(can_device):
    root, child, _ = can_device
    handler = root.profile.handler
    assert handler.handle(root, can_packet(root, {'t': 'wlan'}, 1)) == []
    assert handler.handle(root, {'t': 'cmd', 'sub': child.mac, 'opt': ['Pow'], 'p': [1]}) == []
    assert handler.wlan(root, {'t': 'wlan', 'ssid': 'synthetic', 'psw': 'synthetic'})[0].outer == {
        't': 'ret', 'r': 200, 'mac': root.mac}
    assert can_reply(root, {'t': 'wlan', 'ssid': 'synthetic'}, 2) == {'t': 'ret', 'r': 200, 'mac': root.mac}
    assert can_reply(root, {'t': 'bind'}, 257, uid=-17, cid='peer-a') == {
        't': 'bindok', 'mac': root.mac, 'key': root.key.decode(), 'r': 200}
    assert can_reply(root, {'t': 'status', 'mac': child.mac, 'cols': ['Pow', 'MIdType']},
                     256, uid=99, cid='peer-b')['dat'] == [0, '6079']
    with pytest.raises(InvalidPacket):
        handler.handle(root, can_packet(root, {'t': 'status', 'mac': child.mac, 'cols': ['Pow']},
                                        key=b'wrongkeywrongkey'))


def test_can_native_header_mutation_routes_until_enumeration_restores_id(can_device):
    root, child, _ = can_device
    assert can_reply(root, {'t': 'cmd', 'sub': child.mac, 'opt': ['MIdType'], 'p': [1]})['p'] == [1]
    with pytest.raises(InvalidPacket):
        can_reply(root, {'t': 'status', 'mac': child.mac, 'cols': ['Pow']})
    changed = child.mac[:-2] + '01'
    assert can_reply(root, {'t': 'status', 'mac': changed, 'cols': ['Pow', 'MIdType']})['dat'] == [0, '6079']
    assert can_reply(root, {'t': 'subDev', 'mac': root.mac, 'i': 0})['list'][0]['mac'] == child.mac
    assert can_reply(root, {'t': 'status', 'mac': child.mac, 'cols': ['Pow']})['dat'] == [0]


def test_can_timer_storage_holes_native_total_and_source_enable_polarity(can_device):
    root, child, clock = can_device
    handler = root.profile.handler
    command = json.dumps({'mac': [child.mac], 'opt': ['Pow'], 'p': [1]}, separators=(',', ':'))
    timer = {'id': 0, 'name': 'once', 'enable': 0, 'hr': 0, 'min': 1, 'sec': 59,
             'tz': 123, 'week': [0] * 7, 'cmd': [command, 'noop']}
    assert can_reply(root, {'t': 'setT', **timer}) == {'t': 'resT', 'r': 200}
    assert can_reply(root, {'t': 'queryT', 'index': 0, 'count': 1}) == {
        't': 'listT', 'total': 1, 'index': 0, 'list': [{**timer, 'cmd': [json.loads(command)]}]}
    assert can_reply(root, {'t': 'queryT', 'index': 0, 'count': 2})['list'] == []
    clock[0] += 60
    handler.thermal_target(root)
    assert can_reply(root, {'t': 'status', 'mac': child.mac, 'cols': ['Pow']})['dat'] == [1]
    assert can_reply(root, {'t': 'queryT', 'index': 0, 'count': 1})['list'][0]['enable'] == 1
    can_reply(root, {'t': 'deleteT', 'id': 9})
    assert can_reply(root, {'t': 'queryT', 'index': 0, 'count': 1})['total'] == 0
    can_reply(root, {'t': 'deleteT', 'id': 0})
    assert can_reply(root, {'t': 'queryT', 'index': 0, 'count': 1}) == {
        't': 'listT', 'total': 0, 'index': 0, 'list': []}


def test_can_clock_tm_watchdog_log_and_upgrade_acceptance_not_completion(can_device):
    root, child, clock = can_device
    handler = root.profile.handler
    assert handler.handle(root, {'t': 'tm', 'time': '2026-10-24 01:02:03'}) == []
    assert can_reply(root, {'t': 'status', 'mac': child.mac, 'cols': ['time']})['dat'] == ['2026-00-24 09:02:03']
    assert handler.handle(root, {'t': 'hbok'}) == []
    assert root.state['_can_heartbeat_period'] == 120
    clock[0] += 131
    handler.thermal_target(root)
    assert root.state['_can_heartbeat_period'] == 10
    assert handler.handle(root, {'t': 'espLog', 'tag': 'synthetic', 'level': 9}) == []
    assert root.state['_can_log_level'] == 5
    assert handler.handle(root, can_packet(root, {'t': 'loginRes', 'r': 200}, 1)) == []
    assert root.state['_can_login_ok'] is True
    assert can_reply(root, {'t': 'upgrade', 'url': 'http://synthetic.invalid/firmware'}) == {
        't': 'ret', 'r': 200, 'mac': root.mac}
    assert root.state['_can_upgrade_url'] == 'http://synthetic.invalid/firmware'


@pytest.mark.parametrize('bad', [True, None, [], {}, '2147483648', 2147483648])
def test_can_atomic_parser_recovery_preserves_raw_banks_and_descriptor_cache(can_device, bad):
    root, child, _ = can_device
    assert can_reply(root, {'t': 'status', 'mac': child.mac, 'cols': ['Pow']})['dat'] == [0]
    before = deepcopy(root.state['_can_boards']), deepcopy(root.state['_can_cache'].values)
    with pytest.raises(InvalidPacket):
        can_reply(root, {'t': 'cmd', 'sub': child.mac, 'opt': ['Pow', 'Mod'], 'p': [1, bad]})
    assert (root.state['_can_boards'], root.state['_can_cache'].values) == before
    assert can_reply(root, {'t': 'status', 'mac': child.mac, 'cols': ['Pow']})['dat'] == [0]


def test_can_source_time_word_wrap_and_malformed_operation_recovery(can_device):
    root, child, clock = can_device
    can_reply(root, {'t': 'cmd', 'opt': ['time'], 'p': ['2038-01-19 11:14:07']})
    clock[0] += 1
    assert can_reply(root, {'t': 'status', 'mac': child.mac, 'cols': ['time']})['dat'] == ['1901-12-14 04:45:52']
    for kind in ([], {}, 1, None):
        with pytest.raises(InvalidPacket):
            root.profile.handler.handle(root, can_packet(root, {'t': kind}))
    assert can_reply(root, {'t': 'status', 'mac': child.mac, 'cols': ['Pow']})['dat'] == [0]


def test_can_complete_metadata_root_and_child_unknowns_are_not_typed_controls(can_device):
    root, child, _ = can_device
    columns = ['host', 'name', 'hid', 'rssi', 'MIdType', 'bc', 'time', 'ElcEn', 'unknown']
    expected = ['dis.gree.com', 'CAN', '362001063222+U-ESP32_GR_CANV2.01.bin',
                0, '6079', '', '2000-01-01 00:00:00', 0, 0]
    for identity in (root.mac, child.mac):
        assert can_reply(root, {'t': 'status', 'mac': identity, 'cols': columns})['dat'] == expected
    result = can_reply(root, {'t': 'cmd', 'opt': ['host', 'name', 'hid', 'rssi', 'ElcEn'],
                              'p': ['changed', 'changed', 'changed', 99, 1]})
    assert result['p'] == result['val'] == ['changed', 'changed', 'changed', '99', '1']
    assert can_reply(root, {'t': 'status', 'mac': child.mac, 'cols': columns})['dat'] == expected
