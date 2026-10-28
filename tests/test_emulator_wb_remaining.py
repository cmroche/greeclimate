"""Exact-source bounded WB namespaces; no native UDP admission for ART or SR."""
import base64
from copy import deepcopy
import json
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles import wb_remaining as wb
from gree_emulator.wire import InvalidPacket, Reply, encode_reply


VECTORS = json.loads((Path(__file__).parent / 'fixtures/emulator/catalog-wb-remaining_research.json').read_text())
RAW = VECTORS['sources']
DRA = VECTORS['dra']


def model(vector):
    profile = next(item for item in wb.PROFILES if item.id == vector['profile'])
    return EmulatedDevice(id='raw', mac='020000000001', name='WB Raw', mid=vector['mid'],
                          key=b'0123456789abcdef', profile=profile,
                          state=deepcopy(dict(profile.initial_state)))


def request(device, inner, index=0, uid=7):
    key = wb.GENERIC_KEY if index else device.key
    outer = {'t': 'pack', 'i': index, 'uid': uid, 'cid': 'peer', 'tcid': device.mac}
    packet = json.loads(encode_reply(Reply(outer, inner, key, wb.CODEC)))
    return device.profile.handler.handle(device, packet)


def exchange(device, inner, **kwargs):
    return request(device, inner, **kwargs)[0].inner


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch):
    monkeypatch.setattr(wb.time, 'monotonic', lambda: 0.0)


def test_only_native_reply_qualified_source_roles_are_exported():
    assert {profile.id for profile in wb.PROFILES} == {row['profile'] for row in RAW} | {DRA['profile']}
    assert all('art' not in profile.id and 'sr' not in profile.id for profile in wb.PROFILES)
    assert len(wb.ART_NAMES) == 343
    assert len(wb.ART138_NAMES) == 324
    assert len(wb.MARJ_NAMES) == len(wb.MAJD_NAMES) == 476
    assert len(wb.DRA_OPERATIONS) == 37
    assert len(set(wb.DRA_OPERATIONS)) == 36
    assert next(profile for profile in wb.PROFILES if profile.id == DRA['profile']).max_request_bytes == 1024


@pytest.mark.parametrize('vector', RAW, ids=lambda row: row['profile'])
def test_every_source_raw_getter_and_command_uses_low16_not_ac_presets(vector):
    device = model(vector)
    assert device.profile.source_sha256 == vector['source_sha256']
    assert device.profile.hid == vector['hid']
    for offset in range(0, len(vector['raw_names']), 8):
        names = vector['raw_names'][offset:offset + 8]
        reply = exchange(device, {'t': 'cmd', 'opt': names, 'p': [-1] * len(names)})
        assert reply == {'t': 'res', 'mac': device.mac, 'opt': names, 'p': [-1] * len(names), 'r': 200}
        assert exchange(device, {'t': 'status', 'cols': names})['dat'] == [65535] * len(names)
        assert all(device.state['reported'][name] == 65535 for name in names)


@pytest.mark.parametrize('vector', RAW, ids=lambda row: row['profile'])
def test_literal_metadata_precedence_and_zero_output_cardinality(vector):
    device = model(vector)
    expected = vector['metadata']
    reply = exchange(device, {'t': 'status', 'cols': expected['cols'] + ['__unknown__']}, uid=-1)
    assert reply == {'t': 'dat', 'uid': 4294967295, 'mac': device.mac, 'cid': device.mac,
                     'cols': expected['cols'], 'dat': expected['dat'], 'r': 200}
    assert len(reply['cols']) == len(reply['dat']) + 2
    for name in vector['raw_write_only_names']:
        before = exchange(device, {'t': 'status', 'cols': [name]})['dat']
        assert exchange(device, {'t': 'cmd', 'opt': [name], 'p': [65537]})['p'] == [65537]
        assert device.state['reported'][name] == 1
        assert exchange(device, {'t': 'status', 'cols': [name]})['dat'] == before


@pytest.mark.parametrize('vector', RAW, ids=lambda row: row['profile'])
def test_raw_boundaries_duplicates_and_fresh_instance_isolation(vector):
    device, other = model(vector), model(vector)
    reply = exchange(device, {'t': 'cmd', 'opt': ['Pow', 'Pow', 'SetTem', 'NoD'],
                              'p': [-1, 65536, 74565, -65537]})
    assert reply['p'] == [-1, 65536, 74565, -65537]
    assert exchange(device, {'t': 'status', 'cols': ['Pow', 'SetTem', 'NoD', 'Pow']})['dat'] == [0, 9029, 65535, 0]
    assert exchange(other, {'t': 'status', 'cols': ['Pow', 'SetTem', 'NoD']})['dat'] == [0, 0, 0]
    assert device.profile.handler.thermal_target(device) is None


@pytest.mark.parametrize('vector', RAW, ids=lambda row: row['profile'])
@pytest.mark.parametrize('invalid', [True, 1.5, '1', None, {}, [], 2147483648])
def test_invalid_batch_rejects_atomically_before_cache_or_queue_changes(vector, invalid):
    device = model(vector)
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        request(device, {'t': 'cmd', 'opt': ['Pow', 'ElcP'], 'p': [1, invalid]})
    assert device.state == before


@pytest.mark.parametrize('vector', RAW, ids=lambda row: row['profile'])
def test_local_setters_are_regrouped_and_do_not_rename_or_enable_timer(vector):
    device = model(vector)
    reply = exchange(device, {'t': 'cmd', 'opt': ['Pow', 'name', 'SetTem', 'AppTimer'],
                              'p': [1, 'Not applied', 31, 9]})
    assert reply['opt'] == ['name', 'AppTimer', 'Pow', 'SetTem']
    assert reply['p'] == ['WB Raw', 0, 1, 31]
    assert device.name == 'WB Raw'
    exchange(device, {'t': 'cmd', 'opt': ['ReportClientID'], 'p': ['local-peer']})
    assert device.state['_report_client'] == 'local-peer'
    exchange(device, {'t': 'cmd', 'opt': ['time'], 'p': ['2031-02-03 04:05:06']})
    assert exchange(device, {'t': 'status', 'cols': ['time']})['dat'] == ['2031-02-03 04:05:06']


@pytest.mark.parametrize('vector', RAW, ids=lambda row: row['profile'])
def test_native_binary_queue_shape_is_not_a_mainboard_completion_ack(vector):
    device = model(vector)
    frame = b'~~\x06\x00\x00\x00\x00\x00'
    reply = exchange(device, {'t': 'binCmd', 'hex01': base64.b64encode(frame).decode()})
    assert reply == {'t': 'res', 'r': 200}
    queued = bytes.fromhex(device.state['outbound'][-1])
    assert queued[:8] == b'~~\x06\x00\x00\x00\x00\xaf'
    assert len(queued) == 60 and queued[43] == 2
    assert exchange(device, {'t': 'status', 'cols': ['Pow']})['dat'] == [0]
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        request(device, {'t': 'binCmd', 'hex01': 'not-base64'})
    assert device.state == before


def timer(identifier=257, name='timer'):
    return {'t': 'setT', 'id': identifier, 'name': name, 'enable': 2, 'tz': 8,
            'hr': 257, 'min': 258, 'sec': 99, 'week': [2, 0, 0, 0, 0, 0, 0],
            'cmd': [{'opt': ['Pow', 'SetTem'], 'p': [511, 33]}]}


@pytest.mark.parametrize('vector', RAW, ids=lambda row: row['profile'])
def test_source_timer_storage_widths_seconds_bug_and_literal_query(vector):
    device = model(vector)
    assert exchange(device, timer()) == {'t': 'resT', 'r': 200}
    reply = exchange(device, {'t': 'queryT', 'index': 0, 'count': 10})
    assert reply == {'t': 'listT', 'total': 1, 'index': 0, 'list': [
        {'id': 1, 'name': 'timer', 'enable': 0, 'week': [0, 1, 0, 0, 0, 0, 0],
         'hr': 1, 'min': 2, 'sec': 0,
         'cmd': [{'mac': [device.mac], 'opt': ['Pow'], 'p': [255]}]}]}
    if 'majd' in vector['profile']:
        with pytest.raises(InvalidPacket):
            request(device, timer(name='duplicate'))
    else:
        exchange(device, timer(name='duplicate'))
        assert exchange(device, {'t': 'queryT', 'index': 0, 'count': 1})['list'][0]['name'] == 'duplicate'
    update = timer(identifier=2)
    update['t'] = 'updateT'
    exchange(device, update)
    assert len(device.state['timers']) == 1
    assert exchange(device, {'t': 'deleteT', 'id': 257}) == {'t': 'resT', 'r': 200}
    assert exchange(device, {'t': 'queryT', 'index': 0, 'count': 10})['list'] == []


@pytest.mark.parametrize('vector', RAW, ids=lambda row: row['profile'])
def test_plain_wlan_and_clock_paths_keep_native_plain_reply_and_no_network_work(vector):
    device = model(vector)
    replies = device.profile.handler.wlan(device, {'t': 'wlan', 'host': 'dis.gree.com', 'ssid': 'lab', 'psw': 'secret'})
    assert replies[0].inner is None
    assert replies[0].outer == {'t': 'ret', 'r': 200, 'mac': device.mac}
    challenge = base64.b64encode(AES.new(device.key, AES.MODE_ECB).encrypt(pad(b'key is ok', 16))).decode()
    assert device.profile.handler.handle(device, {'t': 'tm', 'encrypt': challenge, 'time': '2031-02-03 04:05:06'}) == []
    assert exchange(device, {'t': 'status', 'cols': ['time']})['dat'] == ['2031-02-03 04:05:06']
    if 'marj' in vector['profile']:
        with pytest.raises(InvalidPacket, match='pointer0xc8'):
            request(device, {'t': 'reset'})
    assert exchange(device, {'t': 'upgrade', 'url': 'https://example.invalid/source.bin'}) == {'t': 'ret', 'r': 200}


def test_dra_custom_discovery_and_coordinator_counter_are_not_ordinary_dev():
    device = model(DRA)
    reply = device.profile.handler.advertise(device, {'t': 'scan'})[0]
    assert reply.destination_port == 5001
    assert reply.outer == {'t': 'pack', 'i': 1, 'uid': 0, 'msgId': 1, 'cid': device.mac, 'tcid': ''}
    assert reply.inner == {'t': 'UBind', 'scene': 1, 'mid': '10001', 'ver': 'V3.5.MF4',
                           'lock': 0, 'devkey': '0123456789abcdef', 'hid': DRA['hid']}
    reply = request(device, {'t': 'UBindok', 'mac': 'coordinator'})[0]
    assert reply.inner == {'t': 'Utm', 'mac': device.mac}
    assert reply.outer['tcid'] == 'coordinator' and reply.outer['msgId'] == 2
    assert device.state['_msg_id'] == 4
    assert exchange(device, {'t': 'subBList'}) == {'t': 'subBList', 'i': 0, 'list': '(null)|10001'}
    assert exchange(device, {'t': 'connect'})['onlineSub'] == []


def test_dra_all_metadata_fields_and_scalar_local_operations():
    device = model(DRA)
    reply = exchange(device, {'t': 'status', 'cols': ['host', 'ver', 'hid', 'mid', 'bc', 'Pow']})
    assert reply == {'t': 'dat', 'r': 200, 'mac': device.mac,
                     'cols': ['host', 'ver', 'hid', 'mid', 'bc'],
                     'dat': ['synthetic.invalid', 'V3.5.MF4', DRA['hid'], '10001', '0' * 32]}
    assert request(device, {'t': 'metadata', 'p': [257]}) == []
    assert exchange(device, {'t': 'metadatapub'})['p'] == [1]
    assert request(device, {'t': 'loginInfoRes', 'r': 200, 'loginInfo': {'GnetID': 257}}) == []
    assert exchange(device, {'t': 'GnetOK'})['GnetID'] == 1
    assert request(device, {'t': 'tm', 'timestamp': 1234000}) == []
    assert device.state['_clock'] == 1234
    assert request(device, {'t': 'ReportCtrl', 'ActiveTime': -1, 'ReportInterval': 7}) == []
    assert (device.state['_active_time'], device.state['_report_interval']) == (4294967295, 7)
    assert exchange(device, {'t': 'statusCheck'}) == {'t': 'statusCheckRes', 'binStatus': ''}
    device.state['_uart_status'] = [(b'~~\x01\x00', False), (b'~~\x01\xff', True)]
    assert exchange(device, {'t': 'statusCheck'}) == {'t': 'statusCheckRes', 'binStatus': 'fn4BAA=='}
    assert exchange(device, {'t': 'bind'}, index=1)['key'] == '0123456789abcdef'
    assert 'key' not in exchange(device, {'t': 'blekey', 'oldkey': 1}, index=1)
    generated = exchange(device, {'t': 'jsonStatus'})
    assert generated['cols'] == ['AppTimer', 'ver', 'host', 'name', 'bc', 'mac', 'mid', 'hid', 'BuzzerCtrl', 'ElcEn']
    assert generated['dat'][-2:] == [0, 0]


@pytest.mark.parametrize('kind', ['binStatus', 'binEvent'])
def test_dra_binary_wrappers_preserve_original_encrypted_token_bytes(kind):
    device = model(DRA)
    plain = ('{ "t" : "' + kind + '" }').encode()
    packet = {'t': 'pack', 'i': 0, 'tcid': device.mac,
              'pack': base64.b64encode(AES.new(device.key, AES.MODE_ECB).encrypt(pad(plain, 16))).decode()}
    reply = device.profile.handler.handle(device, packet)[0]
    assert reply.inner == {'t': kind, 'mac': device.mac, kind: base64.b64encode(plain).decode()}


def test_dra_cp_fragment_reassembly_and_plaintext_slot_minus_one():
    device = model(DRA)
    payload = '{"t":"status","cols":["ver"]}'
    assert device.profile.handler.handle(device, {'t': 'CP', 'pins': 2, 'pin': 1, 'tag': 'case', 'CP': payload[:12]}) == []
    reply = device.profile.handler.handle(device, {'t': 'CP', 'pins': 2, 'pin': 2, 'tag': 'case', 'CP': payload[12:]})[0]
    assert reply.inner['dat'] == ['V3.5.MF4']
    reply = device.profile.handler.handle(device, {'t': 'pack', 'i': -1, 'tcid': device.mac, 'pack': '{"t":"metadatapub"}'})[0]
    assert reply.inner is None and reply.outer == {'t': 'metadata', 'mac': device.mac, 'opt': ['permitStatus'], 'p': [0]}


def test_dra_frequency_uses_strstr_and_original_pointer_period_without_ack():
    device = model(DRA)
    assert request(device, {'t': 'freqCount',
                            'opt': ['prefixSendFreq', 'FreqTimeSuffix', 'FreqCount'],
                            'p': [0, 7, 99]}) == []
    assert device.state['_freq_time'] == 7
    assert ('UartEvent', 8) in device.state['outbound']
    assert ('UartEvent', 14) in device.state['outbound']
    assert device.state['_native_timers']['activeTime']['ticks'] == 63898
    assert device.state['_native_timers']['activeTime']['callback'] == '0x0e016ad8'


def test_dra_report_limit_copies_binary_and_low_byte_nra_without_ack():
    device = model(DRA)
    assert request(device, {'t': 'ReportLimit', 'prefixCtrlFunc': 'fn4DEAEC',
                            'NRA': [[272, -1, 3.9], [1, 2, 3, 99]],
                            'midReportInterval': -7.9}) == []
    assert device.state['_ctrl_func'] == b'~~\x03\x10\x01\x02'
    assert device.state['_nra'] == [(16, 255, 3), (1, 2, 3)]
    assert device.state['_mid_report_interval'] == -7
    assert ('state-event', 8) in device.state['outbound']
    before = deepcopy(device.state['_nra'])
    assert request(device, {'t': 'ReportLimit', 'NRA': []}) == []
    assert device.state['_nra'] == before


def test_dra_network_info_substring_one_time_key_and_conditional_restart():
    device = model(DRA)
    device.state['_native_mode'] = 1
    assert request(device, {'t': 'networkInfo', 'gnetKey': 'ffffffff'}) == []
    assert device.state['_gnet_key'] == b''
    assert request(device, {'t': 'networkInfo', 'prefixgnetkeysuffix': 'a1b2c3d4extra'}) == []
    assert device.state['_gnet_key'] == b'\xa1\xb2\xc3\xd4'
    assert device.state['_gnet_key_ready'] == 1
    assert ('state-event', 4) in device.state['outbound']
    assert ('network-restart',) in device.state['outbound']
    before = deepcopy(device.state)
    assert request(device, {'t': 'networkInfo', 'gnetkey': '00000000'}) == []
    assert device.state == before


def test_dra_network_hex_converter_maps_nonhex_nibbles_to_zero():
    device = model(DRA)
    assert request(device, {'t': 'networkInfo', 'gnetkey': 'z1b?c3d4'}) == []
    assert device.state['_gnet_key'] == b'\x01\xb0\xc3\xd4'


def test_dra_binary_command_queues_native_frame_without_claiming_delivery():
    device = model(DRA)
    reply = exchange(device, {'t': 'binCmd', 'hex01': 'fn4DEAAA', 'roomId': 257})
    assert reply == {'t': 'res', 'r': 200, 'mac': device.mac}
    assert ('UartEvent', 9, b'~~\x03\x10\x00\x00') in device.state['outbound']
    assert device.state['_room_id'] == 1
    assert device.state['_uart_status'] == []
    assert device.state['_native_timers']['fragmentTimer']['ticks'] == 30


def test_dra_fragment_masks_and_scene_one_inverse_storage_are_source_specific():
    device = model(DRA)
    reply = exchange(device, {'t': 'binCmd', 'hex01': 'fn4DEAAA',
                              'fragment': [[16, 1, 240, 2]], 'sceneId': 1, 'operType': 1})
    assert reply == {'t': 'res', 'r': 200, 'mac': device.mac}
    assert device.state['_scenes'][1] == b'~~\x03\x10\x20\x00'
    assert device.state['_scenes'][2] == b'~~\x03\x10\x00\x00'
    assert not any(work[0] == 'UartEvent' and work[1] == 9
                   for work in device.state['outbound'])
    assert exchange(device, {'t': 'binCmd', 'sceneId': 1, 'operType': 2})['r'] == 200
    assert 1 not in device.state['_scenes']


def test_dra_scene_store_retains_native_overwrite_not_invented_concatenation():
    device = model(DRA)
    assert exchange(device, {'t': 'binCmd', 'hex01': 'fn4DEAAA',
                             'hex02': 'fn4DEQAA', 'sceneId': 3, 'operType': 1})['r'] == 200
    assert device.state['_scenes'][3] == b'~~\x03\x11\x00\x00' + bytes(6)
    assert exchange(device, {'t': 'binCmd', 'sceneId': 1, 'operType': 1})['r'] == 501


def test_dra_special_binary_fields_cache_time_countdown_weather_and_flag():
    device = model(DRA)
    fields = {
        'hex6A': b'RAW',
        'hex6B': b'~~\x15\x00' + b'2025-01-02 03:04:05' + b'\x00',
        'hex6C': b'~~\x03\x00\x46\x00',
        'hex6D': b'~~\x05\x00sun\x00',
        'hex6E': b'~~\x09\x00\x00\x00\x01' + bytes(5),
    }
    reply = exchange(device, {'t': 'binCmd', **{
        name: base64.b64encode(value).decode() for name, value in fields.items()}})
    assert reply == {'t': 'res', 'r': 200, 'mac': device.mac}
    assert device.state['_binary_cache']['hex6A'][:3] == b'RAW'
    assert device.state['_time_valid'] == 1
    assert device.state['_default_timer'] == -1
    assert device.state['_default_countdown'] == 60
    assert device.state['_weather'] == b'sun'
    assert device.state['_binary_flag'] == 1
    assert ('UartEvent', 5) in device.state['outbound']
    assert not any(work[0] == 'UartEvent' and work[1] == 9
                   for work in device.state['outbound'])
    cached = device.state['_binary_cache']['hex6A']
    assert exchange(device, {'t': 'binCmd', 'hex6A': ''})['r'] == 200
    assert device.state['_binary_cache']['hex6A'] == cached


@pytest.mark.parametrize('inner', [
    {'t': 'freqCount', 'opt': ['FreqTime'], 'p': []},
    {'t': 'ReportLimit', 'CtrlFunc': 'not-base64'},
    {'t': 'ReportLimit', 'NRA': [[1, 2]]},
    {'t': 'networkInfo', 'gnetkey': '123'},
    {'t': 'binCmd', 'hex01': 'not-base64'},
    {'t': 'binCmd', 'hex01': 'fn4DEAAA', 'fragment': [[16, 255, 1, 1]]},
])
def test_dra_native_unsafe_inputs_are_atomic_safe_rejections(inner):
    device = model(DRA)
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        request(device, inner)
    assert device.state == before


@pytest.mark.parametrize('vector', RAW, ids=lambda row: row['profile'])
@pytest.mark.parametrize('index', [0, 1])
def test_native_selectors_do_not_invent_per_operation_key_restrictions(vector, index):
    device = model(vector)
    replies = request(device, {'t': 'status', 'cols': ['Pow']}, index=index)
    assert replies[0].outer['i'] == index
    assert replies[0].key == (wb.GENERIC_KEY if index else device.key)
    assert replies[0].inner['dat'] == [0]
    reply = exchange(device, {'t': 'bind', 'mac': 'opaque-peer'}, index=index)
    assert reply == {'r': 200, 't': 'bindok', 'mac': 'opaque-peer', 'key': '0123456789abcdef'}


def test_dra_local_identity_network_config_reset_and_upgrade_queue_paths():
    device = model(DRA)
    assert exchange(device, {'t': 'bleinfo'}) == {
        't': 'bleinfo', 'wificon': 0, 'mac': device.mac, 'mid': '10001', 'ver': 'V3.5.MF4'}
    assert exchange(device, {'t': 'bleCheck'}) == {'t': 'bleCheck', 'mac': device.mac, 'num': 0}
    assert exchange(device, {'t': 'wlanchk'}) == {'t': 'wlanchk', 'mac': device.mac, 'num': 0, 'code': 0}
    assert exchange(device, {'t': 'subBDev'}) == {'t': 'subBList', 'i': 0, 'list': '(null)|10001'}
    network = {'ssid': 'lab', 'psw': 'secret', 'host': 'network.invalid'}
    assert request(device, {'t': 'wlan', **network}) == []
    assert device.state['_network'] == network
    assert exchange(device, {'t': 'status', 'cols': ['host']})['dat'] == ['synthetic.invalid']
    assert exchange(device, {'t': 'GnetDev', **network, 'GnetID': 257, 'GnetKey': '00010203'})['GnetID'] == 1
    assert device.state['_gnet_key'] == b'\x00\x01\x02\x03'
    mqtt = {'host': 'mqtt.invalid', 'port': 1883, 'username': 'user', 'password': 'secret'}
    assert request(device, {'t': 'svr', 'mqttInfo': mqtt}) == []
    assert device.state['_mqtt'] == mqtt
    assert request(device, {'t': 'reset', 'mac': 'not-this-module'}) == []
    assert exchange(device, {'t': 'reset', 'mac': device.mac}) == {'t': 'res', 'r': 200, 'mac': device.mac}
    assert device.state['outbound'][-1] == ('reset', 2)
    before = deepcopy(device.state['outbound'])
    assert exchange(device, {'t': 'upgrade', 'mac': 'not-this-module'}) == {'t': 'res', 'r': 200, 'mac': device.mac}
    assert device.state['outbound'] == before
    url = 'https://example.invalid/source.bin'
    assert exchange(device, {'t': 'upgrade', 'mac': device.mac, 'url': url})['r'] == 200
    assert device.state['outbound'][-1] == ('upgrade', url)
    assert exchange(device, {'t': 'Ackup', 'OTAMac': device.mac}) == {'t': 'res', 'r': 200, 'mac': device.mac}
    assert device.state['_ota_ack'] is True
    reply = request(device, {'t': 'dis'})[0]
    assert reply.outer == {'t': 'dis', 'mac': device.mac, 'needMqtt': 1}
    assert reply.inner is None and reply.trailing_newline and reply.destination_port == 5001
