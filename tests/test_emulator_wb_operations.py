"""Literal source-qualified RT13 operations, independent of client polling presets."""
from copy import deepcopy
import json

import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles import wb_rt13
from gree_emulator.wire import InvalidPacket, Reply, encode_reply


@pytest.fixture(params=['1.54', '1.64', '1.57', '1.54-c9e8d4b563f7'])
def device(request):
    profile = next(profile for profile in wb_rt13.PROFILES if profile.id == 'sim-wb05rt13-v' + request.param)
    return EmulatedDevice(id='operations', mac='020000000001', name='RT13', mid='10001',
                          key=b'0123456789abcdef', profile=profile,
                          state=deepcopy(dict(profile.initial_state)))


def send(device, inner):
    envelope = {'t': 'pack', 'i': 0, 'uid': 9, 'cid': 'peer', 'tcid': device.mac}
    packet = json.loads(encode_reply(Reply(envelope, inner, device.key, 'aes-gcm')))
    return [reply.inner for reply in device.profile.handler.handle(device, packet)]


def timer(identifier=2):
    return {'t': 'setT', 'id': identifier, 'name': 'Morning', 'enable': 2,
            'tz': 480, 'hr': 256, 'min': 257, 'sec': 47,
            'week': [1, 2, 0, 0, 0, 0, 1],
            'cmd': [{'mac': ['ignored-native-input'], 'opt': ['SetTem', 'Pow', 'Pow'], 'p': [511, 257, 258]}]}


def test_timer_store_query_and_update_preserve_source_effective_projection(device):
    assert send(device, timer()) == [{'t': 'resT', 'r': 200}]
    expected = {'t': 'listT', 'total': 1, 'index': 0, 'list': [
        {'id': 2, 'name': 'Morning', 'enable': 0, 'week': [1, 0, 1, 0, 0, 0, 1],
         'hr': 0, 'min': 1, 'sec': 0,
         'cmd': {'mac': ['020000000001'], 'opt': ['Pow'], 'p': [2]}}]}
    assert send(device, {'t': 'queryT', 'index': 0, 'count': 10}) == [expected]
    update = {**timer(), 't': 'updateT', 'name': 'Changed', 'enable': 1}
    update.pop('sec')
    assert send(device, update) == [{'t': 'resT', 'r': 200}]
    expected['list'][0].update(name='Changed', enable=1, sec=1)
    assert send(device, {'t': 'queryT', 'index': 0, 'count': 10}) == [expected]
    assert send(device, {'t': 'queryT', 'index': 3, 'count': 10}) == [
        {'t': 'listT', 'total': 1, 'index': 3, 'list': []}]


def test_timer_capacity_and_unknown_delete_keep_native_count_distinct_from_records(device):
    assert send(device, {'t': 'deleteT', 'id': 7}) == [{'t': 'resT', 'r': 200}]
    assert send(device, {'t': 'queryT', 'index': 0, 'count': 10}) == [
        {'t': 'listT', 'total': 255, 'index': 0, 'list': []}]
    assert send(device, timer()) == []


def test_timer_missing_update_ack_does_not_invent_a_record(device):
    assert send(device, {**timer(4), 't': 'updateT'}) == [{'t': 'resT', 'r': 200}]
    assert send(device, {'t': 'queryT', 'index': 0, 'count': 10}) == [
        {'t': 'listT', 'total': 0, 'index': 0, 'list': []}]


def test_timer_full_capacity_rejects_even_set_of_an_existing_id(device):
    for identifier in range(10):
        assert send(device, timer(identifier)) == [{'t': 'resT', 'r': 200}]
    assert send(device, {**timer(), 'name': 'Not stored'}) == []
    assert device.state['_wb_timers'][2]['name'] == 'Morning'


@pytest.mark.parametrize('period,count,expected', [(0, 0, (60, 1)), (1, -5, (5, 1)), (5000, 7, (4096, 7))])
def test_dump_clamps_exact_report_configuration(device, period, count, expected):
    assert send(device, {'t': 'dump', 'period': period, 'cnt': count}) == [{'t': 'ret', 'r': 200}]
    assert device.state['_wb_dump'] == {'period': expected[0], 'cnt': expected[1]}


def test_binary_command_stages_uart_without_claiming_reported_power(device):
    assert send(device, {'t': 'binCmd', 'hex01': 'fn4GAQAAAAA='}) == [{'t': 'res', 'r': 200}]
    expected = [126, 126, 6, 1, 0, 0, 0, 175] + [0] * 35 + [2] + [0] * 16
    assert device.state['_wb_uart_frame'] == expected
    assert device.state['Pow'] == 0
    assert send(device, {'t': 'binCmd', 'hex15': 'fn4GAQAAAAA=', 'ReportFreq': 255,
                         'ReportClientID': 'request/local-peer'}) == [{'t': 'res', 'r': 200}]
    expected[7] = 0
    assert device.state['_wb_uart_frame'] == expected
    assert device.state['_wb_report_frequency'] == 300
    assert device.state['_wb_report_client'] == 'request/local-peer'


def test_binary_invalid_batch_is_atomic_before_report_target_mutation(device):
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        send(device, {'t': 'binCmd', 'hex01': 'bm90LWFuLXVhcnQtZnJhbWU=', 'ReportClientID': 'request/changed'})
    assert device.state == before


def test_report_control_and_frequency_have_no_fabricated_ack(device):
    assert send(device, {'t': 'ReportCtrl', 'ActiveTime': 3, 'ReportInterval': 9,
                         'reportAnyway': True}) == []
    assert device.state['_wb_reporting'] == {'request': {'ActiveTime': 3, 'ReportInterval': 9}}
    assert device.state['_wb_report_active_word'] == 16564
    assert device.state['_wb_report_state'] == 2
    assert send(device, {'t': 'freqCount', 'opt': ['SendFreq', 'FreqTime', 'DRTime'], 'p': [1, 7, 8]}) == []
    assert [device.state[name] for name in ('_wb_SendFreq', '_wb_FreqTime', '_wb_DRTime')] == [1, 7, 8]


def test_upgrade_is_a_local_queue_not_a_download_and_busy_requests_get_no_success(device):
    request = {'t': 'upgrade', 'OTAVer': ['V9.99'], 'OTAUrl': ['https://example.invalid/firmware.bin'],
               'OTACode': ['362001065279']}
    assert send(device, request) == [{'t': 'ret', 'r': 200}]
    assert device.state['_wb_ota_queue'] == {'code': '362001065279', 'version': 999,
                                            'url': 'https://example.invalid/firmware.bin'}
    assert device.state['_wb_upgrade_status'] == 16387
    assert send(device, request) == []
    assert send(device, {'t': 'Ackup', 'OTAType': 1}) == [{'t': 'ret', 'r': 200}]
    assert device.state['_wb_ota_ack']['OTAType'] == 1


def test_reset_does_not_turn_unqualified_rom_string_bytes_into_success(device):
    before = deepcopy(device.state)
    assert send(device, {'t': 'reset', 'mac': device.mac}) == []
    assert device.state == before


@pytest.mark.parametrize('change', [{'week': [1]}, {'tz': True}, {'name': 'x' * 32},
                                    {'cmd': [{'opt': ['Pow'], 'p': []}]}])
def test_timer_validation_is_atomic_not_native_partial_mutation(device, change):
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        send(device, {**timer(), **change})
    assert device.state == before
