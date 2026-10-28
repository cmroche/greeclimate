"""Literal original-source commercial tables, local callbacks and work receipts."""
import base64
from copy import deepcopy
import json
from pathlib import Path

import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles import commercial
from gree_emulator.wire import InvalidPacket, Reply, encode_reply


VECTORS = json.loads((Path(__file__).parent / 'fixtures/emulator/catalog-wb-commercial_research.json').read_text())


def model(vector, suffix='3027', **kwargs):
    profile = next(profile for profile in commercial.PROFILES
                   if profile.id == f"sim-wb04brt13-v{vector['version']}-{suffix}")
    return EmulatedDevice(id='commercial', mac='020000000001', name='Commercial Raw',
                          mid=suffix, key=b'0123456789abcdef', profile=profile,
                          state=deepcopy(dict(profile.initial_state)), **kwargs)


def exchange(device, inner):
    outer = {'t': 'pack', 'i': 0, 'uid': 9, 'cid': 'peer', 'tcid': device.mac}
    packet = json.loads(encode_reply(Reply(outer, inner, device.key, commercial.CODEC)))
    return device.profile.handler.handle(device, packet)


@pytest.mark.parametrize('vector', VECTORS['sources'], ids=lambda row: row['version'])
def test_complete_commercial_numeric_namespace_and_fresh_low16_reads(vector):
    device = model(vector)
    assert device.profile.source_sha256 == vector['source_sha256']
    for offset in range(0, len(vector['raw_names']), 8):
        names = vector['raw_names'][offset:offset + 8]
        reply = exchange(device, {'t': 'cmd', 'opt': names, 'p': [-1] * len(names)})[0].inner
        assert reply == {'t': 'res', 'mac': device.mac, 'opt': names,
                         'p': [-1] * len(names), 'r': 200}
        assert exchange(device, {'t': 'status', 'cols': names})[0].inner['dat'] == [65535] * len(names)
    assert exchange(model(vector), {'t': 'status', 'cols': ['Pow', 'SetTem']})[0].inner['dat'] == [0, 24]


@pytest.mark.parametrize('vector', VECTORS['sources'], ids=lambda row: row['version'])
def test_metadata_callbacks_empty_members_and_explicit_synthetic_readings(vector):
    device = model(vector, room_c=26.75)
    expected = vector['metadata']
    reply = exchange(device, {'t': 'status', 'cols': expected['cols'] + ['__unknown__']})[0].inner
    assert reply['cols'] == expected['cols']
    assert reply['dat'] == expected['dat']
    assert exchange(device, {'t': 'status', 'cols': ['InTem', 'rssi']})[0].inner['dat'] == [26, -50]


@pytest.mark.parametrize('vector', VECTORS['sources'], ids=lambda row: row['version'])
def test_native_status_opt_mutates_but_command_cols_only_acknowledges(vector):
    device = model(vector)
    reply = exchange(device, {'t': 'status', 'opt': ['Pow', 'Pow', 'SetTem'],
                              'p': [-1, 65536, 74565]})[0].inner
    assert reply['dat'] == [0, 0, 9029]
    reply = exchange(device, {'t': 'cmd', 'cols': ['Pow'], 'opt': ['SetTem'], 'p': [8]})[0].inner
    assert reply['opt'] == ['Pow'] and reply['p'] == [0]
    assert exchange(device, {'t': 'status', 'cols': ['Pow', 'SetTem']})[0].inner['dat'] == [0, 9029]
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        exchange(device, {'t': 'cmd', 'opt': ['Pow', '__unknown__'], 'p': [1, 2]})
    assert device.state == before


@pytest.mark.parametrize('vector', VECTORS['sources'], ids=lambda row: row['version'])
def test_local_setters_and_numeric_shadow_slots_do_not_retype_metadata(vector):
    device = model(vector)
    names = ['Pow', 'name', 'AppTimer', 'ModelType', 'time', 'ReportClientID']
    values = [7, 'ignored', 99, 'ignored', '2032-02-29 03:04:05', 'local-peer']
    reply = exchange(device, {'t': 'cmd', 'opt': names, 'p': values})[0].inner
    assert reply['opt'] == names[1:] + ['Pow']
    assert reply['p'] == ['Commercial Raw', 0, '', '2032-02-29 03:04:05', 7]
    assert device.state['_wb_report_client'] == 'local-peer'
    if vector['version'] != '1.14':
        reply = exchange(device, {'t': 'cmd', 'opt': ['ver'], 'p': ['ignored']})[0].inner
        assert reply['p'] == ['']
    else:
        exchange(device, {'t': 'cmd', 'opt': ['ver'], 'p': [511]})
        assert device.state['ver'] == 511
        assert exchange(device, {'t': 'status', 'cols': ['ver']})[0].inner['dat'] == ['']


@pytest.mark.parametrize('vector', VECTORS['sources'], ids=lambda row: row['version'])
def test_binary_receipts_queue_original_buffers_without_appliance_state_effect(vector):
    device = model(vector)
    request = {'t': 'binCmd', 'hex01': 'fn4GAQAAAAA='}
    if vector['version'] != '1.14':
        request.update(hex6B='fn4GAQAAAAA=', hex6A=base64.b64encode(b'client').decode())
    else:
        request['ReportClientID'] = 'local-peer'
    before = {name: value for name, value in device.state.items() if not name.startswith('_')}
    assert exchange(device, request)[0].inner == {'t': 'res', 'r': 200}
    assert device.state['_wb_uart_frame'] == b'~~\x06\x01\0\0\0\xaf' + bytes(52)
    assert {name: value for name, value in device.state.items() if not name.startswith('_')} == before
    snapshot = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        exchange(device, {**request, 'hex01': base64.b64encode(b'~~\xff').decode()})
    assert device.state == snapshot


@pytest.mark.parametrize('vector', VECTORS['sources'], ids=lambda row: row['version'])
def test_upgrade_and_source_specific_reset_are_receipts_not_executed_hardware(vector):
    device = model(vector)
    assert exchange(device, {'t': 'upgrade', 'url': 'http://offline.invalid/firmware.bin'})[0].inner == {'t': 'ret', 'r': 200}
    assert device.state['_brt_upgrade_url'] == 'http://offline.invalid/firmware.bin'
    reply = exchange(device, {'t': 'reset', 'mac': device.mac})
    if vector['version'] == '1.50':
        assert reply[0].inner == {'t': 'res', 'r': 200}
        assert device.state['_brt_reset_pending'] is True
    else:
        assert reply == []


@pytest.mark.parametrize('vector', VECTORS['sources'], ids=lambda row: row['version'])
def test_each_build_exposes_only_its_actual_root_and_child_mid_roles(vector):
    prefix = f"sim-wb04brt13-v{vector['version']}-"
    profiles = [profile for profile in commercial.PROFILES if profile.id.startswith(prefix)]
    assert sorted(profile.mids[0] for profile in profiles) == sorted(sum(
        (vector['mid_roles'][role] for role in ('standalone', 'root', 'children')), []))
    root = model(vector, '60')
    child = model(vector, '6400')
    child.mac = root.mac + '00'
    root.children.append(child)
    root.profile.handler.validate_topology(root)
    response = exchange(root, {'t': 'subDev', 'i': 0})[0].inner
    assert response['list'] == [{'mac': child.mac, 'name': 'ACUnit', 'mid': '6400',
                                  'model': 'gree', 'lock': 0}]
    assert exchange(root, {'t': 'subDev', 'i': 1})[0].inner['list'] == []
