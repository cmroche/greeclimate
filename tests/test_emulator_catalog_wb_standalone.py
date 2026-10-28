"""Exact-source standalone WB raw namespaces and callback precedence."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles import wb, wb_rt13
from gree_emulator.wire import InvalidPacket, Reply, encode_reply


VECTORS = json.loads((Path(__file__).parent / 'fixtures/emulator/catalog-wb-standalone_research.json').read_text())
PROFILES = wb.PROFILES + wb_rt13.PROFILES


def model(vector):
    profile = next(profile for profile in PROFILES if profile.id == vector['profile'])
    return EmulatedDevice(id='raw', mac='020000000001', name='WB Raw', mid=vector['mid'],
                          key=b'0123456789abcdef', profile=profile,
                          state=deepcopy(dict(profile.initial_state)))


def exchange(device, inner):
    codec = wb.CODEC if device.profile.id.startswith('sim-wb04a-') else wb_rt13.CODEC
    outer = {'t': 'pack', 'i': 0, 'uid': 1, 'cid': 'peer', 'tcid': device.mac}
    packet = json.loads(encode_reply(Reply(outer, inner, device.key, codec)))
    return device.profile.handler.handle(device, packet)[0].inner


@pytest.mark.parametrize('vector', VECTORS['sources'], ids=lambda row: row['profile'])
def test_every_source_declared_raw_getter_uses_unsigned16_not_ac_presets(vector):
    device = model(vector)
    assert device.profile.source_sha256 == vector['source_sha256']
    for name in vector['raw_names']:
        device.state[name] = 511
    for offset in range(0, len(vector['raw_names']), 16):
        columns = vector['raw_names'][offset:offset + 16]
        reply = exchange(device, {'t': 'status', 'cols': columns})
        assert reply['cols'] == columns
        assert reply['dat'] == [511] * len(columns)


@pytest.mark.parametrize('vector', VECTORS['sources'], ids=lambda row: row['profile'])
def test_every_source_raw_command_reaches_fresh_unsigned_cache(vector):
    device = model(vector)
    for offset in range(0, len(vector['raw_names']), 8):
        names = vector['raw_names'][offset:offset + 8]
        values = [-1] * len(names)
        reply = exchange(device, {'t': 'cmd', 'opt': names, 'p': values})
        assert reply == {'t': 'res', 'mac': device.mac, 'opt': names, 'p': values, 'r': 200}
        assert exchange(device, {'t': 'status', 'cols': names})['dat'] == [65535] * len(names)


@pytest.mark.parametrize('vector', VECTORS['sources'], ids=lambda row: row['profile'])
def test_native_raw_boundaries_duplicates_and_independent_instances(vector):
    device, other = model(vector), model(vector)
    reply = exchange(device, {'t': 'cmd', 'opt': ['Pow', 'Pow', 'SetTem', 'NoD'],
                              'p': [-1, 65536, 74565, -65537]})
    assert reply['p'] == [-1, 65536, 74565, -65537]
    assert exchange(device, {'t': 'status', 'cols': ['Pow', 'SetTem', 'NoD', 'Pow']})['dat'] == [0, 9029, 65535, 0]
    assert exchange(other, {'t': 'status', 'cols': ['Pow', 'SetTem', 'NoD']})['dat'] == [0, 24, 0]


@pytest.mark.parametrize('vector', VECTORS['sources'], ids=lambda row: row['profile'])
def test_metadata_callback_types_precede_numeric_table_and_preserve_empty_appends(vector):
    device = model(vector)
    expected = vector['metadata']
    reply = exchange(device, {'t': 'status', 'cols': expected['cols'] + ['__unknown__']})
    assert reply['cols'] == expected['cols']
    assert reply['dat'] == expected['dat']


@pytest.mark.parametrize('vector', VECTORS['sources'], ids=lambda row: row['profile'])
def test_local_commands_report_effective_values_before_raw_requested_values(vector):
    device = model(vector)
    reply = exchange(device, {'t': 'cmd', 'opt': ['Pow', 'name', 'SetTem', 'AppTimer', 'ModelType', 'ReportClientID'],
                              'p': [1, 'Not applied', 31, 9, 'not applied', 'local-peer']})
    assert reply['opt'] == ['name', 'AppTimer', 'ModelType', 'ReportClientID', 'Pow', 'SetTem']
    assert reply['p'] == (['WB Raw', 0, 1, 31] if vector['profile'].startswith('sim-wb04a-')
                          else ['WB Raw', 0, '', 1, 31])
    assert device.name == 'WB Raw'
    assert device.state['_wb_report_client'] == 'local-peer'


@pytest.mark.parametrize('vector', VECTORS['sources'], ids=lambda row: row['profile'])
@pytest.mark.parametrize('invalid', [True, 1.5, '1', None, {}, []])
def test_invalid_raw_token_rejects_entire_batch_before_any_mutation(vector, invalid):
    device = model(vector)
    before = deepcopy(device.state)
    with pytest.raises(InvalidPacket):
        exchange(device, {'t': 'cmd', 'opt': ['Pow', 'ElcP'], 'p': [1, invalid]})
    assert device.state == before

def test_raw_write_can_target_a_cache_slot_whose_getter_uses_another_buffer():
    for vector in VECTORS['sources']:
        device = model(vector)
        for name in vector['raw_write_only_names']:
            reply = exchange(device, {'t': 'cmd', 'opt': [name], 'p': [65537]})
            assert reply['p'] == [65537]
            assert device.state[name] == 1
            assert exchange(device, {'t': 'status', 'cols': [name]})['dat'] == ['']

def test_clock_setter_is_updated_only_on_the_rt13_source_path():
    for vector in VECTORS['sources']:
        device = model(vector)
        reply = exchange(device, {'t': 'cmd', 'opt': ['time'], 'p': ['2026-10-24 12:34:56']})
        expected = '2000-01-01 00:00:00' if vector['profile'].startswith('sim-wb04a-') else '2026-10-24 12:34:56'
        assert reply['p'] == [expected]
        assert exchange(device, {'t': 'status', 'cols': ['time']})['dat'] == [expected]


@pytest.mark.parametrize('vector', VECTORS['sources'], ids=lambda row: row['profile'])
def test_property_parser_distinguishes_status_opt_writes_from_cmd_cols_reads(vector):
    device = model(vector)
    reply = exchange(device, {'t': 'status', 'opt': ['ElcP', 'ElcP'], 'p': [-1, 65536]})
    assert reply['cols'] == ['ElcP', 'ElcP']
    assert reply['dat'] == [0, 0]
    assert exchange(device, {'t': 'status', 'cols': ['ElcP']})['dat'] == [0]
    exchange(device, {'t': 'cmd', 'opt': ['Pow'], 'p': [1]})
    reply = exchange(device, {'t': 'cmd', 'cols': ['Pow', 'lock'], 'p': [99, 99]})
    assert reply['opt'] == ['lock', 'Pow']
    assert reply['p'] == [0, 0]
    assert exchange(device, {'t': 'status', 'cols': ['Pow']})['dat'] == [1]


def test_wb04_model_type_getter_falls_through_to_raw_cache_but_setter_is_a_noop():
    device = model(VECTORS['sources'][0])
    device.state["ModelType"] = 511
    assert exchange(device, {'t': 'status', 'cols': ['ModelType']})['dat'] == [511]
    assert exchange(device, {'t': 'cmd', 'opt': ['ModelType'], 'p': ['unused']})['p'] == []
    assert device.state["ModelType"] == 511
