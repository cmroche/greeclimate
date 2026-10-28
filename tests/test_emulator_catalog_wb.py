"""Literal exact-build WB namespace and mutation checks; no research imports."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.wb_gateway import PROFILES
from gree_emulator.wire import InvalidPacket
from tests.test_emulator_wb_gateway import DEVICE_KEY, exchange, outer


VECTORS = json.loads((Path(__file__).parent / 'fixtures/emulator/catalog-wb_research.json').read_text())


def model(version, category='ac', mid=None):
    prefix = f'sim-wb05br-v{version}'
    root_profile = next(profile for profile in PROFILES if profile.id == prefix)
    suffix = 'water' if category == 'water_floor' else category
    child_profile = next(profile for profile in PROFILES if profile.id == prefix + '-' + suffix)
    root = EmulatedDevice(id='root', mac='020000000001', name='WB Gateway', mid='60',
                          key=DEVICE_KEY, profile=root_profile, state={})
    child = EmulatedDevice(id='child', mac='0244668800017f', name='Raw child',
                           mid=mid or child_profile.mids[0], key=DEVICE_KEY,
                           profile=child_profile, state=deepcopy(dict(child_profile.initial_state)))
    root.children = [child]
    root_profile.handler.validate_topology(root)
    return root, child


def status(root, child, columns):
    return exchange(root, outer(), {'t': 'status', 'mac': child.mac,
                                     'cols': columns})[0]['inner']['dat']


@pytest.mark.parametrize('vector', VECTORS['status'],
                         ids=lambda row: row['version'] + '-' + row['category'])
def test_every_exact_build_category_getter_has_literal_coverage(vector):
    root, child = model(vector['version'], vector['category'], vector['mid'])
    assert status(root, child, vector['cols']) == vector['dat']


@pytest.mark.parametrize('vector', VECTORS['commands'])
def test_exact_build_command_conversion_and_independent_fresh_status(vector):
    for version in vector['versions']:
        root, child = model(version, vector['category'])
        response = exchange(root, outer(), {'t': 'cmd', 'sub': child.mac,
                                            'opt': vector['opt'], 'p': vector['p']})[0]['inner']
        assert response == {'t': 'res', 'mac': child.mac, 'opt': vector['opt'],
                            'p': vector['p'], 'val': vector['p'], 'r': 200}
        assert child.state['outbound'] == [tuple(value) for value in vector['outbound']]
        assert status(root, child, vector['cols']) == vector['dat']


@pytest.mark.parametrize('version', ['1.13', '1.16', '1.18', '1.22', '1.31', '1.38'])
def test_complete_categories_do_not_invent_later_build_fields(version):
    root, child = model(version)
    values = status(root, child, ['InTem', 'TotalEle', 'AutoCleanMod', 'InFeelTemp'])
    assert values == ([20, 0, 0, 0] if version == '1.38' else
                      [20, 0, '', ''] if version == '1.31' else ['', '', '', ''])
    filter_root, filter_child = model(version, 'filter')
    assert status(filter_root, filter_child, ['ReportFreq', 'TemRec', 'TemUn', 'TotalEle']) == (
        ['', 0, 0, 0] if version in ('1.31', '1.38') else
        ['', 0, 0, ''] if version == '1.22' else ['', '', '', ''])


@pytest.mark.parametrize('version', ['1.13', '1.16', '1.18', '1.22', '1.31', '1.38'])
def test_raw_widths_readonly_unknown_and_duplicates_are_not_ac_constraints(version):
    root, child = model(version)
    response = exchange(root, outer(), {'t': 'cmd', 'sub': child.mac,
                                        'opt': ['SetTem', 'SetTem', 'TemBody', 'unknown', 'Pow'],
                                        'p': [63, 19, 1, 7, -2]})[0]['inner']
    assert response['p'] == [63, 19, 1, 7, -2]
    assert response['val'] == [63, 19, 1, None, -2]
    assert status(root, child, ['SetTem', 'TemBody', 'unknown', 'Pow']) == [63, 0, '', 1]


@pytest.mark.parametrize('version', ['1.13', '1.16', '1.18'])
def test_older_filter_setpoint_does_not_require_later_unit_context(version):
    root, child = model(version, 'filter', '6098')
    exchange(root, outer(), {'t': 'cmd', 'sub': child.mac, 'opt': ['SetTem'], 'p': [23]})
    assert status(root, child, ['SetTem', 'TemUn', 'TemRec']) == [23, '', '']


def test_new_callback_invalid_batch_is_atomic_and_does_not_mutate_report_cache():
    root, child = model('1.38')
    before = deepcopy(child.state)
    with pytest.raises(InvalidPacket):
        exchange(root, outer(), {'t': 'cmd', 'sub': child.mac,
                                 'opt': ['Pow', 'OutQuietMode'], 'p': [1, 13]})
    assert child.state == before


def test_distinct_categories_and_instances_keep_separate_reports():
    root, child = model('1.38', 'water_floor')
    independent, other = model('1.38', 'water_floor')
    exchange(root, outer(), {'t': 'cmd', 'sub': child.mac,
                             'opt': ['WPow', 'FSetTem'], 'p': [1, 47]})
    assert status(root, child, ['WPow', 'FSetTem']) == [1, 47]
    assert status(independent, other, ['WPow', 'FSetTem']) == [0, 24]


def test_new_getters_preserve_native_widths_without_sensor_calibration():
    root, child = model('1.38')
    child.state['reported'].update({'08100e': 255, '08100f': 128,
                                    '08327c': 65535, '08327e': 65534,
                                    '003122': 65000, '082154': 13})
    assert status(root, child, ['ODURatedCap', 'PowTime', 'PowTimeMin', 'PowTimeEn',
                                'InFeelTemp', 'OutQuietMode']) == [33023, 65535, 65534, 1, 65000, 12]
    exchange(root, outer(), {'t': 'cmd', 'sub': child.mac,
                             'opt': ['UVCKilling'], 'p': [-2]})
    assert status(root, child, ['UVCKilling']) == [1]
    child.state['reported'].pop('08327c')
    assert status(root, child, ['PowTime', 'PowTimeEn']) == [0, 0]


@pytest.mark.parametrize('version', ['1.13', '1.16', '1.18', '1.22', '1.31', '1.38'])
def test_half_degree_branch_preserves_original_signed32_intermediate(version):
    root, child = model(version)
    exchange(root, outer(), {'t': 'cmd', 'sub': child.mac,
                             'opt': ['SetTem', 'Add0.5'], 'p': [-(2**31), 0]})
    assert status(root, child, ['SetTem', 'Add0.1', 'Add0.5']) == [0, 0, 0]


@pytest.mark.parametrize('version', ['1.16', '1.18'])
def test_old_mode_callback_reasserts_precommand_power_report_in_source_order(version):
    root, child = model(version)
    exchange(root, outer(), {'t': 'cmd', 'sub': child.mac,
                             'opt': ['Pow', 'Mod'], 'p': [1, 0]})
    assert child.state['outbound'] == [('006f00', 1), ('007100', 5), ('006f00', 0)]
    assert status(root, child, ['Pow', 'Mod']) == [0, 0]
    exchange(root, outer(), {'t': 'cmd', 'sub': child.mac,
                             'opt': ['Mod', 'Pow'], 'p': [1, 1]})
    assert child.state['outbound'] == [('007100', 1), ('006f00', 0), ('006f00', 1)]
    assert status(root, child, ['Pow', 'Mod']) == [1, 1]
