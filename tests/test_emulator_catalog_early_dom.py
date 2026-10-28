"""Independent12-view literal callback and fixed-W LAN model contracts."""
import base64
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.device import EmulatedDevice
from gree_emulator.profiles.catalog_early_dom import OldDom, PROFILES
from gree_emulator.wire import InvalidPacket, encode_reply

FIXTURE = json.loads((Path(__file__).parent / 'fixtures/emulator/catalog-early-dom_research.json').read_text())
IDENTITIES = json.loads((Path(__file__).parent / 'fixtures/emulator/catalog-early-dom-identity_research.json').read_text())
ENERGY = json.loads((Path(__file__).parent / 'fixtures/emulator/catalog-early-dom-energy_research.json').read_text())
KEY = b'a3K8Bx%2r8Y7#xDh'


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch):
    monkeypatch.setattr('gree_emulator.profiles.catalog_early_small.monotonic', lambda: 1000)


def callback_context(view):
    handler = OldDom(view['source_index'])
    state = dict.fromkeys(handler.fields, 511)
    if view['source_index'] in (14, 16):
        state['ModelType'] = 0
    unit = SimpleNamespace(name='', mac='', mid=view['mid'] or '', last_step=1000,
                           profile=SimpleNamespace(hid=view['hid']))
    return unit, handler, state, handler._runtime(unit, state)


def status(unit, handler, state, runtime, names):
    reply, selector, newline = handler._dispatch(unit, state, runtime, {'t':'status', 'cols':names})
    assert selector == 0 and newline
    return reply


@pytest.mark.parametrize('view', FIXTURE['views'], ids=lambda v: str(v['source_index'])+'-bank'+str(v['bank']))
def test_every_independent_native_getter_and_namespace(view):
    unit, handler, state, runtime = callback_context(view)
    first_hole = view['ordered_namespace'].index(None)
    assert first_hole == 476 and len(view['ordered_namespace']) == 495
    assert set(handler.fields) == set(view['ordered_namespace'][:445])
    assert handler.names == frozenset(name for name in view['ordered_namespace'][:first_hole] if name)
    for vector in view['getter_vectors']:
        assert vector['completed']
        reply = status(unit, handler, state, runtime, [vector['name']])
        assert reply['cols'] == vector['cols'] and reply['dat'] == vector['dat']
    assert handler.thermal_target(unit) is None


@pytest.mark.parametrize('view', FIXTURE['views'], ids=lambda v: str(v['source_index'])+'-bank'+str(v['bank']))
def test_native_requested_effective_fresh_and_status_boundaries(view):
    for vector in view['transactions']:
        unit, handler, state, runtime = callback_context(view)
        if vector['names'] == ['not-known']:
            before = deepcopy(state)
            with pytest.raises(InvalidPacket):
                status(unit, handler, state, runtime, vector['names'])
            assert state == before
        elif vector['requested'] is None:
            reply = status(unit, handler, state, runtime, vector['names'])
            assert reply['cols'] == vector['columns'] and reply['dat'] == vector['values']
        else:
            reply, _, _ = handler._dispatch(unit, state, runtime,
                {'t':'cmd', 'opt':vector['names'], 'p':vector['requested']})
            if view['source_index'] != 18:
                assert reply is None
            else:
                assert reply['opt'] == vector['columns'] and reply['p'] == vector['values']
            fresh = status(unit, handler, state, runtime, vector['names'])
            assert fresh['cols'] == vector['fresh_columns'] and fresh['dat'] == vector['fresh_values']
            if view['source_index'] in (14, 15, 16):
                assert not vector['completed'] and vector['fresh_completed']


@pytest.mark.parametrize('view', FIXTURE['views'], ids=lambda v: str(v['source_index'])+'-bank'+str(v['bank']))
def test_separate_model_word_numeric_metadata_and_native_type_findings(view):
    unit, handler, state, runtime = callback_context(view)
    for vector in view['type_vectors']:
        if 'platform_context' in vector:
            state['ModelType'] = vector['platform_context']['value']
            assert status(unit, handler, state, runtime, ['ModelType'])['dat'] == vector['values']
            continue
        if vector['requested'] == [65537, -1]:
            handler._command(state, runtime, vector['names'], vector['requested'])
            assert status(unit, handler, state, runtime, vector['names'])['dat'] == vector['fresh_values']
    assert runtime['mid'] == ''
    for vector in view['type_vectors'][:3]:
        assert vector['requested'] in ([True], [None], [3.75])
        with pytest.raises(InvalidPacket):
            handler._command(state, runtime, ['Pow'], vector['requested'])


def device(profile_id='sim-w05w-v11'):
    profile = next(profile for profile in PROFILES if profile.id == profile_id)
    return EmulatedDevice('dom', FIXTURE['mac'], FIXTURE['name'], profile.mids[0],
                          FIXTURE['session_key'].encode(), profile,
                          deepcopy(dict(profile.initial_state)), room_c=None,
                          ambient_c=None, last_step=1000)


def packet(unit, inner, *, index=0, uid=42, key=None):
    key = (KEY if index else unit.key) if key is None else key
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(json.dumps(inner, separators=(',', ':')).encode(),16))
    return {'t':'pack', 'i':index, 'uid':uid, 'cid':'app', 'tcid':unit.mac,
            'pack':base64.b64encode(encrypted).decode()}


def decode(reply):
    raw = encode_reply(reply)
    outer = json.loads(raw)
    key = KEY if outer['i'] else FIXTURE['session_key'].encode()
    inner = json.loads(unpad(AES.new(key,AES.MODE_ECB).decrypt(base64.b64decode(outer['pack'])),16))
    return raw, outer, inner


def exchange(unit, inner, **kwargs):
    replies = unit.profile.handler.handle(unit, packet(unit,inner,**kwargs))
    return decode(replies[0]) if replies else (None,None,None)


def test_fixed_identity_discovery_binding_no_ack_fresh_and_metadata():
    unit = device()
    profile = unit.profile
    views = [v for v in FIXTURE['views'] if v['source_index'] == 15]
    assert len(views) == 2 and profile.mids == ('3019',)
    assert all(v['source_sha256'] == profile.source_sha256 and v['hid'] == profile.hid for v in views)
    assert all(v['profile'] is None for v in FIXTURE['views'] if v['source_index'] != 15)
    raw, outer, inner = decode(profile.handler.advertise(unit, {'t':'scan'})[0])
    expected = json.loads(views[0]['native_discovery_printed'])
    expected.update(name=unit.name,mac=unit.mac)
    assert inner == expected and raw.endswith(b'\n') and outer['i'] == 1
    _, outer, bound = exchange(unit, {'t':'bind','mac':unit.mac}, index=-1, uid=-(1<<31))
    assert bound == {'t':'bindok','mac':unit.mac,'r':200,'key':FIXTURE['session_key']}
    assert outer['uid'] == -(1<<31) and outer['i'] == 1
    assert exchange(unit, {'t':'cmd','opt':['Pow','Pow'],'p':[-1,65538]}) == (None,None,None)
    raw, outer, fresh = exchange(unit, {'t':'status','cols':['Pow','Pow','mid','model','hid']})
    assert fresh == {'t':'dat','mac':unit.mac,'r':200,'cols':['Pow','Pow','mid','model','hid'],
                     'dat':[2,2,'',profile.hid]}
    assert raw.endswith(b'\n') and outer['i'] == 0 and outer['tcid'] == ''
    assert device().state['Pow'] == 0


@pytest.mark.parametrize('bad', [True, None, 3.75, [], {}, 1<<31, -(1<<31)-1])
def test_safe_atomic_rejection_no_partial_mutation_or_clock_advance(bad):
    unit = device()
    before = deepcopy(unit.state)
    with pytest.raises(InvalidPacket):
        exchange(unit, {'t':'cmd','opt':['Pow','Mod'],'p':[1,bad]})
    assert unit.state == before and unit.last_step == 1000
    with pytest.raises(InvalidPacket):
        exchange(unit, {'t':'cmd','opt':['Pow','not-known'],'p':[1,1]})
    assert unit.state == before


def test_key_target_object_pack_reply_bound_and_lifecycle(monkeypatch):
    unit = device()
    for inner in ({'t':'status','cols':['rssi']}, {'t':'status','cols':['unknown']},
                  {'t':'status','cols':['Pow']*31}, {'t':'status','cols':['hid']*29},
                  {'t':'status','mac':'020000000072','cols':['Pow']},
                  {'t':'cmd','opt':['Pow'],'p':[]}, {'t':'cmd','sub':unit.mac,'opt':['Pow'],'p':[1]}):
        before = deepcopy(unit.state)
        with pytest.raises(InvalidPacket):
            exchange(unit,inner)
        assert unit.state == before
    with pytest.raises(InvalidPacket):
        exchange(unit,{'t':'status','cols':['Pow']},index=2,key=unit.key)
    outer = packet(unit,{'t':'status','cols':['Pow']})
    outer.update(i=2,pack={'t':'status','cols':['Pow']})
    with pytest.raises(InvalidPacket):
        unit.profile.handler.handle(unit,outer)
    _, _, exact = exchange(unit,{'t':'status','cols':['Pow']*30})
    assert exact['cols'] == exact['dat'] == []
    _, _, hole = exchange(unit,{'t':'status','cols':['Pow','','Mod']})
    assert hole['cols'] == ['Pow'] and hole['dat'] == [0]
    exchange(unit,{'t':'cmd','opt':['host','name'],'p':['local','pending']})
    _, _, fresh = exchange(unit,{'t':'status','cols':['host','name']})
    assert fresh['dat'] == ['local','dom']
    _, _, clock = exchange(unit,{'t':'status','cols':['time']})
    assert clock['dat'] == ['2036-02-06 06:28:16']
    monkeypatch.setattr('gree_emulator.profiles.catalog_early_small.monotonic',lambda:1002)
    _, _, clock = exchange(unit,{'t':'status','cols':['time']})
    assert clock['dat'] == ['2036-02-06 06:28:18']


def test_original_shared_timer_schema_and_bounded_upgrade_model():
    unit = device()
    timer = {'t':'setT','id':257,'name':'raw','enable':0,'hr':7,'min':0,'sec':0,'tz':0,
             'week':[], 'cmd':[{'mac':[unit.mac],'opt':['Pow'],'p':[1]}]}
    raw, _, response = exchange(unit,timer)
    assert response == {'t':'resT','r':200} and not raw.endswith(b'\n')
    _, _, response = exchange(unit,{'t':'queryT','index':0,'count':0})
    assert response == {'t':'listT','total':0,'index':0,'list':[
        {'id':1,'name':'raw','enable':0,'hr':7,'min':0,'sec':0,'week':[0]*7,'cmd':timer['cmd']}]}
    _, _, response = exchange(unit,{'t':'deleteT','id':1})
    assert response == {'t':'resT','r':200}
    assert exchange(unit,{'t':'upgrade','url':'https://example.invalid/source.bin'}) == (None,None,None)
    assert unit.state['_small']['upgrade'] == 'https://example.invalid/source.bin'
    reply, = unit.profile.handler.handle(unit,packet(unit,{'t':'surver','mac':unit.mac}))
    assert json.loads(encode_reply(reply)) == {'t':'configok','r':'200','mac':unit.mac}
    assert reply.destination_port == 8001


@pytest.mark.parametrize('view', IDENTITIES['views'], ids=lambda v: v['profile']+'-bank'+str(v['bank']))
def test_actual_producer_to_emission_and_exact_static_preset(view):
    unit = device(view['profile'])
    assert view['producer_completed'] and view['formatted_mid'] == '10001'
    assert unit.mid == view['configured_mid'] and unit.profile.source_sha256 == view['source_sha256']
    raw, _, emitted = decode(unit.profile.handler.advertise(unit, {'t':'scan'})[0])
    expected = json.loads(view['printed'])
    expected.update(name=unit.name, mac=unit.mac)
    assert emitted == expected and raw.endswith(b'\n')
    _, _, fresh = exchange(unit, {'t':'status','cols':['mid','ModelType']})
    if view['source_index'] == 15:
        assert fresh['dat'] == ['', 0]  # Fixed-W preset deliberately has no supplied board identity.
    else:
        assert fresh['dat'] == view['fresh_values'] == ['10001', 0]
    assert unit.profile.handler.thermal_target(unit) is None


@pytest.mark.parametrize('view', ENERGY['views'], ids=lambda v: v['source_sha256'][:12]+'-bank'+str(v['bank']))
def test_energy_helper_selects_request_ordinal_not_matched_cache_slot(view):
    identity = next(v for v in IDENTITIES['views'] if
                    (v['source_sha256'], v['bank']) == (view['source_sha256'], view['bank']))
    unit = device(identity['profile'])
    assert [(v['ordinal'], v['pending_flags'], v['request_word'], v['status_return'])
            for v in view['vectors']] == [
        (0, 128, 4660, 1), (67, 129, 37428, 0), (68, 130, 37428, 0),
        (69, 132, 4660, 0), (71, 132, 37428, 0), (72, 132, 37428, 0)]
    assert all(v['helper_completed'] and v['status_completed'] for v in view['vectors'])
    _, _, status = exchange(unit, {'t':'status','cols':['ElcDatHor']*20})
    assert status['cols'] == ['ElcDatHor']*20 and status['dat'] == [0]*20
