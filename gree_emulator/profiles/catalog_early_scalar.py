"""Bounded exact-source WB05MR V1.05 UDP model.

The four 4M DF/UR sources were assessed separately but have no qualified LAN
ingress and are not emulator presets. Synthetic mainboard MID10001 is an
explicit source-accepted input, not a fixed physical-device identity."""
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import calendar
import json
import math
import re
from ..wire import InvalidPacket, Reply, decode_pack, encode_reply
from . import Profile
from .catalog_early_frvr import GENERIC_KEY, VR_NUMERIC
CODEC = 'aes-ecb-pkcs7'
DEFAULT_TIME = '2036-03-09 06:28:16'
DEFAULT_EPOCH = calendar.timegm(datetime.strptime(DEFAULT_TIME, '%Y-%m-%d %H:%M:%S').timetuple())
MAX_EPOCH = (1 << 32) - 1
MAX_DATAGRAM = 1460
FOUR_PATCHES = {203: 'OutEnvTem', 204: 'InEvaTem', 205: 'CompressorTem', 206: 'CompressorFqy', 371: 'override', 372: 'DRLevel', 373: 'Duration', 374: 'RemainDuration', 375: 'MaxTempRise', 376: 'DRState', 377: 'ElcP', 378: 'ElcAllKwhH', 379: 'ElcAllKwhL', 380: 'DRType', 381: 'DROnline', 382: 'TempRiseValid', 421: 'PowReduceType', 422: 'AutoPowReduce', 423: 'PowReduceGear'}
FOUR_NAMES = tuple((FOUR_PATCHES.get(index, name) for index, name in enumerate(VR_NUMERIC)))
MR_PATCHES = {45: 'NoD', 46: 'NoD', 47: 'NoD', 48: 'NoD', 49: 'NoD', 50: 'Buzzer_ON_OFF', 51: 'ElcEn', 52: 'EnvTem', 53: 'DFPoint', 54: 'CpsTem', 55: 'TemsSenOut', 56: 'FaultDisplay', 58: 'NoD', 59: 'NoD', 197: 'EnergyFlow', 198: 'NoD', 199: 'NoD', 200: 'NoD', 201: 'NoD', 202: 'NoD', 203: 'NoD', 204: 'NoD', 205: 'NoD', 206: 'NoD', 295: 'SmartSlpMod', 296: 'SmartSlpModEx', 297: 'StSlp1C', 298: 'StSlp1CInc', 299: 'StSlp1CSp', 300: 'StSlp1H', 301: 'StSlp1HInc', 302: 'StSlp1HSp', 303: 'StSlp2C', 304: 'StSlp2CInc', 305: 'StSlp2CSp', 306: 'StSlp2H', 307: 'StSlp2HInc', 308: 'StSlp2HSp', 309: 'StSlp3C', 310: 'StSlp3CInc', 311: 'StSlp3CSp', 312: 'StSlp3H', 313: 'StSlp3HInc', 314: 'StSlp3HSp', 315: 'StSlp4C', 316: 'StSlp4CInc', 317: 'StSlp4CSp', 318: 'StSlp4H', 319: 'StSlp4HInc', 320: 'StSlp4HSp', 321: 'AntiDirectBlow', **dict.fromkeys(range(371, 383), 'NoD'), 421: 'NoD', 422: 'NoD', 423: 'NoD', **dict.fromkeys(range(476, 495), None)}
MR_NAMES = tuple((MR_PATCHES.get(index, name) for index, name in enumerate(FOUR_NAMES)))
SOURCE_NAMES = {22: MR_NAMES}
LOCAL_MR = frozenset(('time', 'name', 'lock', 'AutoUpdate', 'host', 'hid', 'mid', 'bc', 'DevID', 'MafIdf', 'AppTimer', 'MidType', 'ReportClientID'))
METADATA_NAMES_MR = ('name', 'time', 'AppTimer', 'ReportClientID', 'ModelType', 'lock', 'AutoUpdate', 'host', 'hid', 'mid', 'bc', 'DevID', 'MafIdf', 'MidType', 'ver', 'vender', 'rssi')
_SOURCE_ROWS = ((22, 'sim-wb05mr-v1.05-10001', 'ac43e9ff82a55cb1719055eaa9ced115948814efbeb18086f818bb8ea9fedf9e', '362001068458+U-WB05MRV1.05.bin'),)
LOCAL_NAMES = {22: LOCAL_MR}
METADATA_NAMES = {22: METADATA_NAMES_MR}

def _metadata_defaults(source, hid):
    return {'name': [''], 'time': [DEFAULT_TIME], 'AppTimer': [0], 'ReportClientID': [], 'ModelType': [0], 'lock': [0], 'AutoUpdate': [0], 'host': [''], 'hid': [hid], 'mid': [''], 'bc': [''], 'DevID': [], 'MafIdf': [], 'MidType': [0], 'ver': [''], 'vender': [''], 'rssi': [0]}
OPERATIONS = {22: frozenset(('bind', 'status', 'cmd', 'upgrade', 'setT', 'queryT', 'deleteT', 'updateT', 'dump', 'binCmd', 'freqCount'))}

def _bounded_text(value, name, maximum, *, empty=True):
    if not isinstance(value, str) or '\x00' in value or len(value.encode('utf-8')) > maximum or (not empty and (not value)):
        raise InvalidPacket(f'scalar {name} exceeds its source buffer')
    return value

def _names(value):
    if not isinstance(value, list) or len(value) > 64 or any((not isinstance(name, str) or not name or '\x00' in name for name in value)) or (sum((len(name.encode('utf-8')) + 1 for name in value if isinstance(name, str))) > 512):
        raise InvalidPacket('scalar property array exceeds the 64-name source bound')
    return value

@dataclass(frozen=True)
class _JsonNumber:
    token: str

def _int32(value, name):
    if type(value) is _JsonNumber:
        if len(value.token) > 64:
            raise InvalidPacket(f'scalar {name} numeric token exceeds the source bound')
        match = re.match('^-?[0-9]+', value.token)
        value = int(match.group()) if match is not None else 0
    if type(value) is not int or not -(1 << 31) <= value < 1 << 31:
        raise InvalidPacket(f'scalar {name} requires a bounded signed32 integer')
    return value

def _cjson_int32(value, name):
    if type(value) is _JsonNumber:
        if len(value.token) > 64:
            raise InvalidPacket(f'scalar {name} numeric token exceeds the source bound')
        try:
            number = float(value.token)
        except (ValueError, OverflowError) as exc:
            raise InvalidPacket(f'scalar {name} requires a finite JSON number') from exc
        if not math.isfinite(number) or not -(1 << 31) <= number < 1 << 31:
            raise InvalidPacket(f'scalar {name} exceeds the bounded cJSON integer range')
        value = int(number)
    return _int32(value, name)

def _epoch(value):
    _bounded_text(value, 'time', 19, empty=False)
    if not re.fullmatch('\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}', value):
        raise InvalidPacket('scalar time requires YYYY-MM-DD HH:MM:SS')
    try:
        parsed = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        result = calendar.timegm(parsed.timetuple())
    except (ValueError, OverflowError) as exc:
        raise InvalidPacket('scalar time is outside the source calendar') from exc
    if not 0 <= result <= MAX_EPOCH:
        raise InvalidPacket('scalar time exceeds the uint32 SDK calendar')
    return result

class ScalarController:
    """Bounded model of one exact 495-slot source table and its registered roots."""
    plaintext_types = ('hbok', 'tm', 'wlan')

    def __init__(self, source_index):
        if source_index not in OPERATIONS:
            raise ValueError('scalar controller requires an exact source index')
        self.source_index = source_index
        self.id, self.source_sha256, self.hid = next(((profile_id, digest, hid) for index, profile_id, digest, hid in _SOURCE_ROWS if index == source_index))
        self.ordered_names = SOURCE_NAMES[source_index]
        if len(self.ordered_names) != 495:
            raise ValueError('scalar source table must contain exactly 495 ordered slots')
        self.numeric = frozenset((name for name in self.ordered_names if name is not None))
        self.local_names = LOCAL_NAMES[source_index]
        self.special = self.local_names
        self.metadata_names = METADATA_NAMES[source_index]
        self.metadata_defaults = _metadata_defaults(source_index, self.hid)
        self.getter_overrides = GETTER_OVERRIDES[source_index]
        self.numeric_controls = frozenset()
        self.write_only = frozenset(('ReportClientID', 'Onoff')) & self.local_names | self.numeric_controls
        self.fields = self.numeric | self.local_names | self.numeric_controls
        self.operations = OPERATIONS[source_index]

    def validate_state(self, state):
        for name, value in state.items():
            if name == '_uid' and type(value) is int and -(1 << 31) <= value < (1 << 31):
                continue
            if name not in self.numeric or type(value) is not int or (not 0 <= value <= 65535):
                raise ValueError('scalar state requires finite source uint16 cache values')

    def thermal_target(self, device):
        return None

    def encode_room(self, device):
        """Raw source caches have no calibrated room state."""

    def _runtime(self, device, state):
        if '_runtime' not in state:
            state['_runtime'] = {
                'clock_epoch': DEFAULT_EPOCH,
                'clock_origin': getattr(device, 'last_step', 0),
                'timers': {}, 'frames': {}, 'raw_pending': False,
                'time_sync_pending': False, 'time_synchronized': False,
                'upgrade_url': None, 'upgrade_pending': False,
                'frequency': {}, 'dump_period': 0, 'dump_count': 0,
                'last_sequence': 0, 'heartbeat_retries': 0,
                'heartbeat_pending': False, 'network': {},
            }
        return state['_runtime']

    def _clock_epoch(self, device, runtime):
        elapsed = max(0, int(getattr(device, 'last_step', runtime['clock_origin']) - runtime['clock_origin']))
        epoch = runtime['clock_epoch'] + elapsed
        if not 0 <= epoch <= MAX_EPOCH:
            raise InvalidPacket('scalar SDK calendar exceeded uint32 epoch')
        return epoch

    def _get(self, device, state, runtime, name):
        if name == 'time':
            value = datetime.fromtimestamp(self._clock_epoch(device, runtime), timezone.utc)
            return [value.strftime('%Y-%m-%d %H:%M:%S')]
        if name in self.metadata_defaults:
            if name == 'ModelType':
                return [state[name]]
            return deepcopy(self.metadata_defaults[name])
        if name in self.numeric:
            return [state[name]]
        return []

    def _report_id(self, runtime, value):
        encoded = value.encode('utf-8')
        if len(encoded) > 26:
            raise InvalidPacket('MR ReportClientID exceeds its 26-byte UART buffer payload')
        frame = bytearray(30)
        frame[:4] = b'~~\x12j'
        frame[4:4 + len(encoded)] = encoded
        runtime['frames']['ReportClientID'] = bytes(frame)
        runtime['raw_pending'] = True

    def _binary(self, runtime, inner):
        sequence = None
        if type(inner.get('seq')) is _JsonNumber:
            sequence = _cjson_int32(inner['seq'], 'seq')
            if sequence == runtime.get('last_sequence'):
                return None
        encoded = _bounded_text(inner.get('hex01'), 'hex01', 1023, empty=False)
        try:
            frame = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as exc:
            raise InvalidPacket('scalar hex01 must be base64') from exc
        length = (frame[2] if len(frame) >= 3 else 0) + 2
        if not 2 <= len(frame) <= 60 or frame[:2] != b'~~' or length > 60:
            raise InvalidPacket('scalar binary frame exceeds its 60-byte source buffer')
        report_client = inner.get('ReportClientID')
        if 'ReportClientID' in inner:
            report_client = _bounded_text(report_client, 'ReportClientID', 26)
        report_freq = inner.get('ReportFreq')
        if 'ReportFreq' in inner:
            report_freq = _cjson_int32(report_freq, 'ReportFreq')
        outgoing = bytearray(60)
        outgoing[:length] = frame.ljust(60, b'\0')[:length]
        outgoing[43] |= 2
        outgoing[7] = 0 if report_freq is not None else 175
        runtime['frames']['hex01'] = bytes(outgoing)
        if report_client is not None:
            client_frame = bytearray(30)
            client_frame[:4] = b'~~\x12j'
            encoded_client = report_client.encode('utf-8')
            client_frame[4:4 + len(encoded_client)] = encoded_client
            runtime['frames']['ReportClientID'] = bytes(client_frame)
        if report_freq is not None:
            frequency = report_freq & 255
            sentinel = report_freq == 255
            runtime['report_frequency'] = 60 if sentinel else frequency
            offset = 34
            frequency_frame = bytearray(runtime['frames'].get('ReportFreq', bytes(60)))
            frequency_frame[offset + 2:offset + 4] = b'Z@'
            if not sentinel:
                frequency_frame[offset:offset + 2] = (frequency + 16384).to_bytes(2, 'little')
            runtime['frames']['ReportFreq'] = bytes(frequency_frame)
        if sequence is not None:
            runtime['last_sequence'] = sequence
        runtime['raw_pending'] = True
        return {'t': 'res', 'r': 200}

    def _set_local(self, device, state, runtime, name, value):
        _bounded_text(value, name, 256)
        readonly = {'lock', 'AutoUpdate', 'hid', 'mid', 'bc', 'DevID', 'MafIdf', 'MidType'}
        if name in readonly:
            raise InvalidPacket(f'scalar {name} is a read-only source getter')
        if name == 'time':
            runtime['time_sync_pending'] = True
        elif name == 'host':
            raise InvalidPacket('MR host has no registered string setter')
        elif name == 'ReportClientID':
            self._report_id(runtime, value)

    def _stage_fields(self, device, pending, runtime, names, values):
        names = _names(names)
        if not isinstance(values, list) or len(names) != len(values):
            raise InvalidPacket('scalar command arrays must have equal lengths')
        local, numeric, numeric_names, numeric_values = ([], [], [], [])
        local_seen = False
        for name, value in zip(names, values):
            if name not in self.fields:
                raise InvalidPacket('scalar unknown command crosses the finite source table')
            if name in self.local_names:
                local_seen = True
                local.append((name, _bounded_text(value, name, 256)))
            else:
                negative_token = isinstance(value, _JsonNumber) and value.token.startswith('-')
                value = _int32(value, name)
                numeric_names.append(name)
                if not negative_token and value >= 0:
                    numeric_values.append(value)
        numeric = [(name, numeric_values[index] if index < len(numeric_values) else 0) for index, name in enumerate(numeric_names)]
        if any((name == 'Onoff' for name, _ in local)):
            runtime['onoff_frames'] = []
        for name, value in local:
            self._set_local(device, pending, runtime, name, value)
        for name, value in numeric:
            pending[name] = value & 65535
        if numeric or any((name == 'time' for name, _ in local)):
            runtime['uart_buzzer_bit'] = pending['Buzzer_ON_OFF'] & 1
            runtime['raw_pending'] = True
        return (local, numeric)

    def _timer_record(self, inner):
        fields = {name: _int32(inner.get(name), name) for name in ('id', 'enable', 'tz', 'hr', 'min')}
        seconds = 0 if 'sec' in inner else fields['min'] & 255
        if 'sec' in inner:
            _int32(inner['sec'], 'sec')
        timer_name = _bounded_text(inner.get('name'), 'timer name', 31)
        week = inner.get('week')
        if not isinstance(week, list) or len(week) != 7:
            raise InvalidPacket('scalar timer requires seven weekday values')
        mask = 0
        for index, value in enumerate(week):
            mask |= _int32(value, 'weekday') << index & 255
        commands = inner.get('cmd')
        if not isinstance(commands, list) or not commands or not isinstance(commands[0], dict):
            raise InvalidPacket('MR timer requires its first command object')
        names = _names(commands[0].get('opt'))
        values = commands[0].get('p')
        if not isinstance(values, list) or len(names) != len(values):
            raise InvalidPacket('scalar timer command arrays must match')
        power = 0
        for field, value in zip(names, values):
            parsed = _int32(value, 'timer value')
            if field == 'Pow':
                power = parsed & 255
        return {'id': fields['id'] & 255, 'name': timer_name, 'enable': int(fields['enable'] == 1), 'week': [mask >> bit & 1 for bit in range(7)], 'hr': fields['hr'] & 255, 'min': fields['min'] & 255, 'sec': seconds, 'power': power}

    def _timer(self, device, runtime, inner):
        kind, timers = (inner['t'], runtime['timers'])
        if kind == 'queryT':
            start = _int32(inner.get('index'), 'timer index')
            count = _int32(inner.get('count'), 'timer count')
            if not 0 <= start <= 255 or not 0 <= count <= 10:
                raise InvalidPacket('scalar timer pagination exceeds the source table')
            entries = []
            for position, timer in enumerate(timers.values()):
                if start <= position < start + count:
                    entries.append({'id': timer['id'], 'name': timer['name'], 'enable': timer['enable'], 'week': timer['week'], 'hr': timer['hr'], 'min': timer['min'], 'sec': timer['sec'], 'cmd': [{'mac': [device.mac], 'opt': ['Pow'], 'p': [timer['power']]}]})
            return {'t': 'listT', 'total': len(timers), 'index': start, 'list': entries}
        if kind == 'deleteT':
            timer_id = _int32(inner.get('id'), 'timer id') & 255
            if timer_id not in timers:
                raise InvalidPacket('scalar safely rejects deletion of a missing timer')
            del timers[timer_id]
            return {'t': 'resT', 'r': 200}
        if kind == 'setT' and len(timers) >= 10:
            raise InvalidPacket('scalar source setT is gated at ten timer records')
        timer = self._timer_record(inner)
        timer_id = timer['id']
        if kind == 'updateT' and timer_id not in timers:
            return {'t': 'resT', 'r': 200}
        epoch = self._clock_epoch(device, runtime)
        timer['remaining'] = (timer['hr'] * 3600 + timer['min'] * 60
                              + timer['sec'] - epoch % 86400)
        runtime.setdefault('timer_tick_epoch', epoch - 1)
        timers[timer_id] = timer
        return {'t': 'resT', 'r': 200}

    def _timer_tick(self, runtime, epoch):
        timers = runtime['timers'].values()
        if epoch < 0x5c2a3d00:
            return
        if epoch % 86400 == 0:
            for timer in timers:
                if timer['enable'] == 0:
                    timer['remaining'] = timer['hr'] * 3600 + timer['min'] * 60 + timer['sec']
        nearest, selected = 0x7fffffff, 0
        future_on = future_off = past_on = past_off = False
        weekday = (datetime.fromtimestamp(epoch, timezone.utc).weekday() + 1) % 7
        for timer in timers:
            # Constructor stores (enable != 1); the worker runs only stored1.
            if timer['enable'] != 0:
                continue
            remaining, power = timer['remaining'], timer['power']
            if remaining < 0:
                past_on |= power == 1
                past_off |= power == 0
            elif remaining < nearest:
                nearest = remaining
                if power == 1:
                    selected, future_on = 1, True
                elif power == 0:
                    selected, future_off = 2, True
            periodic = any(timer['week'])
            if not periodic or timer['week'][weekday]:
                if remaining > 0:
                    timer['remaining'] -= 1
                elif remaining == 0:
                    timer['remaining'] = -epoch
                    if not periodic:
                        timer['enable'] = 1
        projection = bytearray(runtime.get('timer_projection', bytes(14)))
        if selected:
            offset = 8 if selected == 1 else 11
            projection[offset:offset + 3] = bytes((
                (nearest // 3600) & 255, (nearest // 60) % 60, nearest % 60))
            if nearest < 2:
                runtime['timer_command_pending'] = 3
                runtime['raw_pending'] = True
            opposite = ((future_off or past_off or projection[4] & 0x40)
                        if selected == 1 else
                        (future_on or past_on or projection[4] & 0x80))
            if opposite:
                offset = 11 if selected == 1 else 8
                projection[offset:offset + 3] = b'\x17\x3b\x3b'
        else:
            if past_off:
                projection[11:14] = b'\x17\x3b\x3b'
            if past_on:
                projection[8:11] = b'\x17\x3b\x3b'
        runtime['timer_projection'] = bytes(projection)

    def tick(self, device, now):
        runtime = self._runtime(device, device.state)
        if not runtime['timers']:
            return []
        epoch = self._clock_epoch(device, runtime)
        previous = runtime.get('timer_tick_epoch', epoch - 1)
        for current in range(previous + 1, epoch + 1):
            self._timer_tick(runtime, current)
        runtime['timer_tick_epoch'] = epoch
        # The source stages MCU countdown fields, not a physical Pow transition.
        return []

    def advertise(self, device, outer):
        inner = {'t': 'dev', 'cid': '', 'bc': '', 'brand': '', 'catalog': '', 'mac': device.mac, 'mid': '10001', 'model': '', 'name': '', 'lock': 0, 'series': '', 'vender': '', 'ver': '', 'hid': device.profile.hid}
        reply = Reply({'t': 'pack', 'i': 1, 'uid': 0, 'cid': '', 'tcid': ''}, inner, GENERIC_KEY, CODEC)
        if len(encode_reply(reply)) > MAX_DATAGRAM:
            raise InvalidPacket('scalar discovery exceeds the source datagram bound')
        return [reply]

    def _reply(self, device, outer, inner):
        index, uid = (outer['i'], outer['uid'])
        reply = Reply({'t': 'pack', 'i': index, 'uid': uid, 'cid': outer.get('tcid', ''), 'tcid': outer.get('cid', '')}, inner, GENERIC_KEY if index else device.key, CODEC)
        if len(encode_reply(reply)) > MAX_DATAGRAM:
            raise InvalidPacket('scalar reply exceeds the source datagram bound')
        return reply

    def _plaintext(self, device, outer):
        if outer.get('tcid', device.mac) != device.mac:
            raise InvalidPacket('wrong MR plaintext target')
        pending = deepcopy(device.state)
        runtime = self._runtime(device, pending)
        kind = outer['t']
        replies = []
        if kind == 'hbok':
            runtime['heartbeat_retries'] = 0
            runtime['heartbeat_pending'] = False
        elif kind == 'tm':
            epoch = _epoch(outer.get('time'))
            runtime['server_epoch'] = epoch
            if epoch > 0x5c2a3d00:
                effective = (epoch + 28800) & MAX_EPOCH
                runtime['clock_epoch'] = effective
                runtime['clock_origin'] = getattr(device, 'last_step', 0)
                runtime['server_epoch'] = effective
                for timer in runtime['timers'].values():
                    if timer['enable'] == 0:
                        timer['remaining'] = (timer['hr'] * 3600 + timer['min'] * 60
                                              + timer['sec'] - effective % 86400)
                runtime['timer_tick_epoch'] = effective - 1
            runtime['time_synchronized'] = True
            runtime['time_sync_pending'] = False
        else:
            network = {
                name: _bounded_text(outer.get(name), name, bound)
                for name, bound in (('host', 19), ('ssid', 32), ('psw', 64))
            }
            # Declared virtual configuration storage; no host networking or flash writes.
            runtime['network'] = network
            runtime['restart_requested'] = True
            replies = [Reply({'t': 'ret', 'r': 200, 'mac': ''})]
        device.state.clear()
        device.state.update(pending)
        return replies

    def _request_target(self, device, inner):
        # Original parser tries mac first, then sub, then the SDK NIC fallback.
        for name in ('mac', 'sub'):
            value = inner.get(name)
            if isinstance(value, str):
                if '\0' in value:
                    raise InvalidPacket('MR request target contains a C-string terminator')
                if len(value.encode('utf-8')) < 32:
                    return value
        return device.mac


    def handle(self, device, outer):
        if outer.get('t') in self.plaintext_types:
            return self._plaintext(device, outer)
        if outer.get('t') != 'pack' or outer.get('tcid') != device.mac:
            raise InvalidPacket('wrong scalar root target')
        index, uid = (outer.get('i'), outer.get('uid'))
        cid = outer.get('cid', '')
        if isinstance(cid, str) and ('\0' in cid or len(cid.encode('utf-8')) >= 64):
            raise InvalidPacket('MR outer cid exceeds its bounded source string slot')
        if type(index) is not int or index not in (0, 1) or type(uid) is not int or (not -(1 << 31) <= uid < 1 << 31) or (not isinstance(outer.get('cid', ''), str)) or ('tag' in outer):
            raise InvalidPacket('invalid scalar ECB session selector')
        inner = decode_pack(outer, GENERIC_KEY if index else device.key, CODEC, number_parser=_JsonNumber)
        kind = inner.get('t')
        if not isinstance(kind, str) or not kind or '\x00' in kind:
            raise InvalidPacket('invalid scalar request type')
        if kind not in self.operations:
            return []
        pending = deepcopy(device.state)
        runtime = self._runtime(device, pending)
        if kind == 'bind':
            try:
                key = device.key.decode('ascii')
            except UnicodeDecodeError as exc:
                raise InvalidPacket('scalar bind key is not source ASCII') from exc
            response = {'r': 200, 't': 'bindok', 'mac': device.mac, 'key': key}
        elif kind == 'status':
            names = _names(inner.get('cols'))
            selected, values = [], []
            for name in names:
                if name in self.write_only:
                    raise InvalidPacket('MR write-only getter reaches the NULL source namespace')
                if name not in self.numeric and name not in self.metadata_defaults:
                    raise InvalidPacket('scalar unknown getter reaches a NULL source name')
                selected.append(name)
                values.extend(self._get(device, pending, runtime, name))
            target = self._request_target(device, inner)
            response = {'t': 'dat', 'uid': uid, 'mac': target, 'cid': device.mac, 'dat': values, 'cols': selected, 'r': 200}
        elif kind == 'cmd':
            local, numeric = self._stage_fields(device, pending, runtime, inner.get('opt'), inner.get('p'))
            selected, applied = [], []
            target = self._request_target(device, inner)
            ack_mac = target
            for name, _ in local:
                if name not in self.write_only:
                    selected.append(name)
                    applied.extend(self._get(device, pending, runtime, name))
            for name, value in numeric:
                selected.append(name)
                applied.append(value)
            response = {'t': 'res', 'mac': ack_mac, 'p': applied, 'opt': selected, 'r': 200}
        elif kind in ('setT', 'queryT', 'deleteT', 'updateT'):
            response = self._timer(device, runtime, inner)
        elif kind == 'binCmd':
            response = self._binary(runtime, inner)
            if response is None:
                return []
        elif kind == 'upgrade':
            # Original handler ACKs after queuing its OTA task. This virtual
            # backend records the request; it never downloads or flashes bytes.
            runtime['upgrade_url'] = _bounded_text(inner.get('url'), 'url', 119)
            runtime['upgrade_pending'] = True
            response = {'t': 'ret', 'r': 200}
        elif kind == 'dump':
            period, count = (_int32(inner.get('period'), 'dump period'), _int32(inner.get('cnt'), 'dump count'))
            runtime['dump_period'], runtime['dump_count'] = (period, count)
            response = {'t': 'ret', 'r': 200}
        elif kind == 'freqCount':
            if 'cols' in inner:
                _names(inner['cols'])
                device.state.clear()
                device.state.update(pending)
                return []
            names, values = (_names(inner.get('opt')), inner.get('p'))
            if not isinstance(values, list) or len(names) != len(values):
                raise InvalidPacket('scalar frequency arrays must have equal lengths')
            self._stage_fields(device, pending, runtime, names, values)
            device.state.clear()
            device.state.update(pending)
            return []
        else:
            return []
        pending['_uid'] = uid
        device.state.clear()
        device.state.update(pending)
        return [self._reply(device, outer, response)]
ORDERED_NAMES = SOURCE_NAMES
METADATA_DEFAULTS = {index: _metadata_defaults(index, hid) for index, _, _, hid in _SOURCE_ROWS}
GETTER_OVERRIDES = {index: frozenset(METADATA_DEFAULTS[index]) - ({'ModelType'} if index == 22 else set()) for index, *_ in _SOURCE_ROWS}
PROFILES = tuple((Profile(id=profile_id, mids=('10001',), hid=hid, source_sha256=digest, initial_state={'_uid': 0, **{name: 0 for name in SOURCE_NAMES[index] if name is not None}}, handler=ScalarController(index), max_request_bytes=MAX_DATAGRAM) for index, profile_id, digest, hid in _SOURCE_ROWS if index == 22))
