"""Original H uint16 callback semantics, ragged metadata and safe atomicity."""

import base64
from copy import deepcopy
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest

from gree_emulator.__main__ import load_config
from gree_emulator.wire import InvalidPacket, encode_reply


def unit():
    return load_config({"devices": [{"id": "h", "profile": "sim-w04h-v3.55",
                                    "mid": "10001", "mac": "020000000001",
                                    "name": "H controller", "room_c": 25}]})[2][0]


def exchange(device, inner):
    payload = AES.new(device.key, AES.MODE_ECB).encrypt(pad(json.dumps(inner).encode(), 16))
    reply, = device.profile.handler.handle(device, {
        "t": "pack", "tcid": device.mac, "cid": "app", "uid": 7, "i": 0,
        "pack": base64.b64encode(payload).decode(),
    })
    outer = json.loads(encode_reply(reply))
    return json.loads(unpad(AES.new(device.key, AES.MODE_ECB).decrypt(base64.b64decode(outer["pack"])), 16))


def test_raw_cache_wraps_instead_of_applying_ac_ranges_and_keeps_duplicates():
    device = unit()
    ack = exchange(device, {"t": "cmd", "opt": ["ElcP", "ElcP", "NoD", "lock"],
                            "p": [65537, -1, 65538, 65539]})
    assert ack["p"] == [1, 65535, 2, 3]
    assert exchange(device, {"t": "status", "cols": ["ElcP", "NoD", "lock", "ElcP"]})["dat"] == [65535, 2, 3, 65535]


def test_rssi_command_ack_is_cache_value_but_fresh_getter_uses_sdk_input():
    device = unit()
    ack = exchange(device, {"t": "cmd", "opt": ["rssi"], "p": [65537]})
    assert ack["p"] == [1]
    assert exchange(device, {"t": "status", "cols": ["rssi"]})["dat"] == [-51]


def test_full_metadata_retains_columns_without_fabricating_values():
    device = unit()
    reply = exchange(device, {"t": "status", "cols": ["model", "rssi", "hid", "apssid", "mac", "NoD"]})
    assert reply["cols"] == ["model", "rssi", "hid", "apssid", "mac", "NoD"]
    assert reply["dat"] == [-51, "362001061060+U-W04HV3.55.bin", device.mac, 0]
    ack = exchange(device, {"t": "cmd", "opt": ["host", "name"], "p": ["dis.gree.com", "new config name"]})
    # Original name setter and getter use different storage; do not rename the reported platform name.
    assert ack["p"] == ["dis.gree.com", "H controller"]
    assert exchange(device, {"t": "status", "cols": ["host", "name"]})["dat"] == ["dis.gree.com", "H controller"]


def test_invalid_metadata_batch_does_not_apply_raw_prefix_or_advance():
    device = unit()
    before = deepcopy(device.state), device.last_step, device.room_c
    with pytest.raises(InvalidPacket):
        exchange(device, {"t": "cmd", "opt": ["ElcP", "host"], "p": [65537, "x" * 21]})
    assert (device.state, device.last_step, device.room_c) == before


@pytest.mark.parametrize("value,expected", [(10 ** 400, 65535), (-(10 ** 400), 0)])
def test_large_json_integer_saturates_without_float_overflow(value, expected):
    device = unit()
    assert exchange(device, {"t": "cmd", "opt": ["ElcP"], "p": [value]})["p"] == [expected]
    assert exchange(device, {"t": "status", "cols": ["ElcP"]})["dat"] == [expected]
