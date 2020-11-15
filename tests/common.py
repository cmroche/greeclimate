import asyncio
import socket

from unittest.mock import Mock, create_autospec, patch

DEFAULT_TIMEOUT = 5
DISCOVERY_REQUEST = {"t": "scan"}
DISCOVERY_RESPONSE = {
    "t": "pack",
    "i": 1,
    "uid": 0,
    "cid": "aabbcc112233",
    "tcid": "",
    "pack": {
        "t": "dev",
        "cid": "aabbcc112233",
        "bc": "gree",
        "brand": "gree",
        "catalog": "gree",
        "mac": "aabbcc112233",
        "mid": "10001",
        "model": "gree",
        "name": "fake unit",
        "series": "gree",
        "vender": "1",
        "ver": "V1.1.13",
        "lock": 0,
    },
}
DISCOVERY_RESPONSE_NO_CID = {
    "t": "pack",
    "i": 1,
    "uid": 0,
    "cid": "",
    "tcid": "",
    "pack": {
        "t": "dev",
        "cid": "",
        "bc": "gree",
        "brand": "gree",
        "catalog": "gree",
        "mac": "aabbcc112233",
        "mid": "10001",
        "model": "gree",
        "name": "fake unit",
        "series": "gree",
        "vender": "1",
        "ver": "V1.1.13",
        "lock": 0,
    },
}
DEFAULT_RESPONSE = {
    "t": "pack",
    "i": 1,
    "uid": 0,
    "cid": "aabbcc112233",
    "tcid": "",
    "pack": {},
}


def get_mock_device_info():
    return Mock(
        name="device-info",
        ip="127.0.0.1",
        port="7000",
        mac="aabbcc112233",
        brand="gree",
        model="gree",
        version="1.1.13",
    )
