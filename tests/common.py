import asyncio
import socket
from socket import SOCK_DGRAM
from unittest.mock import Mock, create_autospec, patch

from greeclimate.network import DeviceProtocolBase2

DEFAULT_TIMEOUT = 1
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
DEFAULT_REQUEST = {
    "t": "pack",
    "i": 1,
    "uid": 0,
    "cid": "aabbcc112233",
    "tcid": "",
    "pack": {
        "t": "test"
    }
}
DEFAULT_RESPONSE = {
    "t": "pack",
    "i": 1,
    "uid": 0,
    "cid": "aabbcc112233",
    "tcid": "",
    "pack": {
        "t": "testresponse"
    }
}


def generate_response(data):
    """Generate a response from a request."""
    response = DEFAULT_RESPONSE.copy()
    response["pack"].update(data)
    return response


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


def encrypt_payload(data):
    """Encrypt the payload of responses quickly."""
    d = data.copy()
    d["pack"] = DeviceProtocolBase2.encrypt_payload(d["pack"])
    return d


class Responder:
    """Context manage for easy raw socket responders."""

    def __init__(self, family, addr, bcast=False) -> None:
        """Initialize the class."""
        self.sock = None
        self.family = family
        self.addr = addr
        self.bcast = bcast

    def __enter__(self):
        """Enter the context manager."""
        self.sock = socket.socket(self.family, SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, self.bcast)
        self.sock.settimeout(DEFAULT_TIMEOUT)
        self.sock.bind(("", self.addr))
        return self.sock

    def __exit__(self, *args):
        """Exit the context manager."""
        self.sock.close()
