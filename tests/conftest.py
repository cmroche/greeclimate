"""Pytest module configuration."""
from unittest.mock import patch

import pytest

from tests.common import FakeCipher

MOCK_INTERFACES = ["lo"]
MOCK_LO_IFACE = {
    2: [{"addr": "10.0.0.1", "netmask": "255.0.0.0", "peer": "10.255.255.255"}]
}


@pytest.fixture(name="netifaces")
def netifaces_fixture():
    """Patch netifaces interface discover."""
    with patch("netifaces.interfaces", return_value=MOCK_INTERFACES), patch(
            "netifaces.ifaddresses", return_value=MOCK_LO_IFACE
    ) as ifaddr_mock:
        yield ifaddr_mock



@pytest.fixture(name="cipher")
def cipher_fixture():
    """Patch the cipher object."""
    with patch("greeclimate.device.CipherV1") as mock1, patch("greeclimate.device.CipherV2") as mock2:
        mock1.return_value = FakeCipher(b"1234567890123456")
        mock2.return_value = FakeCipher(b"1234567890123456")
        yield
