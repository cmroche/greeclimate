"""Pytest module configuration."""
from unittest.mock import patch

import pytest

from greeclimate.device import Device
from tests.common import FakeCipher


@pytest.fixture(name="ifaddr_adapters")
def ifaddr_adapters_fixture():
    """Patch ifaddr adapter discovery."""
    with patch("ifaddr.get_adapters", return_value=[]) as adapters_mock:
        yield adapters_mock


@pytest.fixture(name="cipher")
def cipher_fixture():
    """Patch the cipher object."""
    with patch("greeclimate.device.CipherV1") as mock1, patch("greeclimate.device.CipherV2") as mock2:
        mock1.return_value = FakeCipher(b"1234567890123456")
        mock2.return_value = FakeCipher(b"1234567890123456")
        yield mock1, mock2


@pytest.fixture(name="send")
def network_fixture():
    """Patch the device object."""
    with patch.object(Device, "send") as mock:
        yield mock
