"""Pytest module configuration."""
import pytest
from unittest.mock import patch

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


@pytest.fixture(name="search_devices")
def search_devices_fixture():
    """Patch search_on_interface."""
    with patch("greeclimate.discovery.Discovery._search_devices") as mock:
        yield mock
