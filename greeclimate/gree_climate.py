import logging

from greeclimate.device_info import DeviceInfo
import greeclimate.network_helper as nethelper
from typing import List


class GreeClimate:
    """Interact with gree devices on the network

    The `GreeClimate` class provides basic services for discovery and interaction
    with gree device on the network.
    """

    _logger = None

    def __init__(self):
        self._logger = logging.getLogger(__name__)

    async def search_devices(self) -> List[DeviceInfo]:
        """ Sends a discovery broadcast packet on each network interface to
            locate Gree units on the network

        Returns:
            List[DeviceInfo]: List of device informations
        """
        self._logger.info("Starting Gree device discovery process")

        devices = await nethelper.search_devices()
        for d in devices:
            self._logger.info("Found %s", str(d))

        return devices
