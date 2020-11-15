import logging
from typing import List

import greeclimate.network as nethelper
from greeclimate.device import DeviceInfo

_LOGGER = logging.getLogger(__name__)


class Discovery:
    """Interact with gree devices on the network

    The `GreeClimate` class provides basic services for discovery and interaction
    with gree device on the network.
    """

    @staticmethod
    async def search_devices(timeout=10) -> List[DeviceInfo]:
        """Sends a discovery broadcast packet on each network interface to
            locate Gree units on the network

        Returns:
            List[DeviceInfo]: List of device informations
        """
        _LOGGER.info("Starting Gree device discovery process")

        results = await nethelper.search_devices(timeout=timeout)
        devices = [DeviceInfo(*d) for d in list(set(results))]
        for d in devices:
            _LOGGER.info("Found %s", str(d))

        return devices
