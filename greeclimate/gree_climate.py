import logging

import greeclimate.network_helper as nethelper


class GreeClimate:
    _logger = None

    def __init__(self):
        self._logger = logging.getLogger(__name__)

    async def search_devices(self):
        """ Sends a discovery broadcast packet on each network interface to
            locate Gree units on the network
        """
        self._logger.info("Starting Gree device discovery process")

        devices = await nethelper.search_devices()
        for d in devices:
            self._logger.info("Found %s", str(d))

        return devices
