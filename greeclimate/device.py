import logging

import greeclimate.network_helper as nethelper
from greeclimate.device_info import DeviceInfo


class Device:
    _logger = None
    _device_info = None
    
    device_key = None

    def __init__(self, device_info):
        self._device_info = device_info
        self._logger = logging.getLogger("gree_climate")

    async def bind(self):
        """ Run the binding procedure. This possibly results in a new device
            encryption key being assigned and returned via the binding response
        """

        self._logger.info(
            "Starting device binding to %s", str(self._device_info))

        self.device_key = await nethelper.bind_device(self._device_info)

        if self.device_key:
            self._logger.info(
                "Bound to device using key %s", self.device_key)
