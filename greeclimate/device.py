import logging

import greeclimate.network_helper as nethelper
from greeclimate.exceptions import DeviceNotBoundError
from greeclimate.network_helper import Props
from greeclimate.device_info import DeviceInfo


class Device:
    
    def __init__(self, device_info):
        self._device_info = device_info
        self._logger = logging.getLogger("gree_climate")

        self.device_key = None

        """ Device properties """
        self._properties = None

    async def bind(self, key=None):
        """ Run the binding procedure. Binding happens two ways:
            1 - Without the key, binding must pass the device info structure immediately following
                the search devices procedure. There is only a small window to complete registration.
            2 - With a key, binding is implicit and no further action is required

            Both approaches result in a device_key which is used as like a persitent session id.
        """

        self._logger.info(
            "Starting device binding to %s", str(self._device_info))

        if key:
            self.device_key = key
        else:
            self.device_key = await nethelper.bind_device(self._device_info)

        if self.device_key:
            self._logger.info(
                "Bound to device using key %s", self.device_key)

    async def update_state(self):
        """ Update the internal state of the device structure from the physical device """
        if not self.device_key:
            raise DeviceNotBoundError

        self._logger.debug("Updating device properties for (%s)", str(self._device_info))

        props = [x.value for x in Props]
        self._properties = await nethelper.request_state(props, self._device_info, self.device_key)


    def get_property(self, name):
        """ Generic lookup of properties tracked from the physical device """
        if self._properties:
            return self._properties.get(name)
        return None
