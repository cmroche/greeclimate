import unittest
import socket

from greeclimate.gree_climate import GreeClimate
from greeclimate.device import Device
from greeclimate.device_info import DeviceInfo
from greeclimate.network_helper import Props
from unittest.mock import patch


class GreeDeviceTestCase(unittest.IsolatedAsyncioTestCase):

    @patch("greeclimate.network_helper.search_devices")
    @patch("greeclimate.network_helper.bind_device")
    async def testShouldReturnKeyWhenBoundToDevice(self, mock_bind, mock_search):
        # DeviceInfo("192.168.1.29", 7000, "f4911e7aca59", "1e7aca59")

        mock_search.return_value = [
            DeviceInfo("1.1.1.0", "7000", "aabbcc001122", "MockDevice1")
        ]
        mock_bind.return_value = "St8Vw1Yz4Bc7Ef0H"

        """ The only way to get the key through binding is by scanning first
        """
        gree = GreeClimate()
        devices = await gree.search_devices()
        device = Device(devices[0])
        await device.bind()

        self.assertIsNotNone(device)
        self.assertEquals(device.device_key, "St8Vw1Yz4Bc7Ef0H")

    @patch("greeclimate.network_helper.search_devices")
    @patch("greeclimate.network_helper.bind_device")
    async def testShouldTimeoutWhenNoResponse(self, mock_bind, mock_search):

        mock_search.return_value = [
            DeviceInfo("1.1.1.0", "7000", "aabbcc001122", "MockDevice1")
        ]
        mock_bind.side_effect = socket.timeout

        """ The only way to get the key through binding is by scanning first
        """
        gree = GreeClimate()
        devices = await gree.search_devices()
        device = Device(devices[0])

        with self.assertRaises(socket.timeout):
            await device.bind()

        self.assertIsNotNone(device)
        self.assertIsNone(device.device_key)


class GreeDeviceStateTestCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._device = Device(DeviceInfo("192.168.1.29", 7000, "f4911e7aca59", "1e7aca59"))
        await self._device.bind(key="St8Vw1Yz4Bc7Ef0H")

    def getMockState(self):
        return {"Pow": 1, "Mod": 3, "SetTem": 25, "TemUn": 0, "TemRec": 0, "WdSpd": 0,
                "Air": 0, "Blo": 0, "Health": 0, "SwhSlp": 0, "Lig": 1, "SwingLfRig": 1, "SwUpDn": 1, "Quiet": 0, "Tur": 0,
                "StHt": 0, "SvSt": 0, "HeatCoolType": 0}

    @patch("greeclimate.network_helper.request_state")
    async def testShouldUpdatePropertiesWhenRequested(self, mock_request):
        mock_request.return_value = self.getMockState()

        for p in [x.value for x in Props]:
            self.assertIsNone(self._device.get_property(p))

        await self._device.update_state()

        for p in [x.value for x in Props]:
            self.assertIsNotNone(self._device.get_property(p), f"Property {p} was unexpectedly None")
            self.assertEquals(self._device.get_property(p), self.getMockState()[p])

    
