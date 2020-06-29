import unittest
import socket

from greeclimate.gree_climate import GreeClimate
from greeclimate.device import Device
from greeclimate.device_info import DeviceInfo
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
        
    # async def testShouldReturnDeviceWhenRequested(self):
    #     gree = GreeClimate()

    #     device = gree.get_device(""" some kind of device id """)

    #     self.assertIsNotNone(device)
