import unittest

from greeclimate.gree_climate import GreeClimate
from greeclimate.device_info import DeviceInfo
from unittest.mock import patch


class GreeClimateTestCase(unittest.IsolatedAsyncioTestCase):

    @patch("greeclimate.network_helper.search_devices")
    async def testShouldListDevicesWhenSearched(self, mock_search_devices):
        gree = GreeClimate()
        mock_search_devices.return_value = [
            DeviceInfo("1.1.1.0", "7000", "aabbcc001122", "MockDevice1")
        ]

        devices = await gree.search_devices()

        self.assertIsNotNone(devices)
        self.assertGreater(len(devices), 0, "No devices were discovered")

    @patch("greeclimate.network_helper.search_devices")
    async def testShouldReturnEmptyListDevicesWhenNoDevicesFound(self, mock_search_devices):
        gree = GreeClimate()
        mock_search_devices.return_value = []

        devices = await gree.search_devices()

        self.assertIsNotNone(devices)
        self.assertEqual(len(devices), 0)
