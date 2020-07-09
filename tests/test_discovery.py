import unittest

from greeclimate.discovery import Discovery
from greeclimate.device import DeviceInfo
from unittest.mock import patch


class GreeClimateTestCase(unittest.IsolatedAsyncioTestCase):

    @patch("greeclimate.network_helper.search_devices")
    async def testShouldListDevicesWhenSearched(self, mock_search_devices):
        mock_search_devices.return_value = [
            ("1.1.1.0", "7000", "aabbcc001122", "MockDevice1")
        ]

        devices = await Discovery.search_devices()

        self.assertIsNotNone(devices)
        self.assertGreater(len(devices), 0, "No devices were discovered")

    @patch("greeclimate.network_helper.search_devices")
    async def testShouldReturnEmptyListDevicesWhenNoDevicesFound(self, mock_search_devices):
        mock_search_devices.return_value = []

        devices = await Discovery.search_devices()

        self.assertIsNotNone(devices)
        self.assertEqual(len(devices), 0)
