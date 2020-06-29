import unittest

from greeclimate.gree_climate import GreeClimate


class GreeClimateTestCase(unittest.IsolatedAsyncioTestCase):

    async def testShouldListDevicesWhenSearched(self):
        gree = GreeClimate()

        devices = await gree.search_devices()

        self.assertIsNotNone(devices)
        self.assertGreater(len(devices), 0, "No devices were discovered")

    # async def testShouldReturnKeyWhenBoundToDevice(self):
    #     gree = GreeClimate()

    #     device = gree.bind_device(""" some kind of device id """)

    #     self.assertIsNotNone(device)

    # async def testShouldReturnDeviceWhenRequested(self):
    #     gree = GreeClimate()

    #     device = gree.get_device(""" some kind of device id """)

    #     self.assertIsNotNone(device)
