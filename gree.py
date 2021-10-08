import argparse
import asyncio
import logging

from greeclimate.device import Device, DeviceInfo
from greeclimate.discovery import Discovery, Listener

logging.basicConfig(
    level=logging.DEBUG, format="%(name)s - %(levelname)s - %(message)s"
)
_LOGGER = logging.getLogger(__name__)


class DiscoveryListener(Listener):
    def __init__(self, bind):
        """Initialize the event handler."""
        super().__init__()
        self.bind = bind

    """Class to handle incoming device discovery events."""

    async def device_found(self, device_info: DeviceInfo) -> None:
        """A new device was found on the network."""
        if self.bind:
            device = Device(device_info)
            await device.bind()
            await device.request_version()
            _LOGGER.info(f"Device firmware: {device.hid}")


async def run_discovery(bind=False):
    """Run the device discovery process."""
    _LOGGER.debug("Scanning network for Gree devices")

    discovery = Discovery()
    listener = DiscoveryListener(bind)
    discovery.add_listener(listener)

    await discovery.scan(wait_for=10)

    _LOGGER.info("Done discovering devices")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gree command line utility.")
    parser.add_argument("--discovery", default=False, action="store_true")
    parser.add_argument("--bind", default=False, action="store_true")
    args = parser.parse_args()

    if args.discovery:
        asyncio.run(run_discovery(args.bind))
