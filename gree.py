import argparse
import asyncio
import logging

from greeclimate.device import Device
from greeclimate.discovery import Discovery

logging.basicConfig(
    level=logging.DEBUG, format="%(name)s - %(levelname)s - %(message)s"
)
_LOGGER = logging.getLogger(__name__)


async def run_discovery():
    devices = []
    _LOGGER.debug("Scanning network for Gree devices")

    for device_info in await Discovery.search_devices():
        device = Device(device_info)
        await device.bind()

        _LOGGER.debug(
            "Adding Gree device at %s:%i (%s)",
            device.device_info.ip,
            device.device_info.port,
            device.device_info.name,
        )
        devices.append(device)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gree command line utility.")
    parser.add_argument("--discovery", action="store_true", default=False)
    args = parser.parse_args()

    if args.discovery:
        asyncio.run(run_discovery())
        