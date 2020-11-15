import argparse
import asyncio
import logging

from greeclimate.device import Device
from greeclimate.discovery import Discovery

logging.basicConfig(
    level=logging.DEBUG, format="%(name)s - %(levelname)s - %(message)s"
)
_LOGGER = logging.getLogger(__name__)


async def run_discovery(bind=False):
    devices = []
    _LOGGER.debug("Scanning network for Gree devices")
    print(bind)

    async def _bind(di):
        device = Device(di)
        devices.append(device)
        await device.bind()

    discovery = Discovery()

    if bind:
        await discovery.search_devices(async_callback=_bind)
    else:
        await discovery.search_devices(async_callback=None)

    _LOGGER.info("Done discovering devices")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gree command line utility.")
    parser.add_argument("--discovery", default=False, action="store_true")
    parser.add_argument("--bind", default=False, action="store_true")
    args = parser.parse_args()

    if args.discovery:
        asyncio.run(run_discovery(args.bind))
