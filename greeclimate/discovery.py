import asyncio
import json
import logging
import time

from ipaddress import IPv4Network
from typing import Coroutine, List, Tuple

from greeclimate.network import BroadcastListenerProtocol, DatagramStream, IPInterface
from greeclimate.device import DeviceInfo

_LOGGER = logging.getLogger(__name__)


class Discovery:
    """Interact with gree devices on the network

    The `GreeClimate` class provides basic services for discovery and
    interaction with gree device on the network.
    """

    def __init__(self, timeout: int = 10, allow_loopback: bool = False):
        """Intialized the discovery manager.

        Args:
            timeout (int): Wait this long for responses to the scan request
        """
        self._timeout = timeout
        self._allow_loopback = allow_loopback
        self._iface_streams = {}
        self._cbs = []

    async def search_devices(
        self, async_callback: Coroutine = None
    ) -> Tuple[List[DeviceInfo], List[Coroutine]]:
        """Sends a discovery broadcast packet on each network interface to
            locate Gree units on the network

        Args:
            async_callback (coro): Called as soon as a device is located on the network

        Returns:
            List[DeviceInfo]: List of device informations for each device found
            List[Coroutine]: List of callback tasks
        """
        _LOGGER.info("Locating Gree devices ...")

        self._cbs = []
        results = await self._search_devices(async_callback=async_callback)
        devices = [DeviceInfo(*d) for d in list(set(results))]

        return devices, self._cbs

    def _get_broadcast_addresses(self) -> List[IPInterface]:
        """ Return a list of broadcast addresses for each discovered interface"""
        import netifaces

        broadcastAddrs = []

        interfaces = netifaces.interfaces()
        for iface in interfaces:
            addr = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addr:
                netmask = addr[netifaces.AF_INET][0].get("netmask")
                ipaddr = addr[netifaces.AF_INET][0].get("addr")
                if netmask and addr:
                    net = IPv4Network(f"{ipaddr}/{netmask}", strict=False)
                    if net.broadcast_address:
                        if not net.is_loopback or self._allow_loopback:
                            broadcastAddrs.append(
                                IPInterface(str(ipaddr), str(net.broadcast_address))
                            )

        return broadcastAddrs

    async def _search_on_interface(
        self, bcast_iface: IPInterface, async_callback: Coroutine
    ):
        _LOGGER.debug("Listening for devices on %s", bcast_iface.ip_address)

        if self._iface_streams.get(bcast_iface.ip_address) is None:
            loop = asyncio.get_event_loop()
            recvq = asyncio.Queue()
            excq = asyncio.Queue()
            drained = asyncio.Event()

            local_addr = (bcast_iface.ip_address, 0)

            transport, _ = await loop.create_datagram_endpoint(
                lambda: BroadcastListenerProtocol(recvq, excq, drained),
                local_addr=local_addr,
                allow_broadcast=True,
            )
            self._iface_streams[bcast_iface.ip_address] = DatagramStream(
                transport, recvq, excq, drained, self._timeout
            )

        stream = self._iface_streams[bcast_iface.ip_address]
        data = json.dumps({"t": "scan"}).encode()
        await stream.send(data, (bcast_iface.bcast_address, 7000))

        devices = []

        start_ts = time.time()
        loop_ts = start_ts + self._timeout
        while loop_ts > time.time() or stream.recv_ready():
            if not stream.recv_ready():
                dt = loop_ts - time.time()
                dt = min(dt, 1)
                await asyncio.sleep(dt)
                continue

            try:
                (response, addr) = await stream.recv_device_data()
                pack = response["pack"]
                _LOGGER.debug("Received response from device search\n%s", pack)
                device = (
                    addr[0],
                    addr[1],
                    pack.get("mac") or pack.get("cid"),
                    pack.get("name"),
                    pack.get("brand"),
                    pack.get("model"),
                    pack.get("ver"),
                )

                if async_callback:
                    self._cbs.append(
                        asyncio.create_task(async_callback(DeviceInfo(*device)))
                    )

                _LOGGER.info("Found %s", str(DeviceInfo(*device)))
                devices.append(device)
            except asyncio.TimeoutError:
                break
            except json.JSONDecodeError:
                _LOGGER.debug("Unable to decode device search response payload")

        return devices

    async def _search_devices(
        self, broadcastAddrs: str = None, async_callback: Coroutine = None
    ):
        if not broadcastAddrs:
            broadcastAddrs = self._get_broadcast_addresses()

        broadcastAddrs = list(broadcastAddrs)
        done, _ = await asyncio.wait(
            [
                asyncio.create_task(self._search_on_interface(b, async_callback))
                for b in broadcastAddrs
            ]
        )

        devices = []
        for task in done:
            results = task.result()
            for result in results:
                devices.append(result)

        return devices
