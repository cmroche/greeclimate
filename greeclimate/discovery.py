import asyncio
import json
import logging
import time
from asyncio import Task
from asyncio.events import AbstractEventLoop
from ipaddress import IPv4Address
from typing import Coroutine, List

from greeclimate.device import DeviceInfo
from greeclimate.network import BroadcastListenerProtocol, IPAddr, IPInterface

_LOGGER = logging.getLogger(__name__)


class Listener:
    """Base class for device discovery events."""

    async def device_found(self, device_info: DeviceInfo) -> None:
        """Called any time a new (unique) device is found on the network."""

    async def device_update(self, device_info: DeviceInfo) -> None:
        """Called any time an up address for a device has changed on the network."""


class Discovery(BroadcastListenerProtocol, Listener):
    """Interact with gree devices on the network

    The `GreeClimate` class provides basic services for discovery and
    interaction with gree device on the network.
    """

    def __init__(
        self,
        timeout: int = 2,
        allow_loopback: bool = False,
        loop: AbstractEventLoop = None,
    ):
        """Intialized the discovery manager.

        Args:
            timeout (int): Wait this long for responses to the scan request
            allow_loopback (bool): Allow scanning the loopback interface, default `False`
            loop (AbstractEventLoop): Async event loop
        """
        super(BroadcastListenerProtocol, self).__init__()
        self._timeout = timeout
        self._allow_loopback = allow_loopback

        self._device_infos = []
        self._listeners = []
        self._tasks = []

        self._loop = loop or asyncio.get_event_loop()
        self._transport = None

    # Task management
    @property
    def tasks(self) -> List[Coroutine]:
        """Returns the outstanding tasks waiting completion."""
        return self._tasks

    @property
    def devices(self) -> List[DeviceInfo]:
        """Return the current known list of devices."""
        return self._device_infos

    def _task_done_callback(self, task):
        if task.exception():
            _LOGGER.exception("Uncaught exception", exc_info=task.exception())
        self._tasks.remove(task)

    def _create_task(self, coro) -> Task:
        """Create and track tasks that are being created for events."""
        task = self._loop.create_task(coro)
        self._tasks.append(task)
        task.add_done_callback(self._task_done_callback)
        return task

    # Listener management
    def add_listener(self, listener: Listener) -> List[Coroutine]:
        """Add a listener that will receive discovery events.

        Adding a listener will cause all currently known device to trigger a
        new device added event on the listen object.

        Args:
            listener (Listener): A listener object which will receive events

        Returns:
            List[Coro]: List of tasks for device found events.
        """
        if not listener in self._listeners:
            self._listeners.append(listener)
            return [self._create_task(listener.device_found(x)) for x in self.devices]

    def remove_listener(self, listener: Listener) -> bool:
        """Remove a listener that has already been registered.

        Args:
            listener (Listener): A listener object which will receive events

        Returns:
            bool: True if listener has been remove, false if it didn't exist
        """
        if listener in self._listeners:
            self._listeners.remove(listener)
            return True
        return False

    async def device_found(self, device_info: DeviceInfo) -> None:
        """Device is found.

        Notify all listeners that a device was found. Exceptions raised by
        listeners are ignored.

        Args:
            device_info (DeviceInfo): Information about the newly discovered
            device
        """

        for index, last_info in enumerate(self._device_infos):
            if device_info == last_info:
                if device_info.ip != last_info.ip:
                    # ip address info may have been updated, so store the new info
                    # and trigger a `device_update` event.
                    self._device_infos[index] = device_info
                    tasks = [l.device_update(device_info) for l in self._listeners]
                    await asyncio.gather(*tasks, return_exceptions=True)
                return

        self._device_infos.append(device_info)

        _LOGGER.info("Found gree device %s", str(device_info))

        tasks = [l.device_found(device_info) for l in self._listeners]
        await asyncio.gather(*tasks, return_exceptions=True)

    def packet_received(self, obj, addr: IPAddr) -> None:
        """Event called when a packet is received and decoded."""
        pack = obj.get("pack")
        if not pack:
            _LOGGER.error("Received an unexpected response during discovery")
            return

        device = (
            addr[0],
            addr[1],
            pack.get("mac") or pack.get("cid"),
            pack.get("name"),
            pack.get("brand"),
            pack.get("model"),
            pack.get("ver"),
        )

        self._create_task(self.device_found(DeviceInfo(*device)))

    # Discovery
    async def scan(self, wait_for=0) -> List[DeviceInfo]:
        """Sends a discovery broadcast packet on each network interface to
            locate Gree units on the network

        Args:
            wait_for (int): Optionally wait this many seconds for discovery
                            and return the devices found.

        Returns:
            List[DeviceInfo]: List of devices found during this scan
        """
        _LOGGER.info("Scanning for Gree devices ...")

        await self.search_devices()
        if wait_for:
            await asyncio.sleep(wait_for)
            await asyncio.gather(*self.tasks, return_exceptions=True)

        return self._device_infos

    def _get_broadcast_addresses(self) -> List[IPInterface]:
        """Return a list of broadcast addresses for each discovered interface"""
        import netifaces

        bdrAddrs = []
        for iface in netifaces.interfaces():
            for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
                ipaddr = addr.get("addr")
                bdr = addr.get("broadcast")
                peer = addr.get("peer")
                if addr:
                    ip4addr = IPv4Address(ipaddr)
                    if ip4addr.is_private:
                        if ip4addr.is_loopback and self._allow_loopback:
                            bdrAddrs.append(IPInterface(ipaddr, bdr or peer))
                        elif not ip4addr.is_loopback:
                            bdrAddrs.append(IPInterface(ipaddr, bdr))

        return bdrAddrs

    async def search_on_interface(self, bcast_iface: IPInterface) -> None:
        """Search for devices on a specific interface."""
        _LOGGER.debug(
            "Listening for devices on %s using %s",
            bcast_iface.ip_address,
            bcast_iface.bcast_address,
        )

        if self._transport is None:
            local_addr = (bcast_iface.ip_address, 0)

            self._transport, _ = await self._loop.create_datagram_endpoint(
                lambda: self, local_addr=local_addr, allow_broadcast=True
            )

        await self.send({"t": "scan"}, (bcast_iface.bcast_address, 7000))

    async def search_devices(self, broadcastAddrs: str = None) -> None:
        """Search for devices with specific broadcast addresses."""
        if not broadcastAddrs:
            broadcastAddrs = self._get_broadcast_addresses()

        broadcastAddrs = list(broadcastAddrs)
        await asyncio.gather(
            *[asyncio.create_task(self.search_on_interface(b)) for b in broadcastAddrs]
        )
