from __future__ import annotations

import asyncio
import logging
from asyncio import Task
from asyncio.events import AbstractEventLoop
from ipaddress import IPv4Address

from greeclimate.cipher import CipherV1
from greeclimate.device import DeviceInfo
from greeclimate.network import BroadcastListenerProtocol, IPAddr
from greeclimate.taskable import Taskable

_LOGGER = logging.getLogger(__name__)


class Listener:
    """Base class for device discovery events."""

    async def device_found(self, device_info: DeviceInfo) -> None:
        """Called any time a new (unique) device is found on the network."""

    async def device_update(self, device_info: DeviceInfo) -> None:
        """Called any time an up address for a device has changed on the network."""


class Discovery(BroadcastListenerProtocol, Listener, Taskable):
    """Interact with gree devices on the network

    The `GreeClimate` class provides basic services for discovery and
    interaction with gree device on the network.
    """

    def __init__(
        self,
        timeout: int = 2,
        allow_loopback: bool = False,
        loop: AbstractEventLoop = None,
    ) -> None:
        """Initialized the discovery manager.

        Args:
            timeout (int): Wait this long for responses to the scan request
            allow_loopback (bool): Allow scanning the loopback interface, default `False`
            loop (AbstractEventLoop): Async event loop
        """
        BroadcastListenerProtocol.__init__(self, timeout)
        Taskable.__init__(self, loop)
        self.device_cipher = CipherV1()
        self._allow_loopback: bool = allow_loopback
        self._device_infos: list[DeviceInfo] = []
        self._listeners: list[Listener] = []

    # Task management
    @property
    def devices(self) -> list[DeviceInfo]:
        """Return the current known list of devices."""
        return self._device_infos

    # Listener management
    def add_listener(self, listener: Listener) -> list[Task]:
        """Add a listener that will receive discovery events.

        Adding a listener will cause all currently known device to trigger a
        new device added event on the listen object.

        Args:
            listener (Listener): A listener object which will receive events

        Returns:
            List[Coro]: List of tasks for device found events.
        """
        if listener not in self._listeners:
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
    async def scan(self, wait_for: int = 0, bcast_ifaces: list[IPv4Address] | None = None) -> list[DeviceInfo]:
        """Sends a discovery broadcast packet on each network interface to
            locate Gree units on the network

        Args:
            wait_for (int): Optionally wait this many seconds for discovery
                            and return the devices found.
            bcast_ifaces (list[IPv4Address]): List of broadcast addresses to scan

        Returns:
            List[DeviceInfo]: List of devices found during this scan
        """
        _LOGGER.info("Scanning for Gree devices ...")

        await self.search_devices(bcast_ifaces)
        if wait_for:
            await asyncio.sleep(wait_for)
            await asyncio.gather(*self.tasks, return_exceptions=True)

        return self._device_infos

    def _get_broadcast_addresses(self) -> list[IPv4Address]:
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
                    if ip4addr.is_loopback and self._allow_loopback:
                        if bdr or peer:
                            bdrAddrs.append(IPv4Address(bdr or peer))
                    elif not ip4addr.is_loopback:
                        if bdr:
                            bdrAddrs.append(IPv4Address(bdr))

        return bdrAddrs

    async def search_on_interface(self, bcast_iface: IPv4Address) -> None:
        """Search for devices on a specific interface."""
        _LOGGER.debug(
            "Listening for devices on %s",
            bcast_iface,
        )

        if self._transport is None:
            self._transport, _ = await self._loop.create_datagram_endpoint(
                lambda: self, local_addr=("0.0.0.0", 0), allow_broadcast=True
            )

        await self.send({"t": "scan"}, (str(bcast_iface), 7000))

    async def search_devices(self, broadcastAddrs: list[IPv4Address] | None = None) -> None:
        """Search for devices with specific broadcast addresses."""
        if not broadcastAddrs:
            broadcastAddrs = self._get_broadcast_addresses()
        await asyncio.gather(
            *[asyncio.create_task(self.search_on_interface(b)) for b in broadcastAddrs], return_exceptions=True
        )