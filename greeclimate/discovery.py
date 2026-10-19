from __future__ import annotations

import asyncio
import logging
from asyncio import Task
from asyncio.events import AbstractEventLoop
from ipaddress import IPv4Address, IPv4Interface

from greeclimate.cipher import CipherV1, CipherV2
from greeclimate.deviceinfo import DeviceInfo, _canonical_mac
from greeclimate.network import BroadcastListenerProtocol, IPAddr
from greeclimate.taskable import Taskable

_LOGGER = logging.getLogger(__name__)


class Listener:
    """Base class for device discovery events."""

    async def device_found(self, device_info: DeviceInfo) -> None:
        """Report a first canonical MAC observation or replay, not enrollment approval."""

    async def device_update(self, device_info: DeviceInfo) -> None:
        """Report a changed IP or port; metadata-only refreshes emit no event."""


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
        self._endpoint_lock = asyncio.Lock()

    # Task management
    @property
    def devices(self) -> list[DeviceInfo]:
        """Return latest snapshots in first-observation order, keyed by canonical MAC."""
        return self._device_infos

    # Listener management
    def add_listener(self, listener: Listener) -> list[Task] | None:
        """Add a listener that will receive discovery events.

        Existing devices are replayed using their latest metadata snapshot.
        Closing cancels listener work and releases registered listeners.

        Args:
            listener (Listener): A listener object which will receive events

        Returns:
            List[Coro]: List of tasks for device found events or None if lister was added early.
        """
        if self._closing:
            return None
        if listener not in self._listeners:
            self._listeners.append(listener)
            return [self._create_task(listener.device_found(x)) for x in self.devices]
        return None

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
        """Refresh the canonical identity's snapshot and notify endpoint changes.

        First observations emit device_found; changed IP or port emits
        device_update. Metadata-only observations silently replace the cache
        entry. Listener failures are isolated; enrollment remains caller-owned.
        """
        if self._closing:
            return
        mac = _canonical_mac(device_info.mac)
        if mac is None:
            return
        device_info.mac = mac
        for index, last_info in enumerate(self._device_infos):
            if mac == _canonical_mac(last_info.mac):
                endpoint_changed = (device_info.ip, device_info.port) != (last_info.ip, last_info.port)
                self._device_infos[index] = device_info
                if endpoint_changed:
                    tasks = [listener.device_update(device_info) for listener in self._listeners]
                    await asyncio.gather(*tasks, return_exceptions=True)
                return

        self._device_infos.append(device_info)
        _LOGGER.info("Found gree device %s", device_info)
        tasks = [listener.device_found(device_info) for listener in self._listeners]
        await asyncio.gather(*tasks, return_exceptions=True)

    def close(self) -> None:
        """Cancel listener work and close UDP; a later explicit search may reopen."""
        self._cancel_tasks()
        self._listeners.clear()
        BroadcastListenerProtocol.close(self)

    def _decrypt_pack(self, pack):
        """Decrypt a scan reply, falling back to CipherV2 if CipherV1 fails.

        Some Gree Wi-Fi modules only speak the GCM-based protocol, even
        for the initial scan reply, so the generic CipherV1 fails to
        decrypt them. Device.bind() already has this same CipherV1 ->
        CipherV2 fallback; this brings Discovery in line with it. Returns
        None if the reply is undecryptable under either cipher, so
        packet_received's existing "unexpected response" handling takes
        care of it.
        """
        try:
            return self._cipher.decrypt(pack)
        except Exception:
            try:
                return CipherV2().decrypt(pack)
            except Exception:
                return None

    def packet_received(self, obj, addr: IPAddr) -> None:
        """Event called when a packet is received and decoded."""
        if self._closing:
            return
        pack = obj.get("pack") if isinstance(obj, dict) else None
        if not isinstance(pack, dict):
            _LOGGER.debug("Ignoring discovery response without dictionary pack")
            return
        identity = pack.get("mac")
        if identity is None or identity == "":
            identity = pack.get("cid")
        mac = _canonical_mac(identity)
        if mac is None:
            _LOGGER.debug("Ignoring discovery response without usable identity")
            return

        device = (
            addr[0],
            addr[1],
            mac,
            pack.get("name"),
            pack.get("brand"),
            pack.get("model"),
            pack.get("ver"),
            pack.get("mid"),
        )

        self._create_task(self.device_found(DeviceInfo(*device)))

    # Discovery
    async def scan(
        self,
        wait_for: int = 0,
        bcast_ifaces: list[IPv4Address] | None = None,
        *,
        target_addresses: list[IPv4Address] | None = None,
    ) -> list[DeviceInfo]:
        """Send discovery packets to broadcast or unicast destinations.

        Args:
            wait_for (int): Optionally wait this many seconds for discovery
                            and return the devices found.
            bcast_ifaces (list[IPv4Address]): Compatibility alias for target_addresses.
            target_addresses (list[IPv4Address]): Destination addresses to scan.
                None or an empty list uses automatic broadcast discovery.

        Raises:
            ValueError: Both address parameters are supplied with non-None values.

        Returns:
            List[DeviceInfo]: List of devices found during this scan
        """
        if bcast_ifaces is not None:
            if target_addresses is not None:
                raise ValueError("Use either target_addresses or bcast_ifaces, not both")
            target_addresses = bcast_ifaces

        _LOGGER.info("Scanning for Gree devices ...")

        await self.search_devices(target_addresses=target_addresses)
        if wait_for:
            await asyncio.sleep(wait_for)
            await asyncio.gather(*self.tasks, return_exceptions=True)

        return self._device_infos

    def _get_broadcast_addresses(self) -> list[IPv4Address]:
        """Return a list of broadcast addresses for each discovered interface"""
        import ifaddr

        broadcast_addresses = []
        for adapter in ifaddr.get_adapters():
            for address in adapter.ips:
                if not address.is_IPv4:
                    continue
                interface = IPv4Interface((address.ip, address.network_prefix))
                if interface.ip.is_loopback:
                    if self._allow_loopback:
                        broadcast_addresses.append(interface.ip)
                    continue
                if interface.network.prefixlen >= 31:
                    continue
                broadcast_addresses.append(interface.network.broadcast_address)

        return broadcast_addresses

    async def search_on_interface(self, target_address: IPv4Address) -> None:
        """Search for devices at a broadcast or unicast destination."""
        _LOGGER.debug(
            "Searching for devices at %s",
            target_address,
        )

        async with self._endpoint_lock:
            if self._transport is None:
                await self._transport_closed.wait()
                await self._loop.create_datagram_endpoint(
                    lambda: self, local_addr=("0.0.0.0", 0), allow_broadcast=True
                )

        await self.send({"t": "scan"}, (str(target_address), 7000))

    async def search_devices(
        self,
        broadcastAddrs: list[IPv4Address] | None = None,
        *,
        target_addresses: list[IPv4Address] | None = None,
    ) -> None:
        """Search explicit destinations or automatic broadcast addresses.

        broadcastAddrs is a compatibility alias for target_addresses.
        Supplying both with non-None values raises ValueError.
        """
        if broadcastAddrs is not None:
            if target_addresses is not None:
                raise ValueError("Use either target_addresses or broadcastAddrs, not both")
            target_addresses = broadcastAddrs
        if not target_addresses:
            target_addresses = self._get_broadcast_addresses()
        await asyncio.gather(
            *[asyncio.create_task(self.search_on_interface(address)) for address in target_addresses], return_exceptions=True
        )