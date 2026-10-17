from __future__ import annotations

import asyncio
import logging
from asyncio import Task
from asyncio.events import AbstractEventLoop
from ipaddress import IPv4Address, IPv4Interface

from greeclimate.cipher import CipherV1, CipherV2
from greeclimate.device import Device
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.exceptions import DeviceNotBoundError, DeviceTimeoutError
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
        self._include_gateways: bool = False
        self._scan_lock = asyncio.Lock()
        self._querying_gateways = set()
        self._device_infos: list[DeviceInfo] = []
        self._listeners: list[Listener] = []

    # Task management
    @property
    def devices(self) -> list[DeviceInfo]:
        """Return the current known list of devices."""
        return self._device_infos

    # Listener management
    def add_listener(self, listener: Listener) -> list[Task] | None:
        """Add a listener that will receive discovery events.

        Adding a listener will cause all currently known device to trigger a
        new device added event on the listen object.

        Args:
            listener (Listener): A listener object which will receive events

        Returns:
            List[Coro]: List of tasks for device found events or None if lister was added early.
        """
        if listener not in self._listeners:
            self._listeners.append(listener)
            return [
                self._create_task(listener.device_found(x))
                for x in self.devices if self._include_gateways or x.sub_count == 0
            ]
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
        """Device is found.

        Notify all listeners that a device was found. Exceptions raised by
        listeners are ignored.

        Args:
            device_info (DeviceInfo): Information about the newly discovered
            device
        """

        include_gateway = self._include_gateways
        is_new = True
        address_changed = False
        for index, last_info in enumerate(self._device_infos):
            if device_info == last_info:
                is_new = False
                address_changed = device_info.ip != last_info.ip
                if address_changed:
                    self._device_infos[index] = device_info
                break
        else:
            self._device_infos.append(device_info)
            _LOGGER.info("Found gree device %s", str(device_info))

        if device_info.sub_count > 0:
            if device_info.mac in self._querying_gateways:
                return
            self._querying_gateways.add(device_info.mac)
            try:
                # Keep enumeration inside this tracked task so scan() waits for it.
                await self._query_gateway(device_info)
            finally:
                self._querying_gateways.discard(device_info.mac)
            if not include_gateway:
                return

        if is_new or address_changed:
            tasks = [
                l.device_found(device_info) if is_new else l.device_update(device_info)
                for l in self._listeners
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

    def decode_response_pack(self, obj):
        """Decrypt a scan reply, falling back to CipherV2 if CipherV1 fails.

        Some Gree Wi-Fi modules only speak the GCM-based protocol, even
        for the initial scan reply, so the generic CipherV1 fails to
        decrypt them. Device.bind() already has this same CipherV1 ->
        CipherV2 fallback; this brings Discovery in line with it. Returns
        None if the reply is undecryptable under either cipher, so
        packet_received's existing "unexpected response" handling takes
        care of it.
        """
        pack = obj["pack"]
        try:
            return self._cipher.decrypt(pack)
        except Exception:
            try:
                return CipherV2().decrypt(pack)
            except Exception:
                return None

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
            pack.get("mid"),
        )

        self._create_task(self.device_found(DeviceInfo(*device, sub_count=pack.get("subCnt", 0))))

    async def _query_gateway(self, gw_info: DeviceInfo) -> None:
        """Bind to a gateway device and discover its sub-devices."""
        gw = Device(gw_info, timeout=10, bind_timeout=15, loop=self._loop)
        try:
            await gw.bind()
            sub_infos = await gw.get_sub_devices()
            for sub_info in sub_infos:
                await self.device_found(sub_info)
        except (DeviceNotBoundError, DeviceTimeoutError):
            _LOGGER.warning(
                "Failed to query sub-devices from gateway %s", gw_info.mac
            )
        finally:
            try:
                gw.close()
            except (RuntimeError, AttributeError):
                pass

    # Discovery
    async def scan(
        self,
        wait_for: int = 0,
        bcast_ifaces: list[IPv4Address] | None = None,
        include_gateways: bool = False,
        *,
        target_addresses: list[IPv4Address] | None = None,
    ) -> list[DeviceInfo]:
        """Send discovery packets to broadcast or unicast destinations.
            Gateway sub-devices are automatically queried and returned as
            regular devices.

        Args:
            wait_for (int): Optionally wait this many seconds for discovery
                            and return the devices found.
            bcast_ifaces (list[IPv4Address]): Compatibility alias for target_addresses.
            target_addresses (list[IPv4Address]): Destination addresses to scan.
                None or an empty list uses automatic broadcast discovery.
            include_gateways (bool): If True, gateway devices are included in
                                     the results alongside their sub-devices.
                                     Default is False.
            Concurrent scans are serialized. The latest scan's gateway policy
            remains active for late responses, including when wait_for is zero.

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

        async with self._scan_lock:
            self._include_gateways = include_gateways
            await self.search_devices(target_addresses=target_addresses)
            if wait_for:
                await asyncio.sleep(wait_for)
                await asyncio.gather(*self.tasks, return_exceptions=True)

            if include_gateways:
                return list(self._device_infos)
            return [d for d in self._device_infos if d.sub_count == 0]

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

        if self._transport is None:
            self._transport, _ = await self._loop.create_datagram_endpoint(
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