"""One UDP endpoint and thermal ticker for independently controlled devices."""

import asyncio
import logging
import socket
import time
from contextlib import suppress

from .wire import InvalidPacket, decode_outer, encode_reply


_LOGGER = logging.getLogger(__name__)


class EmulatorServer(asyncio.DatagramProtocol):
    def __init__(self, devices):
        self.devices = devices
        child_ids = {child.id for device in devices for child in device.children}
        self.roots = [device for device in devices if device.id not in child_ids]
        self.targets = {device.mac: device for device in self.roots}
        self.raw_routes = {}
        self.outer_routes = {}
        for device in self.roots:
            handler = device.profile.handler
            decoder = getattr(handler, "decode_outer", None)
            self.outer_routes.setdefault(decoder, []).append(device)
            magic = getattr(handler, "datagram_magic", None)
            if isinstance(magic, bytes) and magic and callable(
                getattr(handler, "handle_datagram_from", None)
            ):
                self.raw_routes.setdefault(magic, []).append(device)
        self.plaintext_types = frozenset(
            kind for device in self.roots
            for kind in getattr(device.profile.handler, "plaintext_types", ())
        )
        self.transport = None
        self.ticker = None
        self.closed = asyncio.get_running_loop().create_future()

    def connection_made(self, transport):
        self.transport = transport
        now = time.monotonic()
        for device in self.devices:
            device.last_step = now
        self.ticker = asyncio.create_task(self._tick())
        self.ticker.add_done_callback(self._ticker_done)

    async def _tick(self):
        intervals = [getattr(device.profile.handler, "tick_interval", 1)
                     for device in self.devices]
        now = time.monotonic()
        next_ticks = [now + interval for interval in intervals]
        interval = min(intervals, default=1)
        while True:
            await asyncio.sleep(interval)
            now = time.monotonic()
            for index, device in enumerate(self.devices):
                if now < next_ticks[index]:
                    continue
                next_ticks[index] = now + intervals[index]
                device.advance(now)
                tick = getattr(device.profile.handler, "tick", None)
                if tick is not None:
                    for reply, addr in tick(device, now):
                        self._send(reply, addr)

    def _ticker_done(self, task):
        # wait_closed surfaces programming errors instead of leaving a stale simulator.
        self.close()

    def datagram_received(self, data, addr):
        _LOGGER.info("RX from %s:%s (%d bytes)", *addr, len(data))
        raw_devices = self.raw_routes.get(data[:4])
        if raw_devices is not None:
            replies = []
            for device in raw_devices:
                if getattr(device.profile.handler, "source_port", addr[1]) != addr[1]:
                    continue
                if (device.profile.max_request_bytes is not None
                        and len(data) > device.profile.max_request_bytes):
                    continue
                try:
                    replies.extend(device.profile.handler.handle_datagram_from(device, data, addr))
                except InvalidPacket:
                    continue
            for reply in replies:
                self._send(reply, addr)
            return
        for decoder, roots in self.outer_routes.items():
            self._receive_json(data, addr, roots, decoder)

    def _receive_json(self, data, addr, roots, decoder):
        try:
            outer = (decode_outer(data, plaintext_types=self.plaintext_types)
                     if decoder is None else decoder(data))
            if outer["t"] == "scan":
                _LOGGER.info("RX payload: %r", outer)
                if outer.get("tcid"):
                    return
                replies = []
                for device in roots:
                    if (device.profile.max_request_bytes is not None
                            and len(data) > device.profile.max_request_bytes):
                        continue
                    family = device.profile.handler
                    if getattr(family, "source_port", addr[1]) != addr[1]:
                        continue
                    try:
                        replies.extend(family.advertise(device, outer))
                    except InvalidPacket:
                        continue
            elif outer["t"] in ("mate", "wlan") or outer["t"] in self.plaintext_types:
                replies = []
                for device in roots:
                    family = device.profile.handler
                    if getattr(family, "source_port", addr[1]) != addr[1]:
                        continue
                    admitted = outer["t"] in getattr(family, "plaintext_types", ())
                    raw_dispatch = (getattr(family, "handle_plaintext_from", None)
                                    if admitted or outer["t"] == "wlan" else None)
                    dispatch = (getattr(family, outer["t"], None)
                                if admitted or outer["t"] in ("mate", "wlan") else None)
                    if dispatch is None and admitted:
                        dispatch = family.handle
                    if (dispatch is None and raw_dispatch is None) or (
                        device.profile.max_request_bytes is not None
                        and len(data) > device.profile.max_request_bytes
                    ):
                        continue
                    try:
                        if raw_dispatch is not None:
                            replies.extend(raw_dispatch(device, outer, data, addr))
                        else:
                            replies.extend(dispatch(device, outer))
                    except InvalidPacket:
                        continue
            else:
                target = outer.get("tcid")
                device = self.targets.get(target)
                candidates = [root for root in roots
                              if root is device
                              or getattr(root.profile.handler, "accept_any_target", False)
                              or (target == "" and getattr(root.profile.handler, "accept_empty_target", False))]
                replies = []
                for device in candidates:
                    if device.profile.max_request_bytes is not None and len(data) > device.profile.max_request_bytes:
                        continue
                    family = device.profile.handler
                    if getattr(family, "source_port", addr[1]) != addr[1]:
                        continue
                    handle_from = getattr(family, "handle_from", None)
                    try:
                        replies.extend(family.handle(device, outer) if handle_from is None
                                       else handle_from(device, outer, addr))
                    except InvalidPacket:
                        continue
        except InvalidPacket:
            return
        for reply in replies:
            self._send(reply, addr)

    def _send(self, reply, addr):
        data = encode_reply(reply)
        target = addr
        if reply.destination_host is not None or reply.destination_port is not None:
            target = (
                addr[0] if reply.destination_host is None else reply.destination_host,
                addr[1] if reply.destination_port is None else reply.destination_port,
                *addr[2:],
            )
        self.transport.sendto(data, target)
        _LOGGER.info("TX to %s:%s (%d bytes): %r", target[0], target[1], len(data),
                     reply.inner if reply.inner is not None else reply.outer)

    def error_received(self, exc):
        asyncio.get_running_loop().call_exception_handler(
            {"message": "Emulator UDP transport error", "exception": exc, "protocol": self}
        )

    def connection_lost(self, exc):
        if self.ticker is not None:
            self.ticker.cancel()
        if not self.closed.done():
            if exc is None:
                self.closed.set_result(None)
            else:
                self.closed.set_exception(exc)

    def close(self):
        if self.ticker is not None:
            self.ticker.cancel()
        if self.transport is not None:
            self.transport.close()
        elif not self.closed.done():
            self.closed.set_result(None)

    async def wait_closed(self):
        await asyncio.shield(self.closed)
        if self.ticker is not None:
            with suppress(asyncio.CancelledError):
                await self.ticker


async def start_server(devices, listen, port):
    protocol = EmulatorServer(devices)
    try:
        return await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: protocol, local_addr=(listen, port), family=socket.AF_INET,
            allow_broadcast=True,
        )
    except BaseException:
        protocol.close()
        await protocol.wait_closed()
        raise
