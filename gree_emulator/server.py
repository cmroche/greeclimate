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
        while True:
            await asyncio.sleep(1)
            now = time.monotonic()
            for device in self.devices:
                device.advance(now)

    def _ticker_done(self, task):
        # wait_closed surfaces programming errors instead of leaving a stale simulator.
        self.close()

    def datagram_received(self, data, addr):
        _LOGGER.info("RX from %s:%s (%d bytes)", *addr, len(data))
        try:
            outer = decode_outer(data)
            if outer["t"] == "scan":
                _LOGGER.info("RX payload: %r", outer)
                if outer.get("tcid"):
                    return
                replies = [reply for device in self.roots
                           if device.profile.max_request_bytes is None
                           or len(data) <= device.profile.max_request_bytes
                           for reply in device.profile.handler.advertise(device, outer)]
            else:
                device = self.targets.get(outer.get("tcid"))
                if device is None or (
                    device.profile.max_request_bytes is not None
                    and len(data) > device.profile.max_request_bytes
                ):
                    return
                replies = device.profile.handler.handle(device, outer)
        except InvalidPacket:
            return
        for reply in replies:
            data = encode_reply(reply)
            self.transport.sendto(data, addr)
            _LOGGER.info("TX to %s:%s (%d bytes): %r", *addr, len(data),
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
