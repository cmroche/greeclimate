import asyncio
import base64
import json
import logging
import socket
import time
from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import List, Text, Tuple, Union

from Crypto.Cipher import AES

GENERIC_KEY = "a3K8Bx%2r8Y7#xDh"

_LOGGER = logging.getLogger(__name__)


IPAddr = Tuple[str, int]


@dataclass
class IPInterface:
    ip_address: str
    bcast_address: str


class DeviceProtocol(asyncio.DatagramProtocol):
    def __init__(
        self, recvq: asyncio.Queue, excq: asyncio.Queue, drained: asyncio.Queue
    ) -> None:
        self._loop = asyncio.get_event_loop()

        self._recvq = recvq
        self._excq = excq
        self._drained = drained

        self._drained.set()

        # Transports are connected at the time a connection is made.
        self._transport = None

    def connection_made(self, transport: asyncio.transports.DatagramTransport) -> None:

        self._transport = transport

    def datagram_received(self, data: Union[bytes, Text], addr: IPAddr) -> None:
        self._recvq.put_nowait((data, addr))

    def connection_lost(self, exc) -> None:
        if exc is not None:
            self._excq.put_nowait(exc)

        if self._transport is not None:
            self._transport.close()
            self._transport = None

    def error_received(self, exc) -> None:
        self._excq.put_nowait(exc)

    def pause_writing(self) -> None:
        self._drained.clear()
        super().pause_writing()

    def resume_writing(self) -> None:
        self._drained.set()
        super().resume_writing()


class BroadcastListenerProtocol(DeviceProtocol):
    def connection_made(self, transport: asyncio.transports.DatagramTransport) -> None:

        super().connection_made(transport)

        sock = transport.get_extra_info("socket")  # type: socket.socket
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)


# Concepts and code here were taken from https://github.com/jsbronder/asyncio-dgram
class DatagramStream:
    def __init__(self, transport, recvq, excq, drained, timeout: int = 120):
        self._transport = transport
        self._recvq = recvq
        self._excq = excq
        self._drained = drained
        self._timeout = timeout

    def __del__(self):
        self.close()

    @property
    def exception(self):
        try:
            exc = self._excq.get_nowait()
            raise exc
        except asyncio.queues.QueueEmpty:
            pass

    @property
    def socket(self):
        return self._transport.get_extra_info("socket")

    def close(self):
        try:
            self._transport.close()
        except RuntimeError:
            pass

    async def send(self, data, addr=None) -> None:
        _ = self.exception
        self._transport.sendto(data, addr)

        task = asyncio.create_task(self._drained.wait())
        await asyncio.wait_for(task, self._timeout)

    async def send_device_data(self, data, key=GENERIC_KEY) -> None:
        """Send a formatted request to the device."""
        _LOGGER.debug("Sending packet:\n%s", json.dumps(data))

        if "pack" in data:
            data["pack"] = DatagramStream.encrypt_payload(data["pack"], key)

        data_bytes = json.dumps(data).encode()
        await self.send(data_bytes)

    def recv_ready(self):
        _ = self.exception
        return not self._recvq.empty()

    async def recv(self):
        _ = self.exception

        task = asyncio.create_task(self._recvq.get())
        await asyncio.wait_for(task, self._timeout)
        return task.result()

    async def recv_device_data(self, key=GENERIC_KEY):
        """Receive a formatted request from the device."""
        (data_bytes, addr) = await self.recv()
        if len(data_bytes) == 0:
            return

        data = json.loads(data_bytes)

        if "pack" in data:
            data["pack"] = DatagramStream.decrypt_payload(data["pack"], key)

        _LOGGER.debug("Received packet:\n%s", json.dumps(data))
        return (data, addr)

    @staticmethod
    def decrypt_payload(payload, key=GENERIC_KEY):
        cipher = AES.new(key.encode(), AES.MODE_ECB)
        decoded = base64.b64decode(payload)
        decrypted = cipher.decrypt(decoded).decode()
        t = decrypted.replace(decrypted[decrypted.rindex("}") + 1 :], "")
        return json.loads(t)

    @staticmethod
    def encrypt_payload(payload, key=GENERIC_KEY):
        def pad(s):
            bs = 16
            return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

        cipher = AES.new(key.encode(), AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(json.dumps(payload)).encode())
        encoded = base64.b64encode(encrypted).decode()
        return encoded


def get_broadcast_addresses() -> List[IPInterface]:
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
                if net.broadcast_address and not net.is_loopback:
                    broadcastAddrs.append(
                        IPInterface(str(ipaddr), str(net.broadcast_address))
                    )

    return broadcastAddrs


async def search_on_interface(bcast_iface: IPInterface, timeout: int):
    logger = logging.getLogger(__name__)
    logger.debug("Listening for devices on %s", bcast_iface.ip_address)

    loop = asyncio.get_event_loop()
    recvq = asyncio.Queue()
    excq = asyncio.Queue()
    drained = asyncio.Event()

    bcast = ("255.255.255.255", 7000)
    local_addr = (bcast_iface.ip_address, 0)

    transport, _ = await loop.create_datagram_endpoint(
        lambda: BroadcastListenerProtocol(recvq, excq, drained),
        local_addr=local_addr,
    )
    stream = DatagramStream(transport, recvq, excq, drained, timeout)

    data = json.dumps({"t": "scan"}).encode()
    await stream.send(data, bcast)

    devices = []
    start_ts = time.time()
    while start_ts + timeout > time.time() or stream.recv_ready():
        try:
            (response, addr) = await stream.recv_device_data()
            pack = response["pack"]
            logger.debug("Received response from device search\n%s", pack)
            devices.append(
                (
                    addr[0],
                    addr[1],
                    pack.get("mac") or pack.get("cid"),
                    pack.get("name"),
                    pack.get("brand"),
                    pack.get("model"),
                    pack.get("ver"),
                )
            )
        except asyncio.TimeoutError:
            break
        except json.JSONDecodeError:
            logger.debug("Unable to decode device search response payload")
        except Exception as e:
            logging.error("Unable to search devices due to an exception %s", str(e))
            break

    stream.close()
    return devices


async def search_devices(timeout: int = 2, broadcastAddrs: str = None):
    if not broadcastAddrs:
        broadcastAddrs = get_broadcast_addresses()

    broadcastAddrs = list(broadcastAddrs)
    done, _ = await asyncio.wait(
        [search_on_interface(b, timeout=timeout) for b in broadcastAddrs]
    )

    devices = []
    for task in done:
        results = task.result()
        for result in results:
            devices.append(result)

    return devices


async def create_datagram_stream(target: IPAddr) -> DatagramStream:
    loop = asyncio.get_event_loop()
    recvq = asyncio.Queue()
    excq = asyncio.Queue()
    drained = asyncio.Event()

    transport, _ = await loop.create_datagram_endpoint(
        lambda: DeviceProtocol(recvq, excq, drained), remote_addr=target
    )
    return DatagramStream(transport, recvq, excq, drained, timeout=10)


async def bind_device(device_info):
    payload = {
        "cid": "app",
        "i": "1",
        "t": "pack",
        "uid": 0,
        "tcid": device_info.mac,
        "pack": {"mac": device_info.mac, "t": "bind", "uid": 0},
    }

    remote_addr = (device_info.ip, device_info.port)
    stream = await create_datagram_stream(remote_addr)
    try:
        # Binding uses the generic key only
        await stream.send_device_data(payload)
        (r, _) = await stream.recv_device_data()
    except asyncio.TimeoutError as e:
        _LOGGER.debug("Timeout trying to bind device")
        raise e
    except Exception as e:
        _LOGGER.debug("Encountered an error trying to bind device")
        _LOGGER.debug(str(e))
        raise e
    finally:
        stream.close()

    if r["pack"]["t"] == "bindok":
        return r["pack"]["key"]


async def send_state(property_values, device_info, key=GENERIC_KEY):
    payload = {
        "cid": "app",
        "i": 0,
        "t": "pack",
        "uid": 0,
        "tcid": device_info.mac,
        "pack": {
            "opt": list(property_values.keys()),
            "p": list(property_values.values()),
            "t": "cmd",
        },
    }

    remote_addr = (device_info.ip, device_info.port)
    stream = await create_datagram_stream(remote_addr)
    try:
        await stream.send_device_data(payload, key)
        (r, _) = await stream.recv_device_data(key)
    except asyncio.TimeoutError as e:
        raise e
    except Exception as e:
        _LOGGER.debug("Encountered an error sending state to device")
        _LOGGER.debug(str(e))
        raise e
    finally:
        stream.close()

    cols = r["pack"]["opt"]
    dat = r["pack"]["val"]
    return dict(zip(cols, dat))


async def request_state(properties, device_info, key=GENERIC_KEY):
    payload = {
        "cid": "app",
        "i": 0,
        "t": "pack",
        "uid": 0,
        "tcid": device_info.mac,
        "pack": {"mac": device_info.mac, "t": "status", "cols": list(properties)},
    }

    remote_addr = (device_info.ip, device_info.port)
    stream = await create_datagram_stream(remote_addr)
    try:
        await stream.send_device_data(payload, key)
        (r, _) = await stream.recv_device_data(key)
    except asyncio.TimeoutError as e:
        raise e
    except Exception as e:
        _LOGGER.debug("Encountered an error requesting update from device")
        _LOGGER.debug(str(e))
        raise e
    finally:
        stream.close()

    cols = r["pack"]["cols"]
    dat = r["pack"]["dat"]
    return dict(zip(cols, dat))
