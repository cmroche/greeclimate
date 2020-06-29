import asyncio
import base64
import json
import logging
import socket

from Crypto.Cipher import AES
from functools import reduce
from ipaddress import IPv4Network

from greeclimate.device_info import DeviceInfo

GENERIC_KEY = "a3K8Bx%2r8Y7#xDh"


def _get_broadcast_addresses():
    import ipaddress
    import netifaces

    broadcastAddrs = []

    interfaces = netifaces.interfaces()
    for iface in interfaces:
        addr = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addr:
            netmask = addr[netifaces.AF_INET][0]["netmask"]
            ipaddr = addr[netifaces.AF_INET][0]["addr"]
            net = IPv4Network(f"{ipaddr}/{netmask}", strict=False)
            if net.broadcast_address and not net.is_loopback:
                broadcastAddrs.append(str(net.broadcast_address))

    return broadcastAddrs


async def _search_on_interface(bcast, timeout):
    logger = logging.getLogger("gree_climate")
    logger.debug("Listening for devices on %s", bcast)

    s = socket.socket(type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    s.settimeout(timeout)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    payload = {'t': 'scan'}
    s.sendto(json.dumps(payload).encode(), (bcast, 7000))

    devices = []
    while True:
        try:
            (d, addr) = s.recvfrom(2048)
            if (len(d)) == 0:
                continue

            logger.debug("Received response from device search\n%s", d)
            response = json.loads(d)
            pack = decrypt_payload(response['pack'])
            devices.append(DeviceInfo(
                addr[0], addr[1], pack['cid'], pack['name']))
        except socket.timeout:
            """ Intentionally unprocessed exception """
            break
        except json.JSONDecodeError:
            logger.debug("Unable to decode device search response payload")
        except Exception as e:
            logging.error(
                "Unable to search devices due to an exception %s", str(e))

    s.close()
    return devices


async def search_devices(timeout=10, broadcastAddrs=None):
    logger = logging.getLogger("gree_climate")
    logger.info("Starting Gree device discovery process")

    if not broadcastAddrs:
        broadcastAddrs = _get_broadcast_addresses()

    broadcastAddrs = list(broadcastAddrs)
    done, pending = await asyncio.wait(
        [_search_on_interface(b, timeout=timeout) for b in broadcastAddrs])

    devices = []
    for task in done:
        results = task.result()
        for result in results:
            devices.append(result)

    return devices


def decrypt_payload(payload, key=GENERIC_KEY):
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    decoded = base64.b64decode(payload)
    decrypted = cipher.decrypt(decoded).decode()
    t = decrypted.replace(decrypted[decrypted.rindex('}')+1:], '')
    return json.loads(t)


def encrypt_payload(payload, key=GENERIC_KEY):
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    encrypted = cipher.encrypt(json.dumps(payload)).encode()
    encoded = base64.encode(encrypted).decode()
    return encoded
