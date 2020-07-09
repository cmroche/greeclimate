import asyncio
import base64
import json
import logging
import socket
import enum

from Crypto.Cipher import AES
from ipaddress import IPv4Network

GENERIC_KEY = "a3K8Bx%2r8Y7#xDh"

_LOGGER = logging.getLogger(__name__)


class Props(enum.Enum):
    POWER = "Pow"
    MODE = "Mod"
    TEMP_SET = "SetTem"
    TEMP_UNIT = "TemUn"
    TEMP_BIT = "TemRec"
    FAN_SPEED = "WdSpd"
    FRESH_AIR = "Air"
    XFAN = "Blo"
    ANION = "Health"
    SLEEP = "SwhSlp"
    LIGHT = "Lig"
    SWING_HORIZ = "SwingLfRig"
    SWING_VERT = "SwUpDn"
    QUIET = "Quiet"
    TURBO = "Tur"
    STEADY_HEAT = "StHt"
    POWER_SAVE = "SvSt"
    UNKNOWN_HEATCOOLTYPE = "HeatCoolType"


def _get_broadcast_addresses():
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
    logger = logging.getLogger(__name__)
    logger.debug("Listening for devices on %s", bcast)

    s = create_socket(timeout)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    payload = {"t": "scan"}
    s.sendto(json.dumps(payload).encode(), (bcast, 7000))

    devices = []
    while True:
        try:
            (d, addr) = s.recvfrom(2048)
            if (len(d)) == 0:
                continue

            response = json.loads(d)
            pack = decrypt_payload(response["pack"])
            logger.debug("Received response from device search\n%s", pack)
            devices.append((addr[0], addr[1], pack["cid"], pack["name"]))
        except socket.timeout:
            """ Intentionally unprocessed exception """
            break
        except json.JSONDecodeError:
            logger.debug("Unable to decode device search response payload")
        except Exception as e:
            logging.error("Unable to search devices due to an exception %s", str(e))

    s.close()
    return devices


async def search_devices(timeout=2, broadcastAddrs=None):
    if not broadcastAddrs:
        broadcastAddrs = _get_broadcast_addresses()

    broadcastAddrs = list(broadcastAddrs)
    done, pending = await asyncio.wait(
        [_search_on_interface(b, timeout=timeout) for b in broadcastAddrs]
    )

    devices = []
    for task in done:
        results = task.result()
        for result in results:
            devices.append(result)

    return devices


async def bind_device(device_info):
    payload = {
        "cid": "app",
        "i": "1",
        "t": "pack",
        "uid": 0,
        "tcid": device_info.mac,
        "pack": {"mac": device_info.mac, "t": "bind", "uid": 0},
    }

    s = create_socket()
    try:
        send_data(s, device_info.ip, device_info.port, payload)
        r = receive_data(s)
    except Exception as e:
        raise e
    finally:
        s.close()

    if r["pack"]["t"] == "bindok":
        return r["pack"]["key"]


def send_state(property_values, device_info, key=GENERIC_KEY):
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

    s = create_socket()
    try:
        send_data(s, device_info.ip, device_info.port, payload, key=key)
        r = receive_data(s, key=key)
    except Exception as e:
        raise e
    finally:
        s.close()

    cols = r["pack"]["opt"]
    dat = r["pack"]["val"]
    return dict(zip(cols, dat))


def request_state(properties, device_info, key=GENERIC_KEY):
    payload = {
        "cid": "app",
        "i": 0,
        "t": "pack",
        "uid": 0,
        "tcid": device_info.mac,
        "pack": {"mac": device_info.mac, "t": "status", "cols": list(properties)},
    }

    s = create_socket()
    try:
        send_data(s, device_info.ip, device_info.port, payload, key=key)
        r = receive_data(s, key=key)
    except Exception as e:
        raise e
    finally:
        s.close()

    cols = r["pack"]["cols"]
    dat = r["pack"]["dat"]
    return dict(zip(cols, dat))


def decrypt_payload(payload, key=GENERIC_KEY):
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    decoded = base64.b64decode(payload)
    decrypted = cipher.decrypt(decoded).decode()
    t = decrypted.replace(decrypted[decrypted.rindex("}") + 1 :], "")
    return json.loads(t)


def encrypt_payload(payload, key=GENERIC_KEY):
    def pad(s):
        bs = 16
        return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

    cipher = AES.new(key.encode(), AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(json.dumps(payload)).encode())
    encoded = base64.b64encode(encrypted).decode()
    return encoded


def create_socket(timeout=60):
    s = socket.socket(type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    s.settimeout(timeout)
    return s


def send_data(socket, ip, port, payload, key=GENERIC_KEY):
    _LOGGER.debug("Sending packet:\n%s", json.dumps(payload))
    payload["pack"] = encrypt_payload(payload["pack"], key)
    d = json.dumps(payload).encode()
    socket.sendto(d, (ip, int(port)))


def receive_data(socket, key=GENERIC_KEY):
    d = socket.recv(2048)
    payload = json.loads(d)
    payload["pack"] = decrypt_payload(payload["pack"], key)
    _LOGGER.debug("Recived packet:\n%s", json.dumps(payload))
    return payload
