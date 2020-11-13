"""
Micropython device emulator, intended to run on 8266 mcus
"""

import json
import machine
import network
import socket
import time
import ubinascii

from ucryptolib import aes

device_id = ubinascii.hexlify(network.WLAN().config("mac")).decode()
device_name = device_id[-8:]

GENERIC_KEY = "a3K8Bx%2r8Y7#xDh"
DEVICE_KEY = device_id + device_id[:4]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 7000))

print("listening on for device events")


def send_device_data(addr, data, key):
    """Send a formatted request to the device."""
    print("\r\nS: ", json.dumps(data))

    if "pack" in data:

        def pad(s):
            bs = 16
            return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

        cipher = aes(key, 1)
        encrypted = cipher.encrypt(pad(json.dumps(data.get("pack")).encode()))
        data["pack"] = ubinascii.b2a_base64(encrypted).decode()

    data_bytes = json.dumps(data).encode()
    sock.sendto(data_bytes, addr)


def scan_response(addr):
    resp = {
        "t": "pack",
        "i": 1,
        "uid": 0,
        "cid": device_id,
        "tcid": "",
        "pack": {
            "t": "dev",
            "cid": device_id,
            "bc": "",
            "brand": "gree",
            "catalog": "gree",
            "mac": device_id,
            "mid": "10001",
            "model": "gree",
            "name": device_name,
            "series": "gree",
            "vender": "1",
            "ver": "V1.2.1",
            "lock": 0,
        },
    }
    send_device_data(addr, resp, GENERIC_KEY)


def bind_response(addr):
    resp = {
        "t": "pack",
        "i": 1,
        "uid": 0,
        "cid": device_id,
        "tcid": "",
        "pack": {
            "t": "bindok",
            "mac": device_id,
            "key": DEVICE_KEY,
            "r": 200,
        },
    }
    send_device_data(addr, resp, GENERIC_KEY)


while True:
    (d, addr) = sock.recvfrom(2048)
    p = json.loads(d.decode())

    print("\r\nR: ", d.decode())
    command = p.get("t")
    if command == "scan":
        scan_response(addr)
    elif command == "pack":
        # Decrypt the incoming request
        key = GENERIC_KEY if p.get("cid") == "app" else DEVICE_KEY
        cipher = aes(key, 1)
        decoded = ubinascii.a2b_base64(p.get("pack"))
        decrypted = cipher.decrypt(decoded).decode()
        fixed = decrypted.replace(decrypted[decrypted.rindex("}") + 1 :], "")
        print("D: ", fixed)
        data = json.loads(fixed)

        command = data.get("t")
        if command == "bind":
            bind_response(addr)

    time.sleep_ms(500)
