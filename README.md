![Python package](https://github.com/cmroche/greeclimate/workflows/Python%20package/badge.svg)

## Gree Climate

Discover, connect and control Gree based mini-split systems.

**greeclimate** is a ***fully async*** Python3 based package for controlling Gree based ACs and heat pumps. Gree is a common brand for mini-split systems and is licensed and resold under many product names. This module should work for any device that also works with the Gree+ app, but has been tested on

- Proklima mini-splits units
- Trane mini-split heat pump (4TXK38)

_If you have tested and know of others systems that work, please fork and submit a PR with the make and model_

**Based on the following work**

- [Gree Remote by tomikaa87](https://github.com/tomikaa87/gree-remote)

## Getting the package

The easiest way to grab **greeclimate** is through PyPI
`pip3 install greeclimate`

## Use Gree Climate

Simple example showing how to discover and bind to devices on the LAN

```python
import asyncio

from greeclimate.device_factory import create_device
from greeclimate.discovery import Discovery


async def main():
    discovery = Discovery()
    try:
        for device_info in await discovery.scan(wait_for=5):
            device = create_device(device_info)
            try:
                await device.bind()
                print(device_info.name, device_info.ip)
            finally:
                device.close()
    finally:
        discovery.close()


asyncio.run(main())
```

Scan a known IP address instead of broadcasting on the LAN.

```python
from ipaddress import IPv4Address

devices = await discovery.scan(
    wait_for=5, target_addresses=[IPv4Address("192.0.2.10")]
)
```

Discover a device listening on UDP port 7000, including loopback addresses.

```python
discovery = Discovery(allow_loopback=True)
devices = await discovery.scan(wait_for=5)
```

Manually poll for updated device state.

```python
await device.update_state()
```

Request exact status columns and access raw protocol properties by name.

```python
await device.update_state(["Pow", "Lig"])
# Read the cache after a DATA reply arrives.
print(device.get_property("Pow"))
device.set_property("Lig", 0)
await device.push_state_update()
```

Iterate through children from a Gateway device

```python
from greeclimate.gateway import GatewayDevice
from greeclimate.network import Response

gateway = create_device(device_info)
if not isinstance(gateway, GatewayDevice):
    raise TypeError("Select a MID 60 gateway")
try:
    await gateway.bind()
    for child in await gateway.get_sub_devices():
        if not child.ready.is_set():  # Metadata-only commercial records.
            continue
        data_received = asyncio.Event()

        def on_child_data(data):
            if {"Pow", "Mod", "SetTem"} <= data.keys():
                data_received.set()

        child.add_handler(Response.DATA, on_child_data)
        try:
            await child.update_state(["Pow", "Mod", "SetTem"])
            await asyncio.wait_for(data_received.wait(), timeout=5)
            print(child.device_info.name, dict(child.raw_properties))
            child.set_property("Mod", 2)
            child.set_property("SetTem", 22)
            child.set_property("Pow", 1)
            await child.push_state_update()
            data_received.clear()
            await child.update_state(["Pow", "Mod", "SetTem"])
            await asyncio.wait_for(data_received.wait(), timeout=5)
            print(child.get_property("Pow"), child.get_property("SetTem"))
        finally:
            child.remove_handler(Response.DATA, on_child_data)
finally:
    gateway.close()  # Also closes every owned child.
```

For an AC, cool to 25°C and send updates to the device.

```python
from greeclimate.device import Mode, TemperatureUnits

device.power = True
device.mode = Mode.Cool
device.temperature_units = TemperatureUnits.C
device.target_temperature = 25
await device.push_state_update()
```

Set a Fahrenheit target by selecting units before setting the temperature.

```python
from greeclimate.device import TemperatureUnits

device.temperature_units = TemperatureUnits.F
device.target_temperature = 77
await device.push_state_update()
```

Set fan speed and swing positions.

```python
from greeclimate.device import FanSpeed, HorizontalSwing, VerticalSwing

device.fan_speed = FanSpeed.Auto
device.horizontal_swing = HorizontalSwing.FullSwing
device.vertical_swing = VerticalSwing.FullSwing
await device.push_state_update()
```

Enable optional features where supported by the device.

```python
device.light = True
device.xfan = True
device.quiet = True
await device.push_state_update()
```

Use capability evidence to offer an optional AC control without treating unknown as unsupported.

```python
if device.capabilities["quiet"] is True:
    device.quiet = True
    await device.push_state_update()
```

Turn the device off, then request a fresh status update.

```python
device.power = False
await device.push_state_update()
await device.update_state()
```

## Use Gree Emulator

List supported simulated profiles and their exact MID values.

```bash
python -m gree_emulator --list-profiles
```

Run one simulated AC on loopback, with stable identity across restarts.

```bash
python -m gree_emulator --profile sim-w04n-v17 --mid 10001 --seed demo --listen 127.0.0.1
```

Run three independently controlled simulated ACs on the same endpoint.

```bash
python -m gree_emulator --profile sim-w04n-v17 --mid 10001 --count 3 --seed demo --listen 127.0.0.1
```

Run the supplied mixed-device configuration, including gateways and child devices.

```bash
python -m gree_emulator --config examples/emulator-devices.json
```

Run the simulated air-to-water heat pump (the `9301` and `9302` profiles remain raw-client families).

```bash
python -m gree_emulator --profile sim-w06a-p3-v6.04-9300 --mid 9300 --seed demo --listen 127.0.0.1
```

Expose the simulated ACs to LAN discovery on UDP port 7000, on a trusted test network only.

```bash
python -m gree_emulator --profile sim-w04n-v17 --mid 10001 --count 3 --seed demo --listen 0.0.0.0 --port 7000
```

Capture packet logs on stderr while keeping startup announcements on stdout; scrub identities, addresses, and bind exchanges before sharing.

```bash
python -m gree_emulator --profile sim-w04n-v17 --mid 10001 --seed demo --listen 127.0.0.1 2> emulator-packets.log
```

## Device and protocol reference

- [Known MIDs](docs/MIDS.md): current polling contracts and gateway observations.
- [Known HIDs](docs/HIDS.md): firmware-string segments, matching rules, and sourced firmware codes.
- [Cloud-only firmware findings](docs/CLOUD_ONLY_FIRMWARE.md): inspected LAN/cloud boundaries, not upgrade recommendations.

## Debugging

Maybe the reason you're here is that you're working with Home Assistant and your device isn't being detected.

There are a few tools to help investigate the various compatibility problems that Gree based devices present.

Below is a series of tests, please run them and use their output in issue reports. Additionally using [Wireshark](https://www.wireshark.org) or tcpdump to capture the network traffic can greatly assist in investigations.

### Setup

This presumes you have python installed

```bash
pip install -r requirements.txt
```

### Getting some basic information about your network
#### Linux / OSX
```bash
sudo route -n
sudo ifconfig
```
#### Windows command line
```
route print -4
ipconfig
```

### Running the discovery tests

First test is to check the response of devices when trying to discovery them, writes the results to **discovery_results.txt**. Use [Wireshark](https://www.wireshark.org) here if you can.

```bash
python gree.py --discovery > discovery_results.txt
```
