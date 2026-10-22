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

Discover devices on the LAN and bind immediately after scanning.

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

Creating a device type directly (not using the `create_device()` factory).

```python
device = AirConditionerDevice(device_info)
try:
    await device.bind()
    device.target_temperature = 25
    await device.push_state_update()
finally:
    device.close()
```

Probe a known IP address instead of full LAN discovery.

```python
from ipaddress import IPv4Address

devices = await discovery.scan(
    wait_for=5, target_addresses=[IPv4Address("192.0.2.10")]
)
```

Manually poll for updated device state.

```python
await device.update_state()

# Or request an exact bounded set of raw columns.
await device.update_state(["Pow", "hid"])
```

Check a device's capabilities.

```python
if device.capabilities["quiet"] is True:
    device.quiet = True
    await device.push_state_update()
```

Cool to 25°C and send change to the device.

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

Set a dehumidifier's target relative humidity.

```python
from greeclimate.dehumidifier import DehumidifierDevice

# Alternatively, use the direct construction example below when the family is known.
if not isinstance(device, DehumidifierDevice):
    raise TypeError("This example requires a dehumidifier")
device.target_humidity = 45
await device.push_state_update()
```

## Use Gree Device Emulator

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

Expose the simulated ACs to LAN discovery on UDP port 7000, on a trusted test network only.

```bash
python -m gree_emulator --profile sim-w04n-v17 --mid 10001 --count 3 --seed demo --listen 0.0.0.0 --port 7000
```

## Device and protocol reference

- [Known MIDs](docs/MIDS.md): public polling, family-selection and capability contracts.
- [Known HIDs](https://github.com/cmroche/gree-research/blob/main/docs/HIDS.md) (private): firmware-string segments, sourced firmware codes, and unresolved reports.

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
