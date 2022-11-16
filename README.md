![Python package](https://github.com/cmroche/greeclimate/workflows/Python%20package/badge.svg)

## Gree Climate

Discover, connect and control Gree based mini-split systems.

**greenclimat** is a ***fully async*** Python3 based package for controlling Gree based ACs and heat pumps. Gree is a common brand for mini-split systems and is licensed and resold under many product names. This module should work for any device that also works with the Gree+ app, but has been tested on

- Proklima mini-splits units
- Trane mini-split heat pump (4TXK38)

_If you have tested and know of others systems that work, please fork and submit a PR with the make and model_

**Based on the following work**

- [Gree Remote by tomikaa87](https://github.com/tomikaa87/gree-remote)

## Getting the package

The easiest way to grab **greeclimate** is through PyPI
`pip3 install greeclimate`

## Use Gree Climate

### Finding and binding to devices

Scan the network for devices, select a device and immediately bind. See the notes below for caveats.

```python
discovery = Discovery()
for device_info in await discovery.scan(wait_for=5):
    try:
        device = Device(device_info)
        await device.bind() # Device will auto bind on update if you omit this step
    except CannotConnect:
        _LOGGER.error("Unable to bind to gree device: %s", device_info)
        continue

    _LOGGER.debug(
        "Adding Gree device at %s:%i (%s)",
        device.device_info.ip,
        device.device_info.port,
        device.device_info.name,
    )
```

#### Caveats

Devices have and use 2 encryption keys. 1 for discovery and setup which is the same on all gree devices, and a second which is negotiated during the binding process.

Binding is incredibly finnicky, if you do not have the device key you must first scan and re-bind. The device will only respond to binding requests immediately proceeding a scan.

### Update device state

It's possible for devices to be updated from external sources, to update the `Device` internal state with the physical device call `Device.update_state()`

### Properties

There are several properties representing the state of the HVAC. Setting these properties will command the HVAC to change state.

Not all properties are supported on each device, in the event a property isn't supported commands to the HVAC will simply be ignored.

When setting a value it is cached but not pushed to the device until `Device.push_state_update()` is called.

```python
device = Device(...)
device.power = True
device.mode = Mode.Auto
device.target_temperature = 25
device.temperature_units = TemperatureUnits.C
device.fan_speed = FanSpeed.Auto
device.fresh_air = True
device.xfan = True
device.anion = True
device.sleep = True
device.light = True
device.horizontal_swing = HorizontalSwing.FullSwing
device.vertical_swing = VerticalSwing.FullSwing
device.quiet = True
device.turbo = True
device.steady_heat = True
device.power_save = True
device.target_humidity = 45

# Send the state update to the HVAC
await device.push_state_update()
```

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