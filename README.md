![Python package](https://github.com/cmroche/greeclimate/workflows/Python%20package/badge.svg)

## Gree Climate

Discover, connect and control Gree based mini-split systems.

**greenclimat** is a Python3 based package for controll Gree mini-split ACs and heat pumps. Gree is a common brand for minisplit systems and is licensed and resold under many product names. This module may (or may not) work for any of those system, but has been tested on

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
try:
    if not self._device_key:
        devices = await Discovery.search_devices()
        if self._mac:
            deviceinfo = next((d for d in devices if d.mac == self._mac), None)
        else:
            deviceinfo = next((d for d in devices if d.ip == self._ip), None)
    else:
        deviceinfo = DeviceInfo(self._ip, self._port, self._mac, self._name)
    device = Device(deviceinfo)
    await device.bind(key=self._device_key)
except Exception:
    raise CannotConnect
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

# Send the state update to the HVAC
await device.push_state_update()
```
