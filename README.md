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

### Publishing releases

Maintainers can prepare a release from `master` with:

```bash
gh workflow run python-package.yml --repo cmroche/greeclimate --ref master
```

Nightly preparation remains enabled. After the test matrix passes, semantic-release updates the version and changelog and creates a GitHub release, without uploading to PyPI. A new release explicitly dispatches `pypi.yml` at its release tag: tags created with `GITHUB_TOKEN` do not trigger other push workflows. Ordinary branch pushes and pull requests do not publish.

The PyPI workflow also accepts `v*` tag pushes, but only publishes stable `vX.Y.Z` tags. It checks that the tag's commit is on `master`, matches the workflow event's commit, and has the same version in `setup.cfg`. It tests that exact source on Python 3.14, builds and checks the wheel and sdist, and transfers only those artifacts to a separate publishing job. The publishing job uses PyPI Trusted Publishing (OIDC) and uploads PEP 740 attestations through the pinned official PyPA action; it has no package checkout or static PyPI credentials.

Before enabling the first OIDC publication:

1. In [PyPI's publishing settings](https://pypi.org/manage/project/greeclimate/settings/publishing/), register a GitHub Trusted Publisher with owner `cmroche`, repository `greeclimate`, workflow filename `pypi.yml`, and environment `pypi`. The filename is not the workflow's display name or full path.
2. Configure the GitHub `pypi` environment to allow only tags matching `v*`, and protect those tags against updates and deletion. Both restrictions are configured for `cmroche/greeclimate`; repositories using this workflow elsewhere need their own setup. Required deployment reviewers can be added for manual approval.
3. Merge these workflow changes before creating a release: the publishing workflow must exist at the release tag. After the first successful OIDC upload, remove the obsolete `PYPI_TOKEN` and `PYPI_USERNAME` GitHub secrets (and `PYPI_USER` if present), and revoke the old API token in PyPI. Do not remove them while the old publishing workflow is still active.

To retry an interrupted publication, dispatch the existing release tag, not `master`:

```bash
gh workflow run pypi.yml --repo cmroche/greeclimate --ref vX.Y.Z
```

Already uploaded files are not silently skipped or overwritten. If an upload partially succeeded, inspect PyPI before retrying. Attestations apply to newly uploaded files; existing releases are not retroactively attested. See [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/using-a-publisher/) and [attestation documentation](https://docs.pypi.org/attestations/producing-attestations/).

## Use Gree Climate

Discover devices on the LAN and bind immediately after scanning.

```python
import asyncio

from greeclimate.device import Device
from greeclimate.discovery import Discovery


async def main():
    discovery = Discovery()
    try:
        for device_info in await discovery.scan(wait_for=5):
            device = Device(device_info)
            try:
                await device.bind()
                print(device_info.name, device_info.ip)
            finally:
                device.close()
    finally:
        discovery.close()


asyncio.run(main())
```

The following snippets run inside `main()`; device-control snippets go after binding and before closing `device`.

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

Cool to 25°C and send updates to the device.

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
device.target_humidity = 45
await device.push_state_update()
```

Turn the device off, then request a fresh status update.

```python
device.power = False
await device.push_state_update()
await device.update_state()
```

Automatic discovery uses IPv4 subnet broadcasts via `ifaddr`, skipping IPv6, loopback, and non-loopback `/31` and `/32` networks. `allow_loopback=True` adds loopback host addresses; non-empty `target_addresses` bypasses interface enumeration, while `None` or `[]` uses it.

Legacy `bcast_ifaces` (`scan`) and `broadcastAddrs` (`search_devices`) keywords and positional calls remain supported; combining an alias with non-`None` `target_addresses` raises `ValueError`.

## Use Gree Emulator

Run these commands from the repository root with Python 3.10+ and dependencies installed; each server runs until Ctrl-C.

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

Expose the simulated ACs to LAN discovery on UDP port 7000, on a trusted test network only.

```bash
python -m gree_emulator --profile sim-w04n-v17 --mid 10001 --count 3 --seed demo --listen 0.0.0.0 --port 7000
```

Capture packet logs on stderr while keeping startup announcements on stdout; scrub identities, addresses, and bind exchanges before sharing.

```bash
python -m gree_emulator --profile sim-w04n-v17 --mid 10001 --seed demo --listen 127.0.0.1 2> emulator-packets.log
```

These are simulated appliances, not complete firmware emulations. The library's `push_state_update()` currently adds an unsupported `BuzzerCtrl` field, so simulator commands can be rejected even when sending succeeds. See the [emulator guide](docs/EMULATOR.md) for configuration, protocol differences, and consumer-compatibility limits.

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
