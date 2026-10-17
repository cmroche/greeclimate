"""Simulated AC appliances with firmware-derived LAN packet framing."""

import argparse
import asyncio
import copy
import hashlib
import ipaddress
import json
import logging
import math
import re
import secrets
import sys

from .device import EmulatedDevice
from .profiles import PROFILES
from .server import start_server
from .wire import InvalidPacket


_CONFIG_KEYS = {"listen", "port", "seed", "devices"}
_DEVICE_KEYS = {
    "id", "profile", "mid", "name", "mac", "parent", "room_c", "ambient_c", "state"
}
_IDENTITY_KEYS = {
    "id", "profile", "mid", "name", "mac", "parent", "hid", "key", "keys", "tcid", "cid", "sub"
}


def _unknown_keys(value: dict, allowed: set[str], location: str) -> None:
    for key in value:
        if key not in allowed:
            raise ValueError(f"{location}: unknown key {key!r}")


def _text(value: object, location: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value):
        raise ValueError(f"{location}: expected {'a' if empty else 'a nonempty'} string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{location}: expected valid UTF-8 text") from exc
    return value


def _temperature(value: object, location: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{location}: expected a finite temperature")
    try:
        result = float(value)
    except OverflowError as exc:
        raise ValueError(f"{location}: expected a finite temperature") from exc
    if not math.isfinite(result):
        raise ValueError(f"{location}: expected a finite temperature")
    return result


def _digest(kind: str, seed: str, logical_id: str) -> bytes:
    encoded = json.dumps(
        [f"gree-emulator-{kind}", seed, logical_id],
        ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).digest()


def load_config(config: dict, *, seed: str | None = None) -> tuple[str, int, list[EmulatedDevice]]:
    """Validate a complete configuration and return all devices in declaration order."""
    if not isinstance(config, dict):
        raise ValueError("config: expected an object")
    _unknown_keys(config, _CONFIG_KEYS, "config")
    listen = config.get("listen", "0.0.0.0")
    if not isinstance(listen, str):
        raise ValueError("listen: expected an IPv4 address")
    try:
        listen = str(ipaddress.IPv4Address(listen))
    except ipaddress.AddressValueError as exc:
        raise ValueError("listen: expected an IPv4 address") from exc
    port = config.get("port", 7000)
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("port: expected an integer from 0 to 65535")
    if "seed" in config:
        _text(config["seed"], "seed", empty=True)
    if seed is not None:
        _text(seed, "seed", empty=True)
    else:
        seed = config.get("seed")
    if seed is None:
        seed = secrets.token_hex(32)
    records = config.get("devices")
    if not isinstance(records, list) or not records:
        raise ValueError("devices: expected a nonempty array")

    devices = {}
    parents = {}
    identities = set()
    for index, record in enumerate(records):
        location = f"devices[{index}]"
        if not isinstance(record, dict):
            raise ValueError(f"{location}: expected an object")
        logical_id = _text(record.get("id"), f"{location}.id")
        location = f"device {logical_id!r}"
        _unknown_keys(record, _DEVICE_KEYS, location)
        if logical_id in devices:
            raise ValueError(f"{location}: duplicate id")
        profile_id = _text(record.get("profile"), f"{location}.profile")
        profile = PROFILES.get(profile_id)
        if profile is None:
            raise ValueError(f"{location}.profile: unavailable or unknown profile {profile_id!r}")
        mid = _text(record.get("mid"), f"{location}.mid")
        if mid not in profile.mids:
            raise ValueError(f"{location}.mid: {mid!r} is not supported by {profile_id!r}")
        name = _text(record.get("name", logical_id), f"{location}.name")
        parent = None
        if "parent" in record:
            parent = _text(record["parent"], f"{location}.parent")
        parents[logical_id] = parent
        if "mac" in record:
            mac = record["mac"]
            if not isinstance(mac, str) or re.fullmatch(
                rf"[0-9a-fA-F]{{{profile.identity_bytes * 2}}}", mac
            ) is None:
                raise ValueError(
                    f"{location}.mac: expected exactly {profile.identity_bytes * 2} hexadecimal characters"
                )
            mac = mac.lower()
        else:
            identity = bytearray(_digest("mac", seed, logical_id)[:profile.identity_bytes])
            identity[0] = (identity[0] & 0xfc) | 0x02
            mac = identity.hex()
        if mac in identities:
            raise ValueError(f"{location}.mac: duplicate canonical wire identity {mac!r}")
        identities.add(mac)
        overrides = record.get("state", {})
        if not isinstance(overrides, dict):
            raise ValueError(f"{location}.state: expected an object")
        for field in overrides:
            if not isinstance(field, str) or field.startswith("_"):
                raise ValueError(f"{location}.state: private or invalid field {field!r}")
            if field in _IDENTITY_KEYS:
                raise ValueError(f"{location}.state: identity field {field!r} cannot be overridden")
            if field not in profile.initial_state:
                raise ValueError(f"{location}.state: unsupported field {field!r}")
        state = copy.deepcopy(dict(profile.initial_state))
        state.update(copy.deepcopy(overrides))
        try:
            profile.handler.validate_state(state)
        except ValueError as exc:
            raise ValueError(f"{location}.state: {exc}") from exc
        device = EmulatedDevice(
            id=logical_id, mac=mac, name=name, mid=mid,
            key=_digest("key", seed, logical_id).hex()[:16].encode("ascii"),
            profile=profile, state=state,
        )
        if profile.handler.thermal_target(device) is None:
            for field in ("room_c", "ambient_c"):
                if field in record:
                    raise ValueError(f"{location}.{field}: not allowed on a gateway/container")
            device.room_c = device.ambient_c = None
        else:
            device.room_c = _temperature(record.get("room_c", 26), f"{location}.room_c")
            device.ambient_c = _temperature(record.get("ambient_c", 26), f"{location}.ambient_c")
        profile.handler.encode_room(device)
        devices[logical_id] = device

    for logical_id, parent in parents.items():
        if parent is not None and parent not in devices:
            raise ValueError(f"device {logical_id!r}.parent: nonexistent device {parent!r}")
    checked = set()
    roots = {}
    for logical_id in devices:
        path = set()
        current = logical_id
        while current is not None and current not in checked:
            if current in path:
                raise ValueError(f"device {logical_id!r}.parent: cycle involving {current!r}")
            path.add(current)
            current = parents[current]
        checked.update(path)
    for logical_id, device in devices.items():
        parent = parents[logical_id]
        if parent is None:
            if device.profile.parent_profiles:
                raise ValueError(f"device {logical_id!r}.parent: required for child profile")
        elif devices[parent].profile.id not in device.profile.parent_profiles:
            raise ValueError(
                f"device {logical_id!r}.parent: unsupported parent profile {devices[parent].profile.id!r}"
            )
        current = logical_id
        chain = []
        while current not in roots and parents[current] is not None:
            chain.append(current)
            current = parents[current]
        root = roots.get(current, current)
        roots[current] = root
        for child in chain:
            roots[child] = root
        device.key = devices[root].key
    for logical_id, device in devices.items():
        parent = parents[logical_id]
        if parent is not None:
            devices[parent].children.append(device)
    for device in devices.values():
        if len(device.children) > device.profile.max_children:
            raise ValueError(
                f"device {device.id!r}: profile allows at most {device.profile.max_children} children"
            )
        if parents[device.id] is None:
            validate_topology = getattr(device.profile.handler, "validate_topology", None)
            if validate_topology is not None:
                validate_topology(device)
            try:
                device.profile.handler.advertise(device, {"t": "scan"})
            except InvalidPacket as exc:
                raise ValueError(f"device {device.id!r}.name: cannot advertise configured metadata: {exc}") from exc
    return listen, port, list(devices.values())


def _json_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"JSON: duplicate key {key!r}")
        result[key] = value
    return result


def _json_number(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("JSON: numbers must be finite")
    return number


def _json_constant(value: str) -> None:
    raise ValueError("JSON: numbers must be finite")


def _device_output(device: EmulatedDevice, parent: str | None = None) -> None:
    print(json.dumps({
        "id": device.id, "name": device.name, "profile": device.profile.id,
        "mid": device.mid, "mac": device.mac, "parent": parent,
    }, ensure_ascii=True), flush=True)


async def _serve(devices: list[EmulatedDevice], listen: str, port: int) -> int:
    try:
        transport, protocol = await start_server(devices, listen, port)
    except OSError as exc:
        print(f"gree_emulator: socket startup failed: {exc}", file=sys.stderr, flush=True)
        return 1
    try:
        endpoint = transport.get_extra_info("sockname")
        print(f"Listening on {endpoint[0]}:{endpoint[1]}", flush=True)
        parents = {child.id: device.id for device in devices for child in device.children}
        for device in devices:
            _device_output(device, parents.get(device.id))
        await protocol.wait_closed()
    finally:
        protocol.close()
        await protocol.wait_closed()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--list-profiles", action="store_true", help="list available models without opening a socket")
    parser.add_argument("--config", help="JSON configuration path")
    parser.add_argument("--profile", help="explicit simulated appliance profile ID")
    parser.add_argument("--mid", help="exact appliance MID")
    parser.add_argument("--count", type=int, help="number of quick-start devices (default: 1)")
    parser.add_argument("--listen", help="IPv4 listen address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, help="UDP listen port (default: 7000; 0 chooses a free port)")
    parser.add_argument("--seed", help="stable synthetic identity seed; never printed or saved")
    args = parser.parse_args(argv)
    quick_start = any(value is not None for value in (args.profile, args.mid, args.count))
    if args.list_profiles:
        if args.config is not None or quick_start or any(
            value is not None for value in (args.listen, args.port, args.seed)
        ):
            parser.error("--list-profiles cannot be combined with configuration or startup options")
        for profile in PROFILES.values():
            for mid in profile.mids:
                if profile.parent_profiles:
                    role = "child"
                elif profile.max_children:
                    role = "gateway/container"
                else:
                    role = "standalone"
                print(json.dumps({
                    "profile": profile.id, "mid": mid, "role": role, "hid": profile.hid,
                    "parents": list(profile.parent_profiles),
                }), flush=True)
        return 0
    if args.config is not None and quick_start:
        parser.error("--config cannot be combined with --profile, --mid, or --count")
    if args.config is None and (args.profile is None or args.mid is None):
        parser.error("provide --config, --list-profiles, or both --profile and --mid")
    if args.count is not None and args.count <= 0:
        parser.error("--count must be positive")
    try:
        if args.config is not None:
            with open(args.config, encoding="utf-8") as source:
                config = json.load(
                    source, object_pairs_hook=_json_object,
                    parse_float=_json_number, parse_constant=_json_constant,
                )
            if not isinstance(config, dict):
                raise ValueError("config: expected an object")
        else:
            config = {"devices": [
                {"id": f"device-{index}", "profile": args.profile, "mid": args.mid}
                for index in range(1, (args.count if args.count is not None else 1) + 1)
            ]}
        for field in ("listen", "port", "seed"):
            value = getattr(args, field)
            if value is not None:
                config[field] = value
        listen, port, devices = load_config(config)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        parser.error(str(exc))
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    try:
        return asyncio.run(_serve(devices, listen, port))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
