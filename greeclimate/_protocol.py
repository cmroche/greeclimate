"""Pure packet parsing and request construction for the network layer.

This module owns no transports, sessions, ciphers, or callback lifecycles.
Request builders use the caller's envelope hook to preserve subclass overrides.
Inventory parsing preserves raw slots and metadata; the gateway matches the
transaction before validating page bounds or accepting children.
"""

from greeclimate.deviceinfo import DeviceInfo, _canonical_mac


class InvalidPacket(ValueError):
    """A decoded packet has an invalid protocol structure."""


def parse_properties(pack, kind: str) -> dict:
    """Normalize a DATA or RESULT property array without changing wire rules."""
    if not isinstance(pack, dict):
        raise InvalidPacket("Response pack is not a dictionary")
    if kind == "dat":
        columns, values = pack.get("cols"), pack.get("dat")
    elif kind == "res":
        columns = pack.get("opt")
        values = pack.get("val")
        if values is not None and not isinstance(values, list):
            raise InvalidPacket("RESULT val is not a list")
        values = values or pack.get("p", [])
    else:
        raise InvalidPacket(f"Unsupported property response kind: {kind!r}")

    if (
        not isinstance(columns, list)
        or not isinstance(values, list)
        or len(columns) != len(values)
        or any(
            not isinstance(name, str) or not name or name == "self"
            for name in columns
        )
    ):
        raise InvalidPacket("Invalid response property arrays")
    return dict(zip(columns, values))


def parse_discovery(pack, addr) -> DeviceInfo:
    """Use CID only when MAC is absent or empty; retain the wire identity spelling."""
    if not isinstance(pack, dict):
        raise InvalidPacket("Discovery response pack is not a dictionary")
    identity = pack.get("mac")
    if identity is None or identity == "":
        identity = pack.get("cid")
    if _canonical_mac(identity) is None:
        raise InvalidPacket("Discovery response has no usable identity")
    return DeviceInfo(
        addr[0],
        addr[1],
        identity,
        pack.get("name"),
        pack.get("brand"),
        pack.get("model"),
        pack.get("ver"),
        pack.get("mid"),
    )


def parse_inventory_page(pack) -> dict | None:
    """Return structurally valid 200 pages unchanged; ignore malformed replies."""
    if not isinstance(pack, dict):
        return None
    if (
        type(pack.get("r")) is not int
        or type(pack.get("c")) is not int
        or type(pack.get("i")) is not int
        or not isinstance(pack.get("list"), list)
        or pack["r"] != 200
    ):
        return None
    return pack


def validate_inventory_page_bounds(page) -> None:
    """Reject count or raw page-size limits on a matching inventory page."""
    if not 0 <= page["c"] <= 255 or len(page["list"]) > 5:
        raise InvalidPacket("Invalid gateway inventory count or page size")


def build_envelope(
    command, device_info: DeviceInfo, data, bind_or_scan: bool
) -> dict:
    """Build the common outer packet and optional inner request pack."""
    mac = _canonical_mac(device_info.mac)
    payload = {
        "cid": "app",
        "i": 1 if bind_or_scan else 0,
        "t": "pack" if data is not None else command.value,
        "uid": 0,
        "tcid": mac,
    }
    if data is not None:
        payload["pack"] = {"t": command.value, "mac": mac}
        payload["pack"].update(data)
    return payload


def build_bind_request(payload_builder, command, device_info: DeviceInfo) -> dict:
    return payload_builder(command, device_info, {"uid": 0})


def build_status_request(
    payload_builder, command, device_info: DeviceInfo, columns
) -> dict:
    return payload_builder(command, device_info, {"cols": list(columns)})


def build_command_request(
    payload_builder, command, device_info: DeviceInfo, properties
) -> dict:
    return payload_builder(
        command,
        device_info,
        {"opt": list(properties.keys()), "p": list(properties.values())},
    )


def build_inventory_request(
    payload_builder, command, device_info: DeviceInfo, offset: int, uid: int
) -> dict:
    payload = payload_builder(command, device_info, {"i": offset})
    payload["uid"] = uid
    return payload


def build_child_status_request(
    payload_builder,
    command,
    gateway_info: DeviceInfo,
    child_mac: str,
    columns,
) -> dict:
    return payload_builder(
        command,
        gateway_info,
        {"mac": _canonical_mac(child_mac), "cols": list(columns)},
    )


def build_child_command_request(
    payload_builder,
    command,
    gateway_info: DeviceInfo,
    child_mac: str,
    properties,
    dialect,
) -> dict:
    payload = payload_builder(
        command,
        gateway_info,
        {
            "sub": _canonical_mac(child_mac),
            "opt": list(properties.keys()),
            "p": list(properties.values()),
        },
    )
    if dialect == "commercial":
        payload["pack"].pop("mac")
    return payload
