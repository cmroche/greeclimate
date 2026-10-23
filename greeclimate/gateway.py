"""Explicit gateway inventory and raw, gateway-owned child devices.

Reported values are the Wi-Fi module's last DATA cache, not confirmation that a
physical mainboard accepted a command or measured a value.
"""

import asyncio
import re
from typing import Any, Union

from greeclimate.cipher import CipherV1, CipherV2
from greeclimate.device import Device, _property_name
from greeclimate.device_profile import match_device_profile
from greeclimate.deviceinfo import DeviceInfo, _canonical_mac
from greeclimate.exceptions import DeviceNotBoundError, DeviceTimeoutError
from greeclimate.network import Commands, IPAddr


_NO_HID = object()


def _fail_waiter(waiter, error) -> None:
    if waiter is not None and not waiter.done():
        waiter.set_exception(error)
        waiter.exception()


def _owned_task(owner, coroutine):
    """Track awaited work without logging exceptions its caller handles."""
    task = owner._loop.create_task(coroutine)
    owner._tasks.append(task)

    def finished(completed):
        if completed in owner._tasks:
            owner._tasks.remove(completed)
        if not completed.cancelled():
            completed.exception()

    task.add_done_callback(finished)
    return task


class GatewayDevice(Device):
    """A MID60 root owns its socket, session and explicitly requested inventory."""

    def __init__(self, device_info, timeout=120, bind_timeout=10, loop=None):
        super().__init__(device_info, timeout, bind_timeout, loop)
        self._children = {}
        self._context = 0
        self._reported_hid = _NO_HID
        self._dialect = None
        self._hid_waiter = None
        self._page_waiter = None
        self._page_context = None
        self._page_offset = None
        self._page_uid = None
        self._inventory_task = None
        self._inventory_serial = 0
        self._commercial_active = None
        self._response_envelope = None
        self._validated_root_data = False

    @property
    def children(self) -> tuple["GatewayChildDevice", ...]:
        """Retained handles, not a promise of a complete or fresh inventory."""
        return tuple(child for child in self._children.values() if not child._closed)

    def _invalidate_context(self, cancel_work=True) -> None:
        self._context += 1
        self._commercial_active = None
        for child in self.children:
            child._invalidate(cancel_work)
        _fail_waiter(self._hid_waiter, DeviceNotBoundError())
        _fail_waiter(self._page_waiter, DeviceNotBoundError())
        if cancel_work:
            task = self._inventory_task
            if task is not None and task is not asyncio.current_task(loop=self._loop) and not task.done():
                task.cancel()

    def handle_device_bound(self, key: str) -> None:
        waiter = self._bind_waiter
        if self._closed or waiter is None or waiter.done():
            return
        self._invalidate_context(cancel_work=False)
        self._reported_hid = _NO_HID
        self._dialect = None
        self._hid_waiter = self._loop.create_future()
        # Install the report waiter before Device schedules its initial poll.
        super().handle_device_bound(key)

    def close(self) -> None:
        if self._closed:
            return
        self._invalidate_context()
        self._reported_hid = _NO_HID
        self._dialect = None
        for child in self.children:
            child.close()
        super().close()

    def connection_lost(self, exc: Exception) -> None:
        self._invalidate_context()
        self._reported_hid = _NO_HID
        self._dialect = None
        super().connection_lost(exc)

    def _bound_envelope(self, obj) -> bool:
        root = _canonical_mac(self.device_info.mac)
        return (
            type(obj.get("i")) is int and obj["i"] == 0
            and _canonical_mac(obj.get("cid")) == root
            and obj.get("tcid") in (None, "", "app")
        )

    def _response_target(self, obj, pack):
        response = pack.get("t")
        response = response.casefold() if isinstance(response, str) else None
        if response == "bindok":
            return super()._response_target(obj, pack)
        if response in ("dat", "res", "sublist") and not self._bound_envelope(obj):
            return None, False
        root = _canonical_mac(self.device_info.mac)
        mac = _canonical_mac(pack.get("mac"))
        if mac is not None and mac != root:
            child = self._children.get(mac)
            if (
                response not in ("dat", "res") or child is None
                or not child._is_current_member()
                or ("cid" in pack and _canonical_mac(pack["cid"]) != root)
            ):
                return None, False
            return child, True
        target, identified = super()._response_target(obj, pack)
        if target is self and response == "dat":
            self._validated_root_data = identified
        return target, identified

    def packet_received(self, obj, addr: IPAddr) -> None:
        self._response_envelope = obj
        self._validated_root_data = False
        try:
            super().packet_received(obj, addr)
        finally:
            self._response_envelope = None
            self._validated_root_data = False

    def handle_data_update(self, **data) -> None:
        if self._validated_root_data and "hid" in data:
            hid = data["hid"]
            if self._reported_hid is not _NO_HID and hid != self._reported_hid:
                self._invalidate_context()
            self._reported_hid = hid
            profile = match_device_profile(hid)
            self._dialect = profile.gateway_dialect if profile is not None else None
            waiter = self._hid_waiter
            if waiter is not None and not waiter.done():
                waiter.set_result(hid)
        super().handle_state_update(**data)

    def handle_result_update(self, **data) -> None:
        """Command echoes never replace reported root DATA or qualify firmware."""

    async def _wait_for_report(self, waiter, request) -> None:
        if request:
            await self.request_version()
        await asyncio.wait((waiter,))
        waiter.result()

    async def _qualify(self, context) -> None:
        if self._reported_hid is _NO_HID:
            waiter = self._hid_waiter
            request = waiter is None or waiter.done()
            if request:
                waiter = self._loop.create_future()
                self._hid_waiter = waiter
            try:
                await asyncio.wait_for(self._wait_for_report(waiter, request), self._bind_timeout)
            except asyncio.TimeoutError as exc:
                raise DeviceTimeoutError from exc
            finally:
                if self._hid_waiter is waiter:
                    self._hid_waiter = None
                    if not waiter.done():
                        waiter.cancel()
        if context != self._context or not self.ready.is_set() or self._transport is None:
            raise DeviceNotBoundError
        if self._dialect is None:
            raise ValueError(f"Unsupported gateway HID: {self._reported_hid!r}")

    async def get_sub_devices(self) -> list["GatewayChildDevice"]:
        """Bind, qualify and enumerate, sharing one root-owned traversal."""
        if self._closed:
            raise DeviceNotBoundError
        task = self._inventory_task
        if task is None or task.done():
            task = _owned_task(self, self._enumerate())
            self._inventory_task = task
        try:
            await asyncio.wait((task,))
            return list(task.result())
        except asyncio.CancelledError:
            if self._closed or task.cancelled():
                raise DeviceNotBoundError from None
            raise

    async def _send_page(self, payload, waiter):
        await self.send(payload)
        return await waiter

    async def _enumerate(self):
        context = None
        try:
            await self.bind()
            if self._closed or not self.ready.is_set() or self._transport is None or self.device_cipher is None:
                raise DeviceNotBoundError
            context = self._context
            await self._qualify(context)
            offset, total = 0, None
            while True:
                if self._inventory_serial == 0x7fffffff:
                    raise ValueError("Gateway inventory transaction UID space exhausted")
                waiter = self._loop.create_future()
                self._page_waiter = waiter
                self._page_context = context
                self._page_offset = offset
                self._inventory_serial += 1
                self._page_uid = self._inventory_serial
                payload = self._generate_payload(Commands.SUBDEV, self.device_info, {"i": offset})
                payload["uid"] = self._page_uid
                try:
                    page = await asyncio.wait_for(self._send_page(payload, waiter), self._bind_timeout)
                except asyncio.TimeoutError as exc:
                    raise DeviceTimeoutError from exc
                finally:
                    if self._page_waiter is waiter:
                        self._page_waiter = None
                    if not waiter.done():
                        waiter.cancel()
                if context != self._context or not self.ready.is_set():
                    raise DeviceNotBoundError
                count, records = page["c"], page["list"]
                if total is not None and count != total:
                    raise ValueError("Gateway inventory count changed during pagination")
                total = count
                if offset + len(records) > count or (not records and offset < count):
                    raise ValueError("Gateway inventory page contradicts its declared total")
                if self._dialect == "commercial" and count > 1:
                    raise ValueError("Commercial gateway inventory exceeds its single-child contract")
                for record in records:
                    self._accept_child(record)
                offset += len(records)
                if offset >= total:
                    return self.children
        except asyncio.CancelledError:
            if self._closed or context != self._context or not self.ready.is_set():
                raise DeviceNotBoundError from None
            raise
        finally:
            if self._inventory_task is asyncio.current_task(loop=self._loop):
                self._inventory_task = None

    def handle_sublist(self, pack) -> None:
        waiter = self._page_waiter
        if waiter is None or waiter.done() or self._page_context != self._context:
            return
        envelope = self._response_envelope
        # Original wrappers echo the outer UID for every qualified dialect.
        if (
            not isinstance(envelope, dict) or type(envelope.get("uid")) is not int
            or envelope["uid"] != self._page_uid
        ):
            return
        if (
            type(pack.get("r")) is not int or type(pack.get("c")) is not int
            or type(pack.get("i")) is not int or not isinstance(pack.get("list"), list)
            or pack["r"] != 200 or pack["i"] != self._page_offset
        ):
            return
        if not 0 <= pack["c"] <= 255 or len(pack["list"]) > 5:
            _fail_waiter(waiter, ValueError("Invalid gateway inventory count or page size"))
            return
        waiter.set_result(pack)

    def _accept_child(self, record) -> None:
        if not isinstance(record, dict):
            return
        spelling = record.get("mac")
        mac = _canonical_mac(spelling)
        if mac is None or re.fullmatch(r"[0-9a-f]{14}", mac) is None or mac == _canonical_mac(self.device_info.mac):
            return
        mid = record.get("mid")
        mid = str(mid) if isinstance(mid, (str, int)) and not isinstance(mid, bool) else None
        child = self._children.get(mac)
        name = record.get("name")
        name = name if isinstance(name, str) and name else (child.device_info.mac if child else spelling)
        info = DeviceInfo(
            self.device_info.ip, self.device_info.port,
            child.device_info.mac if child else spelling, name,
            model=record.get("model"), mid=mid,
        )
        info.lock = record.get("lock")
        if child is None or child.device_info.mid != mid:
            replacement = GatewayChildDevice(self, info)
            self._children[mac] = replacement
            if child is not None:
                child.close()
            child = replacement
        else:
            child.device_info = info
        if self._dialect == "commercial":
            for old in self.children:
                if old is not child and old._routable:
                    old._routable = False
                    old._invalidate()
            self._commercial_active = mac
        child._routable = self._dialect != "commercial" or (
            mac == _canonical_mac(self.device_info.mac) + "00" and mid in ("6400", "6045", "609d")
        )
        child._observed_context = self._context
        if child._routable:
            child.ready.set()
        else:
            child.ready.clear()


class GatewayChildDevice(Device):
    """A logical raw device; only its owner holds a transport or credentials."""

    def __init__(self, gateway: GatewayDevice, device_info: DeviceInfo):
        self._gateway = gateway
        super().__init__(device_info, gateway._timeout, gateway._bind_timeout, gateway._loop)
        self._observed_context = None
        self._routable = False
        self._lifetime = 0

    @property
    def gateway(self) -> GatewayDevice:
        return self._gateway

    @property
    def device_cipher(self):
        return self.gateway.device_cipher

    @device_cipher.setter
    def device_cipher(self, value):
        raise ValueError("Gateway children cannot install an independent cipher")

    @property
    def device_key(self):
        return self.gateway.device_key

    @device_key.setter
    def device_key(self, value):
        raise ValueError("Gateway children cannot install an independent key")

    def _is_current_member(self) -> bool:
        return (
            not self._closed and not self.gateway._closed and self._routable
            and self._observed_context == self.gateway._context
            and self.gateway._dialect is not None and self.gateway.ready.is_set()
            and self.gateway._transport is not None and self.gateway.device_cipher is not None
            and self.gateway._children.get(_canonical_mac(self.device_info.mac)) is self
            and (self.gateway._dialect != "commercial"
                 or self.gateway._commercial_active == _canonical_mac(self.device_info.mac))
        )

    def _require_role(self) -> None:
        if not self._routable:
            raise ValueError(
                f"Gateway child {self.device_info.mac!r} MID {self.device_info.mid!r} "
                "is metadata-only; its routed status/control contract is not qualified"
            )

    def _invalidate(self, cancel_work=True) -> None:
        if cancel_work:
            self._lifetime += 1
        self._observed_context = None
        self.ready.clear()
        self._valid_state.clear()
        if cancel_work:
            self._cancel_tasks()

    def close(self) -> None:
        """Retire this handle, never its parent's endpoint or other children."""
        if self._closed:
            return
        self._closed = True
        self._closing = True
        self._handlers.clear()
        self._invalidate()
        mac = _canonical_mac(self.device_info.mac)
        if self.gateway._children.get(mac) is self:
            self.gateway._children.pop(mac)
        if self.gateway._commercial_active == mac:
            self.gateway._commercial_active = None

    async def _await_owned(self, coroutine):
        lifetime = self._lifetime
        try:
            return await _owned_task(self, coroutine)
        except asyncio.CancelledError:
            if self._closed or lifetime != self._lifetime or self.gateway._closed:
                raise DeviceNotBoundError from None
            raise

    async def bind(self, key: str = None, cipher: Union[CipherV1, CipherV2, None] = None):
        if self._closed or self.gateway._closed:
            raise DeviceNotBoundError
        if key is not None or cipher is not None:
            raise ValueError("Gateway children bind through their owner; keys and ciphers are not accepted")
        await self._ensure_bound()

    async def _ensure_bound(self) -> None:
        self._require_role()
        if self._is_current_member():
            return
        await self._await_owned(self.gateway.get_sub_devices())
        if not self._is_current_member():
            raise DeviceNotBoundError

    def create_status_message(self, device_info: DeviceInfo, *args):
        return self.gateway._generate_payload(
            Commands.STATUS, self.gateway.device_info,
            {"mac": _canonical_mac(self.device_info.mac), "cols": list(args)},
        )

    def create_command_message(self, device_info: DeviceInfo, **kwargs):
        payload = self.gateway._generate_payload(
            Commands.CMD, self.gateway.device_info,
            {"sub": _canonical_mac(self.device_info.mac), "opt": list(kwargs), "p": list(kwargs.values())},
        )
        if self.gateway._dialect == "commercial":
            payload["pack"].pop("mac")
        return payload

    async def send(self, obj, addr=None, cipher=None) -> None:
        if self._closed or self.gateway._closed:
            raise DeviceNotBoundError
        self._require_role()
        if not self._is_current_member():
            raise DeviceNotBoundError
        if addr is not None or cipher is not None:
            raise ValueError("Gateway child sends cannot override the owner address or cipher")
        pack = obj.get("pack") if isinstance(obj, dict) else None
        root, child = _canonical_mac(self.gateway.device_info.mac), _canonical_mac(self.device_info.mac)
        if (
            not isinstance(pack, dict) or obj.get("t") != Commands.PACK.value
            or obj.get("cid") != "app" or _canonical_mac(obj.get("tcid")) != root
            or type(obj.get("i")) is not int or obj["i"] != 0
            or pack.get("t") not in (Commands.STATUS.value, Commands.CMD.value)
            or ("cid" in pack and _canonical_mac(pack["cid"]) != root)
        ):
            raise ValueError("Gateway children can send only bound, owner-targeted status or command packets")
        if pack["t"] == Commands.STATUS.value:
            valid_route = _canonical_mac(pack.get("mac")) == child and "sub" not in pack
        else:
            valid_route = _canonical_mac(pack.get("sub")) == child and (
                "mac" not in pack if self.gateway._dialect == "commercial"
                else _canonical_mac(pack.get("mac")) == root
            )
        if not valid_route:
            raise ValueError("Gateway child packet has a conflicting routed identity")
        lifetime = self._lifetime
        context = self._observed_context
        await self._await_owned(self.gateway.send(obj))
        if lifetime != self._lifetime or context != self.gateway._context or not self._is_current_member():
            raise DeviceNotBoundError

    def handle_data_update(self, **data) -> None:
        super().handle_state_update(**data)

    def handle_result_update(self, **data) -> None:
        """RESULT callbacks receive echoes without changing last reported DATA."""

    def set_property(self, name, value: Any) -> None:
        if self._closed or self.gateway._closed:
            raise DeviceNotBoundError
        self._require_role()
        name = _property_name(name)
        if name in self._dirty:
            if self._dirty[name] == value:
                return
        elif self._properties.get(name) == value:
            return
        self._dirty[name] = value

    async def push_state_update(self):
        if self._closed or self.gateway._closed:
            raise DeviceNotBoundError
        self._require_role()
        await super().push_state_update()
