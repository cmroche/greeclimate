"""Independent literal W05SA cache, projection and metadata regressions."""
import base64
import asyncio
import json
from pathlib import Path

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from gree_emulator.__main__ import load_config
from gree_emulator.wire import InvalidPacket
from gree_emulator.server import start_server
from greeclimate.device import Device
from greeclimate.device_factory import create_device
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.network import Response


def topology(prefix="020000000001"):
    return load_config({"devices": [
        {"id": "root", "profile": "sim-w05sa-v1.28", "mid": "50", "mac": prefix},
        {"id": "master", "profile": "sim-w05sa-v1.28-master", "mid": "5000",
         "parent": "root", "mac": prefix + "00"},
        {"id": "one", "profile": "sim-w05sa-v1.28-zone", "mid": "5001",
         "parent": "root", "mac": prefix + "01"},
        {"id": "eight", "profile": "sim-w05sa-v1.28-zone", "mid": "5001",
         "parent": "root", "mac": prefix + "08"},
    ]})[2]


def request(root, operation, target=None, **fields):
    inner = {"t": operation, "mac": root.mac, **fields}
    if operation == "status":
        inner["mac"] = target or root.mac
    elif operation == "cmd":
        inner["sub"] = target or root.mac
    encrypted = AES.new(root.key, AES.MODE_ECB).encrypt(pad(json.dumps(inner).encode(), 16))
    outer = {"t": "pack", "tcid": root.mac, "cid": "app", "uid": 7,
             "i": 0, "pack": base64.b64encode(encrypted).decode()}
    return root.profile.handler.handle(root, outer)[0].inner


def test_entire_numeric_namespace_roundtrips_without_ac_union():
    fixture = json.loads((Path(__file__).parent / "fixtures/emulator/zones-complete_research.json").read_text())
    root, master, one, eight = topology()
    names = fixture["numeric_names"]
    assert len(names) == 88
    for start in range(0, len(names), 12):
        columns = names[start:start + 12]
        assert request(root, "cmd", opt=columns, p=[511] * len(columns))["p"] == [511] * len(columns)
        assert request(root, "status", cols=columns)["dat"] == [511] * len(columns)
    for device in (master, one, eight):
        assert request(root, "status", device.mac, cols=["Pow", "StTem", "Demand"])["dat"] == [511, 511, 511]
    assert request(root, "status", cols=["TemSen", "SetTem", "NoD", "NoD"])["dat"] == [511, 511]


def test_local_alias_projection_shared_state_and_root_isolation():
    root, master, one, eight = topology()
    other = topology("020000000002")[0]
    request(root, "cmd", one.mac, opt=["Pow", "StTem", "Demand"], p=[1, 24, -1])
    assert request(root, "status", cols=["EnWdVlv1", "StTem1", "Demand"])["dat"] == [1, 24, 65535]
    assert request(root, "status", eight.mac, cols=["Pow", "StTem", "Demand"])["dat"] == [0, 8, 65535]
    assert request(other, "status", cols=["EnWdVlv1", "Demand"])["dat"] == [0, 0]
    assert "Demand" not in one.state and "Demand" not in master.state
    request(root, "cmd", master.mac, opt=["Pow"], p=[1])
    assert request(root, "status", cols=["MasterPow", "Pow"])["dat"] == [1, 0]


def test_ack_precedes_energy_clamp_and_preserves_duplicate_sequence():
    root, _, one, eight = topology()
    reply = request(root, "cmd", opt=["Mod", "EnSvSt", "CoolSvStTemMin", "StTem1", "StTem1"],
                    p=[1, 1, 5, 24, 4])
    assert reply["p"] == [1, 1, 5, 24, 4]
    assert request(root, "status", cols=["StTem1", "StTem8", "StTem2"])["dat"] == [5, 8, 8]
    request(root, "cmd", opt=["Mod", "HeatSvStTemMax", "StTem8"], p=[2, 10, 65535])
    assert request(root, "status", eight.mac, cols=["StTem"])["dat"] == [10]


def test_metadata_precedence_and_native_ragged_footer_arrays():
    root, _, one, _ = topology()
    request(root, "cmd", one.mac, opt=["name", "host", "lat", "time", "apssid", "appsw"],
            p=["Shared", "example.test", "-42.1", "2026-10-24 12:34:56", "network", "secret"])
    reply = request(root, "status", cols=["name", "host", "lat", "time", "hid", "mid", "model", "apssid", "appsw"])
    assert reply["cols"] == ["name", "host", "lat", "time", "hid", "mid", "model", "apssid", "appsw"]
    assert reply["dat"] == ["Shared", "example.test", "-42.1", "2026-10-24 12:34:56",
                            "362001062617+U-W05SAV1.28.bin", "50"]
    assert request(root, "status", one.mac, cols=["name", "mid", "mac"])["dat"] == ["Shared", "50", root.mac]
    assert "secret" not in json.dumps(reply)


@pytest.mark.parametrize("bad", [True, None, 1.5, {}, []])
def test_invalid_batches_are_atomic(bad):
    root = topology()[0]
    with pytest.raises(InvalidPacket):
        request(root, "cmd", opt=["MasterPow", "Demand"], p=[1, bad])
    assert request(root, "status", cols=["MasterPow", "Demand"])["dat"] == [0, 0]


def test_native_status_exact_capacity_and_safe_oversize_policy():
    root = topology()[0]
    assert request(root, "status", cols=["Pow"] * 30)["dat"] == []
    assert request(root, "status", cols=["Pow"] * 29)["dat"] == [0] * 29
    with pytest.raises(InvalidPacket):
        request(root, "status", cols=["Pow"] * 31)
    assert request(root, "status", cols=["Pow"])["dat"] == [0]
    assert request(root, "status", cols=["Pow", "", "Demand"])["cols"] == ["Pow"]


async def test_public_raw_consumer_reads_full_cache_and_metadata_after_bind():
    devices = topology()
    root = devices[0]
    transport, server = await start_server(devices, "127.0.0.1", 0)
    host, port = transport.get_extra_info("sockname")
    unit = create_device(DeviceInfo(host, port, root.mac, "Zones", mid="50"), bind_timeout=1)
    assert type(unit) is Device
    data, results = asyncio.Queue(), asyncio.Queue()
    unit.add_handler(Response.DATA, data.put_nowait)
    unit.add_handler(Response.RESULT, results.put_nowait)
    try:
        await unit.bind()
        while unit.hid is None:
            await asyncio.wait_for(data.get(), 2)
        assert unit.hid == "362001062617+U-W05SAV1.28.bin"
        unit.set_property("Demand", -1)
        await unit.push_state_update()
        assert (await asyncio.wait_for(results.get(), 2))["Demand"] == 65535
        await unit.update_state(["Demand", "ErVavle", "NoD"])
        while unit.raw_properties.get("Demand") != 65535 or "NoD" not in unit.raw_properties:
            await asyncio.wait_for(data.get(), 2)
        assert unit.raw_properties["ErVavle"] == 0
        assert unit.raw_properties["NoD"] == 0
    finally:
        unit.close()
        await asyncio.wait_for(unit._transport_closed.wait(), 2)
        await asyncio.gather(*unit.tasks, return_exceptions=True)
        server.close()
        await server.wait_closed()


def test_cloud_control_ack_then_effective_master_power_uses_source_branch():
    root, master, one, _ = topology()
    reply = request(root, "cmd", opt=["MasterPow", "EnWdVlv1", "Tcloud"], p=[0, 1, 1])
    assert reply["p"] == [0, 1, 1]
    assert request(root, "status", cols=["MasterPow", "Tcloud"])["dat"] == [1, 0]
    assert request(root, "status", master.mac, cols=["Pow"])["dat"] == [1]
    request(root, "cmd", opt=["EnWdVlv1", "Tcloud"], p=[0, 1])
    assert request(root, "status", cols=["MasterPow", "Tcloud"])["dat"] == [0, 0]
    request(root, "cmd", opt=["MasterPow", "Mod", "EnWdVlv1"], p=[2, 1, 1])
    assert one.profile.handler.thermal_target(one)[0] == "idle"


def test_root_numbered_cache_configuration_projects_into_zone_without_global_copies():
    records = [
        {"id": "root", "profile": "sim-w05sa-v1.28", "mid": "50", "mac": "020000000001",
         "state": {"StTem1": 0, "EnWdVlv1": 1, "Demand": 37}},
        {"id": "master", "profile": "sim-w05sa-v1.28-master", "mid": "5000",
         "parent": "root", "mac": "02000000000100"},
        {"id": "one", "profile": "sim-w05sa-v1.28-zone", "mid": "5001",
         "parent": "root", "mac": "02000000000101"},
    ]
    root, _, one = load_config({"devices": records})[2]
    assert request(root, "status", one.mac, cols=["StTem", "Pow", "Demand"])["dat"] == [0, 1, 37]
    request(root, "cmd", one.mac, opt=["StTem"], p=[24])
    assert root.state["StTem1"] == 24
    assert "Demand" not in one.state
    records[2]["state"] = {"StTem": 7}
    with pytest.raises(ValueError, match="conflicting zone cache aliases"):
        load_config({"devices": records})
