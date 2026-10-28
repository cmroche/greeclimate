from unittest.mock import AsyncMock

import pytest

from greeclimate.cipher import CipherV1
from greeclimate.device import Device
from greeclimate.device_factory import create_device
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.gateway import GatewayDevice

from greeclimate.mid_profile import (
    FALLBACK_MID_PROFILE,
    KNOWN_MID_PROFILES,
    MidProfile,
    match_mid_profile,
)
from greeclimate.network import DeviceProtocol2


@pytest.mark.parametrize("mid", ["0001", "10f01"])
def test_exact_mid_matches_registry_object(mid):
    expected = next(profile for profile in KNOWN_MID_PROFILES if profile.mid == mid)
    assert match_mid_profile(mid) is expected


@pytest.mark.parametrize("mid", [
    1, "1", "10F01", " 0001", "unrecorded", None, "", [], {},
    "AC0001", "080241", "80261 ", "8090300",
])
def test_unknown_or_malformed_mid_uses_fallback(mid):
    assert match_mid_profile(mid) is FALLBACK_MID_PROFILE


@pytest.mark.parametrize("name,columns", [
    ("target_temperature", ("SetTem", "TemRec", "TemUn")),
    ("sleep", ("SwhSlp", "SlpMod")),
])
def test_composite_evidence_requires_every_exact_case_column(name, columns):
    for omitted in columns:
        incomplete = tuple(column for column in columns if column != omitted)
        assert name not in MidProfile("composite", incomplete, "air_conditioner").capabilities
    for renamed in columns:
        wrong_case = tuple(column.lower() if column == renamed else column for column in columns)
        assert name not in MidProfile("composite", wrong_case, "air_conditioner").capabilities
    assert MidProfile("composite", columns, "air_conditioner").capabilities[name] is True


def test_omitted_and_similarly_named_fields_do_not_declare_negative_or_alias_evidence():
    profile = MidProfile("partial", ("Pow", "SetTem", "TemUn", "HumSen", "Lamp", "Quier"),
                         "air_conditioner")
    assert profile.capabilities == {"power": True, "temperature_units": True}
    assert "target_temperature" not in profile.capabilities
    assert "lan_buzzer_control" not in profile.capabilities


@pytest.mark.parametrize("profile", [
    FALLBACK_MID_PROFILE,
    MidProfile(None, ("Pow", "Mod"), "air_conditioner"),
    MidProfile("untyped", ("Pow", "Mod")),
])
def test_missing_mid_or_untyped_profile_has_no_capability_evidence(profile):
    assert profile.capabilities == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("mid", ["6049", "604a", "604b", "604c", "605c", "608f", "6092"])
async def test_ordinary_gateway_child_poll_remains_raw_after_parent_hid(mid):
    unit = create_device(DeviceInfo("127.0.0.1", 7000, "001122334455", "Child", mid=mid))
    assert type(unit) is Device
    await unit.bind(key="0123456789abcdef", cipher=CipherV1())
    unit.send = AsyncMock()
    await unit.update_state()
    assert unit.send.call_args.args[0]["pack"]["cols"] == ["Pow", "Mod", "SetTem", "TemBody", "hid"]
    unit.handle_state_update(hid="362001061433+U-W06AV7.bin", TemBody=85)
    await unit.update_state()
    assert unit.send.call_args.args[0]["pack"]["cols"] == ["Pow", "Mod", "SetTem", "TemBody"]
    assert type(unit) is Device
    assert all(value is None for value in unit.capabilities.values())
    assert unit.get_property("TemBody") == 85
    unit.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mid", ["608e", "06049", "604A"])
async def test_routing_comparisons_and_mid_aliases_do_not_borrow_ordinary_child_poll(mid):
    unit = create_device(DeviceInfo("127.0.0.1", 7000, "001122334455", "Unqualified route", mid=mid))
    await unit.bind(key="0123456789abcdef", cipher=CipherV1())
    unit.send = AsyncMock()
    unit.handle_state_update(hid="362001067012+U-W06AV30.bin", Pow=1, TemBody=85)
    await unit.update_state()
    assert unit.send.call_args.args[0]["pack"]["cols"] == ["hid"]
    assert type(unit) is Device
    assert all(value is None for value in unit.capabilities.values())
    unit.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mid,hid", [
    ("60", "362001061433+U-W06AV7.bin"),
    ("60", "362001066326+U-WB05BRV1.18.bin"),
    ("60", "362001066380+U-WB05BRV1.38.bin"),
    (None, "362001065279+U-WB05RT13V1.64.bin"),
])
async def test_gateway_or_missing_mid_stays_identity_only_despite_known_firmware(mid, hid):
    unit = create_device(DeviceInfo("127.0.0.1", 7000, "001122334455", "Parent", mid=mid))
    await unit.bind(key="0123456789abcdef", cipher=CipherV1())
    unit.send = AsyncMock()
    unit.handle_state_update(hid=hid, Pow=1, TemSen=65)
    await unit.update_state()
    assert unit.send.call_args.args[0]["pack"]["cols"] == ["hid"]
    assert type(unit) is (GatewayDevice if mid == "60" else Device)
    assert all(value is None for value in unit.capabilities.values())
    unit.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mid,hid,columns,state", [
    ("6079", "362001067012+U-W06AV30.bin",
     ["Pow", "FanMod", "WdSpd", "GetEr"], {"Pow": 1, "FanMod": 2}),
    ("11f00", "362001067427+U-WB65VRV1.02.bin",
     ["Pow", "Mod", "SetTem", "WdSpd", "TemSen"], {"Pow": 65535, "TemSen": 255}),
    ("13801", "362001060200+U-CS849AV10.bin",
     ["Pow", "Dmod", "Dwet", "host", "name"], {"Pow": 1, "Dmod": 2, "Dwet": 6}),
    ("828503", "362001063012+U-W06TV1.10.bin",
     ["UV", "Mode", "Sleep", "HumiditySet", "hid", "time", "rssi"],
     {"UV": 1, "Mode": 3, "Sleep": 0, "HumiditySet": 255}),
    ("828901", "362001062030+U-W05MV1.18.bin",
     ["Wash", "Dry", "hid", "time"], {"Wash": 1, "Dry": 255}),
    ("80260", "362001062978+U-MSTWB801AV1.01.bin",
     ["Pow", "WorkState", "AlarmCancel", "AlarmTmrEnable", "AlarmTime", "host", "name",
      "rssi", "hid", "InHid", "OEEPHid", "AllErr"],
     {"Pow": -1, "WorkState": 2147483647, "AlarmTime": -2147483648, "AllErr": "0"}),
    ("80261", "362001061890+U-ESP32_GRV1.1.bin",
     ["WorkState", "count", "border", "JFerr", "doorenable", "doortotal", "host", "ver",
      "name", "rssi", "hid", "InHid", "OEEPHid", "InHidDownPer", "devinhidownver",
      "induptype"],
     {"WorkState": 1, "count": 65535, "border": 255, "doortotal": -1}),
    ("809030", "362001060629",
     ["hid", "Pow", "Mod", "Quiet", "SvSt", "TemUn", "Temp", "WtTemp", "HtSetTem",
      "ColSetTem", "HtWtSetTem", "ColWtSetTem", "Er"],
     {"Pow": 1, "Temp": -32768, "WtTemp": 65535, "Er": True}),
    ("80241", "362001061649+U-W06KV4.4.bin",
     ["hid", "Pow", "LigPow", "ScrTime", "AutoCtr", "TemSor", "HumSor", "HCHO", "PM2P5", "CO2",
      "VOC", "InAirQuality", "SensorErr", "BatteryWarn"],
     {"Pow": 1, "TemSor": 65535, "HumSor": 255, "CO2": 65535, "rssi": -50}),
    ("80242", "362001061649+U-W06KV4.4.bin",
     ["hid", "Pow", "LigPow", "ScrTime", "AutoCtr", "TemSor", "HumSor", "HCHO", "PM2P5", "CO2",
      "VOC", "InAirQuality", "SensorErr", "BatteryWarn"],
     {"Pow": 0, "SensorErr": 255, "BatteryWarn": 255, "HCHO": 65535}),
])
async def test_evidenced_raw_polling_does_not_infer_typed_appliance(mid, hid, columns, state):
    unit = create_device(DeviceInfo("127.0.0.1", 7000, "001122334455", "Raw", mid=mid))
    await unit.bind(key="0123456789abcdef", cipher=CipherV1())
    unit.send = AsyncMock()
    unit.handle_state_update(hid=hid)
    await unit.update_state()
    DeviceProtocol2.packet_received(
        unit,
        {"pack": {"t": "dat", "cols": list(state), "dat": list(state.values())}},
        ("127.0.0.1", 7000),
    )
    assert unit.send.call_args.args[0]["pack"]["cols"] == columns
    assert type(unit) is Device
    assert all(value is None for value in unit.capabilities.values())
    for name, value in state.items():
        assert unit.get_property(name) == value
    unit.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mid,hid", [
    ("70501", "362001069922+ZTS31BV1.57.img"),
    ("70503", "362001071823+ZTS31B3V1.092.bin"),
    ("80305", "362001067919+U-W05GaV1.9.bin"),
])
async def test_non_generic_root_does_not_inherit_child_or_appliance_polling_fields(mid, hid):
    unit = create_device(DeviceInfo("127.0.0.1", 7000, "001122334455", "Root", mid=mid))
    await unit.bind(key="0123456789abcdef", cipher=CipherV1())
    unit.send = AsyncMock()
    unit.handle_state_update(hid=hid)
    await unit.update_state()
    assert unit.send.call_args.args[0]["pack"]["cols"] == []
    assert type(unit) is Device
    assert unit.raw_properties == {}
    assert all(value is None for value in unit.capabilities.values())
    unit.close()


@pytest.mark.asyncio
async def test_voice_controller_cache_fields_do_not_create_a_climate_device_or_sensor():
    unit = create_device(DeviceInfo("127.0.0.1", 7000, "001122334455", "Voice", mid="80222"))
    await unit.bind(key="0123456789abcdef", cipher=CipherV1())
    unit.send = AsyncMock()
    unit.handle_state_update(hid="362001062573+IS-T3BBW03V3.62.img", Pow=1, SetTem=26)
    # Exercise decoded DATA dispatch; the supplied key does not open a UDP transport.
    DeviceProtocol2.packet_received(
        unit,
        {"pack": {"t": "dat", "cols": ["RealTimePower", "VoiceVolume", "VoiceGate"],
                  "dat": [123, 65535, 0]}},
        ("127.0.0.1", 7000),
    )
    await unit.update_state()
    columns = unit.send.call_args.args[0]["pack"]["cols"]
    assert {"Pow", "SetTem", "VoltErr", "RelayErr"}.issubset(columns)
    assert "TemSen" not in columns
    assert {"RealTimePower", "VoiceVolume", "VoiceGate", "AppTimer", "time"}.issubset(columns)
    assert "RefBtnList" not in columns
    assert type(unit) is Device
    assert all(value is None for value in unit.capabilities.values())
    assert unit.get_property("SetTem") == 26
    assert unit.get_property("TemSen") is None
    assert unit.get_property("RealTimePower") == 123
    assert unit.get_property("VoiceVolume") == 65535
    assert unit.get_property("VoiceGate") == 0
    unit.close()


@pytest.mark.asyncio
async def test_central_root_polling_does_not_inherit_child_climate_or_placeholder_fields():
    unit = create_device(DeviceInfo("127.0.0.1", 7000, "001122334455", "Central", mid="80901"))
    # A provisioned key bypasses bootstrap; this controller requires mate, not bind.
    await unit.bind(key="0123456789abcdef", cipher=CipherV1())
    unit.send = AsyncMock()
    unit.handle_state_update(hid="362001063066+MC-ETSBH01V1.38.img", Subcount=0, Pow=1)
    await unit.update_state()
    columns = unit.send.call_args.args[0]["pack"]["cols"]
    assert {"Subcount", "SubOnline", "Pow", "GcloudHid"}.issubset(columns)
    assert "time" in columns
    assert "subdev" not in columns
    DeviceProtocol2.packet_received(
        unit,
        {"pack": {"t": "dat", "cols": ["SubOnline", "time"],
                  "dat": [[], "2026-10-24 12:34:56"]}},
        ("127.0.0.1", 7000),
    )
    assert unit.get_property("SubOnline") == []
    assert unit.get_property("time") == "2026-10-24 12:34:56"
    assert not {"No", "BleON", "TemSen", "TemBody", "SetTem", "AllInWatTemHi"}.intersection(columns)
    assert type(unit) is Device
    assert all(value is None for value in unit.capabilities.values())
    unit.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mid,hid,state", [
    ("80221", "362001061917+W05RV2.35.bin", {"RealTimePower": 65535, "ConBtnName": 7}),
    ("80300", "362001061996+U-W05G(RELT)V4.3.bin",
     {"Sceneid": 7, "AdminRadom": "1234", "SubOnline": '["001122334455"]'}),
    ("80801", "362001063300+U-W05ZV2.28.bin",
     {"StartTime": [-2147483648, -1, 0, 1, 2147483647],
      "EndTime": [1, 2147483647, 17, 31, 99], "rssi": -50, "RealTimePower": 65535}),
])
async def test_sensorless_realtek_root_polling_remains_raw_and_source_balanced(mid, hid, state):
    unit = create_device(DeviceInfo("127.0.0.1", 7000, "001122334455", "Realtek", mid=mid))
    await unit.bind(key="0123456789abcdef", cipher=CipherV1())
    unit.send = AsyncMock()
    await unit.update_state()
    columns = unit.send.call_args.args[0]["pack"]["cols"]
    assert len(columns) == len(set(columns))
    DeviceProtocol2.packet_received(
        unit, {"pack": {"t": "dat", "cols": list(state), "dat": list(state.values())}},
        ("127.0.0.1", 7000),
    )
    unit.handle_state_update(hid=hid)
    await unit.update_state()
    assert unit.send.call_args.args[0]["pack"]["cols"] == columns
    for name, value in state.items():
        assert unit.get_property(name) == value
    assert type(unit) is Device
    assert all(value is None for value in unit.capabilities.values())
    assert unit.get_property("TemSen") is None
    assert not {"TemSen", "RefBtnList", "BleKey", "NoD", "Reota", "Lpn"}.intersection(columns)
    if mid == "80300":
        assert "Pow" not in columns  # Native callback has no corresponding dat item.
    if mid == "80801":
        assert "Electnumzero" not in columns
    unit.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mids,state", [
    (("828202", "828203", "828204", "828205", "828208", "828209", "828210", "828211", "828213"),
     {"Temperature": -1, "PM25": 65535, "WetLevel": 3}),
    (("828a00", "828a01", "828a02", "828a03", "828a04", "828a05"),
     {"SetTemp": 26, "EnvTemp": -1, "HeatLevel": 3}),
    (("828301", "828306", "828307", "828308", "828309", "828310"),
     {"WorkStatus": 2, "TotalPureWater": 65535, "FilterKind5": 7}),
    (("829000",), {"eState": 65535, "InsFlowRate": 17, "SaltStatus": 1}),
    (("828100", "828103", "828105"),
     {"meshid": 7, "RemLifePerErr2": 65535, "LifeTimeMesh1": 123}),
])
async def test_raw_hi3861_polling_preserves_schema_case_and_raw_values(mids, state):
    for mid in mids:
        unit = create_device(DeviceInfo("127.0.0.1", 7000, "001122334455", "Raw", mid=mid))
        await unit.bind(key="0123456789abcdef", cipher=CipherV1())
        unit.send = AsyncMock()
        await unit.update_state()
        columns = unit.send.call_args.args[0]["pack"]["cols"]
        assert set(state).issubset(columns)
        assert len(columns) == len(set(columns))
        # Qualified W05J common preset (MidContract 828103/828105, 34 cols):
        # W05J selector-2 order + six Hi3861-only names + hid; time/rssi/ver
        # are no longer default-polled here and must be requested explicitly
        assert "hid" in columns
        DeviceProtocol2.packet_received(
            unit,
            {"pack": {"t": "dat", "cols": list(state), "dat": list(state.values())}},
            ("127.0.0.1", 7000),
        )
        unit.handle_state_update(hid="362001063856+U-Hi3861-OldV1.13.bin")
        await unit.update_state()
        assert unit.send.call_args.args[0]["pack"]["cols"] == columns
        assert type(unit) is Device
        assert all(value is None for value in unit.capabilities.values())
        assert unit.get_property("TemSen") is None
        for name, value in state.items():
            assert unit.get_property(name) == value
        unit.close()


@pytest.mark.parametrize("mid", ["0828202", "828A00", "828a06", "828206", "82900", "828f00"])
def test_unqualified_raw_mid_variants_remain_unknown(mid):
    assert match_mid_profile(mid) is FALLBACK_MID_PROFILE


@pytest.mark.asyncio
@pytest.mark.parametrize("mid", ["6084", "608d", "6091", "6099", "60a0", "60a4", "60a9"])
async def test_conditional_wb_fan_polling_preserves_raw_channel_arrays(mid):
    unit = create_device(DeviceInfo("127.0.0.1", 7000, "001122334455", "Fan", mid=mid))
    await unit.bind(key="0123456789abcdef", cipher=CipherV1())
    unit.send = AsyncMock()
    await unit.update_state()
    columns = unit.send.call_args.args[0]["pack"]["cols"]
    assert {"MIdType", "GasQ", "TemSor", "CO2", "GasAvail", "PM2P5Sta"}.issubset(columns)
    assert len(columns) == len(set(columns))
    assert not {"GasN", "ReportFreq", "InEffClRes", "InEffReRes", "IFDClRes",
                "EffReRes", "TemSen", "TemBody"}.intersection(columns)
    # One dat item per column; two channels stay inside the individual array.
    DeviceProtocol2.packet_received(
        unit,
        {"pack": {"t": "dat", "cols": ["GasQ", "TemSor", "CO2", "MIdType"],
                  "dat": [3, [0, 255], [0, 65535], mid]}},
        ("127.0.0.1", 7000),
    )
    assert unit.get_property("GasQ") == 3
    assert unit.get_property("TemSor") == [0, 255]
    assert unit.get_property("CO2") == [0, 65535]
    assert unit.get_property("MIdType") == mid
    assert unit.get_property("TemSen") is None
    assert type(unit) is Device
    assert all(value is None for value in unit.capabilities.values())
    unit.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mid", ["6083", "6094"])
async def test_conditional_wb_energy_polling_keeps_counters_raw(mid):
    unit = create_device(DeviceInfo("127.0.0.1", 7000, "001122334455", "Energy", mid=mid))
    await unit.bind(key="0123456789abcdef", cipher=CipherV1())
    unit.send = AsyncMock()
    await unit.update_state()
    columns = unit.send.call_args.args[0]["pack"]["cols"]
    assert {"PvTotEngy", "NewGridTotEngy", "OldGridTotEngy", "PSSGoCPwr",
            "PVGenedPwr", "CalMeth"}.issubset(columns)
    assert columns.index("NewGridTotEngy") < columns.index("OldGridTotEngy")
    assert not {"Pow", "Mod", "SetTem", "TemSen", "TemBody"}.intersection(columns)
    DeviceProtocol2.packet_received(
        unit,
        {"pack": {"t": "dat", "cols": ["PvTotEngy", "NewGridTotEngy", "PSSGoCPwr"],
                  "dat": [4294967295, 65535, -32768]}},
        ("127.0.0.1", 7000),
    )
    assert unit.get_property("PvTotEngy") == 4294967295
    assert unit.get_property("NewGridTotEngy") == 65535
    assert unit.get_property("PSSGoCPwr") == -32768
    assert type(unit) is Device
    assert all(value is None for value in unit.capabilities.values())
    unit.close()
