"""Keep gateway routing distinct from indoor-unit identity."""
from greeclimate.deviceinfo import DeviceInfo
from greeclimate.network import DeviceProtocol2


def test_indoor_status_and_commands_route_through_gateway():
    info = DeviceInfo("127.0.0.1", 7000, "aabbcc00000001", "Indoor", gateway_mac="aabbcc001122")
    protocol = DeviceProtocol2()
    status = protocol.create_status_message(info, "Pow", "SetTem")
    assert status["tcid"] == info.gateway_mac
    assert status["pack"] == {"t": "status", "mac": info.mac, "cols": ["Pow", "SetTem"]}
    command = protocol.create_command_message(info, Pow=1, SetTem=25)
    assert command["tcid"] == info.gateway_mac
    assert command["pack"] == {
        "t": "cmd", "mac": info.gateway_mac, "sub": info.mac,
        "opt": ["Pow", "SetTem"], "p": [1, 25],
    }


def test_standalone_addressing_is_unchanged():
    info = DeviceInfo("127.0.0.1", 7000, "aabbcc001122", "Standalone")
    protocol = DeviceProtocol2()
    status = protocol.create_status_message(info, "Pow")
    command = protocol.create_command_message(info, Pow=0)
    for packet in (status, command):
        assert packet["tcid"] == info.mac
        assert packet["pack"]["mac"] == info.mac
        assert "sub" not in packet["pack"]
