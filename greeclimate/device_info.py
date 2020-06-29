

class DeviceInfo:

    ip = None
    port = None
    mac = None
    name = "<Unknown>"

    def __init__(self, ip, port, mac, name):
        self.ip = ip
        self.port = port
        self.mac = mac
        self.name = name if name else self.name

    def __str__(self):
        return f"Device: {self.name}, {self.ip}:{self.port} ({self.mac})"
