class DeviceInfo:
    """Device information class, used to identify and connect

    Attributes
        ip: IP address (ipv4 only) of the physical device
        port: Usually this will always be 7000
        mac: mac address, in the format 'aabbcc112233'
        name: Name of unit, if available
    """

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
