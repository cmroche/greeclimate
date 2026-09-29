class DeviceInfo:
    """Device information class, used to identify and connect

    Attributes
        ip: IP address (ipv4 only) of the physical device
        port: Usually this will always be 7000
        mac: mac address, in the format 'aabbcc112233'
        name: Name of unit, if available
        sub_count: Number of sub-devices behind this device (>0 for a gateway)
        gateway_key: For a sub-device, the bound key of its parent gateway
        gateway_cipher: For a sub-device, the cipher instance of its parent gateway
    """

    def __init__(self, ip, port, mac, name, brand=None, model=None, version=None, sub_count=0, gateway_key=None, gateway_cipher=None):
        self.ip = ip
        self.port = port
        self.mac = mac
        self.name = name if name else mac.replace(":", "")
        self.brand = brand
        self.model = model
        self.version = version
        self.sub_count = sub_count
        self.gateway_key = gateway_key
        self.gateway_cipher = gateway_cipher

    def __str__(self):
        return f"Device: {self.name} @ {self.ip}:{self.port} (mac: {self.mac})"

    def __eq__(self, other):
        """Check equality based on Device Info properties"""
        if isinstance(other, DeviceInfo):
            return (
                    self.mac == other.mac
                    and self.name == other.name
                    and self.brand == other.brand
                    and self.model == other.model
                    and self.version == other.version
                    and self.sub_count == other.sub_count
            )
        return False

    def __ne__(self, other):
        """Check inequality based on Device Info properties"""
        return not self.__eq__(other)

