class DeviceNotBoundError(Exception):
    """The device being used does not have it's device key set yet. Either provide one or bind the device"""
    pass