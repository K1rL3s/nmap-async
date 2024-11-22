class PortScannerError(Exception):
    """
    Exception error class for PortScanner class

    """

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

    def __repr__(self):
        return f"PortScannerError exception {self.value}"


class PortScannerTimeout(PortScannerError):
    pass
