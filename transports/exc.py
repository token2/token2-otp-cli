class TransportUnavailable(RuntimeError):
    def __init__(self):
        super().__init__("Unable to auto-detect token on the selected transport.")


class TokenNotDetected(RuntimeError):
    def __init__(self):
        super().__init__("Token not found.")
