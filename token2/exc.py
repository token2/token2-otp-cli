class BadStatusCode(RuntimeError):
    def __init__(self, status_code: bytes):
        super().__init__("Command unexpectedly failed with status code: " + status_code.hex())
        self.status_code = status_code


class ExpectedCommandError(RuntimeError):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class EntryNotFound(ExpectedCommandError):
    def __init__(self) -> None:
        super().__init__("Specified entry was not found.")


class HIDNotSupported(ExpectedCommandError):
    def __init__(self) -> None:
        super().__init__("HOTP via HID is not supported on this device")

class NotEnoughSpace(ExpectedCommandError):
    def __init__(self) -> None:
        super().__init__("Not enough space on the device to perform the requested operation.")


class ButtonPressRequired(ExpectedCommandError):
    def __init__(self) -> None:
        super().__init__("The operation timed out waiting for the user to press the button on the token.")
