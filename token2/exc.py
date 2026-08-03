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


class PinConditionsNotSatisfied(ExpectedCommandError):
    def __init__(self) -> None:
        super().__init__("PIN conditions not satisfied (session not established, "
                         "or a read/verify was attempted out of order).")


# Backwards-compatible alias; 6985 does NOT mean "no PIN set".
PinNotSet = PinConditionsNotSatisfied


class PinInvalid(ExpectedCommandError):
    def __init__(self) -> None:
        super().__init__("Wrong OTP PIN (or authentication tag mismatch).")


class PinLocked(ExpectedCommandError):
    def __init__(self) -> None:
        super().__init__("OTP PIN is locked (too many wrong attempts). A global OTP reset is required.")


class FunctionNotSupported(ExpectedCommandError):
    def __init__(self, detail: str = "") -> None:
        msg = "The device does not support this operation in its current state."
        if detail:
            msg += " " + detail
        super().__init__(msg)


class PinAlreadySet(ExpectedCommandError):
    def __init__(self) -> None:
        super().__init__(
            "An OTP PIN is already set on this device. Use 'change_pin' to change "
            "it, 'remove_pin' to clear it, or reset the OTP applet first.")


class PinPolicyRejected(ExpectedCommandError):
    def __init__(self) -> None:
        super().__init__(
            "The device rejected this PIN by policy (6A80). Avoid sequential "
            "(123456/654321), repeated (111111), palindrome (321123), or "
            "digits repeating more than 3 times; pick a less predictable PIN.")
