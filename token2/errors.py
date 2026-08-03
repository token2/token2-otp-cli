from .exc import EntryNotFound, NotEnoughSpace, ButtonPressRequired, HIDNotSupported, BadStatusCode, \
    PinNotSet, PinInvalid, PinLocked, FunctionNotSupported


def check_status_code(status_code):
    if status_code == b"\x6a\x80":
        raise EntryNotFound() from None
    elif status_code == b"\x6a\x83":
        raise EntryNotFound() from None
    elif status_code == b"\x6a\x84":
        raise NotEnoughSpace() from None
    elif status_code == b"\x6a\x81":
        raise FunctionNotSupported() from None
    elif status_code == b"\x6f\xf9":
        raise ButtonPressRequired() from None

    if status_code == b"\x6a\x86":
        raise HIDNotSupported() from None

    if status_code == b"\x69\x85":
        raise PinNotSet() from None
    if status_code == b"\x69\x82":
        raise PinInvalid() from None
    if status_code == b"\x69\x83":
        raise PinLocked() from None
    
    if status_code != b"\x90\x00":
        raise BadStatusCode(status_code)
