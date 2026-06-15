from .exc import EntryNotFound, NotEnoughSpace, ButtonPressRequired, HIDNotSupported, BadStatusCode


def check_status_code(status_code):
    if status_code == b"\x6a\x80":
        raise EntryNotFound() from None
    elif status_code == b"\x6a\x83":
        raise EntryNotFound() from None
    elif status_code == b"\x6a\x84":
        raise NotEnoughSpace() from None
    elif status_code == b"\x6f\xf9":
        raise ButtonPressRequired() from None

    if status_code == b"\x6a\x86":
        raise HIDNotSupported() from None    
    
    if status_code != b"\x90\x00":
        raise BadStatusCode(status_code)
