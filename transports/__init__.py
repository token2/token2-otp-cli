"""Transport auto-detection for Token2 OTP devices.

Tries USB-HID first, then falls back to PC/SC (smart card / NFC readers).
"""

from transports.base import BaseTransport
from transports.exc import TransportUnavailable, TokenNotDetected

import os


def _load_pcsc():
    from transports.pcsc import PCSCTransport
    return PCSCTransport


def _load_usb():
    from transports.usb import USBTransport
    return USBTransport


def _load_apdu_hid():
    from transports.apdu_hid import ApduHidTransport
    return ApduHidTransport


def detect_token(ask_button_cb: callable = None, debug: bool = False,
                 prefer: str = None) -> BaseTransport:
    """Locate and open a connected Token2 device.

    :param ask_button_cb: optional callback invoked when the device is
        waiting for a physical button press.
    :param debug: when True, transports print raw command/response traces.
    :param prefer: force a transport: "pcsc" (CCID / NFC) or "usb". May also be
        set via the TOKEN2_TRANSPORT environment variable. Default: try USB-HID
        first, then fall back to PC/SC. Use "pcsc" on devices where the HID
        interface is disabled (HID opens but cannot be read).
    :raises TokenNotDetected: if no device could be found on any transport.
    """
    prefer = (prefer or os.environ.get("TOKEN2_TRANSPORT") or "").lower()

    if prefer in ("apdu-hid", "apdu_hid", "hidapdu"):
        try:
            transport = _load_apdu_hid()(ask_button_cb=ask_button_cb, debug=debug)
            transport.open()
            return transport
        except TransportUnavailable:
            raise RuntimeError(
                "Setting a new OTP PIN requires direct CCID access, which needs a "
                "libusb backend and the WinUSB driver bound to the key's CCID "
                "interface (Zadig). This is a firmware constraint: PIN *set* is not "
                "accepted over the standard PC/SC path. All other PIN operations "
                "(verify, read, change, remove, status) work over PC/SC with "
                "--transport pcsc. Alternatively, set the initial PIN with the "
                "Token2 companion app, then manage it from the CLI over PC/SC."
            ) from None

    if prefer == "pcsc":
        try:
            transport = _load_pcsc()(ask_button_cb=ask_button_cb, debug=debug)
            transport.open()
            return transport
        except TransportUnavailable:
            raise TokenNotDetected() from None

    if prefer == "usb":
        try:
            transport = _load_usb()(ask_button_cb=ask_button_cb, debug=debug)
            transport.open()
            return transport
        except TransportUnavailable:
            raise TokenNotDetected() from None

    try:
        transport = _load_usb()(ask_button_cb=ask_button_cb, debug=debug)
        transport.open()
    except TransportUnavailable:
        try:
            transport = _load_pcsc()(ask_button_cb=ask_button_cb, debug=debug)
            transport.open()
        except TransportUnavailable:
            raise TokenNotDetected() from None

    return transport
