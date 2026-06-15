"""Transport auto-detection for Token2 OTP devices.

Tries USB-HID first, then falls back to PC/SC (smart card / NFC readers).
"""

from transports.base import BaseTransport
from transports.exc import TransportUnavailable, TokenNotDetected
from transports.pcsc import PCSCTransport
from transports.usb import USBTransport


def detect_token(ask_button_cb: callable = None, debug: bool = False) -> BaseTransport:
    """Locate and open a connected Token2 device.

    :param ask_button_cb: optional callback invoked when the device is
        waiting for a physical button press.
    :param debug: when True, transports print raw command/response traces.
    :raises TokenNotDetected: if no device could be found on any transport.
    """
    try:
        transport = USBTransport(ask_button_cb=ask_button_cb, debug=debug)
        transport.open()
    except TransportUnavailable:
        try:
            transport = PCSCTransport(ask_button_cb=ask_button_cb, debug=debug)
            transport.open()
        except TransportUnavailable:
            raise TokenNotDetected() from None

    return transport
