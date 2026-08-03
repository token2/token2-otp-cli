"""Direct CCID-over-USB transport for OTP PIN management.

A USB capture of the Token2 companion app setting an OTP PIN revealed two
things:

  1. PIN management does NOT go through Windows' PC/SC layer. On PC/SC the
     reader auto-selects the PIV applet and the OTP PIN Set command returns
     6A80. The companion app instead talks to the key's CCID interface
     *directly* over USB, reaching the card's default (OTP) context, where the
     same Set APDU returns 9000.

  2. The framing on the wire is standard CCID bulk messages, not a custom HID
     protocol:
        PC_to_RDR_XfrBlock  (0x6F): 6F <dwLength:4 LE> <bSlot> <bSeq> 00 00 00 <APDU>
        RDR_to_PC_DataBlock (0x80): 80 <dwLength:4 LE> <bSlot> <bSeq> <status> <err> <chain> <data..SW>

This transport claims the CCID interface with pyusb and exchanges APDUs via
XfrBlock on its bulk endpoints, bypassing winscard/PIV entirely. It is used for
PIN operations; base OTP commands keep using the existing transports.

Requires pyusb (`pip install pyusb`) and a USB backend (libusb). On Windows the
device's CCID interface may need the WinUSB/libusb driver bound (e.g. via Zadig)
for pyusb to claim it, since Windows' usbccid driver otherwise owns it.
"""

import struct

import usb.core
import usb.util

from token2.data_structures import APDU
from token2.errors import check_status_code
from transports.base import BaseTransport
from transports.exc import TransportUnavailable

_TOKEN2_VID = 0x349E

# CCID message types
_PC_TO_RDR_XFRBLOCK = 0x6F
_PC_TO_RDR_ICCPOWERON = 0x62
_PC_TO_RDR_GETSLOTSTATUS = 0x65
_RDR_TO_PC_DATABLOCK = 0x80


class ApduHidTransport(BaseTransport):
    """CCID-over-USB transport (name kept for compatibility with the selector)."""

    def __init__(self, *, ask_button_cb=None, debug=False):
        super().__init__(ask_button_cb=ask_button_cb, debug=debug)
        self.dev = None
        self.ep_out = None
        self.ep_in = None
        self.intf = None
        self._seq = 0

    # -- discovery / open --------------------------------------------------
    def open(self):
        try:
            dev = usb.core.find(idVendor=_TOKEN2_VID)
        except usb.core.NoBackendError:
            raise RuntimeError(
                "pyusb has no USB backend (libusb) installed. Install libusb: "
                "on Windows put libusb-1.0.dll on PATH or use the libusb package; "
                "then bind WinUSB to the key's CCID interface (interface 1) with Zadig."
            )
        if dev is None:
            # Enumerate what pyusb CAN see, to tell 'no backend/driver' from 'not present'.
            try:
                seen = [(hex(d.idVendor), hex(d.idProduct)) for d in usb.core.find(find_all=True)]
            except Exception:
                seen = []
            raise RuntimeError(
                "Token2 device (VID 0x349E) not visible to pyusb. This usually means "
                "the CCID interface is still owned by the Windows usbccid driver — "
                "bind WinUSB to interface 1 with Zadig. pyusb currently sees: %r" % (seen,)
            )
        self.dev = dev

        # Find the CCID interface (bInterfaceClass 0x0B) and its bulk endpoints.
        cfg = dev.get_active_configuration()
        ccid_intf = None
        for intf in cfg:
            if intf.bInterfaceClass == 0x0B:
                ccid_intf = intf
                break
        if ccid_intf is None:
            raise TransportUnavailable()
        self.intf = ccid_intf

        # On Linux, detach the kernel usbccid driver so we can claim the interface.
        # (macOS/Windows don't support detach; we just try to claim directly and
        # surface a clear error if the OS smartcard driver holds the interface.)
        try:
            if dev.is_kernel_driver_active(ccid_intf.bInterfaceNumber):
                dev.detach_kernel_driver(ccid_intf.bInterfaceNumber)
        except (NotImplementedError, usb.core.USBError):
            pass

        # Some platforms need the configuration explicitly set before claiming.
        try:
            dev.set_configuration()
        except usb.core.USBError:
            pass  # already configured, or claimed elsewhere

        try:
            usb.util.claim_interface(dev, ccid_intf.bInterfaceNumber)
        except usb.core.USBError as e:
            raise RuntimeError(
                "Could not claim the CCID interface (%s). On macOS the system "
                "smartcard driver (usbsmartcardreaderd/CryptoTokenKit) may hold "
                "it. Try: (1) run with sudo; (2) if it persists, the OS owns the "
                "interface and direct-CCID set_pin isn't available on this "
                "platform — set the initial PIN with the companion app and "
                "manage it from the CLI over PC/SC." % e
            ) from None

        ep_out = ep_in = None
        for ep in ccid_intf:
            if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_OUT \
                    and usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK:
                ep_out = ep
            elif usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN \
                    and usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK:
                ep_in = ep
        if ep_out is None or ep_in is None:
            raise TransportUnavailable()
        self.ep_out, self.ep_in = ep_out, ep_in
        self._debug_print("CCID interface %d, ep_out %#x, ep_in %#x"
                          % (ccid_intf.bInterfaceNumber,
                             ep_out.bEndpointAddress, ep_in.bEndpointAddress))

        # SELECT the OTP applet (short-form Lc), mirroring the companion app.
        from token2.data_structures import CommandType
        self.send_command(APDU(CommandType.CMD_ISO_SELECT,
                               bytes.fromhex("f00000014f747001"),
                               force_short_lc=True))

    def close(self):
        if self.dev is not None:
            usb.util.dispose_resources(self.dev)

    # -- CCID framing ------------------------------------------------------
    def _xfr(self, apdu: bytes) -> bytes:
        """Send one PC_to_RDR_XfrBlock and return the RDR_to_PC data body."""
        self._seq = (self._seq + 1) & 0xFF
        header = struct.pack("<BIBBBBB",
                             _PC_TO_RDR_XFRBLOCK,  # bMessageType
                             len(apdu),            # dwLength (LE)
                             0x00,                 # bSlot
                             self._seq,            # bSeq
                             0x00, 0x00, 0x00)     # bBWI + wLevelParameter
        msg = header + apdu
        self._debug_print("CCID send: " + msg.hex())
        self.ep_out.write(msg)

        # Read the response block (may exceed one bulk packet; keep reading).
        raw = bytes(self.ep_in.read(65536, timeout=7000))
        self._debug_print("CCID recv: " + raw.hex())
        if len(raw) < 10 or raw[0] != _RDR_TO_PC_DATABLOCK:
            raise RuntimeError("Unexpected CCID response: " + raw[:10].hex())
        dwlen = struct.unpack("<I", raw[1:5])[0]
        body = raw[10:10 + dwlen]
        # If the reader chained the response across blocks, keep reading.
        while len(body) < dwlen:
            more = bytes(self.ep_in.read(65536, timeout=7000))
            body += more[10:] if more[:1] == bytes([_RDR_TO_PC_DATABLOCK]) else more
        return body

    # -- public API --------------------------------------------------------
    def send_command(self, cmd: APDU, detect_btn_wait: bool = False) -> bytes:
        apdu = cmd.serialize()
        resp = self._xfr(apdu)
        data = resp[:-2] if len(resp) >= 2 else b""
        sw1, sw2 = (resp[-2], resp[-1]) if len(resp) >= 2 else (0, 0)

        # In-band ISO 7816 T=0 conventions, as the card uses them.
        while sw1 == 0x61 or sw1 == 0x6C:
            if sw1 == 0x6C:
                resp = self._xfr(apdu[:-1] + bytes([sw2]) if apdu[-1:] else apdu + bytes([sw2]))
                data = resp[:-2] if len(resp) >= 2 else b""
            else:  # 61 xx -> GET RESPONSE
                resp = self._xfr(bytes([0x80, 0xC0, 0x00, 0x00, sw2]))
                data += resp[:-2] if len(resp) >= 2 else b""
            sw1, sw2 = (resp[-2], resp[-1]) if len(resp) >= 2 else (0, 0)

        self._debug_print("APDU result: %s SW=%02X%02X" % (data.hex(), sw1, sw2))
        check_status_code(bytes([sw1, sw2]))
        return data
