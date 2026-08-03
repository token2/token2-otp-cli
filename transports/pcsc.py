import binascii
import time

from smartcard.Exceptions import NoCardException
from smartcard.Exceptions import CardConnectionException
from smartcard.System import readers
from smartcard.scard import SCARD_SHARE_EXCLUSIVE, SCARD_SHARE_SHARED
import os
from smartcard.util import toHexString

from token2.data_structures import APDU, CommandType
from token2.errors import check_status_code
from token2.exc import BadStatusCode
from transports.base import BaseTransport
from transports.exc import TransportUnavailable


class PCSCTransport(BaseTransport):
    def __init__(self, *, ask_button_cb=None, debug=False):
        super().__init__(ask_button_cb=ask_button_cb, debug=debug)
        self.connection = None

    def open(self):
        for reader in readers():
            try:
                connection = reader.createConnection()
                # Connect EXCLUSIVE by default so the OTP PIN session established by
                # the ECDH handshake survives to the Set command. Under shared mode
                # the card/session can be reset by the PC/SC layer between commands,
                # which shows up as 6A80 on Set. Set TOKEN2_PCSC_SHARED=1 to force
                # the old shared behaviour.
                shared = os.environ.get("TOKEN2_PCSC_SHARED") == "1"
                mode = SCARD_SHARE_SHARED if shared else SCARD_SHARE_EXCLUSIVE
                try:
                    connection.connect(mode=mode)
                except Exception:
                    connection.connect()

                self._debug_print(f'Reader {reader}: ATR {toHexString(connection.getATR())} exclusive={not shared}')

                try:
                    cmd = APDU(CommandType.CMD_ISO_SELECT, binascii.unhexlify("f00000014f747001")).serialize(
                        extended_length=False)
                    self._send_pcsc(connection, cmd)
                except RuntimeError as e:
                    self._debug_print(f'Reader {reader}: {e}')
                    continue

                self.connection = connection
                break
            except NoCardException:
                self._debug_print(f'Reader {reader}: no tag inserted')
        else:
            raise TransportUnavailable()

    def close(self):
        self.connection.disconnect()

    def _transmit(self, conn, cmd_arr):
        start = time.perf_counter()
        res = conn.transmit(cmd_arr)
        end = time.perf_counter()
        self._debug_print('Took: ' + str(round((end - start) * 1000)) + ' ms')
        return res  # (data_list, sw1, sw2)

    def _send_pcsc(self, conn, cmd: bytes) -> bytes:
        self._debug_print('Send: ' + cmd.hex())
        data, sw1, sw2 = self._transmit(conn, [x for x in cmd])
        data = list(data)

        # ISO 7816 T=0 conventions some CCID/PIV contexts use:
        #   61 xx -> success, xx bytes waiting; fetch via GET RESPONSE (00 C0 00 00 xx)
        #   6C xx -> wrong Le; re-issue the same command with Le = xx
        while sw1 == 0x61 or sw1 == 0x6C:
            if sw1 == 0x6C:
                retry = [x for x in cmd[:-1]] + [sw2]
                self._debug_print('Resend (6C) Le=%02x: ' % sw2 + bytes(retry).hex())
                data, sw1, sw2 = self._transmit(conn, retry)
                data = list(data)
            else:  # 61 xx
                get_resp = [0x00, 0xC0, 0x00, 0x00, sw2]
                self._debug_print('GET RESPONSE (61): ' + bytes(get_resp).hex())
                more, sw1, sw2 = self._transmit(conn, get_resp)
                data += list(more)

        res_b = bytes(data) + bytes([sw1, sw2])
        self._debug_print('Recv: ' + res_b.hex())

        check_status_code(bytes([sw1, sw2]))
        return bytes(data)

    def send_command(self, cmd: APDU, detect_btn_wait: bool = False) -> bytes:
        # Are we asking for a serial number? If so, switch to the FIDO applet first,
        # which is the one that implements the "read serial number" command.
        if cmd.data == b"\xd1\x10" + (b"\x00" * 16):
            try:
                switch_to_fido = APDU(CommandType.CMD_ISO_SELECT, binascii.unhexlify("A0000006472F0001")).serialize(
                    extended_length=False)
                self._send_pcsc(self.connection, switch_to_fido)
            except CardConnectionException:
                print("Reading the Serial number over NFC needs Administrator permissions.")
                exit(1)

        try:
            return self._send_pcsc(self.connection, cmd.serialize())
        except BadStatusCode:
            if cmd.data == b"\xd1\x10" + (b"\x00" * 16):
                print("This model does not support reading the serial number over NFC.")
            else:
                print("Error during communication.")
            exit(1)