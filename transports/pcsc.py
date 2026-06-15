import binascii
import time

from smartcard.Exceptions import NoCardException
from smartcard.Exceptions import CardConnectionException
from smartcard.System import readers
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
                connection.connect()

                self._debug_print(f'Reader {reader}: ATR {toHexString(connection.getATR())}')

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

    def _send_pcsc(self, conn, cmd: bytes) -> bytes:
        self._debug_print('Send: ' + cmd.hex())
        cmd_arr = [x for x in cmd]

        start = time.perf_counter()
        res = conn.transmit(cmd_arr)
        end = time.perf_counter()

        res_b = bytes(res[0]) + bytes([res[1], res[2]])
        self._debug_print('Took: ' + str(round((end - start) * 1000)) + ' ms')
        self._debug_print('Recv: ' + res_b.hex())

        check_status_code(bytes([res[1], res[2]]))
        return bytes(res[0])

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