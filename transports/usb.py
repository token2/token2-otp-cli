import io

import hid

from token2.data_structures import APDU
from token2.errors import check_status_code
from transports.base import BaseTransport
from transports.exc import TransportUnavailable


class USBTransport(BaseTransport):
    def __init__(self, *, ask_button_cb=None, debug=False):
        super().__init__(ask_button_cb=ask_button_cb, debug=debug)
        self.handle = hid.device()

    @staticmethod
    def _detect_token():
        for device_dict in hid.enumerate():
            if device_dict.get('vendor_id') == 13470:
                return device_dict['vendor_id'], device_dict['product_id']

            if device_dict.get('manufacturer_string') == 'TOKEN2' \
                    and device_dict.get('product_string') == 'FIDO2 Security Key':
                return device_dict['vendor_id'], device_dict['product_id']

        raise TransportUnavailable()

    def open(self):
        vendor_id, product_id = self._detect_token()
        self.handle.open(vendor_id, product_id)

    def close(self):
        self.handle.close()

    def send_command(self, cmd: APDU, detect_btn_wait: bool = False) -> bytes:
        data = cmd.serialize()
        send_buf = io.BytesIO(data)
        msg_id = 0
        has_more = True

        while has_more:
            chunk = send_buf.read(61)
            has_more = send_buf.tell() < len(data)
            tmp = msg_id % 16
            if has_more:
                tmp |= 0x20

            msg_id += 1
            write_data = b"\x00\x21" + bytes([tmp]) + bytes([len(chunk)]) + chunk
            pad = 65 - len(write_data)
            write_data += b"\x00" * pad

            self._debug_print(f'Send: {write_data.hex()}')
            self.handle.send_feature_report([b for b in write_data])

        has_more = True
        out = io.BytesIO()
        num_messages = 0
        num_retries = 0

        while has_more:
            data = bytes(self.handle.get_feature_report(0, 65))
            self._debug_print(f'Recv: {data.hex()}')

            if data[0:2] != b"\x00\x21":
                raise RuntimeError('Unexpected response header via USB: ' + data[0:2].hex())

            status_byte = data[2]
            flags = status_byte & 0xF0
            msg_id = status_byte & 0x0F

            if flags == 0xC0:
                # command in progress, retry
                num_retries += 1

                if num_retries == 3 and detect_btn_wait:
                    if self.ask_button_cb:
                        self.ask_button_cb()

                continue

            if msg_id != num_messages % 16:
                raise RuntimeError('Receive error, invalid msg_id.')

            num_messages += 1
            has_more = flags & 0x20 == 0x20
            resp_len = data[3]
            out.write(data[4:4 + resp_len])

        resp = out.getvalue()
        check_status_code(resp[-2:])
        return resp[:-2]

    def close(self):
        self.handle.close()
