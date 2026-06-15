"""High-level client for the Token2 OTP management protocol.

See docs/Token2-OTP-SDK-Protocol.md for the full wire-protocol reference.
"""

import binascii
import struct
from typing import Union

from .data_structures import APDU, CommandType, ReadOTPEntry, WriteOTPEntry, DeleteOTPEntry, EnumOTPEntry, \
    EnumCodesSubCommand, SetButtonHOTPData
from .ecdh_enc import encrypt_payload_ecdh, CIPHER_IV_2, CIPHER_IV_1
from .exc import EntryNotFound, NotEnoughSpace, ButtonPressRequired


class Token2:
    def __init__(self, transport):
        self.transport = transport

    def _extract_partial_flag(self, res):
        is_partial = res[0] & 0x80 == 0x80
        return is_partial, bytes([res[0] & 0x7F]) + res[1:]

    def enum_codes(self, ts):
        cmd = APDU(CommandType.CMD_ENUM_CODES, data=EnumCodesSubCommand.READ_ALL.value + struct.pack(">Q", int(ts)))

        try:
            is_partial, res = self._extract_partial_flag(self.transport.send_command(cmd))
        except EntryNotFound:
            # no records to return at all
            return

        yield from EnumOTPEntry.unserialize(res)

        while is_partial:
            cmd = APDU(CommandType.CMD_ENUM_CODES_CONTINUE, data=struct.pack(">Q", int(ts)))
            is_partial, res = self._extract_partial_flag(self.transport.send_command(cmd))
            yield from EnumOTPEntry.unserialize(res)

    def read_entry(self, spec: ReadOTPEntry):
        spec.validate()
        cmd = APDU(CommandType.CMD_ENUM_CODES, data=EnumCodesSubCommand.READ_ONE.value + spec.serialize())
        entries = list(
            EnumOTPEntry.unserialize(self.transport.send_command(cmd, detect_btn_wait=True), full_decode=True))

        if len(entries) != 1:
            raise RuntimeError("Expected a single result on the result list.")

        return entries[0]

    def write_entry(self, entry: Union[WriteOTPEntry, DeleteOTPEntry]):
        entry.validate()
        token_pk = self.transport.send_command(APDU(CommandType.CMD_GET_ECDH_PUBKEY, data=b""))
        cmd_data = encrypt_payload_ecdh(token_pk, entry.serialize(), iv=CIPHER_IV_1)
        self.transport.send_command(APDU(CommandType.CMD_WRITE_SEED, data=cmd_data))

    def erase_all(self):
        self.transport.send_command(APDU(CommandType.CMD_WRITE_SEED, data=b""), detect_btn_wait=True)

    def set_btn_seed(self, spec: SetButtonHOTPData):
        spec.validate()
        token_pk = self.transport.send_command(APDU(CommandType.CMD_GET_ECDH_PUBKEY, data=b""))
        cmd_data = encrypt_payload_ecdh(token_pk, spec.serialize_seed_payload(), iv=CIPHER_IV_2)
        self.transport.send_command(APDU(CommandType.CMD_WRITE_HOTP_SEED, data=cmd_data))
        self.transport.send_command(APDU(CommandType.CMD_CFG_HOTP_ENTER, data=spec.serialize_cfg_enter()))
        self.transport.send_command(APDU(CommandType.CMD_CFG_HOTP_TOUCH, data=spec.serialize_cfg_long_touch()))
        self.transport.send_command(APDU(CommandType.CMD_CFG_HOTP_KBD_TYPE, data=spec.serialize_cfg_num_kbd()))

    def delete_btn_seed(self):
        token_pk = self.transport.send_command(APDU(CommandType.CMD_GET_ECDH_PUBKEY, data=b""))
        cmd_data = encrypt_payload_ecdh(token_pk, b"\x00\x00", iv=CIPHER_IV_2)
        self.transport.send_command(APDU(CommandType.CMD_WRITE_HOTP_SEED, data=cmd_data))

    def read_serial_no(self):
        cmd_data = b"\xD1\x10" + (b"\x00" * 16)
        res = self.transport.send_command(APDU(CommandType.CMD_GET_INFO, data=cmd_data))

        if res[0] != 0xD1:
            raise RuntimeError("Assertion failed, expected response type 0xD1")

        sn_len = res[1]
        return binascii.unhexlify(res[2:2+sn_len])
