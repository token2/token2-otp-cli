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
from .otp_pin import OtpPinSession, PinFlag


class Token2:
    def __init__(self, transport):
        self.transport = transport
        self._pin_session = None  # set by unlock(); enables PIN-mode decrypt

    def _extract_partial_flag(self, res):
        is_partial = res[0] & 0x80 == 0x80
        return is_partial, bytes([res[0] & 0x7F]) + res[1:]

    def _maybe_decrypt(self, res: bytes) -> bytes:
        """In PIN mode the enum response is IV||EncData||Auth; decrypt it if a
        verified session is active. Otherwise return it unchanged (plaintext)."""
        if self._pin_session is not None:
            return self._pin_session.unwrap_enc_data(res)
        return res

    def enum_codes(self, ts):
        cmd = APDU(CommandType.CMD_ENUM_CODES, data=EnumCodesSubCommand.READ_ALL.value + struct.pack(">Q", int(ts)))

        try:
            res = self._maybe_decrypt(self.transport.send_command(cmd))
            is_partial, res = self._extract_partial_flag(res)
        except EntryNotFound:
            # no records to return at all
            return

        yield from EnumOTPEntry.unserialize(res)

        while is_partial:
            cmd = APDU(CommandType.CMD_ENUM_CODES_CONTINUE, data=struct.pack(">Q", int(ts)))
            res = self._maybe_decrypt(self.transport.send_command(cmd))
            is_partial, res = self._extract_partial_flag(res)
            yield from EnumOTPEntry.unserialize(res)

    def read_entry(self, spec: ReadOTPEntry):
        spec.validate()
        cmd = APDU(CommandType.CMD_ENUM_CODES, data=EnumCodesSubCommand.READ_ONE.value + spec.serialize())
        res = self._maybe_decrypt(self.transport.send_command(cmd, detect_btn_wait=True))
        entries = list(EnumOTPEntry.unserialize(res, full_decode=True))

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

    # --- R3.4 optional PIN --------------------------------------------------
    def pin_flag(self, verify_device_key=None) -> PinFlag:
        """Read the OTP PIN flag (state + encrypted challenge).

        On real firmware the flag read happens INSIDE the session (the returned
        challenge is encrypted under the session key), so this establishes the
        ECDH session first, then reads the flag. Returns a PinFlag with Rand
        already decrypted."""
        session = self.open_pin_session(verify_device_key=verify_device_key)
        return session.read_flag(want_challenge=False)

    def open_pin_session(self, verify_device_key=None) -> OtpPinSession:
        """Establish an authenticated ECDH session for PIN operations."""
        return OtpPinSession.establish(self.transport, verify_device_key=verify_device_key)

    def unlock(self, pin: bytes, verify_device_key=None) -> OtpPinSession:
        """Convenience: open a session and verify the PIN, opening the read
        window. Returns the session and retains it so subsequent reads can
        decrypt PIN-mode (encrypted) responses."""
        session = self.open_pin_session(verify_device_key=verify_device_key)
        session.verify(pin)
        self._pin_session = session
        return session
