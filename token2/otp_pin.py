"""Host side of the R3.4 optional-PIN protocol for the Token2 OTP applet.

Implements the encrypted-session PIN scheme (OTP on FIDO Command Manual V1.2,
commands 1.12-1.19): an ECC521-signed ECDH handshake, an HKDF session-key
ladder, and Set / Verify / Change / Lock of the OTP PIN. See PROTOCOL.md in
the applet repo (token2/token2-otp-applet) for the wire-level spec.

This module is additive: it does not change the plaintext (no-PIN) paths. The
Token2 client uses it only when a PIN is set.
"""

import hashlib
import hmac
import os
import struct

from Crypto.Cipher import AES
from ecdsa import ECDH, NIST256p, NIST521p, VerifyingKey, BadSignatureError
from ecdsa.util import sigdecode_string

from .data_structures import APDU, CommandType
from .exc import EntryNotFound, FunctionNotSupported, PinAlreadySet, PinPolicyRejected
from .ecdh_enc import CIPHER_IV_1

# HKDF info strings from the manual: ASCII || 0x01
_INFO_MAC = b"TOTP HMAC key" + b"\x01"
_INFO_ENC = b"TOTP AES key" + b"\x01"

import os as _os
_DEBUG = _os.environ.get("DEBUG_PIN") == "1"
def _dbg(label, value=b""):
    if not _DEBUG:
        return
    if isinstance(value, (bytes, bytearray)):
        print("  [PIN] %-22s %s" % (label, bytes(value).hex()))
    else:
        print("  [PIN] %-22s %s" % (label, value))


def _aes_cbc_enc(key, iv, data):
    return AES.new(key, AES.MODE_CBC, IV=iv).encrypt(data)


def _aes_cbc_dec(key, iv, data):
    return AES.new(key, AES.MODE_CBC, IV=iv).decrypt(data)


def _hmac256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


class OtpPinSession:
    """One authenticated ECDH session with the OTP applet.

    Usage:
        s = OtpPinSession.establish(transport, device_pubkeys=...)
        flag = s.read_flag()          # PinFlag
        s.verify(pin)                 # opens the 5-minute window
        # ... reads happen through the normal Token2 client ...
        s.lock()                      # optional: end the window early
    """

    def __init__(self, transport, session_enc_key, session_mac_key):
        self.transport = transport
        self.session_enc_key = session_enc_key
        self.session_mac_key = session_mac_key
        self._rand = None  # last challenge from read_flag()

    # ------------------------------------------------------------------ #
    # 1.17 handshake
    # ------------------------------------------------------------------ #
    @classmethod
    def establish(cls, transport, verify_device_key: "VerifyingKey | None" = None):
        """Run READ_AGREEMENT_PUBKEY and derive the session keys.

        If ``verify_device_key`` (an ecdsa P-521 VerifyingKey) is given, the
        device's ECC521 signature over the two agreement pubkeys is checked and
        a mismatch raises BadSignatureError. Pass None to skip the check (e.g.
        against the open-source sample key on a dev card), but note that skips
        device authentication.
        """
        # The OEM sequence reads the PIN flag FIRST (Lc=09) to obtain PubVer/PubCrc
        # and to let the device initialize PIN state, THEN runs the handshake.
        # Replicate that order exactly.
        transport.send_command(
            APDU(CommandType.CMD_READ_OTP_PIN_FLAG, data=b"\x00" * 9, force_short_lc=True))

        ecdh = ECDH(curve=NIST256p)
        ecdh.generate_private_key()
        host_pub = ecdh.get_public_key().to_string("uncompressed")[1:]  # 64B X||Y

        cmd = APDU(CommandType.CMD_READ_AGREEMENT_PUBKEY, data=host_pub, force_short_lc=True)
        resp = transport.send_command(cmd)

        dev_pub = resp[0:64]
        dev_sign = resp[64:]
        _dbg("host_pub", host_pub)
        _dbg("dev_pub", dev_pub)
        _dbg("dev_sign", dev_sign)

        if verify_device_key is not None:
            # DevSign = ECDSA-P521-SHA512 over (host_pub64 || dev_pub64)
            try:
                verify_device_key.verify(
                    dev_sign, host_pub + dev_pub,
                    hashfunc=hashlib.sha512, sigdecode=sigdecode_string,
                )
            except BadSignatureError:
                raise BadSignatureError(
                    "Device agreement signature did not verify — the device "
                    "may not be genuine, or the wrong device key was supplied."
                )

        ecdh.load_received_public_key_bytes(b"\x04" + dev_pub, "uncompressed")
        agreement = ecdh.generate_sharedsecret_bytes()          # 32B X coord
        pu1_key = agreement[:32]
        pu1_prkey = _hmac256(b"\x00" * 32, pu1_key)
        session_mac = _hmac256(pu1_prkey, _INFO_MAC)
        session_enc = _hmac256(pu1_prkey, _INFO_ENC)
        _dbg("pu1_key(shared X)", pu1_key)
        _dbg("pu1_prkey", pu1_prkey)
        _dbg("SessionMacKey", session_mac)
        _dbg("SessionEncKey", session_enc)
        return cls(transport, session_enc, session_mac)

    # ------------------------------------------------------------------ #
    # 1.12 read flag / challenge
    # ------------------------------------------------------------------ #
    def read_flag(self, want_challenge: bool = False) -> "PinFlag":
        """Read the OTP PIN flag using SHORT-form Lc (as the OEM does).

        The OEM scripts use different request lengths per purpose, all short-Lc:
          - status only (before Set/Change): Lc=04
          - full incl. IV+EncRand (before Verify): Lc=41 (0x29)
        The device returns exactly Lc flag bytes; requesting the challenge when
        it is not needed consumes state the next command expects to be fresh.
        """
        # Data is all zeros; the length (Lc) alone tells the device how many flag
        # bytes to return. Match the OEM: 41 zero bytes for the challenge read,
        # 4 zero bytes for a status-only read.
        if want_challenge:
            data = b"\x00" * 41   # -> AlgId..EncRand
        else:
            data = b"\x00" * 4    # -> AlgId Retry PinLen MaxRetry
        cmd = APDU(CommandType.CMD_READ_OTP_PIN_FLAG, data=data, force_short_lc=True)
        resp = self.transport.send_command(cmd)
        _dbg("flag resp (want_ch=%d)" % (1 if want_challenge else 0), resp)
        flag = PinFlag.parse(resp)
        _dbg("  AlgId/Retry/Len/Max", bytes([flag.alg_id, flag.pin_retry, flag.pin_len, flag.max_retry]))
        if want_challenge and flag.enc_rand is not None:
            self._rand = _aes_cbc_dec(self.session_enc_key, flag.iv, flag.enc_rand)
            _dbg("  IV", flag.iv)
            _dbg("  EncRand", flag.enc_rand)
            _dbg("  Rand(dec)", self._rand)
        return flag

    # ------------------------------------------------------------------ #
    # 1.13 set PIN
    # ------------------------------------------------------------------ #
    def set_pin(self, pin: bytes, max_retry: int = 100):
        _validate_pin(pin)
        # Set only works from the unprotected state. If a PIN is already set,
        # the device rejects Set (6A81); check first for a clear message.
        existing = self.read_flag()
        if existing.pin_len and existing.pin_len > 0:
            raise PinAlreadySet()
        new_pin_plain = bytes([0x07, max_retry & 0xFF, len(pin)]) + pin
        _dbg("NewPin (pre-pad)", new_pin_plain)
        new_pin = _pkcs5_pad(new_pin_plain)
        _dbg("NewPin (padded)", new_pin)
        iv = os.urandom(16)
        _dbg("IV", iv)
        new_pin_enc = _aes_cbc_enc(self.session_enc_key, iv, new_pin)
        _dbg("NewPinEnc", new_pin_enc)
        new_pin_auth = _hmac256(self.session_mac_key, new_pin_enc)[:16]
        _dbg("NewPinAuth[0:16]", new_pin_auth)
        data = iv + new_pin_enc + new_pin_auth
        _dbg("NewPinData", data)
        _dbg("SET APDU (short Lc)", bytes([0x80,0xC5,0x05,0x05,len(data)]) + data)
        try:
            self.transport.send_command(APDU(CommandType.CMD_SET_OTP_PIN, data=data, force_short_lc=True))
        except EntryNotFound:
            # 6A80 on Set = the device rejected the PIN *value* by policy (weak/
            # sequential/repeated), not a crypto error. _validate_pin catches most
            # of these first; this covers anything the firmware rejects that our
            # client-side check didn't.
            raise PinPolicyRejected() from None
        except FunctionNotSupported:
            # 6A81 on Set typically means a PIN is already set (or Set isn't
            # available in this state). read_flag above should have caught the
            # already-set case; re-raise with guidance regardless.
            raise PinAlreadySet() from None

    # ------------------------------------------------------------------ #
    # 1.14 verify PIN  (opens the 5-minute window)
    # ------------------------------------------------------------------ #
    def verify(self, pin: bytes):
        if self._rand is None:
            self.read_flag(want_challenge=True)
        if self._rand is None:
            raise RuntimeError("No PIN challenge available (is a PIN set?).")
        pin_hash = hashlib.sha256(pin).digest()
        iv2 = hashlib.sha256(self._rand).digest()[:16]
        pin_hash_enc = _aes_cbc_enc(pin_hash, iv2, self._rand)
        iv = os.urandom(16)
        pin_hash_enc2 = _aes_cbc_enc(self.session_enc_key, iv, pin_hash_enc)
        data = iv + pin_hash_enc2
        self._rand = None  # single-use; force a fresh challenge next time
        self.transport.send_command(APDU(CommandType.CMD_VERIFY_OTP_PIN, data=data, force_short_lc=True))

    # ------------------------------------------------------------------ #
    # 1.15 change / delete PIN
    # ------------------------------------------------------------------ #
    def change_pin(self, old_pin: bytes, new_pin: bytes, max_retry: int = 100):
        _validate_pin(new_pin)
        self._change(old_pin, new_pin, max_retry)

    def delete_pin(self, old_pin: bytes):
        # Change with OtpPinLen = 0 removes the PIN.
        self._change(old_pin, b"", 100)

    def _change(self, old_pin: bytes, new_pin: bytes, max_retry: int):
        body = bytes([0x07, max_retry & 0xFF, len(new_pin)]) + new_pin
        body = _pkcs5_pad(body)
        iv = os.urandom(16)
        new_pin_enc = _aes_cbc_enc(self.session_enc_key, iv, body)
        old_pin_hash = hashlib.sha256(old_pin).digest()[:16]
        old_pin_hash_enc = _aes_cbc_enc(self.session_enc_key, iv, old_pin_hash)
        new_pin_auth = _hmac256(self.session_mac_key, new_pin_enc + old_pin_hash_enc)[:16]
        data = iv + new_pin_enc + new_pin_auth + old_pin_hash_enc
        self.transport.send_command(APDU(CommandType.CMD_CHANGE_OTP_PIN, data=data, force_short_lc=True))

    # ------------------------------------------------------------------ #
    # 1.19 lock  (P3 = 0x01, data = 0x00)
    # ------------------------------------------------------------------ #
    def unwrap_enc_data(self, resp: bytes) -> bytes:
        """Decrypt a PIN-mode OTP data response: IV(16) || EncData || Auth(16).

        Verifies the HMAC (SessionMacKey over EncData), then AES-CBC-decrypts
        EncData under SessionEncKey and strips PKCS#5 padding. Returns the
        plaintext (e.g. a partial-flag byte followed by packed entries)."""
        if len(resp) < 32 or (len(resp) - 32) % 16 != 0:
            raise ValueError("malformed encrypted OTP response")
        iv = resp[:16]
        auth = resp[-16:]
        enc = resp[16:-16]
        expect = _hmac256(self.session_mac_key, enc)[:16]
        if not hmac.compare_digest(expect, auth):
            raise ValueError("OTP response auth tag mismatch")
        pt = _aes_cbc_dec(self.session_enc_key, iv, enc)
        pad = pt[-1]
        if 1 <= pad <= 16:
            pt = pt[:-pad]
        return pt

    def lock(self):
        # Lock shares VERIFY's header (80 C5 05 06). The manual shows P3=01/data=00,
        # but this CLI always frames with extended Lc, so the applet distinguishes
        # lock from verify by DATA: lock = a single 0x00 byte, verify = IV||... (>=32).
        self.transport.send_command(APDU(CommandType.CMD_VERIFY_OTP_PIN, data=b"\x00", force_short_lc=True))


class PinFlag:
    """Parsed 1.12 Read OTP PIN Flag response."""

    def __init__(self, alg_id, pin_retry, pin_len, max_retry, fp_enable,
                 pub_ver, pub_crc, iv, enc_rand):
        self.alg_id = alg_id
        self.pin_retry = pin_retry
        self.pin_len = pin_len
        self.max_retry = max_retry
        self.fp_enable = fp_enable
        self.pub_ver = pub_ver
        self.pub_crc = pub_crc
        self.iv = iv
        self.enc_rand = enc_rand

    @property
    def pin_set(self) -> bool:
        # Real firmware leaves PinAlgId=0x07 and PinRetry=100 even when unset;
        # OtpPinLen == 0 is the only reliable "no PIN" signal.
        return self.pin_len != 0

    @classmethod
    def parse(cls, resp: bytes) -> "PinFlag":
        # Minimum status is 4 bytes: AlgId Retry PinLen MaxRetry (OEM Lc=04 read).
        if len(resp) < 4:
            raise ValueError("PIN flag response too short: %d bytes" % len(resp))
        alg_id    = resp[0]
        pin_retry = resp[1]
        pin_len   = resp[2]
        max_retry = resp[3]
        fp_enable = resp[4] if len(resp) >= 5 else 0
        pub_ver = pub_crc = None
        iv = enc_rand = None
        if len(resp) >= 9:
            pub_ver = struct.unpack(">H", resp[5:7])[0]
            pub_crc = struct.unpack(">H", resp[7:9])[0]
        if len(resp) >= 41:
            iv = resp[9:25]
            enc_rand = resp[25:41]
        return cls(alg_id, pin_retry, pin_len, max_retry, fp_enable,
                   pub_ver, pub_crc, iv, enc_rand)


def _pkcs5_pad(data: bytes, block: int = 16) -> bytes:
    n = block - (len(data) % block)
    return data + bytes([n]) * n


def _validate_pin(pin: bytes):
    """Enforce the R3.4 OTP-PIN policy client-side, so weak PINs get a clear
    message instead of a cryptic 6A80 from the device.

    Numeric (>= 6 digits; the minimum is configurable upward, 6 is the floor):
      - no ascending/descending sequences (123456, 654321)
      - no all-identical digits (111111)
      - no palindrome / mirror numbers (321123, 69233296)
      - no single digit appearing more than 3 times (111123, 990000)
    Alphanumeric (>= 10 chars): must use >= 2 of {upper, lower, digit, special}.
    """
    try:
        text = pin.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("PIN must be ASCII")
    if len(pin) > 255:
        raise ValueError("PIN too long")

    if text.isdigit():
        if len(text) < 6:
            raise ValueError("numeric PIN must be at least 6 digits")
        if len(set(text)) == 1:
            raise ValueError("PIN rejected: all digits identical (e.g. 111111)")
        asc = all(ord(b) - ord(a) == 1 for a, b in zip(text, text[1:]))
        desc = all(ord(a) - ord(b) == 1 for a, b in zip(text, text[1:]))
        if asc or desc:
            raise ValueError("PIN rejected: sequential digits (e.g. 123456 / 654321)")
        if text == text[::-1]:
            raise ValueError("PIN rejected: palindrome / mirror number (e.g. 321123)")
        from collections import Counter
        if max(Counter(text).values()) > 3:
            raise ValueError(
                "PIN rejected: a digit repeats more than 3 times (e.g. 111123, 990000)")
    else:
        if len(text) < 10:
            raise ValueError("alphanumeric PIN must be at least 10 characters")
        cats = 0
        cats += any(c.isupper() for c in text)
        cats += any(c.islower() for c in text)
        cats += any(c.isdigit() for c in text)
        cats += any(not c.isalnum() for c in text)
        if cats < 2:
            raise ValueError(
                "alphanumeric PIN must include at least two of: uppercase, "
                "lowercase, digits, special characters")
