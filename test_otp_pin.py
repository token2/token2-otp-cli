#!/usr/bin/env python3
"""
test_otp_pin.py — validate token2/otp_pin.py without hardware.

A MockDevice mirrors the applet's V1.2 PIN behaviour (ECC521-signed handshake,
HKDF session keys, encrypted single-use challenge, Set/Verify/Change/Lock). The
client module is driven against it exactly as it would drive a real card, so a
green run means the host-side crypto and framing are self-consistent with the
spec. It does NOT prove on-card behaviour — run against hardware for that.

Requires: pip install pycryptodome ecdsa
Run:      python3 test_otp_pin.py   (from the CLI repo root)
"""
import hashlib
import hmac
import os
import struct
import sys

from Crypto.Cipher import AES
from ecdsa import ECDH, NIST256p, NIST521p, SigningKey
from ecdsa.util import sigencode_string

from token2.data_structures import APDU, CommandType
from token2.otp_pin import OtpPinSession, PinFlag, _pkcs5_pad
from token2 import Token2
from token2.data_structures import EnumCodesSubCommand, OTPType, OTPAlgorithm, OTPButtonFlag

IV1 = bytes.fromhex("9DD8918E34F3CCAB08CB7518F71938F1")
INFO_MAC = b"TOTP HMAC key" + b"\x01"
INFO_ENC = b"TOTP AES key" + b"\x01"

PASS = []
def ok(name, cond):
    assert cond, "FAIL: " + name
    PASS.append(name); print("  ok  " + name)


def _hmac256(k, d): return hmac.new(k, d, hashlib.sha256).digest()
def _enc(k, iv, d): return AES.new(k, AES.MODE_CBC, IV=iv).encrypt(d)
def _dec(k, iv, d): return AES.new(k, AES.MODE_CBC, IV=iv).decrypt(d)


class MockDevice:
    """Mirrors the applet's PIN state machine for the crypto paths under test."""
    def __init__(self):
        self.dev_sign_sk = SigningKey.generate(curve=NIST521p)
        self.dev_verify_key = self.dev_sign_sk.get_verifying_key()
        self.pin_hash = None
        self.max_retry = 100
        self.retry = 100
        self.locked = False
        self.window_open = False
        self._sess_enc = None
        self._sess_mac = None
        self._rand = None
        self.last_set_ok = False

    # transport.send_command(apdu) -> response bytes (SW stripped, raises on error)
    def send_command(self, cmd: APDU, detect_btn_wait=False) -> bytes:
        h = cmd.hdr.value
        data = cmd.data
        if cmd.hdr == CommandType.CMD_READ_AGREEMENT_PUBKEY:
            return self._agreement(data)
        if cmd.hdr == CommandType.CMD_READ_OTP_PIN_FLAG:
            return self._flag(len(cmd.data))
        if cmd.hdr == CommandType.CMD_SET_OTP_PIN:
            return self._set(data)
        if cmd.hdr == CommandType.CMD_VERIFY_OTP_PIN:
            if data == b"\x00":
                self.window_open = False   # lock
                return b""
            return self._verify(data)
        if cmd.hdr == CommandType.CMD_CHANGE_OTP_PIN:
            return self._change(data)
        if cmd.hdr == CommandType.CMD_ENUM_CODES:
            return self._enum(cmd.data)
        raise AssertionError("unexpected command " + cmd.hdr.name)

    def make_enum_plaintext(self):
        # one TOTP entry: type,alg,ts(2),len,btn,applen,app,acctlen,acct,codelen,code
        e = bytes([0x01, 0xC1, 0x00, 0x1E, 0x06, 0x00,
                   0x04]) + b"Test" + bytes([0x05]) + b"alice" + bytes([0x06]) + b"123456"
        return e

    def _enum(self, data):
        # data = sub(1) || ts(8) ; PIN mode -> return IV||EncData||Auth
        pt = self.make_enum_plaintext()
        if self.pin_hash is not None:
            if not self.window_open:
                raise _sw(b"\x69\x82")
            iv = os.urandom(16)
            padded = _pkcs5_pad(pt)
            enc = _enc(self._sess_enc, iv, padded)
            auth = _hmac256(self._sess_mac, enc)[:16]
            return iv + enc + auth
        return pt

    def _agreement(self, host_pub):
        ecdh = ECDH(curve=NIST256p)
        ecdh.generate_private_key()
        dev_pub = ecdh.get_public_key().to_string("uncompressed")[1:]
        ecdh.load_received_public_key_bytes(b"\x04" + host_pub, "uncompressed")
        shared = ecdh.generate_sharedsecret_bytes()
        prk = _hmac256(b"\x00"*32, shared[:32])
        self._sess_mac = _hmac256(prk, INFO_MAC)
        self._sess_enc = _hmac256(prk, INFO_ENC)
        sig = self.dev_sign_sk.sign(host_pub + dev_pub, hashfunc=hashlib.sha512,
                                    sigencode=sigencode_string)
        return dev_pub + sig

    def _flag(self, req_len=41):
        # Status bytes are always readable (even pre-session). AlgId/Retry stay
        # populated even with no PIN; OtpPinLen is the reliable signal.
        alg = 0x07
        plen = (len(self._pin_plain) if self.pin_hash else 0)
        full = bytes([alg, self.retry, plen, self.max_retry, 0x00])
        full += struct.pack(">H", 1) + struct.pack(">H", 0x1234)
        # EncRand only exists inside a session and only when the challenge is asked for.
        if req_len > 9:
            if self._sess_enc is None:
                raise _sw(b"\x69\x85")
            iv = os.urandom(16)
            self._rand = os.urandom(16)
            full += iv + _enc(self._sess_enc, iv, self._rand)
        return full[:req_len]

    def _set(self, data):
        iv, enc, auth = data[:16], data[16:32], data[32:48]
        assert _hmac256(self._sess_mac, enc)[:16] == auth, "set: bad auth tag"
        pt = _dec(self._sess_enc, iv, enc)
        pad = pt[-1]; pt = pt[:-pad]
        alg, retry, plen = pt[0], pt[1], pt[2]
        pin = pt[3:3+plen]
        self.pin_hash = hashlib.sha256(pin).digest()
        self._pin_plain = pin
        self.max_retry = retry or 100
        self.retry = self.max_retry
        self.last_set_ok = True
        return b""

    def _verify(self, data):
        iv, enc2 = data[:16], data[16:]
        pin_hash_enc = _dec(self._sess_enc, iv, enc2)
        iv2 = hashlib.sha256(self._rand).digest()[:16]
        expected = _enc(self.pin_hash, iv2, self._rand)
        self._rand = None
        if pin_hash_enc[:16] == expected[:16]:
            self.retry = self.max_retry
            self.window_open = True
            return b""
        self.retry -= 1
        if self.retry <= 0:
            self.locked = True
        raise _sw(b"\x69\x82")

    def _change(self, data):
        iv, enc, auth, oldenc = data[:16], data[16:32], data[32:48], data[48:64]
        assert _hmac256(self._sess_mac, enc + oldenc)[:16] == auth, "change: bad tag"
        old_hash16 = _dec(self._sess_enc, iv, oldenc)
        assert old_hash16 == self.pin_hash[:16], "change: wrong old PIN"
        pt = _dec(self._sess_enc, iv, enc); pad = pt[-1]; pt = pt[:-pad]
        plen = pt[2]; pin = pt[3:3+plen]
        if plen == 0:
            self.pin_hash = None    # delete
        else:
            self.pin_hash = hashlib.sha256(pin).digest()
            self._pin_plain = pin
        return b""


class _sw(Exception):
    def __init__(self, sw): self.sw = sw


# ---------------------------------------------------------------- tests
print("[1] handshake: signature verifies, session keys agree")
dev = MockDevice()
s = OtpPinSession.establish(dev, verify_device_key=dev.dev_verify_key)
ok("client derived a session enc key", len(s.session_enc_key) == 32)
ok("client and device agree on SessionEncKey", s.session_enc_key == dev._sess_enc)
ok("client and device agree on SessionMacKey", s.session_mac_key == dev._sess_mac)

print("[2] handshake: a tampered device key is rejected")
from ecdsa import BadSignatureError
wrong = SigningKey.generate(curve=NIST521p).get_verifying_key()
try:
    OtpPinSession.establish(MockDevice(), verify_device_key=wrong)
    ok("bad device key rejected", False)
except BadSignatureError:
    ok("bad device key rejected", True)

print("[3] set PIN, then verify opens the window")
dev = MockDevice()
s = OtpPinSession.establish(dev, verify_device_key=dev.dev_verify_key)
s.read_flag()
s.set_pin(b"123123")
ok("device stored a PIN", dev.pin_hash is not None)
s2 = OtpPinSession.establish(dev, verify_device_key=dev.dev_verify_key)
s2.read_flag()
s2.verify(b"123123")
ok("correct PIN opens the window", dev.window_open is True)

print("[4] wrong PIN fails and decrements retry")
dev = MockDevice()
s = OtpPinSession.establish(dev); s.read_flag(); s.set_pin(b"123123")
s2 = OtpPinSession.establish(dev); s2.read_flag()
try:
    s2.verify(b"999999"); ok("wrong PIN raised", False)
except _sw as e:
    ok("wrong PIN raised 6982", e.sw == b"\x69\x82")
ok("retry decremented", dev.retry == 99)

print("[5] Rand is single-use (fresh challenge required per verify)")
dev = MockDevice()
s = OtpPinSession.establish(dev); s.read_flag(); s.set_pin(b"123123")
s2 = OtpPinSession.establish(dev); s2.read_flag()
first_rand = s2._rand
s2.verify(b"123123")
ok("client cleared its cached Rand after verify", s2._rand is None)
ok("device cleared Rand after verify", dev._rand is None)

print("[6] change PIN, then new PIN verifies and old fails")
dev = MockDevice()
s = OtpPinSession.establish(dev); s.read_flag(); s.set_pin(b"123123")
sc = OtpPinSession.establish(dev); sc.read_flag()
sc.change_pin(b"123123", b"456456")
sv = OtpPinSession.establish(dev); sv.read_flag()
sv.verify(b"456456")
ok("new PIN verifies after change", dev.window_open is True)
dev.window_open = False
sv2 = OtpPinSession.establish(dev); sv2.read_flag()
try:
    sv2.verify(b"123123"); ok("old PIN rejected after change", False)
except _sw:
    ok("old PIN rejected after change", True)

print("[7] delete PIN removes it")
dev = MockDevice()
s = OtpPinSession.establish(dev); s.read_flag(); s.set_pin(b"123123")
sd = OtpPinSession.establish(dev); sd.read_flag()
sd.delete_pin(b"123123")
ok("device reports no PIN after delete", dev.pin_hash is None)

print("[8] alphanumeric length policy enforced client-side")
dev = MockDevice(); s = OtpPinSession.establish(dev); s.read_flag()
try:
    s.set_pin(b"abc123"); ok("short alnum rejected", False)
except ValueError:
    ok("short alnum rejected", True)
s.set_pin(b"abcdef1234")  # 10 chars ok
ok("10-char alnum accepted", dev.pin_hash is not None)

print("[9] lock ends the window")
dev = MockDevice()
s = OtpPinSession.establish(dev); s.read_flag(); s.set_pin(b"123123")
sv = OtpPinSession.establish(dev); sv.read_flag(); sv.verify(b"123123")
ok("window open before lock", dev.window_open is True)
sv.lock()
ok("window closed after lock", dev.window_open is False)

print("[10] PinFlag parsing")
f = PinFlag.parse(bytes([0x07, 90, 6, 100, 0]) + struct.pack(">H", 2)
                  + struct.pack(">H", 0xABCD) + b"\x11"*16 + b"\x22"*16)
ok("pin_set true, fields parsed",
   f.pin_set and f.pin_retry == 90 and f.pin_len == 6 and f.pub_crc == 0xABCD)
# real firmware leaves alg=0x07, retry=100 even when unset; only OtpPinLen=0 matters
f0 = PinFlag.parse(bytes([0x07, 100, 0, 0, 0]) + b"\x00"*4)
ok("pin_set false when unset (alg/retry still populated)", f0.pin_set is False)

print("[11] challenge flag read requires a session; status read does not")
dev = MockDevice()
# status-only (<=9 bytes) works pre-session:
st = dev._flag(9)
ok("status flag readable pre-session", len(st) == 9)
try:
    dev._flag(41); ok("session-less challenge rejected", False)
except _sw as e:
    ok("session-less challenge raises 6985", e.sw == b"\x69\x85")

print("[12] PIN-mode enum response is decrypted and parsed")
dev = MockDevice()
s0 = OtpPinSession.establish(dev); s0.read_flag(); s0.set_pin(b"3219918")
client = Token2(dev)
client.unlock(b"3219918")
entries = list(client.enum_codes(0))
ok("decrypted one entry from PIN-mode enum", len(entries) == 1)
ok("entry fields correct after decrypt",
   entries[0].app_name == b"Test" and entries[0].account_name == b"alice"
   and entries[0].otp_code == "123456")

print("[13] CCID XfrBlock framing matches the companion-app capture")
import struct as _struct
class _MockCcidEp:
    """A mock bulk endpoint pair replaying captured CCID XfrBlock exchanges."""
    def __init__(self, script):
        self.script=script; self.idx=0; self.stage="cmd"; self._out=None
    # OUT endpoint
    def write(self, msg):
        msg=bytes(msg)
        assert msg[0]==0x6F, "expected PC_to_RDR_XfrBlock"
        dwlen=_struct.unpack("<I", msg[1:5])[0]
        apdu=msg[10:10+dwlen]
        self._dispatch(apdu.hex()); return len(msg)
    # IN endpoint
    def read(self, size, timeout=0):
        return self._pending
    def _frame(self, hx):
        b=bytes.fromhex(hx)
        self._pending=bytes([0x80])+_struct.pack("<I",len(b))+bytes([0,0,0,0,0])+b
    def _dispatch(self, ah):
        exp,interims,final=self.script[self.idx]
        if self.stage=="cmd":
            assert ah.lower()==exp.lower(), "CCID APDU mismatch: %s != %s"%(ah,exp)
            if interims: self._frame(interims[0]); self.stage="getresp"
            else: self._frame(final); self.idx+=1
        else:
            assert ah.lower().startswith("80c000"), "expected GET RESPONSE, got "+ah
            self._frame(final); self.idx+=1; self.stage="cmd"

import importlib.util as _ilu, types as _types, sys as _sys
if "transports" not in _sys.modules:
    _pkg=_types.ModuleType("transports"); _pkg.__path__=["transports"]; _sys.modules["transports"]=_pkg
for _n in ("base","exc"):
    if "transports."+_n not in _sys.modules:
        _sp=_ilu.spec_from_file_location("transports."+_n, "transports/%s.py"%_n)
        _mm=_ilu.module_from_spec(_sp); _sp.loader.exec_module(_mm); _sys.modules["transports."+_n]=_mm
# stub usb.core / usb.util so importing the transport module doesn't require pyusb
if "usb" not in _sys.modules:
    _usb=_types.ModuleType("usb"); _core=_types.ModuleType("usb.core"); _util=_types.ModuleType("usb.util")
    _core.find=lambda **k: None
    class _USBError(Exception): pass
    _core.USBError=_USBError
    _util.endpoint_direction=lambda a:0; _util.endpoint_type=lambda a:0
    _util.ENDPOINT_OUT=0; _util.ENDPOINT_IN=0x80; _util.ENDPOINT_TYPE_BULK=2
    _util.dispose_resources=lambda d:None
    _usb.core=_core; _usb.util=_util
    _sys.modules["usb"]=_usb; _sys.modules["usb.core"]=_core; _sys.modules["usb.util"]=_util
_sp=_ilu.spec_from_file_location("transports.apdu_hid","transports/apdu_hid.py")
_ccidmod=_ilu.module_from_spec(_sp); _sp.loader.exec_module(_ccidmod)

_cap=[("00a4040008f00000014f747001", ["6104"], "313030309000"),
      ("80c5050409000000000000000000", ["6109"], "00000000000001222b9000")]
_ep=_MockCcidEp(_cap)
_t=_ccidmod.ApduHidTransport()
_t.ep_out=_ep; _t.ep_in=_ep
_r1=_t.send_command(APDU(CommandType.CMD_ISO_SELECT, bytes.fromhex("f00000014f747001"), force_short_lc=True))
ok("CCID SELECT framing + 61xx assembly", _r1.hex()=="31303030")
_r2=_t.send_command(APDU(CommandType.CMD_READ_OTP_PIN_FLAG, data=b"\x00"*9, force_short_lc=True))
ok("CCID flag09 framing + 61xx assembly", _r2.hex()=="00000000000001222b")

print("[14] PIN policy validation matches the firmware rules")
from token2.otp_pin import _validate_pin as _vp
def _accepts(pin):
    try:
        _vp(pin); return True
    except ValueError:
        return False
ok("valid numeric PIN accepted (3219918)", _accepts(b"3219918"))
ok("valid random numeric accepted (481920)", _accepts(b"481920"))
ok("ascending rejected (123456)", not _accepts(b"123456"))
ok("descending rejected (654321)", not _accepts(b"654321"))
ok("all-identical rejected (111111)", not _accepts(b"111111"))
ok("palindrome rejected (321123)", not _accepts(b"321123"))
ok("mirror rejected (69233296)", not _accepts(b"69233296"))
ok(">3 repeats rejected (111123)", not _accepts(b"111123"))
ok(">3 repeats rejected (990000)", not _accepts(b"990000"))
ok("too-short numeric rejected (12345)", not _accepts(b"12345"))
ok("alnum single-category rejected (abcdefghij)", not _accepts(b"abcdefghij"))
ok("alnum two-category accepted (Passw0rd12)", _accepts(b"Passw0rd12"))
ok("alnum too-short rejected (Ab1!x)", not _accepts(b"Ab1!x"))

print("[15] set_pin refuses when a PIN is already set (6A81 / flag check)")
# Mock a device whose flag shows PinLen>0; set_pin must raise PinAlreadySet
# before sending SET.
from token2.exc import PinAlreadySet as _PinAlreadySet, FunctionNotSupported as _FNS
from token2.errors import check_status_code as _csc

# 6a81 maps to FunctionNotSupported
_raised = None
try:
    _csc(b"\x6a\x81")
except _FNS:
    _raised = "fns"
ok("6a81 -> FunctionNotSupported", _raised == "fns")

# set_pin on a device reporting an existing PIN raises PinAlreadySet
class _FlagSetDev:
    def __init__(self): self.n = 0
    def send_command(self, cmd, detect_btn_wait=False):
        apdu = cmd.serialize()
        if apdu[1] == 0xa4:
            return b""
        if apdu[:4].hex() == "80c50504":  # flag read -> report PinLen=7
            return bytes([0x07,0x64,0x07,0x64,0,0,1,0x22,0x2b])[:apdu[4]]
        if apdu[:4].hex() == "80c50509":  # handshake
            from ecdsa import SigningKey, NIST256p, NIST521p
            from ecdsa.util import sigencode_string
            import hashlib as _h
            sk=SigningKey.generate(curve=NIST256p); dp=sk.get_verifying_key().to_string("uncompressed")[1:]
            s5=SigningKey.generate(curve=NIST521p); hp=apdu[5:5+64]
            return dp+s5.sign(hp+dp, hashfunc=_h.sha512, sigencode=sigencode_string)
        return b""
_dev=_FlagSetDev()
from token2 import Token2 as _T2
_sess=_T2(_dev).open_pin_session()
_raised=False
try:
    _sess.set_pin(b"481920")
except _PinAlreadySet:
    _raised=True
except Exception:
    _raised=False
ok("set_pin raises PinAlreadySet when PIN exists", _raised)

print(f"\nALL {len(PASS)} CHECKS PASSED")
