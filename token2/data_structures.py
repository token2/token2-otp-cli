import io
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class CommandType(Enum):
    CMD_ISO_SELECT = (0x00, 0xA4, 0x04, 0x00)
    CMD_WRITE_HOTP_SEED = (0x80, 0xC5, 0x00, 0x00)
    CMD_GET_ECDH_PUBKEY = (0x80, 0xC5, 0x01, 0x00)
    CMD_CFG_HOTP_ENTER = (0x80, 0xC5, 0x02, 0x02)
    CMD_CFG_HOTP_TOUCH = (0x80, 0xC5, 0x02, 0x04)
    CMD_CFG_HOTP_KBD_TYPE = (0x80, 0xC5, 0x02, 0x06)
    CMD_WRITE_SEED = (0x80, 0xC5, 0x05, 0x02)
    CMD_ENUM_CODES = (0x80, 0xC5, 0x05, 0x00)
    CMD_ENUM_CODES_CONTINUE = (0x80, 0xC5, 0x05, 0x01)
    CMD_GET_INFO = (0x80, 0x33, 0x00, 0x00)


class EnumCodesSubCommand(Enum):
    READ_ONE = b"\x01"
    GET_METADATA = b"\x02"
    READ_ALL = b"\x03"


@dataclass
class APDU:
    hdr: CommandType
    data: bytes

    def serialize(self, extended_length=True):
        buf = io.BytesIO()
        cla, ins, p1, p2 = self.hdr.value
        buf.write(bytes([cla, ins, p1, p2]))
        if not extended_length:
            buf.write(bytes([len(self.data)]))
        else:
            buf.write(b"\x00" + struct.pack(">H", len(self.data)))
        buf.write(self.data)

        return buf.getvalue()


class OTPType(Enum):
    HOTP = 0x00
    TOTP = 0x01


class OTPAlgorithm(Enum):
    SHA1 = 0xC1
    SHA256 = 0xC2


class OTPButtonFlag(Enum):
    BTN_NOT_REQUIRED = 0x00
    BTN_REQUIRED = 0x01


@dataclass
class BaseOTPEntry:
    type: OTPType
    algorithm: OTPAlgorithm
    timestep: int
    code_length: int
    btn_flag: OTPButtonFlag
    app_name: bytes
    account_name: bytes

    def validate(self):
        if self.timestep < 1 or self.timestep > 0xFFFF:
            raise ValueError('timestep')

        if self.code_length < 4 or self.code_length > 10:
            raise ValueError('code_length')

        if len(self.app_name) > 64:
            raise ValueError('app_name')

        if len(self.account_name) < 1 or len(self.account_name) > 64:
            raise ValueError('account_name')


@dataclass
class WriteOTPEntry(BaseOTPEntry):
    seed: bytes

    def validate(self):
        super().validate()

        if len(self.seed) < 1 or len(self.seed) > 64:
            raise ValueError('seed')

    def serialize(self):
        buf = io.BytesIO()
        buf.write(bytes([self.type.value, self.algorithm.value]))
        buf.write(struct.pack(">H", self.timestep))
        buf.write(bytes([self.code_length, self.btn_flag.value]))
        buf.write(bytes([len(self.app_name)]))
        buf.write(self.app_name)
        buf.write(bytes([len(self.account_name)]))
        buf.write(self.account_name)
        buf.write(bytes([len(self.seed)]))
        buf.write(self.seed)

        return buf.getvalue()


@dataclass
class DeleteOTPEntry:
    app_name: bytes
    account_name: bytes

    def validate(self):
        if len(self.app_name) > 64:
            raise ValueError('app_name')

        if len(self.account_name) < 1 or len(self.account_name) > 64:
            raise ValueError('account_name')

    def serialize(self):
        buf = io.BytesIO()
        buf.write(bytes([0, 0]))
        buf.write(struct.pack(">H", 0x00))
        buf.write(bytes([0, 0]))
        buf.write(bytes([len(self.app_name)]))
        buf.write(self.app_name)
        buf.write(bytes([len(self.account_name)]))
        buf.write(self.account_name)
        buf.write(bytes([0]))

        return buf.getvalue()


@dataclass
class EnumOTPEntry(BaseOTPEntry):
    otp_code: Optional[str]

    def print(self):
        app_name = self.app_name.decode('ascii', 'replace') or "<unnamed app>"
        account_name = self.account_name.decode('ascii', 'replace')
        otp_code = self.otp_code or ('*' * self.code_length)

        if self.type == OTPType.TOTP:
            print_hdr = f"{self.type.name}/{self.algorithm.name}/{self.timestep}s"
        else:
            print_hdr = f"{self.type.name}/{self.algorithm.name}"

        print(f"[{print_hdr}] {app_name} / {account_name} - {otp_code}")

    def as_json(self):
        return {
            "type": self.type.name,
            "algorithm": self.algorithm.name,
            "timestep": self.timestep if self.type == OTPType.TOTP else None,
            "app_name": self.app_name.decode('ascii', 'replace'),
            "account_name": self.account_name.decode('ascii', 'replace'),
            "otp_code": self.otp_code or None
        }

    @classmethod
    def unserialize(cls, data, full_decode=False):
        buf = io.BytesIO(data)

        while buf.tell() < len(data):
            inp_data = {}

            inp_data["type"] = OTPType(buf.read(1)[0])
            inp_data["algorithm"] = OTPAlgorithm(buf.read(1)[0])
            inp_data["timestep"] = struct.unpack(">H", buf.read(2))[0]
            inp_data["code_length"] = buf.read(1)[0]
            inp_data["btn_flag"] = OTPButtonFlag(buf.read(1)[0])
            app_name_len = buf.read(1)[0]
            inp_data["app_name"] = buf.read(app_name_len)
            account_name_len = buf.read(1)[0]
            inp_data["account_name"] = buf.read(account_name_len)
            inp_data["otp_code"]: Optional[str] = None

            if full_decode or (
                    inp_data["type"] == OTPType.TOTP and inp_data["btn_flag"] == OTPButtonFlag.BTN_NOT_REQUIRED):
                otp_code_len = buf.read(1)[0]
                inp_data["otp_code"] = buf.read(otp_code_len).decode('ascii')

            yield EnumOTPEntry(**inp_data)


@dataclass
class ReadOTPEntry:
    timestamp: int
    app_name: bytes
    account_name: bytes

    def validate(self):
        if self.timestamp < 0:
            raise ValueError('timestamp')

        if len(self.app_name) > 64:
            raise ValueError('app_name')

        if len(self.account_name) < 1 or len(self.account_name) > 64:
            raise ValueError('account_name')

    def serialize(self):
        buf = io.BytesIO()
        buf.write(struct.pack(">Q", self.timestamp))
        buf.write(bytes([len(self.app_name)]))
        buf.write(self.app_name)
        buf.write(bytes([len(self.account_name)]))
        buf.write(self.account_name)

        return buf.getvalue()


@dataclass
class SetButtonHOTPData:
    code_length: int
    seed: bytes
    long_touch: bool
    dont_send_enter: bool
    numeric_keyboard: bool

    def validate(self):
        if self.code_length not in [6, 8]:
            raise ValueError('code_length')

        if len(self.seed) < 1 or len(self.seed) > 64:
            raise ValueError('seed')

    def serialize_seed_payload(self):
        buf = io.BytesIO()
        buf.write(bytes([self.code_length]))
        buf.write(bytes([len(self.seed)]))
        buf.write(self.seed)

        return buf.getvalue()

    def serialize_cfg_enter(self):
        if self.dont_send_enter:
            return b"\x01"
        else:
            return b"\x00"

    def serialize_cfg_long_touch(self):
        if self.long_touch:
            return b"\x01"
        else:
            return b"\x00"

    def serialize_cfg_num_kbd(self):
        if self.numeric_keyboard:
            return b"\x01"
        else:
            return b"\x00"
