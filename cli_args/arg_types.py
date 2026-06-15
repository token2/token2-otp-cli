import base64
import binascii
from argparse import ArgumentTypeError
from typing import Optional, List


class ArgEnumType(object):
    def __init__(self, enum_class):
        self.enum_class = enum_class

    def __call__(self, value):
        try:
            return self.enum_class[value]
        except IndexError:
            raise ArgumentTypeError("Unsupported value of " + self.enum_class.__name__)


class ArgInt(object):
    def __init__(self, min: Optional[int] = None, max: Optional[int] = None, one_of: Optional[List[int]] = None):
        self.min = min
        self.max = max
        self.one_of = one_of

    def __call__(self, value):
        try:
            value = int(value)
        except ValueError:
            raise ArgumentTypeError("Required an integer.")

        if self.min is not None and self.min > value:
            raise ArgumentTypeError("Lowest accepted value is: " + self.min)

        if self.max is not None and self.max < value:
            raise ArgumentTypeError("Highest accepted value is: " + self.max)

        if self.one_of is not None and value not in self.one_of:
            raise ArgumentTypeError("Value must be one of: " + str(self.one_of))

        return value


class ArgStr(object):
    def __init__(self, min, max):
        self.min = min
        self.max = max

    def __call__(self, value):
        if not isinstance(value, str):
            raise ArgumentTypeError("Required a string.")

        if self.min > len(value):
            raise ArgumentTypeError("The value could not be shorter than " + str(self.min) + " characters.")

        if self.max < len(value):
            raise ArgumentTypeError("The value could be no longer than " + str(self.max) + " characters.")

        return value


class ArgBytes(object):
    def __init__(self, min, max):
        self.min = min
        self.max = max

    def __call__(self, value):
        if not isinstance(value, str):
            raise ArgumentTypeError("Required a string.")

        if self.min > len(value):
            raise ArgumentTypeError("The value could not be shorter than " + str(self.min) + " characters.")

        if self.max < len(value):
            raise ArgumentTypeError("The value could be no longer than " + str(self.max) + " characters.")

        return value.encode('ascii')


class ArgSeed(object):
    def __init__(self, decoded_max):
        self.decoded_max = decoded_max

    def __call__(self, value):
        r = len(value) % 8

        if r != 0:
            pad = 8 - r
            value += ("=" * pad)

        try:
            decoded_val = base64.b32decode(value.encode('ascii'))
        except binascii.Error:
            raise ArgumentTypeError("Failed to decode Base32.")

        if len(decoded_val) < 1:
            raise ArgumentTypeError("Empty seed.")

        if len(decoded_val) > self.decoded_max:
            raise ArgumentTypeError(
                "Maximal length of seed is " + str(self.decoded_max) + " bytes after decoding, got: " + str(
                    len(decoded_val)))

        return decoded_val
