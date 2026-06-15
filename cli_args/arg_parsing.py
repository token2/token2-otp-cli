import argparse
import sys

from cli_args.arg_types import ArgEnumType, ArgInt, ArgSeed, ArgBytes
from token2.data_structures import OTPType, OTPAlgorithm, OTPButtonFlag

parser = argparse.ArgumentParser(
    description='Token2 HOTP/TOTP CLI Tool'
)

parser.add_argument("--json", action='store_const', const=True, default=False)
subparsers = parser.add_subparsers(help='command to be executed', dest='command')

read_serial_no_parser = subparsers.add_parser('read_serial_no',
                                              help='read device\'s serial number')

set_btn_seed_parser = subparsers.add_parser('set_btn_seed',
                                            help='set the seed of HOTP generator triggered by button press')
set_btn_seed_parser.add_argument("--code-length", default=6, type=ArgInt(one_of=[6, 8]),
                                 help="number of digits; one of: 6, 8")
set_btn_seed_parser.add_argument("--seed", type=ArgSeed(decoded_max=64), required=True,
                                 help="seed string as Base32; max: 64 bytes after decoding")
set_btn_seed_parser.add_argument("--short-touch", dest='long_touch', action='store_const',
                                 const=False, default=True,
                                 help="trigger HOTP generator with a short button press (instead of requiring to hold it for 2 seconds)")
set_btn_seed_parser.add_argument("--dont-send-enter", dest='dont_send_enter', action='store_const',
                                 const=True, default=False, help="don't send ENTER key after typing the HOTP code")
set_btn_seed_parser.add_argument("--numeric-keyboard", dest='numeric_keyboard', action='store_const',
                                 const=True, default=False, help="use numeric keyboard for typing HOTP code")

delete_btn_seed_parser = subparsers.add_parser('delete_btn_seed',
                                               help='delete the seed of HOTP generator triggered by button press')

get_all_parser = subparsers.add_parser('get_all', help='get all OTP entries')

read_entry_parser = subparsers.add_parser('read_entry', help='read a particular OTP entry')
read_entry_parser.add_argument("--app-name", default='', type=ArgBytes(min=0, max=64),
                               help="target entry's application name (optional)")
read_entry_parser.add_argument("--account-name", type=ArgBytes(min=1, max=64), required=True,
                               help="target entry's account name")

write_entry_parser = subparsers.add_parser('write_entry', help='write or update an OTP entry on the token')
write_entry_parser.add_argument("--type", default="TOTP", type=ArgEnumType(OTPType),
                                help="default: TOTP; one of: TOTP, HOTP")
write_entry_parser.add_argument("--algorithm", default="SHA1", type=ArgEnumType(OTPAlgorithm),
                                help="default: SHA1; one of: SHA1, SHA256")
write_entry_parser.add_argument("--timestep", default=30, type=ArgInt(min=1, max=0xFFFF),
                                help="default: 30; number of seconds after the code is re-generated, only applicable to TOTP")
write_entry_parser.add_argument("--code-length", default=6, type=ArgInt(min=4, max=10),
                                help="number of digits; min: 4, max: 10")
write_entry_parser.add_argument("--button-required", dest='btn_flag', action='store_const',
                                const=OTPButtonFlag.BTN_REQUIRED, default=OTPButtonFlag.BTN_NOT_REQUIRED,
                                help="require a physical button press when reading this OTP code over USB")
write_entry_parser.add_argument("--app-name", default='', type=ArgBytes(min=0, max=64),
                                help="application name (optional); max: 64 characters")
write_entry_parser.add_argument("--account-name", type=ArgBytes(min=1, max=64), required=True,
                                help="account name; max: 64 characters")
write_entry_parser.add_argument("--seed", type=ArgSeed(decoded_max=64), required=True,
                                help="seed string as Base32; max: 64 bytes after decoding")

delete_entry_parser = subparsers.add_parser('delete_entry', help='delete OTP entry on the token')
delete_entry_parser.add_argument("--app-name", default='', type=ArgBytes(min=0, max=64),
                                 help="target entry's application name (optional)")
delete_entry_parser.add_argument("--account-name", type=ArgBytes(min=1, max=64), required=True,
                                 help="target entry's account name")

erase_all_parser = subparsers.add_parser('erase_all', help='erase all OTP entries on the token')

args = parser.parse_args()

if not args.command:
    parser.print_usage()
    sys.exit(0)
