# Token2 T2F2 CLI OTP Tool v0.2
# Copyright (c) 2026 Token2 Sarl
# Licensed under the MIT License — see LICENSE for details.
import datetime
import json
import os
import sys

from cli_args.arg_parsing import args
from token2 import Token2
from token2.data_structures import DeleteOTPEntry, WriteOTPEntry, ReadOTPEntry, SetButtonHOTPData
from token2.exc import ExpectedCommandError
from transports import detect_token, TokenNotDetected


def process_command(args):
    has_fail = False

    def button_required_cb():
        if not args.json:
            print('Please press the button on your device.')

    use_debug = os.environ.get('DEBUG_COMMS') == '1'

    try:
        import os as _os
        # Explicit choice (CLI --transport or TOKEN2_TRANSPORT env) always wins.
        prefer = getattr(args, 'transport', None) or _os.environ.get("TOKEN2_TRANSPORT")
        # Otherwise, auto-route per command. set_pin (write from unprotected state)
        # is the one command the PC/SC path rejects with 6A80 in shared mode; it
        # defaults to the direct-CCID transport. All other PIN ops work over PC/SC.
        # Any explicit --transport/env overrides this (e.g. to try exclusive PC/SC).
        # All PIN commands (set/verify/change/remove/lock/status) work over PC/SC.
        # Default them to it; --transport apdu-hid is available for direct CCID
        # on platforms/setups where that's preferred.
        pcsc_pin_cmds = {'set_pin', 'verify_pin', 'change_pin', 'remove_pin',
                         'lock_pin', 'pin_status'}
        _cmd = getattr(args, 'command', None)
        if not prefer and _cmd in pcsc_pin_cmds:
            prefer = 'pcsc'
        transport = detect_token(ask_button_cb=button_required_cb, debug=use_debug,
                                 prefer=prefer)
    except TokenNotDetected:
        if args.json:
            print(json.dumps({"_error": "Unable to detect the device."}))
        else:
            print(f'ERROR: Unable to detect the device.')

        sys.exit(2)

    token = Token2(transport)

    ts = int(datetime.datetime.now().timestamp())

    # If the reads need an unlocked window and the user supplied --pin, verify first.
    if getattr(args, 'command', None) in ('get_all', 'read_entry') and getattr(args, 'pin', None):
        try:
            if token.pin_flag().pin_set:
                token.unlock(args.pin)
        except Exception:
            pass

    try:
        if args.command == 'read_serial_no':
            serial_no = token.read_serial_no()

            if args.json:
                print(json.dumps({"serial_no": serial_no.hex()}))
            else:
                print(serial_no.hex())

        elif args.command == 'set_btn_seed':
            spec = SetButtonHOTPData(
                code_length=args.code_length,
                seed=args.seed,
                long_touch=args.long_touch,
                dont_send_enter=args.dont_send_enter,
                numeric_keyboard=args.numeric_keyboard
            )
            token.set_btn_seed(spec)

        elif args.command == 'delete_btn_seed':
            token.delete_btn_seed()

        elif args.command == 'get_all':
            entries = list(token.enum_codes(ts))

            if args.json:
                print(json.dumps({"entries": [entry.as_json() for entry in entries]}))
            else:
                for entry in entries:
                    entry.print()

        elif args.command == 'read_entry':
            entry = token.read_entry(ReadOTPEntry(timestamp=ts, app_name=args.app_name, account_name=args.account_name))

            if args.json:
                print(json.dumps(entry.as_json()))
            else:
                entry.print()

        elif args.command == 'write_entry':
            entry = WriteOTPEntry(
                type=args.type,
                algorithm=args.algorithm,
                timestep=args.timestep,
                code_length=args.code_length,
                btn_flag=args.btn_flag,
                app_name=args.app_name,
                account_name=args.account_name,
                seed=args.seed
            )
            token.write_entry(entry)

        elif args.command == 'delete_entry':
            entry = DeleteOTPEntry(
                app_name=args.app_name,
                account_name=args.account_name
            )
            token.write_entry(entry)

        elif args.command == 'pin_status':
            flag = token.pin_flag()
            if args.json:
                print(json.dumps({"pin_set": flag.pin_set, "retry_left": flag.pin_retry,
                                  "max_retry": flag.max_retry}))
            else:
                if flag.pin_set:
                    print(f"OTP PIN is set ({flag.pin_retry}/{flag.max_retry} attempts left)")
                else:
                    print("No OTP PIN set")

        elif args.command == 'set_pin':
            # Match the companion app exactly: handshake then SET, with NO flag
            # read in between. An intervening flag read changes device state and
            # causes SET to return 6A80.
            session = token.open_pin_session()
            session.set_pin(args.pin)

        elif args.command == 'verify_pin':
            token.unlock(args.pin)

        elif args.command == 'change_pin':
            session = token.open_pin_session()
            session.read_flag()
            session.change_pin(args.old_pin, args.new_pin)

        elif args.command == 'remove_pin':
            session = token.open_pin_session()
            session.read_flag()
            session.delete_pin(args.pin)

        elif args.command == 'lock_pin':
            token.open_pin_session().lock()

        elif args.command == 'erase_all':
            token.erase_all()
    except (ExpectedCommandError, ValueError) as e:
        has_fail = True

        if args.json:
            print(json.dumps({"_error": str(e)}))
        else:
            print(f'ERROR: {str(e)}')
    finally:
        transport.close()

    if has_fail:
        sys.exit(1)


if __name__ == "__main__":
    process_command(args)
