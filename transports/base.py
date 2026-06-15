from typing import Optional

from token2.data_structures import APDU


class BaseTransport:
    def __init__(self, *, ask_button_cb: Optional[callable] = None, debug: bool = False) -> None:
        self.ask_button_cb = ask_button_cb
        self.debug = debug

    def _debug_print(self, msg: str) -> None:
        if self.debug:
            print(msg)

    def send_command(self, cmd: APDU, detect_btn_wait: bool = False) -> bytes:
        raise RuntimeError('Not implemented.')

    def close(self):
        pass
