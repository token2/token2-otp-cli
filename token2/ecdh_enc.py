import binascii
import hashlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from ecdsa import ECDH, NIST256p

CIPHER_IV_1 = binascii.unhexlify("9DD8918E34F3CCAB08CB7518F71938F1")
CIPHER_IV_2 = binascii.unhexlify("00000000000000000000000000000000")


def encrypt_payload_ecdh(token_pk, payload, iv):
    ecdh = ECDH(curve=NIST256p)
    ecdh.generate_private_key()
    ecdh.load_received_public_key_bytes(b"\x04" + token_pk, "uncompressed")
    secret = ecdh.generate_sharedsecret_bytes()
    session_key = hashlib.sha256(secret).digest()

    cipher = AES.new(session_key, AES.MODE_CBC, IV=iv)
    cleartext = pad(payload, block_size=16)

    our_pk = ecdh.get_public_key().to_string('uncompressed')[1:]
    ciphertext = cipher.encrypt(cleartext)

    return our_pk + ciphertext
