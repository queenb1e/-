from __future__ import annotations

import os

from crypto_utils import aes_cbc_decrypt, aes_cbc_encrypt


KEY = os.urandom(16)
IV = os.urandom(16)
PREFIX = b"comment1=cooking%20MCs;userdata="
SUFFIX = b";comment2=%20like%20a%20pound%20of%20bacon"


def quote_userdata(userdata: bytes) -> bytes:
    return userdata.replace(b";", b"%3B").replace(b"=", b"%3D")


def encrypt_userdata(userdata: bytes) -> bytes:
    return aes_cbc_encrypt(PREFIX + quote_userdata(userdata) + SUFFIX, KEY, IV)


def is_admin(ciphertext: bytes) -> bool:
    plaintext = aes_cbc_decrypt(ciphertext, KEY, IV)
    return b";admin=true;" in plaintext


def bitflip_attack() -> bytes:
    block_size = 16
    attack_text = b"A" * block_size
    ciphertext = bytearray(encrypt_userdata(attack_text))
    desired = b";admin=true;AAAA"

    prefix_offset = len(PREFIX)
    target_block = prefix_offset // block_size
    previous_block_offset = (target_block - 1) * block_size

    for index, desired_byte in enumerate(desired):
        ciphertext[previous_block_offset + index] ^= ord("A") ^ desired_byte

    return bytes(ciphertext)


def main() -> None:
    forged = bitflip_attack()
    print(f"admin: {is_admin(forged)}")
    print("pass" if is_admin(forged) else "fail")


if __name__ == "__main__":
    main()
