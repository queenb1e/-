from __future__ import annotations

import os

from crypto_utils import BLOCK_SIZE, aes_ecb_encrypt, detect_ecb, pkcs7_unpad, split_blocks, b64decode_clean


UNKNOWN_STRING = b64decode_clean(
    """
    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK
    """
)
KEY = os.urandom(16)


def oracle(data: bytes) -> bytes:
    return aes_ecb_encrypt(data + UNKNOWN_STRING, KEY)


def detect_block_size() -> int:
    base_length = len(oracle(b""))
    for size in range(1, 65):
        new_length = len(oracle(b"A" * size))
        if new_length > base_length:
            return new_length - base_length
    raise ValueError("could not detect block size")


def detect_unknown_length(block_size: int) -> int:
    base_length = len(oracle(b""))
    for pad_length in range(1, block_size + 1):
        if len(oracle(b"A" * pad_length)) > base_length:
            return base_length - pad_length
    raise ValueError("could not detect unknown length")


def decrypt_suffix() -> bytes:
    block_size = detect_block_size()
    if block_size != BLOCK_SIZE:
        raise ValueError("unexpected block size")
    if not detect_ecb(oracle(b"A" * (block_size * 4)), block_size):
        raise ValueError("oracle is not using ECB")

    discovered = b""
    unknown_length = detect_unknown_length(block_size)

    for _ in range(unknown_length):
        pad_length = block_size - 1 - (len(discovered) % block_size)
        prefix = b"A" * pad_length
        block_index = len(discovered) // block_size
        target_block = split_blocks(oracle(prefix), block_size)[block_index]

        dictionary = {}
        known_prefix = prefix + discovered
        for candidate in range(256):
            block = split_blocks(oracle(known_prefix + bytes([candidate])), block_size)[block_index]
            dictionary[block] = candidate

        if target_block not in dictionary:
            break
        discovered += bytes([dictionary[target_block]])

    return discovered


def main() -> None:
    plaintext = decrypt_suffix()
    print(plaintext.decode("utf-8"))
    print("pass" if plaintext == UNKNOWN_STRING else "fail")


if __name__ == "__main__":
    main()
