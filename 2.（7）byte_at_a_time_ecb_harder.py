from __future__ import annotations

import os
import random

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
RANDOM_PREFIX = os.urandom(random.randint(1, 64))


def oracle(data: bytes) -> bytes:
    return aes_ecb_encrypt(RANDOM_PREFIX + data + UNKNOWN_STRING, KEY)


def find_prefix_alignment(block_size: int = BLOCK_SIZE) -> tuple[int, int]:
    for pad_length in range(block_size):
        probe = b"A" * pad_length + b"B" * (block_size * 2)
        blocks = split_blocks(oracle(probe), block_size)
        for index in range(len(blocks) - 1):
            if blocks[index] == blocks[index + 1]:
                return pad_length, index
    raise ValueError("could not align controlled input")


def detect_unknown_length(alignment: bytes, controlled_block: int, block_size: int) -> int:
    base_length = len(oracle(alignment))
    for pad_length in range(1, block_size + 1):
        if len(oracle(alignment + b"A" * pad_length)) > base_length:
            aligned_prefix_length = controlled_block * block_size
            return base_length - aligned_prefix_length - pad_length
    raise ValueError("could not detect unknown length")


def decrypt_suffix() -> bytes:
    block_size = BLOCK_SIZE
    if not detect_ecb(oracle(b"A" * (block_size * 6)), block_size):
        raise ValueError("oracle is not using ECB")

    alignment_pad, controlled_block = find_prefix_alignment(block_size)
    alignment = b"A" * alignment_pad
    discovered = b""
    unknown_length = detect_unknown_length(alignment, controlled_block, block_size)

    for _ in range(unknown_length):
        pad_length = block_size - 1 - (len(discovered) % block_size)
        prefix = alignment + b"A" * pad_length
        block_index = controlled_block + (len(discovered) // block_size)
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
    print(f"random prefix length: {len(RANDOM_PREFIX)}")
    print(plaintext.decode("utf-8"))
    print("pass" if plaintext == UNKNOWN_STRING else "fail")


if __name__ == "__main__":
    main()
