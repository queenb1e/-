from __future__ import annotations

import base64
from functools import lru_cache


BLOCK_SIZE = 16

SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

INV_SBOX = [0] * 256
for index, value in enumerate(SBOX):
    INV_SBOX[value] = index

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("inputs must have the same length")
    return bytes(left_byte ^ right_byte for left_byte, right_byte in zip(left, right))


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if block_size <= 0 or block_size > 255:
        raise ValueError("block size must be between 1 and 255")
    padding_length = block_size - (len(data) % block_size)
    if padding_length == 0:
        padding_length = block_size
    return data + bytes([padding_length]) * padding_length


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("invalid PKCS#7 padded data length")
    padding_length = data[-1]
    if padding_length == 0 or padding_length > block_size:
        raise ValueError("invalid PKCS#7 padding")
    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-padding_length]


def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    return [data[index:index + block_size] for index in range(0, len(data), block_size)]


def has_repeated_block(data: bytes, block_size: int = BLOCK_SIZE) -> bool:
    blocks = split_blocks(data, block_size)
    return len(blocks) != len(set(blocks))


def detect_ecb(ciphertext: bytes, block_size: int = BLOCK_SIZE) -> bool:
    return has_repeated_block(ciphertext, block_size)


def _gmul(left: int, right: int) -> int:
    result = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        high_bit = left & 0x80
        left = (left << 1) & 0xFF
        if high_bit:
            left ^= 0x1B
        right >>= 1
    return result


def _sub_word(word: list[int]) -> list[int]:
    return [SBOX[value] for value in word]


def _rot_word(word: list[int]) -> list[int]:
    return word[1:] + word[:1]


@lru_cache(maxsize=32)
def _expand_key(key: bytes) -> tuple[tuple[int, ...], ...]:
    if len(key) != 16:
        raise ValueError("this implementation supports AES-128 keys only")

    words = [list(key[index:index + 4]) for index in range(0, 16, 4)]
    for index in range(4, 44):
        temp = words[index - 1].copy()
        if index % 4 == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= RCON[index // 4]
        words.append([words[index - 4][offset] ^ temp[offset] for offset in range(4)])

    return tuple(
        tuple(byte for word in words[round_index * 4:(round_index + 1) * 4] for byte in word)
        for round_index in range(11)
    )


def _bytes_to_state(block: bytes) -> list[list[int]]:
    return [[block[row + 4 * column] for column in range(4)] for row in range(4)]


def _state_to_bytes(state: list[list[int]]) -> bytes:
    return bytes(state[row][column] for column in range(4) for row in range(4))


def _add_round_key(state: list[list[int]], round_key: list[int]) -> None:
    for column in range(4):
        for row in range(4):
            state[row][column] ^= round_key[row + 4 * column]


def _sub_bytes(state: list[list[int]]) -> None:
    for row in range(4):
        for column in range(4):
            state[row][column] = SBOX[state[row][column]]


def _inv_sub_bytes(state: list[list[int]]) -> None:
    for row in range(4):
        for column in range(4):
            state[row][column] = INV_SBOX[state[row][column]]


def _shift_rows(state: list[list[int]]) -> None:
    for row in range(1, 4):
        state[row] = state[row][row:] + state[row][:row]


def _inv_shift_rows(state: list[list[int]]) -> None:
    for row in range(1, 4):
        state[row] = state[row][-row:] + state[row][:-row]


def _mix_columns(state: list[list[int]]) -> None:
    for column in range(4):
        a0, a1, a2, a3 = (state[row][column] for row in range(4))
        state[0][column] = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
        state[1][column] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
        state[2][column] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
        state[3][column] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)


def _inv_mix_columns(state: list[list[int]]) -> None:
    for column in range(4):
        a0, a1, a2, a3 = (state[row][column] for row in range(4))
        state[0][column] = _gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9)
        state[1][column] = _gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13)
        state[2][column] = _gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11)
        state[3][column] = _gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14)


@lru_cache(maxsize=65536)
def aes_encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("AES block must be 16 bytes")

    round_keys = _expand_key(key)
    state = _bytes_to_state(block)
    _add_round_key(state, round_keys[0])

    for round_index in range(1, 10):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[round_index])

    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[10])
    return _state_to_bytes(state)


@lru_cache(maxsize=65536)
def aes_decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("AES block must be 16 bytes")

    round_keys = _expand_key(key)
    state = _bytes_to_state(block)
    _add_round_key(state, round_keys[10])

    for round_index in range(9, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys[round_index])
        _inv_mix_columns(state)

    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0])
    return _state_to_bytes(state)


def aes_ecb_encrypt(data: bytes, key: bytes, pad: bool = True) -> bytes:
    plaintext = pkcs7_pad(data, BLOCK_SIZE) if pad else data
    if len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError("ECB plaintext must be a multiple of 16 bytes when pad=False")
    return b"".join(aes_encrypt_block(block, key) for block in split_blocks(plaintext))


def aes_ecb_decrypt(data: bytes, key: bytes, unpad: bool = True) -> bytes:
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("ECB ciphertext must be a multiple of 16 bytes")
    plaintext = b"".join(aes_decrypt_block(block, key) for block in split_blocks(data))
    return pkcs7_unpad(plaintext, BLOCK_SIZE) if unpad else plaintext


def aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes, pad: bool = True) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CBC IV must be 16 bytes")

    plaintext = pkcs7_pad(data, BLOCK_SIZE) if pad else data
    if len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError("CBC plaintext must be a multiple of 16 bytes when pad=False")

    previous = iv
    result = []
    for block in split_blocks(plaintext):
        encrypted = aes_encrypt_block(xor_bytes(block, previous), key)
        result.append(encrypted)
        previous = encrypted
    return b"".join(result)


def aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes, unpad: bool = True) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CBC IV must be 16 bytes")
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("CBC ciphertext must be a multiple of 16 bytes")

    previous = iv
    result = []
    for block in split_blocks(data):
        decrypted = aes_decrypt_block(block, key)
        result.append(xor_bytes(decrypted, previous))
        previous = block
    plaintext = b"".join(result)
    return pkcs7_unpad(plaintext, BLOCK_SIZE) if unpad else plaintext


def b64decode_clean(text: str) -> bytes:
    return base64.b64decode("".join(text.split()))
