from __future__ import annotations

import base64
import hashlib

from crypto_utils import aes_cbc_decrypt


CIPHERTEXT_B64 = (
    "9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jx"
    "aa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2N"
    "fNnWFBTXyf7SDI"
)

MRZ_WITH_MISSING = "12345678<8<<<1110182<111116?<<<<<<<<<<<<<<<4"
WEIGHTS = (7, 3, 1)
CHAR_VALUES = {str(number): number for number in range(10)}
CHAR_VALUES.update({chr(ord("A") + number): 10 + number for number in range(26)})
CHAR_VALUES["<"] = 0


def mrz_check_digit(text: str) -> str:
    total = 0
    for index, char in enumerate(text):
        total += CHAR_VALUES[char] * WEIGHTS[index % 3]
    return str(total % 10)


def restore_missing_character(mrz: str) -> str:
    restored = list(mrz)
    restored[27] = mrz_check_digit(mrz[21:27])
    return "".join(restored)


def derive_k_seed(mrz: str) -> bytes:
    mrz_information = (mrz[:10] + mrz[13:20] + mrz[21:28]).encode("ascii")
    return hashlib.sha1(mrz_information).digest()[:16]


def set_odd_parity(data: bytes) -> bytes:
    result = []
    for value in data:
        top_seven_bits = value & 0xFE
        parity_bit = 0 if top_seven_bits.bit_count() % 2 else 1
        result.append(top_seven_bits | parity_bit)
    return bytes(result)


def derive_kenc(k_seed: bytes) -> bytes:
    digest = hashlib.sha1(k_seed + bytes.fromhex("00000001")).digest()
    return set_odd_parity(digest[:16])


def strip_one_zero_padding(data: bytes) -> bytes:
    index = len(data) - 1
    while index >= 0 and data[index] == 0:
        index -= 1
    if index >= 0 and data[index] == 1:
        return data[:index]
    return data


def solve() -> tuple[str, bytes, bytes, str]:
    mrz = restore_missing_character(MRZ_WITH_MISSING)
    k_seed = derive_k_seed(mrz)
    k_enc = derive_kenc(k_seed)
    ciphertext = base64.b64decode(CIPHERTEXT_B64)
    plaintext = aes_cbc_decrypt(ciphertext, k_enc, bytes(16), unpad=False)
    return mrz, k_seed, k_enc, strip_one_zero_padding(plaintext).decode("utf-8")


def main() -> None:
    mrz, k_seed, k_enc, plaintext = solve()
    print(f"restored MRZ: {mrz}")
    print(f"K_seed: {k_seed.hex()}")
    print(f"K_enc: {k_enc.hex()}")
    print(f"plaintext: {plaintext}")


if __name__ == "__main__":
    main()
