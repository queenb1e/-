from __future__ import annotations

import os
import random

from crypto_utils import aes_cbc_encrypt, aes_ecb_encrypt, detect_ecb


def encryption_oracle(data: bytes) -> tuple[bytes, str]:
    key = os.urandom(16)
    prefix = os.urandom(random.randint(5, 10))
    suffix = os.urandom(random.randint(5, 10))
    plaintext = prefix + data + suffix

    if random.choice((True, False)):
        return aes_ecb_encrypt(plaintext, key), "ECB"

    iv = os.urandom(16)
    return aes_cbc_encrypt(plaintext, key, iv), "CBC"


def guess_mode(ciphertext: bytes) -> str:
    return "ECB" if detect_ecb(ciphertext) else "CBC"


def main() -> None:
    trials = 20
    correct = 0
    probe = b"A" * 64

    for _ in range(trials):
        ciphertext, actual_mode = encryption_oracle(probe)
        guessed_mode = guess_mode(ciphertext)
        if guessed_mode == actual_mode:
            correct += 1

    print(f"correct guesses: {correct}/{trials}")
    print("pass" if correct == trials else "fail")


if __name__ == "__main__":
    main()
