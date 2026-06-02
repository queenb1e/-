from __future__ import annotations

import os

from crypto_utils import aes_ecb_decrypt, aes_ecb_encrypt


KEY = os.urandom(16)


def parse_cookie(cookie: str) -> dict[str, str]:
    result = {}
    for pair in cookie.split("&"):
        key, value = pair.split("=", 1)
        result[key] = value
    return result


def profile_for(email: str) -> str:
    cleaned = email.replace("&", "").replace("=", "")
    return f"email={cleaned}&uid=10&role=user"


def encrypt_profile(email: str) -> bytes:
    return aes_ecb_encrypt(profile_for(email).encode("utf-8"), KEY)


def decrypt_profile(ciphertext: bytes) -> dict[str, str]:
    return parse_cookie(aes_ecb_decrypt(ciphertext, KEY).decode("utf-8"))


def forge_admin_profile() -> bytes:
    admin_block_email = "A" * 10 + "admin" + chr(11) * 11
    admin_block = encrypt_profile(admin_block_email)[16:32]

    normal_profile = encrypt_profile("B" * 13)
    return normal_profile[:32] + admin_block


def main() -> None:
    forged = forge_admin_profile()
    profile = decrypt_profile(forged)

    print(profile)
    print("pass" if profile.get("role") == "admin" else "fail")


if __name__ == "__main__":
    main()
