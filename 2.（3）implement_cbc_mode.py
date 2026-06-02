from crypto_utils import aes_cbc_decrypt, aes_cbc_encrypt


def main() -> None:
    key = b"YELLOW SUBMARINE"
    iv = bytes(16)
    plaintext = (
        b"CBC mode chains every plaintext block with the previous ciphertext block. "
        b"This test verifies encryption and decryption with a zero IV."
    )

    ciphertext = aes_cbc_encrypt(plaintext, key, iv)
    recovered = aes_cbc_decrypt(ciphertext, key, iv)

    print(f"ciphertext hex: {ciphertext.hex()}")
    print(f"recovered: {recovered.decode('utf-8')}")
    print("pass" if recovered == plaintext else "fail")


if __name__ == "__main__":
    main()
