from crypto_utils import pkcs7_pad


def main() -> None:
    plaintext = b"YELLOW SUBMARINE"
    padded = pkcs7_pad(plaintext, 20)
    expected = b"YELLOW SUBMARINE\x04\x04\x04\x04"

    print(repr(padded))
    print("pass" if padded == expected else "fail")


if __name__ == "__main__":
    main()
