from crypto_utils import pkcs7_unpad


def main() -> None:
    samples = [
        (b"ICE ICE BABY\x04\x04\x04\x04", True),
        (b"ICE ICE BABY\x05\x05\x05\x05", False),
        (b"ICE ICE BABY\x01\x02\x03\x04", False),
    ]

    for data, expected_valid in samples:
        try:
            plaintext = pkcs7_unpad(data, 16)
            actual_valid = True
            print(f"{data!r} -> {plaintext!r}")
        except ValueError as exc:
            actual_valid = False
            print(f"{data!r} -> {exc}")

        print("pass" if actual_valid == expected_valid else "fail")


if __name__ == "__main__":
    main()
