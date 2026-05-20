def repeating_key_xor(data: bytes, key: bytes) -> bytes:
    """Encrypt or decrypt data with repeating-key XOR."""
    if not key:
        raise ValueError("key must not be empty")

    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def repeating_key_xor_hex(plaintext: str, key: str) -> str:
    plaintext_bytes = plaintext.encode("utf-8")
    key_bytes = key.encode("utf-8")
    return repeating_key_xor(plaintext_bytes, key_bytes).hex()


def main() -> None:
    plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = "ICE"
    expected = (
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
        "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    )

    actual = repeating_key_xor_hex(plaintext, key)
    print(actual)
    print("pass" if actual == expected else "fail")


if __name__ == "__main__":
    main()
