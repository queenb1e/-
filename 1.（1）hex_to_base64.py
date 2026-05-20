BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def hex_to_bytes(hex_text: str) -> bytes:
    """Convert a hex string into raw bytes."""
    cleaned = "".join(hex_text.split())
    if len(cleaned) % 2 != 0:
        raise ValueError("hex string length must be even")
    return bytes.fromhex(cleaned)


def bytes_to_base64(data: bytes) -> str:
    """Encode raw bytes with Base64."""
    result = []

    for index in range(0, len(data), 3):
        block = data[index:index + 3]
        padding = 3 - len(block)
        twenty_four_bits = int.from_bytes(block, "big") << (padding * 8)

        for shift in (18, 12, 6, 0):
            six_bits = (twenty_four_bits >> shift) & 0b111111
            result.append(BASE64_ALPHABET[six_bits])

        if padding:
            result[-padding:] = "=" * padding

    return "".join(result)


def hex_to_base64(hex_text: str) -> str:
    raw_bytes = hex_to_bytes(hex_text)
    return bytes_to_base64(raw_bytes)


def main() -> None:
    source_hex = (
        "49276d206b696c6c696e6720796f757220627261696e206c696b652061"
        "20706f69736f6e6f7573206d757368726f6f6d"
    )
    expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

    actual = hex_to_base64(source_hex)
    print(actual)
    print("pass" if actual == expected else "fail")


if __name__ == "__main__":
    main()
