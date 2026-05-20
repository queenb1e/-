def hex_to_bytes(hex_text: str) -> bytes:
    """Convert a hex string into raw bytes."""
    cleaned = "".join(hex_text.split())
    if len(cleaned) % 2 != 0:
        raise ValueError("hex string length must be even")
    return bytes.fromhex(cleaned)


def fixed_xor(left: bytes, right: bytes) -> bytes:
    """XOR two equal-length byte buffers."""
    if len(left) != len(right):
        raise ValueError("buffers must have the same length")

    return bytes(left_byte ^ right_byte for left_byte, right_byte in zip(left, right))


def fixed_xor_hex(left_hex: str, right_hex: str) -> str:
    left = hex_to_bytes(left_hex)
    right = hex_to_bytes(right_hex)
    return fixed_xor(left, right).hex()


def main() -> None:
    first_hex = "1c0111001f010100061a024b53535009181c"
    second_hex = "686974207468652062756c6c277320657965"
    expected = "746865206b696420646f6e277420706c6179"

    actual = fixed_xor_hex(first_hex, second_hex)
    print(actual)
    print("pass" if actual == expected else "fail")


if __name__ == "__main__":
    main()
