ENGLISH_FREQUENCY = {
    "a": 0.08167,
    "b": 0.01492,
    "c": 0.02782,
    "d": 0.04253,
    "e": 0.12702,
    "f": 0.02228,
    "g": 0.02015,
    "h": 0.06094,
    "i": 0.06966,
    "j": 0.00153,
    "k": 0.00772,
    "l": 0.04025,
    "m": 0.02406,
    "n": 0.06749,
    "o": 0.07507,
    "p": 0.01929,
    "q": 0.00095,
    "r": 0.05987,
    "s": 0.06327,
    "t": 0.09056,
    "u": 0.02758,
    "v": 0.00978,
    "w": 0.02360,
    "x": 0.00150,
    "y": 0.01974,
    "z": 0.00074,
    " ": 0.13000,
}


def hex_to_bytes(hex_text: str) -> bytes:
    """Convert a hex string into raw bytes."""
    cleaned = "".join(hex_text.split())
    if len(cleaned) % 2 != 0:
        raise ValueError("hex string length must be even")
    return bytes.fromhex(cleaned)


def xor_with_single_byte(data: bytes, key: int) -> bytes:
    """XOR every byte in data with the same one-byte key."""
    if not 0 <= key <= 255:
        raise ValueError("key must be in range 0..255")
    return bytes(byte ^ key for byte in data)


def score_english(data: bytes) -> float:
    """Give higher scores to byte strings that look like English text."""
    score = 0.0

    for byte in data:
        char = chr(byte)
        lower_char = char.lower()

        if lower_char in ENGLISH_FREQUENCY:
            score += ENGLISH_FREQUENCY[lower_char]
        elif char in "',.!?-":
            score += 0.005
        elif char in "\n\r\t":
            score += 0.001
        elif 32 <= byte <= 126:
            score -= 0.020
        else:
            score -= 0.200

    return score


def break_single_byte_xor(ciphertext: bytes) -> tuple[int, bytes, float]:
    """Try every possible one-byte key and keep the best English-looking result."""
    best_key = 0
    best_plaintext = b""
    best_score = float("-inf")

    for key in range(256):
        plaintext = xor_with_single_byte(ciphertext, key)
        score = score_english(plaintext)
        if score > best_score:
            best_key = key
            best_plaintext = plaintext
            best_score = score

    return best_key, best_plaintext, best_score


def main() -> None:
    source_hex = (
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    )
    expected_plaintext = "Cooking MC's like a pound of bacon"

    ciphertext = hex_to_bytes(source_hex)
    key, plaintext_bytes, score = break_single_byte_xor(ciphertext)
    plaintext = plaintext_bytes.decode("ascii")

    print(f"key byte: {key} ({chr(key)!r})")
    print(f"plaintext: {plaintext}")
    print(f"score: {score:.4f}")
    print("pass" if plaintext == expected_plaintext else "fail")


if __name__ == "__main__":
    main()
