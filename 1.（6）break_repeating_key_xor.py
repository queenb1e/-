from dataclasses import dataclass
import base64
import importlib.util
from itertools import combinations
from pathlib import Path


def load_single_byte_xor_module():
    module_path = Path(__file__).with_name("1.（3）single_byte_xor.py")
    spec = importlib.util.spec_from_file_location("single_byte_xor_challenge_3", module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load module from {module_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


single_byte_xor = load_single_byte_xor_module()
break_single_byte_xor = single_byte_xor.break_single_byte_xor
score_english = single_byte_xor.score_english


@dataclass
class RepeatingKeyXorCandidate:
    keysize: int
    key: bytes
    plaintext: bytes
    score: float
    distance: float


def hamming_distance(left: bytes, right: bytes) -> int:
    """Count differing bits between two equal-length byte strings."""
    if len(left) != len(right):
        raise ValueError("inputs must have the same length")

    return sum((left_byte ^ right_byte).bit_count() for left_byte, right_byte in zip(left, right))


def normalized_keysize_distance(ciphertext: bytes, keysize: int, block_count: int = 8) -> float:
    """Estimate a keysize by averaging normalized Hamming distances."""
    blocks = [
        ciphertext[index:index + keysize]
        for index in range(0, keysize * block_count, keysize)
    ]
    full_blocks = [block for block in blocks if len(block) == keysize]
    if len(full_blocks) < 2:
        return float("inf")

    distances = [
        hamming_distance(left, right) / keysize
        for left, right in combinations(full_blocks, 2)
    ]
    return sum(distances) / len(distances)


def guess_keysizes(ciphertext: bytes, minimum: int = 2, maximum: int = 40, keep: int = 4) -> list[tuple[int, float]]:
    scores = [
        (keysize, normalized_keysize_distance(ciphertext, keysize))
        for keysize in range(minimum, maximum + 1)
    ]
    return sorted(scores, key=lambda item: item[1])[:keep]


def transpose_blocks(ciphertext: bytes, keysize: int) -> list[bytes]:
    """Collect bytes encrypted by the same repeating-key byte."""
    return [
        bytes(ciphertext[index] for index in range(position, len(ciphertext), keysize))
        for position in range(keysize)
    ]


def repeating_key_xor(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("key must not be empty")

    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def break_repeating_key_xor(ciphertext: bytes) -> RepeatingKeyXorCandidate:
    best_candidate: RepeatingKeyXorCandidate | None = None

    for keysize, distance in guess_keysizes(ciphertext):
        key = bytes(
            break_single_byte_xor(block)[0]
            for block in transpose_blocks(ciphertext, keysize)
        )
        plaintext = repeating_key_xor(ciphertext, key)
        score = score_english(plaintext) / len(plaintext)
        candidate = RepeatingKeyXorCandidate(keysize, key, plaintext, score, distance)

        if best_candidate is None or candidate.score > best_candidate.score:
            best_candidate = candidate

    if best_candidate is None:
        raise ValueError("could not find a candidate key")

    return best_candidate


def load_ciphertext(path: Path) -> bytes:
    encoded = "".join(path.read_text(encoding="utf-8").split())
    return base64.b64decode(encoded)


def main() -> None:
    test_distance = hamming_distance(b"this is a test", b"wokka wokka!!!")
    print(f"hamming test: {test_distance}")

    data_path = Path(__file__).with_name("repeating_key_xor_ciphertext.txt")
    ciphertext = load_ciphertext(data_path)
    candidate = break_repeating_key_xor(ciphertext)

    print(f"keysize: {candidate.keysize}")
    print(f"normalized distance: {candidate.distance:.4f}")
    print(f"key: {candidate.key.decode('ascii')!r}")
    print()
    print(candidate.plaintext.decode("utf-8"))
    print()
    print("pass" if test_distance == 37 else "fail")


if __name__ == "__main__":
    main()
