from dataclasses import dataclass
import importlib.util
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
hex_to_bytes = single_byte_xor.hex_to_bytes


@dataclass
class Candidate:
    line_number: int
    ciphertext_hex: str
    key: int
    plaintext: bytes
    score: float


def detect_single_character_xor(lines: list[str]) -> Candidate:
    """Find the line most likely encrypted by single-byte XOR."""
    best_candidate: Candidate | None = None

    for line_number, line in enumerate(lines, start=1):
        ciphertext_hex = line.strip()
        if not ciphertext_hex:
            continue

        ciphertext = hex_to_bytes(ciphertext_hex)
        key, plaintext, score = break_single_byte_xor(ciphertext)
        candidate = Candidate(line_number, ciphertext_hex, key, plaintext, score)

        if best_candidate is None or candidate.score > best_candidate.score:
            best_candidate = candidate

    if best_candidate is None:
        raise ValueError("no ciphertext lines were found")

    return best_candidate


def main() -> None:
    data_path = Path(__file__).with_name("detect_single_character_xor.txt")
    lines = data_path.read_text(encoding="utf-8").splitlines()
    candidate = detect_single_character_xor(lines)
    plaintext = candidate.plaintext.decode("ascii")

    print(f"line number: {candidate.line_number}")
    print(f"ciphertext: {candidate.ciphertext_hex}")
    print(f"key byte: {candidate.key} (0x{candidate.key:02x}, {chr(candidate.key)!r})")
    print(f"plaintext: {plaintext}")
    print(f"score: {candidate.score:.4f}")


if __name__ == "__main__":
    main()
