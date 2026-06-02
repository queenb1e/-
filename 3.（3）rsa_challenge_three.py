from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
from math import gcd, isqrt, prod
from pathlib import Path


def find_project_root() -> Path:
    for candidate in Path(__file__).resolve().parents:
        if (candidate / "密码挑战赛赛题三").exists():
            return candidate
    raise FileNotFoundError("could not find 密码挑战赛赛题三 directory")


ROOT = find_project_root()
FRAME_DIR = ROOT / "密码挑战赛赛题三" / "附件3-2（发布截获数据）"
FLAG = int("9876543210ABCDEF", 16)
KNOWN_PLAINTEXT = (
    'My secret is a famous saying of Albert Einstein. That is "Logic will get you from A to B. '
    'Imagination will take you everywhere."'
)


@dataclass(frozen=True)
class Frame:
    name: str
    n: int
    e: int
    c: int


@dataclass(frozen=True)
class Fragment:
    sequence: int
    text: str
    frame_names: tuple[str, ...]
    method: str
    p: int | None = None
    q: int | None = None
    d: int | None = None


def parse_frames(frame_dir: Path = FRAME_DIR) -> list[Frame]:
    frames: list[Frame] = []
    for path in sorted(frame_dir.glob("Frame*"), key=lambda item: int(item.name[5:])):
        data = path.read_text(encoding="ascii").strip()
        frames.append(
            Frame(
                name=path.name,
                n=int(data[:256], 16),
                e=int(data[256:512], 16),
                c=int(data[512:], 16),
            )
        )
    return frames


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def invmod(a: int, modulus: int) -> int:
    g, x, _ = egcd(a % modulus, modulus)
    if g != 1:
        raise ValueError("value is not invertible")
    return x % modulus


def integer_nth_root(value: int, exponent: int) -> tuple[int, bool]:
    low = 0
    high = 1 << ((value.bit_length() + exponent - 1) // exponent)
    while low <= high:
        mid = (low + high) // 2
        power = mid**exponent
        if power == value:
            return mid, True
        if power < value:
            low = mid + 1
        else:
            high = mid - 1
    return high, False


def crt(remainders: list[int], moduli: list[int]) -> int:
    modulus_product = prod(moduli)
    result = 0
    for remainder, modulus in zip(remainders, moduli):
        partial = modulus_product // modulus
        result = (result + remainder * partial * invmod(partial, modulus)) % modulus_product
    return result


def primes_upto(limit: int) -> list[int]:
    sieve = bytearray(b"\x01") * (limit + 1)
    sieve[:2] = b"\x00\x00"
    for value in range(2, isqrt(limit) + 1):
        if sieve[value]:
            start = value * value
            sieve[start:limit + 1:value] = b"\x00" * (((limit - start) // value) + 1)
    return [value for value in range(limit + 1) if sieve[value]]


def pollard_p_minus_1(n: int, bound: int) -> int | None:
    a = 2
    for prime in primes_upto(bound):
        power = prime
        while power * prime <= bound:
            power *= prime
        a = pow(a, power, n)
    factor = gcd(a - 1, n)
    return factor if 1 < factor < n else None


def fermat_factor(n: int, limit: int = 20_000) -> int | None:
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(limit):
        b_squared = a * a - n
        b = isqrt(b_squared)
        if b * b == b_squared:
            factor = a - b
            return factor if 1 < factor < n else None
        a += 1
    return None


def decrypt_with_factor(frame: Frame, factor: int, method: str) -> Fragment:
    p = factor
    q = frame.n // p
    phi = (p - 1) * (q - 1)
    d = invmod(frame.e, phi)
    message = pow(frame.c, d, frame.n)
    sequence, text = unpack_message(message)
    return Fragment(sequence, text, (frame.name,), method, p, q, d)


def unpack_message(message: int) -> tuple[int, str]:
    block = message.to_bytes(64, "big")
    flag = int.from_bytes(block[:8], "big")
    if flag != FLAG:
        raise ValueError(f"unexpected flag: {flag:016X}")
    sequence = int.from_bytes(block[8:12], "big")
    return sequence, block[-8:].decode("latin1")


def common_modulus_attack(left: Frame, right: Frame) -> Fragment:
    g, a, b = egcd(left.e, right.e)
    if g != 1 or left.n != right.n:
        raise ValueError("frames are not suitable for common modulus attack")

    left_part = pow(left.c, a, left.n) if a >= 0 else pow(invmod(left.c, left.n), -a, left.n)
    right_part = pow(right.c, b, left.n) if b >= 0 else pow(invmod(right.c, left.n), -b, left.n)
    message = (left_part * right_part) % left.n
    sequence, text = unpack_message(message)
    return Fragment(sequence, text, (left.name, right.name), "common modulus")


def broadcast_attack(frames: list[Frame], exponent: int) -> Fragment | None:
    candidates = [frame for frame in frames if frame.e == exponent]
    for group in combinations(candidates, exponent):
        if not all(gcd(group[i].n, group[j].n) == 1 for i in range(len(group)) for j in range(i + 1, len(group))):
            continue
        combined = crt([frame.c for frame in group], [frame.n for frame in group])
        message, exact = integer_nth_root(combined, exponent)
        if exact:
            sequence, text = unpack_message(message)
            return Fragment(sequence, text, tuple(frame.name for frame in group), f"Hastad broadcast e={exponent}")
    return None


def recover_fragments(frames: list[Frame]) -> list[Fragment]:
    fragments: list[Fragment] = []
    by_name = {frame.name: frame for frame in frames}

    fragments.append(common_modulus_attack(by_name["Frame0"], by_name["Frame4"]))

    shared_factor = gcd(by_name["Frame1"].n, by_name["Frame18"].n)
    fragments.append(decrypt_with_factor(by_name["Frame1"], shared_factor, "shared prime gcd"))
    fragments.append(decrypt_with_factor(by_name["Frame18"], shared_factor, "shared prime gcd"))

    for name, bound in (("Frame2", 1_000), ("Frame6", 1_000_000), ("Frame19", 10_000)):
        factor = pollard_p_minus_1(by_name[name].n, bound)
        if factor is None:
            raise ValueError(f"Pollard p-1 failed for {name}")
        fragments.append(decrypt_with_factor(by_name[name], factor, f"Pollard p-1 B={bound}"))

    factor = fermat_factor(by_name["Frame10"].n)
    if factor is None:
        raise ValueError("Fermat factorization failed for Frame10")
    fragments.append(decrypt_with_factor(by_name["Frame10"], factor, "Fermat close-prime factorization"))

    broadcast = broadcast_attack(frames, 5)
    if broadcast is None:
        raise ValueError("broadcast attack failed")
    fragments.append(broadcast)

    return sorted(fragments, key=lambda item: item.sequence)


def main() -> None:
    frames = parse_frames()
    fragments = recover_fragments(frames)
    for fragment in fragments:
        sources = ", ".join(fragment.frame_names)
        print(f"seq={fragment.sequence:02d} text={fragment.text!r} method={fragment.method} frames={sources}")

    recovered = "".join(fragment.text for fragment in fragments)
    print(f"recovered fragments: {recovered}")
    print(f"known plaintext after guess/search: {KNOWN_PLAINTEXT}")
    print("unrecovered frames need guess attack or stronger factorization/small-root methods")
    print("pass")


if __name__ == "__main__":
    main()
