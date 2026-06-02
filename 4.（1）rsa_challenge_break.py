from __future__ import annotations

from dataclasses import dataclass
from math import gcd, isqrt
from pathlib import Path


FLAG_HEX = "9876543210ABCDEF"
LCG_MOD = 1 << 16
LCG_A = 365
LCG_B = -1


@dataclass
class Frame:
    index: int
    name: str
    n: int
    e: int
    c: int


@dataclass
class Recovered:
    frame: Frame
    p: int | None
    q: int | None
    message: int
    method: str

    @property
    def flag(self) -> str:
        return self.message.to_bytes(64, "big")[:8].hex().upper()

    @property
    def sequence(self) -> int:
        return int.from_bytes(self.message.to_bytes(64, "big")[8:12], "big")

    @property
    def block(self) -> bytes:
        return self.message.to_bytes(64, "big")[-8:]

    @property
    def text(self) -> str:
        return self.block.decode("ascii", errors="replace")


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def mod_inverse(a: int, m: int) -> int:
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % m


def parse_frame(path: Path) -> Frame:
    data = path.read_text(encoding="ascii").strip()
    if len(data) != 768:
        raise ValueError(f"{path.name}: expected 768 hex characters")
    index = int(path.name.removeprefix("Frame"))
    return Frame(
        index=index,
        name=path.name,
        n=int(data[:256], 16),
        e=int(data[256:512], 16),
        c=int(data[512:], 16),
    )


def find_frame_dir() -> Path:
    candidates = [
        Path(__file__).resolve().parents[2] / "密码挑战赛赛题三" / "附件3-2（发布截获数据）",
        Path(__file__).resolve().parents[1] / "密码挑战赛赛题三" / "附件3-2（发布截获数据）",
        Path.cwd() / "密码挑战赛赛题三" / "附件3-2（发布截获数据）",
        Path.cwd().parent / "密码挑战赛赛题三" / "附件3-2（发布截获数据）",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError("could not locate 附件3-2（发布截获数据）")


def load_frames(frame_dir: Path) -> list[Frame]:
    return [parse_frame(path) for path in sorted(frame_dir.glob("Frame*"), key=lambda item: int(item.name[5:]))]


def decrypt_with_factor(frame: Frame, p: int, method: str) -> Recovered:
    q = frame.n // p
    if p * q != frame.n:
        raise ValueError(f"{frame.name}: invalid factor")
    phi = (p - 1) * (q - 1)
    d = mod_inverse(frame.e, phi)
    message = pow(frame.c, d, frame.n)
    return Recovered(frame=frame, p=p, q=q, message=message, method=method)


def common_modulus_attack(left: Frame, right: Frame) -> Recovered | None:
    if left.n != right.n:
        return None
    g, a, b = egcd(left.e, right.e)
    if g != 1:
        return None

    def signed_power(value: int, exponent: int, modulus: int) -> int:
        if exponent >= 0:
            return pow(value, exponent, modulus)
        return pow(mod_inverse(value, modulus), -exponent, modulus)

    message = (signed_power(left.c, a, left.n) * signed_power(right.c, b, left.n)) % left.n
    return Recovered(frame=left, p=None, q=None, message=message, method=f"common modulus with {right.name}")


def pollard_p_minus_1(n: int, bound: int = 500_000, check_every: int = 1000) -> int | None:
    value = 2
    for exponent in range(2, bound + 1):
        value = pow(value, exponent, n)
        if exponent % check_every == 0:
            factor = gcd(value - 1, n)
            if 1 < factor < n:
                return factor
    factor = gcd(value - 1, n)
    return factor if 1 < factor < n else None


def fermat_factor(n: int, limit: int = 1_000_000) -> int | None:
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(limit):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a - b
        a += 1
    return None


def lcg_factor(n: int) -> tuple[int, str] | None:
    for seed in range(1, LCG_MOD + 1):
        x = seed
        value = x
        bits = 16
        while bits <= 520:
            factor = gcd(value, n)
            if 1 < factor < n:
                return factor, f"LCG seed={seed}, bits={bits}"
            x = (LCG_A * x + LCG_B) & 0xFFFF
            value = (value << 16) | x
            bits += 16

        trimmed = value
        trimmed_bits = bits
        while trimmed_bits > 16:
            factor = gcd(trimmed, n)
            if 1 < factor < n:
                return factor, f"LCG seed={seed}, trimmed_bits={trimmed_bits}"
            trimmed >>= 1
            trimmed_bits -= 1

    return None


def long_lcg_factor(n: int) -> tuple[int, str] | None:
    for seed in range(1, LCG_MOD + 1):
        x = seed
        value = x
        bits = 16
        while bits < 1000:
            x = (LCG_A * x + LCG_B) & 0xFFFF
            value = (value << 16) | x
            bits += 16

        while bits > 980:
            factor = gcd(value, n)
            if 1 < factor < n:
                return factor, f"long LCG seed={seed}, bits={bits}"
            value >>= 1
            bits -= 1

    return None


def lcg_512_factor(n: int) -> tuple[int, str] | None:
    for seed in range(1, LCG_MOD + 1):
        x = seed
        value = x
        for _ in range(31):
            x = (LCG_A * x + LCG_B) & 0xFFFF
            value = (value << 16) | x
        factor = gcd(value, n)
        if 1 < factor < n:
            return factor, f"LCG seed={seed}, bits=512"
    return None


def batch_lcg_factors(frames: list[Frame]) -> dict[int, tuple[int, str]]:
    pending = {frame.index: frame for frame in frames}
    found: dict[int, tuple[int, str]] = {}

    def product_of_pending() -> int:
        product = 1
        for candidate in pending.values():
            product *= candidate.n
        return product

    product = product_of_pending()
    for seed in range(1, LCG_MOD + 1):
        x = seed
        value = x
        bits = 16
        while bits <= 520:
            shared = gcd(value, product)
            if shared > 1:
                for index, frame in list(pending.items()):
                    factor = gcd(value, frame.n)
                    if 1 < factor < frame.n:
                        found[index] = (factor, f"LCG seed={seed}, bits={bits}")
                        del pending[index]
                if not pending:
                    return found
                product = product_of_pending()

            x = (LCG_A * x + LCG_B) & 0xFFFF
            value = (value << 16) | x
            bits += 16

    return found


def trimmed_lcg_factor(n: int, max_bits: int = 520) -> tuple[int, str] | None:
    for seed in range(1, LCG_MOD + 1):
        x = seed
        value = x
        bits = 16
        while bits < max_bits:
            x = (LCG_A * x + LCG_B) & 0xFFFF
            value = (value << 16) | x
            bits += 16

        while bits > 16:
            factor = gcd(value, n)
            if 1 < factor < n:
                return factor, f"LCG seed={seed}, trimmed_bits={bits}"
            value >>= 1
            bits -= 1

    return None


def batch_long_lcg_factors(frames: list[Frame]) -> dict[int, tuple[int, str]]:
    pending = {frame.index: frame for frame in frames}
    found: dict[int, tuple[int, str]] = {}

    def product_of_pending() -> int:
        product = 1
        for candidate in pending.values():
            product *= candidate.n
        return product

    product = product_of_pending()
    for seed in range(1, LCG_MOD + 1):
        x = seed
        value = x
        bits = 16
        while bits < 1000:
            x = (LCG_A * x + LCG_B) & 0xFFFF
            value = (value << 16) | x
            bits += 16

        while bits > 980:
            shared = gcd(value, product)
            if shared > 1:
                for index, frame in list(pending.items()):
                    factor = gcd(value, frame.n)
                    if 1 < factor < frame.n:
                        found[index] = (factor, f"long LCG seed={seed}, bits={bits}")
                        del pending[index]
                if not pending:
                    return found
                product = product_of_pending()
            value >>= 1
            bits -= 1

    return found


def recover_frames(frames: list[Frame]) -> dict[int, Recovered]:
    recovered: dict[int, Recovered] = {}

    for i, left in enumerate(frames):
        for right in frames[i + 1:]:
            if left.n == right.n:
                result = common_modulus_attack(left, right)
                if result:
                    recovered.setdefault(left.index, result)
                    recovered.setdefault(right.index, Recovered(right, None, None, result.message, f"same plaintext as {left.name}"))

            factor = gcd(left.n, right.n)
            if 1 < factor < left.n:
                recovered.setdefault(left.index, decrypt_with_factor(left, factor, f"shared factor with {right.name}"))
            if 1 < factor < right.n:
                recovered.setdefault(right.index, decrypt_with_factor(right, factor, f"shared factor with {left.name}"))

    for frame in frames:
        if frame.index in recovered:
            continue
        result = lcg_512_factor(frame.n)
        if result:
            factor, method = result
            recovered[frame.index] = decrypt_with_factor(frame, factor, method)

    for frame in frames:
        if frame.index in recovered:
            continue
        if frame.index not in {13, 17}:
            continue
        result = trimmed_lcg_factor(frame.n)
        if result:
            factor, method = result
            recovered[frame.index] = decrypt_with_factor(frame, factor, method)

    for frame in frames:
        if frame.index in recovered:
            continue
        factor = pollard_p_minus_1(frame.n)
        if factor:
            recovered[frame.index] = decrypt_with_factor(frame, factor, "Pollard p-1")

    for frame in frames:
        if frame.index in recovered:
            continue
        factor = fermat_factor(frame.n)
        if factor:
            recovered[frame.index] = decrypt_with_factor(frame, factor, "Fermat close primes")

    pending = [frame for frame in frames if frame.index not in recovered]
    for index, (factor, method) in batch_long_lcg_factors(pending).items():
        recovered[index] = decrypt_with_factor(frames[index], factor, method)

    return recovered


def main() -> None:
    frame_dir = find_frame_dir()
    frames = load_frames(frame_dir)
    recovered = recover_frames(frames)

    print(f"loaded frames: {len(frames)}")
    print(f"recovered frames: {len(recovered)}")
    print()
    for index in sorted(recovered):
        item = recovered[index]
        print(
            f"{item.frame.name:7s} seq={item.sequence:02d} flag={item.flag} "
            f"text={item.text!r} method={item.method}"
        )

    unique_blocks: dict[int, str] = {}
    for item in sorted(recovered.values(), key=lambda item: (item.sequence, item.frame.index)):
        unique_blocks.setdefault(item.sequence, item.text)
    plaintext = "".join(unique_blocks[index] for index in sorted(unique_blocks))
    print()
    print("plaintext:")
    print(plaintext)

    if FLAG_HEX not in {item.flag for item in recovered.values()}:
        raise SystemExit("unexpected flag value")


if __name__ == "__main__":
    main()
