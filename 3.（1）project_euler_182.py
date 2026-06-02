from __future__ import annotations

from math import gcd


P = 1009
Q = 3643


def count_unconcealed_messages(e: int, p: int = P, q: int = Q) -> int:
    """Return the number of messages m for which m**e == m (mod n)."""
    return (gcd(e - 1, p - 1) + 1) * (gcd(e - 1, q - 1) + 1)


def solve(p: int = P, q: int = Q) -> tuple[int, int]:
    phi = (p - 1) * (q - 1)
    best_count: int | None = None
    total = 0

    for e in range(2, phi):
        if gcd(e, phi) != 1:
            continue

        count = count_unconcealed_messages(e, p, q)
        if best_count is None or count < best_count:
            best_count = count
            total = e
        elif count == best_count:
            total += e

    if best_count is None:
        raise ValueError("no valid RSA exponents found")
    return best_count, total


def main() -> None:
    best_count, total = solve()
    print(f"minimum unconcealed messages: {best_count}")
    print(f"sum of e values: {total}")
    assert total == 399788195976
    print("pass")


if __name__ == "__main__":
    main()
