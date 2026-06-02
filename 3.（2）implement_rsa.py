from __future__ import annotations

from math import gcd


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


def rsa_key_from_primes(p: int, q: int, e: int = 65537) -> tuple[tuple[int, int], tuple[int, int]]:
    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError("e must be coprime to phi(n)")
    d = invmod(e, phi)
    return (e, n), (d, n)


def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "big")


def int_to_bytes(value: int) -> bytes:
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


def rsa_encrypt(message: int, public_key: tuple[int, int]) -> int:
    e, n = public_key
    if not 0 <= message < n:
        raise ValueError("message representative must be in [0, n)")
    return pow(message, e, n)


def rsa_decrypt(ciphertext: int, private_key: tuple[int, int]) -> int:
    d, n = private_key
    return pow(ciphertext, d, n)


def main() -> None:
    p = 1_000_000_007
    q = 1_000_000_009
    public_key, private_key = rsa_key_from_primes(p, q)

    plaintext = b"demo"
    message = bytes_to_int(plaintext)
    ciphertext = rsa_encrypt(message, public_key)
    recovered = int_to_bytes(rsa_decrypt(ciphertext, private_key))

    print(f"public key (e, n): {public_key}")
    print(f"private exponent d: {private_key[0]}")
    print(f"ciphertext: {ciphertext}")
    print(f"recovered: {recovered.decode('ascii')}")
    assert recovered == plaintext
    print("pass")


if __name__ == "__main__":
    main()
