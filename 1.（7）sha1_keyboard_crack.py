from collections.abc import Iterator
from hashlib import sha1
from itertools import permutations, product
from time import perf_counter


TARGET_HASH = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"

# Keyboard traces show the physical keys that were probably used for the
# password. On a German keyboard, Shift changes some of these keys:
# Shift+8 -> (, Shift+0 -> =, Shift+q -> Q.
KEY_OUTPUT_OPTIONS = {
    "8": ("8", "("),
    "q": ("q", "Q"),
    "0": ("0", "="),
    "w": ("w", "W"),
    "i": ("i", "I"),
    "n": ("n", "N"),
    "*": ("*", "+"),
    "5": ("5", "%"),
}


def sha1_hex(text: str) -> str:
    return sha1(text.encode("utf-8")).hexdigest()


def candidate_passwords() -> Iterator[str]:
    keys = tuple(KEY_OUTPUT_OPTIONS)

    for key_order in permutations(keys):
        option_groups = [KEY_OUTPUT_OPTIONS[key] for key in key_order]
        for chars in product(*option_groups):
            yield "".join(chars)


def crack_sha1_password(target_hash: str) -> tuple[str, int]:
    attempts = 0

    for password in candidate_passwords():
        attempts += 1
        if sha1_hex(password) == target_hash:
            return password, attempts

    raise ValueError("password was not found in the keyboard-trace search space")


def main() -> None:
    start_time = perf_counter()
    password, attempts = crack_sha1_password(TARGET_HASH)
    elapsed_seconds = perf_counter() - start_time

    print(f"target hash: {TARGET_HASH}")
    print(f"password: {password}")
    print(f"sha1(password): {sha1_hex(password)}")
    print(f"attempts: {attempts}")
    print(f"elapsed time: {elapsed_seconds:.6f} seconds")
    print("pass" if sha1_hex(password) == TARGET_HASH else "fail")


if __name__ == "__main__":
    main()
