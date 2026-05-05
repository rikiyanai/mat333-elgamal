"""
ElGamal public-key encryption and baby-step giant-step DLP solver.
Companion code for the MAT333 ElGamal project.
"""

import math
import random
from typing import Optional


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def next_prime(n: int) -> int:
    if n < 2:
        return 2
    n = n + 1 if n % 2 == 0 else n + 2
    while not is_prime(n):
        n += 2
    return n


def find_generator(p: int) -> int:
    """Find the smallest primitive root modulo p."""
    phi = p - 1
    factors = set()
    n = phi
    for f in range(2, math.isqrt(n) + 1):
        while n % f == 0:
            factors.add(f)
            n //= f
    if n > 1:
        factors.add(n)
    for g in range(2, p):
        if all(pow(g, phi // f, p) != 1 for f in factors):
            return g
    return -1


def keygen(bits: int) -> tuple[int, int, int, int]:
    """Generate ElGamal keys. Returns (p, g, x, h)."""
    p = next_prime(random.randint(2 ** (bits - 1), 2 ** bits))
    g = find_generator(p)
    x = random.randint(2, p - 2)
    h = pow(g, x, p)
    return p, g, x, h


def encrypt(m: int, p: int, g: int, h: int) -> tuple[int, int]:
    """Encrypt integer m. Returns (c1, c2)."""
    k = random.randint(2, p - 2)
    c1 = pow(g, k, p)
    c2 = (m * pow(h, k, p)) % p
    return c1, c2


def decrypt(c1: int, c2: int, p: int, x: int) -> int:
    """Decrypt ciphertext (c1, c2). Returns m."""
    s_inv = pow(c1, p - 1 - x, p)
    return (c2 * s_inv) % p


def encrypt_message(text: str, p: int, g: int, h: int) -> list[tuple[int, int]]:
    """Encrypt a string character by character."""
    return [encrypt(b, p, g, h) for b in text.encode("ascii")]


def decrypt_message(cipher: list[tuple[int, int]], p: int, x: int) -> str:
    """Decrypt a list of (c1, c2) pairs back to a string."""
    return bytes(decrypt(c1, c2, p, x) for c1, c2 in cipher).decode("ascii")


def bsgs(g: int, h: int, p: int) -> Optional[int]:
    """Baby-step giant-step: find x such that g^x = h (mod p)."""
    m = math.isqrt(p - 1) + 1
    # Baby step
    table = {}
    power = 1
    for j in range(m):
        table[power] = j
        power = (power * g) % p
    # Giant step
    factor = pow(g, p - 1 - m, p)
    gamma = h
    for i in range(m):
        if gamma in table:
            return i * m + table[gamma]
        gamma = (gamma * factor) % p
    return None


if __name__ == "__main__":
    # Demo
    p, g, x, h = keygen(32)
    print(f"Keys: p={p}, g={g}, h={h}")

    msg = "Hello, ElGamal!"
    cipher = encrypt_message(msg, p, g, h)
    recovered = decrypt_message(cipher, p, x)
    print(f"Plaintext:  {msg}")
    print(f"Recovered:  {recovered}")
    print(f"Match: {msg == recovered}")

    # BSGS demo
    x_found = bsgs(g, h, p)
    print(f"\nBSGS cracked 32-bit key: x={x_found}")
    print(f"Correct: {pow(g, x_found, p) == h}")
