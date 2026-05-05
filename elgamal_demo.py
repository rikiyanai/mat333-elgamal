"""
ElGamal Encryption: Interactive Demo and DLP Visualizations
Companion to MAT333 ElGamal Project — Riki Hernandez, May 2026

Run: python3 elgamal_demo.py
"""

import math
import random
import time
import os
import sys

import numpy as np
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.widgets import Button

try:
    import colorama
    from colorama import Fore, Style
    colorama.init()
except ImportError:
    class Fore:
        GREEN = YELLOW = CYAN = RED = MAGENTA = WHITE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = ""

# ══════════════════════════════════════════════════════════════════════
# Core ElGamal + BSGS (imported from elgamal.py)
# ══════════════════════════════════════════════════════════════════════

from elgamal import (
    is_prime, next_prime, find_generator, keygen,
    encrypt, decrypt, encrypt_message, decrypt_message, bsgs,
)


def naive_dlog(g, h, p):
    """Exhaustive search for comparison with BSGS."""
    power = 1
    for x in range(p - 1):
        if power == h:
            return x
        power = (power * g) % p
    return None


# ══════════════════════════════════════════════════════════════════════
# Banner & UI
# ══════════════════════════════════════════════════════════════════════

BANNER = r"""
       ╔═══════════════════════════════════════════════════════════╗
       ║                                                           ║
       ║     ███████╗██╗      ██████╗  █████╗ ███╗   ███╗ █████╗ ██╗     ║
       ║     ██╔════╝██║     ██╔════╝ ██╔══██╗████╗ ████║██╔══██╗██║     ║
       ║     █████╗  ██║     ██║  ███╗███████║██╔████╔██║███████║██║     ║
       ║     ██╔══╝  ██║     ██║   ██║██╔══██║██║╚██╔╝██║██╔══██║██║     ║
       ║     ███████╗███████╗╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║███████╗║
       ║     ╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝║
       ║                                                           ║
       ║        Public-Key Encryption over Z_p*                    ║
       ║        MAT333 — Riki Hernandez — May 2026                ║
       ║                                                           ║
       ╚═══════════════════════════════════════════════════════════╝
"""

def print_banner():
    for line in BANNER.split("\n"):
        colored = ""
        for ch in line:
            if ch in "═╔╗╚╝║":
                colored += Fore.CYAN + ch
            elif ch == "█":
                colored += Fore.GREEN + ch
            elif ch == "╗" or ch == "╝":
                colored += Fore.CYAN + ch
            else:
                colored += Fore.WHITE + ch
        print(colored + Style.RESET_ALL)

def menu():
    print()
    print(f"{Fore.GREEN}  ┌─────────────────────────────────────┐{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  │  1. Encrypt / Decrypt a message     │{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  │  2. Crack a key (BSGS attack)       │{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  │  3. Visualize: Naive vs BSGS        │{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  │  4. Visualize: Probabilistic        │{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  │     Encryption                      │{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  │  5. Visualize: DLP Timing Scaling    │{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  │  6. Quit                             │{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  └─────────────────────────────────────┘{Style.RESET_ALL}")
    return input(f"{Fore.GREEN}  >> {Style.RESET_ALL}")


# ══════════════════════════════════════════════════════════════════════
# 1. Encrypt / Decrypt
# ══════════════════════════════════════════════════════════════════════

def mode_encrypt_decrypt():
    bits = 32
    inp = input(f"{Fore.CYAN}  Key size in bits [32]: {Style.RESET_ALL}").strip()
    if inp.isdigit(): bits = int(inp)

    p, g, x, h = keygen(bits)
    print(f"\n{Fore.YELLOW}  Key pair generated ({bits}-bit prime):{Style.RESET_ALL}")
    print(f"    p = {p}")
    print(f"    g = {g}")
    print(f"    h = {Fore.GREEN}{h}{Style.RESET_ALL}  (public)")
    print(f"    x = {Fore.RED}{x}{Style.RESET_ALL}  (private)")

    msg = input(f"\n{Fore.CYAN}  Message to encrypt: {Style.RESET_ALL}")
    if not msg: msg = "Hello, ElGamal!"

    cipher = encrypt_message(msg, p, g, h)
    print(f"\n{Fore.YELLOW}  Ciphertext ({len(cipher)} pairs):{Style.RESET_ALL}")
    for i, (c1, c2) in enumerate(cipher):
        ch = msg[i] if i < len(msg) else "?"
        print(f"    '{Fore.GREEN}{ch}{Style.RESET_ALL}' -> ({c1}, {c2})")

    recovered = decrypt_message(cipher, p, x)
    match = recovered == msg
    color = Fore.GREEN if match else Fore.RED
    print(f"\n{Fore.YELLOW}  Decrypted:{Style.RESET_ALL} {color}{recovered}{Style.RESET_ALL}")
    print(f"  Match: {color}{match}{Style.RESET_ALL}")

    # Encrypt again to show probabilistic property
    cipher2 = encrypt_message(msg, p, g, h)
    differ = sum(1 for a, b in zip(cipher, cipher2) if a != b)
    print(f"\n{Fore.YELLOW}  Probabilistic property:{Style.RESET_ALL}")
    print(f"    Re-encrypted same message: {differ}/{len(cipher)} pairs differ")


# ══════════════════════════════════════════════════════════════════════
# 2. Crack a key
# ══════════════════════════════════════════════════════════════════════

def mode_crack():
    bits = 24
    inp = input(f"{Fore.CYAN}  Key size to crack [24]: {Style.RESET_ALL}").strip()
    if inp.isdigit(): bits = int(inp)

    p, g, x_secret, h = keygen(bits)
    print(f"\n{Fore.YELLOW}  Generated {bits}-bit key:{Style.RESET_ALL}")
    print(f"    p = {p}, g = {g}, h = {h}")
    print(f"    Secret x = {Fore.RED}{x_secret}{Style.RESET_ALL}")
    print(f"\n  Running BSGS (table size ~ {math.isqrt(p)} entries)...")

    t0 = time.perf_counter()
    x_found = bsgs(g, h, p)
    elapsed = time.perf_counter() - t0

    correct = pow(g, x_found, p) == h
    color = Fore.GREEN if correct else Fore.RED
    print(f"    Found x = {color}{x_found}{Style.RESET_ALL}")
    print(f"    Correct: {color}{correct}{Style.RESET_ALL}")
    print(f"    Time: {Fore.CYAN}{elapsed:.6f}s{Style.RESET_ALL}")

    if correct and bits <= 32:
        # Decrypt a message with the cracked key
        msg = "CRACKED!"
        cipher = encrypt_message(msg, p, g, h)
        recovered = decrypt_message(cipher, p, x_found)
        print(f"\n  Using cracked key to decrypt \"{msg}\": {Fore.GREEN}{recovered}{Style.RESET_ALL}")


# ══════════════════════════════════════════════════════════════════════
# 3. Naive vs BSGS plot
# ══════════════════════════════════════════════════════════════════════

def mode_naive_vs_bsgs():
    print(f"\n{Fore.YELLOW}  Comparing naive exhaustive search vs BSGS...{Style.RESET_ALL}")
    bit_sizes = [8, 10, 12, 14, 16, 18, 20]
    naive_times = []
    bsgs_times = []

    for bits in bit_sizes:
        p = next_prime(random.randint(2**(bits-1), 2**bits))
        g = find_generator(p)
        x = random.randint(2, p - 2)
        h = pow(g, x, p)

        t0 = time.perf_counter()
        naive_dlog(g, h, p)
        t_naive = time.perf_counter() - t0

        t0 = time.perf_counter()
        bsgs(g, h, p)
        t_bsgs = time.perf_counter() - t0

        naive_times.append(t_naive)
        bsgs_times.append(t_bsgs)
        print(f"    {bits:2d}-bit:  naive={t_naive:.6f}s  BSGS={t_bsgs:.6f}s  "
              f"({Fore.GREEN}{t_naive/max(t_bsgs,1e-9):.0f}x faster{Style.RESET_ALL})")

    # Plot
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    fig.patch.set_facecolor("#1a1a2e")

    # Left: both on same axes (log scale)
    ax1.set_facecolor("#16213e")
    ax1.semilogy(bit_sizes, naive_times, "s-", color="#e94560", linewidth=2,
                 markersize=8, label="Naive O(p)", markeredgecolor="white", markeredgewidth=0.5)
    ax1.semilogy(bit_sizes, bsgs_times, "o-", color="#0f3460", linewidth=2,
                 markersize=8, label="BSGS O(√p)", markeredgecolor="white", markeredgewidth=0.5)
    ax1.fill_between(bit_sizes, naive_times, bsgs_times, alpha=0.15, color="#e94560")
    ax1.set_xlabel("Prime bit-size", color="white", fontsize=12)
    ax1.set_ylabel("Solve time (seconds, log scale)", color="white", fontsize=12)
    ax1.set_title("Naive vs BSGS: DLP Solve Time", color="white", fontsize=14)
    ax1.legend(facecolor="#16213e", edgecolor="white", labelcolor="white", fontsize=11)
    ax1.tick_params(colors="white")
    ax1.grid(True, alpha=0.2, color="white")
    for spine in ax1.spines.values(): spine.set_color("#333")

    # Right: speedup factor
    speedups = [n / max(b, 1e-9) for n, b in zip(naive_times, bsgs_times)]
    ax2.set_facecolor("#16213e")
    bars = ax2.bar(bit_sizes, speedups, color="#0f3460", edgecolor="#e94560", width=1.5)
    for bar, s in zip(bars, speedups):
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                 f"{s:.0f}x", ha="center", va="bottom", color="#e94560", fontsize=10, fontweight="bold")
    ax2.set_xlabel("Prime bit-size", color="white", fontsize=12)
    ax2.set_ylabel("Speedup (naive / BSGS)", color="white", fontsize=12)
    ax2.set_title("BSGS Speedup Factor", color="white", fontsize=14)
    ax2.tick_params(colors="white")
    ax2.grid(True, alpha=0.2, color="white", axis="y")
    for spine in ax2.spines.values(): spine.set_color("#333")

    fig.tight_layout(pad=2)
    out = os.path.join(os.path.dirname(__file__), "naive_vs_bsgs.png")
    fig.savefig(out, dpi=150, facecolor=fig.get_facecolor())
    print(f"\n  Plot saved to {out}")
    plt.show()


# ══════════════════════════════════════════════════════════════════════
# 4. Probabilistic encryption visualization
# ══════════════════════════════════════════════════════════════════════

def mode_probabilistic():
    print(f"\n{Fore.YELLOW}  Visualizing probabilistic encryption...{Style.RESET_ALL}")
    p, g, x, h = keygen(16)

    # Encrypt the letter 'A' (byte 65) many times
    char = "A"
    byte_val = ord(char)
    n_encryptions = 200
    c1_vals = []
    c2_vals = []
    for _ in range(n_encryptions):
        c1, c2 = encrypt(byte_val, p, g, h)
        c1_vals.append(c1)
        c2_vals.append(c2)

    # Also encrypt 'B' and 'C' for comparison
    chars = {"A": ([], []), "B": ([], []), "C": ([], [])}
    for ch in chars:
        for _ in range(n_encryptions):
            c1, c2 = encrypt(ord(ch), p, g, h)
            chars[ch][0].append(c1)
            chars[ch][1].append(c2)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    fig.patch.set_facecolor("#1a1a2e")

    # Left: scatter of (c1, c2) for letter 'A' — 200 encryptions, all different
    ax1.set_facecolor("#16213e")
    ax1.scatter(c1_vals, c2_vals, c="#e94560", s=12, alpha=0.7, edgecolors="none")
    ax1.set_xlabel("c₁ = gᵏ mod p", color="white", fontsize=12)
    ax1.set_ylabel("c₂ = m·hᵏ mod p", color="white", fontsize=12)
    ax1.set_title(f"200 encryptions of '{char}' (byte {byte_val})\n"
                  f"Same plaintext, all different ciphertexts",
                  color="white", fontsize=13)
    ax1.tick_params(colors="white")
    ax1.grid(True, alpha=0.15, color="white")
    for spine in ax1.spines.values(): spine.set_color("#333")

    # Right: overlay A, B, C — ciphertexts are indistinguishable
    ax2.set_facecolor("#16213e")
    colors = {"A": "#e94560", "B": "#0f3460", "C": "#00b4d8"}
    for ch, color in colors.items():
        ax2.scatter(chars[ch][0], chars[ch][1], c=color, s=12, alpha=0.6,
                    edgecolors="none", label=f"'{ch}' (byte {ord(ch)})")
    ax2.set_xlabel("c₁", color="white", fontsize=12)
    ax2.set_ylabel("c₂", color="white", fontsize=12)
    ax2.set_title("A, B, C ciphertexts overlap\n"
                  "An adversary cannot tell which letter was encrypted",
                  color="white", fontsize=13)
    ax2.legend(facecolor="#16213e", edgecolor="white", labelcolor="white",
               fontsize=11, markerscale=3)
    ax2.tick_params(colors="white")
    ax2.grid(True, alpha=0.15, color="white")
    for spine in ax2.spines.values(): spine.set_color("#333")

    fig.tight_layout(pad=2)
    out = os.path.join(os.path.dirname(__file__), "probabilistic.png")
    fig.savefig(out, dpi=150, facecolor=fig.get_facecolor())
    print(f"\n  Plot saved to {out}")
    plt.show()


# ══════════════════════════════════════════════════════════════════════
# 5. DLP Timing Scaling
# ══════════════════════════════════════════════════════════════════════

def mode_timing():
    print(f"\n{Fore.YELLOW}  Running BSGS timing across key sizes...{Style.RESET_ALL}")
    bit_sizes = [12, 16, 20, 24, 28, 32, 36, 40]
    trials = 3
    results = []

    for bits in bit_sizes:
        times = []
        for _ in range(trials):
            p = next_prime(random.randint(2**(bits-1), 2**bits))
            g = find_generator(p)
            xv = random.randint(2, p - 2)
            hv = pow(g, xv, p)
            t0 = time.perf_counter()
            bsgs(g, hv, p)
            elapsed = time.perf_counter() - t0
            times.append(elapsed)
        avg = sum(times) / len(times)
        results.append((bits, avg))
        sqrt_p = 2 ** (bits / 2)
        print(f"    {bits:2d}-bit:  avg {avg:.6f}s  (sqrt(p) ~ {sqrt_p:.0f})")

    bits_list = [r[0] for r in results]
    times_list = [r[1] for r in results]

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor("#1a1a2e")
    ax.set_facecolor("#16213e")

    ax.semilogy(bits_list, times_list, "o-", color="#e94560", linewidth=2.5,
                markersize=10, markeredgecolor="white", markeredgewidth=1)

    # Theoretical O(2^(b/2)) reference line
    ref = [times_list[0] * (2**((b - bits_list[0])/2)) for b in bits_list]
    ax.semilogy(bits_list, ref, "--", color="#0f3460", linewidth=1.5,
                alpha=0.7, label="Theoretical O(2^(b/2))")

    ax.fill_between(bits_list, times_list, [t * 0.001 for t in times_list],
                    alpha=0.1, color="#e94560")

    ax.set_xlabel("Prime bit-size (b)", color="white", fontsize=13)
    ax.set_ylabel("BSGS solve time (seconds)", color="white", fontsize=13)
    ax.set_title("DLP Difficulty vs. Key Size", color="white", fontsize=15, pad=15)
    ax.legend(facecolor="#16213e", edgecolor="white", labelcolor="white", fontsize=11)
    ax.tick_params(colors="white")
    ax.grid(True, alpha=0.2, color="white")
    for spine in ax.spines.values(): spine.set_color("#333")

    # Annotation — positioned below the data to avoid overlapping the title
    ax.annotate(
        "At 2048 bits: ~2^1024 steps\n(heat death of the universe)",
        xy=(bits_list[-1], times_list[-1]),
        xytext=(bits_list[2], times_list[-1] * 0.6),
        fontsize=10, color="white",
        arrowprops=dict(arrowstyle="->", color="#e94560", lw=1.5),
        bbox=dict(boxstyle="round,pad=0.4", fc="#16213e", ec="#e94560", alpha=0.9),
    )

    fig.tight_layout()
    out = os.path.join(os.path.dirname(__file__), "dlp_timing.png")
    fig.savefig(out, dpi=150, facecolor=fig.get_facecolor())
    print(f"\n  Plot saved to {out}")
    plt.show()


# ══════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════

def main():
    print_banner()
    while True:
        choice = menu().strip()
        if choice == "1":
            mode_encrypt_decrypt()
        elif choice == "2":
            mode_crack()
        elif choice == "3":
            mode_naive_vs_bsgs()
        elif choice == "4":
            mode_probabilistic()
        elif choice == "5":
            mode_timing()
        elif choice == "6":
            print(f"\n{Fore.CYAN}  g^x mod p = h. Good luck solving that.{Style.RESET_ALL}\n")
            break
        else:
            print(f"{Fore.RED}  Invalid choice.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
