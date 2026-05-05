"""
ElGamal Encryption: Interactive Demo and DLP Visualizations
Companion to MAT331 ElGamal Project - Riki Hernandez, May 2026

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
from mpl_toolkits.mplot3d import Axes3D, proj3d

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
       ║        Public Key Encryption over Z_p*                     ║
       ║        MAT331 - Riki Hernandez - May 2026                 ║
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
    menu_text = [
        "  ┌──────────────────────────────────────────┐",
        "  │  1. Encrypt / Decrypt a message          │",
        "  │  2. Crack a key (BSGS attack)            │",
        "  │  3. 3D: DLP One-Way Landscape            │",
        "  │  4. 3D: Ciphertext Cloud                 │",
        "  │  5. 3D: DLP Needle in a Haystack          │",
        "  │  6. Quit                                 │",
        "  └──────────────────────────────────────────┘",
    ]
    for line in menu_text:
        print(f"{Fore.CYAN}{line}{Style.RESET_ALL}")
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
# Shared 3D styling helpers
# ══════════════════════════════════════════════════════════════════════

BG_DARK = "#1a1a2e"
BG_PANE = "#16213e"
C_ACCENT = "#e94560"
C_DEEP = "#0f3460"
C_TEAL = "#00b4d8"

def style_3d_ax(ax):
    ax.set_facecolor(BG_PANE)
    ax.xaxis.set_pane_color((0.086, 0.129, 0.243, 1.0))
    ax.yaxis.set_pane_color((0.086, 0.129, 0.243, 1.0))
    ax.zaxis.set_pane_color((0.086, 0.129, 0.243, 1.0))
    ax.tick_params(axis='x', colors='white')
    ax.tick_params(axis='y', colors='white')
    ax.tick_params(axis='z', colors='white')
    ax.xaxis.label.set_color('white')
    ax.yaxis.label.set_color('white')
    ax.zaxis.label.set_color('white')
    for line in ax.xaxis.get_gridlines() + ax.yaxis.get_gridlines() + ax.zaxis.get_gridlines():
        line.set_alpha(0.15)
        line.set_color('white')

def style_2d_ax(ax):
    ax.set_facecolor(BG_PANE)
    ax.tick_params(colors="white")
    ax.grid(True, alpha=0.15, color="white")
    for spine in ax.spines.values():
        spine.set_color("#333")


# ══════════════════════════════════════════════════════════════════════
# 3. 3D DLP One-Way Landscape
# ══════════════════════════════════════════════════════════════════════

def mode_dlp_landscape():
    print(f"\n{Fore.YELLOW}  Building DLP one-way function landscape...{Style.RESET_ALL}")

    # Use multiple primes so y-axis shows chaos SCALING with prime size
    primes = [17, 31, 47, 67, 89, 97]
    max_exp = 50  # exponents 0..49 for visual clarity

    # Build surface: X=exponent, Y=prime index, Z=g^x mod p (normalized to [0,1])
    X_exp = np.arange(max_exp)
    Y_idx = np.arange(len(primes))
    X_mesh, Y_mesh = np.meshgrid(X_exp, Y_idx)
    Z_mesh = np.zeros_like(X_mesh, dtype=float)

    for yi, p in enumerate(primes):
        g = find_generator(p)
        for xi in range(max_exp):
            Z_mesh[yi, xi] = pow(g, xi, p) / p  # normalize to [0,1]
        print(f"    p={p:3d}, g={g}: outputs span 1..{p-1}")

    # Pick largest prime for the 2D slice
    p_main = primes[-1]
    g_main = find_generator(p_main)
    exponents = list(range(max_exp))
    outputs = [pow(g_main, x, p_main) for x in exponents]

    fig = plt.figure(figsize=(15, 7))
    fig.patch.set_facecolor(BG_DARK)
    fig.suptitle("DLP One-Way Function: Chaos Grows with Prime Size",
                 color="white", fontsize=14, y=0.95)

    # Left: 3D surface across multiple primes
    ax1 = fig.add_subplot(121, projection='3d')
    style_3d_ax(ax1)
    ax1.plot_surface(X_mesh, Y_mesh, Z_mesh, cmap='magma',
                     alpha=0.85, edgecolor='none', antialiased=True)
    ax1.set_xlabel("Exponent x", fontsize=11, labelpad=8)
    ax1.set_ylabel("Prime size", fontsize=11, labelpad=8)
    ax1.set_zlabel("g^x mod p (normalized)", fontsize=10, labelpad=8)
    ax1.set_yticks(Y_idx)
    ax1.set_yticklabels([str(p) for p in primes], fontsize=8)
    ax1.set_title("g^x mod p across primes\nLarger p = more chaotic",
                  color="white", fontsize=12, pad=5)
    ax1.view_init(elev=25, azim=-60)

    # Right: 2D slice for largest prime
    ax2 = fig.add_subplot(122)
    style_2d_ax(ax2)
    ax2.scatter(exponents, outputs, c=C_ACCENT, s=18, alpha=0.8,
                edgecolors="none", zorder=3)
    ax2.plot(exponents, outputs, color=C_DEEP, alpha=0.3, linewidth=0.8)
    ax2.set_xlabel("Exponent x", color="white", fontsize=12)
    ax2.set_ylabel(f"{g_main}^x mod {p_main}", color="white", fontsize=12)
    ax2.set_title(f"2D slice: g={g_main}, p={p_main}\nGiven an output, find x=?",
                  color="white", fontsize=12)
    target_x = 30
    ax2.axhline(y=outputs[target_x], color=C_TEAL, linestyle="--", alpha=0.6, linewidth=1.5)
    ax2.annotate(f"output={outputs[target_x]}, find x=?",
                 xy=(target_x, outputs[target_x]),
                 xytext=(5, outputs[target_x] + p_main * 0.15),
                 fontsize=9, color=C_TEAL,
                 arrowprops=dict(arrowstyle="->", color=C_TEAL, lw=1.2),
                 bbox=dict(boxstyle="round,pad=0.3", fc=BG_PANE, ec=C_TEAL, alpha=0.9))

    # Toggle: wireframe vs surface
    ax_btn = plt.axes([0.02, 0.02, 0.12, 0.05])
    btn = Button(ax_btn, 'Wireframe', color=BG_PANE, hovercolor="#333")
    btn.label.set_color("white")
    btn.label.set_fontsize(9)
    state = {"wireframe": False}

    def toggle_wireframe(event):
        ax1.clear()
        style_3d_ax(ax1)
        if not state["wireframe"]:
            ax1.plot_wireframe(X_mesh, Y_mesh, Z_mesh, color=C_ACCENT, alpha=0.6, linewidth=0.5)
            btn.label.set_text("Surface")
            state["wireframe"] = True
        else:
            ax1.plot_surface(X_mesh, Y_mesh, Z_mesh, cmap='magma', alpha=0.85,
                           edgecolor='none', antialiased=True)
            btn.label.set_text("Wireframe")
            state["wireframe"] = False
        ax1.set_xlabel("Exponent x", fontsize=11, labelpad=8)
        ax1.set_ylabel("Prime size", fontsize=11, labelpad=8)
        ax1.set_zlabel("g^x mod p (normalized)", fontsize=10, labelpad=8)
        ax1.set_yticks(Y_idx)
        ax1.set_yticklabels([str(p) for p in primes], fontsize=8)
        ax1.set_title("g^x mod p across primes\nLarger p = more chaotic",
                      color="white", fontsize=12, pad=5)
        ax1.view_init(elev=25, azim=-60)
        fig.canvas.draw_idle()

    btn.on_clicked(toggle_wireframe)

    fig.subplots_adjust(left=0.05, right=0.95, top=0.88, bottom=0.12, wspace=0.3)
    out = os.path.join(os.path.dirname(__file__), "dlp_landscape_3d.png")
    fig.savefig(out, dpi=150, facecolor=fig.get_facecolor())
    print(f"\n  Plot saved to {out}")
    plt.show()


# ══════════════════════════════════════════════════════════════════════
# 4. 3D Ciphertext Cloud
# ══════════════════════════════════════════════════════════════════════

def mode_ciphertext_cloud():
    print(f"\n{Fore.YELLOW}  Building 3D ciphertext cloud...{Style.RESET_ALL}")
    p, g, x_priv, h = keygen(16)
    print(f"    Generated 16-bit key: p={p}")

    n_enc = 200
    letters = {"A": 65, "B": 66, "C": 67}
    data = {}  # letter -> (c1_list, c2_list, z_list)

    for ch, byte_val in letters.items():
        c1s, c2s, zs = [], [], []
        for _ in range(n_enc):
            c1, c2 = encrypt(byte_val, p, g, h)
            c1s.append(c1)
            c2s.append(c2)
            zs.append(byte_val)
        data[ch] = (c1s, c2s, zs)
        print(f"    Encrypted '{ch}' x{n_enc}")

    fig = plt.figure(figsize=(15, 7))
    fig.patch.set_facecolor(BG_DARK)
    fig.suptitle("Probabilistic Encryption: Same Plaintext, Different Ciphertexts",
                 color="white", fontsize=14, y=0.95)

    # Left: 3D scatter
    ax1 = fig.add_subplot(121, projection='3d')
    style_3d_ax(ax1)

    layer_colors = {"A": C_ACCENT, "B": C_DEEP, "C": C_TEAL}
    scatter_handles = {}
    for ch, (c1s, c2s, zs) in data.items():
        sc = ax1.scatter(c1s, c2s, zs, c=layer_colors[ch], s=10, alpha=0.6,
                         label=f"'{ch}' (z={letters[ch]})", depthshade=True)
        scatter_handles[ch] = sc

    ax1.set_xlabel("c1 = g^k mod p", fontsize=10, labelpad=8)
    ax1.set_ylabel("c2 = m*h^k mod p", fontsize=10, labelpad=8)
    ax1.set_zlabel("Plaintext value", fontsize=10, labelpad=8)
    ax1.set_title("3D Ciphertext Space\nEach z-layer = one plaintext letter",
                  color="white", fontsize=12, pad=5)
    ax1.legend(facecolor=BG_PANE, edgecolor="white", labelcolor="white", fontsize=9)
    ax1.view_init(elev=20, azim=-45)

    # Right: 2D projection (c1 vs c2), all layers overlapping
    ax2 = fig.add_subplot(122)
    style_2d_ax(ax2)
    for ch, (c1s, c2s, _) in data.items():
        ax2.scatter(c1s, c2s, c=layer_colors[ch], s=12, alpha=0.5,
                    edgecolors="none", label=f"'{ch}'")
    ax2.set_xlabel("c1", color="white", fontsize=12)
    ax2.set_ylabel("c2", color="white", fontsize=12)
    ax2.set_title("2D Projection (top-down)\nClouds overlap: adversary can't distinguish",
                  color="white", fontsize=12)
    ax2.legend(facecolor=BG_PANE, edgecolor="white", labelcolor="white",
               fontsize=10, markerscale=3)

    # Toggle button: show/hide layers
    ax_btn = plt.axes([0.02, 0.02, 0.14, 0.05])
    btn = Button(ax_btn, 'Toggle A only', color=BG_PANE, hovercolor="#333")
    btn.label.set_color("white")
    btn.label.set_fontsize(9)
    state = {"mode": "all"}

    def toggle_layers(event):
        if state["mode"] == "all":
            scatter_handles["B"].set_alpha(0.0)
            scatter_handles["C"].set_alpha(0.0)
            scatter_handles["A"].set_alpha(0.9)
            btn.label.set_text("Show all")
            state["mode"] = "A_only"
        else:
            scatter_handles["A"].set_alpha(0.6)
            scatter_handles["B"].set_alpha(0.6)
            scatter_handles["C"].set_alpha(0.6)
            btn.label.set_text("Toggle A only")
            state["mode"] = "all"
        fig.canvas.draw_idle()

    btn.on_clicked(toggle_layers)

    # Hover annotation
    annot_3d = ax1.text2D(0.02, 0.95, "", transform=ax1.transAxes,
                          color="white", fontsize=9,
                          bbox=dict(boxstyle="round", fc=BG_PANE, ec=C_ACCENT, alpha=0.9))
    annot_3d.set_visible(False)

    def on_motion(event):
        if event.inaxes == ax1:
            annot_3d.set_text(f"p={p} | {n_enc} encryptions per letter | Rotate to explore")
            annot_3d.set_visible(True)
        else:
            annot_3d.set_visible(False)
        fig.canvas.draw_idle()

    fig.canvas.mpl_connect('motion_notify_event', on_motion)

    fig.subplots_adjust(left=0.05, right=0.95, top=0.88, bottom=0.12, wspace=0.3)
    out = os.path.join(os.path.dirname(__file__), "ciphertext_cloud_3d.png")
    fig.savefig(out, dpi=150, facecolor=fig.get_facecolor())
    print(f"\n  Plot saved to {out}")
    plt.show()


# ══════════════════════════════════════════════════════════════════════
# 5. 3D DLP Needle in a Haystack
# ══════════════════════════════════════════════════════════════════════

def mode_bsgs_helix():
    print(f"\n{Fore.YELLOW}  Building DLP needle in a haystack...{Style.RESET_ALL}")

    p = 97
    g = find_generator(p)
    x_secret = random.randint(2, p - 3)
    h = pow(g, x_secret, p)
    n = p - 1  # group order
    m = math.isqrt(n) + 1
    print(f"    p={p}, g={g}, target h={h}")
    print(f"    Secret x={x_secret} (the needle)")
    print(f"    Haystack size: {n} possible exponents")
    print(f"    Odds of guessing: 1/{n} = {100/n:.1f}%")

    # Compute g^x mod p for every candidate x, measure distance from target h
    candidates = list(range(n))
    values = [pow(g, x, p) for x in candidates]
    # Distance: circular distance in Z_p (min of |val-h| and p-|val-h|)
    distances = [min(abs(v - h), p - abs(v - h)) for v in values]

    # Bar colors: the needle is bright, everything else is dim
    bar_colors = []
    for x in candidates:
        if x == x_secret:
            bar_colors.append("yellow")
        else:
            bar_colors.append(C_ACCENT)

    fig = plt.figure(figsize=(16, 7))
    fig.patch.set_facecolor(BG_DARK)
    fig.suptitle(f"Finding x where {g}^x = {h} (mod {p}): 1 Needle in {n} Candidates",
                 color="white", fontsize=14, y=0.95)

    # Left: 3D bar chart showing every candidate's distance from target
    ax1 = fig.add_subplot(121, projection='3d')
    style_3d_ax(ax1)

    xs = np.array(candidates)
    ys = np.zeros_like(xs)
    zs = np.zeros_like(xs)
    dx = np.ones_like(xs) * 0.8
    dy = np.ones_like(xs) * 0.8
    dz = np.array(distances, dtype=float)

    # Normalize distances for coloring
    max_d = max(distances) if max(distances) > 0 else 1
    norm_d = [d / max_d for d in distances]
    rgba_colors = []
    for x_val, nd in zip(candidates, norm_d):
        if x_val == x_secret:
            rgba_colors.append((1.0, 1.0, 0.0, 1.0))  # yellow needle
        else:
            rgba_colors.append((0.91, 0.27, 0.37, 0.3 + 0.5 * nd))  # C_ACCENT with alpha

    ax1.bar3d(xs, ys, zs, dx, dy, dz, color=rgba_colors, zsort='average')

    # Mark the needle explicitly
    ax1.scatter([x_secret], [0], [0], c="yellow", s=150, marker="*", zorder=10)

    ax1.set_xlabel("Candidate x", fontsize=10, labelpad=8)
    ax1.set_ylabel("", fontsize=1)
    ax1.set_zlabel("Distance from target h", fontsize=10, labelpad=8)
    ax1.set_title(f"Every wrong guess towers above\nOnly x={x_secret} hits zero",
                  color="white", fontsize=12, pad=5)
    ax1.set_yticks([])
    ax1.view_init(elev=25, azim=-70)

    # Right: 2D "skyline" view with BSGS overlay
    ax2 = fig.add_subplot(122)
    style_2d_ax(ax2)

    # Draw all bars as a skyline
    bar_cols_2d = [("yellow" if x == x_secret else C_ACCENT) for x in candidates]
    bar_alphas = [(1.0 if x == x_secret else 0.4) for x in candidates]
    bars = ax2.bar(candidates, distances, width=1.0, color=bar_cols_2d, edgecolor="none")
    for bar, alpha in zip(bars, bar_alphas):
        bar.set_alpha(alpha)

    # Mark the needle
    ax2.annotate(f"x={x_secret}\n(the answer)",
                 xy=(x_secret, 0), xytext=(x_secret + n * 0.15, max(distances) * 0.3),
                 fontsize=10, color="yellow", fontweight="bold",
                 arrowprops=dict(arrowstyle="->", color="yellow", lw=2),
                 bbox=dict(boxstyle="round,pad=0.3", fc=BG_PANE, ec="yellow", alpha=0.9))

    # Show BSGS efficiency
    bsgs_text = (f"Guessing: 1/{n} chance ({100/n:.1f}%)\n"
                 f"Naive search: up to {n} checks\n"
                 f"BSGS: only {2*m} checks (sqrt)\n"
                 f"At 2048 bits: 2^2048 candidates\n"
                 f"  BSGS still needs 2^1024")
    ax2.text(0.98, 0.98, bsgs_text, transform=ax2.transAxes,
             fontsize=9, color="white", verticalalignment='top', horizontalalignment='right',
             bbox=dict(boxstyle="round,pad=0.5", fc=BG_PANE, ec=C_TEAL, alpha=0.9),
             family='monospace')

    ax2.set_xlabel("Candidate exponent x", color="white", fontsize=12)
    ax2.set_ylabel("Distance from target h", color="white", fontsize=12)
    ax2.set_title(f"The haystack: {n} candidates, 1 correct\n"
                  f"How lucky would you have to be?",
                  color="white", fontsize=12)

    # Toggle: show BSGS checked candidates
    ax_btn = plt.axes([0.02, 0.02, 0.15, 0.05])
    btn = Button(ax_btn, 'Show BSGS path', color=BG_PANE, hovercolor="#333")
    btn.label.set_color("white")
    btn.label.set_fontsize(9)
    state = {"showing_bsgs": False}

    def toggle_bsgs(event):
        if not state["showing_bsgs"]:
            # Highlight which candidates BSGS actually checks
            # Baby steps check: x = 0, 1, ..., m-1
            for j in range(m):
                ax2.axvline(x=j, color=C_TEAL, alpha=0.4, linewidth=1.5)
            # Giant steps check: x = 0, m, 2m, 3m, ...
            for i in range(m):
                ax2.axvline(x=(i * m) % n, color=C_DEEP, alpha=0.6, linewidth=1.5, linestyle=":")
            ax2.text(0.02, 0.02, f"Teal = {m} baby steps | Blue = {m} giant steps | Total: {2*m}/{n}",
                     transform=ax2.transAxes, fontsize=8, color=C_TEAL,
                     bbox=dict(fc=BG_PANE, ec=C_TEAL, alpha=0.9, boxstyle="round,pad=0.3"))
            btn.label.set_text("Hide BSGS")
            state["showing_bsgs"] = True
        fig.canvas.draw_idle()

    btn.on_clicked(toggle_bsgs)

    fig.subplots_adjust(left=0.05, right=0.95, top=0.88, bottom=0.12, wspace=0.25)
    out = os.path.join(os.path.dirname(__file__), "dlp_needle_3d.png")
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
            mode_dlp_landscape()
        elif choice == "4":
            mode_ciphertext_cloud()
        elif choice == "5":
            mode_bsgs_helix()
        elif choice == "6":
            print(f"\n{Fore.CYAN}  g^x mod p = h. Good luck solving that.{Style.RESET_ALL}\n")
            break
        else:
            print(f"{Fore.RED}  Invalid choice.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
