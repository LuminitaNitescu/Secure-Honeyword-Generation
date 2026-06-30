"""
verify_append_secret.py — Verifies the three security claims of the
Append-Secret Model that a guessing attacker (List/Hashmob/etc.) cannot
test, since every sweetword is password+random_hex and carries no
guessable distribution.

1. Flatness    — hash fragments are uniform, so no honeyword is more
                  guessable than another.
2. Brute force  — cost to find (l, r) if the honeychecker is compromised.
3. MSIO/MSII    — stored values across independent sites are uncorrelated.
"""

import math
import random
from collections import Counter

from honeychecker import Honeychecker
from append_secret_model import (
    generate_honeywords_append_secret,
    _L_ALPHABET,
    _compute_x,
)

HEX_ALPHABET = "0123456789abcdef"
HEX_LEN      = 5


# ── 1. Flatness: are hash fragments uniform? ──────────────────────────────

def check_flatness(n_trials=20_000):
    counts = Counter()
    for _ in range(n_trials):
        r = ''.join(random.choices(_L_ALPHABET, k=3))
        l = ''.join(random.choices(_L_ALPHABET, k=3))
        x = _compute_x("samplepassword1!", l, r)
        for ch in x:
            counts[ch] += 1

    total    = sum(counts.values())
    expected = total / len(HEX_ALPHABET)
    chi2     = sum((counts.get(c, 0) - expected) ** 2 / expected for c in HEX_ALPHABET)
    # 15 degrees of freedom (16 hex chars - 1); critical value at p=0.01 is ~30.58
    passed = chi2 < 30.58
    print(f"[1] Flatness (uniformity of hash fragments, n={n_trials}):")
    print(f"    chi^2 = {chi2:.2f}  (pass if < 30.58)  -> {'PASS' if passed else 'FAIL'}")
    return passed


# ── 2. Brute-force cost if honeychecker is compromised ────────────────────

def check_bruteforce_cost():
    I = len(_L_ALPHABET)

    def n_choose_k_strings(alphabet_size, length):
        return alphabet_size ** length  # l/r are drawn with replacement

    l_space = sum(n_choose_k_strings(I, n) for n in (2, 3, 4))
    r_space = n_choose_k_strings(I, 3)
    total   = l_space * r_space

    print(f"[2] Brute-force cost (honeychecker compromised, alphabet size I={I}):")
    print(f"    |l|-space (len 2-4) = {l_space:,}")
    print(f"    |r|-space (len 3)   = {r_space:,}")
    print(f"    total combinations  = {total:,}  (~2^{math.log2(total):.1f})")
    return total


# ── 3. MSIO/MSII: are stored values uncorrelated across sites ────────────

def check_msio_msii(n_sites=5):
    username, password, l = "alice", "samplepassword1!", "q9"
    stored_values = []

    for site in range(n_sites):
        hc = Honeychecker()
        sw = generate_honeywords_append_secret(username, password, l, hc, k=20)
        real = sw.sweetwords[sw.sugarword_index - 1]
        stored_values.append(real)

    distinct = len(set(stored_values)) == len(stored_values)
    # crude correlation check: no shared 5-char suffix across sites
    suffixes  = [v[-5:] for v in stored_values]
    no_repeat = len(set(suffixes)) == len(suffixes)

    passed = distinct and no_repeat
    print(f"[3] MSIO/MSII resistance ({n_sites} sites, same username/password/l):")
    print(f"    all stored values distinct : {distinct}")
    print(f"    all hash suffixes distinct : {no_repeat}")
    print(f"    -> {'PASS' if passed else 'FAIL'}")
    return passed


if __name__ == "__main__":
    print("Append-Secret Model — Security Verification\n" + "=" * 44)
    r1 = check_flatness()
    print()
    check_bruteforce_cost()
    print()
    r3 = check_msio_msii()
    print("\n" + "=" * 44)
    print("Overall:", "PASS" if (r1 and r3) else "FAIL")