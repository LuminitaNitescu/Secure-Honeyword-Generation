"""
model_evolving.py — Evolving-Password Model (Algorithm 2, Section 5.3.1a).

Overview
--------
The evolving-password model generates honeywords by drawing replacement
tokens from a frequency database that grows with every new user registration
(hence "evolving").  The key insight is that honeywords should be drawn from
the same statistical distribution as real user passwords, making them
indistinguishable to an attacker.

Algorithm (Section 7)
---------------------
Given password p and frequency database DB:

1.  Register p in DB (Algorithm 1 step), updating pattern and token counts.
2.  List1 ← all patterns in DB with the same frequency as p's pattern.
3.  Split p into tokens; for each token type collect peers of the same
    frequency:
        List2 ← same-freq alpha tokens
        List3 ← same-freq digit tokens
        List4 ← same-freq special-char tokens
4.  Repeat until k-1 honeywords accepted:
      a. Pick a random pattern from List1.
      b. For each slot, pick a random token from the appropriate list.
      c. Reject if: equal to p, duplicate, or Levenshtein(p, hw) < min_dist.
5.  Insert p at a uniformly random position → sweetword list W_i; record c(i).

Fix applied (gap 1):
    The paper requires per-slot frequency matching: each token position in
    the honeyword should be filled from candidates that match *that position's*
    token frequency, not a single global pool for all alpha/digit/special slots.

    Previously, only the *first* alpha token, first digit token, and first
    special token were used as global reference values, producing one flat
    pool for all slots of that type.  This loses fidelity for passwords like
    "tiger$2020go" (two alpha tokens with different frequencies).

    The fix builds a per-slot candidate list keyed by the token's position
    index, so slot 0 (alpha "tiger") and slot 3 (alpha "go") each get their
    own frequency-matched pool.  Generation then draws from the pool that
    corresponds to each slot in the chosen pattern.

Length filter:
    Honeywords whose length deviates from the password length by more than
    max_len_delta are rejected.  This prevents machine-generated candidates
    that are obviously longer or shorter than the real password from being
    included in the sweetword list.  Default tolerance is ±3 characters, which
    covers natural variation while excluding the extreme outliers seen with
    large real-world corpora (e.g. RockYou, Yahoo).
"""
from __future__ import annotations

import random
import string

from frequency_db import FrequencyDatabase, _augment_alpha, _augment_digits, _SPECIAL_CHARS
from honeychecker import SweetwordList
from levenshtein  import levenshtein
from tokenizer    import tokenize, get_pattern, parse_pattern


def generate_honeywords_evolving(password, db, k=20, min_lev_dist=3,
                                  max_len_delta=3, max_attempts_factor=200):
    """
    Algorithm 2 — Evolving-Password Model.

    Parameters
    ----------
    password            : the real user password (sugarword)
    db                  : FrequencyDatabase — updated in-place (evolving)
    k                   : total sweetwords; default 20
    min_lev_dist        : minimum Levenshtein distance for typo-safety; default 3
    max_len_delta       : maximum allowed length difference between password and
                          any honeyword; default 3.  Set to None to disable.
    max_attempts_factor : generation retry cap = k × factor; raised to 200 to
                          accommodate the extra length filter rejections.
    """
    # ── Step 1: evolve the database with this registration ────────────────────
    db.add_password(password)

    tokens      = tokenize(password)
    pwd_pattern = get_pattern(tokens)
    pwd_len     = len(password)
    warnings    = []

    # ── List1: same-frequency patterns ───────────────────────────────────────
    list1, tol = db.candidates_for('P', pwd_pattern, tolerance=0)
    if tol != 0:
        warnings.append(f"Pattern '{pwd_pattern}' exact-freq empty; used tolerance={tol}.")
    if not list1:
        list1 = [pwd_pattern]
        warnings.append("No pattern candidates; reusing password pattern.")

    # ── Per-slot candidate pools (gap 1 fix) ─────────────────────────────────
    # Build one candidate list per token position, keyed by position index.
    # This preserves per-slot frequency fidelity: if the password has two alpha
    # tokens "tiger" (freq 4) and "go" (freq 1), slot 0 gets freq-4 alpha peers
    # and slot 3 gets freq-1 alpha peers, rather than merging them into one pool.
    slot_pools    = {}
    ref_digit_len = 2

    for idx, tok in enumerate(tokens):
        cands, tol_used = db.candidates_for(
            tok.type,
            tok.value.lower() if tok.type == 'A' else tok.value,
            tolerance=0,
        )
        if tol_used != 0:
            warnings.append(
                f"Token[{idx}] '{tok.value}' ({tok.type}) exact-freq empty; "
                f"used tolerance={tol_used}."
            )
        if tok.type == 'A' and len(cands) < 15:
            cands = _augment_alpha(cands, 20)
        elif tok.type == 'D':
            ref_digit_len = len(tok.value)
            if len(cands) < 15:
                cands = _augment_digits(cands, 20, ref_digit_len)
        slot_pools[idx] = cands

    # Build per-type ordered queues so each slot in the chosen pattern can be
    # mapped to the correct per-slot pool from the password tokens.
    type_queues = {'A': [], 'D': [], 'S': []}
    for idx, tok in enumerate(tokens):
        type_queues[tok.type].append(idx)

    # ── Filter List1 to patterns we can actually fill ─────────────────────────
    alpha_pool_any = [p for idx, p in slot_pools.items() if tokens[idx].type == 'A']
    has_alpha_pool = any(alpha_pool_any)

    def _satisfiable(pat):
        return all(
            not (p['type'] == 'A' and not has_alpha_pool)
            for p in parse_pattern(pat)
        )

    list1_ok = [p for p in list1 if _satisfiable(p)]
    if pwd_pattern not in list1_ok:
        list1_ok.append(pwd_pattern)

    # Fallback pools used when a pattern slot type has no password-token peer
    fallback_alpha   = _augment_alpha([], 20)
    fallback_digits  = _augment_digits([], 20, ref_digit_len)
    fallback_special = list(_SPECIAL_CHARS)

    list_sizes = {'L1': len(list1_ok), 'slots': len(slot_pools)}

    # ── Step 4: generate k-1 honeywords ──────────────────────────────────────
    honeywords   = []
    attempts     = 0
    max_attempts = k * max_attempts_factor

    while len(honeywords) < k - 1 and attempts < max_attempts:
        attempts += 1
        chosen_pattern = random.choice(list1_ok)
        parts    = parse_pattern(chosen_pattern)
        hw_parts = []
        valid    = True
        type_counters = {'A': 0, 'D': 0, 'S': 0}

        for part in parts:
            ptype    = part['type']
            type_idx = type_counters[ptype]
            type_counters[ptype] += 1

            # Map this slot to the correct per-slot pool from the password
            matching = type_queues[ptype]
            if type_idx < len(matching):
                pool = slot_pools[matching[type_idx]]
            else:
                # Pattern has more slots of this type than the password;
                # fall back to the last available pool of this type
                if matching:
                    pool = slot_pools[matching[-1]]
                elif ptype == 'A':
                    pool = fallback_alpha
                elif ptype == 'D':
                    pool = fallback_digits
                else:
                    pool = fallback_special

            if ptype == 'A':
                if not pool:
                    valid = False; break
                hw_parts.append(random.choice(pool))
            elif ptype == 'D':
                hw_parts.append(
                    random.choice(pool) if pool
                    else ''.join(random.choices(string.digits, k=ref_digit_len))
                )
            elif ptype == 'S':
                slen = part['len']
                if pool:
                    s = random.choice(pool)
                    # Preserve required special-char length (paper spec)
                    s = (s * (slen // len(s) + 1))[:slen] if len(s) < slen else s[:slen]
                    hw_parts.append(s)
                else:
                    hw_parts.append(''.join(random.choices(_SPECIAL_CHARS, k=slen)))

        if not valid:
            continue

        hw = ''.join(hw_parts)
        if not hw or hw == password or hw in honeywords:
            continue

        # ── Length filter ─────────────────────────────────────────────────────
        if max_len_delta is not None and abs(len(hw) - pwd_len) > max_len_delta:
            continue

        if levenshtein(password, hw) >= min_lev_dist:
            honeywords.append(hw)

    if len(honeywords) < k - 1:
        warnings.append(
            f"Only generated {len(honeywords)} honeywords (wanted {k-1}) "
            f"after {max_attempts} attempts. Consider relaxing max_len_delta "
            f"(currently {max_len_delta}) or loading a larger corpus."
        )

    # ── Step 5: insert sugarword at a random position ─────────────────────────
    total       = len(honeywords) + 1
    sugar_index = random.randint(1, total)
    sweetwords  = honeywords[:sugar_index-1] + [password] + honeywords[sugar_index-1:]

    return SweetwordList(sweetwords=sweetwords, sugarword_index=sugar_index,
                         password_pattern=pwd_pattern, list_sizes=list_sizes,
                         warnings=warnings)