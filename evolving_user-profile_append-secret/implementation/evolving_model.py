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

    # ── Per-slot candidate pools ─────────────────────────────────
    # Build one candidate list per token position, keyed by position index.
    # This preserves per-slot frequency fidelity: if the password has two alpha
    # tokens "tiger" (freq 4) and "go" (freq 1), slot 0 gets freq-4 alpha peers
    # and slot 3 gets freq-1 alpha peers, rather than merging them into one pool.
    slot_pools     = {}
    slot_digit_len = {}   # per-slot digit length, keyed by token position
    last_digit_len = 2    # used only for the final un-keyed fallback pool below
    full_fallback_slots = 0   # count of slots that hit tol=-1 (entire vocabulary)

    for idx, tok in enumerate(tokens):
        cands, tol_used = db.candidates_for(
            tok.type,
            tok.value.lower() if tok.type == 'A' else tok.value,
            tolerance=0,
        )
        if tol_used == -1:
            full_fallback_slots += 1
            warnings.append(
                f"Token[{idx}] '{tok.value}' ({tok.type}) had no frequency "
                f"match even after widening tolerance; drew from the entire "
                f"{tok.type}-type vocabulary instead. Honeyword quality for "
                f"this slot is reduced — consider a larger corpus."
            )
        elif tol_used != 0:
            warnings.append(
                f"Token[{idx}] '{tok.value}' ({tok.type}) exact-freq empty; "
                f"used tolerance={tol_used}."
            )
        if tok.type == 'A' and len(cands) < 15:
            cands = _augment_alpha(cands, 20)
        elif tok.type == 'D':
            this_digit_len = len(tok.value)
            slot_digit_len[idx] = this_digit_len
            last_digit_len = this_digit_len
            if len(cands) < 15:
                cands = _augment_digits(cands, 20, this_digit_len)
        slot_pools[idx] = cands

    # Build per-type ordered queues so each slot in the chosen pattern can be
    # mapped to the correct per-slot pool from the password tokens.
    type_queues = {'A': [], 'D': [], 'S': []}
    for idx, tok in enumerate(tokens):
        type_queues[tok.type].append(idx)

    # ── Filter List1 to patterns we can actually fill ─────────────────────────
    # Candidates_for('P', ...) matches purely on *frequency count*,so it can 
    # return patterns with a completely different token shape (e.g.'S10' matching
    # an 'AD' password just because both happened to occur the same number of times
    # in the corpus). Per-slot pooling only makes senseif the candidate pattern has
    # the same type-sequence (same count and order of A/D/S slots) as the password's 
    # own pattern — special-char slot *lengths* may still differ.
    pwd_type_seq = [p['type'] for p in parse_pattern(pwd_pattern)]

    def _same_shape(pat):
        return [p['type'] for p in parse_pattern(pat)] == pwd_type_seq

    alpha_pool_any = [p for idx, p in slot_pools.items() if tokens[idx].type == 'A']
    has_alpha_pool = any(alpha_pool_any)

    def _satisfiable(pat):
        return _same_shape(pat) and all(
            not (p['type'] == 'A' and not has_alpha_pool)
            for p in parse_pattern(pat)
        )

    list1_ok = [p for p in list1 if _satisfiable(p)]
    if list1 and not list1_ok:
        warnings.append(
            f"All {len(list1)} frequency-matched pattern candidate(s) for "
            f"'{pwd_pattern}' had a different token shape (e.g. different "
            f"slot count/order); discarded to avoid structurally mismatched "
            f"honeywords. Falling back to the password's own pattern."
        )
    if pwd_pattern not in list1_ok:
        list1_ok.append(pwd_pattern)

    # Fallback pools used when a pattern slot type has no password-token peer
    fallback_alpha   = _augment_alpha([], 20)
    fallback_digits  = _augment_digits([], 20, last_digit_len)
    fallback_special = list(_SPECIAL_CHARS)

    list_sizes = {'L1': len(list1_ok), 'slots': len(slot_pools),
                   'full_fallback_slots': full_fallback_slots}

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
            slot_len_hint = last_digit_len   # default for digit length fallback
            if type_idx < len(matching):
                src_idx = matching[type_idx]
                pool = slot_pools[src_idx]
                if ptype == 'D':
                    slot_len_hint = slot_digit_len.get(src_idx, last_digit_len)
            else:
                # Pattern has more slots of this type than the password;
                # fall back to the last available pool of this type
                if matching:
                    src_idx = matching[-1]
                    pool = slot_pools[src_idx]
                    if ptype == 'D':
                        slot_len_hint = slot_digit_len.get(src_idx, last_digit_len)
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
                    else ''.join(random.choices(string.digits, k=slot_len_hint))
                )
            elif ptype == 'S':
                slen = part['len']
                # Prefer real corpus tokens that are already the exact
                # required length (no tiling/stretching of a shorter token,
                # which previously turned a single '*' into '****').
                exact_len_pool = [s for s in pool if len(s) == slen]
                if exact_len_pool:
                    hw_parts.append(random.choice(exact_len_pool))
                else:
                    # No corpus token of this length: build one from distinct
                    # random special characters rather than repeating one
                    # character slen times.
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