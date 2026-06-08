"""
model_user_profile.py — User-Profile Model (Section 5.3.1b).

Overview
--------
The user-profile model generates honeywords by combining tokens extracted
from the user's personal information (name, date of birth, address, pet
name, etc.).

Security properties
-------------------
- Approximate flatness for users whose passwords contain personal data.
- Moderate DoS resistance.
- Does NOT prevent MSIO or MSII attacks (Legacy-UI category).
- Typo-safe: Levenshtein distance ≥ 3 enforced between p and every honeyword.
- Honeywords with more than one token overlapping the real password are
  rejected (Section 5.3.1b rule).

Fix applied (gap 2):
    Multi-character special-char slots were filled by repeating a single
    character (e.g. slen=2, picked '!' -> "!!"), whereas the password might
    have "!@".  This reduces the diversity of generated honeywords and slightly
    hurts flatness.

    The fix builds multi-character special tokens by sampling *slen* individual
    characters from the special pool (without replacement where possible) and
    joining them, matching the way the password's own multi-char special token
    was formed.
Length filter — same rationale as the evolving model: honeywords that are
                  much longer or shorter than the real password are rejected.
"""

from __future__ import annotations

import re
import random
from dataclasses import dataclass

from frequency_db import _augment_alpha, _augment_digits, _SPECIAL_CHARS
from honeychecker import SweetwordList
from levenshtein  import levenshtein
from tokenizer    import tokenize, get_pattern, parse_pattern


@dataclass
class UserProfile:
    """
    Personal information used by the user-profile model.

    All fields are optional strings.  The model extracts alpha, digit, and
    special-char tokens from the combined text of all provided fields.

    Attributes
    ----------
    name     : full name (e.g. "Alice Wood")
    dob      : date of birth (e.g. "19/07/1995")
    address  : postal address (e.g. "54 West 28th Street")
    pet_name : name of a pet (e.g. "Jerry")
    extra    : any additional personal detail
    """
    name:     str = ''
    dob:      str = ''
    address:  str = ''
    pet_name: str = ''
    extra:    str = ''

    def extract_tokens(self):
        combined = ' '.join([self.name, self.dob, self.address,
                              self.pet_name, self.extra])
        return {
            'token_alphabet': list({
                t.lower()
                for t in re.findall(r'[a-zA-Z]+', combined)
                if len(t) >= 2
            }),
            'token_digits':  list(set(re.findall(r'[0-9]+', combined))),
            'token_special': (list(set(re.findall(r'[!@#$%^&*\-_+=?]', combined)))
                              or list(_SPECIAL_CHARS)),
        }


def _build_special_token(special_pool, slen):
    """
    Sample *slen* individual characters from *special_pool* to form a
    special-char token, producing combinations like "!@" rather than "!!".
    """
    chars = list(special_pool) if special_pool else list(_SPECIAL_CHARS)
    if slen <= len(chars):
        return ''.join(random.sample(chars, slen))
    return ''.join(random.choices(chars, k=slen))


def generate_honeywords_user_profile(password, profile, k=20, min_lev_dist=3,
                                      max_len_delta=3):
    """
    User-Profile Model — generate k-1 honeywords from user personal data.

    Parameters
    ----------
    password      : the real user password
    profile       : UserProfile with personal details
    k             : total sweetwords; default 20
    min_lev_dist  : minimum Levenshtein distance; default 3
    max_len_delta : maximum allowed length difference; default 3.
                    Set to None to disable.
    """
    tp           = profile.extract_tokens()
    alpha_pool   = tp['token_alphabet'] or ['dragon', 'shadow', 'master']
    digit_pool   = tp['token_digits']   or ['99', '01', '2000', '123']
    special_pool = tp['token_special']  or list(_SPECIAL_CHARS)
    warnings     = []

    if len(alpha_pool) < 5:
        alpha_pool = _augment_alpha(alpha_pool, 8)
        warnings.append("Profile alpha pool was small; augmented with fallback words.")
    if len(digit_pool) < 4:
        digit_pool = _augment_digits(digit_pool, 6)

    pwd_tokens  = tokenize(password)
    pwd_pattern = get_pattern(pwd_tokens)
    pwd_vals    = {t.value.lower() for t in pwd_tokens}
    pwd_len     = len(password)

    honeywords = []
    attempts   = 0

    while len(honeywords) < k - 1 and attempts < k * 100:
        attempts += 1
        parts    = parse_pattern(pwd_pattern)
        hw_parts = []

        for part in parts:
            if part['type'] == 'A':
                hw_parts.append(random.choice(alpha_pool))
            elif part['type'] == 'D':
                hw_parts.append(random.choice(digit_pool))
            elif part['type'] == 'S':
                hw_parts.append(_build_special_token(special_pool, part['len']))

        hw = ''.join(hw_parts)
        if not hw or hw == password or hw in honeywords:
            continue

        # Reject if more than one token overlaps with the password
        hw_vals = {t.value.lower() for t in tokenize(hw)}
        if len(pwd_vals & hw_vals) > 1:
            continue

        # ── Length filter ─────────────────────────────────────────────────────
        if max_len_delta is not None and abs(len(hw) - pwd_len) > max_len_delta:
            continue

        if levenshtein(password, hw) >= min_lev_dist:
            honeywords.append(hw)

    if len(honeywords) < k - 1:
        warnings.append(
            f"Only generated {len(honeywords)} honeywords (wanted {k-1}). "
            f"Consider relaxing max_len_delta (currently {max_len_delta}) "
            f"or adding more profile details."
        )

    sugar_index = random.randint(1, len(honeywords) + 1)
    sweetwords  = honeywords[:sugar_index-1] + [password] + honeywords[sugar_index-1:]

    return SweetwordList(sweetwords=sweetwords, sugarword_index=sugar_index,
                         password_pattern=pwd_pattern,
                         list_sizes={'profile_alpha':   len(alpha_pool),
                                     'profile_digit':   len(digit_pool),
                                     'profile_special': len(special_pool)},
                         warnings=warnings)