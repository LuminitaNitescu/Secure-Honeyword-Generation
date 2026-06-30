"""
frequency_db.py — Frequency database (Algorithm 1) and fallback token pools.

Implements the evolving frequency database described in Sections 5.3.1a and 7
of the paper.  The database is updated with every new user registration so
that its distribution diverges from any static, publicly available corpus
an attacker might use.

Key classes
-----------
FreqIndex          Bidirectional index: token → count AND count → {token set}.
                   O(1) exact-frequency candidate lookup, with automatic
                   tolerance-widening fallback.

FrequencyDatabase  Manages four FreqIndex objects (patterns, alpha tokens,
                   digit tokens, special-char tokens).  Exposes
                   candidates_for() and bulk load / save / restore helpers.

Module-level constants
----------------------
PRESET_CORPUS      Small built-in password list used by the CLI and demo
                   when no external corpus file is supplied.
_FALLBACK_ALPHA    Common alpha words used to pad sparse alpha pools.
_SPECIAL_CHARS     Charset used to generate synthetic special-char tokens.
"""
from __future__ import annotations

import collections
import json
import random
import string
from typing import Optional

from tokenizer import tokenize, get_pattern


# ─────────────────────────────────────────────────────────────────────────────
# Fallback token pools
# ─────────────────────────────────────────────────────────────────────────────

_FALLBACK_ALPHA = [
    'dragon', 'shadow', 'master', 'hunter', 'ranger', 'winter', 'summer',
    'forest', 'river',  'stone',  'light',  'dark',   'fire',   'water',
    'moon',   'sun',    'star',   'cloud',  'eagle',  'tiger',  'wolf',
    'bear',   'fox',    'lion',   'hawk',   'dove',   'rose',   'oak',
    'mike',   'john',   'alex',   'chris',  'kate',   'anna',   'emma',
    'nick',   'sam',    'tom',    'secret', 'monkey', 'pepper',
]

_SPECIAL_CHARS = '!@#$%^&*-_+=?'


# Pad *pool* with common alpha words if it's too small, then with random
# letter strings as last resort to reach *target_size*.
def _augment_alpha(pool, target_size):
    pool = list(pool)
    for w in _FALLBACK_ALPHA:
        if len(pool) >= target_size:
            break
        if w not in pool:
            pool.append(w)
    while len(pool) < target_size:
        pool.append(
            ''.join(random.choices(string.ascii_lowercase,
                                   k=random.randint(3, 7)))
        )
    return pool


# Pad *pool* with random digit strings of length *ref_len* until it
# reaches *target_size*.  Automatically increases the length when all
# strings of the current length have been exhausted.
def _augment_digits(pool, target_size, ref_len=2):
    pool = list(pool)
    cur_len = max(ref_len, 1)
    while len(pool) < target_size:
        max_unique = 10 ** cur_len
        existing_of_len = sum(1 for p in pool if len(p) == cur_len)
        if existing_of_len >= max_unique:
            cur_len += 1
            continue
        d = ''.join(random.choices(string.digits, k=cur_len))
        if d not in pool:
            pool.append(d)
    return pool


# ─────────────────────────────────────────────────────────────────────────────
# FreqIndex — bidirectional frequency index
# ─────────────────────────────────────────────────────────────────────────────

class FreqIndex:
    """
    Bidirectional index: token → count  AND  count → {token set}.

    ``candidates()`` uses tolerance=0 (exact match) by default and widens
    only when explicitly requested by the caller.

    Design rationale
    ----------------
    The paper requires honeywords to be drawn from tokens whose frequency
    matches the password token's frequency as closely as possible.  A plain
    dict lookup against the reverse (count → tokens) map makes exact lookups
    O(1) instead of the O(n) scan required by a flat dictionary.
    """

    def __init__(self):
        self._count   = {}
        self._by_freq = collections.defaultdict(set)

    # ── Mutation ─────────────────────────────────────────────────────────────

    # Increment the count for *token* by 1, updating both maps.
    def add(self, token):
        old = self._count.get(token, 0)
        if old > 0:
            self._by_freq[old].discard(token)
            if not self._by_freq[old]:
                del self._by_freq[old]
        new = old + 1
        self._count[token] = new
        self._by_freq[new].add(token)

    # ── Query ─────────────────────────────────────────────────────────────────

    # Return the current count for *token* (0 if unseen).
    def get(self, token):
        return self._count.get(token, 0)

    # Return tokens whose frequency is within ±*tolerance* of *token*'s
    # frequency, excluding *token* itself.
    # ``tolerance=0`` means only tokens with exactly the same frequency
    # are returned (strict paper interpretation).
    def candidates(self, token, tolerance=0):
        f = self._count.get(token, 1)
        result = []
        for delta in range(-tolerance, tolerance + 1):
            bucket = self._by_freq.get(f + delta)
            if bucket:
                result.extend(t for t in bucket if t != token)
        return result

    # Return a list of all tokens in the index.
    def all_tokens(self):
        return list(self._count.keys())

    # Return an iterable of (token, count) pairs for all tokens in the index.
    def items(self):
        return self._count.items()

    # Return the number of unique tokens in the index.
    def __len__(self):
        return len(self._count)

    # ── Serialisation ─────────────────────────────────────────────────────────

    # Convert the index to a plain dict for JSON serialisation.
    def to_dict(self):
        return dict(self._count)

    # Create a FreqIndex from a plain dict of token → count.
    # The reverse map is reconstructed automatically.
    @classmethod
    def from_dict(cls, d):
        obj = cls()
        for token, count in d.items():
            obj._count[token] = count
            obj._by_freq[count].add(token)
        return obj


# ─────────────────────────────────────────────────────────────────────────────
# FrequencyDatabase — Algorithm 1
# ─────────────────────────────────────────────────────────────────────────────

class FrequencyDatabase:
    """
    Evolving frequency database (Algorithm 1, Section 5.3.1a).

    Maintains four FreqIndex objects — one each for password patterns,
    alphabet-string tokens, digit-string tokens, and special-character-string
    tokens.

    The database is updated with every new user registration via
    ``add_password()``.  This ensures the distribution evolves over time and
    diverges from any static public corpus, making it harder for an attacker
    to pre-compute the same candidate sets.

    ``candidates_for()`` is the primary lookup interface for the generation
    algorithms.  It starts with tolerance=0 (exact frequency match as
    required by the paper) and widens automatically if the exact bucket is
    empty, returning the tolerance actually used so callers can record a
    warning.
    """

    def __init__(self):
        self._patterns  = FreqIndex()
        self._alphabets = FreqIndex()
        self._digits    = FreqIndex()
        self._specials  = FreqIndex()
        self.total_passwords = 0

    # ── Public property shims (for backwards-compat / display) ───────────────

    @property
    def patterns_map(self):
        return dict(self._patterns.items())

    @property
    def alphabets_map(self):
        return dict(self._alphabets.items())

    @property
    def digits_map(self):
        return dict(self._digits.items())

    @property
    def special_chars_map(self):
        return dict(self._specials.items())

    # ── Algorithm 1: ingest ──────────────────────────────────────────────────

    # Add a single password to the database, updating all four FreqIndex objects.
    def add_password(self, password):
        if not password or not password.isascii():
            return
        tokens = tokenize(password)
        if not tokens:
            return
        pattern = get_pattern(tokens)
        self._patterns.add(pattern)
        for t in tokens:
            if   t.type == 'A': self._alphabets.add(t.value.lower())
            elif t.type == 'D': self._digits.add(t.value)
            else:               self._specials.add(t.value)
        self.total_passwords += 1
    
    # Bulk-load an in-memory list of passwords (Algorithm 1 over a corpus).
    def load_corpus(self, passwords):
        for pw in passwords:
            self.add_password(pw)

    # Bulk-load passwords from a file, streaming line by line to avoid memory issues with large corpora.
    def load_file(self, path, limit=None, verbose=True):
        count = 0
        report_every = 500_000
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                pw = line.rstrip('\n\r')
                if not pw or pw.startswith('#'):
                    continue
                self.add_password(pw)
                count += 1
                if verbose and count % report_every == 0:
                    print(f"  [DB] {count:,} passwords loaded ...", end='\r')
                if limit and count >= limit:
                    break
        if verbose:
            print(f"  [DB] {count:,} passwords loaded from '{path}'.")

    # ── Persistence ──────────────────────────────────────────────────────────

    # Save the database to a JSON file, including all four FreqIndex objects and the total password count.
    def save(self, path):
        data = {
            'patterns_map':      self._patterns.to_dict(),
            'alphabets_map':     self._alphabets.to_dict(),
            'digits_map':        self._digits.to_dict(),
            'special_chars_map': self._specials.to_dict(),
            'total_passwords':   self.total_passwords,
        }
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"[DB] Saved to '{path}'.")

    # Restore the database from a JSON file.
    def load(self, path):
        with open(path) as f:
            data = json.load(f)
        self._patterns  = FreqIndex.from_dict(data['patterns_map'])
        self._alphabets = FreqIndex.from_dict(data['alphabets_map'])
        self._digits    = FreqIndex.from_dict(data['digits_map'])
        self._specials  = FreqIndex.from_dict(data.get('special_chars_map', {}))
        self.total_passwords = data.get('total_passwords', 0)
        print(f"[DB] Loaded from '{path}' ({self.total_passwords:,} passwords).")

    # ── Statistics ───────────────────────────────────────────────────────────

    # Return a summary dict of database size and vocabulary counts for display or logging.
    def stats(self):
        return {
            'total_passwords':       self.total_passwords,
            'unique_patterns':       len(self._patterns),
            'unique_alpha_tokens':   len(self._alphabets),
            'unique_digit_tokens':   len(self._digits),
            'unique_special_tokens': len(self._specials),
        }

    # ── Candidate lookup (Algorithm 2 building block) ─────────────────────────

    def candidates_for(self, token_type, token_value, tolerance=0):
        """
        Return ``(candidates, tolerance_used)``.

        Implements the same-frequency lookup required by Algorithm 2.
        Tries ``tolerance=0`` first (exact match, paper spec); if the bucket
        is empty, widens by 1 up to a maximum of 5, then falls back to
        returning the entire vocabulary for that token type.

        Parameters
        ----------
        token_type  : 'A' alpha  |  'D' digit  |  'S' special  |  'P' pattern
        token_value : the reference token whose frequency we match against
        tolerance   : starting tolerance (normally 0)

        Returns
        -------
        candidates     : list[str] — tokens (may be empty only on empty DB)
        tolerance_used : int       — 0 means exact match; -1 means full
                                     vocabulary fallback was used
        """
        index = {
            'A': self._alphabets,
            'D': self._digits,
            'S': self._specials,
            'P': self._patterns,
        }[token_type]

        for tol in range(tolerance, 6):
            cands = index.candidates(token_value, tol)
            if cands:
                return cands, tol

        # Last resort: entire vocabulary minus the token itself
        all_t = [t for t in index.all_tokens() if t != token_value]
        return all_t, -1


# ─────────────────────────────────────────────────────────────────────────────
# Preset corpus
# ─────────────────────────────────────────────────────────────────────────────

PRESET_CORPUS = [
    'dragon99!',    'sunshine2023!', 'mydog@fluffy1', 'welcome1!',    'qwerty123#',
    'hunter2$safe', 'password1!x',   'football99@',   'shadow_77x',   'master123!',
    'alex2020!go',  'iloveyou!3',    'monkey99#fun',  'baseball#1x',  'superman2!',
    'batman99!dc',  'jessica#3pw',   'charlie2000!',  'ranger$08go',  'starwars1!',
    'winter2021!x', 'summer99#hot',  'michael7!pw',   'thomas$1994x', 'robert@23p',
    'ninja2022!go', 'pirate#99arr',  'wizard_03!pw',  'phoenix!1pw',  'falcon88!x',
    'tiger$2020go', 'ocean_blue1!',  'red_dragon3!',  'bluesky@99go', 'fire2023!pw',
    'matrix#01neo', 'comet_99!fly',  'shield2022!x',  'rocket@1launch','legend99!pw',
    'dragon88!',    'dragon77!',     'dragon66!',     'dragon55!',
    'shadow_88x',   'shadow_99x',    'shadow_11x',
    'master456!',   'master789!',
    'secret42!go',  'secret55!go',   'secret88!go',
    'winter2020!x', 'winter2019!x',  'winter2018!x',
    'tiger$2019go', 'tiger$2018go',  'tiger$2017go',
]