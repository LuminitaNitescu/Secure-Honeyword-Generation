"""
tokenizer.py — Password tokenisation and pattern utilities.

Shared by the evolving-password and user-profile models.  Implements the
token / pattern representation described in Section 5.3.1a of the paper.

Terminology
-----------
Token   A contiguous run of characters of the same class:
          A  — alphabetic string   (e.g. "shadow", "hello")
          D  — digit string        (e.g. "77", "2023")
          S  — special-character string (e.g. "_", "!@")

Pattern The sequence of token-type symbols derived from a password, with
        the *length* of special-character runs encoded as a numeric suffix
        (because the paper preserves special-char length but not alpha/digit
        length when generating honeywords).

        Examples
          "shadow_77x"   → tokens [A:"shadow", S1:"_", D:"77", A:"x"]
                         → pattern "AS1DA"
          "pass@2023!"   → tokens [A:"pass", S1:"@", D:"2023", S1:"!"]
                         → pattern "AS1DS1"
          "Hi!There9"    → tokens [A:"Hi", S1:"!", A:"There", D:"9"]
                         → pattern "AS1AD"
"""
from __future__ import annotations
import re
from dataclasses import dataclass


@dataclass
class Token:
    """A typed token extracted from a password string."""
    kind: str   # 'A' (alpha) | 'D' (digit) | 'S' (special)
    value: str

    # expose as .type for compatibility with the rest of the code
    @property
    def type(self) -> str:
        return self.kind

    @property
    def pattern_repr(self) -> str:
        return f"S{len(self.value)}" if self.kind == 'S' else self.kind


def tokenize(password: str) -> list:
    """
    Split *password* into a list of typed Token objects.

    Consecutive characters of the same class form a single token; the split points are wherever the class changes.

    Examples
    --------
    tokenize("shadow_77x")
    [Token(type='A', value='shadow'), Token(type='S', value='_'),
     Token(type='D', value='77'),     Token(type='A', value='x')]
    """
    tokens = []
    i = 0
    while i < len(password):
        c = password[i]
        if c.isalpha():
            m = re.match(r'[a-zA-Z]+', password[i:])
            t = 'A'
        elif c.isdigit():
            m = re.match(r'[0-9]+', password[i:])
            t = 'D'
        else:
            m = re.match(r'[^a-zA-Z0-9]+', password[i:])
            t = 'S'
        if m is None:
            i += 1
            continue
        tokens.append(Token(t, m.group()))
        i += len(m.group())
    return tokens

# Derive the pattern string from a list of tokens.
def get_pattern(tokens: list) -> str:
    return ''.join(t.pattern_repr for t in tokens)

# Parse a pattern string back into a list of ``{type, len}`` dicts.
def parse_pattern(pattern: str) -> list:
    parts = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch in ('A', 'D'):
            parts.append({'type': ch, 'len': None})
            i += 1
        elif ch == 'S':
            i += 1
            num = ''
            while i < len(pattern) and pattern[i].isdigit():
                num += pattern[i]
                i += 1
            parts.append({'type': 'S', 'len': int(num) if num else 1})
        else:
            i += 1
    return parts