"""
honeychecker.py — Honeychecker and SweetwordList (Section 2).

Honeychecker
------------
The honeychecker is an auxiliary secure server that holds only the sugarword
index c(i) for each user — never the full password or honeyword values.  This
means a standalone compromise of the honeychecker reveals only position
integers, which are useless without the separate password database.

The two standard commands defined by the paper are:
    Set(i, j)   — record that user i's sugarword is at position j.
    Check(i, j) — verify j == c(i); raise an alarm on mismatch.

For the append-secret model, the honeychecker also stores the per-user random
secret r so that the authentication server can reconstruct x = f(pwd||l||r)
without r ever appearing in the main password database:
    set_with_secret(i, j, r)
    get_secret(i) → r

SweetwordList
-------------
Return value of all three generation functions.  Holds the full sweetword list
W_i, the 1-based sugarword index c(i), the password pattern, auxiliary size
information for display, and any non-fatal warnings emitted during generation
(e.g. tolerance-widening events or short generation runs).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class HoneyEntry:
    sugarword_index: int
    append_secret_r: Optional[str] = None


class Honeychecker:
    def __init__(self):
        self._store = {}   # username -> HoneyEntry

    def set(self, username, index):
        self._store[username] = HoneyEntry(sugarword_index=index)

    def check(self, username, index):
        entry = self._store.get(username)
        if entry is None:
            print(f"  [ALARM] Unknown user '{username}'!")
            return False
        if entry.sugarword_index != index:
            print(f"  [ALARM] Login with HONEYWORD for '{username}'! "
                  "Password database may be compromised.")
            return False
        return True

    def set_with_secret(self, username, index, r):
        self._store[username] = HoneyEntry(sugarword_index=index,
                                            append_secret_r=r)

    def get_secret(self, username):
        entry = self._store.get(username)
        return entry.append_secret_r if entry else None

    def delete(self, username):
        self._store.pop(username, None)


@dataclass
class SweetwordList:
    sweetwords:       list
    sugarword_index:  int
    password_pattern: str
    list_sizes:       dict  = field(default_factory=dict)
    warnings:         list  = field(default_factory=list)

    def display(self, reveal=False):
        print(f"\n  Pattern  : {self.password_pattern}")
        print(f"  Sizes    : {self.list_sizes}")
        print(f"  c(i)     : {self.sugarword_index}"
              f"  {'<- stored in honeychecker only' if reveal else ''}")
        for w in self.warnings:
            print(f"  [WARN]   : {w}")
        print()
        for i, w in enumerate(self.sweetwords, 1):
            marker = '  <- SUGARWORD' if (reveal and i == self.sugarword_index) else ''
            print(f"  [{i:2d}]  {w}{marker}")