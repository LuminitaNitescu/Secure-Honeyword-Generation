# """
# honeychecker.py — Honeychecker and SweetwordList (Section 2).

# Honeychecker
# ------------
# The honeychecker is an auxiliary secure server that holds only the sugarword
# index c(i) for each user — never the full password or honeyword values.  This
# means a standalone compromise of the honeychecker reveals only position
# integers, which are useless without the separate password database.

# The two standard commands defined by the paper are:
#     Set(i, j)   — record that user i's sugarword is at position j.
#     Check(i, j) — verify j == c(i); raise an alarm on mismatch.

# For the append-secret model, the honeychecker also stores the per-user random
# secret r so that the authentication server can reconstruct x = f(pwd||l||r)
# without r ever appearing in the main password database:
#     set_with_secret(i, j, r)
#     get_secret(i) → r

# SweetwordList
# -------------
# Return value of all three generation functions.  Holds the full sweetword list
# W_i, the 1-based sugarword index c(i), the password pattern, auxiliary size
# information for display, and any non-fatal warnings emitted during generation
# (e.g. tolerance-widening events or short generation runs).
# """

# from dataclasses import dataclass, field
# from typing import Optional


# # ─────────────────────────────────────────────────────────────────────────────
# # Internal honeychecker storage record
# # ─────────────────────────────────────────────────────────────────────────────

# @dataclass
# class HoneyEntry:
#     """Per-user record held by the Honeychecker."""
#     sugarword_index: int
#     # Only set for the append-secret model; None for the other two models.
#     append_secret_r: Optional[str] = None


# # ─────────────────────────────────────────────────────────────────────────────
# # Honeychecker
# # ─────────────────────────────────────────────────────────────────────────────

# class Honeychecker:
#     """
#     Simulated auxiliary secure server (Section 2).

#     Stores the sugarword index c(i) for each user and raises an alarm on any
#     login attempt that presents an index other than c(i).  For the
#     append-secret model it additionally stores the per-user random secret r.

#     In a real deployment the honeychecker communicates with the main server
#     over dedicated, encrypted, and authenticated channels.  Here the
#     interaction is in-process.

#     Standard interface (all models)
#     --------------------------------
#     set(username, index)          Record c(i) = index.
#     check(username, index)        Verify; print alarm on mismatch; return bool.
#     delete(username)              Remove a user's record.

#     Append-secret extension
#     -----------------------
#     set_with_secret(username, index, r)   Store c(i) and r together.
#     get_secret(username) → r | None       Retrieve r for authentication.
#     """

#     def __init__(self) -> None:
#         self._store: dict[str, HoneyEntry] = {}

#     # ── Standard interface ───────────────────────────────────────────────────

#     def set(self, username: str, index: int) -> None:
#         """Set(i, j): record that user *username*'s sugarword is at *index*."""
#         self._store[username] = HoneyEntry(sugarword_index=index)

#     def check(self, username: str, index: int) -> bool:
#         """
#         Check(i, j): return True iff *index* matches the stored sugarword index.

#         Prints a console alarm and returns False when the indices differ or the
#         user is unknown (simulating the honeychecker raising an alarm).
#         """
#         entry = self._store.get(username)
#         if entry is None:
#             print(f"  [ALARM] Unknown user '{username}'!")
#             return False
#         if entry.sugarword_index != index:
#             print(f"  [ALARM] Login with HONEYWORD for '{username}'! "
#                   "Password database may be compromised.")
#             return False
#         return True

#     def delete(self, username: str) -> None:
#         """Remove the honeychecker record for *username*."""
#         self._store.pop(username, None)

#     # ── Append-secret extension ──────────────────────────────────────────────

#     def set_with_secret(self, username: str, index: int, r: str) -> None:
#         """
#         Store the sugarword index *and* the system-generated secret *r*.

#         Used exclusively by the append-secret model at registration time.
#         The secret *r* is never returned to the calling code — it lives only
#         here, inside the honeychecker.
#         """
#         self._store[username] = HoneyEntry(
#             sugarword_index=index,
#             append_secret_r=r,
#         )

#     def get_secret(self, username: str) -> Optional[str]:
#         """
#         Return the system secret *r* for *username*.

#         Called by the authentication server at login time to reconstruct
#         x = f(pwd || l || r) before checking the sweetword list.  Returns
#         None if the user was not registered under the append-secret model.
#         """
#         entry = self._store.get(username)
#         return entry.append_secret_r if entry else None


# # ─────────────────────────────────────────────────────────────────────────────
# # SweetwordList
# # ─────────────────────────────────────────────────────────────────────────────

# @dataclass
# class SweetwordList:
#     """
#     The complete sweetword list W_i for one user.

#     Attributes
#     ----------
#     sweetwords      : list[str]  — k entries; exactly one is the real password.
#     sugarword_index : int        — 1-based index c(i) stored in the honeychecker.
#     password_pattern: str        — pattern string of the real password.
#     list_sizes      : dict       — diagnostic sizes of the candidate lists used
#                                    during generation (L1–L4 or model-specific).
#     warnings        : list[str]  — non-fatal issues encountered during generation
#                                    (e.g. tolerance-widening, short runs).
#     """

#     sweetwords:       list[str]
#     sugarword_index:  int
#     password_pattern: str
#     list_sizes:       dict       = field(default_factory=dict)
#     warnings:         list[str]  = field(default_factory=list)

#     def display(self, reveal: bool = False) -> None:
#         """
#         Pretty-print the sweetword list.

#         Parameters
#         ----------
#         reveal : if True, mark the sugarword position (demo / debug use only;
#                  never do this in production).
#         """
#         print(f"\n  Pattern  : {self.password_pattern}")
#         print(f"  Sizes    : {self.list_sizes}")
#         print(f"  c(i)     : {self.sugarword_index}"
#               f"  {'← stored in honeychecker only' if reveal else ''}")
#         if self.warnings:
#             for w in self.warnings:
#                 print(f"  [WARN]   : {w}")
#         print()
#         for i, w in enumerate(self.sweetwords, 1):
#             marker = '  ← SUGARWORD' if (reveal and i == self.sugarword_index) else ''
#             print(f"  [{i:2d}]  {w}{marker}")

"""
honeychecker.py — Honeychecker, HoneyEntry, SweetwordList (Section 2).
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