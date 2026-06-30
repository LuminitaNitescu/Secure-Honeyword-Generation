"""
levenshtein.py — Edit-distance computation (typo-safety).

Used by all three generation models to enforce a minimum distance between
the real password and every generated honeyword, preventing false alarms
when a legitimate user makes a typing error (Section 5.2).
"""

from __future__ import annotations


def levenshtein(a: str, b: str) -> int:
    """
    Compute the Levenshtein edit distance between two strings.

    Uses a space-optimised rolling-array implementation: O(min(m,n)) space,
    O(m * n) time.

    Parameters
    ----------
    a, b : strings to compare

    Returns
    -------
    int — minimum number of single-character insertions, deletions,
          or substitutions required to transform *a* into *b*.

    Examples
    --------
    levenshtein("shadow_77x", "dragon88!") = 9
    levenshtein("password1!", "password1@") = 1
    levenshtein("abc", "abc") = 0
    """
    # Ensure a is the shorter string to minimise memory use
    if len(a) > len(b):
        a, b = b, a
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, n + 1):
            temp = dp[j]
            if a[i - 1] == b[j - 1]:
                dp[j] = prev
            else:
                dp[j] = 1 + min(prev, dp[j], dp[j - 1])
            prev = temp
    return dp[n]
