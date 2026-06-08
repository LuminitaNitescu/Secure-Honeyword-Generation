"""
policy.py — Password policy enforcement (Section 5.1).

The paper imposes two lightweight, practical conditions on every registered
password to reduce correlation with the username and to guarantee minimum
entropy:

  1. The username, or any of its substrings of length ≥ 3, must not appear
     in the password (case-insensitive).
  2. The password must be at least 8 characters long and must contain at
     least one alphabetic character, one digit, and one special
     (non-alphanumeric) character.

The paper deliberately avoids overly strict policies; research (Florêncio
& Herley 2010) shows the most restrictive policies do not provide
proportionally greater security.
"""
from __future__ import annotations

# Raised when a candidate password violates the policy.
class PasswordPolicyError(ValueError):
    pass

def enforce_password_policy(username: str, password: str) -> None:
    """
    Validate *password* against the Section 5.1 policy for *username*.

    Raises
    ------
    PasswordPolicyError
        With a descriptive message identifying which rule was violated.

    Examples
    --------
    enforce_password_policy("alice", "shadow_77x")     Passes silently
    enforce_password_policy("alice", "short1!")        PasswordPolicyError: Password must be at least 8 characters (got 7).
    enforce_password_policy("alice", "alicepass1!")    PasswordPolicyError: Password must not contain the username substring 'ali'.
    enforce_password_policy("alice", "allletters!!!")  PasswordPolicyError: Password must contain at least one letter, one digit, and one special character.
    """
    # Rule 2a: minimum length
    if len(password) < 8:
        raise PasswordPolicyError(
            f"Password must be at least 8 characters (got {len(password)})."
        )

    # Rule 2b: character-class diversity
    has_alpha   = any(c.isalpha()   for c in password)
    has_digit   = any(c.isdigit()   for c in password)
    has_special = any(not c.isalnum() for c in password)
    if not (has_alpha and has_digit and has_special):
        raise PasswordPolicyError(
            "Password must contain at least one letter, one digit, "
            "and one special character."
        )

    # Rule 1: no username substring of length ≥ 3
    uname_lower = username.lower()
    pwd_lower   = password.lower()
    for length in range(3, len(uname_lower) + 1):
        for start in range(len(uname_lower) - length + 1):
            sub = uname_lower[start : start + length]
            if sub in pwd_lower:
                raise PasswordPolicyError(
                    f"Password must not contain the username substring '{sub}'."
                )