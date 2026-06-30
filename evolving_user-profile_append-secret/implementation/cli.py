"""
cli.py — Interactive CLI for the three generation models from Akshima 
et al. (IEEE TDSC 2019)

Usage
-----
    python cli.py

Menu structure
--------------
  ── Database ───────────────────────────────────────────────────
  1  Add a single password to the frequency database
  2  Load the built-in preset corpus (57 passwords)
  3  Load passwords from a file (one per line)
  4  Show database statistics
  5  Save database to JSON
  6  Load database from JSON
  ── Honeyword generation ───────────────────────────────────────
  7  Evolving-Password Model   (Algorithm 2, Section 5.3.1a)
  8  User-Profile Model        (Section 5.3.1b)
  9  Append-Secret Model       (Section 5.3.2a)
  ── Utilities ──────────────────────────────────────────────────
  10 Check Levenshtein distance between two strings
  11 Validate a password against the policy (Section 5.1)
  12 Simulate a login attempt (honeychecker check)
  13 Show the honeychecker's current records
  ── ────────────────────────────────────────────────────────────
  0  Exit
"""

import os
import sys

from frequency_db      import FrequencyDatabase, PRESET_CORPUS
from honeychecker       import Honeychecker
from levenshtein        import levenshtein
from policy             import enforce_password_policy, PasswordPolicyError
from evolving_model     import generate_honeywords_evolving
from user_profile_model import generate_honeywords_user_profile, UserProfile
from append_secret_model import generate_honeywords_append_secret, authenticate_append_secret

# In-memory store of the most recently generated SweetwordList per username,
# used by the login simulation (option 12).
_sweetword_store: dict = {}   # username → (model, SweetwordList)

W = 65   # display width


# ─────────────────────────────────────────────────────────────────────────────
# Menu and input handling
# ─────────────────────────────────────────────────────────────────────────────

def banner() -> None:
    print()
    print('=' * W)
    print('  Honeyword Generator — Akshima et al. (IEEE TDSC 2019)')
    print('  Implementation of the Evolving-Password, User-Profile,')
    print('  and Append-Secret models with Levenshtein typo-safety.')
    print('=' * W)


def menu() -> None:
    print()
    print("-" * W)
    print('  DATABASE')
    print('    1   Add one password to the frequency database')
    print('    2   Load built-in preset corpus')
    print('    3   Load passwords from a file')
    print('    4   Show database statistics')
    print('    5   Save database to JSON')
    print('    6   Load database from JSON')
    print()
    print('  HONEYWORD GENERATION')
    print('    7   Evolving-Password Model')
    print('    8   User-Profile Model')
    print('    9   Append-Secret Model')
    print()
    print('  UTILITIES')
    print('   10   Levenshtein distance between two strings')
    print('   11   Validate a password against the policy')
    print('   12   Simulate a login attempt')
    print('   13   Show honeychecker records')
    print()
    print('    0   Exit')
    print("-" * W)

# Handles prompting for integer inputs with defaults and basic validation.
def prompt_int(prompt: str, default: int) -> int:
    raw = input(f"  {prompt} (default {default}): ").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        print(f"  ⚠  Invalid number; using {default}.")
        return default

# Handles prompting for string inputs with optional defaults.
def prompt_str(prompt: str, default: str = '') -> str:
    raw = input(f"  {prompt}: ").strip()
    return raw if raw else default

# Runs the password policy check and prints the result. 
# Returns True if the password passes the policy, False if it violates any rule.
def run_policy_check(username: str, password: str) -> bool:
    try:
        enforce_password_policy(username, password)
        print(f"  ✓  Password passes policy check.")
        return True
    except PasswordPolicyError as e:
        print(f"  ✗  Policy violation: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Database options (1–6)
# ─────────────────────────────────────────────────────────────────────────────

# Adds a single password to the frequency database, with a check for empty input.
def opt1_add_password(db: FrequencyDatabase) -> None:
    pw = prompt_str("Password to add")
    if not pw:
        print("  ⚠  Empty input; nothing added.")
        return
    db.add_password(pw)
    s = db.stats()
    print(f"  ✓  Added. DB now has {s['total_passwords']} passwords, {s['unique_patterns']} patterns.")

# Loads the preset corpus of 57 passwords into the frequency database.
# Prints a summary of the new total after loading.
def opt2_load_preset(db: FrequencyDatabase) -> None:
    db.load_corpus(PRESET_CORPUS)
    s = db.stats()
    print(f"  ✓  Loaded {len(PRESET_CORPUS)} preset passwords. DB total: {s['total_passwords']}.")

# Loads passwords from a user-specified file. 
# Checks for file existence and optional limit on the number of passwords to load.
def opt3_load_file(db: FrequencyDatabase) -> None:
    path = prompt_str("Path to password file")
    if not path:
        print("  ⚠  No path given.")
        return
    if not os.path.isfile(path):
        print(f"  ✗  File not found: {path}")
        return
    limit_raw = prompt_str("Max passwords to load (Enter = no limit)", '')
    limit = int(limit_raw) if limit_raw.isdigit() else None
    db.load_file(path, limit=limit, verbose=True)

# Displays statistics about the frequency database.
def opt4_stats(db: FrequencyDatabase) -> None:
    s = db.stats()
    print("-" * W)
    print(f"  Total passwords    : {s['total_passwords']:,}")
    print(f"  Unique patterns    : {s['unique_patterns']:,}")
    print(f"  Unique alpha tokens: {s['unique_alpha_tokens']:,}")
    print(f"  Unique digit tokens: {s['unique_digit_tokens']:,}")
    print(f"  Unique special tok.: {s['unique_special_tokens']:,}")
    print("-" * W)

# Saves the frequency database to a JSON file at a user-specified path, with a default suggestion.
def opt5_save_db(db: FrequencyDatabase) -> None:
    path = prompt_str("Save path", 'honeyword_db.json')
    db.save(path)

# Loads the frequency database from a JSON file at a user-specified path, with checks for file existence.
def opt6_load_db(db: FrequencyDatabase) -> None:
    path = prompt_str("Load path", 'honeyword_db.json')
    if not os.path.isfile(path):
        print(f"  ✗  File not found: {path}")
        return
    db.load(path)


# ─────────────────────────────────────────────────────────────────────────────
# Evolving-Password Model (7)
# ─────────────────────────────────────────────────────────────────────────────

def opt7_evolving(db: FrequencyDatabase, hc: Honeychecker) -> None:
    print()
    print("-" * W)
    print("  EVOLVING-PASSWORD MODEL")
    print("  Honeywords drawn from same-frequency tokens in the frequency DB.")
    print("-" * W)

    if db.total_passwords == 0:
        print("  ⚠  Database is empty.  Load the preset corpus first (option 2).")
        return

    username = prompt_str("Username")
    password = prompt_str("Password")
    if not username or not password:
        print("  ⚠  Username and password are required.")
        return

    if not run_policy_check(username, password):
        cont = prompt_str("Generate anyway? (y/n)", 'n')
        if cont.lower() != 'y':
            return

    k             = prompt_int("k  (sweetwords per user)", 20)
    min_lev_dist  = prompt_int("Min Levenshtein distance (typo-safety)", 3)
    max_len_delta = prompt_int("Max length delta vs password (length filter)", 3)

    result = generate_honeywords_evolving(password, db, k=k, min_lev_dist=min_lev_dist, max_len_delta=max_len_delta)
    hc.set(username, result.sugarword_index)
    _sweetword_store[username] = ('evolving', result)

    print(f"\n  ── Sweetword list for '{username}' ──")
    result.display(reveal=True)

    print("\n  Levenshtein distances and length deltas:")
    for i, w in enumerate(result.sweetwords, 1):
        if i != result.sugarword_index:
            d      = levenshtein(password, w)
            lendif = abs(len(w) - len(password))
            lev_ok = '✓' if d >= min_lev_dist else '✗'
            len_ok = '✓' if lendif <= max_len_delta else '✗'
            print(f"    [{i:2d}] {w:<28} lev={d}{lev_ok}  |Δlen|={lendif}{len_ok}")

    print(f"\n  Honeychecker updated: c({username}) = {result.sugarword_index}")


# ─────────────────────────────────────────────────────────────────────────────
# User-Profile Model (8)
# ─────────────────────────────────────────────────────────────────────────────

def opt8_user_profile(hc: Honeychecker) -> None:
    print()
    print("-" * W)
    print("  USER-PROFILE MODEL")
    print("  Honeywords built from the user's personal information.")
    print("-" * W)

    print("  Enter profile details (press Enter to skip any field):")
    profile = UserProfile(
        name     = prompt_str("  Full name"),
        dob      = prompt_str("  Date of birth (DD/MM/YYYY)"),
        address  = prompt_str("  Address"),
        pet_name = prompt_str("  Pet name"),
        extra    = prompt_str("  Other personal detail"),
    )

    username = prompt_str("Username")
    password = prompt_str("Password")
    if not username or not password:
        print("  ⚠  Username and password are required.")
        return

    if not run_policy_check(username, password):
        cont = prompt_str("Generate anyway? (y/n)", 'n')
        if cont.lower() != 'y':
            return

    k             = prompt_int("k  (sweetwords per user)", 20)
    min_lev_dist  = prompt_int("Min Levenshtein distance (typo-safety)", 3)
    max_len_delta = prompt_int("Max length delta vs password (length filter)", 3)

    result = generate_honeywords_user_profile(password, profile, k=k, min_lev_dist=min_lev_dist, max_len_delta=max_len_delta)
    hc.set(username, result.sugarword_index)
    _sweetword_store[username] = ('user_profile', result)

    print(f"\n  ── Sweetword list for '{username}' ──")
    result.display(reveal=True)
    print(f"\n  Honeychecker updated: c({username}) = {result.sugarword_index}")


# ─────────────────────────────────────────────────────────────────────────────
# Append-Secret Model (9)
# ─────────────────────────────────────────────────────────────────────────────

def opt9_append_secret(hc: Honeychecker) -> None:
    print()
    print("-" * W)
    print("  APPEND-SECRET MODEL")
    print("  Stored form is pwd||f(pwd||l||r); r lives only in honeychecker.")
    print("  Typo-safety is structural (wrong pwd -> no match); no distance filter.")
    print("-" * W)

    username = prompt_str("Username")
    password = prompt_str("Password")
    if not username or not password:
        print("  ⚠  Username and password are required.")
        return

    if not run_policy_check(username, password):
        cont = prompt_str("Generate anyway? (y/n)", 'n')
        if cont.lower() != 'y':
            return

    while True:
        extra = prompt_str("Your extra string l  (2-4 characters)")
        if 2 <= len(extra) <= 4:
            break
        print("  ⚠  Must be 2-4 characters.")

    k = prompt_int("k  (sweetwords per user)", 20)

    result = generate_honeywords_append_secret(username, password, extra, hc, k=k)
    _sweetword_store[username] = ('append_secret', result)

    print(f"\n  ── Stored sweetword list for '{username}' ──")
    print(f"  (Entries are pwd||x; r is held in honeychecker — not shown here)")
    result.display(reveal=True)
    print(f"\n  Honeychecker updated: c({username}) = {result.sugarword_index}, r = [hidden]")

    # Offer immediate authentication test
    test = prompt_str("\n  Test authentication now? (y/n)", 'n')
    if test.lower() == 'y':
        authentication_test_append_secret(username, password, extra, result, hc)

# Authentication test for the append-secret model
# Prompts the user to enter the correct credentials and checks if authentication is granted.
# Then prompts for a wrong extra string to verify that authentication is denied and an alarm is raised.
def authentication_test_append_secret(username, password, extra, result, hc):
    print("\n  ── Authentication test ──")
    ok = authenticate_append_secret(username, password, extra, result, hc)
    print(f"  Correct login  : {'✓ granted' if ok else '✗ denied'}")
    wrong = prompt_str("  Enter a wrong extra string to test honeyword detection")
    if wrong:
        ok2 = authenticate_append_secret(username, password, wrong, result, hc)
        print(f"  Wrong extra    : {'✓ granted' if ok2 else '✗ denied — alarm raised'}")


# ─────────────────────────────────────────────────────────────────────────────
# Utilities (10–13)
# ─────────────────────────────────────────────────────────────────────────────

# Levenshtein distance calculator for testing typo-safety thresholds.
def opt10_levenshtein() -> None:
    print()
    print("-" * W)
    print("  LEVENSHTEIN DISTANCE")
    print("-" * W)
    a = input("  String A: ").strip()
    b = input("  String B: ").strip()
    d = levenshtein(a, b)
    print(f"\n  Levenshtein('{a}', '{b}') = {d}")
    for threshold in (2, 3):
        status = '✓ typo-safe' if d >= threshold else '✗ NOT typo-safe'
        print(f"  Threshold {threshold}: {status}")

# Password policy enforcement test: prompts the user for a username and password.
# Checks if the password complies with the policy.
def opt11_policy() -> None:
    print()
    print("-" * W)
    print("  PASSWORD POLICY CHECK  (§5.1)")
    print("-" * W)
    username = prompt_str("Username")
    password = prompt_str("Password")
    run_policy_check(username, password)

# Simulates a login attempt by prompting for username and password.
# Checks the submitted password against the stored sweetword list for that user. 
# Then uses the honeychecker to determine if authentication should be granted or denied.
def opt12_login(hc: Honeychecker) -> None:
    print()
    print("-" * W)
    print("  SIMULATE LOGIN  (honeychecker check)")
    print("-" * W)

    username = prompt_str("Username")
    if username not in _sweetword_store:
        print(f"  ✗  No sweetword list on record for '{username}'.")
        print(f"     Registered users: {list(_sweetword_store.keys()) or ['(none)']}")
        return

    model, result = _sweetword_store[username]

    if model == 'append_secret':
        # Full re-authentication: need submitted_password and submitted_extra
        print("  (Append-secret model — full credentials required)")
        sub_pwd   = prompt_str("  Submitted password")
        sub_extra = prompt_str("  Submitted extra string l")
        ok = authenticate_append_secret(username, sub_pwd, sub_extra, result, hc)
    else:
        # Evolving / user-profile: look up submitted password in sweetword list
        sub_pwd = prompt_str("  Submitted password")
        if sub_pwd in result.sweetwords:
            position = result.sweetwords.index(sub_pwd) + 1  # 1-based
            ok = hc.check(username, position)
        else:
            print(f"  [DENY] '{username}': submitted password not found in sweetword list.")
            ok = False

    print(f"\n  Result: {'✓ Authentication granted' if ok else '✗ Authentication denied'}")

# Utility to display the honeychecker's current records.
# Shows the stored sugarword index and whether an append-secret is present (without revealing the secret itself).
def opt13_show_hc(hc: Honeychecker) -> None:
    print()
    print("-" * W)
    print("  HONEYCHECKER RECORDS")
    print("-" * W)
    if not hc._store:
        print("  (no records yet)")
    else:
        for username, entry in hc._store.items():
            r_info = f"  r=[hidden]" if entry.append_secret_r else ""
            print(f"  {username:<20} c(i)={entry.sugarword_index}{r_info}")
    print("-" * W)


# ─────────────────────────────────────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    db = FrequencyDatabase()
    hc = Honeychecker()
    banner()

    dispatch = {
        '1':  lambda: opt1_add_password(db),
        '2':  lambda: opt2_load_preset(db),
        '3':  lambda: opt3_load_file(db),
        '4':  lambda: opt4_stats(db),
        '5':  lambda: opt5_save_db(db),
        '6':  lambda: opt6_load_db(db),
        '7':  lambda: opt7_evolving(db, hc),
        '8':  lambda: opt8_user_profile(hc),
        '9':  lambda: opt9_append_secret(hc),
        '10': lambda: opt10_levenshtein(),
        '11': lambda: opt11_policy(),
        '12': lambda: opt12_login(hc),
        '13': lambda: opt13_show_hc(hc),
    }

    while True:
        menu()
        choice = input("  Select option: ").strip()
        if choice == '0':
            print("  Goodbye.\n")
            break
        handler = dispatch.get(choice)
        if handler:
            handler()
        else:
            print("  ⚠  Unknown option.")


if __name__ == '__main__':
    main()