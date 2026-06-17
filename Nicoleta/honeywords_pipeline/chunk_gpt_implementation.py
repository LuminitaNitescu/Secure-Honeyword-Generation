"""
Full pipeline orchestrator. Runs all steps in sequence.

Steps:
    1. breach_extract   — extract & filter passwords from BreachCompilation
    2. honeywords_strong — score, chunk, generate honeywords for strong passwords
    3. honeywords_weak   — score, chunk, generate honeywords for weak passwords

You can also run each module independently:
    python breach_extract.py
    python honeywords_strong.py
    python honeywords_weak.py
    python honeywords_single.py [password]
"""

import runpy

print("Step 1/3 — Extracting breach passwords")
runpy.run_module("breach_extract", run_name="__main__", alter_sys=True)

print("Step 2/3 — Strong password honeywords")
runpy.run_module("honeywords_strong", run_name="__main__", alter_sys=True)

print("Step 3/3 — Weak password honeywords")
runpy.run_module("honeywords_weak", run_name="__main__", alter_sys=True)

print("\nAll steps complete.")
