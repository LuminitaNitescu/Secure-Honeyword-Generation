"""
Run once to extract passwords from the BreachCompilation dataset.
Produces breach_passwords_unique_email_8_32.csv with one password per line.
Passwords are filtered to be 8–32 chars and ASCII-only, and deduplicated by password.

Usage:
    python breach_extract.py
"""

import os
import re
from common import BREACH_DATA_DIR, BREACH_PASSWORDS_OUT

_ASCII_ONLY = re.compile(r'^[A-Za-z0-9!@#$%^&*()\-_=+\[\]{};:\'",.<>?/\\|`~]+$')

# Extracts the passwords (in the dataset, they are username:password)
def extract(src_dir=BREACH_DATA_DIR, out_path=BREACH_PASSWORDS_OUT):
    if os.path.exists(out_path):
        print(f"Already exists: {out_path}, delete it to re-extract.")
        return

    seen = set()
    kept = 0
    with open(out_path, "w", encoding="utf-8") as out_f:
        out_f.write("pw\n")
        for root, _dirs, files in os.walk(src_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.rstrip("\n\r")
                            if ":" not in line:
                                continue
                            pw = line.rsplit(":", 1)[-1]
                            if not (8 <= len(pw) <= 32):
                                continue
                            if not _ASCII_ONLY.match(pw):
                                continue
                            if pw in seen:
                                continue
                            seen.add(pw)
                            out_f.write(pw + "\n")
                            kept += 1
                except Exception:
                    continue

    print(f"Extracted {kept:,} unique ASCII passwords (8–32 chars) in {out_path}")


if __name__ == "__main__":
    extract()
