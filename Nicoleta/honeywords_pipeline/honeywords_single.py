"""
Generate honeywords for a single password entered via command line or interactively.

Usage:
    python honeywords_single.py
    python honeywords_single.py MyP@ssw0rd
"""

import sys
from ckl_psm import ckl_pcfg as psm
from common import qwen4b_honeywords_chunk, replace_all, AI_MODEL

# get the chunks for a password and return them as a string
def get_chunks(password):
    result = psm.check_pwd(password)
    chunk_set = set(list(zip(*result["chunks"]))[0])
    return replace_all(str(chunk_set), {"{}": " ", "}": ","})[2:-2]


def main():
    if len(sys.argv) > 1:
        password = sys.argv[1]
    else:
        password = input("Enter password: ").strip()

    if not (8 <= len(password) <= 32):
        print(f"Password must be between 8 and 32 characters (got {len(password)}).")
        sys.exit(1)

    print(f"\nGenerating honeywords for: {password!r}  (model: {AI_MODEL})")
    print("Make sure Ollama is running: `ollama serve`\n")

    chunks = get_chunks(password)
    honeywords = qwen4b_honeywords_chunk(password, chunks)

    print(f"Real password + {len(honeywords)} honeywords:")
    all_words = [password] + honeywords
    for i, w in enumerate(all_words, 1):
        tag = " - real" if i == 1 else ""
        print(f" {i:>2}. {w}{tag}")


if __name__ == "__main__":
    main()
