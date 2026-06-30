"""
Pipeline for weak passwords: score - chunk - generate honeywords.

Usage:
    python honeywords_weak.py
"""

import random
import time
import pandas as pd
from zxcvbn import zxcvbn
from tqdm import tqdm
from common import (
    NUM_USER, NUM_SWEETWORDS, BREACH_PASSWORDS_OUT,
    add_chunks, add_chunk_num, chaffing_by_qwen4b_chunk, AI_MODEL,
)

print(f"Loading passwords from {BREACH_PASSWORDS_OUT}")
df = pd.read_csv(BREACH_PASSWORDS_OUT)
if "pw" not in df.columns:
    df = df.rename(columns={df.columns[0]: "pw"})
df["pw"] = df["pw"].astype(str)
df = df[df["pw"].str.len().between(8, 32)]
print(f"Found {len(df):,} passwords in length range.")

random.seed(42)
sampled = random.sample(df["pw"].tolist(), min(1_000_000, len(df)))
df = pd.DataFrame({"pw": sampled})

print("\nScoring with zxcvbn and selecting weak passwords")
strength = []
for row in tqdm(df.itertuples(), total=len(df), desc="Scoring", unit="pw"):
    strength.append(zxcvbn(row.pw)["score"])
df["strength"] = strength

weak_pw = df.sort_values(by="strength", ascending=True).head(NUM_USER)
weak_pw.to_csv(f"weak_pw_{NUM_USER}_breach.csv", index=False)
print(f"Saved weak_pw_{NUM_USER}_breach.csv")

weak_pw_chunks = add_chunk_num(add_chunks(weak_pw))
weak_pw_chunks.to_csv(f"weak_pw_chunks_{NUM_USER}_breach.csv", index=False)
print(f"Chunked {len(weak_pw_chunks)} passwords to weak_pw_chunks_{NUM_USER}_breach.csv")

print(f"\nGenerating honeywords (model: {AI_MODEL})")
print("Make sure Ollama is running: `ollama serve`")

start = time.time()
sweetwords = chaffing_by_qwen4b_chunk(weak_pw_chunks)
elapsed = time.time() - start
print(f"Time taken: {elapsed:.2f} seconds")

res = [([key] + val)[:NUM_SWEETWORDS] for key, val in sweetwords.items()]
out = f"honeywords_Qwen4B_psm_chunk_{NUM_USER}_weak.csv"
pd.DataFrame(res).to_csv(out, index=False)
print(f"Saved {out}")

filled = sum(1 for r in res if len(r) >= 2)
print(f"{filled}/{len(res)} rows have at least one honeyword.")
