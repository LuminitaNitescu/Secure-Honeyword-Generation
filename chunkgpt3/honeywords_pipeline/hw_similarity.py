"""
Compute average honeyword similarity for generated honeywords.
"""

import csv
import numpy as np
from sentence_transformers import SentenceTransformer, util

INPUT_CSV  = "honeywords_Mistral_psm_chunk_1000_weak.csv" # modify with the honeywords csv
OUTPUT_CSV = "similarity_Mistral_psm_strong.csv"
MODEL_NAME = "nli-mpnet-base-v2"

# Load honeywords, filtering out empty honeywords
rows = []
filtered_identical = 0
with open(INPUT_CSV, newline='', encoding='utf-8') as f:
    reader = csv.reader(f)
    next(reader)                          
    for row in reader:
        tokens = [x.strip() for x in row]
        if not tokens or not tokens[0]:
            continue
        real_pw = tokens[0]
        honeywords = []
        for token in tokens[1:]:
            if not token or token == 'nan':
                continue
            if token == real_pw:
                filtered_identical += 1
                continue
            honeywords.append(token)
        rows.append([real_pw] + honeywords)

print(f"Loaded {len(rows)} users from {INPUT_CSV}")

# Load the SentenceTransformer model for computing embeddings
print(f"Loading SentenceTransformer '{MODEL_NAME}'")
model = SentenceTransformer(MODEL_NAME)

# Embed honeywords
print("Encoding all unique passwords")
unique_pws = list({pw for row in rows for pw in row if pw})
embeddings = model.encode(unique_pws, batch_size=256, show_progress_bar=True, convert_to_tensor=True)
emb_map = {pw: emb for pw, emb in zip(unique_pws, embeddings)}

import torch

# Compute average HWSimilarity
avg_scores = []
for i, row in enumerate(rows):
    real_pw    = row[0]
    honeywords = [hw for hw in row[1:] if hw and hw in emb_map]
    if not honeywords:
        avg_scores.append(1.0)
        continue
    real_emb = emb_map[real_pw].unsqueeze(0)                        
    hw_embs  = torch.stack([emb_map[hw] for hw in honeywords])      
    sims = util.pytorch_cos_sim(real_emb, hw_embs)[0]           
    avg  = sims.mean().item()
    avg_scores.append(avg)
    if (i + 1) % 100 == 0 or (i + 1) == len(rows):
        print(f"  {i+1}/{len(rows)}  last_avg={avg:.4f}")

np.savetxt(OUTPUT_CSV, avg_scores, delimiter=', ', fmt='%s')
overall = sum(avg_scores) / len(avg_scores)
print(f"\nSaved {len(avg_scores)} scores in {OUTPUT_CSV}")
print(f"Overall average similarity: {overall:.4f}")
