# HoneyGen — Modular Honeyword Generation (HGT)

This folder contains a modular re-implementation of the **HoneyGen HGT** (Honeyword Generation via representation learning) model, originally published at [This Bitbucket Link](https://bitbucket.org/srecgrp/honeygen-generating-honeywords-using-representation-learning/src/master/).

The implementation extends the original design with pluggable embedding backends, a PCFG-hybrid generation mode, and a full evaluation pipeline (attacker simulation, flatness metrics, graph output).


## Layout

```
implementation/
├── hgt.py                      # Core HoneywordGenerator class (all three modes)
├── config.py                   # Default hyperparameters (k, l, seed, model path)
├── statistics.py               # Evaluation metrics (ε-flatness, attack success rate)
├── graphs.py                   # Graph generation (flatness curves, success-number, LaTeX table)
├── test_honeygen.py            # CLI entrypoint — hybrid model evaluation
├── test_honeygen_pcfg.py       # CLI entrypoint — PCFG-hybrid model evaluation
│
├── utils/
│   ├── embedding.py            # Abstract EmbeddingBackend + FastTextBackend
│   ├── ft_train.py             # FastText model training script
│   ├── aggregate_sorted_pw.py  # Password list aggregation utilities
│   └── dataset_overlap.py      # Dataset overlap analysis
│
├── attackers/
│   ├── normalized_top_pw_hg.py # Primary attacker: normalised top-password attack
│   ├── normalized_top_pw.py    # Base attacker without HG adjustments
│   └── top_pw.py               # Simpler top-password attacker
│
├── data/
│   ├── 50k_subsample/          # 50k preprocessed passwords per breach dataset
│   │   ├── rockyou_sorted_preprocessed.txt
│   │   ├── linkedin_sorted_preprocessed.txt
│   │   ├── yahoo_sorted_preprocessed.txt
│   │   ├── dropbox_sorted_preprocessed.txt
│   │   ├── chegg-com_sorted_preprocessed.txt
│   │   ├── dubsmash-com_sorted_preprocessed.txt
│   │   ├── youku_sorted_preprocessed.txt
│   │   └── ...
│   ├── cache/                  # Cached sweetword lists (JSONL, keyed by run params)
│   │   ├── cbh/                #   chaffing-by-hybrid cache
│   │   ├── cbt/                #   chaffing-by-tweaking cache
│   │   └── pcfg-hybrid/        #   PCFG-hybrid cache
│   └── process_wordlist.py     # Data preprocessing utilities
│
├── honeygen_models/            # Pre-trained FastText skipgram models (500 epochs each)
│   ├── model_trained_on_rockyou_500_epochs.bin
│   ├── model_trained_on_linkedin_500_epochs.bin
│   └── ...
│
└── outputs/                    # Evaluation results (JSON stats per dataset/method)
    ├── hybrid/                 # Hybrid (HGT) results
    ├── tweaking/               # Tweaking-only results
    ├── pcfg-hybrid/            # PCFG-hybrid results
    └── ...
```

---

## Quickstart

### 1. Setup

```bash
cd implementation
python -m venv .venv && source .venv/bin/activate
pip install fasttext tqdm matplotlib numpy
```

### 2. Train a FastText model (will be stored in `honeygen_models/`)

Edit the `dataset` variable in `utils/ft_train.py`, then:

```bash
cd honeygen_models
python ../utils/ft_train.py
```

### 3-4. Run Hybrid/PCFG-Hybrid HGT evaluation:

Update the Bash scripts in `test_honeygen(_pcfg).sh` to have the exact variables you desire, then simply run the script; The results will be stored in two separate folders:
- **`outputs`** — result metrics
- **`data/cache`** — cached sweetword lists

### 5. Generate evaluation graphs

```bash
python graphs.py \
    --folders outputs/hybrid outputs/tweaking outputs/pcfg-hybrid \
    --k 20 \
    --out-dir graphs/
```

Produces per-folder and aggregate:
- **Flatness curve** — fraction of users cracked within _t_ guesses
- **Success-number curve** — successful vs failed logins under a global guessing campaign
- **`metrics_table.tex`** — LaTeX table of ε-flatness and mean attack success rate

