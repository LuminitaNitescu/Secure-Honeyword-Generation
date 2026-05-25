#!/bin/bash
set -euo pipefail

# Tweakable parameters
VENV="$PWD/.venv"
TARGET_DATASET="data/50k_subsample/rockyou_sorted_preprocessed.txt"
ATTACKER_DATASET="yahoo"   # chegg-com | dropbox | linkedin | yahoo
MODEL_PATH="honeygen_models/model_trained_on_rockyou_500_epochs.bin"
K=20
L=10
SEED=67
T1=20
T2=61                         
LIMIT=""                      # empty = full dataset
OUT_PREFIX="honeygen"
CACHE_DIR="data/cache"


if [[ ! -d "$VENV" ]]; then
    echo "Venv not found at $VENV. Create it first."
    exit 1
fi

source "$VENV/bin/activate"

CMD=(
    python -u test_honeygen.py
    --target-dataset "$TARGET_DATASET"
    --attacker-dataset "$ATTACKER_DATASET"
    --model-path "$MODEL_PATH"
    --k "$K"
    --l "$L"
    --seed "$SEED"
    --t1 "$T1"
    --out-prefix "$OUT_PREFIX"
    --cache-dir "$CACHE_DIR"
)

if [[ -n "$T2" ]]; then
    CMD+=(--t2 "$T2")
fi

if [[ -n "$LIMIT" ]]; then
    CMD+=(--limit "$LIMIT")
fi

"${CMD[@]}"
