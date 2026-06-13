#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv"

C_IMPL="$(cd "$SCRIPT_DIR/../../Christos/implementation" && pwd)"

PCFG_RULES_BASE="$C_IMPL/legacy_pcfg_master/python_pcfg_cracker_version3/Rules"

DATASET="dubsmash-com"   # chegg-com | dropbox | linkedin | yahoo | rockyou | dubsmash-com | youku
TRAIN_DATASET="data/50k_subsample/${DATASET}_sorted_preprocessed.txt"
# "data/50k_subsample/rockyou_sorted_preprocessed.txt"
# "data/50k_subsample/dropbox_sorted_preprocessed.txt"
# "data/50k_subsample/linkedin_sorted_preprocessed.txt"
# data/50k_subsample/yahoo_sorted_preprocessed.txt
# "data/50k_subsample/chegg-com_sorted_preprocessed.txt"
# "data/50k_subsample/dubsmash-com_sorted_preprocessed.txt"
# "data/50k_subsample/youku_sorted_preprocessed.txt"
ATTACKER_DATASET="hashmob_counts"   # chegg-com | dropbox | linkedin | yahoo | all
MODEL_PATH="honeygen_models/model_trained_on_${DATASET}_500_epochs.bin"

K=20
L=4                           # KNN base words; K must be divisible by L
SEED=67
T1=20
T2=61
LIMIT=""                      # empty = full dataset
CACHE_DIR="data/cache"

if [[ ! -d "$VENV" ]]; then
    echo "Venv not found at $VENV. Create it first."
    exit 1
fi

source "$VENV/bin/activate"

if [[ ! -f "$TRAIN_DATASET" ]]; then
    echo "Training dataset not found: $TRAIN_DATASET"
    exit 1
fi

RULES_DIR="$PCFG_RULES_BASE/$DATASET"

if [[ ! -d "$RULES_DIR" ]]; then
    echo "Rule '${DATASET}' not found — training PCFG grammar from: $TRAIN_DATASET"
    python - <<PYEOF
import sys
sys.path.insert(0, "$C_IMPL")

from legacy_pcfg_master.python_pcfg_cracker_version3.pcfg_trainer import train

data = []
with open("$TRAIN_DATASET", "r", encoding="utf-8") as fh:
    for line in fh:
        pw = line.strip()
        if pw:
            data.append([pw])

print(f"Loaded {len(data):,} training passwords.")
train(data=data, rule_name="$DATASET")
print("Training complete. Rule saved to: $RULES_DIR")
PYEOF
else
    echo "Rule '${DATASET}' already exists at: $RULES_DIR — skipping training."
fi

CMD=(
    python -u test_honeygen_pcfg.py
    --target-dataset "$TRAIN_DATASET"
    --attacker-dataset "$ATTACKER_DATASET"
    --model-path "$MODEL_PATH"
    --rule-name "$DATASET"
    --k "$K"
    --l "$L"
    --seed "$SEED"
    --t1 "$T1"
    --cache-dir "$CACHE_DIR"
)

if [[ -n "$T2" ]]; then
    CMD+=(--t2 "$T2")
fi

if [[ -n "$LIMIT" ]]; then
    CMD+=(--limit "$LIMIT")
fi

"${CMD[@]}"
