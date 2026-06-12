#!/bin/bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv"

# Absolute path to Christos's implementation directory (where pcfg.py lives).
CHRISTOS_IMPL="$(cd "$SCRIPT_DIR/../../Christos/implementation" && pwd)"

# The rule directory is fixed by the trainer:
#   <christos_impl>/legacy_pcfg_master/python_pcfg_cracker_version3/Rules/<RULE_NAME>/
PCFG_RULES_BASE="$CHRISTOS_IMPL/legacy_pcfg_master/python_pcfg_cracker_version3/Rules"

# ---------------------------------------------------------------------------
# Tweakable parameters
# ---------------------------------------------------------------------------
TARGET_DATASET="data/50k_subsample/dropbox_sorted_preprocessed.txt"
# Other target options:
# "data/50k_subsample/rockyou_sorted_preprocessed.txt"
# "data/50k_subsample/linkedin_sorted_preprocessed.txt"
# "data/50k_subsample/yahoo_sorted_preprocessed.txt"
# "data/50k_subsample/chegg-com_sorted_preprocessed.txt"

# Training corpus for the PCFG grammar (should differ from the target).
TRAIN_DATASET="data/50k_subsample/rockyou_sorted_preprocessed.txt"

ATTACKER_DATASET="hashmob_counts"   # hashmob_counts | all
MODEL_PATH="honeygen_models/model_trained_on_rockyou_500_epochs.bin"
RULE_NAME="RockYouFinal"
K=20
L=4                           # KNN base words; K must be divisible by L
SEED=67
T1=20
T2=61
LIMIT=""                      # empty = full dataset
CACHE_DIR="data/cache"

# ---------------------------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------------------------
if [[ ! -d "$VENV" ]]; then
    echo "Venv not found at $VENV. Create it first."
    exit 1
fi

source "$VENV/bin/activate"

if [[ ! -f "$TRAIN_DATASET" ]]; then
    echo "Training dataset not found: $TRAIN_DATASET"
    exit 1
fi

# ---------------------------------------------------------------------------
# Train PCFG grammar if the rule directory doesn't exist yet
# ---------------------------------------------------------------------------
RULES_DIR="$PCFG_RULES_BASE/$RULE_NAME"

if [[ ! -d "$RULES_DIR" ]]; then
    echo "Rule '${RULE_NAME}' not found — training PCFG grammar from: $TRAIN_DATASET"
    python - <<PYEOF
import sys
sys.path.insert(0, "$CHRISTOS_IMPL")

from legacy_pcfg_master.python_pcfg_cracker_version3.pcfg_trainer import train

data = []
with open("$TRAIN_DATASET", "r", encoding="utf-8") as fh:
    for line in fh:
        pw = line.strip()
        if pw:
            data.append([pw])

print(f"Loaded {len(data):,} training passwords.")
train(data=data, rule_name="$RULE_NAME")
print("Training complete. Rule saved to: $RULES_DIR")
PYEOF
else
    echo "Rule '${RULE_NAME}' already exists at: $RULES_DIR — skipping training."
fi

# ---------------------------------------------------------------------------
# Run the PCFG honeyword evaluation
# ---------------------------------------------------------------------------
CMD=(
    python -u test_honeygen_pcfg.py
    --target-dataset "$TARGET_DATASET"
    --attacker-dataset "$ATTACKER_DATASET"
    --model-path "$MODEL_PATH"
    --rule-name "$RULE_NAME"
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
