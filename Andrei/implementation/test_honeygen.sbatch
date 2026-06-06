#!/bin/bash
#SBATCH --job-name=honeygen_eval
#SBATCH --partition=compute
#SBATCH --time=02:00:00
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=8
#SBATCH --mem-per-cpu=3968M
#SBATCH --account=Education-EEMCS-MSc-CS
#SBATCH --output=honeygen_eval.%j.out
#SBATCH --error=honeygen_eval.%j.err

module load 2025
module load python

# Tweakable parameters
VENV="$PWD/.venv"
TARGET_DATASET="data/rockyou_sorted_preprocessed.txt"
ATTACKER_DATASET="chegg-com"   # chegg-com | dropbox | linkedin | yahoo
MODEL_PATH="honeygen_models/model_trained_on_rockyou_500_epochs.bin"
K=20
L=10
SEED=67
T1=20
T2=61                         
LIMIT=""                      # empty = full dataset
OUT_PREFIX="honeygen_chegg"

if [[ ! -d "$VENV" ]]; then
    echo "Venv not found at $VENV. Create it first on the login node."
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
)

if [[ -n "$T2" ]]; then
    CMD+=(--t2 "$T2")
fi

if [[ -n "$LIMIT" ]]; then
    CMD+=(--limit "$LIMIT")
fi

"${CMD[@]}"
