#!/bin/bash

MODEL_NAME="markov" # list | markov | pcfg | tarmarkov | tarlist | tarpcfg
# MODEL_PATH="RockYouUltraFinal"
MODEL_PATH="../trained_models/markov3.pickle"
# MODEL_PATH=""
K=20
SEED=67
T1=20
T2=61
TRAIN_PATH=""
# TRAIN_PATH="../data2/rockyou_final_tr.txt"
TEST_PATH="../data/test.txt"
MODE="honeywords" # honeywords | experiments
ATTACKER_PATH="../data/"
ATTACKER_SIZE=10000000
SAVE_PATH="../results"

if [[ -z "$VIRTUAL_ENV" && -z "$CONDA_DEFAULT_ENV" ]]; then
    echo "ERROR: No virtual environment active. Activate a venv or conda env first." >&2
    exit 1
fi

python "$(dirname "$0")/run_experiments.py" \
    "$MODEL_NAME" "$MODEL_PATH" "$K" "$SEED" "$T1" "$T2" \
    "$TRAIN_PATH" "$TEST_PATH" "$MODE" "$ATTACKER_PATH" "$ATTACKER_SIZE" "$SAVE_PATH"