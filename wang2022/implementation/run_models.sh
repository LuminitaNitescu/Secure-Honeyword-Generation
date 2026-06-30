#!/bin/bash

MODEL_NAME="markov" # list | markov | pcfg | tarmarkov | tarlist | tarpcfg

# If you would like to load a trained PCFG/TarPCFG
# MODEL_PATH="RockYouRules"

# If you would like to load a trained Markov/TarMarkov or TarList model
# MODEL_PATH="../trained_models/markov.pickle"

MODEL_PATH=""
K=20
SEED=67
T1=20
T2=61

# Parameter configuration for experiments on non-targeted models
TRAIN_PATH="../data/rockyou_final_tr.txt"
TEST_PATH="../data/rockyou_final_ts.txt"
ATTACKER_PATH="../data/hashmob_counts.txt"
ATTACKER_SIZE=23136055988

# Parameter configuration for experiments on targeted models
# TRAIN_PATH="../data/synthetic.rockyou_tr.csv"
# TEST_PATH="../data/synthetic.rockyou_ts.csv"
# ATTACKER_PATH="../data/synthetic_attacker_counts.txt"
# ATTACKER_SIZE=32602874

MODE="experiments" # honeywords | experiments

SAVE_PATH="../results"

if [[ -z "$VIRTUAL_ENV" && -z "$CONDA_DEFAULT_ENV" ]]; then
    echo "ERROR: No virtual environment active. Activate a venv or conda env first." >&2
    exit 1
fi

python "$(dirname "$0")/run_experiments.py" \
    "$MODEL_NAME" "$MODEL_PATH" "$K" "$SEED" "$T1" "$T2" \
    "$TRAIN_PATH" "$TEST_PATH" "$MODE" "$ATTACKER_PATH" "$ATTACKER_SIZE" "$SAVE_PATH"