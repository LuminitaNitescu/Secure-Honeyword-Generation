#!/bin/bash
#SBATCH --job-name=ft_train
#SBATCH --partition=compute
#SBATCH --time=01:00:00
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=8
#SBATCH --mem-per-cpu=3968M
#SBATCH --account=Education-EEMCS-MSc-CS
#SBATCH --output=ft_train.%j.out
#SBATCH --error=ft_train.%j.err

module load 2025
module load python

OUTPUT_DIR="$HOME/honeyword_models"
MODEL_NAME="model_trained_on_rockyou_500_epochs.bin"

mkdir -p "$OUTPUT_DIR"

VENV="$PWD/.venv_fasttext"
if [[ ! -d "$VENV" ]]; then
    echo "Venv not found at $VENV. Create it first on the login node."
    exit 1
fi

source "$VENV/bin/activate"

python -u ft_train.py

if [[ -f "$MODEL_NAME" ]]; then
    mv "$MODEL_NAME" "$OUTPUT_DIR/"
    echo "Model moved to: $OUTPUT_DIR/$MODEL_NAME"
else
    echo "Model not found: $MODEL_NAME"
    exit 1
fi
