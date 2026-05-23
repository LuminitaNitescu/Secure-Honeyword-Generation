#!/bin/bash
#SBATCH --job-name=ft_train
#SBATCH --partition=compute
#SBATCH --time=00:10:00
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=8
#SBATCH --mem-per-cpu=3968M
#SBATCH --account=Education-EEMCS-MSc-CS
#SBATCH --output=ft_train.%j.out
#SBATCH --error=ft_train.%j.err

module load 2025
module load python

VENV="$PWD/.venv"
if [[ ! -d "$VENV" ]]; then
    echo "Venv not found at $VENV. Create it first on the login node."
    exit 1
fi

source "$VENV/bin/activate"

if [[ -z "$1" ]]; then
    echo "Usage: sbatch mainv2.sbatch <password>"
    exit 1
fi

python -u mainv2.py "$1"
