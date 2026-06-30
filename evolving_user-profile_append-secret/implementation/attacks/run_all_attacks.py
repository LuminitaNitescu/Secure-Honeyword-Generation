#!/usr/bin/env python3
"""
run_all_attacks.py — Run all three attack evaluators and produce plots.

Usage
-----
# Default run (rockyou, 5000 users):
python run_all_attacks.py

# Custom parameters:
python run_all_attacks.py --dataset yahoo --n-users 10000 --train-size 10000

# Skip an attacker (e.g. skip hashmob if DB not available):
python run_all_attacks.py --skip-hashmob

# Skip plotting:
python run_all_attacks.py --no-plot

# List available datasets:
python run_all_attacks.py --list-datasets
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

# ── Path setup ────────────────────────────────────────────────────────────────
_HERE = Path(__file__).resolve().parent          # .../attacks/
_IMPL = _HERE.parent                             # .../implementation/
sys.path.insert(0, str(_IMPL))

from run_attack_evolving_model import TARGET_DATASET_MAP


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def run(cmd: list, label: str) -> bool:
    """Run a subprocess command, stream output live, return True on success."""
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    print(f"  CMD: {' '.join(str(c) for c in cmd)}\n")
    result = subprocess.run([str(c) for c in cmd])
    if result.returncode != 0:
        print(f"\n  [ERROR] {label} failed with exit code {result.returncode}.")
        return False
    return True


def parse_args():
    p = argparse.ArgumentParser(
        description="Run all three honeyword attack evaluators and plot results.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument('--dataset',        default='rockyou',
                   choices=sorted(TARGET_DATASET_MAP.keys()),
                   help='Target dataset name.')
    p.add_argument('--n-users',        type=int, default=5000,
                   help='Number of test users for every attacker.')
    p.add_argument('--train-size',     type=int, default=5000,
                   help='Training passwords for list-model attackers.')
    p.add_argument('--k',              type=int, default=20,
                   help='Sweetwords per user.')
    p.add_argument('--t1',             type=int, default=1,
                   help='Max failed guesses per user.')
    p.add_argument('--t2',             type=int, default=10_000,
                   help='Global failed-guess cap (list-model attackers).')
    p.add_argument('--seed',           type=int, default=42)
    p.add_argument('--min-lev',        type=int, default=3,
                   help='Levenshtein typo-safety threshold.')
    p.add_argument('--max-len-delta',  type=int, default=3,
                   help='Length filter tolerance.')
    p.add_argument('--skip-evolving',  action='store_true',
                   help='Skip list-model evolving-DB attacker.')
    p.add_argument('--skip-fixed',     action='store_true',
                   help='Skip list-model fixed-DB attacker.')
    p.add_argument('--skip-hashmob',   action='store_true',
                   help='Skip hashmob (NormalizedTopPWModelHG) attacker.')
    p.add_argument('--no-plot',        action='store_true',
                   help='Skip plotting after attacks finish.')
    p.add_argument('--list-datasets',  action='store_true',
                   help='Print available datasets and exit.')
    return p.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    if args.list_datasets:
        print("\nAvailable datasets:")
        for name, path in sorted(TARGET_DATASET_MAP.items()):
            exists = '✓' if Path(path).exists() else '✗ NOT FOUND'
            print(f"  {name:<25} {exists}  {path}")
        return

    dataset_path = TARGET_DATASET_MAP[args.dataset]
    if not Path(dataset_path).exists():
        print(f"[ERROR] Dataset file not found: {dataset_path}")
        print("Run with --list-datasets to see all registered paths.")
        sys.exit(1)

    outputs = _HERE / 'outputs'
    outputs.mkdir(exist_ok=True)

    # ── Output JSON paths ─────────────────────────────────────────────────────
    tag           = f"k{args.k}_seed{args.seed}"
    evolving_json = outputs / f"{args.dataset}_list_evolving_{tag}.json"
    fixed_json    = outputs / f"{args.dataset}_list_fixed_{tag}.json"
    hashmob_json  = outputs / f"{args.dataset}_{tag}_t1{args.t1}_t2None.json"
    plot_out      = outputs / f"{args.dataset}_{tag}_comparison.png"

    py = sys.executable   # same Python interpreter running this script
    completed = []

    print(f"\n{'='*60}")
    print(f"  Honeyword Security Evaluation — All Attackers")
    print(f"  Dataset    : {args.dataset}")
    print(f"  File       : {dataset_path}")
    print(f"  Users      : {args.n_users}  (train={args.train_size})")
    print(f"  k={args.k}  T1={args.t1}  T2={args.t2}  seed={args.seed}")
    print(f"{'='*60}")

    # ── 1. List-model attacker — evolving DB ──────────────────────────────────
    if not args.skip_evolving:
        ok = run([
            py, _HERE / 'attack_evolving_db.py',
            '--dataset',    dataset_path,
            '--n_users',    args.n_users,
            '--train_size', args.train_size,
            '--k',          args.k,
            '--min_lev',    args.min_lev,
            '--T1',         args.t1,
            '--T2',         args.t2,
            '--seed',       args.seed,
            '--save_json',  evolving_json,
        ], label=f"[1/4] List-model attacker — evolving DB")
        if ok:
            completed.append(str(evolving_json))
    else:
        print("\n  [SKIP] List-model evolving DB attacker.")

    # ── 2. List-model attacker — fixed DB ─────────────────────────────────────
    if not args.skip_fixed:
        ok = run([
            py, _HERE / 'attack_fixed_db.py',
            '--dataset',    dataset_path,
            '--n_users',    args.n_users,
            '--train_size', args.train_size,
            '--k',          args.k,
            '--min_lev',    args.min_lev,
            '--T1',         args.t1,
            '--T2',         args.t2,
            '--seed',       args.seed,
            '--save_json',  fixed_json,
        ], label=f"[2/4] List-model attacker — fixed DB")
        if ok:
            completed.append(str(fixed_json))
    else:
        print("\n  [SKIP] List-model fixed DB attacker.")

    # ── 3. Hashmob attacker ───────────────────────────────────────────────────
    if not args.skip_hashmob:
        ok = run([
            py, _HERE / 'run_attack_evolving_model.py',
            '--target-dataset',   args.dataset,
            '--attacker-dataset', 'hashmob_counts',
            '--train-size',       args.train_size,
            '--num-users',        args.n_users,
            '--k',                args.k,
            '--t1',               args.t1,
            '--min-lev-dist',     args.min_lev,
            '--max-len-delta',    args.max_len_delta,
            '--seed',             args.seed,
            '--no-progress',
            '--no-plot',
        ], label=f"[3/4] Hashmob attacker (NormalizedTopPWModelHG)")
        if ok and hashmob_json.exists():
            completed.append(str(hashmob_json))
        elif ok:
            # hashmob runner saves with a slightly different name pattern;
            # find the most recent JSON in outputs that matches
            candidates = sorted(
                outputs.glob(f"{args.dataset}_k{args.k}_t1{args.t1}*.json"),
                key=lambda p: p.stat().st_mtime, reverse=True
            )
            if candidates:
                completed.append(str(candidates[0]))
    else:
        print("\n  [SKIP] Hashmob attacker.")

    # ── 4. Plot ───────────────────────────────────────────────────────────────
    if args.no_plot:
        print("\n  [SKIP] Plotting (--no-plot).")
    elif not completed:
        print("\n  [SKIP] No successful results to plot.")
    else:
        run([
            py, _HERE / 'plot_results.py',
            '--files', *completed,
            '--title', (f"Evolving-Password Model — Attacker Comparison "
                        f"({args.dataset}, k={args.k}, n={args.n_users})"),
            '--out', str(plot_out),
        ], label=f"[4/4] Plotting results")

    print(f"\n{'='*60}")
    print(f"  Done.")
    print(f"  Results : {outputs}/")
    if not args.no_plot and completed:
        print(f"  Plot    : {plot_out}")
    print(f"{'='*60}\n")


if __name__ == '__main__':
    main()