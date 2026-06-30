"""
run_attack_evolving_model.py

Evaluates the evolving-password honeyword generator against the
NormalizedTopPWModelHG attacker (collaborator's implementation, in
honeygen).

Builds a disjoint reservoir-sampled train/test split: the training half 
seeds the generator's FrequencyDatabase, and only the test half is run 
through generate_honeywords_evolving(), with the DB still evolving live 
during that process. This avoids double-counting test passwords that would 
occur from loading the DB directly from the same file being attacked.

Usage
-----
python run_attack_evolving_model.py \\
    --target-dataset rockyou \\
    --attacker-dataset hashmob_counts \\
    --train-size 5000 \\
    --num-users 200 \\
    --k 20 \\
    --t1 1

python run_attack_evolving_model.py --list-datasets

Arguments
---------
--target-dataset    Target password dataset. Default: rockyou
--attacker-dataset  Attacker dataset name. Default: hashmob_counts
--k                 Sweetwords per user. Default: 20
--t1                Max failed guesses per user. Default: 1
--t2                Global failed-guess cap. Default: unlimited
--train-size        Passwords used to seed the FrequencyDatabase before any
                    test user registers. Disjoint from the test set.
                    Default: 5000
--num-users         Number of test users, reservoir-sampled disjoint from
                    --train-size and processed sequentially in full.
                    Default: 200
--min-lev-dist      Levenshtein typo-safety threshold. Default: 3
--max-len-delta     Length filter tolerance. Default: 3
--seed              Random seed; fixes the train/test split and the
                    per-user sweetword shuffle. Default: 42
--limit             Limit passwords scanned from the target dataset before
                    the train/test split is drawn.
--no-progress       Disable progress bars.
--no-plot           Skip calling plot_results.py after the run.
--plot-out          Output PNG path for plot_results.py.
                    Default: outputs/<results-json-stem>.png
--plot-title        Plot title. Default: auto-generated from
                    target/attacker dataset, k, n.
--list-datasets     Print available datasets and exit.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import List, Optional, Tuple

# ── Path setup ────────────────────────────────────────────────────────────────
# Resolves the repository layout so this script can import the generator
# modules from the implementation directory and the attacker modules from
# the collaborator's honeygen package, regardless of where it is invoked from.
_HERE        = Path(__file__).resolve().parent             # .../evolving_user-profile_append-secret/implementation/attacks
_IMPL        = _HERE.parent                                # .../evolving_user-profile_append-secret/implementation
_METHODS        = _IMPL.parent                             # .../evolving_user-profile_append-secret
_ROOT        = _METHODS.parent                             # .../Secure-Honeyword-Generation
_HONEYGEN_IMPL = _ROOT / 'honeygen' / 'implementation'     # .../honeygen/implementation
_DATASETS    = _METHODS / 'datasets'                       # .../evolving_user-profile_append-secret/datasets

sys.path.insert(0, str(_IMPL))        # generator modules
sys.path.insert(0, str(_HONEYGEN_IMPL)) # attacker modules

# ── Generator imports ─────────────────────────────────────────────────────────
from frequency_db   import FrequencyDatabase
from evolving_model import generate_honeywords_evolving

# ── Attacker imports ──────────────────────────────────────────────────────────
from attackers.normalized_top_pw_hg import (
    NormalizedTopPWModelHG,
    SweetwordList as AttackerSweetwordList,
)

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    tqdm = None
    TQDM_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# Dataset registry
# ─────────────────────────────────────────────────────────────────────────────

# Target datasets: corpora used both to seed the generator's FrequencyDatabase
# and to draw the test-user passwords for which honeywords are generated.
TARGET_DATASET_MAP = {
    'adultfriendfinder':    str(_DATASETS / 'adultfriendfinder-com-2016_sorted_preprocessed.txt'),
    'chegg-com':            str(_DATASETS / 'chegg-com_sorted_preprocessed.txt'),
    'dropbox':              str(_DATASETS / 'dropbox_sorted_preprocessed.txt'),
    'dubsmash':             str(_DATASETS / 'dubsmash-com_sorted_preprocessed.txt'),
    'pwned':                str(_DATASETS / 'have-i-been-pwned-v2_sorted_preprocessed.txt'),
    'lastfm':               str(_DATASETS / 'last-fm-2016_sorted_preprocessed.txt'),
    'linkedin':             str(_DATASETS / 'linkedin_sorted_preprocessed.txt'),
    'myspace':              str(_DATASETS / 'myspace_sorted_preprocessed.txt'),
    # 'rockyou':            str(_DATASETS / 'rockyou_targeted_attacker_counts.txt'),
    'rockyou':            str(_DATASETS / 'rockyou_50k_sorted_preprocessed.txt'),
    # 'rockyou':              str(_DATASETS / 'rockyou_sorted_preprocessed.txt'),
    'yahoo':                str(_DATASETS / 'yahoo_sorted_preprocessed.txt'),
    'yoku':                 str(_DATASETS / 'yoku_sorted_preprocessed.txt'),
    'zynga':                str(_DATASETS / 'zynga-com_sorted_preprocessed.txt'),
    
}

# Attacker datasets: password:count files supplying the probability
# distribution the attacker uses to rank sweetwords.
ATTACKER_DATASET_MAP = {
    'hashmob_counts': str(_DATASETS / 'hashmob_counts.txt'),
}

# Total sum of counts for each attacker dataset, used to normalize raw
# counts into probabilities.
DATASET_SIZE_MAP = {
    'hashmob_counts': 23_136_055_988,
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def load_passwords(path: str, limit: Optional[int] = None) -> List[str]:
    """Read a plain-text password file (one per line) into a list, in
    file order, optionally truncated at `limit`."""
    passwords = []
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            pw = line.strip()
            if not pw:
                continue
            passwords.append(pw)
            if limit and len(passwords) >= limit:
                break
    return passwords


def split_train_test(
    path:        str,
    train_limit: int,
    test_limit:  int,
    seed:        int,
    file_limit:  Optional[int] = None,
) -> Tuple[List[str], List[str]]:
    """
    Disjoint reservoir-sampling split (Vitter Algorithm R), single pass.

    Returns (train_passwords, test_passwords) with zero overlap: train
    passwords seed the generator's FrequencyDatabase, and test passwords
    are the only set ever passed to generate_honeywords_evolving(). This
    guarantees no test password is counted twice toward the database's
    statistics.

    If `file_limit` is set, the split is drawn from within that truncated
    prefix of the source file rather than the full file.
    """
    rng  = random.Random(seed)
    need = train_limit + test_limit

    reservoir: List[str] = []
    n_seen = 0
    t0     = time.time()

    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            pw = line.strip()
            if not pw:
                continue
            n_seen += 1
            if len(reservoir) < need:
                reservoir.append(pw)
            else:
                j = rng.randint(0, n_seen - 1)
                if j < need:
                    reservoir[j] = pw
            if file_limit and n_seen >= file_limit:
                break

    elapsed = time.time() - t0
    print(f"      {n_seen:,} passwords scanned in {elapsed:.1f}s "
          f"(reservoir={len(reservoir):,})")

    if len(reservoir) < need:
        print(f"      [WARN] Only {len(reservoir):,} passwords available "
              f"(needed {need:,} for train+test). Rescaling split.")
        train_limit = int(len(reservoir) * train_limit / need) if need else 0
        test_limit  = len(reservoir) - train_limit

    rng.shuffle(reservoir)
    train_passwords = reservoir[:train_limit]
    test_passwords  = reservoir[train_limit:train_limit + test_limit]
    return train_passwords, test_passwords


def build_attacker_entries(
    test_passwords: List[str],
    db:             FrequencyDatabase,
    k:              int,
    min_lev_dist:   int,
    max_len_delta:  int,
    seed:           int,
) -> List[AttackerSweetwordList]:
    """Generate a sweetword list for each test password and package the
    results into the SweetwordList shape the attacker expects, shuffling
    each list so position carries no information about the real password."""
    rng      = random.Random(seed)
    entries  = []
    skipped  = 0

    for i, password in enumerate(test_passwords):
        try:
            result = generate_honeywords_evolving(
                password,
                db,
                k=k,
                min_lev_dist=min_lev_dist,
                max_len_delta=max_len_delta,
            )
        except Exception as e:
            skipped += 1
            continue

        sweetwords = list(result.sweetwords)
        rng.shuffle(sweetwords)

        entries.append(AttackerSweetwordList(
            user_id=f"user_{i}",
            sweetwords=sweetwords,
            real_password=password,
        ))

    if skipped:
        print(f"  [WARN] Skipped {skipped} passwords due to generation errors.")

    return entries


def save_results(stats: dict, output_path: Path) -> None:
    """Write the results dict to `output_path` as indented JSON, creating
    parent directories as needed."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(stats, f, indent=2)
    print(f"\n  Results saved to: {output_path}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate evolving-password honeyword generator against attacker."
    )
    parser.add_argument(
        '--target-dataset',
        choices=sorted(TARGET_DATASET_MAP.keys()),
        default='rockyou',
        help=f"Target password dataset (default: rockyou)",
    )
    parser.add_argument(
        '--attacker-dataset',
        choices=sorted(ATTACKER_DATASET_MAP.keys()),
        default='hashmob_counts',
        help="Attacker dataset name (default: hashmob_counts)",
    )
    parser.add_argument('--k',             type=int, default=20,
                        help='Sweetwords per user (default 20)')
    parser.add_argument('--t1',            type=int, default=1,
                        help='Max failed guesses per user (default 1)')
    parser.add_argument('--t2',            type=int, default=None,
                        help='Global failed-guess cap (default: unlimited)')
    parser.add_argument('--train-size',    type=int, default=5000,
                        help='Passwords used to seed the FrequencyDatabase '
                             'before any test user registers (default 5000). '
                             'Disjoint from the test set.')
    parser.add_argument('--num-users',     type=int, default=200,
                        help='Number of test users (default 200), '
                             'reservoir-sampled disjoint from --train-size '
                             'passwords and processed sequentially in full.')
    parser.add_argument('--min-lev-dist',  type=int, default=3,
                        help='Levenshtein typo-safety threshold (default 3)')
    parser.add_argument('--max-len-delta', type=int, default=3,
                        help='Length filter tolerance (default 3)')
    parser.add_argument('--seed',          type=int, default=42,
                        help='Random seed (default 42). Fixes both the '
                             'train/test split and the per-user sweetword shuffle.')
    parser.add_argument('--limit',         type=int, default=None,
                        help='Limit passwords scanned from target dataset '
                             'before the train/test split is drawn')
    parser.add_argument('--no-progress',   action='store_true',
                        help='Disable progress bars')
    parser.add_argument('--no-plot',       action='store_true',
                        help='Skip calling plot_results.py after the run')
    parser.add_argument('--plot-out',      type=str, default=None,
                        help='Output PNG path for plot_results.py (default: '
                             'outputs/<same-stem-as-results-json>.png)')
    parser.add_argument('--plot-title',    type=str, default=None,
                        help='Title for the plot (default: auto-generated '
                             'from target/attacker dataset, k, n)')
    parser.add_argument('--list-datasets', action='store_true',
                        help='Print available datasets and exit')
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()

    if args.list_datasets:
        print("\nTarget datasets:")
        for name, path in sorted(TARGET_DATASET_MAP.items()):
            exists = '✓' if Path(path).exists() else '✗ NOT FOUND'
            print(f"  {name:<20} {exists}  {path}")
        print("\nAttacker datasets:")
        for name, path in sorted(ATTACKER_DATASET_MAP.items()):
            exists = '✓' if Path(path).exists() else '✗ NOT FOUND'
            size   = DATASET_SIZE_MAP.get(name, 'unknown')
            print(f"  {name:<20} {exists}  size={size}  {path}")
        return

    random.seed(args.seed)

    target_path   = TARGET_DATASET_MAP[args.target_dataset]
    attacker_path = ATTACKER_DATASET_MAP[args.attacker_dataset]
    dataset_size  = DATASET_SIZE_MAP[args.attacker_dataset]

    # Validate files exist before doing any work
    for label, path in [('Target dataset', target_path),
                         ('Attacker DB',    attacker_path)]:
        if not Path(path).exists():
            print(f"  [ERROR] {label} not found: {path}")
            print(f"          Check your dataset paths in DATASET_MAP at the top of this file.")
            sys.exit(1)

    # ── Step 1: disjoint train/test split ─────────────────────────────────────
    print(f"[1/4] Building disjoint train/test split from: {target_path}")
    print(f"      train_size={args.train_size:,}  num_users={args.num_users:,}")
    train_passwords, test_passwords = split_train_test(
        target_path,
        train_limit=args.train_size,
        test_limit=args.num_users,
        seed=args.seed,
        file_limit=args.limit,
    )
    if len(test_passwords) < args.num_users:
        print(f"      [WARN] Test set rescaled to {len(test_passwords):,} "
              f"users (insufficient data for the requested split).")
        args.num_users = len(test_passwords)

    db = FrequencyDatabase()
    db.load_corpus(train_passwords)
    s = db.stats()
    print(f"      Train DB: {s['total_passwords']:,} passwords | "
          f"{s['unique_patterns']} patterns | "
          f"{s['unique_alpha_tokens']:,} alpha tokens | "
          f"{s['unique_digit_tokens']:,} digit tokens")
    print(f"      Test set: {len(test_passwords):,} passwords "
          f"(disjoint from train; will be processed sequentially, in full —"
          f" no further subsampling)")

    # ── Step 2: generate sweetword lists ──────────────────────────────────────
    # Each test password is registered into the database immediately before
    # its own honeywords are generated, so the database evolves throughout
    # this pass: later test users draw from a pool enriched by earlier ones.
    print(f"\n[2/4] Generating sweetword lists "
          f"(k={args.k}, lev≥{args.min_lev_dist}, |Δlen|≤{args.max_len_delta}) ...")
    entries = build_attacker_entries(
        test_passwords, db,
        k=args.k,
        min_lev_dist=args.min_lev_dist,
        max_len_delta=args.max_len_delta,
        seed=args.seed,
    )
    print(f"      Generated {len(entries)} sweetword lists.")
    if not entries:
        print("  [ERROR] No sweetword lists generated. Exiting.")
        sys.exit(1)

    # ── Step 3: run attacker ──────────────────────────────────────────────────
    show_progress = not args.no_progress and TQDM_AVAILABLE
    print(f"\n[3/4] Running attacker "
          f"(t1={args.t1}, t2={args.t2}, db={args.attacker_dataset}) ...")
    attacker = NormalizedTopPWModelHG(
        db_path=attacker_path,
        dataset_size=dataset_size,
    )
    attack_stats, flatness_graph, epsilon_flatness, success_number_stats = attacker.analyze(
        sweetword_lists=entries,
        k=args.k,
        t1=args.t1,
        t2=args.t2,
        show_progress=show_progress,
        success_number=True,
    )

    # cracked_by_t1 and attack_success_rate are derived the same way as in
    # statistics.py, so the saved JSON shares its structure with the other
    # attackers' output and can be combined directly for plotting.
    cracked_by_t1 = [
        sum(1 for value in flatness_graph if value <= t)
        for t in range(1, args.k + 1)
    ] if flatness_graph else []
    attack_success_rate = attack_stats.cracked_percent / 100.0

    # ── Results ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  ATTACK RESULTS — Evolving-Password Model")
    print("=" * 60)
    print(f"  Target dataset           : {args.target_dataset}")
    print(f"  Attacker dataset         : {args.attacker_dataset}")
    print(f"  k={args.k}  t1={args.t1}  t2={args.t2}  "
          f"seed={args.seed}  users={len(entries)}")
    print(f"  Train size               : {len(train_passwords):,} "
          f"(disjoint from test set)")
    print()
    print(f"  Users cracked            : {attack_stats.cracked_users} / "
          f"{attack_stats.total_users} "
          f"({attack_stats.cracked_percent:.1f}%)")
    print(f"  Total guesses            : {attack_stats.total_guesses}")
    print(f"  Failed guesses           : {attack_stats.failed_guesses}")
    print(f"  Mean guesses to crack    : {attack_stats.mean_guesses_to_crack:.2f}")
    print(f"  Mean failures before crack: {attack_stats.mean_failures_before_crack:.2f}")
    print()
    print(f"  Empirical ε-flatness     : {epsilon_flatness:.4f}  "
          f"(ideal = {1/args.k:.4f} for k={args.k})")

    if flatness_graph:
        avg_pos = sum(flatness_graph) / len(flatness_graph)
        found_1 = sum(1 for x in flatness_graph if x == 1)
        print(f"\n  Flatness graph:")
        print(f"    Average guess position : {avg_pos:.2f}  "
              f"(ideal = {args.k / 2:.1f})")
        print(f"    Found at position 1    : {found_1} / {len(flatness_graph)} "
              f"({100 * found_1 / len(flatness_graph):.1f}%)")
    print("=" * 60)

    # ── Save results to JSON ──────────────────────────────────────────────────
    # Filename pattern: {target_dataset}_k{k}_t1{t1}_t2{t2}_seed{seed}.json
    output_dir  = _HERE / 'outputs'
    output_name = (f"{args.target_dataset}_k{args.k}_t1{args.t1}"
                   f"_t2{args.t2}_seed{args.seed}.json")
    output_path = output_dir / output_name
    results = {
        'target_dataset':       args.target_dataset,
        'attacker_dataset':     args.attacker_dataset,
        'k':                    args.k,
        't1':                   args.t1,
        't2':                   args.t2,
        'seed':                 args.seed,
        'train_size':           len(train_passwords),
        'num_users':            len(entries),
        'epsilon_flatness':     epsilon_flatness,
        'attack_success_rate':  attack_success_rate,
        'flatness_graph':       flatness_graph,
        'cracked_by_t1':        cracked_by_t1,
        'attack_stats':         asdict(attack_stats),
        'success_number':       asdict(success_number_stats) if success_number_stats else None,
    }
    save_results(results, output_path)

    # ── Step 4: plot results ───────────────────────────────────────────────────
    # plot_results.py reads this JSON shape directly (epsilon_flatness /
    # flatness_graph / attack_stats.success_curve); no further conversion
    # is needed before pointing it at the file just written.
    if not args.no_plot:
        plot_script = _HERE / 'plot_results.py'
        if not plot_script.exists():
            print(f"\n  [WARN] plot_results.py not found at {plot_script}; "
                  "skipping plot. Pass --no-plot to suppress this warning.")
        else:
            plot_out = args.plot_out or str(
                output_dir / f"{output_path.stem}_plot.png"
            )
            plot_title = args.plot_title or (
                f"Evolving-Password Model — {args.target_dataset} "
                f"[{args.attacker_dataset}]  (k={args.k}, n={len(entries)})"
            )
            print(f"\n[4/4] Plotting results ...")
            cmd = [
                sys.executable, str(plot_script),
                '--files', str(output_path),
                '--out',   plot_out,
                '--title', plot_title,
            ]
            result = subprocess.run(cmd)
            if result.returncode != 0:
                print(f"  [WARN] plot_results.py exited with code "
                      f"{result.returncode}; plot may not have been saved.")
    else:
        print("\n  [SKIP] Plotting (--no-plot).")


if __name__ == '__main__':
    main()