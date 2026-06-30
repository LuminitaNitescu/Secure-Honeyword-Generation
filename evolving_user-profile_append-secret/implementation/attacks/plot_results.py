#!/usr/bin/env python3
"""
plot_results.py

Plots flatness and success-number graphs from attacker JSON result files.
Auto-detects and supports output from:
  attack_evolving_db.py        list-model attacker, evolving DB
  attack_fixed_db.py           list-model attacker, fixed DB
  run_attack_evolving_model.py NormalizedTopPWModelHG (Hashmob)

attack_evolving_db.py and attack_fixed_db.py require --save_json to
produce a result file; run_attack_evolving_model.py saves one natively.

Usage
-----
python plot_results.py --files outputs/rockyou_k20_t11_t2None_seed42.json

python plot_results.py \\
    --files \\
        outputs/rockyou_k20_t11_t2None_seed42.json \\
        outputs/yahoo_k20_t11_t2None_seed42.json \\
    --out outputs/comparison.png

python plot_results.py \\
    --files \\
        outputs/evolving_db_rockyou.json \\
        outputs/fixed_db_rockyou.json \\
        outputs/hashmob_rockyou.json \\
    --title "Evolving model — attacker comparison" \\
    --out outputs/attacker_comparison.png

Arguments
---------
--files                One or more JSON result files to plot. Required.
--out                  Output PNG path. Default: outputs/plot.png
--title                Plot title. Default: Honeyword Security Evaluation
--no-success-number    Only plot the flatness graph; skip success-number.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Tuple

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
except ImportError:
    sys.exit("matplotlib is required: pip install matplotlib")


# ─────────────────────────────────────────────────────────────────────────────
# Data loading — handles all three attacker output formats
# ─────────────────────────────────────────────────────────────────────────────

def load_result(path: str) -> dict:
    """
    Load a JSON result file and normalise it into a common schema:

    {
        'label':          str      — display name for legend
        'k':              int      — sweetwords per user
        'epsilon':        float    — ε-flatness
        'flatness_ranks': list[int]— rank of real password per user (Algorithm 2)
        'success_curve':  list[(int,int)] — (failed, cracked) pairs (Algorithm 1)
        'n_users':        int
    }

    Handles output from:
      - run_attack_evolving_model.py  (hashmob attacker)
      - attack_evolving_db.py / attack_fixed_db.py  (list-model attacker,
        when saved via --save_json or save_list_model_results())
    """
    with open(path) as f:
        raw = json.load(f)

    # ── Format 1: run_attack_evolving_model.py (hashmob attacker) ────────────
    # Keys: target_dataset, attacker_dataset, k, epsilon_flatness,
    #       flatness_graph, attack_stats.success_curve
    if 'epsilon_flatness' in raw and 'flatness_graph' in raw:
        k        = raw.get('k', 20)
        ranks    = [int(r) for r in raw['flatness_graph']]
        epsilon  = raw.get('epsilon_flatness', sum(1 for r in ranks if r == 1) / len(ranks))
        curve    = []
        if 'attack_stats' in raw and 'success_curve' in raw.get('attack_stats', {}):
            curve = [(int(f), int(s))
                     for f, s in raw['attack_stats']['success_curve']]
        target   = raw.get('target_dataset', Path(path).stem)
        attacker = raw.get('attacker_dataset', 'hashmob')
        label    = f"{target} [{attacker}]"
        return {
            'label':          label,
            'k':              k,
            'epsilon':        epsilon,
            'flatness_ranks': ranks,
            'success_curve':  curve,
            'n_users':        raw.get('num_users', len(ranks)),
        }

    # ── Format 2: attack_evolving_db / attack_fixed_db (list-model attacker)
    # Keys: ranks, success_curve, k, epsilon, label, n_users
    if 'ranks' in raw:
        ranks   = [int(r) for r in raw['ranks']]
        epsilon = raw.get('epsilon', sum(1 for r in ranks if r == 1) / len(ranks))
        curve   = [(int(f), int(s)) for f, s in raw.get('success_curve', [])]
        return {
            'label':          raw.get('label', Path(path).stem),
            'k':              raw.get('k', 20),
            'epsilon':        epsilon,
            'flatness_ranks': ranks,
            'success_curve':  curve,
            'n_users':        raw.get('n_users', len(ranks)),
        }

    raise ValueError(
        f"Unrecognised result format in '{path}'. "
        "Expected keys 'epsilon_flatness'+'flatness_graph' "
        "or 'ranks'+'success_curve'."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Derived curves
# ─────────────────────────────────────────────────────────────────────────────

def flatness_cdf(ranks: List[int], k: int) -> Tuple[List[int], List[float]]:
    """
    CDF of the flatness graph: P(real password found within x attempts).
    Returns (x_values, y_values) for x in 1..k.
    """
    n  = len(ranks)
    xs = list(range(1, k + 1))
    ys = [sum(1 for r in ranks if r <= x) / n for x in xs]
    return xs, ys


def perfect_flatness(k: int) -> Tuple[List[int], List[float]]:
    """The 1/k-flat perfect baseline: P(found in ≤ x) = x/k."""
    xs = list(range(1, k + 1))
    ys = [x / k for x in xs]
    return xs, ys


def perfect_success_number(n_users: int, k: int,
                            max_failures: int) -> Tuple[List[int], List[int]]:
    """
    Perfect success-number baseline: one real password cracked per k-1
    failed attempts (uniform random guessing).
    """
    xs, ys = [], []
    successes = 0
    for failures in range(0, max_failures + 1, max(1, k - 1)):
        successes = failures // (k - 1)
        xs.append(failures)
        ys.append(min(successes, n_users))
    return xs, ys


# ─────────────────────────────────────────────────────────────────────────────
# Plotting
# ─────────────────────────────────────────────────────────────────────────────

# Colour cycle for distinguishing multiple result series (print-safe)
_COLOURS = [
    '#1f77b4',  # blue
    '#d62728',  # red
    '#2ca02c',  # green
    '#ff7f0e',  # orange
    '#9467bd',  # purple
    '#8c564b',  # brown
    '#e377c2',  # pink
    '#7f7f7f',  # grey
]
_LINESTYLES = ['--', '-.', ':', (0, (3, 1, 1, 1))]


def plot_all(results: List[dict], out_path: str, title: str,
             show_success_number: bool = True) -> None:
    """
    Produce a figure with:
      Left  — Flatness graph (Wang et al. Algorithm 2 / Fig. 2a)
      Right — Success-number graph (Wang et al. Algorithm 1 / Fig. 2b)
              only shown if show_success_number=True and curves are available.
    """
    k        = results[0]['k']
    perf_xs, perf_ys = perfect_flatness(k)

    has_curves = show_success_number and any(r['success_curve'] for r in results)
    ncols = 2 if has_curves else 1
    fig, axes = plt.subplots(1, ncols, figsize=(7 * ncols, 5))
    if ncols == 1:
        axes = [axes]
    ax_flat = axes[0]
    ax_sn   = axes[1] if has_curves else None

    # ── Flatness graph ────────────────────────────────────────────────────────
    ax_flat.plot(perf_xs, perf_ys, '-', color='black', linewidth=1.5,
                 label='Random guessing baseline', zorder=10)

    for idx, res in enumerate(results):
        colour    = _COLOURS[idx % len(_COLOURS)]
        lstyle    = _LINESTYLES[idx % len(_LINESTYLES)]
        eps       = res['epsilon']
        xs, ys    = flatness_cdf(res['flatness_ranks'], res['k'])
        label     = f"{res['label']}  (ε={eps:.3f})"
        ax_flat.plot(xs, ys, linestyle=lstyle, color=colour,
                     linewidth=2.0, label=label)

    ax_flat.set_xlabel('Sweetword login attempts', fontsize=11)
    ax_flat.set_ylabel('Success rate', fontsize=11)
    ax_flat.set_title('Flatness Graph  (Wang et al. Fig. 2a)', fontsize=11)
    ax_flat.set_xlim(1, k)
    ax_flat.set_ylim(0.0, 1.05)
    ax_flat.xaxis.set_major_locator(ticker.MultipleLocator(max(1, k // 10)))
    ax_flat.grid(True, alpha=0.3)
    ax_flat.legend(loc='lower right', prop={'size': 8}, frameon=False)

    # ── Success-number graph ──────────────────────────────────────────────────
    if ax_sn is not None:
        # Determine x-axis range from available curves
        max_fail = max(
            (c[-1][0] for r in results for c in [r['success_curve']] if c),
            default=10_000,
        )
        n_users = results[0]['n_users']
        pf_xs, pf_ys = perfect_success_number(n_users, k, max_fail)
        ax_sn.plot(pf_xs, pf_ys, '-', color='black', linewidth=1.5,
                   label='Perfect method', zorder=10)

        for idx, res in enumerate(results):
            if not res['success_curve']:
                continue
            colour = _COLOURS[idx % len(_COLOURS)]
            lstyle = _LINESTYLES[idx % len(_LINESTYLES)]
            fs     = [f for f, _ in res['success_curve']]
            ss     = [s for _, s in res['success_curve']]
            ax_sn.plot(fs, ss, linestyle=lstyle, color=colour,
                       linewidth=2.0, label=res['label'])

        ax_sn.set_xscale('log')
        ax_sn.set_yscale('log')
        ax_sn.set_xlabel('Failed honeyword login attempts', fontsize=11)
        ax_sn.set_ylabel('Successful real-password logins', fontsize=11)
        ax_sn.set_title('Success-Number Graph  (Wang et al. Fig. 2b)', fontsize=11)
        ax_sn.grid(True, which='both', alpha=0.3)
        ax_sn.legend(loc='lower right', prop={'size': 8}, frameon=False)

    # ── Overall title ─────────────────────────────────────────────────────────
    fig.suptitle(title, fontsize=12, y=1.01)
    plt.tight_layout()

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"  Saved -> {out}")


# ─────────────────────────────────────────────────────────────────────────────
# Helper: save list-model attacker results as JSON
# (call this from attack_evolving_db.py / attack_fixed_db.py after a run)
# ─────────────────────────────────────────────────────────────────────────────

def save_list_model_results(ranks: List[int], curve: List[Tuple[int, int]],
                             k: int, label: str, out_path: str) -> None:
    """
    Save results from attack_evolving_db.py / attack_fixed_db.py to JSON
    so plot_results.py can load them.

    Call from your attacker scripts after run_full() or run_demo():

        from plot_results import save_list_model_results
        save_list_model_results(ranks, curve, k=args.k,
                                label='rockyou [list-evolving]',
                                out_path='outputs/evolving_db_rockyou.json')
    """
    epsilon = sum(1 for r in ranks if r == 1) / len(ranks) if ranks else 0.0
    data = {
        'label':         label,
        'k':             k,
        'epsilon':       epsilon,
        'ranks':         ranks,
        'success_curve': [[f, s] for f, s in curve],
        'n_users':       len(ranks),
    }
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"  Results saved -> {out_path}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Plot flatness and success-number graphs from attacker JSON results.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument('--files', nargs='+', required=True,
                   help='One or more JSON result files to plot.')
    p.add_argument('--out',   type=str, default='outputs/plot.png',
                   help='Output PNG path.')
    p.add_argument('--title', type=str, default='Honeyword Security Evaluation',
                   help='Plot title.')
    p.add_argument('--no-success-number', action='store_true',
                   help='Only plot the flatness graph (skip success-number).')
    return p.parse_args()


def main():
    args    = parse_args()
    results = []

    for path in args.files:
        if not Path(path).exists():
            print(f"  [WARN] File not found: {path} — skipping.")
            continue
        try:
            res = load_result(path)
            results.append(res)
            print(f"  Loaded: {path}  "
                  f"(label='{res['label']}', k={res['k']}, "
                  f"ε={res['epsilon']:.4f}, n={res['n_users']})")
        except (ValueError, KeyError) as e:
            print(f"  [WARN] Could not parse {path}: {e} — skipping.")

    if not results:
        sys.exit("No valid result files loaded.")

    # Warn if k values differ across files
    ks = {r['k'] for r in results}
    if len(ks) > 1:
        print(f"  [WARN] Mixed k values across files: {ks}. "
              "Using k from first file for perfect-line calculation.")

    plot_all(
        results,
        out_path=args.out,
        title=args.title,
        show_success_number=not args.no_success_number,
    )


if __name__ == '__main__':
    main()