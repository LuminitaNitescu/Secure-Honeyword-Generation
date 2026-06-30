from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate honeyword evaluation graphs and a LaTeX metrics table"
    )
    parser.add_argument(
        "--folders",
        nargs="+",
        required=True,
        help="One or more directories containing stats JSON files",
    )
    parser.add_argument(
        "--k",
        type=int,
        required=True,
        help="Number of sweetwords per list",
    )
    parser.add_argument(
        "--out-dir",
        type=str,
        default="graphs",
        help="Output directory for all generated files",
    )
    return parser.parse_args()


def load_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def flatness_curve(flatness_graph: List[int], k: int) -> List[float]:
    """P(real password found within t guesses) for t = 1..k, using per-user rank data."""
    arr = np.array(flatness_graph)
    n = len(arr)
    if n == 0:
        return []
    return [float((arr <= t).sum() / n) for t in range(1, k + 1)]


def success_number_points(
    success_stats: dict,
) -> Optional[Tuple[List[int], List[int]]]:
    """Raw success-number campaign: (failed logins, successful logins) pairs.

    This is the population-wide curve produced by the global guessing attack:
    x = total honeyword logins (alarms raised), y = total real-password logins.
    """
    if not success_stats:
        return None
    curve = success_stats.get("success_curve")
    if not curve:
        return None
    failures = [int(pt[0]) for pt in curve]
    successes = [int(pt[1]) for pt in curve]
    return failures, successes


def normalize_success_points(
    pts: Optional[Tuple[List[int], List[int]]], total_users: int
) -> Optional[Tuple[List[float], List[float]]]:
    """Normalize a success-number curve by total_users.

    Dividing both axes by total_users makes curves from different population
    sizes (e.g. 50 k vs 10 k) directly comparable:
      x = honeyword hits per user, y = fraction of users cracked.
    """
    if not pts or total_users <= 0:
        return None
    xs, ys = pts
    return [x / total_users for x in xs], [y / total_users for y in ys]


def linear_baseline(k: int) -> List[float]:
    return [t / k for t in range(1, k + 1)]


def mean_of_curves(curves: List[List[float]]) -> List[float]:
    if not curves:
        return []
    return list(np.mean(np.array(curves), axis=0))


def load_folder_data(folder: Path, k: int) -> Dict[str, dict]:
    results: Dict[str, dict] = {}
    for path in sorted(folder.glob("*.json")):
        data = load_json(path)
        flat_list: List[int] = data.get("flatness_graph", [])
        # "success_number" holds the full campaign that runs until every user is
        # cracked; "attack_stats" is a truncated campaign and only used as a
        # fallback for older JSONs that predate the success_number field.
        success_stats: dict = data.get("success_number") or data.get("attack_stats", {})
        total_users: int = success_stats.get("total_users", len(flat_list))
        succ_points = success_number_points(success_stats)

        results[path.stem] = {
            "flatness_curve": flatness_curve(flat_list, k) if flat_list else None,
            "success_points": succ_points,
            "norm_success_points": normalize_success_points(succ_points, total_users),
            "total_users": total_users,
            "epsilon_flatness": data.get("epsilon_flatness"),
            "attack_success_rate": data.get("attack_success_rate"),
        }
    return results


def _save_fig(fig: plt.Figure, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Saved {out_path}")


def plot_graph(
    named_curves: Dict[str, Optional[List[float]]],
    k: int,
    xlabel: str,
    ylabel: str,
    title: str,
    out_path: Path,
    baseline: Optional[List[float]] = None,
) -> None:
    x = list(range(1, k + 1))
    fig, ax = plt.subplots(figsize=(8, 5))

    for label, curve in named_curves.items():
        if curve:
            ax.plot(x[: len(curve)], curve, label=label, linewidth=1.5)

    if baseline:
        ax.plot(
            x,
            baseline,
            label="Linear baseline",
            linestyle="--",
            color="black",
            linewidth=1.2,
            alpha=0.7,
        )

    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.set_xlim(1, k)
    ax.set_ylim(0.0, 1.0)
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=8)
    _save_fig(fig, out_path)


def plot_success_number(
    named_points: Dict[str, Optional[Tuple[List[float], List[float]]]],
    title: str,
    out_path: Path,
    k: Optional[int] = None,
    xlabel: str = "Failed login attempts (honeyword hits / alarms)",
    ylabel: str = "Successful login attempts (real passwords found)",
    ylim: Optional[Tuple[float, float]] = None,
) -> None:
    """Success-number graph: successful logins (y) vs failed logins (x).

    Each guess across the whole user population is played in global confidence
    order; a success is a real-password login, a failure is a honeyword login.
    """
    fig, ax = plt.subplots(figsize=(8, 5))

    max_x = 0.0
    for label, pts in named_points.items():
        if not pts:
            continue
        xs, ys = pts
        if not xs:
            continue
        ax.plot(xs, ys, label=label, linewidth=1.5)
        max_x = max(max_x, xs[-1])

    # Ideal flat HGT: every sweetword equally likely to be real, so in the
    # worst-case campaign each success costs (k-1) failures -> slope 1/(k-1).
    if k and k > 1 and max_x > 0:
        ax.plot(
            [0, max_x],
            [0, max_x / (k - 1)],
            label=f"Ideal flat HGT (slope 1/(k-1)={1 / (k - 1):.3f})",
            linestyle="--",
            color="black",
            linewidth=1.2,
            alpha=0.7,
        )

    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.set_xlim(left=0)
    if ylim is not None:
        ax.set_ylim(*ylim)
    else:
        ax.set_ylim(bottom=0)
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=8)
    _save_fig(fig, out_path)


def mean_success_curve(
    curves: List[Tuple[List[float], List[float]]], num_points: int = 200
) -> Optional[Tuple[List[float], List[float]]]:
    """Average several (x, y) success-number curves onto a common x grid.

    Curves differ in length and range, so each is interpolated (monotone step
    via np.interp) onto a shared x grid before averaging.
    """
    curves = [(xs, ys) for xs, ys in curves if xs and ys]
    if not curves:
        return None
    max_x = max(xs[-1] for xs, _ in curves)
    if max_x <= 0:
        return None
    grid = np.linspace(0.0, max_x, num_points)
    stacked = np.array([np.interp(grid, xs, ys) for xs, ys in curves])
    return list(grid), list(stacked.mean(axis=0))


def make_latex_table(
    folder_metrics: Dict[str, Tuple[Optional[float], Optional[float]]]
) -> str:
    rows = []
    for folder_name, (eps, asr) in sorted(folder_metrics.items()):
        eps_str = f"{eps:.4f}" if eps is not None else "N/A"
        asr_str = f"{asr * 100:.4f}\\%" if asr is not None else "N/A"
        rows.append(f"  {folder_name} & {eps_str} & {asr_str} \\\\")

    return "\n".join(
        [
            r"\begin{table}[h]",
            r"\centering",
            r"\caption{Average Evaluation Metrics per Method}",
            r"\label{tab:honeyword-metrics}",
            r"\begin{tabular}{lcc}",
            r"\hline",
            r"Method & $\varepsilon$-Flatness $\downarrow$ & Mean Attack Success (\%) $\downarrow$ \\",
            r"\hline",
            *rows,
            r"\hline",
            r"\end{tabular}",
            r"\end{table}",
        ]
    )


def main() -> None:
    args = parse_args()
    out_dir = Path(args.out_dir)
    k = args.k
    baseline = linear_baseline(k)

    per_folder_avg: Dict[str, dict] = {}

    for folder_str in args.folders:
        folder = Path(folder_str)
        if not folder.is_dir():
            print(f"Warning: skipping missing folder: {folder}")
            continue

        folder_name = folder.name
        data = load_folder_data(folder, k)
        if not data:
            print(f"Warning: no JSON files in {folder}")
            continue

        print(f"\n=== {folder_name} ({len(data)} files) ===")

        # Per-folder graphs: one line per dataset file
        plot_graph(
            {stem: m["flatness_curve"] for stem, m in data.items()},
            k,
            xlabel="Number of sweetword attempts (t)",
            ylabel="Fraction of users with real password guessed",
            title=f"Flatness Graph — {folder_name}",
            out_path=out_dir / folder_name / "flatness.png",
            baseline=baseline,
        )

        # Success-number graph: raw successful vs failed logins, one line per file.
        plot_success_number(
            {stem: m["success_points"] for stem, m in data.items()},
            title=f"Success-Number Graph — {folder_name}",
            out_path=out_dir / folder_name / "success_number.png",
            k=k,
        )

        valid_flat = [m["flatness_curve"] for m in data.values() if m["flatness_curve"] is not None]
        valid_succ = [m["success_points"] for m in data.values() if m["success_points"]]
        valid_norm_succ = [m["norm_success_points"] for m in data.values() if m["norm_success_points"]]
        valid_eps = [m["epsilon_flatness"] for m in data.values() if m["epsilon_flatness"] is not None]
        valid_asr = [m["attack_success_rate"] for m in data.values() if m["attack_success_rate"] is not None]

        per_folder_avg[folder_name] = {
            "flatness_curve": mean_of_curves(valid_flat),
            # Raw failed/successful login counts, averaged across datasets per method.
            "success_curve": mean_success_curve(valid_succ),
            # Normalized curves (both axes / total_users) — comparable across population sizes.
            "norm_success_curve": mean_success_curve(valid_norm_succ),
            "epsilon_flatness": float(np.mean(valid_eps)) if valid_eps else None,
            "attack_success_rate": float(np.mean(valid_asr)) if valid_asr else None,
        }

    if not per_folder_avg:
        print("No valid data found — exiting.")
        return

    print("\n=== Aggregate graphs ===")

    # Mean flatness graph: one line per folder
    plot_graph(
        {name: stats["flatness_curve"] for name, stats in per_folder_avg.items()},
        k,
        xlabel="Number of sweetword attempts (t)",
        ylabel="Fraction of users with real password guessed",
        title="Mean Flatness Graph (averaged across datasets per method)",
        out_path=out_dir / "mean_flatness.png",
        baseline=baseline,
    )

    # Mean success-number graph: one line per folder (raw counts, averaged across datasets).
    plot_success_number(
        {name: stats["success_curve"] for name, stats in per_folder_avg.items()},
        title="Mean Success-Number (averaged across datasets per method)",
        out_path=out_dir / "mean_success_number.png",
        k=k,
    )

    # Normalized mean success-number graph: axes divided by total_users so methods
    # with different population sizes (e.g. 50 k vs 10 k) are directly comparable.
    plot_success_number(
        {name: stats["norm_success_curve"] for name, stats in per_folder_avg.items()},
        title="Norm Mean Success-Number",
        out_path=out_dir / "mean_success_number_normalized.png",
        k=k,
        xlabel="Honeyword hits (alarms) per user",
        ylabel="Fraction of users cracked",
        ylim=(0.0, 1.0),
    )

    # LaTeX table
    latex = make_latex_table(
        {
            name: (stats["epsilon_flatness"], stats["attack_success_rate"])
            for name, stats in per_folder_avg.items()
        }
    )
    table_path = out_dir / "metrics_table.tex"
    table_path.parent.mkdir(parents=True, exist_ok=True)
    table_path.write_text(latex, encoding="utf-8")
    print(f"Saved {table_path}")
    print("\nLaTeX table:\n")
    print(latex)
    print(
        "\nNote: HWSimilarity and False-Alarm Rate are not present in the output JSONs"
        " and have been omitted from the table."
    )


if __name__ == "__main__":
    main()
