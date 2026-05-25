from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable, List, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Plot flatness graph vs random baseline")
	parser.add_argument(
		"--inputs-dir",
		type=str,
		default="outputs",
		help="Directory containing stats JSON files",
	)
	parser.add_argument(
		"--k",
		type=int,
		required=True,
		help="Number of sweetwords per list",
	)
	parser.add_argument(
		"--out",
		type=str,
		default="outputs/flatness_graph.png",
		help="Output PNG path",
	)
	parser.add_argument(
		"--title",
		type=str,
		default="Flatness graph",
		help="Plot title",
	)
	return parser.parse_args()


def load_flatness_list(path: str) -> List[int]:
	with open(path, "r", encoding="utf-8") as handle:
		payload = json.load(handle)
	flatness = payload.get("flatness_graph")
	if not isinstance(flatness, list):
		raise ValueError("flatness_graph missing or invalid in stats JSON.")
	return [int(value) for value in flatness]


def success_curve(attempts: Iterable[int], k: int) -> List[Tuple[int, float]]:
	items = list(attempts)
	if not items:
		return []
	max_attempts = min(k, max(items))
	results: List[Tuple[int, float]] = []
	for t in range(1, max_attempts + 1):
		count = sum(1 for value in items if value <= t)
		results.append((t, count / len(items)))
	return results


def random_baseline(k: int) -> List[Tuple[int, float]]:
	return [(t, min(1.0, t / k)) for t in range(1, k + 1)]


def plot_flatness(
	curves: List[Tuple[str, List[Tuple[int, float]]]],
	k: int,
	out_path: str,
	title: str,
) -> None:
	baseline = random_baseline(k)
	if not curves:
		raise ValueError("No valid flatness curves to plot.")

	fig, ax = plt.subplots(figsize=(8, 5))
	base_x, base_y = zip(*baseline)
	for label, curve in curves:
		if not curve:
			continue
		curve_x, curve_y = zip(*curve)
		ax.plot(curve_x, curve_y, label=label, linewidth=2)

	ax.plot(base_x, base_y, label="Random baseline", linestyle="--")
	ax.set_xlabel("Sweetword login attempts")
	ax.set_ylabel("Success rate")
	ax.set_title(title)
	ax.set_xlim(1, k)
	ax.set_ylim(0.0, 1.0)
	ax.grid(True, alpha=0.3)
	ax.legend()

	output = Path(out_path)
	output.parent.mkdir(parents=True, exist_ok=True)
	fig.tight_layout()
	fig.savefig(output, dpi=150)
	plt.close(fig)


def main() -> None:
	args = parse_args()
	inputs_dir = Path(args.inputs_dir)
	if not inputs_dir.exists():
		raise FileNotFoundError(f"Inputs directory not found: {inputs_dir}")

	json_files = sorted(inputs_dir.glob("*.json"))
	if not json_files:
		raise ValueError(f"No JSON files found in {inputs_dir}")

	curves: List[Tuple[str, List[Tuple[int, float]]]] = []
	for stats_path in json_files:
		try:
			flatness_list = load_flatness_list(str(stats_path))
		except ValueError:
			continue
		curve = success_curve(flatness_list, args.k)
		curves.append((stats_path.stem, curve))

	plot_flatness(curves, args.k, args.out, args.title)
	print(f"Saved flatness graph to {args.out}")


if __name__ == "__main__":
	main()
