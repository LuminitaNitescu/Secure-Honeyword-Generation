from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable, List, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Plot flatness graph vs linear baseline")
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
	parser.add_argument(
		"--use-cracked-by-t1",
		action="store_true",
		help="Plot normalized cracked_by_t1 if present",
	)
	return parser.parse_args()


def load_payload(path: str) -> dict:
	with open(path, "r", encoding="utf-8") as handle:
		return json.load(handle)


def load_flatness_list(payload: dict) -> List[int]:
	flatness = payload.get("flatness_graph")
	if not isinstance(flatness, list):
		raise ValueError("flatness_graph missing or invalid in stats JSON.")
	return [int(value) for value in flatness]


def load_cracked_by_t1(payload: dict) -> List[int]:
	cracked = payload.get("cracked_by_t1")
	if not isinstance(cracked, list):
		raise ValueError("cracked_by_t1 missing or invalid in stats JSON.")
	return [int(value) for value in cracked]


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


def normalized_curve(cracked_by_t1: Iterable[int], total_users: int) -> List[Tuple[int, float]]:
	items = list(cracked_by_t1)
	if not items or total_users <= 0:
		return []
	results: List[Tuple[int, float]] = []
	for idx, count in enumerate(items, start=1):
		results.append((idx, min(1.0, count / total_users)))
	return results


def linear_baseline(k: int) -> List[Tuple[int, float]]:
	return [(t, min(1.0, t / k)) for t in range(1, k + 1)]


def plot_flatness(
	curves: List[Tuple[str, List[Tuple[int, float]]]],
	k: int,
	out_path: str,
	title: str,
) -> None:
	baseline = linear_baseline(k)
	if not curves:
		raise ValueError("No valid flatness curves to plot.")

	fig, ax = plt.subplots(figsize=(8, 5))
	base_x, base_y = zip(*baseline)
	for label, curve in curves:
		if not curve:
			continue
		curve_x, curve_y = zip(*curve)
		ax.plot(curve_x, curve_y, label=label, linewidth=2)

	ax.plot(base_x, base_y, label="Linear baseline", linestyle="--")
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
	mean_eps_flatness = 0.0
	for stats_path in json_files:
		payload = load_payload(str(stats_path))
		eps_flatness = payload.get("epsilon_flatness")
		if isinstance(eps_flatness, (int, float)):
			mean_eps_flatness += eps_flatness
	mean_eps_flatness /= len(json_files)
	print(f"Mean epsilon flatness across {len(json_files)} files: {mean_eps_flatness:.4f}")
	curves: List[Tuple[str, List[Tuple[int, float]]]] = []
	for stats_path in json_files:
		payload = load_payload(str(stats_path))
		try:
			if args.use_cracked_by_t1:
				cracked_by_t1 = load_cracked_by_t1(payload)
				total_users = payload.get("attack_stats", {}).get("total_users")
				if not isinstance(total_users, int):
					flatness_list = load_flatness_list(payload)
					total_users = len(flatness_list)
				curve = normalized_curve(cracked_by_t1, total_users)
				k = len(cracked_by_t1)
			else:
				flatness_list = load_flatness_list(payload)
				curve = success_curve(flatness_list, args.k)
				k = args.k
		except ValueError:
			continue
		curves.append((stats_path.stem, curve))

	if args.use_cracked_by_t1 and curves:
		k = max(len(curve) for _, curve in curves)
		plot_flatness(curves, k, args.out, args.title)
		print(f"Saved flatness graph to {args.out}")
		return

	plot_flatness(curves, args.k, args.out, args.title)
	print(f"Saved flatness graph to {args.out}")


if __name__ == "__main__":
	main()
