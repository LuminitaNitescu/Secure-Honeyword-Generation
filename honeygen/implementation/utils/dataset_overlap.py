#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable, Set


def load_dataset(path: str, casefold: bool) -> Set[str]:
	values: Set[str] = set()
	with open(path, "r", encoding="utf-8") as handle:
		for line in handle:
			item = line.strip()
			if not item:
				continue
			values.add(item.casefold() if casefold else item)
	return values


def jaccard(a: Set[str], b: Set[str]) -> float:
	if not a and not b:
		return 0.0
	return len(a & b) / len(a | b)


def main() -> None:
	parser = argparse.ArgumentParser(description="Compute overlap between two datasets")
	parser.add_argument("dataset_a", type=str, help="Path to first dataset")
	parser.add_argument("dataset_b", type=str, help="Path to second dataset")
	parser.add_argument(
		"--casefold",
		action="store_true",
		help="Case-insensitive comparison",
	)
	args = parser.parse_args()

	path_a = Path(args.dataset_a)
	path_b = Path(args.dataset_b)
	if not path_a.exists():
		raise FileNotFoundError(f"Dataset not found: {path_a}")
	if not path_b.exists():
		raise FileNotFoundError(f"Dataset not found: {path_b}")

	set_a = load_dataset(str(path_a), args.casefold)
	set_b = load_dataset(str(path_b), args.casefold)

	intersection = set_a & set_b
	print(f"A size: {len(set_a)}")
	print(f"B size: {len(set_b)}")
	print(f"Overlap: {len(intersection)}")
	print(f"Jaccard: {jaccard(set_a, set_b):.6f}")


if __name__ == "__main__":
	main()
