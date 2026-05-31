from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
import random
from typing import Iterable, List, Optional

from attackers.normalized_top_pw import NormalizedTopPWModel, SweetwordList
from attackers.normalized_top_pw_hg import NormalizedTopPWModelHG
from config import DEFAULT_K, DEFAULT_L, DEFAULT_MODEL_PATH, DEFAULT_SEED
from utils.embedding import FastTextBackend
from hgt import HoneywordGenerator
from statistics import (
	HoneygenStats,
	compute_attack_success_rate,
	compute_cracked_by_t1,
	compute_epsilon_flatness,
	write_stats_json,
)

try:
	from tqdm import tqdm
	TQDM_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
	tqdm = None
	TQDM_AVAILABLE = False


DATASET_MAP = {
	"chegg-com": "data/50k_subsample/chegg-com_sorted_preprocessed.txt",
	"dropbox": "data/50k_subsample/dropbox_sorted_preprocessed.txt",
	"linkedin": "data/50k_subsample/linkedin_sorted_preprocessed.txt",
	"yahoo": "data/50k_subsample/yahoo_sorted_preprocessed.txt",
	"phpbb2": "data/50k_subsample/phpbb2_sorted_preprocessed.txt",
	"phpbb": "data/50k_subsample/phpbb_sorted_preprocessed.txt",
	"weakpass_4a": "data/weakpass_4a.policy.txt",
	"weakpass_4": "data/weakpass_4.policy.txt",
	"zxcvbn": "data/dropbox_zxcvbn.txt",
	"phpbb_counts": "data/phpbb_counts.txt",
}

DEFAULT_TARGET_DATASET = "data/50k_subsample/rockyou_sorted_preprocessed.txt"


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Honeyword generation + attack evaluation")
	parser.add_argument(
		"--target-dataset",
		type=str,
		default=DEFAULT_TARGET_DATASET,
		help="Path to target password dataset (default: rockyou)",
	)
	parser.add_argument(
		"--attacker-dataset",
		choices=sorted(list(DATASET_MAP.keys()) + ["all"]),
		required=True,
		help="Attacker dataset name",
	)
	parser.add_argument("--k", type=int, default=DEFAULT_K)
	parser.add_argument("--l", type=int, default=DEFAULT_L)
	parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
	parser.add_argument("--model-path", type=str, default=DEFAULT_MODEL_PATH)
	parser.add_argument("--t1", type=int, default=1)
	parser.add_argument("--t2", type=int, default=None)
	parser.add_argument(
		"--limit",
		type=int,
		default=None,
		help="Limit number of target passwords",
	)
	parser.add_argument(
		"--out-prefix",
		type=str,
		default="honeygen",
		help="Prefix for output files",
	)
	parser.add_argument(
		"--no-progress",
		action="store_true",
		help="Disable progress bars",
	)
	parser.add_argument(
		"--cache-dir",
		type=str,
		default="outputs",
		help="Directory to store cached sweetword lists",
	)
	parser.add_argument(
		"--no-cache",
		action="store_true",
		help="Disable sweetword list caching",
	)
	return parser.parse_args()


def progress_iter(iterable: Iterable[str], desc: str, enabled: bool) -> Iterable[str]:
	if not enabled or not TQDM_AVAILABLE:
		return iterable
	return tqdm(iterable, desc=desc, unit="item")


def load_passwords(
	path: str,
	limit: Optional[int] = None,
	progress: bool = False,
) -> List[str]:
	passwords: List[str] = []
	with open(path, "r", encoding="utf-8") as handle:
		for line in progress_iter(handle, "Loading passwords", progress):
			password = line.strip()
			if not password:
				continue
			passwords.append(password)
			if limit is not None and len(passwords) >= limit:
				break
	return passwords


def build_generator(model_path: str, k: int, l: int, seed: int) -> HoneywordGenerator:
	backend = FastTextBackend(model_path)
	return HoneywordGenerator(backend=backend, k=k, l=l, seed=seed)


def build_sweetword_lists(
	passwords: Iterable[str],
	generator: HoneywordGenerator,
	seed: int,
	progress: bool,
) -> List[SweetwordList]:
	rng = random.Random(seed)
	sweetword_lists: List[SweetwordList] = []
	for idx, password in enumerate(
		progress_iter(passwords, "Generating sweetwords", progress)
	):
		sweetwords = generator.generate(password)
		rng.shuffle(sweetwords)
		sweetword_lists.append(
			SweetwordList(
				user_id=str(idx),
				sweetwords=sweetwords,
				real_password=password,
			)
		)
	return sweetword_lists


def cache_path(
	cache_dir: str,
	target_path: Path,
	k: int,
	l: int,
	seed: int,
	limit: Optional[int],
) -> Path:
	limit_tag = "all" if limit is None else str(limit)
	stem = target_path.stem
	name = f"sweetwords_{stem}_k{k}_l{l}_seed{seed}_limit{limit_tag}.jsonl"
	return Path(cache_dir) / name


def load_cached_sweetwords(path: Path) -> List[SweetwordList]:
	entries: List[SweetwordList] = []
	with open(path, "r", encoding="utf-8") as handle:
		for line in handle:
			payload = json.loads(line)
			entries.append(
				SweetwordList(
					user_id=str(payload["user_id"]),
					sweetwords=list(payload["sweetwords"]),
					real_password=payload["real_password"],
				)
			)
	return entries


def save_cached_sweetwords(path: Path, entries: Iterable[SweetwordList]) -> None:
	path.parent.mkdir(parents=True, exist_ok=True)
	with open(path, "w", encoding="utf-8") as handle:
		for entry in entries:
			payload = {
				"user_id": entry.user_id,
				"real_password": entry.real_password,
				"sweetwords": entry.sweetwords,
			}
			handle.write(json.dumps(payload))
			handle.write("\n")


def clone_sweetword_lists(entries: Iterable[SweetwordList]) -> List[SweetwordList]:
	return [
		SweetwordList(
			user_id=entry.user_id,
			sweetwords=list(entry.sweetwords),
			real_password=entry.real_password,
		)
		for entry in entries
	]


def main() -> None:
	args = parse_args()

	target_path = Path(args.target_dataset)
	if not target_path.exists():
		raise FileNotFoundError(f"Target dataset not found: {target_path}")
	if args.attacker_dataset != "all":
		attacker_path = Path(DATASET_MAP[args.attacker_dataset])
		if not attacker_path.exists():
			raise FileNotFoundError(f"Attacker dataset not found: {attacker_path}")

	progress_enabled = not args.no_progress
	if progress_enabled and not TQDM_AVAILABLE:
		print("tqdm not installed; progress bars disabled.")
		progress_enabled = False

	print("Loading target dataset...")
	passwords = load_passwords(
		str(target_path),
		limit=args.limit,
		progress=progress_enabled,
	)
	if not passwords:
		raise ValueError("Target dataset is empty after filtering.")

	print("Loading fastText model...")
	generator = build_generator(args.model_path, args.k, args.l, args.seed)

	cache_enabled = not args.no_cache
	cache_file = cache_path(
		args.cache_dir,
		target_path,
		args.k,
		args.l,
		args.seed,
		args.limit,
	)
	if cache_enabled and cache_file.exists():
		print(f"Loading cached sweetwords: {cache_file}")
		sweetword_lists = load_cached_sweetwords(cache_file)
	else:
		print("Generating sweetwords...")
		sweetword_lists = build_sweetword_lists(
			passwords,
			generator,
			args.seed,
			progress=progress_enabled,
		)
		if cache_enabled:
			save_cached_sweetwords(cache_file, sweetword_lists)

	print("Training attacker model...")
	attacker = NormalizedTopPWModelHG() # NormalizedTopPWModel
	if args.attacker_dataset == "all":
		root = Path("data/50k_subsample")
		paths = sorted(
			path
			for path in root.glob("*_sorted_preprocessed.txt")
			if path.is_file() and "rockyou" not in path.name
		)
		if not paths:
			raise FileNotFoundError("No 50k_subsample datasets found for attacker training.")
		attacker.train_from_sorted_files(str(path) for path in paths)
	else:
		if "counts" in str(attacker_path):
			attacker.train_from_aggregates_file(str(attacker_path))
		else:
			attacker.train_from_file(str(attacker_path))

	print("Running attack simulation...")
	attack_lists = clone_sweetword_lists(sweetword_lists)
	attack_stats = attacker.crack(attack_lists, t1=args.t1, t2=args.t2)

	print("Computing flatness graph...")
	flatness_lists = clone_sweetword_lists(sweetword_lists)
	flatness_graph = attacker.flatness_graph(flatness_lists)
	cracked_by_t1 = compute_cracked_by_t1(flatness_graph, args.k)

	print("Computing epsilon-flatness...")
	epsilon_flatness = compute_epsilon_flatness(sweetword_lists, attacker, args.k)
	attack_success_rate = compute_attack_success_rate(attack_stats)

	stats = HoneygenStats(
		epsilon_flatness=epsilon_flatness,
		attack_success_rate=attack_success_rate,
		flatness_graph=flatness_graph,
		cracked_by_t1=cracked_by_t1,
		attack_stats=asdict(attack_stats),
	)

	outputs_dir = Path("outputs")
	outputs_dir.mkdir(parents=True, exist_ok=True)
	base_name = f"{args.out_prefix}_{args.attacker_dataset}_k{args.k}_l{args.l}"
	output_path = outputs_dir / f"{base_name}.json"
	write_stats_json(stats, str(output_path))

	#print(json.dumps(asdict(stats), indent=2))


if __name__ == "__main__":
	main()
