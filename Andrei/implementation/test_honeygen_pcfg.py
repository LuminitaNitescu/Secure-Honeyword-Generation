from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
import random
from typing import Iterable, List, Optional

# Make Christos's implementation importable.
_CHRISTOS_PATH = str(Path(__file__).resolve().parent.parent.parent / "Christos" / "implementation")
if _CHRISTOS_PATH not in sys.path:
    sys.path.insert(0, _CHRISTOS_PATH)

from attackers.normalized_top_pw import SweetwordList
from attackers.normalized_top_pw_hg import NormalizedTopPWModelHG
from config import DEFAULT_K, DEFAULT_L, DEFAULT_MODEL_PATH, DEFAULT_SEED
from utils.embedding import FastTextBackend
from hgt import HoneywordGenerator
from statistics import (
	HoneygenStats,
	compute_attack_success_rate,
	compute_cracked_by_t1,
	write_stats_json,
)

from pcfg import PCFGModel
from legacy_pcfg_master.python_pcfg_cracker_version3.pcfg_trainer_logic.training_data import TrainingData
from legacy_pcfg_master.python_pcfg_cracker_version3.pcfg_trainer_logic.ret_types import RetType

try:
	from tqdm import tqdm
	TQDM_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
	tqdm = None
	TQDM_AVAILABLE = False


DATASET_MAP = {
	"hashmob_counts": "data/hashmob_counts.txt"
}
DATASET_SIZE_MAP = {
	"hashmob_counts": 23_136_055_988,
}

DEFAULT_TARGET_DATASET = "data/50k_subsample/rockyou_sorted_preprocessed.txt"
DEFAULT_PCFG_RULE_NAME = "RockYouFinal"


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="PCFG honeyword generation + attack evaluation")
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
	parser.add_argument(
		"--rule-name",
		type=str,
		default=DEFAULT_PCFG_RULE_NAME,
		help="PCFG rule set name (default: %(default)s)",
	)
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
		default="honeygen_pcfg",
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


def progress_iter(iterable: Iterable, desc: str, enabled: bool) -> Iterable:
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


def compute_structures(passwords: List[str], progress: bool = False) -> dict:
	"""Parse each password through the PCFG trainer to extract its structure."""
	print("Computing PCFG structures...")
	training_results = TrainingData(targeted=False)
	for i, password in enumerate(
		progress_iter(passwords, "Parsing structures", progress)
	):
		ret = training_results.parse([password])
		if ret != RetType.STATUS_OK:
			continue
		if (i + 1) % 10_000 == 0:
			print(f"  {i + 1:,} passwords parsed.")
	return training_results.structure_dict


def build_generator(
	model_path: str,
	k: int,
	l: int,
	seed: int,
	pcfg_model: PCFGModel,
	pcfg_structures: dict,
) -> HoneywordGenerator:
	backend = FastTextBackend(model_path)
	return HoneywordGenerator(
		backend=backend,
		k=k,
		l=l,
		seed=seed,
		pcfg_model=pcfg_model,
		pcfg_structures=pcfg_structures,
	)


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
	rule_name: str,
	limit: Optional[int],
) -> Path:
	limit_tag = "all" if limit is None else str(limit)
	stem = target_path.stem
	name = f"sweetwords_pcfg_{stem}_k{k}_l{l}_seed{seed}_rule{rule_name}_limit{limit_tag}.jsonl"
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

	# Structures must be computed before building the generator so the
	# filtered KNN step knows which neighbors are PCFG-parseable.
	pcfg_structures = compute_structures(passwords, progress=progress_enabled)

	print(f"Loading PCFG model (rule: {args.rule_name})...")
	pcfg_model = PCFGModel()
	pcfg_model.load_data(rule_name=args.rule_name)

	print("Loading fastText model...")
	generator = build_generator(
		args.model_path,
		args.k,
		args.l,
		args.seed,
		pcfg_model,
		pcfg_structures,
	)

	cache_enabled = not args.no_cache
	cache_file = cache_path(
		args.cache_dir,
		target_path,
		args.k,
		args.l,
		args.seed,
		args.rule_name,
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
	attacker = NormalizedTopPWModelHG(
		db_path=DATASET_MAP[args.attacker_dataset],
		dataset_size=DATASET_SIZE_MAP.get(args.attacker_dataset, 50_000),
	)

	print("Running attacker analysis...")
	attack_stats, flatness_graph, epsilon_flatness = attacker.analyze(
		sweetword_lists,
		k=args.k,
		t1=args.t1,
		t2=args.t2,
		show_progress=progress_enabled,
	)
	cracked_by_t1 = compute_cracked_by_t1(flatness_graph, args.k)

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
	target_dataset_name = target_path.stem.replace("_sorted_preprocessed", "")
	base_name = f"pcfg_{target_dataset_name}_k{args.k}_t1{args.t1}_t2{args.t2}_seed{args.seed}_rule{args.rule_name}"
	output_path = outputs_dir / f"{base_name}.json"
	write_stats_json(stats, str(output_path))


if __name__ == "__main__":
	main()
