from __future__ import annotations

from dataclasses import dataclass, asdict
import json
from typing import Iterable, List, Optional

from attackers.normalized_top_pw import AttackStats, NormalizedTopPWModel, SweetwordList


@dataclass
class HoneygenStats:
	epsilon_flatness: float
	attack_success_rate: float
	flatness_graph: List[int]
	attack_stats: Optional[dict] = None


def _base_prob(attacker: NormalizedTopPWModel, word: str) -> float:
	count = attacker.counts.get(word, 0)
	if count > 0 and attacker.dataset_size > 0:
		return count / attacker.dataset_size
	if attacker.smoothing == "plus_one":
		return 1.0 / (attacker.dataset_size + 1)
	return 0.0


def compute_epsilon_flatness(
	sweetword_lists: Iterable[SweetwordList],
	attacker: NormalizedTopPWModel,
	k: int,
) -> float:
	max_prob = 0.0
	for entry in sweetword_lists:
		if entry.real_password is None:
			continue
		base_probs = [_base_prob(attacker, word) for word in entry.sweetwords]
		total = sum(base_probs)
		if total <= 0:
			prob = 1.0 / k
		else:
			real_idx = entry.sweetwords.index(entry.real_password)
			prob = base_probs[real_idx] / total
		if prob > max_prob:
			max_prob = prob
	return max_prob


def compute_attack_success_rate(stats: AttackStats) -> float:
	return stats.cracked_percent / 100.0


def write_stats_json(stats: HoneygenStats, output_path: str) -> None:
	with open(output_path, "w", encoding="utf-8") as handle:
		json.dump(asdict(stats), handle, indent=2)
