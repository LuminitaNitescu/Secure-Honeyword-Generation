from __future__ import annotations

from dataclasses import dataclass, field
import heapq
from math import inf
from typing import Dict, Iterable, List, Optional, Tuple


ProbabilityMap = Dict[str, float]


@dataclass
class SweetwordList:
	user_id: str
	sweetwords: List[str]
	real_password: Optional[str] = None
	num_failure: int = 0
	attempted: set[str] = field(default_factory=set)
	_index: Dict[str, int] = field(init=False, repr=False)

	def __post_init__(self) -> None:
		self._index = {word: idx for idx, word in enumerate(self.sweetwords)}

	def remaining(self) -> List[str]:
		return [word for word in self.sweetwords if word not in self.attempted]


@dataclass
class AttackStats:
	total_users: int
	cracked_users: int
	cracked_percent: float
	total_guesses: int
	failed_guesses: int
	successful_guesses: int
	mean_guesses_to_crack: float
	mean_failures_before_crack: float
	success_curve: List[Tuple[int, int]]


class NormalizedTopPWModel:
	def __init__(self, smoothing: str = "plus_one") -> None:
		self.pd: ProbabilityMap = {}
		self.total_count = 0
		self.smoothing = smoothing

	def train(self, leaked_passwords: Iterable[str]) -> None:
		counts: Dict[str, int] = {}
		total = 0
		for password in leaked_passwords:
			password = password.strip()
			if not password:
				continue
			counts[password] = counts.get(password, 0) + 1
			total += 1
		self.total_count = total
		if total == 0:
			self.pd = {}
			return
		self.pd = {password: count / total for password, count in counts.items()}

	def train_from_file(self, path: str) -> None:
		with open(path, "r", encoding="utf-8") as handle:
			self.train(handle)

	def _base_prob(self, word: str) -> float:
		if word in self.pd:
			return self.pd[word]
		if self.smoothing == "plus_one" and self.total_count > 0:
			return 1.0 / (self.total_count + 1)
		return 0.0

	def _get_sweetword(self, entry: SweetwordList) -> Tuple[float, Optional[str]]:
		remaining = entry.remaining()
		if not remaining:
			return 0.0, None
		base_probs = {word: self._base_prob(word) for word in remaining}
		denom = sum(base_probs.values())
		if denom <= 0:
			return 0.0, None
		best = max(
			remaining,
			key=lambda word: (base_probs[word], -entry._index.get(word, 0)),
		)
		return base_probs[best] / denom, best

	def crack(
		self,
		sweetword_lists: Iterable[SweetwordList],
		t1: int = 1,
		t2: Optional[int] = None,
	) -> AttackStats:
		max_failures = inf if t2 is None else max(0, t2)
		queue: List[Tuple[float, int, SweetwordList, str]] = []
		insert_counter = 0
		num_failure = 0
		num_success = 0
		success_curve: List[Tuple[int, int]] = []
		crack_guesses: List[int] = []
		crack_failures: List[int] = []

		real_map = {
			entry.user_id: entry.real_password
			for entry in sweetword_lists
			if entry.real_password is not None
		}

		for entry in sweetword_lists:
			priority, word = self._get_sweetword(entry)
			if word is None:
				continue
			heapq.heappush(queue, (-priority, insert_counter, entry, word))
			insert_counter += 1

		while queue and num_failure < max_failures:
			_, _, entry, word = heapq.heappop(queue)
			if entry.num_failure >= t1:
				continue
			if word in entry.attempted:
				continue
			entry.attempted.add(word)

			success = real_map.get(entry.user_id) == word
			if success:
				num_success += 1
				crack_guesses.append(entry.num_failure + 1)
				crack_failures.append(entry.num_failure)
			else:
				entry.num_failure += 1
				num_failure += 1

			success_curve.append((num_failure, num_success))

			if not success and entry.num_failure < t1:
				priority, next_word = self._get_sweetword(entry)
				if next_word is None:
					continue
				heapq.heappush(queue, (-priority, insert_counter, entry, next_word))
				insert_counter += 1

		total_users = len({entry.user_id for entry in sweetword_lists})
		cracked_users = num_success
		cracked_percent = 0.0 if total_users == 0 else (cracked_users / total_users) * 100.0
		total_guesses = num_failure + num_success
		failed_guesses = num_failure
		successful_guesses = num_success
		mean_guesses_to_crack = 0.0 if not crack_guesses else sum(crack_guesses) / len(crack_guesses)
		mean_failures_before_crack = (
			0.0 if not crack_failures else sum(crack_failures) / len(crack_failures)
		)

		return AttackStats(
			total_users=total_users,
			cracked_users=cracked_users,
			cracked_percent=cracked_percent,
			total_guesses=total_guesses,
			failed_guesses=failed_guesses,
			successful_guesses=successful_guesses,
			mean_guesses_to_crack=mean_guesses_to_crack,
			mean_failures_before_crack=mean_failures_before_crack,
			success_curve=success_curve,
		)

	def flatness_graph(self, sweetword_lists: Iterable[SweetwordList]) -> List[int]:
		results: List[int] = []
		real_map = {
			entry.user_id: entry.real_password
			for entry in sweetword_lists
			if entry.real_password is not None
		}
		for entry in sweetword_lists:
			attempts = 0
			while True:
				priority, word = self._get_sweetword(entry)
				if word is None:
					break
				entry.attempted.add(word)
				attempts += 1
				if real_map.get(entry.user_id) == word:
					break
			results.append(attempts)
		return results