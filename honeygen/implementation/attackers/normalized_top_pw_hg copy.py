from __future__ import annotations

from dataclasses import dataclass, field
import heapq
from math import inf
from typing import Dict, Iterable, List, Optional, Tuple


CountMap = Dict[str, int]


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


class NormalizedTopPWModelHG:
	def __init__(self) -> None:
		self.counts: CountMap = {}
		self.dataset_size = 0

	def train(self, leaked_passwords: Iterable[str]) -> None:
		counts: Dict[str, int] = {}
		total = 0
		for password in leaked_passwords:
			password = password.strip()
			if not password:
				continue
			counts[password] = counts.get(password, 0) + 1
			total += 1
		self.dataset_size = total
		self.counts = counts

	def train_from_file(self, path: str) -> None:
		with open(path, "r", encoding="utf-8") as handle:
			self.train(handle)

	def train_from_aggregates_file(self, path: str) -> None:
		counts: Dict[str, int] = {}
		total = 0
		with open(path, "r", encoding="utf-8") as handle:
			for raw_line in handle:
				line = raw_line.rstrip("\n")
				if not line:
					continue
				try:
					password, count_text = line.rsplit(":", 1)
				except ValueError:
					raise ValueError(
						"Invalid aggregates line (expected 'password<whitespace>count')"
					) from None
				count = int(count_text)
				if count <= 0:
					continue
				counts[password] = count
				total += count
		self.dataset_size = total
		self.counts = counts

	def train_from_sorted_files(self, paths: Iterable[str]) -> None:
		counts: Dict[str, int] = {}
		total = 0
		for path in paths:
			current: Optional[str] = None
			count = 0
			with open(path, "r", encoding="utf-8") as handle:
				for raw_line in handle:
					line = raw_line.rstrip("\n")
					if not line:
						continue
					if current is None:
						current = line
						count = 1
						continue
					if line == current:
						count += 1
						continue
					counts[current] = counts.get(current, 0) + count
					total += count
					current = line
					count = 1
			if current is not None:
				counts[current] = counts.get(current, 0) + count
				total += count
		self.dataset_size = total
		self.counts = counts

	def _base_prob(self, word: str) -> float:
		count = self.counts.get(word, 0)
		if count > 0 and self.dataset_size > 0:
			return count / self.dataset_size
		return 0.0

	def _get_sweetword(self, entry: SweetwordList) -> Tuple[float, Optional[str]]:
		remaining = entry.remaining()
		if not remaining:
			return 0.0, None
		base_probs = {word: self._base_prob(word) for word in remaining}
		denom = sum(base_probs.values())
		if denom <= 0:
			# All zero probabilities: fall back to list order so we still attempt up to t1.
			fallback = min(remaining, key=lambda word: entry._index.get(word, 0))
			return 0.0, fallback
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
