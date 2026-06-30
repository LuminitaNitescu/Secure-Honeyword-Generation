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


class TopPWModel:
	def __init__(self) -> None:
		self.pd: ProbabilityMap = {}

	def train(self, leaked_passwords: Iterable[str]) -> None:
		counts: Dict[str, int] = {}
		total = 0
		for password in leaked_passwords:
			password = password.strip()
			if not password:
				continue
			counts[password] = counts.get(password, 0) + 1
			total += 1
		if total == 0:
			self.pd = {}
			return
		self.pd = {password: count / total for password, count in counts.items()}

	def train_from_file(self, path: str) -> None:
		with open(path, "r", encoding="utf-8") as handle:
			self.train(handle)

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
			for word in entry.sweetwords:
				prob = self.pd.get(word, 0.0)
				if prob <= 0:
					continue
				heapq.heappush(queue, (-prob, insert_counter, entry, word))
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
