from __future__ import annotations

import os
import heapq
from dataclasses import dataclass, field
from math import inf
from typing import Dict, Iterable, List, Optional, Tuple
from tqdm import tqdm


@dataclass
class SweetwordList:
    user_id: str
    sweetwords: List[Tuple[str, float]]
    real_password: Optional[str] = None
    num_failure: int = 0
    attempted: set[str] = field(default_factory=set)
    _index: Dict[str, int] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._index = {word: idx for idx, (word, _) in enumerate(self.sweetwords)}

    def remaining(self) -> List[Tuple[str, float]]:
        return [(word, pr_hw) for word, pr_hw in self.sweetwords if word not in self.attempted]


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


class NormalizedPWModel:
    def __init__(self, db_path: str, dataset_size: int) -> None:
        """
        Initializes the model for disk-based binary search.

        :param db_path: Path to the 5GB cleartext-sorted file (password:count)
        :param dataset_size: The total sum of all counts in the dataset, required
                             for accurate probability generation.
        """
        self.db_path = db_path
        self.dataset_size = dataset_size

        if not os.path.exists(self.db_path):
            raise FileNotFoundError(f"Database file not found: {self.db_path}")
        if self.dataset_size <= 0:
            raise ValueError("Dataset size must be strictly greater than 0.")

    def _binary_search_count(self, target_word: str) -> int:
        """
        Performs a zero-RAM binary search directly on the SSD to find the count.
        Assumes the file is sorted by the password column using LC_ALL=C.
        """
        file_size = os.path.getsize(self.db_path)
        low = 0
        high = file_size

        target_bytes = target_word.encode('utf-8')

        with open(self.db_path, 'rb') as f:
            while low < high:
                mid = (low + high) // 2
                f.seek(mid)

                if mid > 0:
                    f.readline()

                line_bytes = f.readline()
                if not line_bytes:
                    break

                try:
                    line_str = line_bytes.decode('utf-8').rstrip('\r\n')
                    current_word, count_str = line_str.rsplit(':', 1)
                    current_count = int(count_str)
                except ValueError:
                    low = f.tell()
                    continue

                current_bytes = current_word.encode('utf-8')

                if current_bytes == target_bytes:
                    return current_count
                elif current_bytes < target_bytes:
                    low = f.tell()
                else:
                    high = mid

        return 0

    def _ratio(self, word: str, count: int, pr_hw: float) -> float:
        """
        Computes PrPW(word) / PrHW(word), the ranking key for the optimal A1
        attacker (paper Eq. 4).

        Clamping rule (paper Sec. IV-B): if the word is OOV (count == 0) and
        the smoothed ratio would exceed 1.0, clamp to 1.0.
        """
        pr_pw = (count / self.dataset_size) if count > 0 else 1.0 / (self.dataset_size + 1)

        if pr_hw <= 0:
            return 1.0

        ratio = pr_pw / pr_hw

        if count == 0 and ratio > 1.0:
            return 1.0

        return ratio

    def _get_sweetword(self, entry: SweetwordList) -> Tuple[float, Optional[str], int]:
        remaining = entry.remaining()
        if not remaining:
            return 0.0, None, 0

        counts = {word: self._binary_search_count(word) for word, _ in remaining}
        nonzero_count = sum(1 for c in counts.values() if c > 0)

        ratios = {
            word: self._ratio(word, counts[word], pr_hw)
            for word, pr_hw in remaining
        }

        denom = sum(ratios.values())

        if denom <= 0:
            fallback = min(remaining, key=lambda wp: entry._index.get(wp[0], 0))
            return 0.0, fallback[0], nonzero_count

        best = max(
            remaining,
            key=lambda wp: (ratios[wp[0]], -entry._index.get(wp[0], 0)),
        )
        return ratios[best[0]] / denom, best[0], nonzero_count

    def _get_sweetword_with_probs(
        self,
        entry: SweetwordList,
        ratio_cache: Dict[str, float],
    ) -> Tuple[float, Optional[str]]:
        remaining = entry.remaining()
        if not remaining:
            return 0.0, None

        denom = sum(ratio_cache.get(word, 0.0) for word, _ in remaining)
        if denom <= 0:
            fallback = min(remaining, key=lambda wp: entry._index.get(wp[0], 0))
            return 0.0, fallback[0]

        best = max(
            remaining,
            key=lambda wp: (ratio_cache.get(wp[0], 0.0), -entry._index.get(wp[0], 0)),
        )
        return ratio_cache.get(best[0], 0.0) / denom, best[0]

    def _clone_entries(self, entries: Iterable[SweetwordList]) -> List[SweetwordList]:
        return [
            SweetwordList(
                user_id=entry.user_id,
                sweetwords=list(entry.sweetwords),
                real_password=entry.real_password,
            )
            for entry in entries
        ]

    def _build_prob_cache(
        self,
        entries: Iterable[SweetwordList],
        k: int,
    ) -> Tuple[Dict[str, Dict[str, float]], float, int]:
        ratio_cache: Dict[str, Dict[str, float]] = {}
        max_posterior = 0.0
        total_nonzero_count = 0

        for entry in entries:
            # CHANGE 6: unpack (word, pr_hw) from each sweetword tuple.
            # pr_hw comes from the stored value rather than being recomputed.
            counts = {word: self._binary_search_count(word) for word, _ in entry.sweetwords}
            total_nonzero_count += sum(1 for c in counts.values() if c > 0)

            entry_ratios = {
                word: self._ratio(word, counts[word], pr_hw)
                for word, pr_hw in entry.sweetwords
            }
            ratio_cache[entry.user_id] = entry_ratios

            if entry.real_password is None:
                continue

            denom = sum(entry_ratios.values())
            if denom <= 0:
                posterior = 1.0 / k
            else:
                posterior = entry_ratios.get(entry.real_password, 0.0) / denom

            if posterior > max_posterior:
                max_posterior = posterior

        return ratio_cache, max_posterior, total_nonzero_count

    def _crack_with_probs(
        self,
        sweetword_lists: Iterable[SweetwordList],
        ratio_cache: Dict[str, Dict[str, float]],
        t1: int = 1,
        t2: Optional[int] = None,
        show_progress: bool = True,
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
            priority, word = self._get_sweetword_with_probs(
                entry,
                ratio_cache.get(entry.user_id, {}),
            )
            if word is None:
                continue
            heapq.heappush(queue, (-priority, insert_counter, entry, word))
            insert_counter += 1

        progress_total = None if max_failures is inf else max_failures
        progress_iter = tqdm(
            total=progress_total,
            desc="Attack progress",
            unit="failures",
            disable=not show_progress,
        )
        try:
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
                    progress_iter.update(1)

                success_curve.append((num_failure, num_success))

                if not success and entry.num_failure < t1:
                    priority, next_word = self._get_sweetword_with_probs(
                        entry,
                        ratio_cache.get(entry.user_id, {}),
                    )
                    if next_word is None:
                        continue
                    heapq.heappush(queue, (-priority, insert_counter, entry, next_word))
                    insert_counter += 1
        finally:
            progress_iter.close()

        total_users = len({entry.user_id for entry in sweetword_lists})
        cracked_users = num_success
        cracked_percent = 0.0 if total_users == 0 else (cracked_users / total_users) * 100.0
        total_guesses = num_failure + num_success
        failed_guesses = num_failure
        successful_guesses = num_success
        mean_guesses_to_crack = (
            0.0 if not crack_guesses else sum(crack_guesses) / len(crack_guesses)
        )
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

    def _flatness_graph_with_probs(
        self,
        sweetword_lists: Iterable[SweetwordList],
        ratio_cache: Dict[str, Dict[str, float]],
        show_progress: bool = True,
    ) -> List[int]:
        results: List[int] = []
        entries = list(sweetword_lists)
        real_map = {
            entry.user_id: entry.real_password
            for entry in entries
            if entry.real_password is not None
        }
        for entry in tqdm(
            entries,
            total=len(entries),
            desc="Flatness graph",
            unit="users",
            disable=not show_progress,
        ):
            attempts = 0
            while True:
                priority, word = self._get_sweetword_with_probs(
                    entry,
                    ratio_cache.get(entry.user_id, {}),
                )
                if word is None:
                    break
                entry.attempted.add(word)
                attempts += 1
                if real_map.get(entry.user_id) == word:
                    break
            results.append(attempts)
        return results

    def analyze(
        self,
        sweetword_lists: Iterable[SweetwordList],
        k: int,
        t1: int = 1,
        t2: Optional[int] = None,
        show_progress: bool = True,
    ) -> Tuple[AttackStats, List[int], float]:
        entries = list(sweetword_lists)
        ratio_cache, epsilon_flatness, total_nonzero = self._build_prob_cache(entries, k)
        print(f"total non-zero probability passwords: {total_nonzero}")

        attack_lists = self._clone_entries(entries)
        attack_stats = self._crack_with_probs(
            attack_lists,
            ratio_cache,
            t1=t1,
            t2=t2,
            show_progress=show_progress,
        )

        flatness_lists = self._clone_entries(entries)
        flatness_graph = self._flatness_graph_with_probs(
            flatness_lists,
            ratio_cache,
            show_progress=show_progress,
        )

        return attack_stats, flatness_graph, epsilon_flatness

    def crack(
        self,
        sweetword_lists: Iterable[SweetwordList],
        t1: int = 1,
        t2: Optional[int] = None,
        show_progress: bool = True,
    ) -> AttackStats:
        max_failures = inf if t2 is None else max(0, t2)
        queue: List[Tuple[float, int, SweetwordList, str]] = []
        insert_counter = 0
        num_failure = 0
        num_success = 0
        total_nonzero_prob_words = 0
        success_curve: List[Tuple[int, int]] = []
        crack_guesses: List[int] = []
        crack_failures: List[int] = []

        real_map = {
            entry.user_id: entry.real_password
            for entry in sweetword_lists
            if entry.real_password is not None
        }

        for entry in sweetword_lists:
            priority, word, nonzero_count = self._get_sweetword(entry)
            if word is None:
                continue
            total_nonzero_prob_words += nonzero_count
            heapq.heappush(queue, (-priority, insert_counter, entry, word))
            insert_counter += 1

        print(f"total non-zero probability passwords: {total_nonzero_prob_words}")
        progress_total = None if max_failures is inf else max_failures
        progress_iter = tqdm(
            total=progress_total,
            desc="Attack progress",
            unit="failures",
            disable=not show_progress,
        )
        try:
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
                    progress_iter.update(1)

                success_curve.append((num_failure, num_success))

                if not success and entry.num_failure < t1:
                    priority, next_word, _ = self._get_sweetword(entry)
                    if next_word is None:
                        continue
                    heapq.heappush(queue, (-priority, insert_counter, entry, next_word))
                    insert_counter += 1
        finally:
            progress_iter.close()

        total_users = len({entry.user_id for entry in sweetword_lists})
        cracked_users = num_success
        cracked_percent = 0.0 if total_users == 0 else (cracked_users / total_users) * 100.0
        total_guesses = num_failure + num_success
        failed_guesses = num_failure
        successful_guesses = num_success
        mean_guesses_to_crack = (
            0.0 if not crack_guesses else sum(crack_guesses) / len(crack_guesses)
        )
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

    def flatness_graph(
        self,
        sweetword_lists: Iterable[SweetwordList],
        show_progress: bool = True,
    ) -> List[int]:
        results: List[int] = []
        entries = list(sweetword_lists)
        real_map = {
            entry.user_id: entry.real_password
            for entry in entries
            if entry.real_password is not None
        }
        for entry in tqdm(
            entries,
            total=len(entries),
            desc="Flatness graph",
            unit="users",
            disable=not show_progress,
        ):
            attempts = 0
            while True:
                priority, word, _ = self._get_sweetword(entry)
                if word is None:
                    break
                entry.attempted.add(word)
                attempts += 1
                if real_map.get(entry.user_id) == word:
                    break
            results.append(attempts)
        return results