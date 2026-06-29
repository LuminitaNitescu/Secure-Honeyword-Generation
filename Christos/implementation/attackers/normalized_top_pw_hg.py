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

        # We encode to bytes to ensure perfect matching with LC_ALL=C Unix sorting
        target_bytes = target_word.encode('utf-8')

        with open(self.db_path, 'rb') as f:
            while low < high:
                mid = (low + high) // 2
                f.seek(mid)

                # If we jump into the middle of the file, we are likely in the 
                # middle of a word. Read and discard until the next newline.
                if mid > 0:
                    f.readline()

                line_bytes = f.readline()
                if not line_bytes:
                    break  # EOF reached

                try:
                    # Decode and safely right-split by the colon
                    line_str = line_bytes.decode('utf-8').rstrip('\r\n')
                    current_word, count_str = line_str.rsplit(':', 1)
                    current_count = int(count_str)
                except ValueError:
                    # If we hit a malformed line, gracefully advance the lower bound
                    low = f.tell()
                    continue

                current_bytes = current_word.encode('utf-8')

                # Binary search logic
                if current_bytes == target_bytes:
                    return current_count
                elif current_bytes < target_bytes:
                    low = f.tell()
                else:
                    high = mid

        return 0  # Word not found in the HIBP dataset

    def _base_prob(self, word: str) -> float:
        """
        Fetches the exact count from disk and returns its normalized probability.
        """
        count = self._binary_search_count(word)
        if count > 0 and self.dataset_size > 0:
            return count / self.dataset_size
        return 0.0

    def _get_sweetword(self, entry: SweetwordList) -> Tuple[float, Optional[str], int]:
        #print(f"from sweetword list: {entry.sweetwords}")
        remaining = entry.remaining()
        if not remaining:
            return 0.0, None, 0
            
        base_probs = {word: self._base_prob(word) for word in remaining}
        #print(f"base probabilities: {base_probs}")
        nonzero_probs = [prob for prob in base_probs.values() if prob > 0]
            
        denom = sum(base_probs.values())
        
        if denom <= 0:
            # All zero probabilities: fall back to list order so we still attempt up to t1.
            fallback = min(remaining, key=lambda word: entry._index.get(word, 0))
            return 0.0, fallback, len(nonzero_probs)
            
        best = max(
            remaining,
            key=lambda word: (base_probs[word], -entry._index.get(word, 0)),
        )
        return base_probs[best] / denom, best, len(nonzero_probs)

    def _get_sweetword_with_probs(
        self,
        entry: SweetwordList,
        base_probs: Dict[str, float],
    ) -> Tuple[float, Optional[str]]:
        remaining = entry.remaining()
        if not remaining:
            return 0.0, None

        denom = sum(base_probs.get(word, 0.0) for word in remaining)
        if denom <= 0:
            fallback = min(remaining, key=lambda word: entry._index.get(word, 0))
            return 0.0, fallback

        best = max(
            remaining,
            key=lambda word: (base_probs.get(word, 0.0), -entry._index.get(word, 0)),
        )
        return base_probs.get(best, 0.0) / denom, best

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
        prob_cache: Dict[str, Dict[str, float]] = {}
        
        valid_user_count = 0
        total_nonzero_prob_words = 0
        
        prob_cache: Dict[str, Dict[str, float]] = {}
    
        successful_guesses = 0.0
        valid_user_count = 0
        total_nonzero_prob_words = 0
        
        for entry in entries:
            entry_probs = {word: self._base_prob(word) for word in entry.sweetwords}
            prob_cache[entry.user_id] = entry_probs
            
            total_nonzero_prob_words += sum(1 for prob in entry_probs.values() if prob > 0)

            if entry.real_password is None:
                continue
            
            valid_user_count += 1

            max_prob = max(entry_probs.values())
            
            best_guesses = [word for word, prob in entry_probs.items() if prob == max_prob]
            

            if entry.real_password in best_guesses:
                successful_guesses += (1.0 / len(best_guesses))

        model_success_rate = (successful_guesses / valid_user_count) if valid_user_count > 0 else 0.0

        return prob_cache, model_success_rate, total_nonzero_prob_words
    def _crack_with_probs(
        self,
        sweetword_lists: Iterable[SweetwordList],
        prob_cache: Dict[str, Dict[str, float]],
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
                prob_cache.get(entry.user_id, {}),
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
                        prob_cache.get(entry.user_id, {}),
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
        prob_cache: Dict[str, Dict[str, float]],
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
                    prob_cache.get(entry.user_id, {}),
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
        success_number: bool = False,
    ) -> Tuple[AttackStats, List[int], float, Optional[AttackStats]]:
        entries = list(sweetword_lists)
        prob_cache, epsilon_flatness, total_nonzero = self._build_prob_cache(entries, k)
        print(f"total non-zero probability passwords: {total_nonzero}")

        attack_lists = self._clone_entries(entries)
        attack_stats = self._crack_with_probs(
            attack_lists,
            prob_cache,
            t1=t1,
            t2=t2,
            show_progress=show_progress,
        )

        flatness_lists = self._clone_entries(entries)
        flatness_graph = self._flatness_graph_with_probs(
            flatness_lists,
            prob_cache,
            show_progress=show_progress,
        )

        # Worst-case success-number run: reuse the (expensive) prob cache but force
        # t2=None so the global guessing campaign runs uncapped until every account
        # is cracked, yielding the full successes-vs-failures curve.
        success_number_stats: Optional[AttackStats] = None
        if success_number:
            success_lists = self._clone_entries(entries)
            success_number_stats = self._crack_with_probs(
                success_lists,
                prob_cache,
                t1=t1,
                t2=None,
                show_progress=show_progress,
            )

        return attack_stats, flatness_graph, epsilon_flatness, success_number_stats

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