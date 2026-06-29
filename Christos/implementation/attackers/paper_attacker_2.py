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
    # ADDED: stores prhw per word, extracted from sweetwords tuples
    _prhw: Dict[str, float] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        # CHANGED: unpack (word, prhw) tuples when building index
        self._index = {word: idx for idx, (word, _) in enumerate(self.sweetwords)}
        # ADDED: build prhw lookup from sweetwords tuples
        self._prhw = {word: prhw for word, prhw in self.sweetwords}

    def remaining(self) -> List[str]:
        # CHANGED: unpack tuples; still returns plain strings
        return [word for word, _ in self.sweetwords if word not in self.attempted]


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


class PaperAttacker:
    def __init__(self, db_path: str, dataset_size: int) -> None:
        self.db_path = db_path
        self.dataset_size = dataset_size
        
        if not os.path.exists(self.db_path):
            raise FileNotFoundError(f"Database file not found: {self.db_path}")
        if self.dataset_size <= 0:
            raise ValueError("Dataset size must be strictly greater than 0.")

    def _binary_search_count(self, target_word: str) -> int:
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

    def _base_prob(self, word: str) -> float:
        count = self._binary_search_count(word)
        return count / self.dataset_size

    def _get_sweetword(self, entry: SweetwordList) -> Tuple[float, Optional[str], int]:
        remaining = entry.remaining()
        if not remaining:
            return 0.0, None, 0
            
        base_probs = {word: self._base_prob(word) for word in remaining}
        nonzero_probs = [prob for prob in base_probs.values() if prob > 0]

        # CHANGED: Case 2 score is prpw/prhw; fall back to 0.0 if prhw is zero
        scores = {
            word: base_probs[word] / entry._prhw[word] if entry._prhw.get(word, 0.0) > 0 else inf
            for word in remaining
        }

        denom = sum(scores.values())
        
        # if denom <= 0:
        #     fallback = min(remaining, key=lambda word: entry._index.get(word, 0))
        #     return 0.0, fallback, len(nonzero_probs)
            
        best = max(
            remaining,
            key=lambda word: (scores[word], -entry._index.get(word, 0)),
        )
        # CHANGED: normalise by sum of case-2 scores instead of sum of prpw
        return scores[best] / denom, best, len(nonzero_probs)

    def _get_sweetword_with_probs(
        self,
        entry: SweetwordList,
        base_probs: Dict[str, float],
    ) -> Tuple[float, Optional[str]]:
        remaining = entry.remaining()
        if not remaining:
            return 0.0, None

        scores = {}
        for word in remaining:
            prhw = entry._prhw[word]
            prpw = base_probs[word]
            if prhw <= 0.0 or prpw / prhw > 20:
                scores[word] = prpw
            else:
                scores[word] = prpw / prhw

        best = max(remaining, key=lambda word: scores[word])

        # if scores[best] == inf:
        #     return 1.0, best

        denom = sum(scores.values())
        return scores[best] / denom, best

    def _clone_entries(self, entries: Iterable[SweetwordList]) -> List[SweetwordList]:
        return [
            SweetwordList(
                user_id=entry.user_id,
                # CHANGED: preserve (word, prhw) tuples when cloning
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
        
        total_prob = 0.0
        valid_user_count = 0
        total_nonzero_prob_words = 0
        
        for entry in entries:
            entry_probs = {word: self._base_prob(word) for word, _ in entry.sweetwords}
            prob_cache[entry.user_id] = entry_probs
            total_nonzero_prob_words += sum(1 for prob in entry_probs.values() if prob > 0)

            if entry.real_password is None:
                continue

            scores = {}
            for word in entry_probs:
                prhw = entry._prhw[word]
                prpw = entry_probs[word]
                if prhw <= 0.0 or prpw / prhw > 20:
                    scores[word] = prpw
                else:
                    scores[word] = prpw / prhw

            best_word = max(scores, key=lambda w: scores[w])
            prob = 1.0 if best_word == entry.real_password else 0.0

            total_prob += prob
            valid_user_count += 1

        empirical_epsilon_flatness = (total_prob / valid_user_count) if valid_user_count > 0 else 0.0

        return prob_cache, empirical_epsilon_flatness, total_nonzero_prob_words

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
        for i, entry in enumerate(tqdm(
            entries,
            total=len(entries),
            desc="Flatness graph",
            unit="users",
            disable=not show_progress,
        )):
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
    ) -> Tuple[AttackStats, List[int], float]:
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