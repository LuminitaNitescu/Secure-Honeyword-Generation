"""
Run the attacker against sweetwords from honeywords_Qwen3_10k_breach.csv and
write a JSON output.
CSV format: real_pw,honey1,honey2,...  
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "Andrei" / "implementation"))

# use the attacker from Andrei's implementation
from attackers.normalized_top_pw_hg import NormalizedTopPWModelHG, SweetwordList
from statistics import (
    HoneygenStats,
    compute_attack_success_rate,
    compute_cracked_by_t1,
    write_stats_json,
)

HASHMOB_PATH = Path(__file__).parent / "hashmob_counts.txt"  # path to the attacker dataser
HASHMOB_DATASET_SIZE = 23_136_055_988

CSV_PATH = Path(__file__).parent / "honeywords_Qwen3_10k_breach.csv"  # path to the honeywords CSV

# Load sweetword lists from CSV, shuffle the order of sweetwords for each user, and return a list of SweetwordList objects.
def load_sweetword_lists(csv_path: Path, seed: int = 67) -> list[SweetwordList]:
    rng = random.Random(seed)
    entries: list[SweetwordList] = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader) 
        for idx, row in enumerate(reader):
            real_password = row[0].strip()
            if not real_password:
                continue
            sweetwords = [w.strip() for w in row if w.strip()]
            rng.shuffle(sweetwords)  # shuffle index of real password
            entries.append(
                SweetwordList(
                    user_id=str(idx),
                    sweetwords=sweetwords,
                    real_password=real_password,
                )
            )
    return entries


def main() -> None:
    parser = argparse.ArgumentParser(description="Attack Qwen honeywords with hashmob attacker")
    parser.add_argument("--csv", type=str, default=str(CSV_PATH), help="Path to honeywords CSV")
    parser.add_argument("--attacker-db", type=str, default=str(HASHMOB_PATH), help="Path to attacker dataset")
    parser.add_argument("--dataset-size", type=int, default=HASHMOB_DATASET_SIZE)
    parser.add_argument("--t1", type=int, default=1, help="Max guesses per user")
    parser.add_argument("--t2", type=int, default=None, help="Total failure budget")
    parser.add_argument("--out-dir", type=str, default="outputs", help="Output directory")
    parser.add_argument("--seed", type=int, default=67)
    parser.add_argument("--no-progress", action="store_true")
    parser.add_argument("--success-number", action="store_true", help="Run inclusive success-number curve")
    args = parser.parse_args()

    csv_path = Path(args.csv)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Loading sweetword lists from CSV...")
    sweetword_lists = load_sweetword_lists(csv_path, seed=args.seed)
    k = len(sweetword_lists[0].sweetwords) if sweetword_lists else 20
    print(f"Loaded {len(sweetword_lists)} users, k={k}")

    print("Initialising attacker...")
    attacker = NormalizedTopPWModelHG(
        db_path=args.attacker_db,
        dataset_size=args.dataset_size,
    )

    print("Running attack analysis...")
    attack_stats, flatness_graph, epsilon_flatness, success_number_stats = attacker.analyze(
        sweetword_lists,
        k=k,
        t1=args.t1,
        t2=args.t2,
        show_progress=not args.no_progress,
        success_number=args.success_number,
    )

    cracked_by_t1 = compute_cracked_by_t1(flatness_graph, k)
    attack_success_rate = compute_attack_success_rate(attack_stats)

    # collect all stats into a HoneygenStats object for JSON output
    stats = HoneygenStats(
        epsilon_flatness=epsilon_flatness,
        attack_success_rate=attack_success_rate,
        flatness_graph=flatness_graph,
        cracked_by_t1=cracked_by_t1,
        attack_stats=asdict(attack_stats),
        success_number=asdict(success_number_stats) if success_number_stats is not None else None,
    )

    stem = csv_path.stem
    output_path = out_dir / f"{stem}_t1{args.t1}_t2{args.t2}.json"
    write_stats_json(stats, str(output_path))
    print(f"Results written to {output_path}")
    print(f"epsilon_flatness: {epsilon_flatness:.4f}")
    print(f"attack_success_rate: {attack_success_rate:.4f}")
    print(f"cracked_users:  {attack_stats.cracked_users}/{attack_stats.total_users}")


if __name__ == "__main__":
    main()
