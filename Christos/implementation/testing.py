from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import random
import sys

parent_dir = str(Path(__file__).resolve().parent.parent.parent)

if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from attackers.normalized_top_pw import NormalizedTopPWModel, SweetwordList
from statistics_custom import (
    HoneygenStats,
    compute_attack_success_rate,
    compute_epsilon_flatness,
    write_stats_json,
)

from list import ListModel, TargetedListModel
from markov import MarkovModel, TargetedMarkovModel
from pcfg import PCFGModel, TargetedPCFGModel
from util import UserData
import pickle
import itertools
import multiprocessing
from typing import List, Iterable
from tqdm import tqdm


worker_model = None

def _init_worker(model_path):
    global worker_model
    worker_model = MarkovModel(path=model_path)

def _generate_single_sweetword_list(args) -> SweetwordList:
        
    idx, user_data, base_seed, k = args
    
    row_seed = base_seed + idx
    worker_rng = random.Random(row_seed)

    sweetwords = worker_model.generate(user_data=user_data, k=k - 1)
    sweetwords.append(user_data.password)
    worker_rng.shuffle(sweetwords)
    
    return SweetwordList(
        user_id=str(idx),
        sweetwords=sweetwords,
        real_password=user_data.password,
    )
    
def _clone_sweetword_lists(entries: Iterable[SweetwordList]) -> List[SweetwordList]:
	return [
		SweetwordList(
			user_id=entry.user_id,
			sweetwords=list(entry.sweetwords),
			real_password=entry.real_password,
		)
		for entry in entries
	]

def main() -> None:    
    # --- Configuration Parameters ---
    k = 20
    seed = 67
    t1 = 20
    t2 = 61

    # --- Core Logic ---
    
    passwords = []
    with open("C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\rockyou_sorted_preprocessed_ts.txt", "r", encoding="utf-8") as f:
        for line in f:
            password = line.strip()
            if not password or len(password) < 8 or len(password) > 20:
                continue
            # if len(passwords) > 999:
            #     break
            
            # passwords.append(password)
            passwords.append(UserData(password=password))

    # 2. Initialize model and build sweetword lists
    data_train = []
    with open("C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\rockyou_sorted_preprocessed_tr.txt", "r", encoding="utf-8") as f:
        for line in f:
            password = line.strip()
            if not password:
                continue
            data_train.append([password])
    # model = MarkovModel(path="C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\trained_models\\markov.pickle")
    print("Training done.")
    
    # 3. Train attacker model
    attacker = NormalizedTopPWModel()
    attacker.train_from_file("C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\rockyou_sorted_preprocessed_tr.txt")
    
    rng = random.Random(seed)
    
    # sweetword_lists_unprocessed = model.generate(password_list=passwords, k=k-1)
    
    # sweetword_lists = []
    # for idx, sweetwords in enumerate(sweetword_lists_unprocessed):

    #     password = passwords[idx]
    #     sweetwords.append(password)
    #     rng.shuffle(sweetwords)
    #     sweetword_lists.append(
    #         SweetwordList(
    #             user_id=str(idx),
    #             sweetwords=sweetwords,
    #             real_password=password,
    #         )
    #     )
    
    
    
    # sweetword_lists = []
    # for idx, password in enumerate(passwords):

    #     sweetwords = model.generate(user_data=password, k=k - 1)
    #     sweetwords.append(password)
    #     rng.shuffle(sweetwords)
    #     sweetword_lists.append(
    #         SweetwordList(
    #             user_id=str(idx),
    #             sweetwords=sweetwords,
    #             real_password=password,
    #         )
    #     )



    tasks = [
        (idx, password, seed, k) 
        for idx, password in enumerate(passwords)
    ]
        
    with multiprocessing.Pool(initializer=_init_worker, initargs=("C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\trained_models\\markov.pickle",)) as pool:
        sweetword_lists = list(
            tqdm(
                pool.imap(_generate_single_sweetword_list, tasks),
                total=len(tasks),
                desc="Generating Honeywords"
            )
        )

    # 4. Run attack simulation using list clones
    attack_lists = _clone_sweetword_lists(sweetword_lists)
    attack_stats = attacker.crack(attack_lists, t1=t1, t2=t2)

    # 5. Compute flatness graph using list clones
    flatness_lists = _clone_sweetword_lists(sweetword_lists)
    flatness_graph = attacker.flatness_graph(flatness_lists)

    # 6. Compute statistics and print output
    epsilon_flatness = compute_epsilon_flatness(sweetword_lists, attacker, k)
    attack_success_rate = compute_attack_success_rate(attack_stats)

    stats = HoneygenStats(
        epsilon_flatness=epsilon_flatness,
        attack_success_rate=attack_success_rate,
        flatness_graph=flatness_graph,
        attack_stats=asdict(attack_stats),
    )
    
    write_stats_json(stats, "C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\results\\markov_results2.json")

    print(json.dumps(asdict(stats), indent=2))


if __name__ == "__main__":
    main()