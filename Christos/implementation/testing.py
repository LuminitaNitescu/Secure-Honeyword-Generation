from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import random
import sys

parent_dir = str(Path(__file__).resolve().parent.parent.parent)

if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# from attackers.normalized_top_pw import SweetwordList
# from attackers.normalized_top_pw_hg import NormalizedTopPWModelHG
from attackers.paper_attacker import NormalizedPWModel, SweetwordList
from statistics_custom import (
    HoneygenStats,
    compute_attack_success_rate,
    compute_cracked_by_t1,
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

from legacy_pcfg_master.python_pcfg_cracker_version3.pcfg_trainer import get_structures

worker_model = None

def _init_worker(model_path):
    global worker_model
    worker_model = MarkovModel(path=model_path)

def _generate_single_sweetword_list(args) -> SweetwordList:
        
    idx, user_data, base_seed, k = args
    
    row_seed = base_seed + idx

    sweetwords = worker_model.generate(user_data=user_data, k=k, seed=row_seed)  
    return SweetwordList(
        user_id=str(idx),
        sweetwords=sweetwords,
        real_password=user_data.password,
    )

def main() -> None:    
    # --- Configuration Parameters ---
    k = 20
    seed = 67
    t1 = 1
    t2 = 10000

    # --- Core Logic ---
    
    passwords = []
    passwords_pure = []
    # with open("C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\50k_subsample\\rockyou_sorted_preprocessed_ascii.txt", "r", encoding="utf-8") as f:
    with open("C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\rockyou_sorted_preprocessed_ts.txt", "r", encoding="utf-8") as f:
        for line in f:
            password = line.strip()
            if not password:
                continue
            
            if len(passwords) > 5:
                break
            
            # passwords.append(password)
            passwords.append(UserData(password=password))
            passwords_pure.append([password])

    # # 2. Initialize model and build sweetword lists
    # data_train = []
    # with open("C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\rockyou_sorted_preprocessed_tr.txt", "r", encoding="utf-8") as f:
    #     for line in f:
    #         password = line.strip()
    #         if not password:
    #             continue
            
    #         data_train.append([password])
    
    # model = MarkovModel()
    # model.load_data(data=data_train)
    model = PCFGModel()
    model.load_data(rule_name="RockYouFinal")
    print("Training done.")
    
    # 3. Train attacker model
    attacker = NormalizedPWModel(db_path="C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\hashmob_counts.txt", 
                                      dataset_size=23136055988) 
    
    sweetword_lists_unprocessed = model.generate(queries=passwords, k=k-1, seed=seed, structures=get_structures(passwords_pure))
    
    sweetword_lists = []
    for idx, sweetwords in enumerate(sweetword_lists_unprocessed):
        sweetword_lists.append(
            SweetwordList(
                user_id=str(idx),
                sweetwords=sweetwords,
                real_password=passwords[idx].password,
            )
        )
    
    rng = random.Random(seed)

    # sweetword_lists = []
    # for idx, password in enumerate(passwords):

    #     sweetwords = model.generate(user_data=password, k=k)
    #     sweetword_lists.append(
    #         SweetwordList(
    #             user_id=str(idx),
    #             sweetwords=sweetwords,
    #             real_password=password.password,
    #         )
    #     )
        
    #     if (idx + 1) % 500 == 0:
    #         print(f"Progress: {idx + 1:,} rows written.")
        
    # tasks = [
    #     (idx, password, seed, k) 
    #     for idx, password in enumerate(passwords)
    # ]
        
    # with multiprocessing.Pool(initializer=_init_worker, initargs=("C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\trained_models\\markov.pickle",)) as pool:
    #     sweetword_lists = list(
    #         tqdm(
    #             pool.imap(_generate_single_sweetword_list, tasks),
    #             total=len(tasks),
    #             desc="Generating Honeywords"
    #         )
    #     )
    
    attack_stats, flatness_graph, epsilon_flatness = attacker.analyze(
		sweetword_lists,
		k=k,
		t1=t1,
		t2=t2,
		show_progress=True,
	)
    cracked_by_t1 = compute_cracked_by_t1(flatness_graph, k)

    attack_success_rate = compute_attack_success_rate(attack_stats)

    stats = HoneygenStats(
        epsilon_flatness=epsilon_flatness,
        attack_success_rate=attack_success_rate,
        flatness_graph=flatness_graph,
        cracked_by_t1=cracked_by_t1,
        attack_stats=asdict(attack_stats),
    )
    
    write_stats_json(stats, "C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\results\\markov_results_final2.json")

    # print(json.dumps(asdict(stats), indent=2))

if __name__ == "__main__":
    main()