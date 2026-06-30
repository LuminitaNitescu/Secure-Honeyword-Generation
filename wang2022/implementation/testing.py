from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import random
import sys
import csv

parent_dir = str(Path(__file__).resolve().parent.parent.parent)

if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

other_implement_dir = str(Path(__file__).resolve().parent.parent.parent / "Andrei" / "implementation")

if other_implement_dir not in sys.path:
    sys.path.append(other_implement_dir)

# from attackers.paper_attacker import PaperAttacker, SweetwordList
from honeygen.implementation.attackers.normalized_top_pw_hg import NormalizedTopPWModelHG, SweetwordList
from honeygen.implementation.statistics import (
	HoneygenStats,
	compute_attack_success_rate,
	compute_cracked_by_t1,
	write_stats_json,
)


from list import ListModel, TargetedListModel
from pcfg import PCFGModel, TargetedPCFGModel
from markov import MarkovModel, TargetedMarkovModel
from util import UserData
import pickle
import itertools
import multiprocessing
from typing import List, Iterable
from tqdm import tqdm

from legacy_pcfg_master.python_pcfg_cracker_version3.pcfg_trainer_logic.training_data import TrainingData
from legacy_pcfg_master.python_pcfg_cracker_version3.pcfg_trainer_logic.ret_types import RetType

worker_model = None


def _get_structures(data, targeted=False):
    
    print("Calculating password structures:") 
        
    training_results = TrainingData(targeted)
        
    for i, password in enumerate(data):
        
        ret_value = training_results.parse(password)
        if ret_value != RetType.STATUS_OK:
            continue
        
        if (i + 1) % 10_000 == 0:
            print(f"Progress: {i + 1:,} items processed.")
        
    return training_results.structure_dict

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
    t1 = 20
    t2 = 61

    # --- Core Logic ---
    
    passwords = []
    passwords_pure = []
    # with open("C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\rockyou_final_ts.txt", "r", encoding="utf-8") as f:
    #     for line in f:
    #         password = line.strip()
    #         if not password:
    #             continue
            
    #         if len(passwords) >= 50_000:
    #             break
            
    #         passwords.append(UserData(password=password))
    #         passwords_pure.append([password])

    with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\data\rockyou_targeted_ts.csv", "r", encoding="utf-8") as infile:

        reader = csv.reader(infile)

        next(reader, None)
        for row in reader:
            
            if len(passwords) >= 50_000:
                break
            
            if row:
                # passwords.append(UserData(password=row[0], email=row[3], username=row[5], first_name=row[1], last_name=row[2], birthday=row[4]))
                # passwords_pure.append([row[0], row[3], row[5], row[1], row[2], row[4]])
                
                passwords.append(UserData(password=row[0]))
                passwords_pure.append([row[0]])

    # 2. Initialize model and build sweetword lists
    data_train = []
    # with open("C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\rockyou_final_tr.txt", "r", encoding="utf-8") as f:
    #     for line in f:
    #         password = line.strip()
    #         if not password:
    #             continue
            
    #         data_train.append([password])
    
    with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\data\rockyou_targeted_tr.csv", "r", encoding="utf-8") as infile:

        reader = csv.reader(infile)
        
        next(reader, None)

        # data_train = [row for row in reader if row]
        
        data_train = [row[0] for row in reader if row]
    
    # model = MarkovModel(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\trained_models\markov3.pickle")
    # model = TargetedMarkovModel()
    
    # model = TargetedListModel(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\trained_models\list_targeted2.pickle")
    model = ListModel()
    
    model.load_data(data=data_train)
    
    # model = TargetedPCFGModel()
    # model.load_data(data=data_train, rule_name="RockYouUltraFinal")
    print("Training done.")
    
    # structures = _get_structures(data=passwords_pure, targeted=True)
    # structures = _get_structures(data=passwords_pure)
    
    sweetword_lists_unprocessed = model.generate(queries=passwords, k=k, seed=seed)
    # sweetword_lists_unprocessed = model.generate(queries=passwords, k=k, seed=seed, structures=structures)

    # with open('markov_a2_sweetwords', 'wb') as f:
    #         pickle.dump(sweetword_lists_unprocessed, f, protocol=pickle.HIGHEST_PROTOCOL)
    
    # with open("markov_a2_sweetwords.pickle", "rb") as f:
    #     sweetword_lists_unprocessed = pickle.load(f)
        
    sweetword_lists = []
    for idx, sweetwords in enumerate(sweetword_lists_unprocessed):
        sweetword_lists.append(
            SweetwordList(
                user_id=str(idx),
                sweetwords=[x[0] for x in sweetwords[1]],
                real_password=sweetwords[0],
            )
        )
    
    # 3. Train attacker model
    # attacker = PaperAttacker(db_path="C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\yahoo_tr_counts.txt", 
    #                                   dataset_size=221418)
    # attacker = NormalizedTopPWModelHG(db_path="C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\hashmob_counts.txt", 
    #                                   dataset_size=23136055988) 
    attacker = NormalizedTopPWModelHG(db_path=r"C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\rockyou_targeted_attacker_counts.txt", 
                                      dataset_size=32_602_874) 
    # attacker = NormalizedTopPWModelHG(db_path="C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\hashmob_targeted_counts.txt", 
    #                                   dataset_size=100_000_000) 
    # attacker = PaperAttacker(db_path="C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\rockyou_final_tr_counts.txt", 
    #                                   dataset_size=16_300_127) 
    
    attack_stats, flatness_graph, epsilon_flatness, success_number_stats = attacker.analyze(
		sweetword_lists,
		k=k,
		t1=t1,
		t2=t2,
		show_progress=True,
		success_number=True,
	)
    
    cracked_by_t1 = compute_cracked_by_t1(flatness_graph, k)
    
    attack_success_rate = compute_attack_success_rate(attack_stats)

    stats = HoneygenStats(
		epsilon_flatness=epsilon_flatness,
		attack_success_rate=attack_success_rate,
		flatness_graph=flatness_graph,
		cracked_by_t1=cracked_by_t1,
		attack_stats=asdict(attack_stats),
		success_number=asdict(success_number_stats) if success_number_stats else None,
	)
    
    write_stats_json(stats, "C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\results\\list_a2_attacker_full.json")


    # attacker = NormalizedTopPWModelHG(db_path="C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\rockyou_final_tr_counts.txt", 
    #                                   dataset_size=16_300_160) 
    
    # attack_stats, flatness_graph, epsilon_flatness, success_number_stats = attacker.analyze(
	# 	sweetword_lists,
	# 	k=k,
	# 	t1=t1,
	# 	t2=t2,
	# 	show_progress=True,
	# 	success_number=True,
	# )
    
    # cracked_by_t1 = compute_cracked_by_t1(flatness_graph, k)
    
    # attack_success_rate = compute_attack_success_rate(attack_stats)

    # stats = HoneygenStats(
	# 	epsilon_flatness=epsilon_flatness,
	# 	attack_success_rate=attack_success_rate,
	# 	flatness_graph=flatness_graph,
	# 	cracked_by_t1=cracked_by_t1,
	# 	attack_stats=asdict(attack_stats),
	# 	success_number=asdict(success_number_stats) if success_number_stats else None,
	# )
    
    # write_stats_json(stats, "C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\results\\pcfg_targeted_a1_1_attacker_tr_FIXED.json")

    # print(json.dumps(asdict(stats), indent=2))

if __name__ == "__main__":
    main()