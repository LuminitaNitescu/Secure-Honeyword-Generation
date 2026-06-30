from dataclasses import asdict
from pathlib import Path
import sys
import csv
import json
import os

parent_dir = str(Path(__file__).resolve().parent.parent.parent)

if parent_dir not in sys.path:
    sys.path.append(parent_dir)

other_implement_dir = str(Path(__file__).resolve().parent.parent.parent / "Andrei" / "implementation")

if other_implement_dir not in sys.path:
    sys.path.append(other_implement_dir)

from Andrei.implementation.attackers.normalized_top_pw_hg import NormalizedTopPWModelHG, SweetwordList
from Andrei.implementation.statistics import (
	HoneygenStats,
	compute_attack_success_rate,
	compute_cracked_by_t1,
	write_stats_json,
)

from list import ListModel, TargetedListModel
from pcfg import PCFGModel, TargetedPCFGModel
from markov import MarkovModel, TargetedMarkovModel
from util import UserData, get_structures


def load_data(model_name: str, path_ts: str, path_tr: str):
    
    train = None
    test = []
    
    if model_name in ['tarlist', 'tarmarkov', 'tarpcfg']:
        with open(path_ts, "r", encoding="utf-8") as infile:

            reader = csv.reader(infile)

            next(reader, None)
            for row in reader:
                
                if row:
                    test.append(UserData(password=row[0], email=row[3], username=row[5], first_name=row[1], last_name=row[2], birthday=row[4]))
           
        if path_tr:         
            with open(path_tr, "r", encoding="utf-8") as infile:

                reader = csv.reader(infile)
                
                next(reader, None)

                train = [row for row in reader if row]
    elif model_name in ['list', 'markov', 'pcfg']:
        
        with open(path_ts, "r", encoding="utf-8") as f:
            for line in f:
                password = line.strip()
                if not password:
                    continue
                
                test.append(UserData(password=password))

        if path_tr:
            train = []
            with open(path_tr, "r", encoding="utf-8") as f:
                for line in f:
                    password = line.strip()
                    if not password:
                        continue
                    
                    train.append([password])
                
    return train, test

def gen_honeywords(model_name: str, k: int, seed: int, data_test: list[UserData], data_train: list, model_path: str, replacement: bool):

    sweetwords_unprocessed = []
    if model_name == "list":
        
        model = ListModel()
        model.load_data(data=data_train)
        sweetwords_unprocessed = model.generate(queries=data_test, k=k, seed=seed)
    elif model_name == "markov":
        
        model = MarkovModel(model_path)
        if not model_path:
            model.load_data(data=data_train)
        sweetwords_unprocessed = model.generate(queries=data_test, k=k, seed=seed)
    else:
        
        passwords = [[entry.password, entry.email, entry.username, entry.first_name, entry.last_name, entry.birthday] for entry in data_test]
        
        if model_name == "pcfg":
            
            model = PCFGModel()
            if model_path:
                model.load_data(data=data_train, rule_name=model_path)
            else:
                model.load_data(data=data_train)
        
            structures = get_structures(data=passwords, targeted=False)
            sweetwords_unprocessed = model.generate(queries=data_test, k=k, seed=seed, structures=structures)
            
        elif model_name == "tarlist":
            
            model = TargetedListModel(path=model_path)
            if not model_path:
                model.load_data(data=data_train)
                
            structures = get_structures(data=passwords, targeted=True)
            sweetwords_unprocessed = model.generate(queries=data_test, k=k, seed=seed, replacement=replacement)
            
        elif model_name == "tarmarkov":
            
            model = TargetedMarkovModel(path=model_path)
            if not model_path:
                model.load_data(data=data_train)

            structures = get_structures(data=passwords, targeted=True)
            sweetwords_unprocessed = model.generate(queries=data_test, k=k, seed=seed, structures=structures, replacement=replacement)
            
        elif model_name == "tarpcfg":
            
            model = TargetedPCFGModel()
            if model_path:
                model.load_data(data=data_train, rule_name=model_path)
            else:
                model.load_data(data=data_train)
        
            structures = get_structures(data=passwords, targeted=True)
            sweetwords_unprocessed = model.generate(queries=data_test, k=k, seed=seed, structures=structures, replacement=replacement)
            
    sweetword_lists = []
    for idx, sweetwords in enumerate(sweetwords_unprocessed):
        sweetword_lists.append(
            SweetwordList(
                user_id=str(idx),
                sweetwords=[x[0] for x in sweetwords[1]],
                real_password=sweetwords[0],
            )
        )
    return sweetword_lists

def run_experiment(model_name: str, k: int, t1: int, t2: int, sweetword_lists: list[SweetwordList], attacker_path: str, attacker_size: int, save_path: str):
    
    attacker = NormalizedTopPWModelHG(db_path=attacker_path, 
                                      dataset_size=attacker_size) 
    
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
    
    output_path = Path(save_path) / model_name
    os.makedirs(output_path, exist_ok=True) 
    output_path = output_path / f"{model_name}_{k}_{t1}_{t2}_experiment.json"
    write_stats_json(stats, str(output_path))
    
def main():    
    
    model_name = sys.argv[1]
    model_path = sys.argv[2]
    k = int(sys.argv[3])
    seed = int(sys.argv[4])
    t1 = int(sys.argv[5])
    t2 = int(sys.argv[6])
    train_path = sys.argv[7]
    test_path = sys.argv[8]
    mode = sys.argv[9]
    attacker_path = sys.argv[10]
    attacker_size = int(sys.argv[11])
    save_path = sys.argv[12]
    
    if model_path == "":
        model_path = None
    if train_path == "":
        train_path = None
        
    os.makedirs(save_path, exist_ok=True)
    
    train_data, test_data = load_data(model_name=model_name, path_tr=train_path, path_ts=test_path)
    
    if mode == "honeywords":
        
        sweetword_lists = gen_honeywords(
            model_name=model_name, 
            k = k,
            seed= seed,
            data_train=train_data,
            data_test=test_data,
            model_path=model_path,
            replacement=True,
        )
        
        json_res = {entry.real_password: entry.sweetwords for entry in sweetword_lists}
        
        output_path = Path(save_path) / f"{model_name}_honeywords.json"
        json.dump(json_res, open(output_path, "w"), indent=2)
    elif mode == "experiments":
        
        sweetword_lists = gen_honeywords(
            model_name=model_name, 
            k = k,
            seed= seed,
            data_train=train_data,
            data_test=test_data,
            model_path=model_path,
            replacement=False,
        )
        
        run_experiment(
            model_name=model_path, 
            k=k, 
            t1=t1, 
            t2=t2, 
            sweetword_lists=sweetword_lists, 
            attacker_path=attacker_path,
            attacker_size=attacker_size,
            save_path=save_path
        )

if __name__ == "__main__":
    
    main()