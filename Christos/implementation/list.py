import random as rng
import re
from util import *
import random
import multiprocessing
from collections import Counter, defaultdict
from tqdm import tqdm
import os
import pickle


_chars = ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', 
            '\x08', '\x0b', '\x0c', '\x0e', '\x0f', '\x10', '\x11', '\x12', 
            '\x13', '\x14', '\x15', '\x16', '\x17', '\x18', '\x19']

_worker_model = None

def _init_worker(model):
    global _worker_model
    _worker_model = model

def _generate_for_single_password(args):

    idx, query, k, seed = args

    rng = random.Random(seed)

    res = [[query.password, _worker_model.counts.get(query.password, 0) / _worker_model.size]]
    honeywords = [query.password]
    while len(res) < k:
        hw = rng.choice(_worker_model.data)[0]
        
        if len(hw) >= 1 and hw not in honeywords:
            res.append([hw, _worker_model.counts[hw] / _worker_model.size])
            honeywords.append(hw)

    rng.shuffle(res)
    
    return [query.password, res]

class ListModel():
    
    def __init__(self):
        self.data = None
        
    def load_data(self, data):
        self.data = data
        self.size = len(data)
        self.counts = Counter(data)
    
    def generate(self, k: int, queries: list[UserData]=None, seed: int=None):
        
        res = []
        
        tasks = [
            (idx, query, k, seed + idx)
            for idx, query in enumerate(queries)
        ]

        with multiprocessing.Pool(initializer=_init_worker, initargs=(self,)) as pool:
            results = tqdm(
                pool.imap(_generate_for_single_password, tasks),
                total=len(tasks),
                desc="Generating Honeywords"
            )
            
            for honeyword_run in results:
                res.append(honeyword_run)
               
        return res


def _process_password(args):
    
    idx, i = args
    
    pw = i[0]
    fn = i[3]
    ln = i[4]
    bd = i[5][0:2]
    bm = i[5][2:4]
    by = i[5][4:8]
    un = i[2]
    em = i[1].split("@")[0]
    
    tags = dict()
    tags[_chars[0]] = f"{fn}{ln}"
    tags[_chars[1]] = f"{fn[0]}{ln[0]}"
    tags[_chars[2]] = ln
    tags[_chars[3]] = fn
    tags[_chars[4]] = f"{fn[0]}{ln}"
    tags[_chars[5]] = f"{ln}{fn[0]}"
    tags[_chars[6]] = f"{ln[0].upper()}{ln[1:]}"
    tags[_chars[7]] = f"{by}{bm}{bd}"
    tags[_chars[8]] = f"{bm}{bd}{by}"
    tags[_chars[9]] = f"{bd}{bm}{by}"
    tags[_chars[10]] = f"{bd}{bm}"
    tags[_chars[11]] = by
    tags[_chars[12]] = f"{by}{bm}"
    tags[_chars[13]] = f"{bm}{by}"
    tags[_chars[14]] = f"{by[2:]}{bm}{bd}"
    tags[_chars[15]] = f"{bm}{bd}{by[2:]}"
    tags[_chars[16]] = f"{bd}{bm}{by[2:]}"
    tags[_chars[17]] = un
    tags[_chars[18]] = em
    regex = re.search(r"([a-zA-Z]+)(\d+)", un)
    if regex:
        tags[_chars[19]] = regex.group(1)
        tags[_chars[20]] = regex.group(2)
    regex = re.search(r"([a-zA-Z]+)(\d+)", em)
    if regex:
        tags[_chars[21]] = regex.group(1)
        tags[_chars[22]] = regex.group(2)
        
    return tokenize_password(pw, tags)    

def _generate_for_single_password_targeted(args):

    idx, query, k, seed, replacement = args

    rng = random.Random(seed)

    values = []
    if replacement:
        fn = query.first_name
        ln = query.last_name
        bd = query.birthday[0:2]
        bm = query.birthday[2:4]
        by = query.birthday[4:8]
        un = query.username
        em = query.email.split("@")[0]
        
        tags = dict()
        tags[_chars[0]] = f"{fn}{ln}"
        tags[_chars[1]] = f"{fn[0]}{ln[0]}"
        tags[_chars[2]] = ln
        tags[_chars[3]] = fn
        tags[_chars[4]] = f"{fn[0]}{ln}"
        tags[_chars[5]] = f"{ln}{fn[0]}"
        tags[_chars[6]] = f"{ln[0].upper()}{ln[1:]}"
        tags[_chars[7]] = f"{by}{bm}{bd}"
        tags[_chars[8]] = f"{bm}{bd}{by}"
        tags[_chars[9]] = f"{bd}{bm}{by}"
        tags[_chars[10]] = f"{bd}{bm}"
        tags[_chars[11]] = by
        tags[_chars[12]] = f"{by}{bm}"
        tags[_chars[13]] = f"{bm}{by}"
        tags[_chars[14]] = f"{by[2:]}{bm}{bd}"
        tags[_chars[15]] = f"{bm}{bd}{by[2:]}"
        tags[_chars[16]] = f"{bd}{bm}{by[2:]}"
        tags[_chars[17]] = un
        tags[_chars[18]] = em
        regex = re.search(r"([a-zA-Z]+)(\d+)", un)
        if regex:
            tags[_chars[19]] = regex.group(1)
            tags[_chars[20]] = regex.group(2)
        regex = re.search(r"([a-zA-Z]+)(\d+)", em)
        if regex:
            tags[_chars[21]] = regex.group(1)
            tags[_chars[22]] = regex.group(2)
    
    pw_processed = _process_password((0, query))
    res = [[pw_processed, _worker_model.counts.get(pw_processed, 0) / _worker_model.size]]
    honeywords = [pw_processed]
    
    while len(res) < k:
        
        hw = rng.choice(_worker_model.data)
        
        if len(hw[0]) >= 1 and hw not in honeywords:
            
            if replacement:
                hw_final = tokenize_password(hw[0], tags)
            else:
                hw_final = hw[0]
            res.append([hw_final, _worker_model.counts[hw[0]] / _worker_model.size])
            honeywords.append(hw_final)
        
    rng.shuffle(res)
    
    return [pw_processed, res]

class TargetedListModel():
    
    def __init__(self, path: str = None):
        
        if path:
            with open(path, 'rb') as f:
                model = pickle.load(f)
            self.data = model['data']
            self.size = model['size']
            self.counts = model['counts']
        else:
            self.data = None
            
    def print(self):
        
        with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\data\synthetic_test_tokenized.txt", "w", encoding="utf-8") as f1:
            f1.write("\n".join(self.data) + "\n")
            
        return self.data
    
    def load_data(self, data):

        tasks = [
            (idx, entry)
            for idx, entry in enumerate(data)
        ]

        data_processed = []
        with multiprocessing.Pool() as pool:
            results = tqdm(
                pool.imap(_process_password, tasks),
                total=len(tasks),
                desc="Training Targeted List Model."
            )
            
            for result in results:
                data_processed.append(result)
                
        self.data = data_processed
        self.size = len(data)
        self.counts = Counter(data_processed)
        
        os.makedirs('./Christos/trained_models', exist_ok=True)
        with open('./Christos/trained_models/list_targeted.pickle', 'wb') as f:
            pickle.dump({"data": self.data, "size": self.size, "counts": self.counts}, f)
            
    def generate(self, k: int, queries: list[UserData]=None, seed: int=None, replacement: bool = False):
        
        res = []
        
        tasks = [
            (idx, query, k, seed + idx)
            for idx, query in enumerate(queries)
        ]

        with multiprocessing.Pool(initializer=_init_worker, initargs=(self,)) as pool:
            results = tqdm(
                pool.imap(_generate_for_single_password_targeted, tasks),
                total=len(tasks),
                desc="Generating Honeywords"
            )
            
            for honeyword_run in results:
                res.append(honeyword_run)
        
        return res