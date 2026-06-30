import pickle
import os
from collections import defaultdict, deque
import re
import itertools
from multiprocessing import Pool, Manager
from functools import partial
from util import *
import math
from tqdm import tqdm
import random
import multiprocessing


_chars = ['\x10', '\x11', '\x12', '\x13', '\x14', '\x15', '\x16', '\x00', 
        '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', 
        '\x08', '\x0b', '\x0c', '\x17', '\x0e', '\x0f', '\x18', '\x19']

_worker_model = None

def _init_worker(model):
    global _worker_model
    _worker_model = model

def _generate_for_single_password(args):

    idx, query, k, seed = args
    
    keys = _worker_model.start_preprocessed[0]
    probs = _worker_model.start_preprocessed[1]
    rng = random.Random(seed)

    res = [[query.password, _worker_model.prob_pw(word=query.password)]]
    honeywords = {query.password}
    while len(res) < k:         
        cur = rng.choices(keys, weights=probs, k=1)[0]
        hw_parts = list(cur)
        
        log_p = math.log(_worker_model.starts[cur])
        
        queue = deque(cur, maxlen=4)
        # while len(hw_parts) < len(user_data.password) and queue:
        while queue:
            lookup_key = "".join(queue)
            
            keys_c, weights_c = _worker_model.chain_preprocessed[lookup_key]
            nxt = rng.choices(keys_c, weights=weights_c, k=1)[0]
            
            log_p += math.log(_worker_model.chain[lookup_key][nxt])
            
            if nxt == '\n':
                break
            
            queue.extend(nxt)
            hw_parts.extend(nxt)
        hw = "".join(hw_parts)
        
        if len(hw) >= 1 and hw not in honeywords:
            res.append([hw, math.exp(log_p)])
            honeywords.add(hw)
        
    rng.shuffle(res)
    
    return [query.password, res]

class MarkovModel():
    
    def __init__(self, path=None):
        
        if path:
            with open(path, 'rb') as f:
                model = pickle.load(f)
            self.chain = model['chain']
            self.starts = model['starts']
            
            self._preprocess()
        else:
            self.starts = None
            self.chain = None

    def _preprocess(self):
        
        self.chain_preprocessed = {
            k: (list(v.keys()), list(v.values()))
            for k, v in self.chain.items()
        }
        
        self.start_preprocessed = (list(self.starts.keys()), list(self.starts.values()))

    def _process_password(self, i):
    
        i = i[0]
                
        chain  = defaultdict(list)
        starts = []

        if len(i) < 4:
            starts.append(i)
            chain[tuple(i)].append('\n')
        else:
            i += '\n'
            starts.append(i[:4])

            window = deque(i[:4], maxlen=4)
            for ch in i[4:]:
                chain[tuple(window)].append(ch)
                window.append(ch) 
        
        return chain, starts

    def load_data(self, data):
        
        with Pool() as pool:
            results = list(
                tqdm(
                    pool.imap(self._process_password, data),
                    total=len(data),
                    desc="Markov model training: Password processing."
                )
            )
            
        total_chain = defaultdict(int)
        total_starts = 0
            
        self.chain  = dict()
        self.starts = defaultdict(float)
        for chain, starts in results:
            self.starts["".join(starts)] += 1
            total_starts += 1
            for k, v in chain.items():
                k_str = "".join(k)
                if k_str not in self.chain.keys():
                    self.chain[k_str] = defaultdict(float)
                for v_ind in v:
                    self.chain[k_str][v_ind] += 1
                total_chain[k_str] += 1
                    
        for start in self.starts.keys():
            self.starts[start] = self.starts[start] / total_starts
        for chain in self.chain.keys():
            for nxt in self.chain[chain].keys():
                self.chain[chain][nxt] = self.chain[chain][nxt] / total_chain[chain]
                
        self._preprocess()
        
        os.makedirs('../trained_models', exist_ok=True)
        with open('../trained_models/markov.pickle', 'wb') as f:
            pickle.dump({"starts": self.starts, "chain": self.chain}, f)
     
    def prob_pw(self, word: str) -> float:

        if not word:
            return 0.0

        start = word[:4]
        start_key = "".join(start)

        if start_key not in self.starts:
            return 0.0

        log_p = math.log(self.starts[start_key])

        queue = deque(start, maxlen=4)
        for ch in word[4:]:
            context_key = "".join(queue)
            if context_key not in self.chain:
                return 0.0
            transitions = self.chain[context_key]
            if ch not in transitions:
                return 0.0
            log_p += math.log(transitions[ch])
            queue.append(ch)

        context_key = "".join(queue)
        if context_key not in self.chain:
            return 0.0
        transitions = self.chain[context_key]
        if '\n' not in transitions:
            return 0.0
        log_p += math.log(transitions['\n'])

        return math.exp(log_p)
    
    def generate(self, k: int, queries: list[UserData], seed: int):
        
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
            
    chain  = defaultdict(list)
    starts = []
    
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
        
    pw = tokenize_password(pw, tags)
    
    if len(pw) < 4:
        starts.append(pw)
        chain[tuple(pw)].append('\n')
    else:
        pw += '\n'
        starts.append(pw[:4])

        window = deque(pw[:4], maxlen=4)
        for ch in pw[4:]:
            chain[tuple(window)].append(ch)
            window.append(ch)       
    
    return chain, starts 

def _generate_for_single_password_targeted(args):

    idx, query, structure, k, seed, replacement = args
    
    rng = random.Random(seed)
      
    pw = query.password  
    fn = query.first_name
    ln = query.last_name
    bd = query.birthday[0:2]
    bm = query.birthday[2:4]
    by = query.birthday[4:8]
    un = query.username
    em = query.email.split("@")[0]
    
    tags = dict()
    if replacement:
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
    
    if replacement:
        pw_processed = pw
    else:
        pw_processed = "".join(special_char_converter(structure))
    res = [[pw_processed, _worker_model.prob_pw(pw, query)]]
    honeywords = [pw_processed]
    
    keys = _worker_model.start_preprocessed[0]
    probs = _worker_model.start_preprocessed[1]

    while len(res) < k:
        cur = rng.choices(keys, weights=probs, k=1)[0]
        hw_parts = []
        for i in cur:
            hw_parts.extend(tags.get(i, i))
        
        log_p = math.log(_worker_model.starts[cur])

        queue = deque(cur, maxlen=4)
        while queue:
            lookup_key = "".join(queue)
            
            keys_c, weights_c = _worker_model.chain_preprocessed[lookup_key]
            nxt = rng.choices(keys_c, weights=weights_c, k=1)[0]
            
            log_p += math.log(_worker_model.chain[lookup_key][nxt])
            
            if nxt == '\n':
                break
            
            queue.extend(nxt)
            hw_parts.extend(tags.get(nxt, nxt))

        hw = "".join(hw_parts)
        
        if len(hw) >= 1 and hw not in honeywords:
            res.append([hw, math.exp(log_p)])
            honeywords.append(hw)
            
    rng.shuffle(res)
            
    return [pw_processed, res]

class TargetedMarkovModel():
    
    def __init__(self, path=None):
        
        if path:
            with open(path, 'rb') as f:
                model = pickle.load(f)
            self.chain = model['chain']
            self.starts = model['starts']
            
            self._preprocess()
        else:
            self.starts = None
            self.chain = None
            
    def _preprocess(self):
        
        self.chain_preprocessed = {
            k: (list(v.keys()), list(v.values()))
            for k, v in self.chain.items()
        }
        
        self.start_preprocessed = (list(self.starts.keys()), list(self.starts.values()))
        
    def load_data(self, data): 
                
        tasks = [
            (idx, entry)
            for idx, entry in enumerate(data)
        ]

        results = []
        with multiprocessing.Pool() as pool:
            results_parallel = tqdm(
                pool.imap(_process_password, tasks),
                total=len(tasks),
                desc="Training Targeted Markov Model."
            )
            
            for result in results_parallel:
                results.append(result)
            
        total_chain  = defaultdict(int)
        total_starts = 0

        self.chain  = dict()
        self.starts = defaultdict(float)
        for chain, starts in results:
            self.starts["".join(starts)] += 1
            total_starts += 1
            for k, v in chain.items():
                k_str = "".join(k)
                if k_str not in self.chain:
                    self.chain[k_str] = defaultdict(float)
                for v_ind in v:
                    self.chain[k_str][v_ind] += 1
                total_chain[k_str] += 1

        for start in self.starts:
            self.starts[start] /= total_starts
        for ctx in self.chain:
            total = total_chain[ctx]
            for nxt in self.chain[ctx]:
                self.chain[ctx][nxt] /= total
                
        self._preprocess()
    
        os.makedirs('../trained_models', exist_ok=True)
        with open('../trained_models/targeted_markov.pickle', 'wb') as f:
            pickle.dump({"starts": self.starts, "chain": self.chain}, f)
     
    def prob_pw(self, word: str, user_data: UserData) -> float:

        fn = user_data.first_name
        ln = user_data.last_name
        bd = user_data.birthday[0:2]
        bm = user_data.birthday[2:4]
        by = user_data.birthday[4:8]
        un = user_data.username
        em = user_data.email.split("@")[0]

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

        tokenized = tokenize_password(word, tags)

        start = tokenized[:4]
        start_key = "".join(start)
        if start_key not in self.starts:
            return 0.0

        log_p = math.log(self.starts[start_key])

        queue = deque(start, maxlen=4)
        for ch in tokenized[4:]:
            context_key = "".join(queue)
            if context_key not in self.chain:
                return 0.0
            transitions = self.chain[context_key]
            if ch not in transitions:
                return 0.0
            log_p += math.log(transitions[ch])
            queue.append(ch)

        context_key = "".join(queue)
        if context_key not in self.chain:
            return 0.0
        transitions = self.chain[context_key]
        if '\n' not in transitions:
            return 0.0
        log_p += math.log(transitions['\n'])

        return math.exp(log_p) 
     
    def generate(self, k: int, queries: list[UserData], seed: int, structures: dict[str, list[list[str]]], replacement: bool = False):
        
        res = []
        
        tasks = []
        for idx, query in enumerate(queries):
            structure = structures.get(query.password)
            if structure:
                tasks.append((idx, query, structure[1], k, seed + idx, replacement))

        with multiprocessing.Pool(initializer=_init_worker, initargs=(self,)) as pool:
            results = tqdm(
                pool.imap(_generate_for_single_password_targeted, tasks),
                total=len(tasks),
                desc="Generating Honeywords"
            )
            
            for honeyword_run in results:
                res.append(honeyword_run)
               
        return res