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


def _process_password(i):
    
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

class MarkovModel():
    
    def __init__(self, path=None):
        self.data = None
        
        if path:
            with open(path, 'rb') as f:
                model = pickle.load(f)
            self.chain = model['chain']
            self.starts = model['starts']
        else:
            self.starts = None
            self.chain = None

    def load_data(self, data):
        self.data = data
        
        with Pool() as pool:
            results = list(
                tqdm(
                    pool.imap(_process_password, self.data),
                    total=len(self.data),
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
    
        os.makedirs('./Christos/trained_models', exist_ok=True)
        with open('./Christos/trained_models/markov.pickle', 'wb') as f:
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
    
    def generate(self, user_data: UserData, k, seed):
    
        keys = list(self.starts.keys())
        probs = list(self.starts.values())
        rng = random.Random(seed)
    
        res = [[user_data.password, self.prob_pw(word=user_data.password)]]
        honeywords = [user_data.password]
        while len(res) < k-1:         
            cur = rng.choices(keys, weights=probs, k=1)[0]
            hw_parts = []
            hw_parts.extend(cur)
            
            log_p = math.log(self.starts[cur])
            
            queue = deque(cur, maxlen=4)
            # while len(hw_parts) < len(user_data.password) and queue:
            while queue:
                chars = self.chain["".join(queue)]
                nxt = rng.choices(list(chars.keys()), weights=list(chars.values()), k=1)[0]
                
                log_p += math.log(chars[nxt])
                
                if nxt == '\n':
                    break
                
                queue.extend(nxt)
                hw_parts.extend(nxt)
            hw = "".join(hw_parts)
            
            if len(hw) >= 1 and hw not in honeywords:
                res.append([hw, math.exp(log_p)])
                honeywords.append(hw)
            
        rng.shuffle(res)
               
        return res

def process_password_targeted(i, chars):
            
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
            tags[chars[0]] = f"{fn}{ln}"
            tags[chars[1]] = f"{fn[0]}{ln[0]}"
            tags[chars[2]] = ln
            tags[chars[3]] = fn
            tags[chars[4]] = f"{fn[0]}{ln}"
            tags[chars[5]] = f"{ln}{fn[0]}"
            tags[chars[6]] = f"{ln[0].upper()}{ln[1:]}"
            tags[chars[7]] = f"{by}{bm}{bd}"
            tags[chars[8]] = f"{bm}{bd}{by}"
            tags[chars[9]] = f"{bd}{bm}{by}"
            tags[chars[10]] = f"{bd}{bm}"
            tags[chars[11]] = by
            tags[chars[12]] = f"{by}{bm}"
            tags[chars[13]] = f"{bm}{by}"
            tags[chars[14]] = f"{by[2:]}{bm}{bd}"
            tags[chars[15]] = f"{bm}{bd}{by[2:]}"
            tags[chars[16]] = f"{bd}{bm}{by[2:]}"
            tags[chars[17]] = un
            tags[chars[18]] = em
            regex = re.search(r"([a-zA-Z]+)(\d+)", un)
            if regex:
                tags[chars[19]] = regex.group(1)
                tags[chars[20]] = regex.group(2)
            regex = re.search(r"([a-zA-Z]+)(\d+)", em)
            if regex:
                tags[chars[21]] = regex.group(1)
                tags[chars[22]] = regex.group(2)
                
            pw = tokenize_password(pw, tags)
            
            if len(pw) < 4:
                starts.append(pw)
            else:
                pw += '\n'
                starts.append(pw[:4])

                window = deque(pw[:4], maxlen=4)
                for ch in pw[4:]:
                    chain[tuple(window)].append(ch)
                    window.append(ch)       
            
            return chain, starts 

class TargetedMarkovModel():
    
    def __init__(self, path=None):
        self.data = None
        
        if path:
            with open(path, 'rb') as f:
                model = pickle.load(f)
            self.chain = model['chain']
            self.starts = model['starts']
        else:
            self.starts = None
            self.chain = None
        
        self.chars = ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', 
                                        '\x08', '\x0b', '\x0c', '\x0e', '\x0f', '\x10', '\x11', '\x12', 
                                        '\x13', '\x14', '\x15', '\x16', '\x17', '\x18', '\x19']
        
    def load_data(self, data):
        self.data = data 
        
        with Manager() as manager:
            shared_list = manager.list(self.chars)
            fn = partial(process_password_targeted, shared_list)
            with Pool() as pool:
                results = pool.map(fn, self.data)
            
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
    
        os.makedirs('./Christos/trained_models', exist_ok=True)
        with open('./Christos/trained_models/targeted_markov.pickle', 'wb') as f:
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
        tags[self.chars[0]] = f"{fn}{ln}"
        tags[self.chars[1]] = f"{fn[0]}{ln[0]}"
        tags[self.chars[2]] = ln
        tags[self.chars[3]] = fn
        tags[self.chars[4]] = f"{fn[0]}{ln}"
        tags[self.chars[5]] = f"{ln}{fn[0]}"
        tags[self.chars[6]] = f"{ln[0].upper()}{ln[1:]}"
        tags[self.chars[7]] = f"{by}{bm}{bd}"
        tags[self.chars[8]] = f"{bm}{bd}{by}"
        tags[self.chars[9]] = f"{bd}{bm}{by}"
        tags[self.chars[10]] = f"{bd}{bm}"
        tags[self.chars[11]] = by
        tags[self.chars[12]] = f"{by}{bm}"
        tags[self.chars[13]] = f"{bm}{by}"
        tags[self.chars[14]] = f"{by[2:]}{bm}{bd}"
        tags[self.chars[15]] = f"{bm}{bd}{by[2:]}"
        tags[self.chars[16]] = f"{bd}{bm}{by[2:]}"
        tags[self.chars[17]] = un
        tags[self.chars[18]] = em
        regex = re.search(r"([a-zA-Z]+)(\d+)", un)
        if regex:
            tags[self.chars[19]] = regex.group(1)
            tags[self.chars[20]] = regex.group(2)
        regex = re.search(r"([a-zA-Z]+)(\d+)", em)
        if regex:
            tags[self.chars[21]] = regex.group(1)
            tags[self.chars[22]] = regex.group(2)

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
     
    def generate(self, user_data: UserData, k, seed):
        
        rng = random.Random(seed)
        
        fn = user_data.first_name
        ln = user_data.last_name
        bd = user_data.birthday[0:2]
        bm = user_data.birthday[2:4]
        by = user_data.birthday[4:8]
        un = user_data.username
        em = user_data.email.split("@")[0]
        
        tags = dict()
        tags[self.chars[0]] = f"{fn}{ln}"
        tags[self.chars[1]] = f"{fn[0]}{ln[0]}"
        tags[self.chars[2]] = ln
        tags[self.chars[3]] = fn
        tags[self.chars[4]] = f"{fn[0]}{ln}"
        tags[self.chars[5]] = f"{ln}{fn[0]}"
        tags[self.chars[6]] = f"{ln[0].upper()}{ln[1:]}"
        tags[self.chars[7]] = f"{by}{bm}{bd}"
        tags[self.chars[8]] = f"{bm}{bd}{by}"
        tags[self.chars[9]] = f"{bd}{bm}{by}"
        tags[self.chars[10]] = f"{bd}{bm}"
        tags[self.chars[11]] = by
        tags[self.chars[12]] = f"{by}{bm}"
        tags[self.chars[13]] = f"{bm}{by}"
        tags[self.chars[14]] = f"{by[2:]}{bm}{bd}"
        tags[self.chars[15]] = f"{bm}{bd}{by[2:]}"
        tags[self.chars[16]] = f"{bd}{bm}{by[2:]}"
        tags[self.chars[17]] = un
        tags[self.chars[18]] = em
        regex = re.search(r"([a-zA-Z]+)(\d+)", un)
        if regex:
            tags[self.chars[19]] = regex.group(1)
            tags[self.chars[20]] = regex.group(2)
        regex = re.search(r"([a-zA-Z]+)(\d+)", em)
        if regex:
            tags[self.chars[21]] = regex.group(1)
            tags[self.chars[22]] = regex.group(2)
        
        res = [[user_data.password, self.prob_pw(user_data.password, user_data)]]
        honeywords = [user_data.password]

        keys   = list(self.starts.keys())
        probs  = list(self.starts.values())

        while len(res) < k-1:
            cur = rng.choices(keys, weights=probs, k=1)[0]
            hw_parts = []
            for i in cur:
                hw_parts.extend(tags.get(i, i))
            
            log_p = math.log(self.starts[cur])

            queue = deque(cur, maxlen=4)
            while queue:
                chars = self.chain["".join(queue)]
                nxt = rng.choices(list(chars.keys()), weights=list(chars.values()), k=1)[0]
                
                log_p += math.log(chars[nxt])
                
                if nxt == '\n':
                    break
                
                queue.extend(nxt)
                hw_parts.extend(tags.get(nxt, nxt))

            hw = "".join(hw_parts)
            
            if len(hw) >= 1 and hw not in honeywords:
                res.append([hw, math.exp(log_p)])
                honeywords.append(hw)
                
        rng.shuffle(res)
                
        return res