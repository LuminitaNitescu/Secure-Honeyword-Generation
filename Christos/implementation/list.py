import random as rng
import re
from util import *
import random
import multiprocessing
from tqdm import tqdm


_worker_model = None

def _init_worker(model):
    global _worker_model
    _worker_model = model

def _generate_for_single_password(args):

    idx, query, k, seed = args

    rng = random.Random(seed)

    res = [query.password]
    while len(res) < k:
        idx = rng.sample(range(len(_worker_model.data)), 1)
        hw = _worker_model.data[idx[0]][0]
        
        if len(hw) >= 1 and hw not in res:
            res.append(hw)

    rng.shuffle(res)
    
    return res

class ListModel():
    
    def __init__(self):
        self.data = None
        
    def load_data(self, data):
        self.data = data
    
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
        
def _generate_for_single_password_targeted(args):

    idx, query, k, seed = args

    rng = random.Random(seed)

    fn_2 = query.first_name
    ln_2 = query.last_name
    bd_2 = query.birthday[0:2]
    bm_2 = query.birthday[2:4]
    by_2 = query.birthday[4:8]
    un_2 = query.username
    em_2 = query.email.split("@")[0]
    
    values = [
        f"{fn_2}{ln_2}",
        f"{fn_2[0]}{ln_2[0]}",
        ln_2,
        fn_2,
        f"{fn_2[0]}{ln_2}",
        f"{ln_2}{fn_2[0]}",
        f"{ln_2[0].upper()}{ln_2[1:]}",

        f"{by_2}{bm_2}{bd_2}",
        f"{bm_2}{bd_2}{by_2}",
        f"{bd_2}{bm_2}{by_2}",
        f"{bd_2}{bm_2}",
        by_2,
        f"{by_2}{bm_2}",
        f"{bm_2}{by_2}",
        f"{by_2[2:]}{bm_2}{bd_2}",
        f"{bm_2}{bd_2}{by_2[2:]}",
        f"{bd_2}{bm_2}{by_2[2:]}",

        un_2,

        em_2
    ]
    
    un_2_1 = None
    un_2_2 = None
    regex = re.search(r"([a-zA-Z]+)(\d+)", un_2)
    if regex:
        un_2_1 = regex.group(1)
        un_2_2 = regex.group(2)

    em_2_1 = None
    em_2_2 = None
    regex = re.search(r"([a-zA-Z]+)(\d+)", em_2)
    if regex:
        em_2_1 = regex.group(1)
        em_2_2 = regex.group(2)
    
    res = [query.password]
    while len(res) < k:
        
        idx = rng.sample(range(len(_worker_model.data)), 1)
        hw = _worker_model.data[idx[0]]
        
        if len(hw) >= 1 and hw not in res:
            
            fn_1 = hw[3]
            ln_1 = hw[4]
            bd_1 = hw[5][0:2]
            bm_1 = hw[5][2:4]
            by_1 = hw[5][4:8]
            un_1 = hw[2]
            em_1 = hw[1].split("@")[0]
            
            pii = {
                values[0]: f"{fn_1}{ln_1}",
                values[1]: f"{fn_1[0]}{ln_1[0]}",
                values[2]: ln_1,     
                values[3]: fn_1,
                values[4]: f"{fn_1[0]}{ln_1}",
                values[5]: f"{ln_1}{fn_1[0]}",
                values[6]: f"{ln_1[0].upper()}{ln_1[1:]}",

                values[7]: f"{by_1}{bm_1}{bd_1}",
                values[8]: f"{bm_1}{bd_1}{by_1}",
                values[9]: f"{bd_1}{bm_1}{by_1}",
                values[10]: f"{bd_1}{bm_1}",
                values[11]: by_1,
                values[12]: f"{by_1}{bm_1}",
                values[13]: f"{bm_1}{by_1}",
                values[14]: f"{by_1[2:]}{bm_1}{bd_1}",
                values[15]: f"{bm_1}{bd_1}{by_1[2:]}",
                values[16]: f"{bd_1}{bm_1}{by_1[2:]}",
    
                values[17]: un_1,

                values[18]: em_1
            }
            
            regex = re.search(r"([a-zA-Z]+)(\d+)", un_1)
            if regex and un_2_1 is not None:
                pii[un_2_1] = regex.group(1)
                pii[un_2_2] = regex.group(2)
                
            regex = re.search(r"([a-zA-Z]+)(\d+)", em_1)
            if regex and em_2_1 is not None:
                pii[em_2_1] = regex.group(1)
                pii[em_2_2] = regex.group(2)

            res.append(tokenize_password(hw[0], pii))
        
    rng.shuffle(res)
    
    return res

class TargetedListModel():
    
    def __init__(self):
        self.data = None
    
    def load_data(self, data):
        self.data = data
            
    def generate(self, k: int, queries: list[UserData]=None, seed: int=None):
        
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