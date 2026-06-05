from legacy_pcfg_master.python_pcfg_cracker_version3.pcfg_trainer import train
from legacy_pcfg_master.python_pcfg_cracker_version3.honeyword_gen import generate

import re
from util import UserData


class PCFGModel():
    
    def __init__(self):
        self.data = None
        self.rule_name = None

    def load_data(self, data=None, rule_name="Default"):
        
        if data:
            train(data=data, rule_name=rule_name)
        self.rule_name = rule_name
     
    def generate(self, k: int, mode:str="honeywords", queries: list[UserData]=None, seed: int=None, structures: dict[str, str]=None):
        
        if mode == "honeywords":
            queries_processed = []
            for query in queries:
                queries_processed.append([query.password, structures[query.password], None])
            
            return generate(queries=queries_processed, k=k-1, rule_name=self.rule_name, seed=seed)
        else:
            return generate(k=k, rule_name=self.rule_name, mode="passwords")
    
class TargetedPCFGModel():
    
    def __init__(self):
        self.data = None
        self.rule_name = None

    def load_data(self, data=None, rule_name="Default"):
        
        if data:
            train(data=data, rule_name=rule_name, targeted=True)
        self.rule_name = rule_name
     
    def generate(self, k: int, mode:str="honeywords", queries: list[UserData]=None, seed: int=None, structures: dict[str, str] = None):
        
        queries_processed = []
        for query in queries:
            pw = query.password
            
            if pw not in structures:
                continue
            
            fn = query.first_name
            ln = query.last_name
            bd = query.birthday[0:2]
            bm = query.birthday[5][2:4]
            by = query.birthday[5][4:8]
            un = query.username[2]
            em = query.email[1].split("@")[0]
        
            tags = dict()
            tags["N1"] = f"{fn}{ln}"
            tags["N2"] = f"{fn[0]}{ln[0]}"
            tags["N3"] = ln
            tags["N4"] = fn
            tags["N5"] = f"{fn[0]}{ln}"
            tags["N6"] = f"{ln}{fn[0]}"
            tags["N7"] = f"{ln[0].upper()}{ln[1:]}"
            tags["B1"] = f"{by}{bm}{bd}"
            tags["B2"] = f"{bm}{bd}{by}"
            tags["B3"] = f"{bd}{bm}{by}"
            tags["B4"] = f"{bd}{bm}"
            tags["B5"] = by
            tags["B6"] = f"{by}{bm}"
            tags["B7"] = f"{bm}{by}"
            tags["B8"] = f"{by[2:]}{bm}{bd}"
            tags["B9"] = f"{bm}{bd}{by[2:]}"
            tags["B10"] = f"{bd}{bm}{by[2:]}"
            tags["U1"] = un
            tags["E1"] = em
            regex = re.search(r"([a-zA-Z]+)(\d+)", un)
            if regex:
                tags["U2"] = regex.group(1)
                tags["U3"] = regex.group(2)
            regex = re.search(r"([a-zA-Z]+)(\d+)", em)
            if regex:
                tags["E2"] = regex.group(1)
                tags["E3"] = regex.group(2)
                
            queries_processed.append([pw, structures[pw], tags])
        
        return generate(queries=queries_processed, k=k-1, rule_name=self.rule_name, seed=seed)