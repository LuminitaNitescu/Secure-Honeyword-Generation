import random as rng
import re
from util import *


class ListModel():
    
    def __init__(self):
        self.data = None
        
    def load_data(self, data):
        self.data = data
     
    def generate(self, user_data: UserData, k):
        res = []
        while len(res) < k:
            idx = rng.sample(range(len(self.data)), 1)
            hw = self.data[idx[0]]
            
            if hw != user_data.password and len(hw) == len(user_data.password):
                res.append(hw)
                
        return res
        

class TargetedListModel():
    
    def __init__(self):
        self.data = None
    
    def load_data(self, data):
        self.data = data
            
    def generate(self, user_data: UserData, k):
        
        fn_2 = user_data.first_name
        ln_2 = user_data.last_name
        bd_2 = user_data.birthday[0:2]
        bm_2 = user_data.birthday[2:4]
        by_2 = user_data.birthday[4:8]
        un_2 = user_data.username
        em_2 = user_data.email.split("@")[0]
        
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
        
        res = []
        while len(res) < k:
            
            idx = rng.sample(range(len(self.data)), 1)
            hw = self.data[idx[0]]
            
            if hw[0] != user_data.password and len(hw[0]) == len(user_data.password):
                
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
        
        return res