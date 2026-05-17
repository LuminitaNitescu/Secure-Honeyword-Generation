import random as rng
import ahocorasick
import re


class UserData():
    
    def __init__(self, password: str, email=None, username=None, first_name=None, last_name=None, birthday=None):
        self.data = None
        
        self.password = password
        self.email = email
        self.username = username
        self.first_name = first_name
        self.last_name = last_name
        self.birthday = birthday


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
        
        fn_2 = user_data.first_name or ""
        ln_2 = user_data.last_name or ""
        bd_2 = user_data.birthday[0:2] if user_data.birthday else ""
        bm_2 = user_data.birthday[2:4] if user_data.birthday else ""
        by_2 = user_data.birthday[4:8] if user_data.birthday else ""
        un_2 = user_data.username or ""
        em_2 = user_data.email.split("@")[0] if user_data.email else ""
        
        values = [
            f"{fn_2}{ln_2}",
            f"{fn_2[0] if fn_2 else ''}{ln_2[0] if ln_2 else ''}",
            ln_2,
            fn_2,
            f"{fn_2[0] if fn_2 else ''}{ln_2}",
            f"{ln_2}{fn_2[0] if fn_2 else ''}",
            f"{ln_2[0].upper() if ln_2 else ''}{ln_2[1:] if ln_2 else ''}",

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
                em_1 = hw[1].split("@")[0] if hw[1] else ""
                
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
                    
            
                auto = ahocorasick.Automaton()
                for key, value in pii.items():
                    if value and len(value) >= 2:
                        auto.add_word(value, (key, value))
                auto.make_automaton()    
    
                matches = []
                for end_idx, (key, value) in auto.iter(hw[0]):
                    start_idx = end_idx - len(value) + 1
                    matches.append((start_idx, end_idx, key, value))
                
                if not matches:
                    res.append(hw[0])
                
                res_parts = []
                matches.sort(key=lambda x: (x[0], -len(x[3])))
                last_start = -1
                for start, end, key, value in matches:
                    if start > last_start:
                        if start != last_start + 1:
                            res_parts.append(hw[0][last_start + 1:start])
                        res_parts.append(key)
                        last_start = end
                res_parts.append(hw[0][last_start + 1:len(hw[0])])

                res.append("".join(res_parts))
        
        return res