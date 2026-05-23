from legacy_pcfg_master.python_pcfg_cracker_version3.pcfg_trainer import train
from legacy_pcfg_master.python_pcfg_cracker_version3.honeyword_gen import generate


class PCFGModel():
    
    def __init__(self):
        self.data = None
        self.rule_name = None

    def load_data(self, data=None, rule_name="Default"):
        
        if data:
            train(data)
        self.rule_name = rule_name
     
    def generate(self, k):
        
        return generate(k)