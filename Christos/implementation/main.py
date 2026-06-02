from list import ListModel, TargetedListModel
from markov import MarkovModel, TargetedMarkovModel
from pcfg import PCFGModel, TargetedPCFGModel
from mimesis import Person, Internet, Datetime
from mimesis.locales import Locale
import random
import csv
import pickle
import itertools
import json
import matplotlib.pyplot as plt
from util import *
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict

# def gen_synthetic_data():
    
#     with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\lengths.json", "r", encoding="utf-8") as handle:
#         lengths = json.load(handle)
        
#     with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\counts.json", "r", encoding="utf-8") as handle:
#         counts = json.load(handle)
    
#     total_rows = len(data)
#     filename = "synthetic.csv"
    
#     # Initialize the specific Mimesis data providers
#     person = Person(Locale.EN)
#     internet = Internet()
#     datetime_provider = Datetime()
    
#     header = ["password", "email", "username", "first_name", "last_name", "birthday"]
    
#     print(f"Generating {total_rows:,} rows utilizing Mimesis...")
    
#     with open(filename, mode="w", newline="", encoding="utf-8") as f:
#         writer = csv.writer(f)
#         writer.writerow(header)
        
#         for i in range(total_rows):
            
#             pw = person.password(length=random.choices(lengths.keys(), weights=lengths.values(), k=1)[0])
#             fn_0 = person.first_name()
#             fn = random.choice([fn_0, fn_0.lower(), fn_0.upper()])
#             ln_0 = person.last_name()
#             ln = random.choice([ln_0, ln_0.lower(), ln_0.upper()])
            
#             row = [
#                 person.password(length=random.choices(lengths.keys(), weights=lengths.values(), k=1)[0])
#                 random.choice([fn, fn.lower(), fn.upper()]),
#                 random.choice([ln, ln.lower(), ln.upper()]),
#                 person.email(domains=["gmail.com", "yahoo.com", "@hotmail.com", "@outlook.com"]),
#                 datetime_provider.formatted_date(fmt="%d%m%Y"),
#                 person.username()
#             ]
            
#             writer.writerow(row)
            
#             if (i + 1) % 10_000 == 0:
#                 print(f"Progress: {i + 1:,} rows written.")
                
#     print(f"Finished! Saved to {filename}")

# def main() -> None:
    
#     # query = UserData("big_chungusBBBBBBBBBBBBBBB", "chAngAs22@gmail.com", "chEngEs11", "Big", "Chungus", "03052002")
#     # model = TargetedListModel()
 
#     # data = [
#     #     ["johnnnAA456Porkson1997BB?C", "johnn456@gmail.com", "porksonn999", "john", "porkson", "11121997"],
#     # ]
    
#     query = UserData("big_chungusB", "chAngAs22@gmail.com", "chEngEs11", "Big", "Chungus", "03052002")
#     # model = MarkovModel("./Christos/trained_models/markov.pickle")
#     model = TargetedPCFGModel()
    
#     # with open("C:/Users/ctamv/Documents/CS/CS4710/BreachCompilation/preprocessed_data/train_data.pickle", 'rb') as f:
#     #     data = pickle.load(f)
#     # data = list(itertools.chain.from_iterable(data))
#     # data = [[x] for x in data][:1000]
    
#     # data = []
#     # with open("synthetic.csv", mode="r", newline="", encoding="utf-8") as file:
        
#     #     reader = csv.reader(file)
#     #     header = next(reader)

#     #     row_count = 0
#     #     for row in reader:
#     #         data.append(row)
#     #         row_count += 1
            
#     #         if row_count % 10_000 == 0:
#     #             print(f"Progress: Read {row_count:,} rows...")
    
#     # query = UserData("big_chungusBBBBBBBBBBBBBBB", "chAngAs22@gmail.com", "chEngEs11", "Big", "Chungus", "03052002")
#     # model = TargetedMarkovModel()
    
#     # data = [
#     #     ["johnnnAAAA456Porkson1997?C", "johnn456@gmail.com", "porksonn999", "john", "porkson", "11121997"],
#     #     ["22chungasAAAA2000!chun", "chunchun22@gmail.com", "chungas", "chunga", "Chungsten", "11122000"]
#     # ]

#     model.load_data(rule_name="Targeted")
#     res = model.generate(10, query)
    
#     aa = 0

def main() -> None:
    
    passwords = []
    with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\data\50k_subsample\rockyou_sorted_preprocessed.txt", "r", encoding="ascii", errors="strict") as f:
        while True:
            try:
                line = f.readline()
                if not line:
                    break
                
                passwords.append(line.strip())   
            except UnicodeDecodeError:
                continue
    
    with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\data\50k_subsample\rockyou_sorted_preprocessed_ascii.txt", mode="w", encoding="utf-8") as f:
        for item in passwords:
            f.write(f"{item}\n")
     
# def main() -> None:
    
#     size = 0
#     lengths = []
#     with open("C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\rockyou_sorted_preprocessed.txt", "r", encoding="utf-8") as f:
#         for line in f:
#             lengths.append(len(line.rstrip('\n')))
#             size += 1
    
#     res = dict()
#     for k,v in Counter(lengths).items():
#         res[k] = v / size
        
#     with open("lengths.json", "w", encoding="utf-8") as handle:
#         json.dump(res, handle, indent=2)

# def main() -> None:
           
#     with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\data\50k_subsample\rockyou_sorted_preprocessed.txt", "r", encoding="utf-8") as f:
#         subsample = {line.strip() for line in f if line.strip()}

#     with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\data\rockyou_sorted_preprocessed.txt", "r", encoding="utf-8") as f:
#         difference = [line.strip() for line in f if line.strip() and line.strip() not in subsample]

#     with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\data\rockyou_sorted_preprocessed_tr2.txt", mode="w", encoding="utf-8") as f:
#         f.write("\n".join(difference) + "\n")

if __name__ == "__main__":
    main()