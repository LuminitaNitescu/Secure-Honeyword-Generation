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
import re

def get_random_birthdate_choice(by: str, bm: str, bd: str) -> str:

    choices_bd = [
        f"{by}{bm}{bd}",
        f"{bm}{bd}{by}",
        f"{bd}{bm}{by}",
        f"{bd}{bm}",
        by,
        f"{by}{bm}",
        f"{bm}{by}",
        f"{by[2:]}{bm}{bd}",
        f"{bm}{bd}{by[2:]}",
        f"{bd}{bm}{by[2:]}",
    ]
    return random.choice(choices_bd)


# --- Case 1: Username Split ---
def get_random_username_choice(un: str) -> str:

    regex = re.search(r"([a-zA-Z]+)(\d+)", un)
    choices = [un, regex.group(1), regex.group(2)]
    return random.choice(choices)


# --- Case 2: Name Variations ---
def get_random_name_choice(fn: str, ln: str) -> str:

    choices = [
        f"{fn}{ln}",
        f"{fn[0]}{ln[0]}",
        ln,
        fn,
        f"{fn[0]}{ln}",
        f"{ln}{fn[0]}",
        f"{ln[0].upper()}{ln[1:]}",
    ]
    return random.choice(choices)


# --- Case 3: Email Split ---
def get_random_email_choice(em: str) -> str:

    regex = re.search(r"([a-zA-Z]+)(\d+)", em)
    choices = [em, regex.group(1), regex.group(2)]
    return random.choice(choices)

def gen_synthetic_data():
    
    # passwords = []
    # with open("C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\rockyou_sorted_preprocessed_tr2_ascii.txt", "r", encoding="utf-8") as f:
    #     for line in f:
    #         password = line.strip()
    #         if not password:
    #             continue

    #         passwords.append([password])
    
    total_rows = 7_000_000
    filename = "synthetic2.csv"
    
    # model = PCFGModel()
    # model.load_data(rule_name="PasswordGenerator")
    
    # passwords_gen = model.generate(k=total_rows, mode="passwords")
    
    # with open("synth_pass.csv", mode="w", newline="", encoding="utf-8") as f:
    #     writer = csv.writer(f)
        
    #     for i, password in enumerate(passwords_gen):
            
    #         writer.writerow(password)
            
    #         if (i + 1) % 10_000 == 0:
    #             print(f"Progress: {i + 1:,} rows written.")
    
    passwords_gen = []
    with open("synth_pass.csv", "r", encoding="utf-8") as infile:

        reader = csv.reader(infile)

        for row in reader:
            if not row:
                continue

            passwords_gen.append("".join(row))
    
    person = Person(Locale.EN)
    datetime_provider = Datetime()
    
    cases = {
        0:  0.19409,
        1: 0.17496,
        2: 0.17967,
        3: 0.09559,
        4: 0.04647,
        5: 0.03594,
        6: 0.03080,
        7: 0.02541,
        8: 0.01749,
        9: 0.01557,
        10: 0.18401
    }
    cases_keys = list(cases.keys())
    cases_values = list(cases.values())
    
    header = ["password", "email", "username", "first_name", "last_name", "birthday"]
    
    print(f"Generating {total_rows:,} rows utilizing Mimesis...")
    
    with open(filename, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        
        for i in range(total_rows):
            
            pw = passwords_gen[i]
            fn_0 = person.first_name()
            fn = random.choice([fn_0, fn_0.lower(), fn_0.upper()])
            ln_0 = person.last_name()
            ln = random.choice([ln_0, ln_0.lower(), ln_0.upper()])
            bd_0 = datetime_provider.formatted_date(fmt="%d%m%Y"),
            bd_0 = bd_0[0]
            bd = bd_0[0:2]
            bm = bd_0[2:4]
            by = bd_0[4:8]
            un = person.username(mask="ld")
            em_0 = person.email()
            em = em_0.split("@")[0]
            
            case = random.choices(cases_keys, weights=cases_values, k=1)[0]
            if case == 0:
                    
                choice = get_random_birthdate_choice(by, bm, bd)
                if len(pw) >= len(choice):
                    idx = random.randint(0, len(pw) - len(choice))
                    pw = f"{pw[:idx]}{choice}{pw[idx + len(choice):]}"
            elif case == 1:
                
                choice = get_random_username_choice(un)
                if len(pw) >= len(choice):
                    idx = random.randint(0, len(pw) - len(choice))
                    pw = f"{pw[:idx]}{choice}{pw[idx + len(choice):]}"
            elif case == 2:
                
                choice = get_random_name_choice(fn, ln)
                if len(pw) >= len(choice):
                    idx = random.randint(0, len(pw) - len(choice))
                    pw = f"{pw[:idx]}{choice}{pw[idx + len(choice):]}"
            elif case == 3:
                
                choice = get_random_email_choice(em)
                if len(pw) >= len(choice):
                    idx = random.randint(0, len(pw) - len(choice))
                    pw = f"{pw[:idx]}{choice}{pw[idx + len(choice):]}"
            elif case == 4:
                
                pw = get_random_username_choice(un)
            elif case == 5:
                
                pw = f"{get_random_name_choice(fn, ln)}{get_random_birthdate_choice(by, bm, bd)}"
            elif case == 6:
                
                pw = get_random_birthdate_choice(by, bm, bd)
            elif case == 7:
                
                pw = get_random_email_choice(em)
            elif case == 8:
                
                pw = f"{get_random_name_choice(fn, ln)}{''.join(random.choices('0123456789', k=7))}"
            elif case == 9:
                
                pw = f"{get_random_username_choice(un)}{get_random_birthdate_choice(by, bm, bd)}"
 
            row = [
                pw,
                fn,
                ln,
                em_0,
                bd_0,
                un
            ]
            
            writer.writerow(row)
            
            if (i + 1) % 10_000 == 0:
                print(f"Progress: {i + 1:,} rows written.")
                
    print(f"Finished! Saved to {filename}")

def gen_synthetic_data_test():
    
    passwords = []
    with open("C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\rockyou_sorted_preprocessed_ts.txt", "r", encoding="utf-8") as f:
        for line in f:
            password = line.strip()
            if not password:
                continue

            passwords.append(password)
    
    filename = "synthetic_test.csv"
    total_rows = len(passwords)
    
    person = Person(Locale.EN)
    datetime_provider = Datetime()
    
    header = ["password", "email", "username", "first_name", "last_name", "birthday"]
    
    print(f"Generating {total_rows:,} rows utilizing Mimesis...")
    
    with open(filename, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        
        for i in range(total_rows):
            
            fn_0 = person.first_name()
            ln_0 = person.last_name()
            bd_0 = datetime_provider.formatted_date(fmt="%d%m%Y"),

            row = [
                passwords[i],
                random.choice([fn_0, fn_0.lower(), fn_0.upper()]),
                random.choice([ln_0, ln_0.lower(), ln_0.upper()]),
                person.email(),
                bd_0[0],
                person.username(mask="ld")
            ]
            
            writer.writerow(row)
            
            if (i + 1) % 10_000 == 0:
                print(f"Progress: {i + 1:,} rows written.")
                
    print(f"Finished! Saved to {filename}")

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
#     res = model.generate(k=100, query_list=[query])
    
#     aa = 0

# def main() -> None:
    
#     passwords = []
#     with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\data\50k_subsample\rockyou_sorted_preprocessed.txt", "r", encoding="ascii", errors="strict") as f:
#         while True:
#             try:
#                 line = f.readline()
#                 if not line:
#                     break
                
#                 passwords.append(line.strip())   
#             except UnicodeDecodeError:
#                 continue
    
#     with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\data\50k_subsample\rockyou_sorted_preprocessed_ascii.txt", mode="w", encoding="utf-8") as f:
#         for item in passwords:
#             f.write(f"{item}\n")
     
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

def main() -> None:
        
    data = []   
    with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\data\rockyou_sorted_preprocessed.txt", "r", encoding="utf-8") as f:
        for line in f:
            data.append(line.rstrip('\n'))
            
    random.shuffle(data)
        
    midpoint = len(data) // 2

    part1 = data[:midpoint]
    part2 = data[midpoint:]
    
    with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\data\rockyou_sorted_preprocessed_tr.txt", "w", encoding="utf-8") as f1:
        f1.write("\n".join(part1) + "\n")
        
    with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\data\rockyou_sorted_preprocessed_ts.txt", "w", encoding="utf-8") as f2:
        f2.write("\n".join(part2) + "\n")

if __name__ == "__main__":
    gen_synthetic_data_test()
    # main()