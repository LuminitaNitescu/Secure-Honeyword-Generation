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

    # choices_bd = [
    #     f"{by}{bm}{bd}",
    #     f"{bm}{bd}{by}",
    #     f"{bd}{bm}{by}",
    #     f"{bd}{bm}",
    #     by,
    #     f"{by}{bm}",
    #     f"{bm}{by}",
    #     f"{by[2:]}{bm}{bd}",
    #     f"{bm}{bd}{by[2:]}",
    #     f"{bd}{bm}{by[2:]}",
    # ]
    choices_bd = [
        '\x00',
        '\x01',
        '\x02',
        '\x03',
        '\x04',
        '\x05',
        '\x06',
        '\x07',
        '\x08',
        '\x0b',
    ]
    return random.choice(choices_bd)


# --- Case 1: Username Split ---
def get_random_username_choice(un: str) -> str:

    # regex = re.search(r"([a-zA-Z]+)(\d+)", un)
    # choices = [un, regex.group(1), regex.group(2)]
    choices = [
        '\x0c',
        '\x0e',
        '\x0f'
    ]
    return random.choice(choices)


# --- Case 2: Name Variations ---
def get_random_name_choice(fn: str, ln: str) -> str:

    # choices = [
    #     f"{fn}{ln}",
    #     f"{fn[0]}{ln[0]}",
    #     ln,
    #     fn,
    #     f"{fn[0]}{ln}",
    #     f"{ln}{fn[0]}",
    #     f"{ln[0].upper()}{ln[1:]}",
    # ]
    choices = [
        '\x10',
        '\x11',
        '\x12',
        '\x13',
        '\x14',
        '\x15',
        '\x16'
    ]
    return random.choice(choices)


# --- Case 3: Email Split ---
def get_random_email_choice(em: str) -> str:

    # regex = re.search(r"([a-zA-Z]+)(\d+)", em)
    # choices = [em, regex.group(1), regex.group(2)]
    choices = [
        '\x17',
        '\x18',
        '\x19'
    ]
    return random.choice(choices)

def gen_synthetic_data_train_attacker():
    
    passwords = []
    with open("C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\rockyou_sorted_preprocessed_ascii.txt", "r", encoding="utf-8") as f:
        for line in f:
            password = line.strip()
            if not password:
                continue

            passwords.append([password])
    
    total_rows = len(passwords)
    filename = "synthetic_train2.csv"
    
    model = PCFGModel()
    model.load_data(data=passwords, rule_name="PasswordGeneratorNew")
    
    passwords_gen = model.generate(k=total_rows, mode="passwords")
    
    with open("synth_pass.csv", mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        
        for i, password in enumerate(passwords_gen):
            
            writer.writerow(password)
            
            if (i + 1) % 10_000 == 0:
                print(f"Progress: {i + 1:,} rows written.")
    
    # passwords_gen = []
    # with open("synth_pass.csv", "r", encoding="utf-8") as infile:

    #     reader = csv.reader(infile)

    #     for row in reader:
    #         if not row:
    #             continue

    #         passwords_gen.append("".join(row))
    
    person = Person(Locale.EN)
    datetime_provider = Datetime()
    
    cases = {
        0: 0.19409,
        1: 0.17496,
        2: 0.17967,
        3: 0.09559,
        4: 0.04647,
        5: 0.03594,
        6: 0.03080,
        7: 0.02541,
        8: 0.01557,
        9: 0.2015
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
            elif case == 10:
                
                pw = f"{get_random_name_choice(fn, ln)}{''.join(random.choices('0123456789', k=7))}"
            elif case == 8:
                
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
     
def get_password_lengths():
    
    size = 0
    lengths = []
    with open("C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\rockyou_sorted_preprocessed.txt", "r", encoding="utf-8") as f:
        for line in f:
            lengths.append(len(line.rstrip('\n')))
            size += 1
    
    res = dict()
    for k,v in Counter(lengths).items():
        res[k] = v / size
        
    with open("lengths.json", "w", encoding="utf-8") as handle:
        json.dump(res, handle, indent=2)

def ascii_conversion_and_split():
        
    data = []   
    with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\data\rockyou_sorted_preprocessed.txt", "r", encoding="utf-8") as f:
        for row in f:
            cleaned = row.encode("ascii", errors="ignore").decode("ascii").strip()
            if cleaned:
                data.append(cleaned)
            
    random.shuffle(data)
    
    with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\data\rockyou_sorted_preprocessed_ascii.txt", "w", encoding="utf-8") as f1:
        f1.write("\n".join(data) + "\n")
        
    midpoint = len(data) // 2

    part1 = data[:midpoint]
    part2 = data[midpoint:]
    
    with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\data\rockyou_sorted_preprocessed_tr.txt", "w", encoding="utf-8") as f1:
        f1.write("\n".join(part1) + "\n")
        
    with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\data\rockyou_sorted_preprocessed_ts.txt", "w", encoding="utf-8") as f2:
        f2.write("\n".join(part2) + "\n")
        
    print(len(data))
    print(len(part1))
    print(len(part2))
    
def data_to_counts_attacker_model():
        
    data = []   
    with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\data\synthetic_attacker.csv", "r", encoding="utf-8") as infile:

        reader = csv.reader(infile)

        next(reader, None)
        for row in reader:
            
            if row:
                data.append(row[0])
     
    res = sorted(Counter(data).items(), key=lambda x: x[0].encode())
    
    with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\data\synthetic_counts.txt", "w", encoding="utf-8") as f:
        for word, count in res:
            f.write(f"{word}:{count}\n")

def main() -> None:
    
    # # query = UserData("big_chungusBBBBBBBBBBBBBBB", "chAngAs22@gmail.com", "chEngEs11", "Big", "Chungus", "03052002")
    # # model = TargetedListModel()
 
    # # data = [
    # #     ["johnnnAA456Porkson1997BB?C", "johnn456@gmail.com", "porksonn999", "john", "porkson", "11121997"],
    # # ]
    
    # query = UserData("big_chungusB", "chAngAs22@gmail.com", "chEngEs11", "Big", "Chungus", "03052002")
    # # model = MarkovModel("./Christos/trained_models/markov.pickle")
    # model = TargetedPCFGModel()
    
    # # with open("C:/Users/ctamv/Documents/CS/CS4710/BreachCompilation/preprocessed_data/train_data.pickle", 'rb') as f:
    # #     data = pickle.load(f)
    # # data = list(itertools.chain.from_iterable(data))
    # # data = [[x] for x in data][:1000]
    
    # # data = []
    # # with open("synthetic.csv", mode="r", newline="", encoding="utf-8") as file:
        
    # #     reader = csv.reader(file)
    # #     header = next(reader)

    # #     row_count = 0
    # #     for row in reader:
    # #         data.append(row)
    # #         row_count += 1
            
    # #         if row_count % 10_000 == 0:
    # #             print(f"Progress: Read {row_count:,} rows...")
    
    # # query = UserData("big_chungusBBBBBBBBBBBBBBB", "chAngAs22@gmail.com", "chEngEs11", "Big", "Chungus", "03052002")
    # # model = TargetedMarkovModel()
    
    # # data = [
    # #     ["johnnnAAAA456Porkson1997?C", "johnn456@gmail.com", "porksonn999", "john", "porkson", "11121997"],
    # #     ["22chungasAAAA2000!chun", "chunchun22@gmail.com", "chungas", "chunga", "Chungsten", "11122000"]
    # # ]

    # model.load_data(rule_name="Targeted")
    # res = model.generate(k=100, query_list=[query])
    
    # aa = 0
    
    test = []
    test_pure = []
    # with open("C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\rockyou_sorted_preprocessed_ts.txt", "r", encoding="utf-8") as f:
    #     for line in f:
    #         password = line.strip()
    #         if not password:
    #             continue

    #         test.append(password)
    
    i = 0     
    with open(r"C:\Users\ctamv\Documents\CS\CS4710\Secure-Honeyword-Generation\Christos\data\synthetic_test.csv", "r", encoding="utf-8") as infile:

        reader = csv.reader(infile)

        next(reader, None)
        for row in reader:
            
            i += 1
            if i % 10_000 == 0:
                print(f"Progress: {i + 1:,} rows processed.")
            
            if row:
                tokenized_pass = process_password((i, [row[0], row[3], row[5], row[1], row[2], row[4]]))
                test.append([tokenized_pass, row[1], row[2], row[3], row[4], row[5]])
                test_pure.append(tokenized_pass)
            
    attacker = {}
    with open("C:\\Users\\ctamv\\Documents\\CS\\CS4710\\Secure-Honeyword-Generation\\Christos\\data\\synthetic_counts.txt", "r", encoding="utf-8") as f:
        for line in f:
            key, value = line.strip().rsplit(":", 1)
            attacker[key] = int(value)
            
    result = {k: attacker[k] for k in set(test_pure) & attacker.keys()}
    print(len(result))
    print(sum(list(result.values())))
    
    with open("intersection2.json", "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
        
    with open("synth_test_tokenized.csv", mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        
        for i, password in enumerate(test):
            
            writer.writerow(password)
            
            if (i + 1) % 10_000 == 0:
                print(f"Progress: {i + 1:,} rows written.")

if __name__ == "__main__":
    # gen_synthetic_data_train_attacker()
    # main()
    
    nums = [
        9,
        1,
        4,
        5,
        1,
        7,
        4,
        12,
        1,
        3,
        12,
        1,
        16,
        10,
        18,
        5,
        1,
        2,
        5,
        2,
        11,
        15,
        4,
        18,
        16,
        19,
        1,
        1,
        10,
        1,
        8,
        14,
        10,
        13,
        18,
        1,
        1,
        16,
        1,
        1,
        1,
        1,
        10,
        13,
        5,
        5,
        16,
        15,
        18,
        1,
        5,
        14,
        12,
        2,
        1,
        2,
        17,
        19,
        15,
        4,
        6,
        16,
        10,
        1,
        12,
        1,
        16,
        6,
        8,
        3,
        1,
        12,
        1,
        1,
        1,
        5,
        1,
        4,
        16,
        1,
        4,
        17,
        4,
        3,
        7,
        1,
        7,
        7,
        19,
        1,
        11,
        16,
        1,
        3,
        1,
        1,
        3,
        7,
        18,
        1,
        3,
        10,
        1,
        18,
        9,
        6,
        1,
        6,
        16,
        4,
        1,
        11,
        1,
        11,
        1,
        4,
        15,
        2,
        2,
        16,
        7,
        13,
        1,
        1,
        18,
        4,
        5,
        6,
        12,
        9,
        9,
        1,
        12,
        7,
        13,
        5,
        3,
        12,
        2,
        8,
        17,
        4,
        14,
        1,
        1,
        3,
        1,
        6,
        1,
        7,
        8,
        1,
        1,
        4,
        12,
        7,
        6,
        8,
        1,
        5,
        6,
        13,
        2,
        1,
        7,
        10,
        14,
        16,
        15,
        7,
        2,
        3,
        2,
        2,
        9,
        1,
        4,
        1,
        15,
        8,
        4,
        1,
        1,
        3,
        11,
        12,
        15,
        1,
        14,
        14,
        16,
        3,
        4,
        1,
        5,
        6,
        3,
        3,
        2,
        1,
        19,
        6,
        4,
        1,
        1,
        14,
        15,
        10,
        1,
        1,
        7,
        7,
        8,
        10,
        1,
        1,
        1,
        6,
        7,
        16,
        5,
        1,
        9,
        6,
        13,
        1,
        5,
        12,
        13,
        14,
        12,
        5,
        4,
        1,
        14,
        9,
        1,
        1,
        12,
        18,
        1,
        14,
        11,
        9,
        8,
        1,
        1,
        9,
        4,
        8,
        13,
        8,
        11,
        6,
        11,
        1,
        11,
        8,
        2,
        7,
        8,
        1,
        9,
        8,
        10,
        3,
        1,
        2,
        7,
        14,
        1,
        15,
        10,
        9,
        14,
        17,
        7,
        8,
        1,
        10,
        3,
        5,
        1,
        9,
        1,
        5,
        15,
        1,
        1,
        18,
        8,
        17,
        5,
        9,
        15,
        14,
        1,
        1,
        1,
        1,
        1,
        7,
        1,
        10,
        11,
        5,
        17,
        15,
        16,
        16,
        16,
        11,
        13,
        1,
        6,
        12,
        3,
        12,
        11,
        1,
        14,
        13,
        10,
        15,
        1,
        4,
        7,
        14,
        1,
        12,
        9,
        8,
        12,
        18,
        1,
        19,
        1,
        2,
        16,
        10,
        1,
        2,
        10,
        5,
        6,
        1,
        15,
        1,
        14,
        1,
        17,
        1,
        11,
        8,
        4,
        12,
        8,
        16,
        13,
        5,
        6,
        9,
        17,
        1,
        13,
        1,
        13,
        5,
        4,
        3,
        15,
        2,
        1,
        1,
        4,
        7,
        2,
        11,
        16,
        3,
        12,
        15,
        12,
        18,
        11,
        1,
        4,
        16,
        7,
        8,
        3,
        11,
        1,
        12,
        15,
        11,
        1,
        10,
        3,
        1,
        8,
        12,
        9,
        8,
        4,
        17,
        15,
        5,
        1,
        1,
        5,
        9,
        3,
        8,
        14,
        1,
        1,
        3,
        12,
        5,
        9,
        1,
        11,
        5,
        17,
        17,
        12,
        7,
        18,
        1,
        1,
        18,
        6,
        11,
        1,
        13,
        1,
        1,
        5,
        12,
        8,
        14,
        11,
        11,
        1,
        13,
        3,
        1,
        1,
        1,
        16,
        14,
        11,
        12,
        12,
        12,
        11,
        17,
        10,
        5,
        19,
        4,
        12,
        12,
        15,
        12,
        1,
        1,
        12,
        8,
        5,
        9,
        12,
        16,
        8,
        1,
        6,
        1,
        1,
        7,
        9,
        1,
        12,
        8,
        1,
        6,
        1,
        1,
        19,
        12,
        16,
        10,
        1,
        11,
        7,
        1,
        18,
        1,
        1,
        1,
        5,
        7,
    ]
    
    print(sum(nums))