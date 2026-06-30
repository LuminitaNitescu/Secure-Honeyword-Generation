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
from pathlib import Path
import random
from multiprocessing import Pool, cpu_count
from tqdm import tqdm
import os


# Returns a random control-char marker representing a birthdate substring.
# by: birth year, bm: birth month, bd: birth day (unused, kept for call-site compatibility)
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
# Returns a random control-char marker representing a username substring.
# un: username (unused, kept for call-site compatibility)
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
# Returns a random control-char marker representing a name variation.
# fn: first name, ln: last name (unused, kept for call-site compatibility)
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
# Returns a random control-char marker representing an email substring.
# em: email local-part (unused, kept for call-site compatibility)
def get_random_email_choice(em: str) -> str:

    # regex = re.search(r"([a-zA-Z]+)(\d+)", em)
    # choices = [em, regex.group(1), regex.group(2)]
    choices = [
        '\x17',
        '\x18',
        '\x19'
    ]
    return random.choice(choices)


_person = None
_datetime_provider = None
_cases_keys = None
_cases_values = None


# Pool initializer: seeds RNG per-process and stashes shared Mimesis providers/case weights in globals.
# cases_keys: list of case ids, cases_values: matching weights for random.choices
def _init_worker(cases_keys, cases_values):
    global _person, _datetime_provider, _cases_keys, _cases_values
    from mimesis import Person, Datetime

    random.seed(os.getpid())
    _person = Person()
    _datetime_provider = Datetime()
    _cases_keys = cases_keys
    _cases_values = cases_values


# Worker function: injects a synthetic PII fragment into a single password.
# pw: the source password to mutate
def _process_row(pw):
    person = _person
    datetime_provider = _datetime_provider
    cases_keys = _cases_keys
    cases_values = _cases_values

    fn_0 = person.first_name()
    fn = random.choice([fn_0, fn_0.lower(), fn_0.upper()])
    ln_0 = person.last_name()
    ln = random.choice([ln_0, ln_0.lower(), ln_0.upper()])
    bd_0 = datetime_provider.formatted_date(fmt="%d%m%Y")
    bd, bm, by = bd_0[0:2], bd_0[2:4], bd_0[4:8]
    un = person.username(mask="ld")
    em = person.email().split("@")[0]

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

    return pw


# Builds a synthetic targeted-password dataset by pairing rockyou passwords with generated PII, then splits into train/test CSVs.
# input_path: source password list file, output_ts_path: test CSV destination, output_tr_path: train CSV destination
def gen_synthetic_data(input_path, output_ts_path, output_tr_path):
    passwords = []
    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            password = line.strip()
            if not password:
                continue

            passwords.append(password)

    total_rows = len(passwords)

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

    rows = []
    for i in range(total_rows):

        pw = passwords[i]
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

        rows.append([
            pw,
            fn,
            ln,
            em_0,
            bd_0,
            un
        ])

        if (i + 1) % 10_000 == 0:
            print(f"Progress: {i + 1:,} rows written.")

    midpoint = total_rows // 2

    test = rows[:midpoint]
    train = rows[midpoint:]

    header = ["password", "first_name", "last_name", "email", "birthday", "username"]

    print(f"Generating {total_rows:,} rows utilizing Mimesis...")

    with open(output_ts_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)

        for row in test:
            writer.writerow(row)

    with open(output_tr_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)

        for row in train:
            writer.writerow(row)

    print(f"Finished!")


# Expands a hashmob count file into a weighted password list, injects synthetic PII in parallel, and writes results + counts.
# input_path: "password:count" file, output_pickle_path: pickled results destination, output_counts_path: sorted counts destination, total_rows: max passwords to expand
def gen_synthetic_data_attacker(input_path, output_pickle_path, output_counts_path, total_rows=100_000_000):
    passwords = []
    for line in open(input_path, "r", encoding="utf-8", errors='ignore'):

        length = len(passwords)
        if length >= total_rows:
            break

        parts = line.split(":", 1)
        if len(parts) != 2:
            continue
        passwords += [parts[0]] * int(parts[1].strip())

        if length % 10_000 == 0:
            print(f"Progress: {length} rows written.")

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

    print(f"Generating {total_rows:,} rows utilizing Mimesis...")

    chunksize = 1000

    with Pool(processes=cpu_count(), initializer=_init_worker, initargs=(cases_keys, cases_values)) as pool:
        res = list(
            tqdm(
                pool.imap(_process_row, passwords, chunksize=chunksize),
                total=total_rows,
                desc="Generating passwords",
                unit="row",
            )
        )

    with open(output_pickle_path, 'wb') as f:
        pickle.dump(res, f, protocol=pickle.HIGHEST_PROTOCOL)

    res_counts = sorted(Counter(res).items(), key=lambda x: -x[1])

    with open(output_counts_path, "w", encoding="utf-8") as f:
        for word, count in res_counts:
            f.write(f"{word}:{count}\n")

    print(f"Finished!")


# Legacy variant: pairs each password with freshly generated PII (no injection into the password) and writes a single CSV.
# input_path: source password list file, output_path: destination CSV
def gen_synthetic_data_old(input_path, output_path):
    passwords = []
    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            password = line.strip()
            if not password:
                continue

            passwords.append(password)

    total_rows = len(passwords)

    person = Person(Locale.EN)
    datetime_provider = Datetime()

    header = ["password", "first_name", "last_name", "email", "birthday", "username"]

    print(f"Generating {total_rows:,} rows utilizing Mimesis...")

    with open(output_path, mode="w", newline="", encoding="utf-8") as f:
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

    print(f"Finished! Saved to {output_path}")


# Computes the relative frequency of each password length and writes it as JSON.
# input_path: source password list file, output_path: destination JSON file
def get_password_lengths(input_path, output_path):
    size = 0
    lengths = []
    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            lengths.append(len(line.rstrip('\n')))
            size += 1

    res = dict()
    for k, v in Counter(lengths).items():
        res[k] = v / size

    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(res, handle, indent=2)


# Strips non-ASCII characters from a password list, shuffles it, and writes the full set plus a train/test split.
# input_path: source password list file, output_all_path: shuffled full-set destination, output_tr_path: train split destination, output_ts_path: test split destination
def ascii_conversion_and_split(input_path, output_all_path, output_tr_path, output_ts_path):
    data = []
    with open(input_path, "r", encoding="utf-8") as f:
        for row in f:
            cleaned = row.encode("ascii", errors="ignore").decode("ascii").strip()
            if cleaned:
                data.append(cleaned)

    random.shuffle(data)

    with open(output_all_path, "w", encoding="utf-8") as f1:
        f1.write("\n".join(data) + "\n")

    midpoint = len(data) // 2

    part1 = data[:midpoint]
    part2 = data[midpoint:]

    with open(output_tr_path, "w", encoding="utf-8") as f1:
        f1.write("\n".join(part1) + "\n")

    with open(output_ts_path, "w", encoding="utf-8") as f2:
        f2.write("\n".join(part2) + "\n")

    print(len(data))
    print(len(part1))
    print(len(part2))


# Tallies password frequencies from a plain password list and writes them sorted as "password:count" lines.
# input_path: source password list file, output_path: destination counts file
def data_to_counts_attacker_model(input_path, output_path):
    data = []
    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            password = line.strip()
            if not password:
                continue

            data.append(password)

    print(len(data))

    res = sorted(Counter(data).items(), key=lambda x: -x[1])

    with open(output_path, "w", encoding="utf-8") as f:
        for word, count in res:
            f.write(f"{word}:{count}\n")


# Finds and prints the count of passwords that appear in both a test file and a train file.
# test_path: test password list file, train_path: train password list file
def find_intersection(test_path, train_path):
    test = []
    with open(test_path, "r", encoding="utf-8") as f:
        for line in f:
            password = line.strip()
            if not password:
                continue

            test.append(password)

    train = []
    with open(train_path, "r", encoding="utf-8") as f:
        for line in f:
            password = line.strip()
            if not password:
                continue

            train.append(password)

    set2 = set(train)

    result = [item for item in test if item in set2]
    print(len(result))


# Expands a "count password" file into a flat, shuffled, ASCII-only password list and writes it to disk.
# input_path: source "count password" file, output_path: destination flat password list file
def counts_to_raw(input_path, output_path):
    items = []
    i = 0
    for line in open(input_path, "r", encoding="utf-8", errors='ignore'):
        parts = line.strip().split(maxsplit=1)
        if len(parts) != 2:
            continue
        items += [parts[1].strip().encode("ascii", errors="ignore").decode("ascii")] * int(parts[0].strip())

        i += 1
        if (i + 1) % 10_000 == 0:
            print(f"Progress: {i + 1:,} rows written.")

    random.shuffle(items)

    open(output_path, 'w').write('\n'.join(items))


# Entry point; wire up calls to the functions above with the desired file paths.
def main() -> None:
    pass


if __name__ == "__main__":
    main()