import random
import string
import hashlib

'''
Generates a random password.
'''
def generate_random_password(length=8):
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))

'''
Hash password.
'''
def hash_password(password, salt):
    return hashlib.sha256(salt + password.encode("utf-8")).hexdigest()

'''
Load password with counts from file.
'''
def load_weighted_data(path):
    passwords = []
    counts = []
    with open(path, encoding="latin-1") as f:
        for line in f:
            line = line.rstrip("\n")
            idx = line.rfind(":")
            pw = line[:idx]
            count_str = line[idx+1:]
            try:
                passwords.append(pw)
                counts.append(int(count_str))
            except ValueError:
                continue
    return passwords, counts

'''
Register n users in a system.
'''
def register_users(chosen_sys, n, password_pool, counts):
    accounts = []
    chosen = random.choices(password_pool, weights=counts, k=n)
    for i, password in enumerate(chosen):
        username = f"user_{i}"
        chosen_sys.register_user(username, password)
        accounts.append((username, password))
    return accounts
