import utils

from matplotlib import pyplot as plt

from amnesia.local.amnesia_system import AmnesiaSystem

'''
Sort accounts based on how they appear in the password list.
'''
def sort_accounts_by_password_rank(amnesia_sys, accounts, password_ranking):
    # Give a rank to each password based on how they appear in the list.
    ranked_accounts = []

    for username, password in accounts:
        # Attacker has access to the account's salt and bloom filter.
        account = amnesia_sys.server.db[username]
        salt = account["salt"]
        bloom = account["bloom"]

        best_rank = float("inf")
        best_candidate = None
        # Attacker goes through his password dictionary and checks if there are any matches with the user's bloom filter.
        for rank, pw in enumerate(password_ranking):
            # If a match is found, the attacker saves the rank and the best candidate for that account.
            if bloom.in_B(utils.hash_password(pw, salt)) and bloom.in_M(utils.hash_password(pw, salt)):
                best_rank = rank
                best_candidate = pw
                break

        # The best candidate is saved as well to perform less operations.
        ranked_accounts.append({
            "username": username,
            "password": password,
            "rank": best_rank,
            "candidate": best_candidate,
        })

    # Sort accounts based on their rank. Lower ranks means easier to access.
    ranked_accounts.sort(key=lambda x: x["rank"])

    return ranked_accounts

'''
A breaching attacker (brat) attacking one account. The attacker breached the site and has access to the accounts' bloom filters
and to a list of ranked passwords.
'''
def attack_single_account_brat(system, username, real_password, password_ranking, L, L_prime, max_attempts=1000):
    account = system.server.db[username]
    # The account is not in the system.
    if account is None:
        return "no_candidate"
    
    stolen_salt = account["salt"]
    stolen_bloom = account["bloom"]
    
    viable_indices = dict()
    
    # Attacker gets a snapshot of the initial filter state.
    initial_M = stolen_bloom.snapshot_M()
    # Creates a list of possible candidates.
    for pw in password_ranking[:max_attempts]:
        h = utils.hash_password(pw, stolen_salt)
        idx = stolen_bloom.get_indices_for_input(h)
        if idx.issubset(initial_M):
            viable_indices[h] = idx
    
    # Real user logs in L times.
    for _ in range(L):
        _, m_snapshot = system.legitimate_login(username, real_password)
        if m_snapshot is None:
            break
        
        # Attacker updates the list of possible candidates.
        viable_indices = {h: idx for h, idx in viable_indices.items() if idx.issubset(m_snapshot)}
 
    if not viable_indices:
        return "no_candidate"
    
    best_candidate = None
    # Attacker looks for the best candidate (the one with the lowest rank from its list).
    for pw in password_ranking[:max_attempts]:
        h = utils.hash_password(pw, stolen_salt)
        if h in viable_indices:
            best_candidate = pw
            break
 
    if best_candidate is None:
        return "no_candidate"
    
    # Attacker logs in L' - L times.
    for _ in range(L_prime - L):
        result = system.login(username, best_candidate)
        if result == "alarm":
            return "detected"

    # Check if the user's login raises an alarm.
    result, _ = system.legitimate_login(username, real_password)
    if result == "alarm":
        return "detected"
    return "undetected"

'''
Simulate a brat that attacks n_attacked accounts.
'''
def simulate_tdp(password_pool, password_ranking, L, L_prime, n_attacked, N, trials, counts):
    detection_count = 0
    for _ in range(trials):
        # Fresh system each trial, fresh mark sets.
        amnesia_sys = AmnesiaSystem(b=128, k=20, p_h=0.05, p_mark=0.95, p_remark=0.065)
        accounts = utils.register_users(amnesia_sys, N, password_pool, counts)
        scored = sort_accounts_by_password_rank(amnesia_sys, accounts, password_ranking)
        targets = [(a["username"], a["password"]) for a in scored[:n_attacked]]

        trial_detected = False
        for username, real_password in targets:
            outcome = attack_single_account_brat(amnesia_sys, username, real_password, password_ranking, L, L_prime)
            if outcome == "detected":
                trial_detected = True
                break
        if trial_detected:
            detection_count += 1
    return detection_count / trials

def simulate_tdp_with_fraction_of_accounts(p_h, password_pool, password_ranking, L, L_prime, n_values, N, trials, counts):
    detected_within = {n: 0 for n in n_values}

    for _ in range(trials):
        # Fresh system each trial, fresh mark sets.
        amnesia_sys = AmnesiaSystem(b=128, k=20, p_h=p_h, p_mark=0.95, p_remark=0.065)
        # Register users in the system.
        accounts = utils.register_users(amnesia_sys, N, password_pool, counts)
        # Compute a sorted list of accounts based on their password rank.
        ranked_accounts = sort_accounts_by_password_rank(amnesia_sys, accounts, password_ranking)

        # Find the 1-indexed position of the first detection.
        first_detection = None
        for i, a in enumerate(ranked_accounts):
            if attack_single_account_brat(amnesia_sys, a["username"], a["password"], password_ranking, L, L_prime) == "detected":
                first_detection = i + 1
                break

        # For each threshold n, this trial is "detected within n" iff first detection <= n.
        for n in n_values:
            if first_detection is not None and first_detection <= n:
                detected_within[n] += 1
    return {n: detected_within[n] / trials for n in n_values}

'''
Experiment 1 computes the tdp table for varying L and L'.
'''
def experiment_1(password, counts):
    password_ranking = password[:100000]
    password_pool = password[:100000]

    N = 40
    TRIALS = 200

    print("\n" + "="*60)
    print("TABLE I - tdp(L, L′, n) varying L and L′-L")
    print("="*60)
 
    n_fixed = max(1, N // 2)
    L_values = [0, 5, 10, 15, 20]
    L_prime_deltas = [1, 6, 11, 16, 21]

    header = f"{'L \\ L′-L':>10}" + "".join(f"{d:>8}" for d in L_prime_deltas)
    print(header)
    print("-" * len(header))

    for L in L_values:
        row = f"{L:>10}"
        for delta in L_prime_deltas:
            tdp = simulate_tdp(password_pool, password_ranking, L, L+delta, n_fixed, N, TRIALS, counts)
            row += f"{tdp:>8.3f}"
        print(row)

'''
For each account, check if an alarm was raised or if the attacker managed to access it.
'''
def success_vs_alarm_amnesia(system, accounts, password_ranking,
                                  L, L_prime, T2=10000):
    total_honeyword_attempts = 0
    total_real_successes = 0
    curve_x = [0]
    curve_y = [0]

    scored = sort_accounts_by_password_rank(system, accounts, password_ranking)

    for acc in scored:
        if total_honeyword_attempts >= T2:
            break

        username = acc["username"]
        real_password = acc["password"]

        outcome = attack_single_account_brat(system, username, real_password, password_ranking, L, L_prime)

        if outcome == "detected":
            total_honeyword_attempts += 1
            curve_x.append(total_honeyword_attempts)
            curve_y.append(total_real_successes)
        elif outcome == "undetected":
            total_real_successes += 1
            curve_x.append(total_honeyword_attempts)
            curve_y.append(total_real_successes)

    return curve_x, curve_y

'''
Experiment 2 calculates the success vs alarm rate.
'''
def experiment_2(password, counts):
    print("\n" + "="*60)
    print("EXPERIMENT 2 - AMNESIA SUCCESS VS ALARM GRAPH")
    print("="*60)

    password_ranking = password[:100000]
    password_pool = password[:100000]

    N  = 1000
    T2 = 10000
    L, L_prime = 10, 31

    amnesia_sys = AmnesiaSystem(b=128, k=20, p_h=0.05, p_mark=0.95, p_remark=0.065)

    accounts = utils.register_users(amnesia_sys, N, password_pool, counts)

    x, y = success_vs_alarm_amnesia(amnesia_sys, accounts, password_ranking, L, L_prime, T2)

    print(f" {y[-1]} real passwords found in {x[-1]} honeyword attempts")

    return (x, y)

def plot_experiment_2(results):
    (x, y) = results

    plt.figure(figsize=(9, 5))
    plt.plot(x, y, label='Passwords', linewidth=2, drawstyle='default')
    plt.xlabel('Total honeyword login attempts (x)')
    plt.ylabel('Real passwords successfully found (y)')
    plt.title('Success vs. Alarm Graph - Amnesia')
    plt.legend()
    plt.tight_layout()
    plt.savefig('output/exp2_success_number_amnesia.png', dpi=150)
    plt.show()

'''
Experiment 3 calculates the tdp for different fractions of accessed accounts.
'''
def experiment_3(data, counts):
    print("\n" + "="*60)
    print("EXPERIMENT 3 - TDP curves")
    print("="*60)

    password_ranking = data[:100000]
    password_pool = data[:100000]

    N = 100
    TRIALS = 100
    n_values = [1, 2, 3, 4, 5, 10, 20, 30, 40, 50]
    results = {}
    for p_h, label in [(10 ** -2, "p_h=1e-2"), (10 ** -4, "p_h=1e-4")]:
        tdp_by_n = simulate_tdp_with_fraction_of_accounts(p_h, password_pool, password_ranking, 10, 31, n_values, N, TRIALS, counts)
        results[label] = {"n": n_values, "tdp": [tdp_by_n[n] for n in n_values]}
        for n in n_values:
            print(f"  {label}  n={n:3d}  tdp={tdp_by_n[n]:.3f}")

    return results, n_values, N

def plot_experiment_3(results, n_values, N):
    fig, axes = plt.subplots(1, 2, figsize=(13, 5), sharey=True)
    fig.suptitle("TDP vs n/N - Amnesia", fontsize=13)
 
    x_vals = [n / N for n in n_values]
 
    configs = [("p_h=1e-2", "p_h = 1e-2"), ("p_h=1e-4", "p_h = 1e-4")]
 
    for ax, (label, title) in zip(axes, configs):
        data = results[label]
        
        ax.plot(x_vals, data["tdp"], marker='o', linewidth=2)
 
        ax.axhline(y=0.5, color='gray', linestyle='--', alpha=0.5, label='tdp = 0.5')
 
        ax.set_title(title)
        ax.set_xlabel("Fraction of accounts attacked (n/N)")
        ax.set_ylabel("True Detection Probability tdp(n)")
        ax.set_xlim(0, 0.5)
        ax.set_ylim(0, 1.05)
        ax.legend(fontsize=9)
        ax.grid(True, alpha=0.3)
 
    plt.tight_layout()
    plt.savefig("output/exp3_amnesia_tdp_curves.png", dpi=150)
    plt.show()

'''
Run experiments.
'''
def run_simulation(ranking, ranking_counts):
    experiment_1(ranking, ranking_counts)

    (x, y) = experiment_2(ranking, ranking_counts)
    plot_experiment_2((x, y))

    results, n_values, N = experiment_3(ranking, ranking_counts)
    plot_experiment_3(results, n_values, N)

    return results, n_values, N, (x, y)
 