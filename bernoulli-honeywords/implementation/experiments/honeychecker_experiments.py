import utils

from honeychecker.system import HoneycheckerSystem
from honeychecker.plots import plot_experiment_1, plot_experiment_2, plot_experiment_3, plot_experiment_4

'''
Calculate the false detection probability (fdp) with the formulas from the paper.
'''
def calculate_fdp(num_attempts, p_h, attacked_accounts):
    hwin = 1 - (1 - p_h) ** num_attempts
    fdp = 1 - (1 - hwin) ** attacked_accounts

    return hwin, fdp

'''
Simulate a raising alarm attacker (raat). A raat wants to enter a honeyword in order to induce a false alarm, but 
they did not breach the site.
'''
def simulate_raat_fdp(honeychecker_sys, username, num_attempts):
    # Keep track of the results from the raat's attempts.
    counts = {"failure": 0, "alarm": 0, "success": 0}

    # The raat attempts num_attempts times to introduce a password.
    for _ in range(num_attempts):
        guess = utils.generate_random_password()
        outcome = honeychecker_sys.login(username, guess)
        counts[outcome] += 1

    print("Results:")
    print(f"    failure  : {counts['failure']}")
    print(f"    alarm    : {counts['alarm']}")
    print(f"    success  : {counts['success']}  ")

    # Calculate the observed p_h
    observed_alarm_rate = counts["alarm"] / num_attempts
    print(f"\n  Observed alarm rate : {observed_alarm_rate}")
    print(f"  Expected alarm rate (≈ p_h) : {honeychecker_sys.p_h}\n")

    return observed_alarm_rate

'''
A breaching attacker (brat) attacking one account. The attacker breached the site and has access to the accounts' bloom filters
and to a list of ranked passwords.
'''
def attack_single_account_brat(honeychecker_sys, username, account):
    # The account is not in the system.
    if username not in honeychecker_sys.server.db:
        return "no_candidate"

    # The attacker uses the best candidate password for loging in into the account.
    best_candidate_password = account["candidate"]

    # No candidate was found.
    if best_candidate_password is None:
        return "no_candidate"

    # Brat logs in using the best candidate found.
    result = honeychecker_sys.login(username, best_candidate_password)

    if result == "alarm":
        # A honeyword was input so the breach was detected.
        return "detected"
    elif result == "success":
        # The real password was input, so the breach was undetected and the brat gained access to the account.
        return "undetected"

'''
Sort accounts based on how they appear in the password list.
'''
def sort_accounts_by_password_rank(honeychecker_sys, accounts, password_ranking):
    # Give a rank to each password based on how they appear in the list.
    ranked_accounts = []

    for username, _ in accounts:
        # Attacker has access to the account's salt and bloom filter.
        account = honeychecker_sys.server.db[username]
        salt = account["salt"]
        bloom = account["bloom"]

        best_rank = float("inf")
        best_candidate = None
        # Attacker goes through his password dictionary and checks if there are any matches with the user's bloom filter.
        for rank, pw in enumerate(password_ranking):
            # If a match is found, the attacker saves the rank and the best candidate for that account.
            if bloom.in_B(utils.hash_password(pw, salt)):
                best_rank = rank
                best_candidate = pw
                break

        # The best candidate is saved as well to perform less operations.
        ranked_accounts.append({
            "username": username,
            "rank": best_rank,
            "candidate": best_candidate,
        })

    # Sort accounts based on their rank. Lower ranks means easier to access
    ranked_accounts.sort(key=lambda x: x["rank"])

    return ranked_accounts

'''
Simulate a brat that attacks n_attacked accounts. Each trial: build accounts once, rank once, attack in order until the first detection, 
record its position. Then tdp(n) = fraction of trials whose first detection occurred within the first n attacked accounts.
'''
def simulate_brat_tdp(p_h, password_pool, password_ranking, n_values, trials, N, counts):
    # Count how many trials were detected by the time n accounts were attacked.
    detected_within = {n: 0 for n in n_values}

    for _ in range(trials):
        # New system for each trial.
        honeychecker_sys = HoneycheckerSystem(b=128, k=20, p_h=p_h)
        # Register users in the system.
        accounts = utils.register_users(honeychecker_sys, N, password_pool, counts)
        # Compute a sorted list of accounts based on their password rank.
        ranked_accounts = sort_accounts_by_password_rank(honeychecker_sys, accounts, password_ranking)

        # Only accounts the attacker can actually attack.
        attackable = [a for a in ranked_accounts if a["candidate"] is not None]

        # Find the 1-indexed position of the first detection.
        first_detection = None
        for i, a in enumerate(attackable):
            if attack_single_account_brat(honeychecker_sys, a["username"], a) == "detected":
                first_detection = i + 1
                break

        # For each threshold n, this trial is "detected within n" iff first detection <= n.
        for n in n_values:
            if first_detection is not None and first_detection <= n:
                detected_within[n] += 1

    return {n: detected_within[n] / trials for n in n_values}

'''
Experiment 1 bounds the fdp value as in chapter IV, section F(1) from the paper.
'''
def experiment_1():
    print("\n" + "="*60)
    print("EXPERIMENT 1 - BOUNDING FDP VALUE")
    print("="*60)

    exponent = -1
    results = []

    # Calculate the fdp with the numbers from chapter IV, section F(1) from the paper.
    _, fdp_depth = calculate_fdp(num_attempts=10 ** 6, p_h=10 ** exponent, attacked_accounts=10)
    _, fdp_breadth = calculate_fdp(num_attempts=10 ** 4, p_h=10 ** exponent, attacked_accounts=1000)
    results.append((10 ** exponent, fdp_depth, fdp_breadth))
    # Shrink p_h until we reach a fdp lower than 0.1 for both depth and breadth-first attacks.
    while fdp_depth > 0.1 or fdp_breadth > 0.1:
        exponent -= 1

        _, fdp_depth = calculate_fdp(num_attempts=10 ** 6, p_h=10 ** exponent, attacked_accounts=10)
        _, fdp_breadth = calculate_fdp(num_attempts=10 ** 4, p_h=10 ** exponent, attacked_accounts=1000)
        
        results.append((10 ** exponent, fdp_depth, fdp_breadth))

    print(f"FDP Depth-first: {fdp_depth} with p_h: {10 ** exponent}")
    print(f"\nFDP Breadth-first: {fdp_breadth} with p_h: {10 ** exponent}")

    return results

'''
Experiment 2 checks how different values of p_h affect the fdp. This experiment ensures the system is correct.
'''
def experiment_2():
    print("\n" + "="*60)
    print("EXPERIMENT 2 - EFFECTS OF DIFFERENT P_H VALUES ON FDP")
    print("="*60)
    p_h_values = [0.00001, 0.0001, 0.001, 0.005, 0.01, 0.05, 0.1]
    results = []
    num_attempts = 10000

    # For every p_h value, simulate a raat attack for one account.
    for p_h in p_h_values:
        honeychecker_sys = HoneycheckerSystem(b=128, k=20, p_h=p_h)
        honeychecker_sys.register_user("alice", "CorrectPasswordWOW!")
        observed = simulate_raat_fdp(honeychecker_sys, "alice", num_attempts)
        results.append((observed, p_h))

    return results

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
        tdp_by_n = simulate_brat_tdp(p_h, password_pool, password_ranking, n_values, TRIALS, N, counts)
        results[label] = {"n": n_values, "tdp": [tdp_by_n[n] for n in n_values]}
        for n in n_values:
            print(f"  {label}  n={n:3d}  tdp={tdp_by_n[n]:.3f}")

    return results, n_values, N

'''
For each account, check if an alarm was raised or if the attacker managed to access it.
'''
def success_vs_alarm(honeychecker_sys, accounts, password_ranking, T2=10000):
    total_honeyword_attempts = 0
    total_real_successes = 0
    curve_x = [0]
    curve_y = [0]

    scored = sort_accounts_by_password_rank(honeychecker_sys, accounts, password_ranking)

    for acc in scored:
        username = acc["username"]

        if total_honeyword_attempts >= T2:
            break

        outcome = attack_single_account_brat(honeychecker_sys, username, acc)

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
Experiment 4 calculates the success vs alarm rate.
'''
def experiment_4(data, counts):
    print("\n" + "="*60)
    print("EXPERIMENT 4 - SUCCESS VS ALARM GRAPH")
    print("="*60)

    password_ranking = data[:100000]
    password_pool = data[:100000]

    N = 1000
    T2 = 10000

    honeychecker_sys = HoneycheckerSystem(b=128, k=20, p_h=0.05)

    accounts = utils.register_users(honeychecker_sys, N, password_pool, counts)

    x, y = success_vs_alarm(honeychecker_sys, accounts, password_ranking, T2)

    print(f"  {y[-1]} real passwords found in {x[-1]} honeyword attempts")

    return (x, y)

'''
Run experiments.
'''
def run_simulation(ranking, ranking_counts):
    results_1 = experiment_1()
    plot_experiment_1(results_1)

    results_2 = experiment_2()
    plot_experiment_2(results_2)

    results, n_values, N = experiment_3(ranking, ranking_counts)
    plot_experiment_3(results, n_values, N)

    (x, y) = experiment_4(ranking, ranking_counts)
    plot_experiment_4((x, y))

    return results, n_values, N, (x, y)
