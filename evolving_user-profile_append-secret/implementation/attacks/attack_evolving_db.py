#!/usr/bin/env python3
"""
attack_evolving_db.py

Honeyword attack evaluator for the evolving-password model, with the
frequency database left evolving during evaluation: each test password
updates the DB before its own sweetword list is generated.

Usage
-----
python attack_evolving_db.py --demo

python attack_evolving_db.py \\
    --dataset rockyou_sorted_preprocessed.txt \\
    --n_users 50000 --train_size 7170748 \\
    --save_db rockyou_half_db.json --plot

python attack_evolving_db.py \\
    --dataset rockyou_sorted_preprocessed.txt \\
    --n_users 50000 --train_size 7170748 \\
    --load_db rockyou_half_db.json --plot

Arguments
---------
--dataset       Path to the password corpus file.
--n_users       Number of test users. Default: 5000
--k             Sweetwords per user. Default: 20
--min_lev       Levenshtein typo-safety threshold. Default: 3
--strategy      Attack strategy: top_pw | norm_top_pw. Default: norm_top_pw
--T1            Max failed guesses per user. Default: 1
--T2            Global failed-guess cap. Default: 10000
--train_size    Training passwords. Default: n_users (50/50 split).
--workers       Ignored; evolution requires sequential processing. Default: 1
--seed          Fixes the train/test split and registration order. Default: 42
--plot          Plot results after the run.
--demo          Run a small demo instead of a full evaluation.
--save_db       Path to save the initial training DB (pre-evolution).
--load_db       Path to load a pre-built training DB.
--save_json     Path to save results as JSON for plot_results.py.
--output        Output file prefix. Default: honeyword_eval_evolving
"""

import argparse
import collections
import heapq
import os
import random
import sys
import time
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from frequency_db   import FrequencyDatabase, PRESET_CORPUS
    from evolving_model import generate_honeywords_evolving
    from honeychecker   import SweetwordList
except ImportError as e:
    sys.exit(
        f"Cannot import honeyword_generator.py: {e}\n"
        "Place both files in the same directory."
    )


# ─────────────────────────────────────────────────────────────
# 1.  Streaming corpus loader
# ─────────────────────────────────────────────────────────────

def stream_build(
    path: str,
    train_limit: int,
    test_limit: int,
    seed: int = 42,
) -> tuple[FrequencyDatabase, "ListPasswordModel", list[str]]:
    """
    Build a disjoint train/test split from a password corpus file via
    two-pass reservoir sampling (Vitter Algorithm R), then build the
    initial frequency database from the training half.

    Pass 1 samples (train_limit + test_limit) passwords uniformly at
    random from the full file. Pass 2 shuffles the reservoir, splits
    it, and builds the database from the training passwords only.

    The returned database holds only the training passwords; the test
    passwords are registered into it one at a time during sweetword
    generation, evolving the database as evaluation proceeds.
    """
    rng  = random.Random(seed)
    need = train_limit + test_limit

    print(f"  Pass 1/2: reservoir-sampling {need:,} passwords …")
    t0           = time.time()
    reservoir: list[str] = []
    n_seen       = 0
    report_every = 500_000

    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            pw = line.rstrip('\n\r')
            if not pw or pw.startswith('#') or not pw.isascii():
                continue
            n_seen += 1
            if len(reservoir) < need:
                reservoir.append(pw)
            else:
                j = rng.randint(0, n_seen - 1)
                if j < need:
                    reservoir[j] = pw
            if n_seen % report_every == 0:
                elapsed = time.time() - t0
                rate    = n_seen / elapsed if elapsed > 0 else 0
                print(f"  {n_seen:>12,} scanned  ({rate:,.0f} pw/s)"
                      f"  reservoir={len(reservoir):,}   ", end='\r')

    elapsed = time.time() - t0
    print(f"  {n_seen:,} passwords scanned in {elapsed:.1f}s"
          f"  ({n_seen/elapsed:,.0f} pw/s)          ")

    if len(reservoir) < need:
        print(f"  WARNING: only {len(reservoir):,} valid ASCII passwords "
              f"found (needed {need:,}). Adjusting split.")
        train_limit = int(len(reservoir) * train_limit / need)
        test_limit  = len(reservoir) - train_limit

    print(f"  Pass 2/2: building training DB "
          f"(train={train_limit:,}  test={test_limit:,}) …")
    t0 = time.time()
    rng.shuffle(reservoir)
    train_passwords = reservoir[:train_limit]
    test_passwords  = reservoir[train_limit:train_limit + test_limit]

    db      = FrequencyDatabase()
    counter: dict[str, int] = {}
    report  = max(1, train_limit // 10)
    for i, pw in enumerate(train_passwords):
        db.add_password(pw)
        counter[pw] = counter.get(pw, 0) + 1
        if (i + 1) % report == 0:
            print(f"  DB build: {i+1:,}/{train_limit:,}   ", end='\r')

    elapsed = time.time() - t0
    print(f"  Training DB built in {elapsed:.1f}s"
          f"  (will evolve as test passwords are registered)          ")

    model = ListPasswordModel.__new__(ListPasswordModel)
    model._counts = counter
    model._total  = train_limit
    model._smooth = 1.0 / (train_limit + 1)
    return db, model, test_passwords


# ─────────────────────────────────────────────────────────────
# 2.  List password model  (Wang et al. NDSS 2018, §III-B)
# ─────────────────────────────────────────────────────────────

class ListPasswordModel:
    """
    List password model with "+1" smoothing (Wang et al. §III-B).

    Trained on the static training corpus only; the attacker never
    sees the test passwords, even though the generator's database
    does. The resulting knowledge gap between generator and attacker
    is the security property the evolving model relies on.
    """

    def __init__(self, corpus: list[str]):
        self._counts: dict[str, int] = collections.Counter(corpus)
        self._total:  int            = len(corpus)
        self._smooth: float          = 1.0 / (self._total + 1)

    def prob(self, pw: str) -> float:
        c = self._counts.get(pw, 0)
        return c / self._total if c else self._smooth


# ─────────────────────────────────────────────────────────────
# 3.  Evolving sweetword generation
#
#     Each call to generate_honeywords_evolving() registers the
#     password into the shared database before building candidate
#     lists, so processing must run sequentially: each registration
#     depends on the database state left by the one before it. The
#     order of test_passwords (fixed by the seed in stream_build)
#     determines the evolution path and therefore the results.
# ─────────────────────────────────────────────────────────────

def build_sweetword_file_evolving(
    test_passwords: list[str],
    db: FrequencyDatabase,
    k: int = 20,
    min_lev: int = 3,
    verbose: bool = True,
) -> list[SweetwordList]:
    """
    Generate a sweetword list for each test password with the
    frequency database evolving as it goes: each registration
    enriches the distribution before that user's own honeywords are
    generated, and before the next user's registration is processed.

    Runs sequentially only; the database state after user i is a
    required input for user i+1, so this cannot be parallelized.
    """
    n  = len(test_passwords)
    t0 = time.time()
    records: list[SweetwordList] = []
    report = max(1, n // 20)

    for i, pw in enumerate(test_passwords):
        # generate_honeywords_evolving() registers pw into db before
        # building candidate lists; this is the evolution step.
        records.append(
            generate_honeywords_evolving(pw, db, k=k, min_lev_dist=min_lev)
        )
        if verbose and (i + 1) % report == 0:
            elapsed = time.time() - t0
            rate    = (i + 1) / elapsed
            eta     = (n - i - 1) / rate if rate > 0 else 0
            print(f"  [{i+1:>{len(str(n))},}/{n:,}]"
                  f"  {rate:.0f} pw/s  ETA {eta:.0f}s   ", end='\r')

    elapsed = time.time() - t0
    if verbose:
        print(f"  {n:,} sweetword lists generated in {elapsed:.1f}s"
              f"  ({n/elapsed:.0f} pw/s)  [evolution enabled]          ")
    return records


# ─────────────────────────────────────────────────────────────
# 4.  Attacking strategies  (Wang et al. NDSS 2018, §III-B)
# ─────────────────────────────────────────────────────────────

def _best_top_pw(
    sw: SweetwordList,
    attempted: set[str],
    model: ListPasswordModel,
) -> tuple[Optional[str], float]:
    candidates = [w for w in sw.sweetwords if w not in attempted]
    if not candidates:
        return None, 0.0
    best = max(candidates, key=model.prob)
    return best, model.prob(best)


def _best_norm_top_pw(
    sw: SweetwordList,
    attempted: set[str],
    model: ListPasswordModel,
) -> tuple[Optional[str], float]:
    """
    Normalized top-PW strategy (Wang et al. §III-B, Steps 1-3, Step 3').

    Ranks candidates using only the static training-corpus
    probabilities; the attacker has no access to the generator's
    evolved database state.
    """
    candidates = [w for w in sw.sweetwords if w not in attempted]
    if not candidates:
        return None, 0.0
    probs = {w: model.prob(w) for w in candidates}
    total = sum(probs.values())
    best  = max(candidates, key=lambda w: probs[w])
    return best, probs[best] / total


def _get_strategy(name: str):
    return _best_norm_top_pw if name == "norm_top_pw" else _best_top_pw


# ─────────────────────────────────────────────────────────────
# 5.  Success-number graph (Wang et al. Algorithm 1)
# ─────────────────────────────────────────────────────────────

def attack_success_number(
    sweetword_file: list[SweetwordList],
    model: ListPasswordModel,
    strategy: str = "norm_top_pw",
    T1: int = 1,
    T2: int = 10_000,
) -> list[tuple[int, int]]:
    """Wang et al. Algorithm 1 — Success-Number Graph."""
    get_best = _get_strategy(strategy)
    n = len(sweetword_file)

    attempted:    list[set[str]] = [set() for _ in range(n)]
    per_failures: list[int]      = [0] * n
    done:         list[bool]     = [False] * n
    total_failures  = 0
    total_successes = 0
    curve: list[tuple[int, int]] = [(0, 0)]
    heap: list[tuple[float, int]] = []

    def enqueue(i: int) -> None:
        if done[i] or per_failures[i] >= T1:
            return
        _, p = get_best(sweetword_file[i], attempted[i], model)
        if p > 0.0:
            heapq.heappush(heap, (-p, i))

    for i in range(n):
        enqueue(i)

    while heap and total_failures < T2:
        neg_pri, i = heapq.heappop(heap)
        if done[i] or per_failures[i] >= T1:
            continue
        sw         = sweetword_file[i]
        best, _    = get_best(sw, attempted[i], model)
        if best is None:
            done[i] = True
            continue
        attempted[i].add(best)
        correct = sw.sweetwords[sw.sugarword_index - 1]
        if best == correct:
            total_successes += 1
            curve.append((total_failures, total_successes))
            done[i] = True
        else:
            per_failures[i] += 1
            total_failures   += 1
            curve.append((total_failures, total_successes))
            enqueue(i)

    return curve


# ─────────────────────────────────────────────────────────────
# 6.  Flatness graph (Wang et al. Algorithm 2)
#
#     Sorts each user's sweetwords by probability once, O(k log k),
#     rather than rebuilding a probability ranking on every attempt.
# ─────────────────────────────────────────────────────────────

def attack_flatness(
    sweetword_file: list[SweetwordList],
    model: ListPasswordModel,
    strategy: str = "norm_top_pw",
) -> list[int]:
    """
    Flatness graph (Wang et al. Algorithm 2).

    Both attack strategies produce the same flatness graph (Wang et
    al. Remark 3), so this sorts by raw probability once per user and
    reads the rank of the real password directly.
    """
    ranks: list[int] = []
    for sw in sweetword_file:
        correct = sw.sweetwords[sw.sugarword_index - 1]
        ranked  = sorted(sw.sweetwords, key=model.prob, reverse=True)
        ranks.append(ranked.index(correct) + 1)
    return ranks


# ─────────────────────────────────────────────────────────────
# 7.  Metrics: epsilon-flatness and flatness CDF
# ─────────────────────────────────────────────────────────────

def epsilon_flat(ranks: list[int]) -> float:
    if not ranks:
        return 0.0
    return sum(1 for r in ranks if r == 1) / len(ranks)


def flatness_cdf(ranks: list[int], k: int) -> list[tuple[int, float]]:
    n = len(ranks)
    if n == 0:
        return [(x, 0.0) for x in range(1, k + 1)]
    return [(x, sum(1 for r in ranks if r <= x) / n)
            for x in range(1, k + 1)]


# ─────────────────────────────────────────────────────────────
# 8.  Console reporting
# ─────────────────────────────────────────────────────────────

def print_results(
    ranks: list[int],
    curve: list[tuple[int, int]],
    k: int,
    n_users: int,
    strategy: str,
    T2: int,
    dataset_name: str = "",
    seed: int = 42,
) -> None:
    eps       = epsilon_flat(ranks)
    cdf       = flatness_cdf(ranks, k)
    exp_eps   = 1.0 / k
    final_f, final_s = curve[-1] if curve else (0, 0)
    perfect_s = T2 / (k - 1)

    print()
    print("═" * 64)
    print("  EVALUATION RESULTS  [EVOLUTION ENABLED]"
          + (f"  —  {dataset_name}" if dataset_name else ""))
    print("═" * 64)
    print(f"  Users        : {n_users:,}")
    print(f"  k            : {k}")
    print(f"  Strategy     : {strategy}")
    print(f"  T2 budget    : {T2:,}")
    print(f"  Seed         : {seed}  (fixes registration order)")
    print()
    print(f"  ε-flat       : {eps:.4f}  "
          f"(perfect = {exp_eps:.4f},  ratio = {eps/exp_eps:.2f}×)")
    print(f"  Wang et al.  : ε ≈ 0.29–0.49 for Juels-Rivest methods")
    print()
    print("  Flatness CDF  (perfect line: P(x) = x/k):")
    header = f"  {'Attempts':>8}  {'P(found)':>10}  {'Perfect':>10}  {'Ratio':>8}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for x, p in cdf:
        pp = x / k
        print(f"  {x:>8}  {p:>10.4f}  {pp:>10.4f}  {p/pp:>7.2f}×")
    print()
    print(f"  Success-number @ T2={T2:,}  (T1=1):")
    print(f"    Successes   : {final_s:,} / {n_users:,}"
          f"  ({final_s/n_users*100:.2f}%)")
    print(f"    Perfect     : {perfect_s:.0f}"
          f"  ({perfect_s/n_users*100:.3f}%)")
    if perfect_s > 0:
        ratio = final_s / perfect_s
        print(f"    Ratio       : {ratio:.1f}×  "
              f"(Wang found 600–1300× for Juels-Rivest)")
    print("═" * 64)


# ─────────────────────────────────────────────────────────────
# 9.  Plotting (flatness and success-number graphs)
# ─────────────────────────────────────────────────────────────

def plot_results(
    ranks: list[int],
    curve: list[tuple[int, int]],
    k: int,
    n_users: int,
    strategy: str,
    output_prefix: str = "honeyword_eval_evolving",
    dataset_name: str = "",
) -> None:
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        print("  (matplotlib not installed — skipping plots)")
        return

    eps        = epsilon_flat(ranks)
    cdf        = flatness_cdf(ranks, k)
    xs         = [x for x, _ in cdf]
    ys         = [y for _, y in cdf]
    perfect_ys = [x / k for x in xs]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

    ax1.plot(xs, ys, 'b-o', markersize=5, linewidth=1.8,
             label=f'Evolving model — evolution ON ({strategy})')
    ax1.plot(xs, perfect_ys, 'k--', linewidth=1.5,
             label='Perfect (1/k-flat)')
    ax1.set_xlabel('Sweetword login attempts per user')
    ax1.set_ylabel('Cumulative success rate P(found in ≤ x)')
    ax1.set_title('Flatness Graph  (Wang et al. Fig. 2a)')
    ax1.legend()
    ax1.set_xlim(1, k)
    ax1.set_ylim(0, 1.05)
    ax1.grid(True, alpha=0.3)
    ax1.annotate(
        f'ε = {eps:.3f}\n(1/k = {1/k:.3f})',
        xy=(1, eps),
        xytext=(k * 0.35, min(eps + 0.10, 0.95)),
        arrowprops=dict(arrowstyle='->', color='navy'),
        fontsize=9, color='navy',
    )

    if curve:
        ax2.plot([f for f, _ in curve], [s for _, s in curve],
                 'r-', linewidth=1.5,
                 label=f'Evolving model — evolution ON ({strategy})')
    T2_val = curve[-1][0] if curve else 10_000
    ax2.plot([0, max(T2_val, 1)], [0, max(T2_val, 1) / (k - 1)],
             'k--', linewidth=1.5, label='Perfect method')
    ax2.set_xscale('log')
    ax2.set_yscale('log')
    ax2.set_xlabel('Failed honeyword login attempts')
    ax2.set_ylabel('Successful real-password logins')
    ax2.set_title('Success-Number Graph  (Wang et al. Fig. 2b)')
    ax2.legend()
    ax2.grid(True, which='both', alpha=0.3)

    tag = dataset_name or 'corpus'
    fig.suptitle(
        f'Honeyword Security [EVOLUTION ON]  —  {n_users:,} users, k={k}  [{tag}]\n'
        f'Akshima et al. Evolving-Password model  ×  Wang et al. attacker',
        fontsize=11,
    )
    plt.tight_layout()
    out = f"{output_prefix}_plots.png"
    plt.savefig(out, dpi=150, bbox_inches='tight')
    print(f"  Plot saved → {out}")


# ─────────────────────────────────────────────────────────────
# 10. CLI argument parsing
# ─────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description=(
            "Evaluate the Akshima et al. evolving-password model with "
            "evolution enabled: each test password updates the frequency "
            "DB before its sweetword list is generated, exactly as in "
            "production registration.  Processing is sequential by design."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument('--dataset',    type=str, default=None)
    p.add_argument('--n_users',    type=int, default=5000,
                   help='Number of test users.')
    p.add_argument('--k',          type=int, default=20)
    p.add_argument('--min_lev',    type=int, default=3)
    p.add_argument('--strategy',   choices=['top_pw', 'norm_top_pw'],
                   default='norm_top_pw')
    p.add_argument('--T1',         type=int, default=1)
    p.add_argument('--T2',         type=int, default=10_000)
    p.add_argument('--train_size', type=int, default=None,
                   help='Training passwords. Default = n_users (50/50).')
    p.add_argument('--workers',    type=int, default=1,
                   help='Ignored (evolution requires sequential processing).')
    p.add_argument('--seed',       type=int, default=42,
                   help='Fixes both the train/test split and registration order.')
    p.add_argument('--plot',       action='store_true')
    p.add_argument('--demo',       action='store_true')
    p.add_argument('--save_db',    type=str, default=None,
                   help='Save the initial training DB (pre-evolution).')
    p.add_argument('--load_db',    type=str, default=None,
                   help='Load a pre-built training DB.')
    p.add_argument('--save_json', type=str, default=None,
                   help='Save results as JSON for plotting with plot_results.py.')
    p.add_argument('--output',     type=str, default='honeyword_eval_evolving')
    return p.parse_args()


# ─────────────────────────────────────────────────────────────
# 11. Entry points: demo and full evaluation runs
# ─────────────────────────────────────────────────────────────

def run_demo(args):
    print("\n  [DEMO] Evolution-faithful evaluation on preset corpus.\n")
    k       = args.k
    train   = PRESET_CORPUS
    test    = PRESET_CORPUS[:min(20, len(PRESET_CORPUS))]
    n_users = len(test)

    db    = FrequencyDatabase()
    db.load_corpus(train)
    model = ListPasswordModel(train)
    print(f"  Training DB stats: {db.stats()}")
    print(f"  DB will evolve as {n_users} test users register.\n")

    sw_file = build_sweetword_file_evolving(test, db, k=k, min_lev=args.min_lev)
    print(f"  Post-evolution DB stats: {db.stats()}")

    ranks = attack_flatness(sw_file, model, strategy=args.strategy)
    curve = attack_success_number(sw_file, model, strategy=args.strategy,
                                  T1=args.T1, T2=min(args.T2, 500))

    print_results(ranks, curve, k=k, n_users=n_users,
                  strategy=args.strategy, T2=min(args.T2, 500),
                  dataset_name='preset-corpus', seed=args.seed)

    # Save results as JSON for plot_results.py
    if args.save_json:
        import sys as _sys
        _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        try:
            from plot_results import save_list_model_results
            _label = f"{os.path.basename(args.dataset).replace('_sorted_preprocessed.txt','')} [evolving-db]"
            save_list_model_results(ranks, curve, k=args.k,
                                    label=_label,
                                    out_path=args.save_json)
        except ImportError:
            print("  [WARN] plot_results.py not found; skipping JSON save.")

    if args.plot:
        plot_results(ranks, curve, k=k, n_users=n_users,
                     strategy=args.strategy, output_prefix=args.output,
                     dataset_name='preset-corpus')


def run_full(args):
    if args.workers > 1:
        print(f"  NOTE: --workers={args.workers} ignored. "
              f"Evolution requires sequential processing.")

    random.seed(args.seed)
    dataset_name = os.path.basename(args.dataset)
    train_size   = args.train_size if args.train_size is not None else args.n_users

    print(f"\n  Dataset   : {args.dataset}")
    print(f"  Train     : {train_size:,}  |  Test : {args.n_users:,}")
    print(f"  Evolution : ENABLED — DB mutates during generation")
    print(f"  Seed      : {args.seed}  (fixes split + registration order)")
    print(f"  k={args.k}  min_lev={args.min_lev}  strategy={args.strategy}")

    if args.load_db and os.path.exists(args.load_db):
        print(f"\n  Loading training DB from {args.load_db} …")
        db = FrequencyDatabase()
        db.load(args.load_db)

        print(f"  Rebuilding model + test set via reservoir sampling …")
        need         = train_size + args.n_users
        rng          = random.Random(args.seed)
        reservoir: list[str] = []
        n_seen       = 0
        report_every = 500_000
        t0_scan      = time.time()
        with open(args.dataset, encoding='utf-8', errors='replace') as f:
            for line in f:
                pw = line.rstrip('\n\r')
                if not pw or pw.startswith('#') or not pw.isascii():
                    continue
                n_seen += 1
                if len(reservoir) < need:
                    reservoir.append(pw)
                else:
                    j = rng.randint(0, n_seen - 1)
                    if j < need:
                        reservoir[j] = pw
                if n_seen % report_every == 0:
                    elapsed = time.time() - t0_scan
                    rate    = n_seen / elapsed if elapsed > 0 else 0
                    print(f"  {n_seen:>12,} scanned  ({rate:,.0f} pw/s)"
                          f"  reservoir={len(reservoir):,}   ", end='\r')
        elapsed = time.time() - t0_scan
        print(f"  {n_seen:,} passwords scanned in {elapsed:.1f}s"
              f"  ({n_seen/elapsed:,.0f} pw/s)          ")
        rng.shuffle(reservoir)
        train_pws      = reservoir[:train_size]
        test_passwords = reservoir[train_size:train_size + args.n_users]
        counter: dict[str, int] = {}
        for pw in train_pws:
            counter[pw] = counter.get(pw, 0) + 1
        model = ListPasswordModel.__new__(ListPasswordModel)
        model._counts = counter
        model._total  = len(train_pws)
        model._smooth = 1.0 / (len(train_pws) + 1)

    else:
        print()
        db, model, test_passwords = stream_build(
            args.dataset,
            train_limit=train_size,
            test_limit=args.n_users,
            seed=args.seed,
        )
        if args.save_db:
            db.save(args.save_db)

    s = db.stats()
    print(f"\n  Training DB: {s['total_passwords']:,} passwords  "
          f"{s['unique_patterns']:,} patterns  "
          f"{s['unique_alpha_tokens']:,} alpha tokens")
    print(f"  Test passwords: {len(test_passwords):,}")

    # Generate sweetword lists with the database evolving live
    print(f"\n  Generating sweetword lists (evolution enabled, sequential) …")
    t0      = time.time()
    sw_file = build_sweetword_file_evolving(
        test_passwords, db, k=args.k, min_lev=args.min_lev, verbose=True,
    )
    gen_elapsed = time.time() - t0
    s2 = db.stats()
    print(f"  Generation: {gen_elapsed:.1f}s  "
          f"({len(test_passwords)/gen_elapsed:.0f} users/s)")
    print(f"  Post-evolution DB: {s2['total_passwords']:,} passwords  "
          f"{s2['unique_alpha_tokens']:,} alpha tokens")

    # Flatness evaluation
    print(f"\n  Running flatness evaluation (Algorithm 2) …")
    t0    = time.time()
    ranks = attack_flatness(sw_file, model, strategy=args.strategy)
    print(f"  Flatness done in {time.time()-t0:.1f}s")

    # Success-number evaluation
    print(f"  Running success-number evaluation "
          f"(Algorithm 1, T1={args.T1}, T2={args.T2:,}) …")
    t0    = time.time()
    curve = attack_success_number(sw_file, model, strategy=args.strategy,
                                  T1=args.T1, T2=args.T2)
    print(f"  Attack done in {time.time()-t0:.1f}s")

    print_results(ranks, curve, k=args.k, n_users=len(test_passwords),
                  strategy=args.strategy, T2=args.T2,
                  dataset_name=dataset_name, seed=args.seed)


    # Save results as JSON for plot_results.py
    if args.save_json:
        import sys as _sys
        _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        try:
            from plot_results import save_list_model_results
            _label = f"{os.path.basename(args.dataset).replace('_sorted_preprocessed.txt','')} [evolving-db]"
            save_list_model_results(ranks, curve, k=args.k,
                                    label=_label,
                                    out_path=args.save_json)
        except ImportError:
            print("  [WARN] plot_results.py not found; skipping JSON save.")

    if args.plot:
        plot_results(ranks, curve, k=args.k, n_users=len(test_passwords),
                     strategy=args.strategy, output_prefix=args.output,
                     dataset_name=dataset_name)


def main():
    args = parse_args()
    print("═" * 64)
    print("  HONEYWORD SECURITY EVALUATOR  [EVOLUTION ENABLED]")
    print("  Akshima et al. generator  ×  Wang et al. attack metrics")
    print("  Wang et al. NDSS 2018  /  Akshima et al. IEEE TDSC 2019")
    print("═" * 64)

    if args.demo or args.dataset is None:
        run_demo(args)
    else:
        if not os.path.exists(args.dataset):
            sys.exit(f"Dataset not found: {args.dataset}")
        run_full(args)


if __name__ == '__main__':
    main()