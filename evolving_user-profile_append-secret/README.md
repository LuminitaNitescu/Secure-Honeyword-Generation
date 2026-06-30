# Honeyword Generation and Evaluation

Implementation and security evaluation of honeyword generation techniques descrbed in Akshima et al.'s "Generation of Secure and Reliable Honeywords, Preventing False Detection" (IEEE TDSC 2019). The evolving-password model is the primary focus of the attack evaluation, as it is the  most directly comparable against the Wang et al. (NDSS 2018) attack metrics used by the other implemented models. The user-profile and append-secret models are implemented alongside it but are evaluated through other means appropriate to their security properties, rather than through the same guessing-attacker pipeline. Attack evaluation follows the metrics and methodology of Wang et al. (NDSS 2018).


## Project structure
```
implementation/
└── attacks/
    ├── attack_evolving_db.py         List-model attacker, evolving DB (evolution-faithful)
    ├── attack_fixed_db.py            List-model attacker, fixed DB (static baseline)
    ├── plot_results.py               Flatness and success-number graphs from attack output JSON
    ├── run_all_attacks.py            Runs all three attackers and produces a comparison plot
     └── run_attack_evolving_model.py  Hashmob attacker (NormalizedTopPWModelHG)
├── __init__.py
├── append_secret_model.py      Append-Secret Model
├── cli.py                      Interactive CLI for all three generation models
├── evolving_model.py           Evolving-Password Model
├── frequency_db.py             Frequency database and fallback token pools
├── honeychecker.py             Honeychecker and SweetwordList data structures
├── levenshtein.py              Edit-distance computation
├── policy.py                   Password policy enforcement
├── tokenizer.py                Password tokenization and pattern utilities
├── user_profile_model.py       User-Profile Model
└── verify_append_secret.py     Standalone security checks for the append-secret model
```

## Generation models
 
Akshima et al. define two UI categories: Legacy-UI (the system does not influence password choice), and Modified-UI (the system requires extra input at registration). The evolving-password and user-profile models target the former; the append-secret model targets the latter. All three use Levenshtein distance as a typo-safety check against false alarms.
 
### Evolving-Password Model (`evolving_model.py`)
Tokenizes passwords into alpha/digit/special-char patterns and maintains a frequency database, updated on every registration, of token and pattern counts. Honeywords are built by matching the password's pattern and filling each slot with a token of the same frequency as the corresponding real token. Deviates from the paper by giving each token its own frequency-matched pool rather than one shared pool per token type, and by enforcing a max length deviation between password and honeyword.
 
### User-Profile Model (`user_profile_model.py`)
Similar pattern-and-token scheme as the Evolving-Password Model, but here the tokens are drawn from the user's personal information (name, date of birth, address, pet name) instead of a frequency database. Candidates sharing more than one token with the real password are discarded. Deviates from the paper by falling back to a small generic word/digit pool when a profile is too sparse, and by sampling multi-character special-char slots character-by-character rather than repeating a single character.
 
### Append-Secret Model (`append_secret_model.py`)
Stores `password + f(password, l, r)`, where `l` is a short user-chosen string and `r` is a random secret known only to the honeychecker. Honeywords vary `l` while `r` stays fixed. Deviates from the paper by drawing fake `l` values from the same alphabet as `r`, and by relying on structural typo-safety (a mistyped password or `l` matches no stored entry) instead of a distance filter, since all stored values for a user differ only in a 5-character suffix. Evaluated separately in `verify_append_secret.py` rather than against a guessing attacker, since this model has no guessable distribution.


## Supporting modules

- `tokenizer.py` - splits a password into typed tokens (alpha/digit/special) and derives/parses the pattern string used by the evolving and user-profile models.
- `frequency_db.py` - `FrequencyDatabase` and `FreqIndex` classes implementing Algorithm 1 from Akshima et al., plus fallback token pools used when a frequency-matched candidate set is too small.
- `levenshtein.py` - edit-distance function used by all three models to enforce typo-safety between the real password and its honeywords.
- `policy.py` - enforces the Section 5.1 password policy (minimum length, character-class diversity, no username substrings).
- `honeychecker.py` - `Honeychecker` (stores only the sugarword index `c(i)`, plus the append-secret `r` where applicable) and `SweetwordList` (the generated sweetword list, sugarword index, and generation metadata).
- `cli.py` - interactive command-line front end for registering passwords, generating honeywords with each model, and simulating logins against the honeychecker.

## Attack evaluation

Attack scripts apply the Wang et al. (NDSS 2018) metrics to evaluate the evolving-password model generator. The attacker implementation of `NormalizedTopPWModelHG`, used by `run_attack_evolving_model.py`, is owned by a collaborator and lives in a separate part of the codebase (honeygen); it implements Wang et al.'s normalized Top-PW attack directly: each sweetword's probability is drawn from a known leaked-password distribution, normalized across a user's k sweetwords, and accounts are attacked in decreasing order of normalized probability, with at most T1 guesses per user and a global budget of T2 failed (honeyword) guesses. The list-model attackers (`attack_evolving_db.py`, `attack_fixed_db.py`), by contrast, are part of this implementation and draw that distribution from the training split of the target corpus itself, while `run_attack_evolving_model.py` substitutes a HashMob counts file as the distribution source for `NormalizedTopPWModelHG`, giving a stronger, externally-informed adversary rather than one confined to the generator's own training data.

- `attack_evolving_db.py` - list-model attacker trained on a static corpus, evaluated against the evolving model running as designed (the frequency database evolves with every test registration). Results are order- and seed-dependent; evaluation must run single-threaded.
- `attack_fixed_db.py` - same list-model attacker, but the frequency database is frozen after training and does not evolve during evaluation. Serves as the static baseline; comparing its results to `attack_evolving_db.py` isolates the security benefit of evolution.
- `run_attack_evolving_model.py` - evaluates the evolving model against the Hashmob-based `NormalizedTopPWModelHG` attacker, a stronger and more realistically-informed adversary than the corpus-only list-model attackers. Builds a disjoint train/test split via reservoir sampling so the same passwords are not double-counted between training the frequency database and generating test honeywords.
- `run_all_attacks.py` - runs all three attackers in sequence with shared parameters and produces a comparison plot via `plot_results.py`.
- `plot_results.py` - reads the JSON output of any of the three attackers and produces flatness and success-number graphs, auto-detecting the output format of each attacker.

## Usage

Run the interactive CLI to generate honeywords with any of the three models:

```
python cli.py
```

Run the full attack comparison on the default dataset (RockYou, 5000 users):

```
python attacks/run_all_attacks.py
```

Run a single attacker with custom parameters:

```
python attacks/run_all_attacks.py --dataset yahoo --n-users 10000 --train-size 10000
```

List available target datasets:

```
python attacks/run_all_attacks.py --list-datasets
```

Verify the append-secret model's security properties directly (no attacker required):

```
python verify_append_secret.py
```

## Notes

- The evolving model's flatness guarantee is corpus-relative: it holds against a list attacker trained on the same corpus, but degrades against a more realistically-informed adversary such as the Hashmob-based attacker.
- The append-secret model cannot be meaningfully evaluated by guessing-style attackers, since every sweetword has the same structure and no guessable distribution; its security properties are verified separately in `verify_append_secret.py`.