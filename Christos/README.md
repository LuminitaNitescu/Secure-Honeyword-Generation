# How to Attack and Generate Honeywords by Wang et al.

This guide explains how to set up your environment, run, and experiment with the List, Markov, PCFG, TarList, TarMarkov, and TarPCFG models.

## 1. Activate a Virtual Environment

If you haven't done so already, please set up and activate a virtual environment (preferrably using Conda) to keep project dependencies isolated.

## 2. Install Dependencies

With your environment activated, install the required packages:
```bash
pip install -r requirements.txt
```

## 3. Configure and Run `run_models.sh`

Open `run_models.sh` in a text editor and set the variables at the top of the file to match your desired experiment configuration:

| Variable | Description | Example / Options |
|---|---|---|
| `MODEL_NAME` | The model type to use | `list`, `markov`, `pcfg`, `tarmarkov`, `tarlist`, `tarpcfg` |
| `MODEL_PATH` | **Optional** path to a pretrained model file. Can be left empty if a `TRAIN_PATH` is supplied to train a new model | `../trained_models/markov.pickle` |
| `K` | Number of honeywords / candidates to generate | `20` |
| `SEED` | Random seed for reproducibility | `67` |
| `T1` | First threshold/tuning parameter | `20` |
| `T2` | Second threshold/tuning parameter | `61` |
| `TRAIN_PATH` | **Optional** path to training data. Can be left emply if `MODEL_PATH` is suppied | `../data2/rockyou_final_tr.txt` |
| `TEST_PATH` | Path to test data | `../data/rockyou_tr.txt` |
| `MODE` | Script execution mode. Use `experiments` to generate honeywords and run the **Trawling-guessing Attacker** against them, or use `honeywords` if you just want the generated honeyword strings. | `honeywords`, `experiments` |
| `ATTACKER_PATH` | **Optional** path to attacker dataset. Can be left empty if script is run in `honeywords` mode | `../data/` |
| `ATTACKER_SIZE` | **Optional** size of attacker dataset. Can be left empty if script is run in `honeywords` mode | `10000000` |
| `SAVE_PATH` | Directory where results will be saved | `../results` |

Once configured, run the script from the directory it lives in:
```bash
bash run_models.sh
```

## 4. Check results / Generate flatness - success number curves

After the run completes, results will be saved to the directory specified in `SAVE_PATH`.
- If you ran the script in `honeywords` mode, the results will be saved as JSON files titled `<MODEL_NAME>_honeywords.json`.
- If you ran the script in `experiments` mode, you will find the results in JSON format for each evaluated model in a separate subfolder inside `SAVE_PATH`. The JSON files will be titled as `<MODEL_NAME>_<K>_<T1>_<T2>_experiment.json`. Assuming you have run experiments for the List and Markov models, you may generate flatness and success number curves for these results by executing:

```bash
python Andrei/implementation/graphs.py --k <K> --folders Christos/<SAVE_PATH>/list + Christos/<SAVE_PATH>/markov
```

## Required dataset structures

* For **non-targeted** models List, Markov, PCFG:

    * **Training set**: Must be a .txt file comprised of password strings, each on a different line. For PCFG, all passwords **must** be comprised of ASCII characters.
    ```
    123456
    password
    hello1234
    ```
    * **Test set**: Same as Training set
    * **Attacker set**: Must be a .txt file comprised of password strings followed by the number of occurences in the dataset, delimited by a ':' character.
    ```
    123456:234567
    password:2402
    hello1234:124
    ```
* For **targeted** models TarList, TarMarkov, TarPCFG:

    * **Training set**: Must be a .csv file with header 'password,first_name,last_name,email,birthday,username'. All data entries must in separate lines, follow this ordering, and use the ',' character as a delimiter.
    ```
    password,first_name,last_name,email,birthday,username
    jandro,VETA,Parrish,may1821@yandex.com,04112002,account2084
    SUMMERSee,DINO,SUMMERS,string1974@example.com,06122020,britain1840
    lawyers1817,ANGILA,RODRIGUEZ,quarters1875@example.com,12042024,lawyers1817
    ```
    * **Test set**: Same as Training set
    * **Attacker set**: Must be a .txt file comprised only of the password strings followed by the number of occurences in the dataset, delimited by a ':' character.
    ```
    jandro:234567
    SUMMERSee:2402
    lawyers1817:124
    ```