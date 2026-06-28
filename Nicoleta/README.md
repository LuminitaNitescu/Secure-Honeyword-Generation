# Honeywords Pipeline

Generates honeywords for passwords from the BreachCompilation dataset using a locally-running Qwen model via Ollama and the CKL-PSM chunking algorithm. There is also the possibiblity of generating honeywords for a single password entered by the user. Other models have been used by replacing the lines where the model is being referred and pulling the other model as explained below for qwen3:4b-instruct. 

## Setup

```bash
pip install -r requirements.txt
```

Ollama must be running with the model pulled:

```bash
ollama pull qwen3:4b-instruct
export OLLAMA_NUM_PARALLEL=4
ollama serve
```

## Module overview

```
common.py               shared constants, helpers, and LLM call
breach_extract.py       step 1 — walk BreachCompilation/data, filter to ASCII 8–32 char passwords, write CSV
honeywords_strong.py    step 2 — load CSV, score with zxcvbn, pick strongest N, chunk, generate honeywords
honeywords_weak.py      step 3 — same as above but picks weakest N passwords
honeywords_single.py    interactive — enter one password, get honeywords printed to terminal
chunk_gpt_implementation.py   orchestrator — runs all three steps in sequence
```

## Module connection

`common.py` is the shared foundation: all other modules import constants (`NUM_USER`, `NUM_SWEETWORDS`, `AI_MODEL`, paths), chunking helpers (`add_chunks`, `add_chunk_num`), and the LLM generation function (`qwen4b_honeywords_chunk`, `chaffing_by_qwen4b_chunk`) from it.

`breach_extract.py` runs once and produces `breach_passwords_unique_email_8_32.csv` in the repo root. Both `honeywords_strong.py` and `honeywords_weak.py` read from that CSV. They are otherwise independent.

`honeywords_single.py` skips the CSV entirely and calls `qwen4b_honeywords_chunk` directly on whatever password the user enters.

## Running

Full pipeline (all steps):
```bash
python chunk_gpt_implementation.py
```
Modules can also be run independently.