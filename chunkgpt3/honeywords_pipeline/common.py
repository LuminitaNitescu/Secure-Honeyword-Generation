import os
import openai
import re
import concurrent.futures
from tqdm import tqdm
from ckl_psm import ckl_pcfg as psm

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

NUM_SWEETWORDS    = 20
NUM_USER          = 10 # number of real passwords to generate honeywords for
BREACH_DATA_DIR   = os.path.join(_ROOT, "BreachCompilation", "data") # path to the data directory of the BreachCompilation for 4iQ
BREACH_PASSWORDS_OUT = os.path.join(_ROOT, "breach_passwords_unique_email_8_32.csv")
OLLAMA_BASE_URL   = "http://localhost:11434/v1"
AI_MODEL          = "qwen3:4b-instruct"  # can switch to different model


openai.api_base = OLLAMA_BASE_URL
openai.api_key  = "ollama"

# obtain the chunks for a password
def add_chunks(df):
    chunks = []
    for row in tqdm(df.itertuples(), total=len(df), desc="Chunking", unit="pw"):
        result = psm.check_pwd(row.pw)
        chunk_set = set(list(zip(*result["chunks"]))[0])
        chunks.append(chunk_set)
    df = df.copy()
    df["chunks"] = chunks
    return df

# get the number of chunks for a password
def add_chunk_num(df):
    df = df.copy()
    df["num_chunks"] = df["chunks"].apply(len)
    return df

# replace the keys in a string with their corresponding values from a dictionary
def replace_all(text, dic):
    for i, j in dic.items():
        text = text.replace(i, j)
    return text

# generate honeywords for a password with openai
def qwen4b_honeywords_chunk(real_password, chunks):
    prompt = (
        "Derive 19 distinct passwords that are similar to " + real_password
        + " and contain" + chunks
        + " . The length of the derived passwords should be at most " + str(len(real_password))
        + ". Do not add digits at the end of the passwords. Answer only with a numbered list, no_think"
    )
    response = openai.ChatCompletion.create(
        model=AI_MODEL,
        messages=[{"role": "user", "content": f"{prompt} /no_think"}],
        temperature=1,
        max_tokens=500,
        top_p=1,
        frequency_penalty=0,
        presence_penalty=0,
    )
    raw = response["choices"][0]["message"]["content"].strip()
    results = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if not re.match(r"^\d+[\.\)]", line):
            continue
        cleaned = re.sub(r"^\d+[\.\)]\s*", "", line).strip()
        if ":" in cleaned or not re.search(r"[a-zA-Z0-9]", cleaned):
            continue
        word = cleaned.split()[0] if cleaned.split() else ""
        if word:
            results.append(word)

    dupes = [w for w in results if w == real_password]
    if dupes:
        print(f"Removed {len(dupes)} honeyword(s) identical to the real password ({real_password!r})")
    results = [w for w in results if w != real_password]
    return results[:NUM_SWEETWORDS - 1]

# call the function to generate honeywords in multiple threads to speed up
def chaffing_by_qwen4b_chunk(df):
    sweetwords = {}
    total = len(df)

    def process_row(row):
        chunks = replace_all(str(row.chunks), {"{}": " ", "}": ","})[2:-2]
        return row.pw, qwen4b_honeywords_chunk(row.pw, chunks)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(process_row, row): i for i, row in enumerate(df.itertuples())}
        for idx, future in enumerate(concurrent.futures.as_completed(futures)):
            pw, honeywords = future.result()
            sweetwords[pw] = honeywords
            if (idx + 1) % 100 == 0 or (idx + 1) == total:
                print(f"{idx + 1}/{total} passwords processed")
    return sweetwords
