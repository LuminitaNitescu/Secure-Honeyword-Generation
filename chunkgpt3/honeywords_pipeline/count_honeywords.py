'''
Compute number of rows with >= 19 honeywords and number of rows with real password duplicated in honeywords.
'''
import csv

INPUT_CSV = "honeywords_Qwen3_10k_breach.csv"

full_rows = 0
duplicates = 0

with open(INPUT_CSV, newline='', encoding='utf-8') as f:
    reader = csv.reader(f)
    next(reader) 
    for row in reader:
        tokens = [t.strip() for t in row if t.strip() and t.strip() != 'nan']
        if not tokens:
            continue
        real_pw = tokens[0]
        honeywords = tokens[1:]
        if len(honeywords) >= 19:
            full_rows += 1
        if real_pw in honeywords:
            duplicates += 1

print(f"Rows with >= 19 honeywords : {full_rows}")
print(f"Rows with real pw duplicated: {duplicates}")
