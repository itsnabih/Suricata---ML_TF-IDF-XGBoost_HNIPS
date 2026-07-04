import re
import random

categories = {
    'Time-based Blind': re.compile(r'(?i)(sleep\s*\(|pg_sleep\s*\(|waitfor\s+delay)'),
    'UNION-based': re.compile(r'(?i)union\s+(all\s+)?select'),
    'Error-based': re.compile(r'(?i)(extractvalue\s*\(|concat.*0x7e)'),
    'Boolean-based Blind': re.compile(r'(?i)\b(and|or)\b.{0,40}\b\d+=\d+\b'),
    'URL Encoded': re.compile(r'(?i)(%27|%22|%2D%2D|%23|%2F%2A|%2A%2F)'),
    'Hex Encoded': re.compile(r'(?i)0x[0-9a-f]{2,}'),
    'Null Byte': re.compile(r'%00'),
    'Misc (Fingerprint/DB/File/Order)': re.compile(r'(?i)(@@version|version\(\)|@@servername|current_user|database\(\)|order\s+by\s+\d+|load_file\s*\()'),
    'Basic Quote/Comment': re.compile(r"['\"\-#]|/\*")
}

targets = {
    'Time-based Blind': 40,
    'UNION-based': 60,
    'Error-based': 30,
    'Boolean-based Blind': 70,
    'URL Encoded': 50,
    'Hex Encoded': 30,
    'Null Byte': 20,
    'Misc (Fingerprint/DB/File/Order)': 30,
    'Basic Quote/Comment': 200
}

buckets = {k: [] for k in categories.keys()}
unmatched = []

with open('sqli.txt', 'r', encoding='utf-8', errors='ignore') as f:
    payloads = [line.strip() for line in f if line.strip()]

for payload in payloads:
    matched = False
    for cat in ['Time-based Blind', 'UNION-based', 'Error-based', 'Boolean-based Blind', 'URL Encoded', 'Hex Encoded', 'Null Byte', 'Misc (Fingerprint/DB/File/Order)', 'Basic Quote/Comment']:
        if categories[cat].search(payload):
            buckets[cat].append(payload)
            matched = True
            break
    
    if not matched:
        unmatched.append(payload)

final_payloads = []
print(f"{'Kategori':<35} | {'Tersedia':<10} | {'Target':<10} | {'Diambil':<10}")
print("-" * 75)

for cat, target in targets.items():
    available = len(buckets[cat])
    take = min(available, target)
    sampled = random.sample(buckets[cat], take)
    final_payloads.extend(sampled)
    
    print(f"{cat:<35} | {available:<10} | {target:<10} | {take:<10}")

out_file = 'sqli_test_payloads.txt'
with open(out_file, 'w', encoding='utf-8') as f:
    for payload in final_payloads:
        f.write(payload + '\n')

print("-" * 75)
print(f"Total payload dipilih: {len(final_payloads)}")
print(f"Disimpan ke: {out_file}")
