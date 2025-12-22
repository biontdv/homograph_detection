#!/usr/bin/env python3


import csv
import json
import requests
import statistics
import time
import sys
from pathlib import Path
from typing import Dict, List

# CONFIG
API_URL = "http://127.0.0.1:5000/sendurl"
DATASET_PATH = Path("./testing/generated_all_cases.csv")
TIMEOUT = 15  # seconds
SLEEP_BETWEEN = 0.02  # pause to avoid hammering local server
OUTPUT_SUMMARY = Path("result_summary.txt")

# internal storage
results: Dict[str, Dict] = {}
rows = []

# read dataset
if not DATASET_PATH.exists():
    print(f"ERROR: dataset not found: {DATASET_PATH.resolve()}")
    sys.exit(1)

with DATASET_PATH.open("r", encoding="utf-8", newline="") as f:
    reader = csv.DictReader(f)
    for r in reader:
        # Normalize keys if needed
        if 'generated_domain' not in r or 'case' not in r:
            raise SystemExit("CSV must contain generated_domain and case columns")
        rows.append(r)

total_domains = len(rows)

# init results structure per case
for r in rows:
    case = r['case']
    if case not in results:
        results[case] = {
            'detected': 0,
            'missed': 0,
            'error': 0,
            'durations': [],
            'memories': [],
            'missed_domains': []
        }

print(f"✨ Memulai pengujian terhadap {total_domains} domain...\n")

scanned = 0
start_all = time.time()
for idx, row in enumerate(rows, start=1):
    domain = row['generated_domain'].strip()
    case = row['case']
    url = f"http://{domain}"

    scanned += 1
    # progress line (overwrite)
    progress = f"Scanning {scanned}/{total_domains} — {domain} ({case})"
    print(progress + ' ' * 10, end='\r', flush=True)

    try:
        resp = requests.post(API_URL, json={'url': url}, timeout=TIMEOUT)
        # accept non-JSON gracefully
        try:
            res = resp.json()
        except Exception:
            res = {}

        status = res.get('status')
        duration = res.get('detection_duration_ms')
        memory = res.get('memory_usage_mb')

        # normalize types
        try:
            duration = float(duration) if duration is not None else 0.0
        except Exception:
            duration = 0.0
        try:
            memory = float(memory) if memory is not None else 0.0
        except Exception:
            memory = 0.0

        if status == 'danger':
            results[case]['detected'] += 1
        elif status == 'safe':
            results[case]['missed'] += 1
            results[case]['missed_domains'].append(domain)
        else:
            # unknown or missing status -> treat as error
            results[case]['error'] += 1

        results[case]['durations'].append(duration)
        results[case]['memories'].append(memory)

    except requests.exceptions.RequestException as e:
        # network / timeout / connection errors
        results[case]['error'] += 1

    # polite pause
    time.sleep(SLEEP_BETWEEN)

# finished
end_all = time.time()
print(' ' * 120, end='\r')  # clear progress line
print(f"✨ Pengecekan {total_domains} domain telah selesai.\n")

# print per-case
print("================== HASIL PENGUJIAN PER CASE ==================")

total_detected = 0
total_missed = 0
total_error = 0

for case, r in results.items():
    total = r['detected'] + r['missed'] + r['error']
    accuracy = (r['detected'] / total * 100) if total > 0 else 0.0
    avg_dur = statistics.mean(r['durations']) if r['durations'] else 0.0
    avg_mem = statistics.mean(r['memories']) if r['memories'] else 0.0

    total_detected += r['detected']
    total_missed += r['missed']
    total_error += r['error']

    # formatting to match example
    print(f"[{case}]")
    print(f"  ✅ Terdeteksi          : {r['detected']}")
    print(f"  🚨 Missed              : {r['missed']}")
    print(f"  🔥 Error               : {r['error']}")
    print(f"  🎯 Akurasi             : {accuracy:.2f}%")
    print(f"  ⏱️  Avg. Duration (ms)  : {avg_dur:.2f}")
    print(f"  💾 Avg. Memory (MB)    : {avg_mem:.4f}\n")

# total summary
print("================== HASIL PENGUJIAN TOTAL ==================")
print(f"Total Domain Diuji      : {total_domains} (dari {total_domains} baris)")
print(f"✅ Berhasil Terdeteksi   : {total_detected}")
print(f"🚨 Gagal Terdeteksi      : {total_missed}")
print(f"🔥 Domain Error          : {total_error}")
print("---------------------------------------------------------------")

# total accuracy: exclude errors (match example behavior)
if (total_detected + total_missed) > 0:
    total_accuracy = total_detected / (total_detected + total_missed) * 100
else:
    total_accuracy = 0.0


all_durations = []
all_memories = []
for r in results.values():
    all_durations.extend(r['durations'])
    all_memories.extend(r['memories'])

avg_duration_total = statistics.mean(all_durations) if all_durations else 0.0
avg_memory_total = statistics.mean(all_memories) if all_memories else 0.0


print(f"🎯 Tingkat Akurasi Total   : {total_accuracy:.2f}%")
print(f"⏱️  Avg. Duration (ms)     : {avg_duration_total:.2f}")   # NEW
print(f"💾 Avg. Memory (MB)       : {avg_memory_total:.4f}")      # NEW
print("===============================================================\n")

# Print missed domains per case (if any)
for case, r in results.items():
    if r['missed_domains']:
        print(f"--- Missed ({case}) ---")
        for d in r['missed_domains']:
            print(f"- {d}")
        print()

# save summary to file for record
try:
    with OUTPUT_SUMMARY.open('w', encoding='utf-8') as out:
        out.write(f"Pengecekan {total_domains} domain\n\n")
        out.write("PER CASE:\n")
        for case, r in results.items():
            total = r['detected'] + r['missed'] + r['error']
            accuracy = (r['detected'] / total * 100) if total > 0 else 0.0
            avg_dur = statistics.mean(r['durations']) if r['durations'] else 0.0
            avg_mem = statistics.mean(r['memories']) if r['memories'] else 0.0
            out.write(f"[{case}]\n")
            out.write(f"  detected: {r['detected']}\n")
            out.write(f"  missed: {r['missed']}\n")
            out.write(f"  error: {r['error']}\n")
            out.write(f"  accuracy: {accuracy:.2f}%\n")
            out.write(f"  avg_duration_ms: {avg_dur:.2f}\n")
            out.write(f"  avg_memory_mb: {avg_mem:.4f}\n\n")

        out.write("TOTAL:\n")
        out.write(f"total_domains: {total_domains}\n")
        out.write(f"detected: {total_detected}\n")
        out.write(f"missed: {total_missed}\n")
        out.write(f"error: {total_error}\n")
        out.write(f"total_accuracy: {total_accuracy:.2f}%\n")

    print(f"Ringkasan disimpan ke: {OUTPUT_SUMMARY.resolve()}")
except Exception:
    pass
