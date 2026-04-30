#!/usr/bin/env python3

import csv
import random
import time
import sys
from pathlib import Path
from statistics import mean
import requests

# CONFIG
TOP1M_PATH = Path("tranco_GVQVK.csv")
SAMPLE_SIZE = 7000
API_URL = "http://192.168.0.111:5000/sendurl"
# TIMEOUT = 15 # (Tidak digunakan di requests.post, tapi bisa ditambahkan jika perlu)
SLEEP_BETWEEN = 0.02
OUTPUT_CSV = Path("results_top1m_sample.csv")

# --- helper functions ---
def load_domains(path: Path):
    if not path.exists():
        print(f"ERROR: {path} not found.", file=sys.stderr)
        sys.exit(1)
    
    domains = []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            # Menggunakan csv.reader untuk menangani format "Rank,Domain"
            reader = csv.reader(f)
            for row in reader:
                # Pastikan baris memiliki setidaknya 2 kolom (Rank, Domain)
                if len(row) >= 2:
                    d = row[1].strip() # Ambil kolom kedua (domain)
                    if d:
                        domains.append(d)
                # Fallback: jika ternyata hanya ada 1 kolom (hanya domain)
                elif len(row) == 1:
                    d = row[0].strip()
                    if d:
                        domains.append(d)
    except Exception as e:
        print(f"ERROR reading CSV: {e}", file=sys.stderr)
        sys.exit(1)

    # deduplicate (memastikan domain unik)
    # Menggunakan dict.fromkeys untuk order-preserving deduplication (lebih cepat dari set loop manual)
    uniq = list(dict.fromkeys(domains))
    
    print(f"Loaded {len(uniq)} unique domains from {path.name}")
    return uniq

def post_url(url: str):
    try:
        # Tambahkan timeout agar script tidak hang jika server API down/lambat
        r = requests.post(API_URL, json={"url": url}, timeout=10) 
        status_code = r.status_code
        
        # hanya anggap error jika status code 5xx
        if 500 <= status_code < 600:
            return False, None, f"server-error-{status_code}"
        
        try:
            js = r.json()
        except Exception:
            js = None
        return True, js, None
    except requests.exceptions.Timeout:
        return False, None, "timeout"
    except Exception as e:
        # Error lain (misal koneksi putus total)
        return False, None, str(e)

# --- main ---
domains = load_domains(TOP1M_PATH)

if not domains:
    print("No domains found in top1m file.", file=sys.stderr)
    sys.exit(1)

sample_count = min(SAMPLE_SIZE, len(domains))
sample = random.sample(domains, sample_count)

rows_out = []
success_count = 0
failed_count = 0 # Flagged as danger
error_count = 0
durations = []
memories = []
missed_domains = []  # collect flagged domains

start_time = time.time()
print(f"Starting test on {sample_count} domains...")

for idx, domain in enumerate(sample, start=1):
    # Pastikan domain tidak mengandung http/https double jika file csv kotor
    clean_domain = domain.replace("http://", "").replace("https://", "").split('/')[0]
    url = f"http://{clean_domain}"
    
    prog = f"Scanning {idx}/{sample_count} — {clean_domain}"
    # Padding spasi agar overwrite line sebelumnya bersih
    print(f"{prog:<80}", end="\r", flush=True)

    ok, js, exc = post_url(url)

    row = {
        "domain": clean_domain,
        "url_sent": url,
        "ok": ok,
        "status": None,
        "message": None,
        "detection_duration_ms": None,
        "memory_usage_mb": None,
        "error": None,
    }

    if not ok:
        row["error"] = str(exc)
        error_count += 1
    else:
        if js is None:
            row["error"] = "non-json-response"
            error_count += 1
        else:
            status = js.get("status")
            row["status"] = status
            row["message"] = js.get("message")
            try:
                dur = float(js.get("detection_duration_ms", 0) or 0)
            except Exception:
                dur = 0.0
            try:
                mem = float(js.get("memory_usage_mb", 0) or 0)
            except Exception:
                mem = 0.0
            row["detection_duration_ms"] = dur
            row["memory_usage_mb"] = mem

            # classify result
            if status == "safe":
                success_count += 1
            elif status == "danger":
                failed_count += 1
                missed_domains.append(clean_domain)  # collect flagged domain
            else:
                row["error"] = f"unknown-status: {status}"
                error_count += 1

            durations.append(dur)
            memories.append(mem)

    rows_out.append(row)
    time.sleep(SLEEP_BETWEEN)

# done
total_time = time.time() - start_time
print(" " * 120, end="\r")

total = sample_count
accuracy = (success_count / total) * 100 if total else 0.0
avg_dur = mean(durations) if durations else 0.0
avg_mem = mean(memories) if memories else 0.0

print(f"✨ Pengecekan {total} domain telah selesai.\n")
print("================== HASIL PENGUJIAN TOTAL ==================")
print(f"Total Domain Diuji      : {total}")
print(f"✅ Berhasil (safe)      : {success_count}")
print(f"🚨 Gagal (flagged)      : {failed_count}")
print(f"🔥 Error                : {error_count}")
print("---------------------------------------------------------------")
print(f"🎯 Tingkat Akurasi       : {accuracy:.2f}%")
print(f"⏱️  Avg. Duration (ms)   : {avg_dur:.2f}")
print(f"💾 Avg. Memory (MB)     : {avg_mem:.4f}")
print(f"⏳ Total Elapsed (s)     : {total_time:.2f}")
print("===============================================================\n")

# print failed domains (status == danger)
if missed_domains:
    print(f"--- DOMAIN YANG GAGAL (status='danger') [{len(missed_domains)} total] ---")
    # Tampilkan max 20 agar terminal tidak penuh jika banyak
    for d in missed_domains[:20]: 
        print(f"- {d}")
    if len(missed_domains) > 20:
        print(f"... dan {len(missed_domains) - 20} lainnya.")
    print("---------------------------------------------------------------\n")

# Save CSV
fieldnames = [
    "domain", "url_sent", "ok", "status", "message",
    "detection_duration_ms", "memory_usage_mb", "error"
]
with OUTPUT_CSV.open("w", encoding="utf-8", newline="") as csvf:
    writer = csv.DictWriter(csvf, fieldnames=fieldnames)
    writer.writeheader()
    for r in rows_out:
        # Bersihkan None values menjadi empty string
        writer.writerow({k: ("" if r.get(k) is None else r.get(k)) for k in fieldnames})

print(f"Per-URL results saved to: {OUTPUT_CSV.resolve()}")