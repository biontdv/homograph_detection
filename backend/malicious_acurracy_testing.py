import csv
from urllib.parse import urlparse
import sys
import os
from contextlib import contextmanager
import logging
from collections import defaultdict
import time    # <-- DITAMBAHKAN: Untuk mengukur waktu
import psutil  # <-- DITAMBAHKAN: Untuk mengukur memori

# ================= KONFIGURASI =================
CSV_FILE = "./testing/generated_all_cases.csv"
# ===============================================

# Sembunyikan log ERROR yang tidak kritikal dari library whois
logging.getLogger('whois.whois').setLevel(logging.CRITICAL)

# Impor semua fungsi deteksi yang diperlukan
try:
    from domain_extract import extract
    from whitelist_tld import whitelist
    from check_mix_script import has_mixed_scripts
    from tld_sld_compare import compare_tld
    from mapping import mapper
    from goole_safebrowsing import check_url_fully
    from non_standart_latin import check_standart_latin
    from utils.load_whitelist import load_resources
except ImportError as e:
    print(f"Error Impor Modul: {e}")
    print("Pastikan skrip ini berada di direktori yang sama dengan file proyek Anda.")
    exit()

@contextmanager
def suppress_stdout():
    """Blokir sementara semua output print (stdout)."""
    with open(os.devnull, "w", encoding="utf-8") as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:
            yield
        finally:
            sys.stdout = old_stdout

# --- FUNGSI 'run_detection_logic' DIMODIFIKASI ---
def run_detection_logic(url: str) -> dict:
    """
    Tiru alur logika dari endpoint /sendurl di app.py dan ukur performa.
    Mengembalikan dictionary berisi status, durasi, dan penggunaan memori.
    """
    # Inisialisasi pengukuran performa
    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss
    start_time = time.time()

    verdict = "safe" # Default verdict

    host = urlparse(url).hostname
    if not host:
        verdict = "safe"
    else:
        try:
            unicode_host = host.encode("ascii").decode("idna")
        except UnicodeError:
            unicode_host = host
        
        decoded_url = urlparse(url).scheme + "://" + unicode_host + urlparse(url).path
        domain, sld, tld = extract(decoded_url)

        with suppress_stdout():
            if whitelist(tld) == 'stop':
                verdict = "safe"
            elif len(has_mixed_scripts(sld)) > 1:
                verdict = "danger"
            elif check_standart_latin(sld) == 'stop':
                verdict = "danger"
            elif (result := compare_tld(sld, tld)) and result[0] == 'stop':
                verdict = "danger"
            elif (result := mapper(domain)) and result[0] == 'stop':
                verdict = "danger"
            else:
                gsb_result = check_url_fully(decoded_url)
                if gsb_result and len(gsb_result) > 1 and gsb_result[1] == 'danger':
                    verdict = "danger"

    # Selesaikan pengukuran performa
    end_time = time.time()
    mem_after = process.memory_info().rss
    
    duration_ms = (end_time - start_time) * 1000
    memory_usage_mb = (mem_after - mem_before) / (1024 * 1024)

    return {
        "status": verdict,
        "detection_duration_ms": duration_ms,
        "memory_usage_mb": memory_usage_mb if memory_usage_mb > 0 else 0.0
    }

def main():
    print("Memuat resource yang dibutuhkan...")
    with suppress_stdout():
        load_resources()
    print("Resource berhasil dimuat.\n")

    try:
        with open(CSV_FILE, mode="r", newline="", encoding="utf-8-sig") as file:
            reader = csv.DictReader(file)
            domain_list = [row for row in reader if row.get("generated_domain")]

            if not domain_list:
                print("⚠️  File CSV kosong atau tidak berisi kolom 'generated_domain'.")
                return

            total_domains = len(domain_list)

            # --- STATS DIMODIFIKASI: Tambahkan key untuk durasi dan memori ---
            stats = defaultdict(lambda: {
                "detected": 0, 
                "missed": 0, 
                "error": 0,
                "total_duration_ms": 0.0,
                "total_memory_mb": 0.0
            })
            missed_domains = defaultdict(list)
            errored_domains = defaultdict(list)

            for i, row in enumerate(domain_list):
                gen_domain = row["generated_domain"].strip()
                case = row.get("case", "UNKNOWN")
                print(f"⚙️  Mengecek domain: {i + 1}/{total_domains}", end="\r")

                try:
                    full_url = f"http://{gen_domain}"
                    # --- PANGGILAN FUNGSI DIMODIFIKASI: Sekarang menerima dictionary ---
                    result = run_detection_logic(full_url)
                    verdict = result["status"]

                    # Akumulasi data performa
                    stats[case]["total_duration_ms"] += result["detection_duration_ms"]
                    stats[case]["total_memory_mb"] += result["memory_usage_mb"]

                    if verdict == "danger":
                        stats[case]["detected"] += 1
                    else:
                        stats[case]["missed"] += 1
                        missed_domains[case].append(gen_domain)

                except Exception as e:
                    stats[case]["error"] += 1
                    errored_domains[case].append((gen_domain, str(e)))

            print(" " * 60, end="\r")
            print(f"✨ Pengecekan {total_domains} domain telah selesai.\n")

    except FileNotFoundError:
        print(f"❌ Error: File '{CSV_FILE}' tidak ditemukan.")
        return

    # Hitung total
    total_detected = sum(c["detected"] for c in stats.values())
    total_missed = sum(c["missed"] for c in stats.values())
    total_error = sum(c["error"] for c in stats.values())
    total_tested = total_detected + total_missed
    accuracy = (total_detected / total_tested) * 100 if total_tested else 0

    # --- TAMPILAN HASIL DIMODIFIKASI: Tambahkan output performa ---
    print("================== HASIL PENGUJIAN PER CASE ==================")
    for case, c in stats.items():
        case_total_tested = c["detected"] + c["missed"]
        case_acc = (c["detected"] / case_total_tested) * 100 if case_total_tested else 0
        
        # Hitung rata-rata
        avg_duration = c["total_duration_ms"] / case_total_tested if case_total_tested else 0
        avg_memory = c["total_memory_mb"] / case_total_tested if case_total_tested else 0
        
        print(f"[{case}]")
        print(f"  ✅ Terdeteksi          : {c['detected']}")
        print(f"  🚨 Missed              : {c['missed']}")
        print(f"  🔥 Error               : {c['error']}")
        print(f"  🎯 Akurasi             : {case_acc:.2f}%")
        print(f"  ⏱️  Avg. Duration (ms)  : {avg_duration:.2f}")
        print(f"  💾 Avg. Memory (MB)    : {avg_memory:.4f}\n")

    # Ringkasan total
    print("================== HASIL PENGUJIAN TOTAL ==================")
    print(f"Total Domain Diuji      : {total_tested} (dari {total_domains} baris)")
    print(f"✅ Berhasil Terdeteksi   : {total_detected}")
    print(f"🚨 Gagal Terdeteksi      : {total_missed}")
    print(f"🔥 Domain Error          : {total_error}")
    print("---------------------------------------------------------------")
    print(f"🎯 Tingkat Akurasi Total   : {accuracy:.2f}%")
    print("===============================================================")

    # Daftar missed & error
    for case, domains in missed_domains.items():
        if domains:
            print(f"\n--- Missed ({case}) ---")
            for d in domains:
                print(f"- {d}")

    for case, errors in errored_domains.items():
        if errors:
            print(f"\n--- Error ({case}) ---")
            for d, msg in errors:
                print(f"- {d} (Error: {msg})")

if __name__ == "__main__":
    main()