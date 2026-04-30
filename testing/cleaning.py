import pandas as pd

def clean_and_sample_homographs(input_file, output_file, target_samples=7000):
    print(f"[*] Loading dataset: {input_file}...")
    try:
        df = pd.read_csv(input_file)
    except FileNotFoundError:
        print(f"[!] Error: File '{input_file}' tidak ditemukan.")
        return

    # Filter 1: Hanya ambil label malicious (1)
    # Filter 2: Pastikan attack_type bukan 'none' untuk menggaransi itu adalah serangan homograph
    print("[*] Filtering malicious homograph domains...")
    malicious_homographs = df[(df['label'] == 1) & (df['attack_type'] != 'none')].copy()
    
    total_found = len(malicious_homographs)
    print(f"[*] Total malicious homographs ditemukan: {total_found}")

    if total_found == 0:
        print("[!] Tidak ada data yang sesuai kriteria.")
        return

    # Melakukan random sampling sebanyak 7000 data
    if total_found >= target_samples:
        print(f"[*] Melakukan random sampling sebanyak {target_samples} baris (random_state=42)...")
        # Menggunakan random_state agar hasilnya reproducible jika script di-run ulang
        final_df = malicious_homographs.sample(n=target_samples, random_state=42)
    else:
        print(f"[!] Peringatan: Jumlah data ({total_found}) kurang dari target ({target_samples}).")
        print("[*] Menyimpan semua data yang tersedia.")
        final_df = malicious_homographs

    # Menyimpan hasil ke file CSV baru
    print(f"[*] Menyimpan dataset bersih ke: {output_file}...")
    final_df.to_csv(output_file, index=False)
    
    # Menampilkan distribusi jenis serangan homograph dari 7000 data terpilih
    print("\n=== Distribusi Tipe Serangan Homograph (Sampled) ===")
    print(final_df['attack_type'].value_counts())
    print("====================================================")
    print("[+] Data cleaning selesai!")

# Eksekusi fungsi dengan memanggil nama file secara verbatim
input_filename = 'Adversarial Homograph Detection.csv'
output_filename = 'Cleaned_7000_Malicious_Homographs.csv'

clean_and_sample_homographs(input_filename, output_filename)
