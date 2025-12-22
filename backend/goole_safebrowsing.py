import sqlite3
import hashlib
import os
import requests
import urllib.parse
from pathlib import Path
import whois
from urllib.parse import urlparse
from datetime import datetime

# --- KONFIGURASI ---
BASE_DIR = Path(__file__).resolve().parent
API_KEY = "xxxx"
DB_FILE = BASE_DIR / "utils" / "safe_browsing.db"
HASH_PREFIX_SIZE = 4

def canonicalize_url(url: str) -> str:
    """
    Melakukan kanonisasi awal pada URL sesuai aturan GSB.
    """
    # 1. Pastikan URL memiliki skema, jika tidak tambahkan http://
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'http://' + url

    # 2. Hapus fragmen (#...)
    url = url.split('#', 1)[0]
    
    # 3. Lakukan un-escape berulang kali
    while True:
        unquoted = urllib.parse.unquote(url)
        if unquoted == url:
            break
        url = unquoted
        
    # 4. Parse URL menjadi komponennya
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname or ''
    path = parsed.path or '/'
    query = parsed.query
    
    # 5. Kanonisasi Hostname
    # Ubah ke huruf kecil
    hostname = hostname.lower()
    # Hapus titik di awal dan akhir
    hostname = hostname.strip('.')
    # Ganti titik berulang dengan satu titik
    hostname = '.'.join(filter(None, hostname.split('.')))
    
    # 6. Kanonisasi Path
    # Sederhanakan path (/a/./b/../c -> /a/c)
    path_segments = path.split('/')
    resolved_path = []
    for segment in path_segments:
        if segment == '.':
            continue
        if segment == '..':
            if resolved_path:
                resolved_path.pop()
        else:
            resolved_path.append(segment)
    if not resolved_path:
        path = '/'
    else:
        path = '/' + '/'.join(resolved_path)
        if url.endswith('/') and not path.endswith('/'):
            path += '/'

    # 7. Gabungkan kembali URL
    # Skema tidak dimasukkan karena GSB menghash host + path
    final_url = hostname + path
    if query:
        final_url += '?' + query
        
    return final_url


def get_domain_age_in_days(url: str) -> int:
    try:
        domain_name = urlparse(url).netloc
        if not domain_name: return 0
        w = whois.whois(domain_name)
        creation_date = w.creation_date
        if isinstance(creation_date, list): creation_date = creation_date[0]
        if creation_date: return (datetime.now() - creation_date).days
        return 0
    except Exception:
        return 0

def check_google_safe_browsing(url: str) -> str:
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
    payload = { "client": {"clientId": "my-python-app", "clientVersion": "3.0.0"}, "threatInfo": { "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}] } }
    try:
        response = requests.post(api_url, json=payload, timeout=5)
        response.raise_for_status()
        if 'matches' in response.json():
            #print("  [Google] Hasil: URL terdeteksi sebagai berbahaya.")
            return "danger"
        return "safe"
    except requests.exceptions.RequestException:
        return "safe"


def get_lookup_combinations(url: str):
    """
    Membuat semua kombinasi hostname dan path untuk di-hash.
    """
    # Pertama, kanonisasi URL utama
    canonical_url = canonicalize_url(url)
    
    # Parse kembali hasil kanonisasi untuk mendapatkan host dan path
    parsed = urllib.parse.urlparse('http://' + canonical_url) # Tambah skema agar bisa di-parse
    hostname = parsed.hostname
    path = parsed.path
    if parsed.query:
        path += '?' + parsed.query
        
    combinations = set()

    # 1. Kombinasi Path
    paths_to_check = ['/']
    if path != '/':
        paths_to_check.append(path)
        segments = path.split('/')
        # Ambil hingga 4 komponen path dari belakang
        if len(segments) > 2:
            paths_to_check.append('/'.join(segments[:3])) # /a/b
        if len(segments) > 3:
            paths_to_check.append('/'.join(segments[:4])) # /a/b/c
        if len(segments) > 4:
            paths_to_check.append('/'.join(segments[:5])) # /a/b/c/d

    # 2. Kombinasi Hostname
    hosts_to_check = []
    host_parts = hostname.split('.')
    # Ambil hingga 5 komponen hostname dari belakang
    if len(host_parts) <= 2:
        hosts_to_check.append(hostname)
    else:
        for i in range(max(0, len(host_parts) - 5), len(host_parts) - 1):
             hosts_to_check.append('.'.join(host_parts[i:]))

    # 3. Gabungkan semua kemungkinan
    for h in hosts_to_check:
        for p in paths_to_check:
            combinations.add(h + p)
            
    return list(combinations)

def check_url_fully(url_to_check: str):
    #domain_age= get_domain_age_in_days(url_to_check)
    """
    Menjalankan pipeline lengkap: kanonisasi, buat kombinasi, hash, dan cek ke DB.
    """
    if not os.path.exists(DB_FILE):
        #print(f"❌ Error: File database '{DB_FILE}' tidak ditemukan.")
        return False
        
    #print(f"\n▶️  Memulai pengecekan penuh untuk URL: {url_to_check}")
    
    # Langkah 1 & 2: Kanonisasi dan buat kombinasi
    combinations = get_lookup_combinations(url_to_check)
    #print(f"   - Dihasilkan {len(combinations)} kemungkinan kombinasi untuk diperiksa.")
    
    found_match = False
    with sqlite3.connect(DB_FILE) as con:
        cur = con.cursor()
        for combo in combinations:
            # Langkah 3: Hashing
            full_hash = hashlib.sha256(combo.encode('utf-8')).digest()
            hash_prefix = full_hash[:HASH_PREFIX_SIZE]
            
            # Langkah 4: Cek ke DB
            cur.execute("SELECT 1 FROM hashes WHERE hash_prefix = ?", (hash_prefix,))
            result = cur.fetchone()
            
            if result:
                #print(f"\n🚨 DITEMUKAN KECOCOKAN PADA DATABASE!")
                #print(f"   - Kombinasi Berbahaya: '{combo}'")
                #print(f"   - Hash Prefix: {hash_prefix.hex()}")
                found_match = True
                break # Hentikan pencarian jika sudah ditemukan satu
    
    #print("\n--- HASIL AKHIR ---")
    if found_match:
        #print("pala bapak 1")
        status="danger"
        return domain_age,status
    else:
        try:

            domain_age = get_domain_age_in_days(url_to_check)
            if domain_age > 30:
                status = "safe"
                return domain_age, status
            else:
                print("search in google safe browsing")
                status = check_google_safe_browsing(url_to_check)
                return domain_age, status

        except Exception as e:
            # 2. Jika terjadi error apapun di dalam blok 'try', 
            #    eksekusi akan loncat ke blok 'except' ini.
            print(f"Gagal mendapatkan info WHOIS karena error: {e}")
            print("Karena info umur domain tidak tersedia, melanjutkan dengan Google Safe Browsing...")
            
            # 3. Jalankan logika alternatif Anda di sini
            status = check_google_safe_browsing(url_to_check)
            return "N/A", status # Mengembalikan "N/A" karena umur domain gagal didapat


        
    

# if __name__ == "__main__":
#     # URL target dari pertanyaan
#     #target_url = "https://www.biontdvkocak.com/phishy-link"
    
#     # Untuk tujuan tes, kita tambahkan hash dari hasil kanonisasi URL ini
#     # agar bisa dipastikan "ditemukan".
#     # Hasil kanonisasi dari "evil.com/login/.." adalah "evil.com/"

#     #x=get_domain_age_in_days(target_url)
#     #print(x)
#     # Jalankan pengecekan penuh
#     #check_url_fully(target_url)