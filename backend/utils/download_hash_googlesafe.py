import sqlite3
import requests
import base64
from pathlib import Path
import json
import os

# --- KONFIGURASI ---
BASE_DIR = Path(__file__).resolve().parent
DB_FILE =  BASE_DIR / "safe_browsing.db"
API_KEY = "xxxx"
CLIENT_ID = "tdvguard"
CLIENT_VERSION = "1.0.0"

def setup_database():
    """Membuat database dan tabel jika belum ada."""
    print("Mempersiapkan database...")
    with sqlite3.connect(DB_FILE) as con:
        cur = con.cursor()
        # Tabel untuk menyimpan hash prefixes (BLOB untuk data biner)
        # PRIMARY KEY akan otomatis membuat index untuk pencarian super cepat.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS hashes (
                hash_prefix BLOB PRIMARY KEY
            )
        """)
        # Tabel untuk menyimpan 'clientState' agar tahu update terakhir
        cur.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
    print("Database siap.")

def initial_download():
    """Mengunduh seluruh daftar hash dan menyimpannya ke SQLite."""
    if not API_KEY or API_KEY == "GANTI_DENGAN_API_KEY_ANDA":
        print("❌ Error: Harap ganti 'API_KEY' dengan kunci asli Anda.")
        return

    print("Memulai proses unduhan awal...")
    url = f"https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch?key={API_KEY}"

    payload = {
        "client": {
            "clientId": CLIENT_ID,
            "clientVersion": CLIENT_VERSION
        },
        "listUpdateRequests": [
            {
                "threatType": "MALWARE",
                "platformType": "ANY_PLATFORM",
                "threatEntryType": "URL",
                "state": "",  # State kosong untuk meminta full update
            },
            {
                "threatType": "SOCIAL_ENGINEERING", # Phishing
                "platformType": "ANY_PLATFORM",
                "threatEntryType": "URL",
                "state": "",
            }
        ]
    }

    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()  # Cek jika ada error HTTP
        data = response.json()
        
        print("Respons diterima, memproses data...")
        process_updates(data)

    except requests.exceptions.RequestException as e:
        print(f"❌ Gagal melakukan permintaan ke API: {e}")
    except json.JSONDecodeError:
        print("❌ Gagal mem-parsing respons JSON dari server.")

def process_updates(data):
    """Memproses respons dari API dan memasukkannya ke database."""
    with sqlite3.connect(DB_FILE) as con:
        cur = con.cursor()
        
        for update in data.get('listUpdateResponses', []):
            # 1. Menangani Penambahan (Additions)
            additions = update.get('additions', [])
            if additions:
                hashes_to_add = []
                for addition in additions:
                    raw_hashes = addition.get('rawHashes', {})
                    prefix_size = raw_hashes.get('prefixSize', 0)
                    hashes_data = base64.b64decode(raw_hashes.get('rawHashes', ''))
                    
                    # Potong data hash sesuai ukurannya (prefixSize)
                    for i in range(0, len(hashes_data), prefix_size):
                        hashes_to_add.append((hashes_data[i:i+prefix_size],))
                
                if hashes_to_add:
                    # 'OR IGNORE' agar tidak error jika hash sudah ada
                    cur.executemany("INSERT OR IGNORE INTO hashes (hash_prefix) VALUES (?)", hashes_to_add)
                    print(f"✅ Berhasil menambahkan {len(hashes_to_add)} hash baru.")

            # 2. Menyimpan clientState yang baru
            new_state = update.get('newClientState')
            if new_state:
                # 'REPLACE' akan insert jika belum ada, atau update jika sudah ada
                list_key = f"{update['threatType']}_{update['platformType']}"
                cur.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)", (list_key, new_state))
                print(f"🔑 clientState untuk '{list_key}' disimpan.")
        
        con.commit()
    print("Proses unduhan awal selesai.")

if __name__ == "__main__":
    if os.path.exists(DB_FILE):
        overwrite = input(f"File database '{DB_FILE}' sudah ada. Timpa dengan data baru? (y/n): ").lower()
        if overwrite != 'y':
            print("Operasi dibatalkan.")
        else:
            os.remove(DB_FILE)
            setup_database()
            initial_download()
    else:
        setup_database()
        initial_download()