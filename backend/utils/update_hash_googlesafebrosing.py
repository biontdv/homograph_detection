import sqlite3
import requests
from pathlib import Path
import base64
import json

# --- KONFIGURASI (Sama seperti sebelumnya) ---
BASE_DIR = Path(__file__).resolve().parent
API_KEY = "xxxxx"
DB_FILE =  BASE_DIR / "safe_browsing.db"
CLIENT_ID = "tdvguard"
CLIENT_VERSION = "1.0.0"

def get_client_state(threat_type, platform_type):
    """Mengambil clientState terakhir dari database."""
    with sqlite3.connect(DB_FILE) as con:
        cur = con.cursor()
        key = f"{threat_type}_{platform_type}"
        cur.execute("SELECT value FROM metadata WHERE key = ?", (key,))
        result = cur.fetchone()
        return result[0] if result else ""

def update_blacklist():
    """Meminta dan menerapkan pembaruan diferensial."""
    if not API_KEY or API_KEY == "GANTI_DENGAN_API_KEY_ANDA":
        print("❌ Error: Harap ganti 'API_KEY' dengan kunci asli Anda.")
        return

    print("Memulai proses pembaruan blacklist...")
    url = f"https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch?key={API_KEY}"

    # Membuat list update request berdasarkan state yang ada di DB
    list_update_requests = []
    threat_lists = [
        ("MALWARE", "ANY_PLATFORM"),
        ("SOCIAL_ENGINEERING", "ANY_PLATFORM")
    ]
    for threat_type, platform_type in threat_lists:
        state = get_client_state(threat_type, platform_type)
        list_update_requests.append({
            "threatType": threat_type,
            "platformType": platform_type,
            "threatEntryType": "URL",
            "state": state
        })

    payload = {
        "client": {
            "clientId": CLIENT_ID,
            "clientVersion": CLIENT_VERSION
        },
        "listUpdateRequests": list_update_requests
    }

    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        data = response.json()
        
        print("Respons pembaruan diterima, memproses...")

        process_updates(data) 
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Gagal melakukan permintaan pembaruan: {e}")

# Fungsi process_updates dari skrip pertama bisa di-copy paste ke sini.
# Pastikan fungsi itu ada di file ini.
def process_updates(data):
    """Memproses respons dari API dan memasukkannya ke database."""
    with sqlite3.connect(DB_FILE) as con:
        cur = con.cursor()
        
        update_count = 0
        for update in data.get('listUpdateResponses', []):
            if update.get('responseType') == 'FULL_UPDATE':
                 print(f"⚠️ Diterima FULL_UPDATE untuk {update['threatType']}. Mungkin state kadaluarsa.")
                 # Di sini Anda bisa memanggil fungsi unduh awal lagi untuk list ini
                 
            # 1. Menangani Penambahan (Additions)
            additions = update.get('additions', [])
            if additions:
                hashes_to_add = []
                for addition in additions:
                    raw_hashes = addition.get('rawHashes', {})
                    prefix_size = raw_hashes.get('prefixSize', 0)
                    hashes_data = base64.b64decode(raw_hashes.get('rawHashes', ''))
                    
                    for i in range(0, len(hashes_data), prefix_size):
                        hashes_to_add.append((hashes_data[i:i+prefix_size],))
                
                if hashes_to_add:
                    cur.executemany("INSERT OR IGNORE INTO hashes (hash_prefix) VALUES (?)", hashes_to_add)
                    update_count += len(hashes_to_add)

            # 2. Menyimpan clientState yang baru
            new_state = update.get('newClientState')
            if new_state:
                list_key = f"{update['threatType']}_{update['platformType']}"
                cur.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)", (list_key, new_state))
        
        con.commit()
        if update_count > 0:
            print(f"✅ Berhasil menambahkan/memperbarui {update_count} hash.")
        else:
            print("✅ Database sudah mutakhir, tidak ada penambahan baru.")

if __name__ == "__main__":
    update_blacklist()