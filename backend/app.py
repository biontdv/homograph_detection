
import psutil
import tracemalloc
import os
from flask import Flask, request, jsonify
from domain_extract import extract
from whitelist_tld import whitelist
from check_mix_script import has_mixed_scripts
from tld_sld_compare import compare_tld
from mapping import mapper
#from mapping_standart import mapper
from goole_safebrowsing import check_url_fully
import time
from urllib.parse import urlparse
from non_standart_latin import check_standart_latin
from utils.load_whitelist import load_resources
from domain_checker import is_in_whitelisted
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
load_resources()

COUNTER_FILE = "analysis_counter.txt"
def get_analysis_count():
    """Membaca jumlah hitungan dari file."""
    try:
        with open(COUNTER_FILE, 'r') as f:
            return int(f.read())
    except (IOError, ValueError):
     
        return 0

def increment_analysis_count():
    """Menambah hitungan dan menyimpannya kembali ke file."""
    count = get_analysis_count() + 1
    with open(COUNTER_FILE, 'w') as f:
        f.write(str(count))
    print(f"[INFO] Analysis count is now: {count}")

# cache in-memory
cache = {}
CACHE_TTL = 3600  # 1 jam

def set_cache(domain, verdict):
    cache[domain] = (verdict, time.time())

def get_cache(domain):
    if domain in cache:
        verdict, ts = cache[domain]
        if time.time() - ts < CACHE_TTL:
            print(f"[CACHE] Hit {domain}")
            return verdict
        else:
            del cache[domain]
    return None


@app.route('/sendurl', methods=['POST', 'OPTIONS'])
def receive_url():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({"error": "Missing 'url' in JSON data"}), 400

    # Persiapan URL dan domain
    host = urlparse(url).hostname
    try:
        unicode_host = host.encode("ascii").decode("idna")
    except UnicodeError:
        unicode_host = host
    decoded_url = urlparse(url).scheme + "://" + unicode_host + urlparse(url).path
    domain, sld, tld = extract(decoded_url)


    print(f"[INFO] Check: {decoded_url}")
    print(f"[INFO] domain: {domain}")
    print(f"[INFO] sld: {sld}")
    print(f"[INFO] tld: {tld}")
    print("=====================================")

    # Cek cache terlebih dahulu. DISABLED IF DONT WANT TO USE CACHE
    if (cached := get_cache(domain)):
        # Jika dari cache, durasi proses dianggap 0 karena tidak ada analisis
        # Pastikan data lama dari cache juga memiliki key ini untuk konsistensi
        if 'detection_duration_ms' not in cached:
            cached['detection_duration_ms'] = 0.0
        return jsonify(cached), 200
    
    #call api counter function
    #increment_analysis_count() 
    # Dapatkan informasi proses
    tracemalloc.start()
    start_time = time.perf_counter()
    
    try:
        verdict = {} # Inisialisasi dictionary verdict

        # Analisis step-by-step (tanpa return langsung)
        # if whitelist(tld) == 'stop':
        #     verdict = {
        #         "message": "URL in whitelist TLD",
        #         "status": "safe",
        #         "url": decoded_url, "sld": sld, "tld": tld
        #     }
        if (len(scripts := has_mixed_scripts(sld)) > 1):
            verdict = {
                "message": "Homograph detected, URL has mix script",
                "status": "danger",
                "url": decoded_url, "sld": sld, "tld": tld,
                "script": list(scripts)
            }
            print("danger")
        elif (check_standart_latin(sld)=='stop'):
            verdict = {
                "message": "Homograph detected, not using standart latin script",
                "status": "danger",
                "url": decoded_url, "sld": sld, "tld": tld
            }
            print("danger")        
        elif (result := compare_tld(sld, tld)) and result[0] == 'stop':
            status, tld_, script_name = result
            verdict = {
                "message": f"Homograph detected, mismatch SLD vs TLD script {script_name}",
                "status": "danger", "url": decoded_url, "sld": sld, "tld": tld_
            }
            print("danger")
        elif (result := mapper(domain,sld,tld)) and result[0] == 'stop':
            status, mirip_dengan, kemungkinan = result
            verdict = {
                "message": f"Homograph detected → Real Domain: {domain} is similar to {mirip_dengan}",
                "status": "danger", "url": decoded_url, "sld": sld, "tld": tld
            }
            print("danger")
        elif (result := check_url_fully(decoded_url)) and result[1] == 'danger':
            domain_age, status = result
            verdict = {
                "message": "URL in blacklist",
                "status": status, "url": decoded_url,
                "age": domain_age, "sld": sld, "tld": tld
            }
            print("danger")
        else:
            verdict = {
                "message": "URL is safe",
                "status": "safe", "url": decoded_url, "sld": sld, "tld": tld
            }
            print("safe")

        # Waktu #3: Hentikan timer SETELAH semua analisis selesai
        end_time = time.perf_counter()
        current, peak = tracemalloc.get_traced_memory()
        
        # 4. Stop tracking agar hemat resource
        tracemalloc.stop()
        processing_duration_ms = (end_time - start_time) * 1000
        memory_usage_mb = peak / (1024 * 1024)

        # Tambahkan durasi ke dalam verdict SEBELUM dikirim atau disimpan di cache
        verdict['detection_duration_ms'] = processing_duration_ms
        verdict['memory_usage_mb'] = round(memory_usage_mb, 2)
        
        # Simpan verdict yang sudah LENGKAP ke cache
        set_cache(domain, verdict)
        
        # Kirim response final
        return jsonify(verdict), 200
    
    except Exception as e:
        tracemalloc.stop()
        # Handle exception dan kembalikan error 500
        return jsonify({"error": str(e)}), 500



@app.route('/')
def index():
    return "Backend is running! Send POST requests to /sendurl"

# --- Fungsi /domainchecker 
@app.route('/domainchecker', methods=['POST', 'OPTIONS'])
def check_domain():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200

    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.get_json()
    domain = data.get('domain')
    
    if not domain:
        return jsonify({"error": "Missing 'domain' in JSON data"}), 400

    is_whitelisted = is_in_whitelisted(domain)
    return jsonify({"domain": domain, "is_whitelisted": is_whitelisted}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)