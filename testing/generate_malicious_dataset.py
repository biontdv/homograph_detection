#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generate malicious-looking domain datasets for testing phishing detection accuracy.

Inputs:
 - ../top-1m.csv  (expected to contain domains; will auto-detect column)

Outputs:
 - generated_case1.csv  (Homograph single-char mixed script)
 - generated_case2.csv  (Homograph with accented / not-standard-latin)
 - generated_case3.csv  (SLD vs TLD script mismatch)
 - generated_case4.csv  (Full Homograph)
 - generated_case5.csv  (Typosquatting single-char)
 - generated_all_cases.csv (combined)

Each case contains 1400 generated samples.
"""

import csv
import random
import sys
from pathlib import Path
from collections import defaultdict

random.seed(42)

TOP1M_PATH = "./tranco_GVQVK.csv"
import unicodedata
OUT_DIR = Path("./")
OUT_DIR.mkdir(parents=True, exist_ok=True)

WANT_PER_CASE = 1400

CONFUSABLES_PATH = "map_standart.txt"  # Nama file standart yang Anda berikan

def load_homograph_map_from_file(file_path):
    """
    Membaca file map_standart.txt (format Unicode confusables) dan
    membangun dictionary HOMOGRAPH_MAP.
    """
    mapping = defaultdict(list)
    path_obj = Path(file_path)
    
    if not path_obj.exists():
        print(f"[WARNING] File '{file_path}' tidak ditemukan! Case 4 mungkin tidak menghasilkan data yang valid.", file=sys.stderr)
        return {}

    print(f"[INFO] Loading homograph map from {file_path}...")
    
    try:
        with open(path_obj, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                # Abaikan komentar dan baris kosong
                if line.strip().startswith('#') or not line.strip():
                    continue
                
                parts = line.split(';')
                if len(parts) < 2:
                    continue
                
                # Format: Source ; Target ; Type ...
                # Source adalah karakter 'mirip' (homograph)
                # Target adalah karakter asli (ASCII latin)
                source_hex = parts[0].strip()
                target_hex = parts[1].strip()
                
                try:
                    # Target bisa terdiri dari beberapa karakter (sequence), kita ambil yang single char saja
                    target_chars = "".join([chr(int(c, 16)) for c in target_hex.split()])
                    
                    # Kita hanya peduli jika targetnya adalah huruf latin kecil (a-z)
                    # karena domain di script ini diproses dalam lowercase.
                    if len(target_chars) == 1 and 'a' <= target_chars <= 'z':
                        # Source biasanya single char di kolom pertama
                        source_char = chr(int(source_hex, 16))
                        
                        # Jangan masukkan jika karakternya sama persis
                        if source_char != target_chars:
                            mapping[target_chars].append(source_char)
                            
                except ValueError:
                    continue
                    
    except Exception as e:
        print(f"[ERROR] Gagal membaca file homograph: {e}", file=sys.stderr)
        return {}

    print(f"[INFO] Berhasil memuat homograph untuk {len(mapping)} karakter ASCII.")
    return dict(mapping)

HOMOGRAPH_MAP = load_homograph_map_from_file(CONFUSABLES_PATH)

def get_script_name(char):
    """Mengembalikan nama script utama dari sebuah karakter."""
    try:
        name = unicodedata.name(char).upper()
        if 'CYRILLIC' in name: return 'Cyrillic'
        if 'GREEK' in name: return 'Greek'
        if 'ARMENIAN' in name: return 'Armenian'
        if 'HEBREW' in name: return 'Hebrew'
        if 'ARABIC' in name: return 'Arabic'
        if 'THAI' in name: return 'Thai'
        if 'LATIN' in name: return 'Latin'
        return 'Common' # Untuk angka, simbol, dll
    except ValueError:
        return 'Unknown'



DIACRITIC_POOL = list("áàâäãåéèêëíìîïóòôõöúùûüçčćñýÿžšđğčć") + [
    'É', 'Ç', 'Š', 'Ł', 'Ø', 'Å', 'Ž', 'Ð', 'Þ', 'œ', 'æ', 'ș', 'ț'
]

TYPOS_MAP = {
    'o': ['0', 'ο', 'О'],
    'l': ['1', 'I', '|'],
    'i': ['1', 'l', 'ı'],
    'e': ['3', '€'],
    's': ['5', '$'],
    'a': ['4'],
    'g': ['9'],
    'b': ['6', '8'],
    't': ['7'],
    'c': ['('],
    'z': ['2']
}

# ---------------------------
# TLD script rules
# ---------------------------
tld_allowed_scripts = {
    'com': {'ANY'}, 'net': {'ANY'}, 'org': {'ANY'}, 'info': {'ANY'}, 'biz': {'ANY'}, 'co': {'ANY'},
    'io': {'ANY'}, 'me': {'ANY'}, 'tv': {'ANY'}, 'xyz': {'ANY'}, 'online': {'ANY'}, 'site': {'ANY'},
    'shop': {'ANY'}, 'top': {'ANY'}, 'club': {'ANY'}, 'store': {'ANY'}, 'app': {'ANY'}, 'pro': {'ANY'},
    'name': {'ANY'}, 'tech': {'ANY'}, 'blog': {'ANY'}, 'website': {'ANY'}, 'my': {'ANY'},
    'gov': {'Latin'}, 'edu': {'Latin'}, 'mil': {'Latin'}, 'int': {'Latin'},
    'id': {'Latin'}, 'au': {'Latin'}, 'uk': {'Latin'}, 'us': {'Latin'}, 'ca': {'Latin'}, 'de': {'Latin'},
    'fr': {'Latin'}, 'it': {'Latin'}, 'es': {'Latin'}, 'nl': {'Latin'}, 'se': {'Latin'}, 'no': {'Latin'},
    'dk': {'Latin'}, 'fi': {'Latin'}, 'be': {'Latin'}, 'ch': {'Latin'}, 'nz': {'Latin'}, 'ie': {'Latin'},
    'pt': {'Latin'}, 'pl': {'Latin'}, 'cz': {'Latin'}, 'ro': {'Latin'}, 'hu': {'Latin'}, 'sk': {'Latin'},
    'si': {'Latin'}, 'hr': {'Latin'}, 'lt': {'Latin'}, 'lv': {'Latin'}, 'ee': {'Latin'}, 'mx': {'Latin'},
    'ar': {'Latin'}, 'br': {'Latin'}, 'cl': {'Latin'}, 'pe': {'Latin'}, 'vn': {'Latin'}, 'sg': {'Latin'},
    'ph': {'Latin'}, 'is': {'Latin'},
    'ru': {'Cyrillic', 'Latin'}, 'рф': {'Cyrillic', 'Latin'}, 'ua': {'Cyrillic', 'Latin'}, 'mn': {'Cyrillic', 'Latin'},
    'gr': {'Greek', 'Latin'}, 'ελ': {'Greek', 'Latin'},
    'sa': {'Arabic', 'Latin'}, 'ae': {'Arabic', 'Latin'}, 'eg': {'Arabic', 'Latin'}, 'iq': {'Arabic', 'Latin'},
    'jp': {'Hiragana', 'Katakana', 'Han', 'Latin'}, 'kr': {'Hangul', 'Latin'},
    'in': {'Devanagari', 'Latin'}, 'bd': {'Bengali', 'Latin'}, 'th': {'Thai', 'Latin'},
    'il': {'Hebrew', 'Latin'}, 'et': {'Ethiopic', 'Latin'}, 'am': {'Armenian', 'Latin'}, 'ge': {'Georgian', 'Latin'}
}

# ---------------------------
# Helpers
# ---------------------------
def read_top1m(path):
    """Read top-1m csv and return list of domains."""
    path = Path(path)
    if not path.exists():
        print(f"[ERROR] File not found: {path}", file=sys.stderr)
        return []
    domains = []
    with path.open('r', encoding='utf-8', errors='replace') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            for cell in row:
                if '.' in cell and not cell.strip().isdigit():
                    domains.append(cell.strip().lower())
                    break
    # deduplicate
    seen, unique = set(), []
    for d in domains:
        if d not in seen:
            seen.add(d)
            unique.append(d)
    return unique

def split_sld_tld(domain):
    """
    Memisahkan domain menjadi SLD (termasuk subdomain) dan TLD 
    dengan heuristic sederhana untuk menangani ccTLD (misal: .com.au, .co.id).
    """
    domain = domain.strip().lower()
    parts = domain.split('.')
    
    if len(parts) < 2:
        return domain, ''
        
    # Heuristic: Jika domain memiliki minimal 3 bagian (misal a.b.c)
    # Cek apakah ini multi-part TLD (seperti .com.au, .co.id, .gov.uk)
    # Logic: Jika part terakhir 2 huruf (ccTLD) DAN part sebelumnya pendek (<=4 huruf)
    tld_parts_count = 1
    if len(parts) >= 3:
        last = parts[-1]
        second_last = parts[-2]
        
        # Daftar ini bisa diperluas, tapi logic len<=4 sudah mencakup com, net, org, co, edu, gov, ac, mil
        if len(last) == 2 and (len(second_last) <= 4):
            tld_parts_count = 2
    
    # Gabungkan bagian TLD
    tld = ".".join(parts[-tld_parts_count:])
    
    # Gabungkan SEMUA bagian sisa di sebelah kiri sebagai SLD
    # Ini memastikan 'essentialenergy' tidak hilang meskipun struktur domainnya panjang
    sld = ".".join(parts[:-tld_parts_count])
    
    return sld, tld

def pick_replacement_for_char(ch):
    ch_lower = ch.lower()
    if ch_lower in HOMOGRAPH_MAP:
        return random.choice(HOMOGRAPH_MAP[ch_lower])
    return None

def make_single_char_homograph(domain):
    sld, tld = split_sld_tld(domain)
    if not sld or not tld:
        return None
    indices = [i for i, c in enumerate(sld) if c.lower() in HOMOGRAPH_MAP and c.isalpha()]
    if not indices:
        return None
    i = random.choice(indices)
    orig_char = sld[i]
    repl = pick_replacement_for_char(orig_char)
    if not repl:
        return None
    new_sld = sld[:i] + repl + sld[i+1:]
    return f"{new_sld}.{tld}"

def make_single_char_diacritic(domain):
    sld, tld = split_sld_tld(domain)
    if not sld or not tld:
        return None
    alpha_indices = [i for i, c in enumerate(sld) if c.isalpha()]
    if not alpha_indices:
        return None
    i = random.choice(alpha_indices)
    repl = random.choice(DIACRITIC_POOL)
    new_sld = sld[:i] + repl + sld[i+1:]
    return f"{new_sld}.{tld}"

def make_sld_tld_mismatch(domain):
    sld, tld = split_sld_tld(domain)
    if not sld:
        return None
    latin_only = [k for k, v in tld_allowed_scripts.items() if v == {'Latin'}]
    chosen_tld = random.choice(latin_only or ['id'])
    new_sld_chars = list(sld)
    changed = False
    for i, ch in enumerate(new_sld_chars):
        lower = ch.lower()
        if lower in HOMOGRAPH_MAP and random.random() < 0.6:
            nonlatin = [c for c in HOMOGRAPH_MAP[lower] if ord(c) > 127]
            if nonlatin:
                new_sld_chars[i] = random.choice(nonlatin)
                changed = True
    if not changed:
        for i, ch in enumerate(new_sld_chars):
            if ch.lower() in HOMOGRAPH_MAP:
                new_sld_chars[i] = random.choice(HOMOGRAPH_MAP[ch.lower()])
                break
    new_sld = ''.join(new_sld_chars)
    return f"{new_sld}.{chosen_tld}"

def make_all_chars_homograph(domain):
    """
    Full Homograph: Mencoba mengganti SELURUH karakter huruf di SLD
    menjadi karakter dari SATU script non-latin yang sama (Consistency Check).
    """
    sld, tld = split_sld_tld(domain)
    if not sld or not tld:
        return None

    # Daftar script target yang ingin dicoba untuk serangan Full Homograph
    # Script diurutkan berdasarkan kemungkinan keberhasilan (Cyrillic & Greek paling banyak mirip Latin)
    target_scripts = ['Cyrillic', 'Greek', 'Armenian']

    # Coba setiap script satu per satu
    for script in target_scripts:
        new_chars = []
        is_script_possible = True
        
        for ch in sld:
            lower = ch.lower()
            
            # Jika karakter bukan huruf (misal angka atau hyphen), biarkan saja (Common script)
            if not ch.isalpha():
                new_chars.append(ch)
                continue

            # Jika huruf tidak ada di map homograph, maka script ini GAGAL untuk domain ini
            # karena kita ingin "Full" replacement.
            if lower not in HOMOGRAPH_MAP:
                is_script_possible = False
                break

            # Cari pengganti yang berasal dari script target saat ini
            candidates_in_script = []
            for candidate in HOMOGRAPH_MAP[lower]:
                if get_script_name(candidate) == script:
                    candidates_in_script.append(candidate)
            
            # Jika tidak ada karakter pengganti di script ini, maka script ini GAGAL
            if not candidates_in_script:
                is_script_possible = False
                break
            
            # Pilih salah satu kandidat dari script yang sesuai
            new_chars.append(random.choice(candidates_in_script))

        # Jika seluruh karakter berhasil dikonversi ke script target, return hasilnya
        if is_script_possible:
            new_sld = ''.join(new_chars)
            # Pastikan hasil generate berbeda dari aslinya
            if new_sld != sld:
                return f"{new_sld}.{tld}"

    # Jika tidak ada satupun script yang bisa menampung seluruh karakter domain ini
    return None

def make_typosquatting(domain):
    sld, tld = split_sld_tld(domain)
    if not sld or not tld:
        return None
    indices = [i for i, c in enumerate(sld) if c.lower() in TYPOS_MAP]
    if not indices:
        vowels = [i for i, c in enumerate(sld) if c.lower() in 'aeiou']
        if vowels:
            i = random.choice(vowels)
            return f"{sld[:i]}0{sld[i+1:]}.{tld}"
        return None
    i = random.choice(indices)
    repl = random.choice(TYPOS_MAP[sld[i].lower()])
    new_sld = sld[:i] + repl + sld[i+1:]
    return f"{new_sld}.{tld}"

# ---------------------------
# Main generation loop
# ---------------------------
def generate_for_case(domains, case_fn, want=WANT_PER_CASE, allow_predicate=lambda d: True):
    results = []
    used = set()
    candidates = [d for d in domains if allow_predicate(d)]
    random.shuffle(candidates)
    for d in candidates:
        if len(results) >= want:
            break
        gen = None
        try:
            gen = case_fn(d)
        except Exception:
            gen = None
        if not gen or gen in used or ' ' in gen or '.' not in gen:
            continue
        used.add(gen)
        results.append((d, gen, case_fn.__name__))
    return results

def write_csv(path, rows):
    hdr = ['original_domain', 'generated_domain', 'case']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(hdr)
        for orig, gen, case in rows:
            writer.writerow([orig, gen, case])

def main():
    domains = read_top1m(TOP1M_PATH)
    if not domains:
        print("[ERROR] No domains read. Exiting.", file=sys.stderr)
        return
    print(f"[INFO] Read {len(domains)} unique domains from {TOP1M_PATH}")

    # Case 1
    print("[INFO] Generating case 1 (single-char homograph mix)...")
    case1 = generate_for_case(domains, make_single_char_homograph)
    write_csv(OUT_DIR / "generated_case1.csv", case1)

    # Case 2
    print("[INFO] Generating case 2 (single-char diacritic)...")
    case2 = generate_for_case(domains, make_single_char_diacritic)
    write_csv(OUT_DIR / "generated_case2.csv", case2)

    # Case 3
    print("[INFO] Generating case 3 (SLD vs TLD mismatch)...")
    case3 = generate_for_case(domains, make_sld_tld_mismatch)
    write_csv(OUT_DIR / "generated_case3.csv", case3)

    # Case 4
    print("[INFO] Generating case 4 (Full Homograph)...")
    case4 = generate_for_case(domains, make_all_chars_homograph)
    write_csv(OUT_DIR / "generated_case4.csv", case4)

    # Case 5
    print("[INFO] Generating case 5 (Typosquatting)...")
    case5 = generate_for_case(domains, make_typosquatting)
    write_csv(OUT_DIR / "generated_case5.csv", case5)

    # Combine all
    combined = case1 + case2 + case3 + case4 + case5
    write_csv(OUT_DIR / "generated_all_cases.csv", combined)
    print(f"[INFO] Combined file saved: generated_all_cases.csv (total {len(combined)})")

    print("[DONE] Files created:")
    for i in range(1,6):
        print(f" - generated_case{i}.csv")
    print(" - generated_all_cases.csv")

if __name__ == "__main__":
    main()


