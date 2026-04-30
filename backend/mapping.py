
import re
import utils.load_whitelist

# Global cache

PETA_HOMOGRAF = None

#uncomment below to use standart map and change path on line code 152
# def muat_peta_homograf(path_file):
  
#     peta = {}

#     try:
#         # Gunakan utf-8-sig untuk menangani BOM (\ufeff) di awal file jika ada
#         with open(path_file, "r", encoding="utf-8-sig") as f:
#             for line in f:
#                 line = line.strip()

#                 # Skip komentar & baris kosong
#                 if not line or line.startswith("#"):
#                     continue

#                 try:
#                     # Pastikan minimal ada 2 kolom (Source ; Target)
#                     parts = line.split(";", 2)
#                     if len(parts) < 2:
#                         continue
                        
#                     src_hex = parts[0].strip()
#                     target_hex = parts[1].strip()

#                     # Decode source character
#                     src_char = chr(int(src_hex, 16))
                    
#                     # [PERBAIKAN 1] Filter Source: Hanya ambil jika source BUKAN ASCII
#                     # Jika source sudah ASCII (misal " -> ''), kita skip agar tidak false positive
#                     if src_char.isascii():
#                         continue

#                     # Decode target (bisa multi codepoint)
#                     target_chars = "".join(chr(int(h, 16)) for h in target_hex.split())

#                     # Filter Target: Hanya ambil target ASCII (domain-safe)
#                     if target_chars and target_chars.isascii():
#                         peta.setdefault(src_char, []).append(target_chars)

#                 except (ValueError, IndexError):
#                     # Skip baris yang format hex-nya salah atau parsing gagal
#                     continue

#     except FileNotFoundError:
#         print(f"[ERROR] File mapping tidak ditemukan: {path_file}")
#         return {}

#     return peta



#custom map
def muat_peta_homograf(path_file):
    """
    [FIXED] Parsing file tdv_homoglyph_map.txt dengan akurat.
    Menangani format: "; Source (Lang) -> Target (Lang)" atau "; Source -> Target Desc"
    """
    peta = {}
    try:
        with open(path_file, 'r', encoding='utf-8-sig') as f:
            for baris in f:
                # 1. Buang komentar (#) dan whitespace
                baris_bersih = baris.split('#')[0].strip()
                
                # 2. PENTING: Buang titik koma (;) di awal baris jika ada
                # Karena di file Anda baris data dimulai dengan "; "
                if baris_bersih.startswith(';'):
                    baris_bersih = baris_bersih[1:].strip()

                if not baris_bersih:
                    continue
                
                # 3. Split berdasarkan panah '->'
                if '->' in baris_bersih:
                    kiri, kanan = baris_bersih.split('->', 1)
                    
                    char_non_latin = kiri.split('(')[0].strip()
                    

                    kanan_parts = kanan.strip().split()
                    
                    if kanan_parts:
                        # Ambil elemen pertama, misal: "A" dari "A Latin", atau "'bl'" dari "'bl' (Latin)"
                        raw_target = kanan_parts[0]
                        # Bersihkan tanda kutip tunggal jika ada (misal: 'bl' -> bl)
                        char_latin = raw_target.replace("'", "")
                    else:
                        continue # Skip jika kanan kosong

                    # Simpan ke map
                    if char_non_latin and char_latin:
                        if char_non_latin not in peta:
                            peta[char_non_latin] = []
                        
                        # Hindari duplikasi jika varian sama muncul 2x
                        if char_latin not in peta[char_non_latin]:
                            peta[char_non_latin].append(char_latin)

    except FileNotFoundError:
        print(f"[ERROR] File map tidak ditemukan: {path_file}")
        return {}
        
    return peta


def normalisasi_homograf(string_domain, peta_homograf, max_kandidat=500):
    """
    Menghasilkan semua kemungkinan normalisasi Latin dari sebuah string.
    Batasi jumlah kandidat agar tidak eksplosif.
    """
    hasil = set()

    def _rekursif(s, hasil_sementara):
        if len(hasil) >= max_kandidat:  # stop jika sudah cukup
            return
        if not s:
            hasil.add(hasil_sementara.lower())
            return

        char_saat_ini = s[0]
        sisa_string = s[1:]

        if char_saat_ini in peta_homograf:
            for normalisasi_char in peta_homograf[char_saat_ini]:
                _rekursif(sisa_string, hasil_sementara + normalisasi_char)
        else:
            _rekursif(sisa_string, hasil_sementara + char_saat_ini)

    _rekursif(string_domain, "")
    return sorted(list(hasil))




def cek_domain_phishing(domain, sld_target, tld):
    # sld_target = sld_target.lower()

    """
    Deteksi phishing pada SLD (Second Level Domain).
    """
    global PETA_HOMOGRAF
    homograph_map_path = "C:\\Users\\user\\Documents\\thesis\\backend\\tdv_homoglyph_map.txt"
    
    if PETA_HOMOGRAF is None:
        PETA_HOMOGRAF = muat_peta_homograf(homograph_map_path)

    # ==========================================================
    # LOGIKA 1: CEK DOMAIN ALL-ASCII (Typosquatting)
    # ==========================================================
    if all(c.isascii() for c in sld_target):
        # Rekomendasi: Threshold 2 untuk domain > 5 karakter, 
        # jika <= 5 karakter tetap threshold 1 untuk menghindari noise.
        threshold_ascii = 2 if len(sld_target) > 5 else 1
        
        matches = utils.load_whitelist.BK_TREE.find(domain, threshold_ascii)

        if matches:
            # Cek apakah ada exact match (jarak 0) di dalam whitelist
            is_exact_match_in_whitelist = any(dist == 0 and item == domain for dist, item in matches)
            
            if is_exact_match_in_whitelist:
                return "continue", None, None
            else:
                # Ambil yang paling mirip (jarak terkecil)
                domain_mirip = min(matches, key=lambda x: x[0])[1]
                return "stop", domain_mirip, None
        else:
            return "continue", None, None

    # ==========================================================
    # LOGIKA 2: CEK IDN / NON-LATIN (Homograph)
    # ==========================================================
    # Normalisasi homoglyph (Tetap Threshold 1 sesuai permintaan)
    sld_target = sld_target[:30]
    kemungkinan_normalisasi = normalisasi_homograf(sld_target, PETA_HOMOGRAF, max_kandidat=500)
    
    # Debug info (bisa dimatikan saat production)
    # print(f"[DEBUG] Normalisasi: {kemungkinan_normalisasi}")

    for normalisasi_string in kemungkinan_normalisasi:
        full_domain = f"{normalisasi_string}.{tld}"
        
        # Tetap gunakan threshold 1 untuk hasil normalisasi homograf
        matches = utils.load_whitelist.BK_TREE.find(full_domain, 1)
        
        if matches:
            # Jika hasil normalisasi mirip dengan whitelist, tandai sebagai phishing
            domain_mirip = matches[0][1]
            return "stop", domain_mirip, kemungkinan_normalisasi

    return "continue", None, None


def mapper(domain,sld,tld):
    """Fungsi pembungkus"""
    status, mirip_dengan, kemungkinan = cek_domain_phishing(domain,sld,tld)
    return status, mirip_dengan, kemungkinan


if __name__ == "__main__":
    status, mirip, kemungkinan = mapper("ЬоокЬаЬү.com")  # contoh input
    #print(status, mirip, kemungkinan)
