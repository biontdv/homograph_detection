import tldextract
import re
import idna


def whitelist(tld):

    # Convert TLD to punycode (if needed)
    try:
        tld_ascii = idna.encode(tld).decode('ascii') if tld else ''
    except idna.IDNAError:
        tld_ascii = tld  # fallback, tetap pakai tld original


    # Whitelist regex
    whitelist_regex = re.compile(
    r"^(?:"  # Mulai grup tanpa tangkapan (non-capturing group)
    # 1. TLD ketat yang berdiri sendiri (gov, mil, edu, int)
    r"gov|mil|edu|int|gouv|"
    
    # 2. Struktur TLD negara yang ketat (seperti ac.id, go.uk, sch.au)
    # Ini mencocokkan (ac|go|...) diikuti TITIK dan DUA HURUF kode negara
    r"(?:ac|go|gob|sch|co|or|leg|nic|mod|police|govt|parliament|judiciary|court)\.[a-z]{2}|"
    
    # 3. TLD Punycode spesifik yang Anda targetkan (biasanya untuk pemerintah/resmi)
    r"xn--p1ai|xn--j1amh|xn--90a3ac|xn--qxam|xn--e1a4c|xn--qxa6a|xn--90ais|xn--90ae|"
    r"xn--fiqs8s|xn--fiqz9s|xn--j6w193g|xn--3e0b707e|xn--kprw13d|xn--kpry57d|xn--o3cw4h|"
    r"xn--lgbbat1ad8j|xn--mgberp4a5d4ar|xn--wgbh1c"
    r")$",
    re.IGNORECASE
)

    # Check whitelist
    is_whitelisted_tld = bool(whitelist_regex.match(tld_ascii)) if tld_ascii else False

    if is_whitelisted_tld:
        return "stop"
    else:
        return "continue"



#print(whitelist('aci'))
