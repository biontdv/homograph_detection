import unicodedataplus as ud


tld_allowed_scripts = {
    # TLD generik: boleh pakai script apapun (TETAP 'ANY')
    'com': {'ANY'},
    'net': {'ANY'},
    'org': {'ANY'},
    'info': {'ANY'},
    'biz': {'ANY'},
    'co': {'ANY'},          # Catatan: di referensi ini {'Latin'}, tapi dipertahankan 'ANY'
    'io': {'ANY'},
    'me': {'ANY'},
    'tv': {'ANY'},
    'xyz': {'ANY'},
    'online': {'ANY'},
    'site': {'ANY'},
    'shop': {'ANY'},
    'top': {'ANY'},
    'club': {'ANY'},
    'store': {'ANY'},
    'app': {'ANY'},
    'pro': {'ANY'},
    'name': {'ANY'},
    'tech': {'ANY'},
    'blog': {'ANY'},
    'website': {'ANY'},
    'my': {'ANY'},

    # TLD reserved: tetap Latin
    'gov': {'Latin','Common'},
    'edu': {'Latin','Common'},
    'mil': {'Latin','Common'},
    'int': {'Latin','Common'},

    # ccTLD Latin
    'id': {'Latin','Common'},
    'au': {'Latin','Common'},
    'uk': {'Latin','Common'},
    'us': {'Latin','Common'},
    'ca': {'Latin','Common'},
    'de': {'Latin','Common'},
    'fr': {'Latin','Common'},
    'it': {'Latin','Common'},
    'es': {'Latin','Common'},
    'nl': {'Latin','Common'},
    'se': {'Latin','Common'},
    'no': {'Latin','Common'},
    'dk': {'Latin','Common'},
    'fi': {'Latin','Common'},
    'be': {'Latin','Common'},
    'ch': {'Latin','Common'},
    'nz': {'Latin','Common'},
    'ie': {'Latin','Common'},
    'pt': {'Latin','Common'},
    'pl': {'Latin','Common'},
    'cz': {'Latin','Common'},
    'ro': {'Latin','Common'},
    'hu': {'Latin','Common'},
    'sk': {'Latin','Common'},
    'si': {'Latin','Common'},
    'hr': {'Latin','Common'},
    'lt': {'Latin','Common'},
    'lv': {'Latin','Common'},
    'ee': {'Latin','Common'},
    'mx': {'Latin','Common'},
    'ar': {'Latin','Common'},
    'br': {'Latin','Common'},
    'cl': {'Latin','Common'},
    'pe': {'Latin','Common'},
    'vn': {'Latin','Common'},
    'sg': {'Latin','Common'},        # Ditambahkan dari referensi
    'ph': {'Latin','Common'},        # Ditambahkan dari referensi
    'is': {'Latin','Common'},

    # ccTLD Cyrillic
    'ru': {'Cyrillic', 'Latin','Common'},
    'рф': {'Cyrillic', 'Latin','Common'},
    'ua': {'Cyrillic', 'Latin','Common'},
    'mn': {'Cyrillic', 'Mongolian', 'Latin','Common'},

    # ccTLD Greek
    'gr': {'Greek', 'Latin','Common'},
    'ελ': {'Greek', 'Latin','Common'},

    # ccTLD Arabic
    'sa': {'Arabic', 'Latin','Common'},
    'ae': {'Arabic', 'Latin','Common'},
    'eg': {'Arabic', 'Latin','Common'},
    'iq': {'Arabic', 'Latin','Common'},
    'jo': {'Arabic', 'Latin','Common'},
    'ye': {'Arabic', 'Latin','Common'},
    'sd': {'Arabic', 'Latin','Common'},
    'ly': {'Arabic', 'Latin','Common'},
    'dz': {'Arabic', 'Latin','Common'},
    'bh': {'Arabic', 'Latin','Common'},
    'om': {'Arabic', 'Latin','Common'},
    'qa': {'Arabic', 'Latin','Common'},
    'sy': {'Arabic', 'Latin','Common'},
    'tn': {'Arabic', 'Latin','Common'},
    'ma': {'Arabic', 'Latin','Common'},
    'ps': {'Arabic', 'Latin','Common'},
    'ir': {'Arabic', 'Latin','Common'},
    'pk': {'Arabic', 'Latin','Common'},       # Ditambahkan dari referensi

    # ccTLD Asia Timur
    'cn': {'Han', 'Latin','Common'},
    'tw': {'Han', 'Latin','Common'},
    'hk': {'Han', 'Latin','Common'},
    'mo': {'Han', 'Latin','Common'},
    'jp': {'Hiragana', 'Katakana', 'Han', 'Latin','Common'},
    'kr': {'Hangul', 'Latin','Common'},

    # Asia Selatan / Tenggara
    'in': {'Devanagari', 'Latin','Common'},
    'bd': {'Bengali', 'Latin','Common'},
    'lk': {'Sinhala', 'Latin','Common'},
    'np': {'Devanagari', 'Latin','Common'},
    'mm': {'Myanmar', 'Latin','Common'},
    'th': {'Thai', 'Latin','Common'},
    'kh': {'Khmer', 'Latin','Common'},
    'la': {'Lao', 'Latin','Common'},
    'idn': {'Latin','Common', 'Latin','Common'},       # Ditambahkan dari referensi

    # Lain-lain
    'il': {'Hebrew', 'Latin','Common'},
    'et': {'Ethiopic', 'Latin','Common'},
    'am': {'Armenian', 'Latin','Common'},
    'ge': {'Georgian', 'Latin','Common'}
}

def compare_tld(sld,tld):
    scriptName = ud.script(sld[0])

    allowed = tld_allowed_scripts.get(tld.split('.')[-1],{'ANY'})
    #print(f'second-level domain:  {sld}')
    #print(f'top-level domain:  {tld}')
    #print(scriptName)
    #print(allowed)

    if 'ANY' in allowed:
        return "continue"
    elif scriptName not in allowed:
        return "stop",tld,scriptName
    else:
        return "continue"

    

#compare_tld('ζcnn','my.cn')


    