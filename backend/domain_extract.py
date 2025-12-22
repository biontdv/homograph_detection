import publicsuffix2
from urllib.parse import urlparse

def extract(url):
    """
    Ekstrak domain, SLD, dan TLD dari URL secara akurat.
    """
    parsed = urlparse(url)
    netloc = parsed.netloc.lower()  # Normalisasi ke huruf kecil

    # Gunakan publicsuffix2 untuk mendapatkan domain yang dapat didaftar
    # Ini akan mengembalikan 'google.com' dari 'www.google.com'
    registrable_domain = publicsuffix2.get_sld(netloc)
    
    # Pisahkan SLD dan TLD dari registrable_domain
    domain_parts = registrable_domain.split('.')
    
    # TLD adalah bagian terakhir dari registrable domain
    tld = '.'.join(domain_parts[1:])
    # SLD adalah bagian pertama
    sld = domain_parts[0]

    return netloc, sld, tld

if __name__ == '__main__':
    # Contoh 1: Dengan subdomain
    url1 = 'https://sub.sub.ctr.co.ru'
    full1, sld1, tld1 = extract(url1)
    
