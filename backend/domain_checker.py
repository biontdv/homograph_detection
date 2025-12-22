import utils.load_whitelist
def is_in_whitelisted(domain):
    """
    Memeriksa apakah hostname atau domain induknya ada di daftar top-1m.
    """
    while domain:
        if domain in utils.load_whitelist.DB_DOMAIN:
            return True
        # Pindahkan ke domain induk
        parts = domain.split('.', 1)
        if len(parts) > 1:
            domain = parts[1]
        else:
            break
    return False
