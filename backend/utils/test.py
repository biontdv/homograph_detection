url = "http://xn--80ad9b.com"
#url= 'http://bca.com/'
from urllib.parse import urlparse



host = urlparse(url).hostname
unicode_host = host.encode("ascii").decode("idna")
print("kipak")
print(unicode_host)  

print(urlparse(url).scheme)