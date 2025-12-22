import tldextract
import unicodedataplus as ud
import re

#looping setiap char, lalu deteksi setiap char masuk ke font apa

def has_mixed_scripts(sld):
    scripts = set()
    for char in sld:
        if char.isprintable():
            script = ud.script(char)
            if script != 'Common':
                scripts.add(script)        
    return scripts



#kompas

if __name__ == '__main__':
    test=0
    print(has_mixed_scripts('123'))
    #print(has_mixed_scripts('extasyasians'))
    #print(has_mixed_scripts('extasyasians'))
    #print(has_mixed_scripts('g2g'))
    


# # Contoh uji
# listscript=has_mixed_scripts('κιίκβζαa')

# if len(listscript)>1:
#     print("not safe")
# else:
#     print('safe')

