import re
import unicodedataplus as ud
def check_standart_latin(sld):
    status='continue'
    pattern = r'^[a-zA-Z0-9-]+$'
    if ud.script(sld[0])=='Latin' or ud.script(sld[0])=='Common' :
        if re.fullmatch(pattern, sld):
            return status
        else:
            status='stop'
            return status
    else:
        return status
    
