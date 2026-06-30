import ahocorasick


tags = {
            "N1": '\x10', 
            "N2": '\x11', 
            "N3": '\x12', 
            "N4": '\x13', 
            "N5": '\x14', 
            "N6": '\x15', 
            "N7": '\x16',
            "B1": '\x00', 
            "B2": '\x01', 
            "B3": '\x02', 
            "B4": '\x03', 
            "B5": '\x04', 
            "B6": '\x05', 
            "B7": '\x06', 
            "B8": '\x07', 
            "B9": '\x08', 
            "B10": '\x0b',
            "U1": '\x0c', 
            "U2": '\x0e', 
            "U3": '\x0f', 
            "E1": '\x17', 
            "E2": '\x18', 
            "E3": '\x19'
        }

class UserData():
    
    def __init__(self, password: str, email=None, username=None, first_name=None, last_name=None, birthday=None):
        self.data = None
        
        self.password = password
        self.email = email
        self.username = username
        self.first_name = first_name
        self.last_name = last_name
        self.birthday = birthday

def tokenize_password(password, tags):
    
    auto = ahocorasick.Automaton()
    for key, value in tags.items():
        if value and len(value) >= 2:
            auto.add_word(value, (key, value))
    auto.make_automaton()
    
    matches = []
    for end_idx, (key, value) in auto.iter(password):
        start_idx = end_idx - len(value) + 1
        matches.append((start_idx, end_idx, key, value))
    
    if not matches:
        return password
    
    res_parts = []
    matches.sort(key=lambda x: (x[0], -len(x[3])))
    last_start = -1
    for start, end, key, value in matches:
        if start > last_start:
            if start != last_start + 1:
                res_parts.append(password[last_start + 1:start])
            res_parts.append(key)
            last_start = end
    res_parts.append(password[last_start + 1:len(password)])
    
    return "".join(res_parts)

def special_char_converter(password_segmented: list[str]):
    
    res = []
    for seg in password_segmented:
        res.append(tags.get(seg, seg))
        
    return res