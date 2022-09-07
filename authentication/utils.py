def istopic(string): 
    hashtag_plus = ["#", "+"]
    if string in hashtag_plus:
        return True
    if '/' not in list(string) or '//' in string:
        return False
    if string.replace('/','').isalnum() or (string.replace('/','')[0:-1].isalnum() and string[-1] in hashtag_plus and string[-2] == '/'):
        return True
    return False