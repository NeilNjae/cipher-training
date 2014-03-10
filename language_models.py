import unicodedata

def unaccent(text):
    """Remove all accents from letters. 
    It does this by converting the unicode string to decomposed compatability
    form, dropping all the combining accents, then re-encoding the bytes.

    >>> unaccent('hello')
    'hello'
    >>> unaccent('HELLO')
    'HELLO'
    >>> unaccent('héllo')
    'hello'
    >>> unaccent('héllö')
    'hello'
    >>> unaccent('HÉLLÖ')
    'HELLO'
    """
    return unicodedata.normalize('NFKD', text).\
        encode('ascii', 'ignore').\
        decode('utf-8')


if __name__ == "__main__":
    import doctest
    doctest.testmod()
