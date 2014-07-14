"""Language-specific functions, including models of languages based on data of
its use.
"""

import string
import unicodedata

def letters(text):
    """Remove all non-alphabetic characters from a text
    >>> letters('The Quick')
    'TheQuick'
    >>> letters('The Quick BROWN fox jumped! over... the (9lazy) DOG')
    'TheQuickBROWNfoxjumpedoverthelazyDOG'
    """
    return ''.join([c for c in text if c in string.ascii_letters])

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

def sanitise(text):
    """Remove all non-alphabetic characters and convert the text to lowercase

    >>> sanitise('The Quick')
    'thequick'
    >>> sanitise('The Quick BROWN fox jumped! over... the (9lazy) DOG')
    'thequickbrownfoxjumpedoverthelazydog'
    >>> sanitise('HÉLLÖ')
    'hello'
    """
    # sanitised = [c.lower() for c in text if c in string.ascii_letters]
    # return ''.join(sanitised)
    return letters(unaccent(text)).lower()



if __name__ == "__main__":
    import doctest
    doctest.testmod()
