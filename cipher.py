import string

def caesar_encipher_letter(letter, shift):
    """Encipher a letter, given a shift amount

    >>> caesar_encipher_letter('a', 1)
    'b'
    >>> caesar_encipher_letter('a', 2)
    'c'
    >>> caesar_encipher_letter('b', 2)
    'd'
    >>> caesar_encipher_letter('x', 2)
    'z'
    >>> caesar_encipher_letter('y', 2)
    'a'
    >>> caesar_encipher_letter('z', 2)
    'b'
    >>> caesar_encipher_letter('z', -1)
    'y'
    >>> caesar_encipher_letter('a', -1)
    'z'
    """
    if letter in string.ascii_letters:
        if letter in string.ascii_uppercase:
            alphabet_start = ord('A')
        else:
            alphabet_start = ord('a')
        return chr(((ord(letter) - alphabet_start + shift) % 26) + 
                   alphabet_start)
    else:
        return letter

def caesar_decipher_letter(letter, shift):
    """Decipher a letter, given a shift amount
    
    >>> caesar_decipher_letter('b', 1)
    'a'
    >>> caesar_decipher_letter('b', 2)
    'z'
    """
    return caesar_encipher_letter(letter, -shift)

def caesar_encipher(message, shift):
    """Encipher a message with the Caesar cipher of given shift
    
    >>> caesar_encipher('abc', 1)
    'bcd'
    >>> caesar_encipher('abc', 2)
    'cde'
    >>> caesar_encipher('abcxyz', 2)
    'cdezab'
    >>> caesar_encipher('ab cx yz', 2)
    'cd ez ab'
    """
    enciphered = [caesar_encipher_letter(l, shift) for l in message]
    return ''.join(enciphered)

def caesar_decipher(message, shift):
    """Decipher a message with the Caesar cipher of given shift
    
    >>> caesar_decipher('bcd', 1)
    'abc'
    >>> caesar_decipher('cde', 2)
    'abc'
    >>> caesar_decipher('cd ez ab', 2)
    'ab cx yz'
    """
    return caesar_encipher(message, -shift)


if __name__ == "__main__":
    import doctest
    doctest.testmod()
