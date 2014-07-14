"""A set of ciphers with implementations for both enciphering and deciphering
them. See cipherbreak for automatic breaking of these ciphers
"""

import string
import collections
from enum import Enum
from itertools import zip_longest, cycle, chain
from language_models import unaccent, sanitise


modular_division_table = [[0]*26 for _ in range(26)]
for a in range(26):
    for b in range(26):
        c = (a * b) % 26
        modular_division_table[b][c] = a


def every_nth(text, n, fillvalue=''):
    """Returns n strings, each of which consists of every nth character,
    starting with the 0th, 1st, 2nd, ... (n-1)th character

    >>> every_nth(string.ascii_lowercase, 5)
    ['afkpuz', 'bglqv', 'chmrw', 'dinsx', 'ejoty']
    >>> every_nth(string.ascii_lowercase, 1)
    ['abcdefghijklmnopqrstuvwxyz']
    >>> every_nth(string.ascii_lowercase, 26) # doctest: +NORMALIZE_WHITESPACE
    ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
     'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
    >>> every_nth(string.ascii_lowercase, 5, fillvalue='!')
    ['afkpuz', 'bglqv!', 'chmrw!', 'dinsx!', 'ejoty!']
    """
    split_text = chunks(text, n, fillvalue)
    return [''.join(l) for l in zip_longest(*split_text, fillvalue=fillvalue)]

def combine_every_nth(split_text):
    """Reforms a text split into every_nth strings

    >>> combine_every_nth(every_nth(string.ascii_lowercase, 5))
    'abcdefghijklmnopqrstuvwxyz'
    >>> combine_every_nth(every_nth(string.ascii_lowercase, 1))
    'abcdefghijklmnopqrstuvwxyz'
    >>> combine_every_nth(every_nth(string.ascii_lowercase, 26))
    'abcdefghijklmnopqrstuvwxyz'
    """
    return ''.join([''.join(l)
                    for l in zip_longest(*split_text, fillvalue='')])

def chunks(text, n, fillvalue=None):
    """Split a text into chunks of n characters

    >>> chunks('abcdefghi', 3)
    ['abc', 'def', 'ghi']
    >>> chunks('abcdefghi', 4)
    ['abcd', 'efgh', 'i']
    >>> chunks('abcdefghi', 4, fillvalue='!')
    ['abcd', 'efgh', 'i!!!']
    """
    if fillvalue:
        padding = fillvalue[0] * (n - len(text) % n)
    else:
        padding = ''
    return [(text+padding)[i:i+n] for i in range(0, len(text), n)]

def deduplicate(text):
    """If a string contains duplicate letters, remove all but the first. Retain
    the order of the letters.

    >>> deduplicate('cat')
    ['c', 'a', 't']
    >>> deduplicate('happy')
    ['h', 'a', 'p', 'y']
    >>> deduplicate('cattca')
    ['c', 'a', 't']
    """
    return list(collections.OrderedDict.fromkeys(text))


def caesar_encipher_letter(accented_letter, shift):
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
    >>> caesar_encipher_letter('A', 1)
    'B'
    >>> caesar_encipher_letter('é', 1)
    'f'
    """
    letter = unaccent(accented_letter)
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
    >>> caesar_encipher('Héllo World!', 2)
    'Jgnnq Yqtnf!'
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
    >>> caesar_decipher('Jgnnq Yqtnf!', 2)
    'Hello World!'
    """
    return caesar_encipher(message, -shift)

def affine_encipher_letter(accented_letter, multiplier=1, adder=0,
                           one_based=True):
    """Encipher a letter, given a multiplier and adder
    >>> ''.join([affine_encipher_letter(l, 3, 5, True) \
            for l in string.ascii_uppercase])
    'HKNQTWZCFILORUXADGJMPSVYBE'
    >>> ''.join([affine_encipher_letter(l, 3, 5, False) \
            for l in string.ascii_uppercase])
    'FILORUXADGJMPSVYBEHKNQTWZC'
    """
    letter = unaccent(accented_letter)
    if letter in string.ascii_letters:
        if letter in string.ascii_uppercase:
            alphabet_start = ord('A')
        else:
            alphabet_start = ord('a')
        letter_number = ord(letter) - alphabet_start
        if one_based: letter_number += 1
        cipher_number = (letter_number * multiplier + adder) % 26
        if one_based: cipher_number -= 1
        return chr(cipher_number % 26 + alphabet_start)
    else:
        return letter

def affine_decipher_letter(letter, multiplier=1, adder=0, one_based=True):
    """Encipher a letter, given a multiplier and adder

    >>> ''.join([affine_decipher_letter(l, 3, 5, True) \
            for l in 'HKNQTWZCFILORUXADGJMPSVYBE'])
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    >>> ''.join([affine_decipher_letter(l, 3, 5, False) \
            for l in 'FILORUXADGJMPSVYBEHKNQTWZC'])
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    """
    if letter in string.ascii_letters:
        if letter in string.ascii_uppercase:
            alphabet_start = ord('A')
        else:
            alphabet_start = ord('a')
        cipher_number = ord(letter) - alphabet_start
        if one_based: cipher_number += 1
        plaintext_number = (
            modular_division_table[multiplier]
                                  [(cipher_number - adder) % 26]
                            )
        if one_based: plaintext_number -= 1
        return chr(plaintext_number % 26 + alphabet_start)
    else:
        return letter

def affine_encipher(message, multiplier=1, adder=0, one_based=True):
    """Encipher a message

    >>> affine_encipher('hours passed during which jerico tried every ' \
           'trick he could think of', 15, 22, True)
    'lmyfu bkuusd dyfaxw claol psfaom jfasd snsfg jfaoe ls omytd jlaxe mh'
    """
    enciphered = [affine_encipher_letter(l, multiplier, adder, one_based)
                  for l in message]
    return ''.join(enciphered)

def affine_decipher(message, multiplier=1, adder=0, one_based=True):
    """Decipher a message

    >>> affine_decipher('lmyfu bkuusd dyfaxw claol psfaom jfasd snsfg ' \
           'jfaoe ls omytd jlaxe mh', 15, 22, True)
    'hours passed during which jerico tried every trick he could think of'
    """
    enciphered = [affine_decipher_letter(l, multiplier, adder, one_based)
                  for l in message]
    return ''.join(enciphered)


if __name__ == "__main__":
    import doctest
    doctest.testmod()
