"""A set of functions to break the ciphers give in ciphers.py.
"""

import string
import collections
import norms
import logging

import matplotlib.pyplot as plt

logger = logging.getLogger(__name__)
logger.addHandler(logging.FileHandler('cipher.log'))
logger.setLevel(logging.WARNING)
#logger.setLevel(logging.INFO)
#logger.setLevel(logging.DEBUG)

from cipher import *
from language_models import *

# To time a run:
#
# import timeit
# c5a = open('2012/5a.ciphertext', 'r').read()
# timeit.timeit('keyword_break(c5a)', setup='gc.enable() ; from __main__ import c5a ; from cipher import keyword_break', number=1)
# timeit.repeat('keyword_break_mp(c5a, chunksize=500)', setup='gc.enable() ; from __main__ import c5a ; from cipher import keyword_break_mp', repeat=5, number=1)


def frequencies(text):
    """Count the number of occurrences of each character in text

    >>> sorted(frequencies('abcdefabc').items())
    [('a', 2), ('b', 2), ('c', 2), ('d', 1), ('e', 1), ('f', 1)]
    >>> sorted(frequencies('the quick brown fox jumped over the lazy ' \
         'dog').items()) # doctest: +NORMALIZE_WHITESPACE
    [(' ', 8), ('a', 1), ('b', 1), ('c', 1), ('d', 2), ('e', 4), ('f', 1),
     ('g', 1), ('h', 2), ('i', 1), ('j', 1), ('k', 1), ('l', 1), ('m', 1),
     ('n', 1), ('o', 4), ('p', 1), ('q', 1), ('r', 2), ('t', 2), ('u', 2),
     ('v', 1), ('w', 1), ('x', 1), ('y', 1), ('z', 1)]
    >>> sorted(frequencies('The Quick BROWN fox jumped! over... the ' \
         '(9lazy) DOG').items()) # doctest: +NORMALIZE_WHITESPACE
    [(' ', 8), ('!', 1), ('(', 1), (')', 1), ('.', 3), ('9', 1), ('B', 1),
     ('D', 1), ('G', 1), ('N', 1), ('O', 2), ('Q', 1), ('R', 1), ('T', 1),
     ('W', 1), ('a', 1), ('c', 1), ('d', 1), ('e', 4), ('f', 1), ('h', 2),
     ('i', 1), ('j', 1), ('k', 1), ('l', 1), ('m', 1), ('o', 2), ('p', 1),
     ('r', 1), ('t', 1), ('u', 2), ('v', 1), ('x', 1), ('y', 1), ('z', 1)]
    >>> sorted(frequencies(sanitise('The Quick BROWN fox jumped! over... '\
         'the (9lazy) DOG')).items()) # doctest: +NORMALIZE_WHITESPACE
    [('a', 1), ('b', 1), ('c', 1), ('d', 2), ('e', 4), ('f', 1), ('g', 1),
     ('h', 2), ('i', 1), ('j', 1), ('k', 1), ('l', 1), ('m', 1), ('n', 1),
     ('o', 4), ('p', 1), ('q', 1), ('r', 2), ('t', 2), ('u', 2), ('v', 1),
     ('w', 1), ('x', 1), ('y', 1), ('z', 1)]
    >>> frequencies('abcdefabcdef')['x']
    0
    """
    return collections.Counter(c for c in text)


def caesar_break(message, fitness=Pletters):
    """Breaks a Caesar cipher using frequency analysis

    >>> caesar_break('ibxcsyorsaqcheyklxivoexlevmrimwxsfiqevvmihrsasrxliwyrh' \
          'ecjsppsamrkwleppfmergefifvmhixscsymjcsyqeoixlm') # doctest: +ELLIPSIS
    (4, -130.849989015...)
    >>> caesar_break('wxwmaxdgheetgwuxztgptedbgznitgwwhpguxyhkxbmhvvtlbhgtee' \
          'raxlmhiixweblmxgxwmhmaxybkbgztgwztsxwbgmxgmert') # doctest: +ELLIPSIS
    (19, -128.82410410...)
    >>> caesar_break('yltbbqnqnzvguvaxurorgenafsbezqvagbnornfgsbevpnaabjurer' \
          'svaquvzyvxrnznazlybequrvfohgriraabjtbaruraprur') # doctest: +ELLIPSIS
    (13, -126.25403935...)
    """
    sanitised_message = sanitise(message)
    best_shift = 0
    best_fit = float('-inf')
    for shift in range(26):
        plaintext = caesar_decipher(sanitised_message, shift)
        fit = fitness(plaintext)
        logger.debug('Caesar break attempt using key {0} gives fit of {1} '
                     'and decrypt starting: {2}'.format(shift, fit,
                                                        plaintext[:50]))
        if fit > best_fit:
            best_fit = fit
            best_shift = shift
    logger.info('Caesar break best fit: key {0} gives fit of {1} and '
                'decrypt starting: {2}'.format(best_shift, best_fit, 
                    caesar_decipher(sanitised_message, best_shift)[:50]))
    return best_shift, best_fit


def plot_frequency_histogram(freqs, sort_key=None):
    x = range(len(freqs.keys()))
    y = [freqs[l] for l in sorted(freqs.keys(), key=sort_key)]
    f = plt.figure()
    ax = f.add_axes([0.1, 0.1, 0.9, 0.9])
    ax.bar(x, y, align='center')
    ax.set_xticks(x)
    ax.set_xticklabels(sorted(freqs.keys(), key=sort_key))
    f.show()


if __name__ == "__main__":
    import doctest
    doctest.testmod()
