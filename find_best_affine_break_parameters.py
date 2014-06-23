import random
import collections
from cipher import *
from cipherbreak import *
import itertools
import csv

corpus = sanitise(''.join([open('shakespeare.txt', 'r').read(), 
    open('sherlock-holmes.txt', 'r').read(), 
    open('war-and-peace.txt', 'r').read()]))
corpus_length = len(corpus)

euclidean_scaled_english_counts = norms.euclidean_scale(english_counts)

metrics = [{'func': norms.l1, 'invert': True, 'name': 'l1'}, 
    {'func': norms.l2, 'invert': True, 'name': 'l2'},
    {'func': norms.l3, 'invert': True, 'name': 'l3'},
    {'func': norms.cosine_similarity, 'invert': False, 'name': 'cosine_similarity'}]
    # {'func': norms.harmonic_mean, 'invert': True, 'name': 'harmonic_mean'},
    # {'func': norms.geometric_mean, 'invert': True, 'name': 'geometric_mean'}]
scalings = [{'corpus_frequency': normalised_english_counts, 
         'scaling': norms.normalise,
         'name': 'normalised'},
        {'corpus_frequency': euclidean_scaled_english_counts, 
         'scaling': norms.euclidean_scale,
         'name': 'euclidean_scaled'}]
message_lengths = [2000, 1000, 500, 250, 100, 50, 20]

trials = 5000

scores = {}


def make_frequency_compare_function(target_frequency, frequency_scaling, metric, invert):
    def frequency_compare(text):
        counts = frequency_scaling(frequencies(text))
        if invert:
            score = -1 * metric(target_frequency, counts)
        else:
            score = metric(target_frequency, counts)
        return score
    return frequency_compare

def scoring_functions():
    return [{'func': make_frequency_compare_function(s['corpus_frequency'], 
                s['scaling'], m['func'], m['invert']),
            'name': '{} + {}'.format(m['name'], s['name'])}
        for m in metrics
        for s in scalings] + [{'func': Pletters, 'name': 'Pletters'}]

def eval_scores():
    [eval_one_score(f, l) 
        for f in scoring_functions()
        for l in message_lengths]

def eval_one_score(scoring_function, message_length):
    print(scoring_function['name'], message_length, ': ', end='', flush=True)
    if scoring_function['name'] not in scores:
        scores[scoring_function['name']] = collections.defaultdict(int)
    for _ in range(trials):
        sample_start = random.randint(0, corpus_length - message_length)
        sample = corpus[sample_start:(sample_start + message_length)]
        multiplier = random.choice([x for x in range(1, 26, 2) if x != 13])
        adder = random.randint(0, 25)
        one_based = random.choice([True, False])
        key = (multiplier, adder, one_based)
        ciphertext = affine_encipher(sample, multiplier, adder, one_based)
        found_key, _ = affine_break(ciphertext, scoring_function['func'])
        if found_key == key:
            scores[scoring_function['name']][message_length] += 1 
    print(scores[scoring_function['name']][message_length], '/', trials)
    return scores[scoring_function['name']][message_length]

def show_results():
    with open('affine_break_parameter_trials.csv', 'w') as f:
        writer = csv.DictWriter(f, ['name'] + message_lengths, 
            quoting=csv.QUOTE_NONNUMERIC)
        writer.writeheader()
        for scoring in sorted(scores.keys()):
            scores[scoring]['name'] = scoring
            writer.writerow(scores[scoring])

print('Starting...')
eval_scores()
show_results()