from language_models import sanitise
import collections

corpora = ['shakespeare.txt', 'sherlock-holmes.txt', 'war-and-peace.txt']
counts = collections.Counter()

for corpus in corpora:
    text = sanitise(open(corpus).read())
    counts.update(text)

with open('count_1l.txt', 'w') as f:
    for l, c in counts.most_common():
        f.write("{}\t{}\n".format(l, c))
