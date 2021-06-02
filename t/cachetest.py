import uwsgi

import random
import string

items = {}


def gen_rand_n(max_n):
    return random.randint(8, max_n)


def gen_rand_s(size):
    return ''.join(random.choice(string.letters) for i in range(size))

print('filling cache...')
for i in range(0, 1000):
    kl = gen_rand_n(200)
    key = gen_rand_s(kl)
    vl = gen_rand_n(10000)
    val = gen_rand_s(vl)
    items[key] = val
    uwsgi.cache_set(key, val)

print('checking cache...')
count = 0
for key in items.keys():
    val = uwsgi.cache_get(key)
    count += 1
    if val != items[key]:
        print(len(val), val)
        print(len(items[key]), items[key])
        raise Exception('CACHE TEST FAILED AFTER %d ITERATIONS !!!' % count)

print("TEST PASSED")
