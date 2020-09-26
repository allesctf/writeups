
try:
  from tqdm import tqdm
except ImportError:
  def tqdm(it, *args, **kwargs):
    return it

NBITS = 64
NSTATE = 64

SZ = NBITS * NSTATE


def dbg(bitvec):
    for i in range(NSTATE):
        vals = bitvec[NBITS * i : NBITS * (i + 1)]
        print("".join([str(x) for x in vals]))


def num_to_bitvec(x, bits=NBITS):
    return [((x >> i) & 1) for i in list(range(bits))[::-1]]


def state_to_bitvec(l):
    res = []
    for el in l:
        res += num_to_bitvec(el, NBITS)
    return res

import json

unrolled = matrix.identity(SZ, GF(2))

for i in tqdm(range(NSTATE)):
    with open("step" + str(i) + ".json") as f:
        data = json.load(f)
        stepmatrix = matrix(GF(2), SZ, data, sparse=False)
        unrolled = stepmatrix * unrolled

print("dumping to json...")
with open("unrolled.json", "w") as f:
    json.dump([list([int(x) for x in x]) for x in list(unrolled)], f)

print("unrolled:")
print(unrolled)
s = []
p = 0


def init():
    global s, p
    s = [i for i in range(0, NSTATE)]
    p = 0
    return


def randgen():
    global s, p
    pn = (p + 1) % NSTATE
    res = (s[p] + s[pn]) & ((1 << NBITS) - 1)
    s1 = s[pn] ^^ ((s[pn] << 3) & ((1 << NBITS) - 1))
    s[pn] = (s1 ^^ s[p] ^^ (s1 >> 13) ^^ (s[p] >> 37)) & ((1 << NBITS) - 1)
    p = pn
    return res


init()
import json

init()
for i in range(100):
    for _ in range(NSTATE):
        randgen()
print(p, s)
sanity_start = state_to_bitvec(s)
for _ in range(NSTATE):
    randgen()
sanity_check = state_to_bitvec(s)
print(s)


sanity_test = unrolled * vector(sanity_start)


print("sanity_start:")
dbg(sanity_start)

print("sanity check:")
dbg(sanity_check)

print("sanity_test:")
dbg(sanity_test)

print("sanity check matches", sanity_check == list(sanity_test))

print("step-by-step check:")

init()
for i in tqdm(range(100)):
    for i in range(NSTATE):
        with open("step" + str(i) + ".json") as f:
            data = json.load(f)
            stepmatrix = matrix(GF(2), SZ, data, sparse=False)
        state = state_to_bitvec(s)
        actual = list(stepmatrix * vector(state))
        randgen()
        expected = state_to_bitvec(s)

        if expected != actual:
            print()
            print("step", i)
            print(stepmatrix)

            print("state")
            dbg(state)

            print("expected")
            dbg(expected)

            print("actual")
            dbg(actual)

            print("matches", expected == actual)
            assert expected == actual