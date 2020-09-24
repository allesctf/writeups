import string
import math
from itertools import chain, combinations

# parameters from publickey.txt
p = 168144747387516592781620466787069575171940752179672411574452734808497653671359884981272746489813635225263167370526619987842319278446075098036112998679570069486935297242638675590736039429506131690941660748942375274820626186241210376537247501823653926524570571499198040207829317830442983944747691656715907048411
h = 98640592922797107093071054876006959817165651265269454302952482363998333376245900760045606011965672215605936345612030149799453733708430421685495677502147392514542499678987737269487279698863617849581626352877756515435930907093553607392143564985566046429416461073375036461770604488387110385404233515192951025299
g = 2

# load ciphertexts
ct = []
with open("ciphertext.txt") as f:
    lines = f.readlines()
    for l in lines:
        c1,c2 = l[1:-2].split(", ")
        ct.append((int(c1), int(c2)))


# all known factors of p-1. Later found: 4588812059915964626441195986601 (but irrelevant, small facs are enough)
p_1_facs = [2,3,5,19,5710354319, 51658928397640816749496741258372813990722627656855754562391398098921970341107502745503897286522726230109424976175433646991098836185027283530688300614255822120936368467861662197207684132094740490803687878442773882280113279254839084462283459148390201062466564601191314219384110976101430980883391327]
assert(math.prod(p_1_facs) == p-1)
p_1_facs_inv = [(p-1) // f for f in p_1_facs]


# Compute some possible generator orders, by taking out individual factors of p-1
tests = []
# we wont find a fac of 5710354319 anyways, so just directly exclude
# powerset hack from SO
for f in chain.from_iterable(combinations(p_1_facs[:-2], r) for r in range(len(p_1_facs[:-2])+1)):
    t = math.prod(f)
    tests.append(t)
possible_generators = sorted([(p-1) // t for t in tests])

# 16 entries, last is p-1, which is guaranteed to be the order, if nothing before was
print(len(possible_generators))

# loop through pairs of ciphertexts, ca and cb. Try out possible plaintext pairs and verify against the ciphertext pairs.
# let ciphertext c = (c1,c2) with
#   c1 = g**r
#   c2 = m * g**(r*x)
# let N be the order of g
# verification is based on the observation that:
# c2**n == m**n * g**(r*x*n) == g**n**(r*x) == m**n, because g**n==1, since n is the order
#
# unfortunately, g has order p-1 (or just too high and we dont know it, since we cannot factor p completely)
# this means that m**n == m**(p-1) == 1 as well, so no use
# BUT: we can 'cheat' and take the order of g**r instead of g.
# This MIGHT be successful for SOME ciphertexts, but not all.
# So we take TWO ciphertexts, and combine them. Let f be a "random" factor
#    c2a*(c2b**f) == ma*mb * g**(x*(ra+f*rb))
# Now define n to be the order of g**(ra+f*rb).
# This n can be experimentally determined, by checking with c1:
#    c1a * c1b**f == g**(ra+f*rb)
# So test possible values for the generator n, until
#    (c1a * c1b**f) ** n == 1
#
# Now, test possible values for pairs of ma,mb so that
#    (ma * mb**f) ** n == (c2a * c2b**f) ** n
#
# Do this "smart", only for possible values of ma, mb.

#known = "TWCTF{8d560108444cc360374ef54433d218e9_for_the_first_time_in_9_years!}"
known = "T"
cand2 = []
for i, (ca, cb) in enumerate(zip(ct[:-1], ct[1:])):

    # STEP 1: 
    # Compute ca*(cb**f), which results in g**(ra+f*rb)
    # find best value for f, so that subgroup is as small as possible -> likely that m is not in it

    #print("Starting", i)
    bestind = len(possible_generators)
    bestn = possible_generators[-1]
    bestmult = 1

    # try 50 multiples of cb
    for mult in range(1000):
        # guess order of the generator with all known possibilities
        for j, n in enumerate(possible_generators[:bestind]):
            candidates = []
            # check order, if 1 its correct
            res = pow(ca[0]*pow(cb[0], mult, p), n, p)
            if res == 1:
                # found order. see if better.
                bestind = j
                bestn = n
                bestmult = mult
                print("Found better index at mult", mult, j, (p-1)//n)
                break

    # STEP 2:
    # use best generator value, and test possible plaintexts

    # limit range of possible chars
    valida = string.printable
    if len(cand2) >= len(known):
        valida = set([x[1] for x in cand2[-1]])
        print("Potentially valid: ", valida)
    else:
        valida = set([known[i]])
        print("We know previous character to be", known[i])

    # loop though plaintext pairs
    candidates = []
    for ma in valida:
        for mb in string.printable:
            # test (ma * mb**f) ** n == (c2a * c2b**f) ** n
            if pow(ord(ma)*(ord(mb)**bestmult), bestn, p) == pow(ca[1]*pow(cb[1], bestmult, p), bestn, p):
                candidates.append((ma, mb))
                #print("Add cand", ma, mb)
    
    print(i, "Valid plaintext pairs", candidates, len(candidates))
    print(i, "--------------- Valid for current are only", set([x[0] for x in candidates]))
    cand2.append(candidates)

print(cand2)


# TWCTF{8d560108444cc360374ef54433d218e9_for_the_first_time_in_9_years!}