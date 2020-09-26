
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

def bitvec_to_num(bv):
    return int(''.join([str(x) for x in bv]), 2)

def state_to_bitvec(l):
    res = []
    for el in l:
        res += num_to_bitvec(el, NBITS)
    return res

def bitvec_to_state(l):
    res = []
    for i in range(NSTATE):
        res.append(bitvec_to_num(l[i*NBITS:(i+1)*NBITS]))
    return res

import json
with open("unrolled.json") as f:
    data = json.load(f)
    unrolled = matrix(GF(2), SZ, data, sparse=False)

print("got matrix")

s = []
p = 0
ctr = 0


def init():
    global s, p, ctr
    s = [i for i in range(0, NSTATE)]
    p = 0
    ctr = 0
    return


def randgen():
    global s, p, ctr
    pn = (p + 1) % NSTATE
    res = (s[p] + s[pn]) & ((1 << NBITS) - 1)
    s1 = s[pn] ^^ ((s[pn] << 3) & ((1 << NBITS) - 1))
    s[pn] = (s1 ^^ s[p] ^^ (s1 >> 13) ^^ (s[p] >> 37)) & ((1 << NBITS) - 1)
    p = pn
    ctr += 1
    return res

def jump(to):
    global s, ctr
    to += ctr
    init()
    state = state_to_bitvec(s)
    to -= 1
    ops = to // NSTATE
    left = to - ops * NSTATE +1
    # print("jump: ops =", ops, "left =", left)
    res = (unrolled ^ ops) * vector(state)
    s = bitvec_to_state(res)
    for _ in range(left):
        res = randgen()
    ctr = to+1
    return res

def check_jump():
    init()
    jump(10000)
    assert randgen() == 7239098760540678124

    init()
    jump(100000)
    assert randgen() == 17366362210940280642

    init()
    jump(1000000)
    assert randgen() == 13353821705405689004

    init()
    jump(10000000)
    assert randgen() == 1441702120537313559

    init()
    for a in range(31337):randgen()
    for a in range(1234567):randgen()
    buf = randgen()
    for a in range(7890123):randgen()
    buf2 = randgen()
    init()
    jump(31337+1234567)
    print (buf == randgen())  
    jump(7890123)
    print (buf2 == randgen())

check_jump()

init()
for a in range(31337):randgen()


enc = open("enc.dat", "rb").read()

# Expected: b"Oh, you can read me, right? OK. I'll give you the"

flag = b""
for x in range(256):
    buf = randgen()
    sh = x//2
    if sh > 64:
        sh = 64
    mask = (1 << sh) - 1
    print(buf, sh, hex(mask))
    buf &= mask
    print("jump", hex(buf))
    jump(buf)
    c = bytes([(randgen() & 0xff) ^^ enc[x]])
    flag += c
    print(flag)
print(flag)