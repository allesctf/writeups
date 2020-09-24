mask = 0xFFFFFFFF

def check1(inp):
    return [
        ((inp[1]+1) * inp[0]) & mask,
        ((inp[2]+1) * inp[1]) & mask,
        ((inp[3]+1) * inp[2]) & mask,
        ((inp[0]+1) * inp[3]) & mask,
    ]

def check2(inp):
    return [
        (inp[0] + 0xEEEC09DC) & mask,
        (inp[1] + 0x03774ED1) & mask,
        (inp[2] + 0x0C443FFF) & mask,
        (inp[3] + 0x9FA8FC57) & mask,
    ]


def magicmod(a, b):
    return btor.Cond(b == 0, a*a, a % b)

def check3(inp):
    return [
        (inp[0] + magicmod(inp[0] , inp[1])) & mask,
        (inp[1] + magicmod(inp[1] , inp[2])) & mask,
        (inp[2] + magicmod(inp[2] , inp[3])) & mask,
        (inp[3] + magicmod(inp[3] , inp[0])) & mask,
    ]

def check4(inp):
    return [
        (inp[0] + 0x0426C4E9) & mask,
        (inp[1] + 0x58918FCD) & mask,
        (inp[2] + 0xFA86D177) & mask,
        (inp[3] + 0x6D320FED) & mask,
    ]

def check5(inp):
    return [
        (inp[0] ^ 0x44D3E8D9) & mask,
        (inp[1] ^ 0x47592C79) & mask,
        (inp[2] ^ 0xEEBCD1C8) & mask,
        (inp[3] ^ 0xF4C4E2F8) & mask,
    ]

def printh(pref, inp):
    print(pref+": "+" ".join(hex(x) for x in inp))

def doHash(inp):
    for i in range(4):
        inp = check1(inp)
        inp = check2(inp)
        inp = check3(inp)
        inp = check4(inp)
        inp = check5(inp)
    return inp

from pyboolector import *
import struct

# initialize boolector, and enable model generation, which is needed to print results when SAT
btor = Boolector()
btor.Set_opt(BTOR_OPT_MODEL_GEN, 1)

inp = [btor.Var(btor.BitVecSort(32)) for _ in range(4)]
final = doHash(inp)

target = [
    0x5935f1de,
    0xb63725e7,
    0xdfa10069,
    0x4e556f64,
]

for j, i in enumerate(inp):
    for x in range(0,32,8):
        char = btor.Slice(i, x+7, x)
        btor.Assert(0x20 <= char)
        btor.Assert(char <= 0x7e)

for i, t in zip(final, target):
    btor.Assert(i == t)

print("Solving...")
result = btor.Sat()

if result == btor.SAT:
  flag = b""
  print("SAT")
  print(",".join([hex(int(x.assignment,2)) for x in inp]))
  for x in inp:
      flag += struct.pack("<I", (int(x.assignment, 2)))
  print("Flag: ", flag)
else:
  print("UNSAT", result)

