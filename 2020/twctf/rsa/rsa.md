# Reversing iS Amazing

The challenge is a binary that expects to be called with a single argument, the flag.
If the flag is passed as argument, it'll print `Correct!`, else `Incorrect!`.

Exploring the disassembly of the binary with [`radare2`](https://www.radare.org/r/), we quickly find an interesting function call:

```
│    │││└─> 0x00000f53      488b8d00f5ff.  mov rcx, qword [var_b00h]
│    │││    0x00000f5a      488d95f0f7ff.  lea rdx, [var_810h]
│    │││    0x00000f61      488db5f0fbff.  lea rsi, [s1]
│    │││    0x00000f68      8b85f0f4ffff   mov eax, dword [n]
│    │││    0x00000f6e      41b801000000   mov r8d, 1
│    │││    0x00000f74      89c7           mov edi, eax
│    │││    0x00000f76      e825f9ffff     call sym.imp.RSA_private_encrypt ;
```

Since we can't find any data that looks like ascii in the binary, we can assume that this call will encrypt our input. Later, we find a call to memcmp, which probably compares the decrypted data to an expected value:

```
│      │    0x00000fa8      4889ce         mov rsi, rcx                ; const void *s2
│      │    0x00000fab      4889c7         mov rdi, rax                ; const void *s1
│      │    0x00000fae      e83df9ffff     call sym.imp.memcmp   
```

So let's first save the pointer to the expected data with gdb (gdb disables ASLR, so this will work):

```
$ pwndbg ./rsa
pwndbg> start 
pwndbg> brva 0xfae # call to memcmp 
pwndbg> r fakeinput
 ► 0x555555554fae    call   memcmp@plt <0x5555555548f0>
        s1: 0x7fffffffdae0 ◂— 0xc9c6241e0aefc3a2
        s2: 0x7fffffffd800 ◂— 0x5e8abe2996e4866f
        n: 0x80
pwndbg> r anotherinput # note s1,s2
 ► 0x555555554fae    call   memcmp@plt <0x5555555548f0>
        s1: 0x7fffffffdae0 ◂— 0x354bf07a076ade69
        s2: 0x7fffffffd800 ◂— 0x5e8abe2996e4866f
        n: 0x80
# s1 changed, so s1 is the input. Save s2
pwndbg> set $data=0x7fffffffd800
```

Now, we can call `RSA_public_decrypt` instead of the `RSA_private_encrypt` function to get the flag:

```
pwndbg> brva 0xf76 # call to encrypt func
Breakpoint *0x555555554f76
pwndbg> r whatever
 ► 0x555555554f76    call   RSA_private_encrypt@plt <0x5555555548a0>
        flen: 0x8
        from: 0x7fffffffdee0 ◂— 0x7265766574616877 ('whatever')
        to: 0x7fffffffdae0 ◂— 0x0
        rsa: 0x55555576f7d0 ◂— 0x0
        padding: 0x1
        
# call decrypt
pwndbg> p (int)RSA_public_decrypt(0x80, $data, 0x7fffffffdae0, 0x55555576f7d0, 0x1)
$11 = 28
pwndbg> x/s 0x7fffffffdae0
0x7fffffffdae0:	"TWCTF{Rivest_Shamir_Adleman}"
```
