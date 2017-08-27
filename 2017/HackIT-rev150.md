# Rev150 - Broken Packer

**Description:** Looks like this packer can not unpack what has been packed :( There are 2 mistakes in unpacking procedure. It leads to the error. Try to fix unpacker and figure out what is inside.

We had two ELF binaries, a packer and a packed file.
```
user@ubuntu:~/Schreibtisch/ITCTF$ file packer
packer: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, BuildID[sha1]=83a5497803c94765ad5b256de346473b64f36459, not stripped

user@ubuntu:~/Schreibtisch/ITCTF$ file packed
packed: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=cdc378f63011a71a8d0f096c6435765db04cbc0c, not stripped
```
Lets take a look at the packer routines first and fire up IDA. I'm not that used to the ELF headers, so I might miss some parts here... The packer basically preforms this actions:
 * Create a random key
 * XOR all the executable code with the key
 * Add a section with asm to decrypt the encrypted code
 * Store the start of the executable code, end of the executable code and the XOR key in the file
 * Change the EntryPoint to the new EP in the generated section 

In *disguise_text()* we find:
```
    key = get_random_key();
    for ( i = 0LL; i < v5; ++i )
    {
      *(_BYTE *)(startOfCode + i) ^= key;
      v3 = rotate_right(v3); // = __ROR8__(v7, 8);
    }
```
The code injected in *create_section()* though looks like this (entry_loader):
```
v4 = info_addr;
v5 = info_start;
do
  {
  *(_BYTE *)v5 ^= v5;
  v5 = __ROR8__(v5, 8);
  v4 += 2LL;
}
while ( v4 != info_addr + info_size );
```
Acctually two things fail here:
 * The loader adds +=2 to the offset index, not 1 as intented
 * The pointer to the encrypted segment is wrong (turns out to be wrong register)

If you look at in the actual packed file we notice the 3 stored values first:
```
seg023:00000000006B54A4 qword_6B54A4    dq 49A4E28A75143878h    => XOR KEY
seg023:00000000006B54AC off_6B54AC      dq offset sub_4003B0    => Start of executable code
seg023:00000000006B54B4 qword_6B54B4    dq 88C17h               => Length of executable code
```
So lets fix the assembly code in the packed file:
```
mov     rax, cs:off_6B54AC => start of code
[...]
xor     [rdx], dl => Change to [rax],dl
ror     rdx, 8
add     rax, 2 => Change to 1
cmp     rax, rcx
jnz     short loc_6B5489
[...]
jmp     near ptr qword_400990 => JMP OEP
```
Patch the file and let the encryption run, dump the process and/or apply the encryption by hand. No matter what you get the decrypted code stored in the packed assembly. Save the file and apply a simple JMP OEP at the start.

When starting the patched, unpacked binary we get a nice text:
```The hardest part is overcome.```
But still the programm crashes immediatly with an invalid write operation from 0x00 memory right after this output. Wierd, it took me a while to figure out whats going on. Take a look at the callstack and see what function called the crashing function:
```
gdb-peda$ bt
#0  0x000000000042194a in ?? ()
#1  0x0000000000400bde in ?? ()
```
```
.text:0000000000400BB8                 lea     rdi, aTheHardestPart ; "The hardest part is overcome."
.text:0000000000400BBF                 call    sub_407FC0 => print string
.text:0000000000400BC4                 mov     rax, [rbp+var_10]
.text:0000000000400BC8                 add     rax, 8
.text:0000000000400BCC                 mov     rax, [rax]
.text:0000000000400BCF                 lea     rsi, aCryp      ; "cryp"
.text:0000000000400BD6                 mov     rdi, rax
.text:0000000000400BD9                 call    sub_400370 => encryption function ??
.text:0000000000400BDE                 test    eax, eax
.text:0000000000400BE0                 jnz     short loc_400BF5
.text:0000000000400BE2                 mov     rax, [rbp+var_10]
.text:0000000000400BE6                 add     rax, 10h
.text:0000000000400BEA                 mov     rax, [rax]
.text:0000000000400BED                 mov     rdi, rax
.text:0000000000400BF0                 call    sub_400AAE
.text:0000000000400BF5
.text:0000000000400BF5 loc_400BF5:                             ; CODE XREF: sub_400BA9+37j
.text:0000000000400BF5                 mov     rax, [rbp+var_10]
.text:0000000000400BF9                 add     rax, 8
.text:0000000000400BFD                 mov     rax, [rax]
.text:0000000000400C00                 lea     rsi, aDecr      ; "decr"
.text:0000000000400C07                 mov     rdi, rax 
.text:0000000000400C0A                 call    sub_400370 => decryption function ??
.text:0000000000400C11                 jnz     short loc_400C18
.text:0000000000400C13                 call    sub_400B39 => XOR Function
```
Looks like some crypting and decrypting is going on. Lets call the program with arguments "cryp" or "decr". With "decr" as argument the program exits normally, so lets break after the "decrypt" function. It turns out that its not interesting, the next function is tough! It performs some XOR on a string:
```
 for ( i = (signed int)result; i >= 0; --i )
  {
    result = aXEIBNuuDcMP_no;
    aXEIBNuuDcMP_no[i] ^= aXEIBNuuDcMP_no[v1 - 1 - i] ^ 0x80;
  }
  ```
  

