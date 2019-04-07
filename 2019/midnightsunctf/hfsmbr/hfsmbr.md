---
tags: ["re", "16bit"]
author: "bennofs"
---
# Challenge
> We made a military-grade secure OS for HFS members. Feel free to beta test it for us! 

The challenge is a qemu image, which displays after startup:

```
.

[HFS SECURE BOOT] Loading  ...
.-. .-.----.----.   .-.   .-.----..----.  
| {_} | {_{ {__     |  `.'  | {}  | {}  } 
| { } | | .-._} }   | |\ /| | {}  | .-. \ 
`-' `-`-' `----'    `-' ` `-`----'`-' `-' 
Enter the correct password to unlock the Operating System
[HFS_MBR]> 
```

# Solution
The image starts with a boot loader that loads sectors 4 and 5 to address 0x7e00 and then jumps there. Let's extract those using dd:

```
$  dd if=dos.img of=stage2.bin skip=3 count=2
```

The code to check password is at address `0x7e37`. Here's an annotated version:

```
0000:7e37                 b701  mov bh, 1 
0000:7e39                 b400  mov ah, 0
0000:7e3b                 cd16  int 0x16         ; read character into al
0000:7e3d                 3c61  cmp al, 0x61   
0000:7e3f             0f8cc101  jl 0x8004        ; if character is < 0x61 ('a'), halt
0000:7e43                 3c7a  cmp al, 0x7a
0000:7e45             0f8fbb01  jg 0x8004        ; if character is > 0x7a ('z'), halt
0000:7e49                 b40e  mov ah, 0xe
0000:7e4b                 cd10  int 0x10         ; print the entered character
0000:7e4d                 30e4  xor ah, ah
0000:7e4f                 88c2  mov dl, al
0000:7e51                 2c61  sub al, 0x61
0000:7e53                 d0e0  shl al, 1
0000:7e55                 31db  xor bx, bx
0000:7e57                 88c3  mov bl, al
0000:7e59               b82680  mov ax, 0x8026
0000:7e5c                 01c3  add bx, ax
0000:7e5e                 8b07  mov ax, word [bx] ; load from 0x8026 + 2*(char - 0x61)
0000:7e60                 ffe0  jmp ax            ; jump to that address
```

Analysis of the 24 different handlers referenced at 0x8026 reveals that the correct password is `sojupwner`.
