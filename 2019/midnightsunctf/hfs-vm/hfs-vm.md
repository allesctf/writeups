---
tags: ["re", "hfs-vm I"]
author: "LinHe"
---
# Challenge
> Write a program in my crappy VM language.  
> Service: nc hfs-vm-01.play.midnightsunctf.se 4096  
> Download: [hfs-vm.tar.gz](https://s3.eu-north-1.amazonaws.com/dl.2019.midnightsunctf.se/529C928A6B855DC07AEEE66037E5452E255684E06230BB7C06690DA3D6279E4C/hfs-vm.tar.gz)

As the description of this challenge already implies, we're required to create some Bytecode for a VM to get the flag. The first thing we did was (obviously) to find out how this Bytecode and the VM works by disassembling the provided binary.

# VM
The VM has 16 registers, with register 14 being the Stack Pointer (SP) and register 15 being the Program Counter (PC).  
Each Register is 16 bit (one word) wide.  
Additionally, there is a Stack which may contain up to 32 words (64 byte).  
The VM consists of two processes:

1. The main process which is used for syscalls (see the Bytecode section below).
2. A secondary process which is executing our bytecode and communicates with the first one. It has seccomp enabled.

# Bytecode
Each instruction in this Bytecode is exactly 32 bit wide.  
Instructions operate on two registers: A source (src) register and a destination (dst) register.  
Some instructions also support immediate (imm) values. In this case, the source register is unused and the immediate value is used instead.  
There are 11 instructions:

0. move: dst = src / dst = imm
1. add: dst = dst + src / dst = dst + imm
2. subtract: dst = dst - src / dst = dst - imm
3. exchange: Exchanges the contents of dst and src
4. xor: dst = dst ^ src / dst = dst ^ imm
5. push: Pushes dst or imm on the stack. src is unused. SP is decremented by one.
6. pop: Pops a value from the stack into dst. src is unused. SP is increased by one.
7. stack set relative: Writes a value on the stack (src or imm) relative to dst. No bounds checking is performed (would have been useful for hfs-vm2).
8. stack get relative: Reads a value from the stack relative to src and stores it in dst. No bounds checking is performed as well.
9. syscall: Performs a syscall. Syscall number must be stored in register 1. See syscalls below.
10. show registers: Prints the contents of all registers and the stack.

# Syscalls
There are 5 syscalls:

0. Run ls.
1. Write the contents of the stack to stdout.
2. Writes the uid or euid to the stack.
3. Writes the flag to the stack(!).
4. Writes data from /dev/urandom to the stack.

# Solution
After looking at the syscalls, the solution was pretty easy:

1. Reserve some space for the flag on the stack.
2. Perform syscall 3 to get the flag.
3. Perform syscall 1 to print the flag.

See exploit.py for the full exploit.
The flag is `midnight{m3_h4bl0_vm}`.
