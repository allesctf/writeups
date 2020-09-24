# Apple
Category: Reverse

Solves: 1, Score: 500

> Clarification and hint:
> There's no problem found in the binary. I've confirmed it accepts the correct flag. Try out a special case.

Attached: [apple.tar.gz](https://github.com/6f70/twctf2020-apple/blob/public/apple.tar.gz)


## Solution
This was a really nice hardware reversing challenge, based on the ESP32. We were given a 4MB flash image of an ESP32, and a custom version of QEMU capable of running the image. It is a basic crack-me, you input a flag and it tells you if it is correct or wrong via some internal algorithm. The goal is to reverse this algorithm.


Luckily my team-member 0x4d5a recently created his own [challenge](https://github.com/allesctf/2020/tree/master/challenges/especially-a-lot-of-fun/public) based on this board, which I test-solved, so I already had all necessary tools ready.

These are mainly ghidra extensions provided by @ebiroll, which allow loading, disassembling and even decompiling of xtensa binaries in ghirda: https://github.com/Ebiroll/ghidra-xtensa and https://github.com/Ebiroll/esp32_flash_loader

In addition, I already had a Function-ID database which was able to tag some functions in the binary, and a custom script which greedily marked all `entry` instructions as function entries. Without this, ghidra struggled to create appropriate function definitions. This is problematic, since x-refs did not work correctly.

The procedure of creating a good ghidra database is:
1. use the @ebiroll's loader to load the binary at the correct offset
2. DO NOT use autoanalysis yet
3. run the custom function tagger
4. run auto-analysis
5. go to strings, search for "Wrong.", the output seen when entering a wrong flag, and look at xrefs.
6. this directly lists the function where the checksum is calculated and compared. The decompiler works somewhat, but does not recognize some loops.
7. reimplement checksum in python

### Checksum
The checksum is based on a 16 byte state, consisting of 4x4byte integers. These are initially seeded with the input, mangled a lot, and finally compared to a hardcoded value.
It consists of 5 rounds, each run 4 times in a row. The round-functions are contained in a function-lookup table.

In the decompiler we see:
```
## checksum 1
  local_30 = (param_1[1] + 1) * *param_1;
  iStack44 = (param_1[2] + 1) * param_1[1];
  iStack40 = (param_1[3] + 1) * param_1[2];
  iStack36 = (*param_1 + 1) * param_1[3];
 
## checksum 2
  *param_1 = *param_1 +     0xEEEC09DC;
  param_1[1] = param_1[1] + 0x03774ED1;
  param_1[2] = param_1[2] + 0x0C443FFF;
  param_1[3] = param_1[3] + 0x9FA8FC57;

## checksum 3
  uVar1 = *param_1;
  uVar2 = param_1[1];
  local_30 = uVar1 + uVar1 % uVar2;
  uVar3 = param_1[2];
  iStack44 = uVar2 + uVar2 % uVar3;
  uVar2 = param_1[3];
  iStack40 = uVar3 + uVar3 % uVar2;
  iStack36 = uVar2 + uVar2 % uVar1;
  
## checksum 4
  *param_1 = *param_1 +     0x0426C4E9;
  param_1[1] = param_1[1] + 0x58918FCD;
  param_1[2] = param_1[2] + 0xFA86D177;
  param_1[3] = param_1[3] + 0x6D320FED;

## checksum 5
*param_1 = *param_1 ^       0x44D3E8D9;
  param_1[1] = param_1[1] ^ 0x47592C79;
  param_1[2] = param_1[2] ^ 0xEEBCD1C8;
  param_1[3] = param_1[3] ^ 0xF4C4E2F8;

## final comparison against
    0x5935F1DE
    0xB63725E7
    0xDFA10069
    0x4E556F64
```

Further, we can also see that the input is restricted to exactly 16 characters, and only chars 0x20 to 0x7e.

I implemented each checksum stage individually, checking with QEMU against the real solution for validity. After some tweaking I had the exact same output on all inputs I tried. Using Boolector, the checksum was trivial to reverse, though not always uniqely. Only one input refused to be reversed: The actual flag. This confused me for a while, and I ran a script in the background trying out random inputs. Around ten thousand tries later, still everything matched, and I worked on another challenge a bit.

Later the autor confirmed that the challenge is working as intended, and a special case should be considered. I opened the xtensa-processor manual and looked at the documentation for each opcode used in the checksum. By doing this I quickly found the issue: The modulo operation. This is done internally with an division, so it can create a Integer Divide By Zero exception. This case is so rare, it should basically never happen, but the constants used in the challenge were chosen specifically so that it occurs. Normally, such an error will crash the program. But the challenge author hooked this exception, and continued execution normally.

This hypothesis was tested with QEMU. The mod register was set to zero, and various values for the operand tried out. This quickly revealed, that it was being squared:
```
0 % 0 == 0
1 % 0 == 1
2 % 0 == 4
3 % 0 == 9
100 % 0 == 10000
0x1000000 % 0 == 0
```

Using this slight modification, my reversing script also worked for the flag. It is attached in [solve.py](./solve.py).

I really liked that a qemu version was provided prebuild, so there was no advantage for people with access to real hardware! All in all, great challenge :)


### Flag
`TWCTF{Rin9oWoT@berun9o}`