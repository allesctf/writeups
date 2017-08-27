# Rev200 

**Description:** You haxor, come on you little sciddie... debug me, eh? You fucking little lamer... You fuckin' come on, come debug me! I'll get your ass, you jerk! Oh, you IDA monkey! Fuck all you and your tools! Come on, you scum haxor, you try to reverse me? Come on, you asshole!!

First of all: The task wasn't even worth 50 points and was solved in 3 min. As a little sciddie i used IDA to decompile the checking algo (algo()):
```
for ( i = 0; i <= 19; ++i )
    v4[i] = *(_BYTE *)(i + a1);
  for ( j = 20; j <= 39; ++j )
    v3[j - 20] = *(_BYTE *)(j + a1);
  for ( k = 0; k <= 19; ++k )
  {
    v4[k] = (((((v4[k] ^ 0xC) + 6) ^ 0xD) + 7) ^ 0xE) + 8;
    v3[k] = (((((v3[k] ^ 0xF) + 9) ^ 0x10) + 10) ^ 0x11) + 11;
  }
  for ( l = 0; l <= 19; ++l )
    v2[l] = v4[l];
  for ( m = 20; m <= 39; ++m )
    v2[m] = v3[m - 20];
  if ( memcmp((__int64)v2, (__int64)&correct, 160) )
    result = Print(L"\nWrong\n");
  else
    result = Print(L"\nCorrect\n");
  return result;
```
Wow, static XOR on a each single byte that is compared to some static memory.

Simple python solution:
```
# Solution for rev200
correct = [104, 60, 121, 113, 99, 124, 129, 146, 146, 101, 101, 147, 146, 73, 121, 146, 56, 108, 60, 111, 123, 135, 88, 85, 137, 90, 89, 126, 126, 107, 135, 108, 87, 108, 107, 88, 89, 90, 90, 111];
correctS = "";

for x in range(20):
	for i in range(256):
		if ((((((i ^ 0xC) + 6) ^ 0xD) + 7) ^ 0xE) + 8) == correct[x]:
			correctS += chr(i)

for x in range(20):
	for i in range(256):
		if (((((i ^ 0xF) + 9) ^ 0x10) + 10) ^ 0x11) + 11 == correct[x+20]:
			correctS += chr(i)
   
print correctS
```

Flag: h4ck1t{ff77af3cf8d4e1e67c4300aeb5ba6344}

  

