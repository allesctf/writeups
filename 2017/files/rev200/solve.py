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