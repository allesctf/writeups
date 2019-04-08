---
tags: ["misc"]
author: "CherryWorm"
---
# Challenge
We have managed to intercept communications from Dr. Evil's base but it seems to be encrypted. Can you recover the secret message.

# Solution
After activating TCP checksum validation in wireshark, we noticed that approximately half of all TCP packets have a broken checksum. Coincidentally, every packet with a faulty checksum had the reserved bit set. The reserved bit is sometimes called the "evil" bit, since it there is no reason for it to be set, and some servers straight up drop a connection if it is.

The following script extracts all evil bits from the packets the server sent and concatenates them:

```python
from scapy.all import *
import binascii

pcap = rdpcap('dr-evil.pcap')
res = []

for packet in pcap:
    if IP in packet and packet[IP].src == '52.15.194.28':
        res.append(packet[IP].flags == 'evil')

# print boolean array as ascii (extra 0 because the string did not have even length)
print(binascii.unhexlify('%x0' % int(''.join(map(lambda b: '1' if b else '0', res)), 2)).decode())
```

This prints the string 
```
Ladies and gentlemen, welcome to my underground lair. I have gathered here before me the world's deadliest assassins. And yet, each of you has failed to kill Austin Powers and submit the flag "midnight{1_Milli0n_evil_b1tz!}". That makes me angry. And when Dr. Evil gets angry, Mr. Bigglesworth gets upset. And when Mr. Bigglesworth gets upset, people DIE!!
```
which contains the flag `midnight{1_Milli0n_evil_b1tz!}`.