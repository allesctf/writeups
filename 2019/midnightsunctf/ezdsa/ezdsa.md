# EZDSA
- Tags: crypto
- Points: 223
- Solves: 57

## Challenge
>Someone told me not to use DSA, so I came up with this. 

We get a server IP and part of the python code which runs on it.

Connecting to the server we see:
```
Welcome to Spooners' EZDSA
Options:
1. Sign protocol
2. Quit
1
Enter data:
asdf
(566787836513318161631424115768553230152020123938L, 150528027594773609234378622493646221096430839490L)
Options:
1. Sign protocol
2. Quit
2
KBye.
Quitting...
```
Code:
```python
from hashlib import sha1
from Crypto import Random
from flag import FLAG


class PrivateSigningKey:

    def __init__(self):
        self.gen = 0x44120dc98545c6d3d81bfc7898983e7b7f6ac8e08d3943af0be7f5d52264abb3775a905e003151ed0631376165b65c8ef72d0b6880da7e4b5e7b833377bb50fde65846426a5bfdc182673b6b2504ebfe0d6bca36338b3a3be334689c1afb17869baeb2b0380351b61555df31f0cda3445bba4023be72a494588d640a9da7bd16L
        self.q = 0x926c99d24bd4d5b47adb75bd9933de8be5932f4bL
        self.p = 0x80000000000001cda6f403d8a752a4e7976173ebfcd2acf69a29f4bada1ca3178b56131c2c1f00cf7875a2e7c497b10fea66b26436e40b7b73952081319e26603810a558f871d6d256fddbec5933b77fa7d1d0d75267dcae1f24ea7cc57b3a30f8ea09310772440f016c13e08b56b1196a687d6a5e5de864068f3fd936a361c5L
        self.key = int(FLAG.encode("hex"), 16)

    def sign(self, m):

        def bytes_to_long(b):
            return long(b.encode("hex"), 16)

        h = bytes_to_long(sha1(m).digest())
        u = bytes_to_long(Random.new().read(20))
        assert(bytes_to_long(m) % (self.q - 1) != 0)

        k = pow(self.gen, u * bytes_to_long(m), self.q)
        r = pow(self.gen, k, self.p) % self.q
        s = pow(k, self.q - 2, self.q) * (h + self.key * r) % self.q
        assert(s != 0)

        return r, s
```

## Solution

Already hinted at by the challenge name, the used algorithm is very similar to [DSA](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm). The only 'difference' is the generation of the supposedly random number `k`. The calculation of `s` is a tiny bit obfuscated, but using fermats little theorem we can see that it is the normal DSA calculation:
```
pow(k, self.q - 2, self.q) == k ^ -1 mod q
```


The secret-key is the wanted flag. 

DSA is only secure if k is actually random. If we know what it is, we can compute the key given just a signature and plaintext/hash. Now what do we know about `k`? It gets 'seeded' by 20 random bytes `u`. But on these bytes, a computation is made:
```
k = pow(self.gen, u * bytes_to_long(m), self.q)
which is essentially
k = gen^(u*m) mod q, where gen is a generator of the mod-q field and u the 20 random bytes
```
Using fermats little theorem again, we know that
```
gen^(p-1) mod p === 1
and thus also
gen^(u*(p-1)) mod p === 1
```
If we could force `m` to be a multiple of `q-1`, which is trivial since we control the input, k is known to be 1!

Unfortunately, the challenge tries to blocks us by checking this explicitly:
```
assert(bytes_to_long(m) % (self.q - 1) != 0)
```
But this is entirely unsuccessful, since we can just pick `m=(p-1)/2`. Assuming `u` is even, which is often the case, we again have a multiple of `p-1` in the exponent, and thus `k=1`. Now we only need to break DSA with known k.

A bit of algebra on the DSA computations assuming k=1 gives us
```
k = 1
r = g^k mod q = g mod q
s = k^-1 * (h+r*key) mod q
s = 1    * (h+g*key) mod q
key = (s-h) * gen^-1 mod q
```

When trying to send the message to the server, we noticed that the server decodes the input as base64, which makes the attack easier since we don't have to worry about null bytes or newlines in the message.

Exploit Script:
```python
from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse
from hashlib import sha1

gen = 0x44120dc98545c6d3d81bfc7898983e7b7f6ac8e08d3943af0be7f5d52264abb3775a905e003151ed0631376165b65c8ef72d0b6880da7e4b5e7b833377bb50fde65846426a5bfdc182673b6b2504ebfe0d6bca36338b3a3be334689c1afb17869baeb2b0380351b61555df31f0cda3445bba4023be72a494588d640a9da7bd16L
q = 0x926c99d24bd4d5b47adb75bd9933de8be5932f4bL
p = 0x80000000000001cda6f403d8a752a4e7976173ebfcd2acf69a29f4bada1ca3178b56131c2c1f00cf7875a2e7c497b10fea66b26436e40b7b73952081319e26603810a558f871d6d256fddbec5933b77fa7d1d0d75267dcae1f24ea7cc57b3a30f8ea09310772440f016c13e08b56b1196a687d6a5e5de864068f3fd936a361c5L

m_int = (q-1)/2
m = long_to_bytes(m_int)
h = bytes_to_long(sha1(m).digest())

# let the server sign our crafted message
with remote('ezdsa-01.play.midnightsunctf.se', 31337) as r:
    r.sendafter("Options:", "1\n")
    r.sendafter("data:", m.encode('base64')+"\n")
    data = r.recvline_contains(("("))

r,s = [int(x[:-1]) for x in data.strip()[1:-1].split(",")]
key = (s-h) * inverse(gen, q) % q

print long_to_bytes(key)
```
Which gives us the flag as 
```
th4t_w4s_e4sy_eh?
```