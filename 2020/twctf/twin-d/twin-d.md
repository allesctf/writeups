# Twin-D

In this challenge, we got an RSA-encrypted message (with 2048 bit modulus) plus two public exponents that were generated from correlated private exponents. The first private exponent is a random 1024 bit number `d` but the second one is `d + 2`.

There are two issues here:

- we get two public exponents generated from a single random private exponent
- the private exponent is not very large compared to the modulus (only half the bits)

We spent quite some time trying to find a way to exploit the small private exponent.
But most attacks require an even smaller private exponent (about 1/4 the size of the modulus).
It turns out that the solution is much simpler than that.

We know that these equations hold, because that's how public/private exponents are related in RSA:

```
phi = (p-1) * (q-1)  # euler phi function
d       * e1    === 1 (mod phi)

(d + 2) * e2    === 1 (mod phi)
d * e2 + 2 * e2 === 1 (mod phi)
```

Multiplying the first equation by `e2` and the second by `e1` and then subtracting the first from the second leads to:

```
2 * e1 * e2           === e1 - e2 (mod phi)
2 * e1 * e2 + e2 - e1 === 0       (mod phi)
```

So we know that `kphi = 2 * e1 * e2 + e2 - e1` is a multiple of `phi`.
That means that we can simply invert `e1` modulo `kphi` (this works because `e1` happens to be coprime to `kphi`) to recover a private exponent `d`.
We can then decrypt the flag with that `d`. In python:

```python
from json import load
params = load(open("output"))
n, e1, e2, enc = [int(params[k]) for k in ("n", "e1", "e2", "enc")]
kphi = 2 * e1 * e2 + e2 - e1
dec = pow(enc, pow(e1, -1, kphi), n)
bytes.fromhex(format(dec, 'x'))

# b'TWCTF{even_if_it_is_f4+e}\n'
```
