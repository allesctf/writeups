# sqrt
Category: Crypto

Solves: 45, Score: 216

No Description, two attached files: [chall.py](./chall.py) and [output.txt](./output.txt)


## Solution
Investigating `chall.py` quickly reveals that the flag is 42 characters long. It is converted to an integer `f`, then squared 64 times modulo a known prime `p`.

```
ct = f ** (2 ** 64) mod p
```

The challenge is conceptually really simple. Just take 64 square roots of `ct` to find `f` again. The problem is that each of these roots has two solutions. We do not know which one is the correct one, until we reach the final iteration and can check the flag format. This means a simple search would need `2**64` decisions, which is unfeasable.

This can be improved upon a lot by considering the order of the multiplicative group of `f` in `mod p`. It is always `p-1`, which can be factored into `2**30 * q`, with `q` another large prime. Now consider:

```
p  = (2 ** 30) * q
ct = f ** (2 ** 64) mod p
ct = f ** (2 ** 64 + k*(p-1)) mod p
ct = f ** (2 ** 64 + k*(2 ** 30 * q)) mod p
ct = f ** (2 ** 30) ** (2 ** 34 + k*q) mod p
ct = f ** (2 ** 30) ** (d) mod p
```

Since `d` and `p-1` are coprime, we can invert it, and are left with only the 30th square of `f`, which is feasable to bruteforce:

```
di = d ** (-1) mod (p-1)
f ** (2 ** 30) = ct ** di mod p
```

Using an unoptimized, but multi-threaded bruteforce took around 10 minutes on 48 hyperthreads. A single-threaded solution is attached in [solve.sage](./solve.sage)

### Flag
`TWCTF{17s_v3ry_34sy_70_f1nd_th3_n_7h_r007}`