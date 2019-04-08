---
tags: ["crypto", "probability"]
author: "black-simon"
---
# Challenge
> We made a ZK protocol with a bit of HFS-flair to it!

We were given the following source code:

```flag = "XXXXXXXXXXXXXXXXXXXXXXXXX"
p = 257
k = len(flag) + 1

def prover(secret, beta=107, alpha=42):
    F = GF(p)
    FF.<x> = GF(p)[]
    r = FF.random_element(k - 1)
    masked = (r * secret).mod(x^k + 1)
    y = [
        masked(i) if randint(0, beta) >= alpha else
        masked(i) + F.random_element()
        for i in range(0, beta)
    ]
    return r.coeffs(), y

sage: prover(flag)
[141, 56, 14, 221, 102, 34, 216, 33, 204, 223, 194, 174, 179, 67, 226, 101, 79, 236, 214, 198, 129, 11, 52, 148, 180, 49] [138, 229, 245, 162, 184, 116, 195, 143, 68, 1, 94, 35, 73, 202, 113, 235, 46, 97, 100, 148, 191, 102, 60, 118, 230, 256, 9, 175, 203, 136, 232, 82, 242, 236, 37, 201, 37, 116, 149, 90, 240, 200, 100, 179, 154, 69, 243, 43, 186, 167, 94, 99, 158, 149, 218, 137, 87, 178, 187, 195, 59, 191, 194, 198, 247, 230, 110, 222, 117, 164, 218, 228, 242, 182, 165, 174, 149, 150, 120, 202, 94, 148, 206, 69, 12, 178, 239, 160, 7, 235, 153, 187, 251, 83, 213, 179, 242, 215, 83, 88, 1, 108, 32, 138, 180, 102, 34]
```

# Solve

If we know `masked`, we can simply compute the flag by multiplying with the inverse of r (mod x^k + 1), and then looking at the coefficients.

But how do we get the value of `masked`?

We can interpolate polynomials of degree 25 (it holds that `k=26`, therefore every polynomial mod `x^k + 1` has a degree of at most 25) with 26 sampled points from the polynomial.

Since some of the points are polluted, we can only use a subset of them to interpolate the polynomial. We expect about 65 values to be correct and the rest to be incorrect. If we choose 26 values at random, the probability that they all are correct is
``` (65 nCr 26) / (107 nCr 26)``` which turns out to be about `1.91e-7`

Therefore we expect to need about `5.23e6` trials to find the correct polynomial, and we can just brute-force that many attempts.

# Implementation
The following script yields the flag:
```
flag = "XXXXXXXXXXXXXXXXXXXXXXXXX"
p = 257
k = len(flag) + 1

F = GF(p)
FF.<x> = GF(p)[]

def prover(secret, beta=107, alpha=42):
    F = GF(p)
    FF.<x> = GF(p)[]
    r = FF.random_element(k - 1)
    masked = (r * secret).mod(x^k + 1)
    y = [
        masked(i) if randint(0, beta) >= alpha else
        masked(i) + F.random_element()
        for i in range(0, beta)
    ]
    return r.coefficients(), y

coeffs = [141, 56, 14, 221, 102, 34, 216, 33, 204, 223, 194, 174, 179, 67, 226, 101, 79, 236, 214, 198, 129, 11, 52, 148, 180, 49]

values = [138, 229, 245, 162, 184, 116, 195, 143, 68, 1, 94, 35, 73, 202, 113, 235, 46, 97, 100, 148, 191, 102, 60, 118, 230, 256, 9, 175, 203, 136, 232, 82, 242, 236, 37, 201, 37, 116, 149, 90, 240, 200, 100, 179, 154, 69, 243, 43, 186, 167, 94, 99, 158, 149, 218, 137, 87, 178, 187, 195, 59, 191, 194, 198, 247, 230, 110, 222, 117, 164, 218, 228, 242, 182, 165, 174, 149, 150, 120, 202, 94, 148, 206, 69, 12, 178, 239, 160, 7, 235, 153, 187, 251, 83, 213, 179, 242, 215, 83, 88, 1, 108, 32, 138, 180, 102, 34]

r = FF(coeffs)

rinv  = r.inverse_mod(x^k+1)
import random
import string
for iii in range(1234567):
	if iii % 1000 == 0:
		print(iii)
	memes = random.sample(list(enumerate(values)), k)
	masked = FF.lagrange_polynomial(memes)

	flag = (rinv * masked).mod(x^k+1)
	res = flag.coefficients()
	if all([cc <= 0xff and chr(cc) in string.printable for cc in res]):
		break
print(res)
print(''.join(map(chr, res)))
```

After about 3 million attempts, we get the flag
> N0p3_th1s_15_n0T_R1ng_LpN

(FYI: there were 66 correct values provided)

# Alternative solution
Have a look at Reed-Solomon codes: [Wikipedia](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction)