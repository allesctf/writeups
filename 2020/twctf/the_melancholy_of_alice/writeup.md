# The Melancholy of Alice
Category: Crypto

Solves: 36, Score: 242

> Carol "That's classified information."

Three attached files: [ciphertext.txt](./ciphertext.txt) and [publickey.txt](./publickey.txt) and [encrypt.py](./encrypt.py)


## Solution
Given that we have a ciphertext, a publickey and an encrypt file, it is immediately obvious that we have somehow break an asymmetric cipher. Closer investigation of the encryption funciton reveals, that it uses the El-Gamal cipher. This can easily be recognized because the ciphertext consists of a pair of large numbers.

Verifying the implementation against Wikipedia shows that everything largely checks out. The generation of the secret key between 2 and `q = (p - 1) // 2` is weird, as it will make it one bit shorter than it could be. No attack against this was found though. However, the suggested key-generation method is different. Usually `p` is chosen such that `q = (p - 1) // 2` is prime, which is NOT checked here. `p` is simply a random large prime. This means that the multiplicative group which El-Gamal operates on has multiple largish sub-groups, a weakness we can exploit!

Important for the following attack to work, is the fact that one flag-byte is encrypted at a time.

Factoring `p-1` reveals some small factors: `2,3,5,19,5710354319`.

Now consider some ciphertext `(c1,c2)` with
``` 
  r  = random session key
  x  = secret key
  g  = generator
  m  = message
  c1 = g**r
  c2 = m * g**(r*x)

  let n be the order of g, so that g**n == 1
  observe that
  c1**n == g ** r ** n
        == (g ** n) ** r
        == 1
  c2**n == m**n * g**(r*x*n) 
        == g**n**(r*x) 
        == m**n
```
This allows us to verify a guess of `n` against c1. We know that `n` always is a product of the factors of `p-1`, so there are limited choices. A guess of `m` can then be verified against `c2`. Unfortunately, this yields all `m` which lie in the same subgroup as each other. To make the attack more reliable, pairs of plain- and ciphertexts are considered as follows: 
```
 Input: Two ciphertexts, (c1a, c2a) and (c1b, c2b), which use random-keys of (ra and rb) corrospondingly.

 Let f be a "random" factor. Then
   c2a*(c2b**f) == ma*mb * g**(x*(ra+f*rb))
 Now define n to be the order of g**(ra+f*rb).

This n can again be experimentally determined, by checking with c1:
   c1a * c1b**f == g**(ra+f*rb)
So test possible values for the generator n, until
   (c1a * c1b**f) ** n == 1

By having f as a tunable parameter, an optimal subgroup can be chosen.

Now, test possible values for pairs of ma,mb so that
   (ma * mb**f) ** n == (c2a * c2b**f) ** n
```

Doing this "smart" reveals the only for possible values for `ma` and `mb`. The result is still not unique, but enough to easily guess the remaining chars.


Fully commented solution script is attached: [solve.py](./solve.py)

### Flag
`TWCTF{8d560108444cc360374ef54433d218e9_for_the_first_time_in_9_years!}`

what exactly the "hash" in the first part is, or why 9 years is relevant is unknown.