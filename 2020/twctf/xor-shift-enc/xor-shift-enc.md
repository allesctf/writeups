xor_shift_enc
=============

This task provides a custom pseudo-random number generator (PRNG) with a `jump` method that's been deleted from the source.
It also includes a test for the behaviour of `jump`: The test esentially requires that `jump(n)` advances the PRNG by `n` `randgen` calls.

As a cheap shot, we can implement `jump` using `for _ in range(n): randgen()`.
This works (and starts printing the flag), but is exponentially slower for each character of the flag text.
We'll have to implement a faster version of `jump`.

Searching for `PRNG jump` leads to:

- The PCG family of PRNGs which implement this operation (https://www.pcg-random.org/useful-features.html)
- This paper which explains how to do it for xorshift: [Further scramblings of Marsaglia's xorshift generators](https://arxiv.org/abs/1404.0390)

The custom PRNG is a lot like `xorshift`: It's got a lot of shifts and xors, an addition and an array of numbers that represent the PRNG state.
The addition is only used for the output of the `randgen` function, and won't be relevant for `jump` as it's not used when advancing the state.

[Further scramblings of Marsaglia's xorshift generators](https://arxiv.org/abs/1404.0390) explains that PRNGs that only use shift and xor can be represented by a matrix-vector multiplication, which has some nice properties:
If the matrix M represents one operation, `M*M` is a jump of 2. If we manage to find this matrix, we can implement `jump` using standard fast exponentiation and matrix-vector multiplication.


To build this matrix, we unrolled 64 `randgen` calls into one operation, as this updates each state cell once and will resumes at the first cell again. We can now introduce each arithmetic operation into the matrix by multiplying a matrix that represents this operation (shifts are identity matrices with an offset, xors are identity matrices with additional diagonals).


Solve scripts:
- [gen.py](./gen.py) generates matrices for each randgen step (numpy, multiplication was very slow for these huge matrices so we switched to sage from here)
- [mulitply_and_check.sage](./mulitply_and_check.sage) verifies these steps and produces the final randgen matrix
- [solve.sage](./solve.sage) implements `jump` using the generated matrix and prints the flag.