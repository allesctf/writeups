import json
import numpy as np
import scipy as sp
import scipy.linalg
import sys

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(it, *args, **kwargs):
        return it


NBITS = 64
NSTATE = 64


def zero():
    return np.zeros((NBITS, NBITS), dtype="int8")


def identity():
    return np.eye(NBITS, dtype="int8")


def shift_left_matrix(by):
    return np.eye(NBITS, k=by, dtype="int8")


def step_matrix():
    a = 3
    b = 13
    c = 37
    s0 = identity()
    s1 = identity()
    s1 = s1 + s1 @ shift_left_matrix(a)
    res_s0 = s0 + s0 @ shift_left_matrix(-c)
    res_s1 = s1 + shift_left_matrix(-b) @ s1
    return np.hstack([res_s0, res_s1]) & 1


def step_matrix_all_0():
    sm = np.vstack(
        [
            np.hstack([identity(), zero()]),
            step_matrix(),
        ]
    )

    complete_diag = [sm] + [identity()] * (NSTATE - 2)
    return sp.linalg.block_diag(*complete_diag)


def step_matrix_all_mod(mod):
    if mod % NSTATE != mod:
        raise ValueError("mod must be between 0 and 63 (incl.)")

    return np.roll(step_matrix_all_0(), mod * NBITS, axis=(0, 1))


with np.printoptions(threshold=np.inf):
    for i in tqdm(range(NSTATE)):
        with open("step{}.json".format(i), "w") as f:
            json.dump(step_matrix_all_mod(i).tolist(), f)
