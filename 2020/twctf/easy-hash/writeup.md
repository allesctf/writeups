# easy-hash

The authors delivered source-code of a hashing function. The following constraints needed to be fulfilled in order to pass the first checks:

- Text begins with 'twctf: '
- Text ends with '2020'
- Text must be different to original MSG = 'twctf: please give me the flag of 2020'

In order to get the flag, the hash of the passed message needs to match the hash of the previous mentioned MSG.

The used hash function was:

```python
[...]
def easy_hash(x):
    m = 0
    for i in range(len(x) - 3):
        m += struct.unpack('<I', x[i:i + 4])[0]
        m = m & 0xffffffff
    return m
[...]
```

## Solution
After locally fiddling around with the function in python, it looked like pretty linear hashing. Thus by decreasing one char (p->o) and increasing another one (l->m) of the word "please" I was able to get the same hash. 

```python
MSG = b'twctf: please give me the flag of 2020'
MSG1 = b'twctf: omease give me the flag of 2020'
easy_hash(MSG) # =1788732187
easy_hash(MSG1) # =1788732187
```

The final curl to the remote server looked like this:

```bash=
curl https://crypto01.chal.ctf.westerns.tokyo -d 'twctf: omease give me the flag of 2020'
```

## Flag
TWCTF{colorfully_decorated_dream}