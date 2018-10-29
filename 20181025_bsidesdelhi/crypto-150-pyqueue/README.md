# BSides Dehli CTF 2018: pyQueue (Crypto 150)

__Tags:__ `crypto`, `aes`, `brute-force`  
__Total Points:__ 150

## Problem Statement

### encrypt.py
The implementation of `encrypt.py` is short enough for us to fully show here.

```python
#!/usr/bin/env python2
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from secret import FLAG


class AES_Key:
    def __init__(self):
        self.key=list(os.urandom(16))

    def enqueue(self):
        self.key+=get_random_bytes(1)

    def dequeue(self):
        self.key=self.key[1:]

    def size(self):
        return len(self.key)

    def shuffle(self):
        self.dequeue()
        self.enqueue()
        assert self.size()==AES.block_size
        return "".join(self.key)

def pad(msg):
    pad_byte = 16 - len(msg) % 16
    return msg + chr(pad_byte) * pad_byte

def slice(msg,step = AES.block_size):
    yield [pad(msg)[i:i+step] for i in range(0,len(msg),step)]


key = AES_Key()
ct=""
MAC = 0
for List in slice(FLAG):
    for block in List:
        cipher = AES.new(key.shuffle(), AES.MODE_ECB)
        ct+= cipher.encrypt(block)
        MAC ^= int(ct[-16:].encode('hex'),16)

MAC ^= int(key.shuffle().encode('hex'),16)

open("ci.pher.text",'wb').write(str(MAC) +":"+ ct.encode('hex'))
```

## Solution

We analyze the code to realize that __a partial key is given in the ciphertext__ which allows us to use brute force to get the plaintext.

### Analyzing the code

We simplify the code.

```python
...
class AES_Key:
    def __init__(self):
        self.key=list(os.urandom(16))

    def next_key(self):
        self.key = self.key[1:] + get_random_bytes(1)
        return "".join(self.key)

key = AES_Key()
ct=""
MAC = 0
for block in slice(FLAG):
    cipher = AES.new(key.next_key(), AES.MODE_ECB)
    ct += cipher.encrypt(block)
    MAC ^= int(ct[-16:].encode('hex'),16)
MAC ^= int(key.next_key().encode('hex'),16)
```

We make the following observations:

1. We use __AES ECB__ mode which means that rounds can be computed independently.
1. Each round uses the previous rounds key, with practically __one byte difference__.
2. The MAC is made up of __xor of all blocks of ciphertext__ xor with __the key__

### Recovering the key

To recover the key, we simply get __xor all the available blocks of ciphertext with the MAC__. What will be left is the key.

```python
with open('ci.pher.text', 'r') as f:
    mac, ct = f.read().strip().split(':')

mac = int(mac)
ct = [int(ct[i:i+2*AES.block_size], 16) for i in range(0, len(ct), 2*AES.block_size)]
ct_mac = reduce(lambda x, y: x^y, ct)
key = long_to_bytes(mac ^ ct_mac)
```

### Brute force

__From the key of the last round, we can derive almost all bytes of the key of the penultimate round.__ There are only 256 possible values of the key, so we try them all and only get the key that an output that makes sens.

```python
def brute_force(key, ct):
    for i in range(256):
        temp_key = chr(i) + key[:-1] # Guess the first byte of the key
        cipher = AES.new(temp_key, AES.MODE_ECB)
        plain = unpad(cipher.decrypt(long_to_bytes(ct)))
        if is_printable(plain) and plain:
            return temp_key, plain
    return key, None

flag = ''
for e in reversed(ct):
    key, pt = brute_force(key, e)
    flag = pt + flag
```

And we get the flag `flag{H4il_bUggi3s!_qu3u3_k3y_2_h0t_4_w4rmUp}`

## Full implementation

```python
from Crypto.Cipher import AES
from Crypto.Util.number import *
from crypto_commons.generic import is_printable


def unpad(msg):
    padding = ord(msg[-1])
    if padding > 16:
        return msg
    return msg[:-padding]

def brute_force(key, ct):
    for i in range(256):
        temp_key = chr(i) + key[:-1] # Guess the first byte of the key
        cipher = AES.new(temp_key, AES.MODE_ECB)
        plain = unpad(cipher.decrypt(long_to_bytes(ct)))
        if is_printable(plain) and plain:
            return temp_key, plain
    return key, None


with open('ci.pher.text', 'r') as f:
    mac, ct = f.read().strip().split(':')

mac = int(mac)
ct = [int(ct[i:i+2*AES.block_size], 16) for i in range(0, len(ct), 2*AES.block_size)]
ct_mac = reduce(lambda x, y: x^y, ct)
key = long_to_bytes(mac ^ ct_mac)

flag = ''
for e in reversed(ct):
    key, pt = brute_force(key, e)
    flag = pt + flag

print flag

```
