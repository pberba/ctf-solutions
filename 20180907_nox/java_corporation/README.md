# noxCTF 2018: Java Corporation

__Tags:__ `crypto`, `crypto-aes`  
__Total Solvers:__ 33  
__Total Points:__ 701

## Problem Statement

Description: How much damage could a single character cause?

`nc chal.noxale.com 3141`

We are given the __encrypted flag__ and the implementation of the server.

## Solution

### Quick Explanation

This is a [__Padding Oracle Attack__](https://en.wikipedia.org/wiki/Padding_oracle_attack) and we use mwielgoszewski's [paddingoracle.py](https://github.com/mwielgoszewski/python-paddingoracle) to get the key.

### Full Solution

I have omitted the parts of `server.py` that are not really necessary.

```python
...

class ThreadedServer(object):
    def listenToClient(self, client, address):
        ciphertext = client.recv(length)
        plaintext = self.decrypt(ciphertext)
        if self.check_pad(plaintext):
            client.send('1')
        else:
            client.send('0')
```

This is pretty easy to figure out since the only information we get is whether or not `check_pad` of the __plaintext__ returns `true` or `false`.

If you are not familiar then a search of `aes padding attack` will eventually lead you to __padding oracle attack__.

Fortunately, as mentioned above, we found existing python code to help us as well as a [writeup](https://eugenekolo.com/blog/csaw-qual-ctf-2016/) from a previous CTF on this attack that confirms 

`noxCTF{0n3_p4d_2_f4r}`

## Implementation

```python
from paddingoracle import BadPaddingException, PaddingOracle  
from pwn import *

r = remote('chal.noxale.com', 3141)

with open('Encrypted.txt', 'rb') as f:
    data = f.read()

iv = data[:16]
cipher = data[16:]

class PadBuster(PaddingOracle):  
    def __init__(self, **kwargs):
        super(PadBuster, self).__init__(**kwargs)

    def oracle(self, data, **kwargs):
        r.send(bytes(48))
        r.send(iv+data)
        if r.recv(1) == '0':
            raise BadPaddingException

padbuster = PadBuster()
value = padbuster.decrypt(cipher, block_size=16, iv=iv)
print('Decrypted: %r' % (value))       

# noxCTF{0n3_p4d_2_f4r}
```
