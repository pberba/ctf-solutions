# BSides Dehli CTF 2018: Tile Mate (Crypto 100)

__Tags:__ `crypto`, `rsa`  
__Total Points:__ 100

## Problem Statement

### encrypt.py
The implementation of `encrypt.py` is short enough for us to fully show here.

```python
#!/usr/bin/env python2

from itertools import cycle as scooter
from secret import FLAG, KEY
from hashlib import sha384

assert FLAG.islower()
assert len(KEY) == 10

def drive(Helmet, Petrol):
    return ''.join(chr(ord(David)^ord(Toni)) for David,Toni in zip(Helmet,scooter(Petrol)))

encrypted = drive(map(f,FLAG),KEY.decode('hex')).encode('hex')
open('ci.pher.text','wb').write(encrypted)
```

## Solution

First we analyze the code and figure out that this is just a __substitution encryption__ + __xor encryption__.

### Analyzing the code

We rename the function and variable names for clarity.

```python
...
def xor(msg, key):
	return ''.join(chr(ord(m)^ord(k)) for m, k in zip(msg, cycle(key)))

def encrypt(ch):
	return sha384(ch).digest()[(ord(ch)+7)%48]

def subs_enc(msg):
	return ''.join(map(encrypt, msg))

# note that len(KEY) == 10
encrypted = drive(subs_enc(FLAG),KEY.decode('hex')).encode('hex')
...
```

### Figuring out the key

If we know the part of the plaintext used in the __xor encryption__ we can get information of the key used.

Since the initial length of the key is __10 hexadecimal digits__ then the __the key is only 5 bytes long.__ So known at least 5 characters and position might make it possible for us to recover the key used.

Luckily, we know that the __flag format__ starts with `flag{` which is 5 digits long! With that __we get the xor key from the ciphertext__. Note that the prefix encrypted with substitution cipher is used as the xor encryption's input.

```python
with open('ci.pher.text') as file:
	ct = binascii.unhexlify(file.read().strip())

known = 'flag{'
known_enc = subs_enc(known)
key = xor(known_enc, ct)

ct = xor(ct, key) # known it is only encryption with a subsitution cipher!
```


### Substitution cipher

Now it is pretty straightforeward. Since we have a function from plaintext to ciphertext, __we make a reverse dictionary for decryption.__

```python
decrypt_dict = {encrypt(e): e for e in alphabet}
def decrypt(ch):
 	return decrypt_dict.get(ch, '?')

def subs_dec(msg):
	return map(decrypt, msg)
```

With that we get the flag `flag{cr1b_dr4g_w1th_u1tr4_c00l_sc00ter!}`

## Full implementation

```python
import binascii
from itertools import cycle
from hashlib import sha384

alphabet = 'abcdefghijklmnopqrstuvwxyz1234567890_{}!'

def xor(msg, key):
	return ''.join(chr(ord(m)^ord(k)) for m, k in zip(msg, cycle(key)))

def encrypt(ch):
	return sha384(ch).digest()[(ord(ch)+7)%48]

def subs_enc(msg):
	return ''.join(map(encrypt, msg))

decrypt_dict = {encrypt(e): e for e in alphabet}
def decrypt(ch):
 	return decrypt_dict.get(ch, '?')

def subs_dec(msg):
	return map(decrypt, msg)

with open('ci.pher.text') as file:
	ct = binascii.unhexlify(file.read().strip())

known = 'flag{'
known_enc = subs_enc(known)
key = xor(known_enc, ct)
ct = xor(ct, key)
print(''.join(subs_dec(ct)))

```
