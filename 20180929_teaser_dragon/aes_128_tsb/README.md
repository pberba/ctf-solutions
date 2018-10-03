# Teaser Dragon CTF 2018: AES-128-TSB

__Tags:__ `crypto`, `aes`  
__Total Solvers:__ 48  
__Total Points:__ 219

## Problem Statement

Haven't you ever thought that GCM mode is overcomplicated and there must be a simpler way to achieve Authenticated Encryption? Here it is!

Server: `aes-128-tsb.hackable.software 1337`

### server.py
See `server.py` for complete details.

```python
...
def main(s):
    aes = AES.new(AES_KEY, AES.MODE_ECB)
    try:
        while True:
            a = recv_binary(s)
            b = recv_enc(s, aes)
            if a == b:
                if a == 'gimme_flag':
                    send_enc(s, aes, FLAG)
                else:
                    # Invalid request, send some random garbage instead of the
                    # flag :)
                    send_enc(s, aes, get_random_bytes(len(FLAG)))
            else:
                send_binary(s, 'Looks like you don\'t know the secret key? Too bad.')
    except (CryptoError, EOFError):
        pass
```

## Solution Overview

Reading the code, it is easy to see that getting the flag requires us to do two things:  
1. Send an ciphertext that decrypts to `gimme_flag` to get the encrypted flag
2. Decrypt the flag

Although _AES_ is set to _ECB_, a custom encryption mode is used, with padding. There is also a __decryption oracle__, since we can validate if  `decrypt(cipher)==plaintext`. These will be used to find craft the desired ciphertext and decrypt the flag.

By constructing the ciphertext in the form `(IV, C^IV, IV)`, __the plaintext will always be `plaintext=IV^decrypt(C)` with a proper MAC__.

We modify the IV to manipulate the padding and this allows us to brute force the byte by byte. We craft a message with plaintext `gimme_flag` and decrypt the flag.

## Full Solution

### Analyzing Encryption Mode

Here is the code for decryption:

```python
def unpad(msg):
    if not msg:
        return ''
    return msg[:-ord(msg[-1])]
...
def tsb_decrypt(aes, msg):
    iv, msg = msg[:16], msg[16:]
    prev_pt = iv
    prev_ct = iv
    pt = ''
    for block in split_by(msg, 16):
        pt_block = xor(block, prev_ct)
        pt_block = aes.decrypt(pt_block)
        pt_block = xor(pt_block, prev_pt)
        pt += pt_block
        prev_pt = pt_block
        prev_ct = block
    pt, mac = pt[:-16], pt[-16:]
    if mac != iv:
        raise CryptoError()
    return unpad(pt)
```

We analyze this in its simplest form where we have 3 block of message. The message would be 48 bytes long: 3 blocks for `IV`, `block`, and `mac`.


![TSB Decryption](https://raw.githubusercontent.com/pberba/ctf-solutions/master/20180929_teaser_dragon/aes_128_tsb/TSB%20Decryption.png)

And from this we simply compute the plaintext and mac blocks based from Block A and B.

![TSB Notes](https://raw.githubusercontent.com/pberba/ctf-solutions/master/20180929_teaser_dragon/aes_128_tsb/TSB%20Decryption%20Notes.png)

Since we want `IV = mac` then `IV = B`

```python
IV = mac
IV = IV^decrypt(IV^A)^decrypt(A^B)
0 = decrypt(IV^A)^decrypt(A^B)
decrypt(IV^A) = decrypt(A^B)
IV^A = A^B #since AES-ECB
IV = B
```
That means a ciphertext in the form of `(IV, A, IV)` __will always decrypt with a proper MAC__.

However manipulating the IV will make result of `decrypt(IV^A)` unpredictable. If we want the result to be constant, `decrypt(IV^A)=decrypt(C)` then we `A=IV^C`

```python
decrypt(IV^A)=decrypt(C)
IV^A=C
A=IV^C
```
If we construct the ciphertext in the form `(IV, C^IV, IV)` then __the plaintext will always be `plaintext=IV^decrypt(C)`__

#### Decrypting C

First assume we have a function `decryption_oracle(p, c)` which would eventually be replaced with messages to and from the server.

```python
def decryption_oracle(p, c):
    return p == tsb_decrypt(c)
```

To be able to craft any message, we have to be able figure out `decrypt(C)` first. One key insight is: __if we know the value of the last byte of decrypt(C), we can predictably manipulate the last byte of the resulting plaintext using the IV. With that, we can use brute force the value of decrypt(C)__

Recall `unpad(msg)`
```python
def unpad(msg):
    if not msg:
        return ''
    return msg[:-ord(msg[-1])]
```

If we can set the last byte to `15` then the the result of `unpad(plaintext)` will be just 1 character. This will only take at most 256 attempts to decrypt. If we know the first character, we can set the last byte to `14` and this will result with 2 characters. It will only take 256 attempts and so on.

#### Getting the last byte of C

If `msg` is exactly 16 bytes long, then `unpad(msg)` will only return a non-empty string if the value of the last byte is between `1` to `15`. So `decryption_oracle('', payload)` will only return false if the last byte is between 1 to 15.

So if we set the last byte of the IV to `iv_byte` and `decryption_oracle('', payload)` is false then we know that `iv_byte=last_byte^e` where e is in [1 to 15]. If we get the xor of all values of iv_byte that results to the decryption oracle returning false, we get the last_byte

```
iv_byte_1^iv_byte_2^...^iv_byte_15
(last_byte^1) ^ (last_byte^2) ^ ... ^ (last_byte^15)
last_byte ^ (1^2^3^...^15)
last_byte
```

So now we know how to get the last byte.
```python
def get_payload(iv_byte, block):
    iv = pack('<I', iv_byte)[0].rjust(16, '\x00')
    return (iv + xor(block, iv) + iv)

def decrypt(block):
    last_byte = 0
    for i in range(256):
        if not decryption_oracle('', get_payload(i, block)):
            last_byte ^= i

    ...
```

#### Brute Force for the value of decrypt(C)

If we know the value of the last byte of decrypt(C), we predictably set the last byte of the plaintext by setting `iv_byte=last_byte^desired_size` and we use the decryption oracle to brute force the value of the first N bytes of decrypt(C)

```python
def decrypt(block):
    ...
    curr = ''
    for i in range(15, 0, -1):
        for c in range(256):
            if decryption_oracle(curr + chr(c), get_payload(last_byte^i, block)):
                curr += chr(c)
                break
    return curr + chr(last_byte)
```

#### Crafting gimme_flag

If we know the value of `decrypt(C)` for any value of `C`, then we can craft a ciphertext for any desired plaintext, by setting `IV=decrypt(C)^desired_plaintext`

```python
desired_plaintext = plaintext
# Recall plaintext = IV^decrypt(C)
desired_plaintext = IV^decrypt(C)
IV = decrypt(C)^desired_plaintext
```

This results to the following code:
```python
block = b'\x00'*(16)
curr = decrypt(block)
desired = 'gimme_flag'.ljust(15, ' ') + chr(6)
iv = xor(curr, desired)
payload = (iv + xor(iv, block) + iv)
flag = get_flag('gimme_flag', payload)
```

This will give us the encrypted flag.


#### Decrypting the flag

Our `decrypt(block)` function is essentially the `aes.decrypt()` of the server. We can use the code `tsb_descrypt(flag)`, replacing it with our own decrypt function.

```python
def __decrypt(msg):
    iv, msg = msg[:16], msg[16:]
    prev_pt = iv
    prev_ct = iv
    pt = ''
    for block in split_by(msg, 16):
        pt_block = xor(block, prev_ct)
        pt_block = decrypt(pt_block) # <--- Internal decrypt(msg) function
        pt_block = xor(pt_block, prev_pt)
        pt += pt_block
        prev_pt = pt_block
        prev_ct = block
    pt, mac = pt[:-16], pt[-16:]
    if mac != iv:
        raise CryptoError()
    return unpad(pt)

print(__decrypt(flag))
```

And we get `DrgnS{Thank_god_no_one_deployed_this_on_production}`


### Implementation

This is the implementation of the POC,

```python
from pwn import *
from struct import unpack, pack
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from server import *

aes = AES.new(get_random_bytes(16), AES.MODE_ECB)
flag = 'flag_is{this_is_the_flag}'

def decryption_oracle(p, c):
	return p == tsb_decrypt(aes, c)

def get_flag(p, c):
	if p != tsb_decrypt(aes, c) or p != 'gimme_flag':
		raise Exception('What...')
	return tsb_encrypt(aes, flag)

def get_payload(iv_byte, block):
    iv = pack('<I', iv_byte)[0].rjust(16, '\x00')
    return (iv + xor(block, iv) + iv)

def decrypt(block):
    last_byte = 0
    for i in range(256):
        if not decryption_oracle('', get_payload(i, block)):
            last_byte ^= i

    curr = ''
    for i in range(15, 0, -1):
        for c in range(256):
            if decryption_oracle(curr + chr(c), get_payload(last_byte^i, block)):
                curr += chr(c)
                break
    return curr + chr(last_byte)


block = b'\x00'*(16)
curr = decrypt(block)
desired = 'gimme_flag'.ljust(15, ' ') + chr(6)
iv = xor(curr, desired)
payload = (iv + xor(iv, block) + iv)
flag = get_flag('gimme_flag', payload)


def __decrypt(msg):
    iv, msg = msg[:16], msg[16:]
    prev_pt = iv
    prev_ct = iv
    pt = ''
    for block in split_by(msg, 16):
        pt_block = xor(block, prev_ct)
        pt_block = decrypt(pt_block)
        pt_block = xor(pt_block, prev_pt)
        pt += pt_block
        prev_pt = pt_block
        prev_ct = block
    pt, mac = pt[:-16], pt[-16:]
    if mac != iv:
        raise CryptoError()
    return unpad(pt)

print(__decrypt(flag))

```
