
#### spy (475 points, 26 solves)

##### Problem 

Here is the source code given but I have removed some code to make it more readable.


Some things to look at:
- `keygen` function, how many bytes are truly random?
- In encryption, AES is doubled but is key strength doubled?

```python
from Crypto.Cipher import AES
import random
import time
import base64

BIT_SIZE = 256
BYTE_SIZE = 32

... 

def keygen():
    random.seed(BYTE_SIZE)
    h = random.getrandbits(BIT_SIZE)
    for i in range(BIT_SIZE):
        random.seed(time.time())
        h = h ^ random.getrandbits(2*BIT_SIZE/BYTE_SIZE)
    return hex(h)[2:-1]

def encrypt(data, key1, key2):
    cipher = AES.new(key1, mode=AES.MODE_ECB)
    ct = cipher.encrypt(pad(data))
    cipher = AES.new(key2, mode=AES.MODE_ECB)
    ct = cipher.encrypt(ct)
    return ct

...

if __name__ == "__main__":
   
    #message = [REDUCTED]
    #flag = [REDUCTED]

    key1 = keygen()
    key2 = keygen()
    
    key1 = key1.decode('hex')
    key2 = key2.decode('hex')

    ct_message = encrypt(message, key1, key2)
    ct_flag = encrypt(flag, key1, key2)
    with open('packet_6.txt.enc', 'w') as f:
        f.write(base64.b64encode(ct_message))

    with open('flag.txt.enc', 'w') as f:
        f.write(base64.b64encode(ct_flag))
```

You are given the ciphertext as well as sample plaintexts for the packets.

```
Plantext packet 3:
'''
Report Day 49:
    Mainframe: Secure
    Main Control Unit: Secure
    Internal Network: Secure
    Cryptographic Protocols: Secure
    
'''

Plantext packet 4:
'''
Report Day 50:
    Mainframe: Secure
    Main Control Unit: Secure
    Internal Network: Secure
    Cryptographic Protocols: Secure
    
''' 

Plantext packet 5:
'''
Report Day 51:
    Mainframe: Secure
    Main Control Unit: Secure
    Internal Network: Secure
    Cryptographic Protocols: Insecure
    
'''    
```

##### Key Generation

Look at the code for key generation

```python
def keygen():
    random.seed(BYTE_SIZE)
    h = random.getrandbits(BIT_SIZE)
    for i in range(BIT_SIZE):
        random.seed(time.time())
        h = h ^ random.getrandbits(2*BIT_SIZE/BYTE_SIZE)
    return hex(h)[2:-1]
```

Notice that the initial value of `h` is _not random_ since the seed is static.

```python
random.seed(BYTE_SIZE)
h = random.getrandbits(BIT_SIZE)
```

Also, notice that the code in the loop only modifies the last 16 bits of `h`

```python
h = h ^ random.getrandbits(2*BIT_SIZE/BYTE_SIZE) # only touches the last 16 bits of h
```

Therefore, we only have to brute force 16 bits per key.

##### Double AES / Triple DES

```python
def encrypt(data, key1, key2):
    cipher = AES.new(key1, mode=AES.MODE_ECB)
    ct = cipher.encrypt(pad(data))
    cipher = AES.new(key2, mode=AES.MODE_ECB)
    ct = cipher.encrypt(ct)
    return ct
```

This way of encrypting the plaintext twice does not double the strenght of the encryption. This is very similar to the classic [Triple DES](https://en.wikipedia.org/wiki/Triple_DES#Security).

This is vulnerable to the "meet in the middle attack" which is possible if we have known plaintext and ciphertext pair.

##### "Guessing" the plaintext

The example plaintexts is not really clear on the exact formating of the packet plaintext.  

```
'''
Report Day 51:
    Mainframe: Secure
    Main Control Unit: Secure
    Internal Network: Secure
    Cryptographic Protocols: Insecure
    
'''    
```

Do I include the ticks? Do I add a newline at the end? Etc...

In the end, I just created a template of the plaintexts and tried to iterate on the different guesses of the plaintex.

I used the following template and 
```python
msg = f"""{prefix}Report Day {day}:
    Mainframe: {s1}
    Main Control Unit: {s2}
    Internal Network: {s3}
    Cryptographic Protocols: {s4}
    {suffix}"""
```

So all in all, just brute force using meet-in-the-middle attack on the 16 random bits of key1 and key2, while guessing the proper plaintext  

##### Full Solution

Here is the full solution. The nested for-loops is an eyesore but it gets the job done.

```python
random.seed(BYTE_SIZE)
key = random.getrandbits(BIT_SIZE)

key_low = key - (key % (1<<16))
key_high = key_low + (1<<16)



ct = {}
for day in [52, 53, 54, 55]:
    for s1 in ['Insecure', 'Secure']:
        for s2 in ['Insecure', 'Secure']:
            for s3 in ['Insecure', 'Secure']:
                for s4 in ['Insecure', 'Secure']:
                    for prefix in ['', '\n']:
                       for suffix in ['', '\n']: 
                        msg = f"""\
{prefix}Report Day {day}:
    Mainframe: {s1}
    Main Control Unit: {s2}
    Internal Network: {s3}
    Cryptographic Protocols: {s4}
    {suffix}"""
                        msg = pad(msg).encode()
                        for k1 in range(key_low, key_high):
                            cipher = AES.new(long_to_bytes(k1), mode=AES.MODE_ECB)
                            _ct = cipher.encrypt(msg)
                            ct[_ct] = k1



with open('packet_6.txt.enc') as f:
    msg_ct = base64.b64decode(f.read())

for k2 in range(key_low, key_high):
    cipher = AES.new(long_to_bytes(k2), mode=AES.MODE_ECB)
    _ct = cipher.decrypt(msg_ct)
    if _ct in ct:
        print(ct[_ct], k2)
        k1 = ct[_ct]
        k2 = k2
        break

# k1, k2 = 27534775351079738483622454743638381042593424795345717535038924797978770229648, 27534775351079738483622454743638381042593424795345717535038924797978770265131


with open('flag.txt.enc') as f:
    ciphertext = base64.b64decode(f.read())

p1 = AES.new(long_to_bytes(k2), mode=AES.MODE_ECB).decrypt(ciphertext)
p2 = AES.new(long_to_bytes(k1), mode=AES.MODE_ECB).decrypt(p1)

print(p2)
```