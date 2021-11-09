
#### Suspicious Signing (650 point, 21 solves)

##### Problem 

You are given the following source code and you would have to interact with a server to get the flag.

```python
from hashlib import md5
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from ecdsa import ellipticcurve
from ecdsa.ecdsa import curve_256, generator_256, Public_key, Private_key
from random import randint
from os import urandom

flag = open("flag.txt").read().strip().encode()
G = generator_256
order = G.order()

def genKey():
    d = randint(1,order-1)
    pubkey = Public_key(G, d*G)
    privkey = Private_key(pubkey, d)
    return pubkey, privkey
    
def ecdsa_sign(msg, privkey):
    hsh = md5(msg).digest()
    nonce = md5(hsh + long_to_bytes(privkey.secret_multiplier)).digest() * 2
    sig = privkey.sign(bytes_to_long(msg), bytes_to_long(nonce))
    return msg, sig.r, sig.s

def encryptFlag(privkey, flag):
    key = md5(long_to_bytes(privkey.secret_multiplier)).digest()
    iv = urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(flag, 16))
    return ciphertext, iv
    
pubkey, privkey = genKey()
ct, iv = encryptFlag(privkey, flag)
print(f"""Encrypted flag: {ct.hex()}
iv: {iv.hex()}""")
while True:
    msg = input("Enter your message in hex: ")
    try:
        msg = bytes.fromhex(msg)
        m, r, s = ecdsa_sign(msg, privkey)
        print(f"""Message: {m.hex()}
r: {hex(r)}
s: {hex(s)}""")
    except:
      print("An error occured when trying to sign your message.")
```

##### Initial Analysis

Notice that in the `encryptFlag` the AES key is generated from the secret exponent of the ECDSA key `privkey.secret_multiplier`. 

Therefore, the main objective is to try to somehow recover the private key of the ECDSA. 


A big clue here is that the `nonce` used in the encryption is not really a `nonce`. 


```python
def ecdsa_sign(msg, privkey):
    hsh = md5(msg).digest()
    nonce = md5(hsh + long_to_bytes(privkey.secret_multiplier)).digest() * 2
    ...
```

Problems like this are usually using [the famous attack on the playstation 3 crypto implementation](
https://arstechnica.com/gaming/2010/12/ps3-hacked-through-poor-implementation-of-cryptography/).   

These attacks are able to recover the private key if the nonce is reused for two different signatures.

This attack is well documented:
- http://koclab.cs.ucsb.edu/teaching/ecc/project/2015Projects/Schmid.pdf
- https://github.com/bytemare/ecdsa-keyrec

##### Hash Collision

This attack is not as straightforward because the nonce uses the hash of the message when being generated. 

You might think that since it is derived from the hash of the message, it should be random right? 

No. We can trick server into using the same hash for two messages by using hash collision.

Because the hash used is `MD5` which is part of a family of hashing that uses the [Merkle–Damgård construction](https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction) we can easily generate hash collisions by sending two messages with the same MD5 hash.

[Wikipedia even an example of hash collision that you can use for this problems](https://en.wikipedia.org/wiki/MD5#Collision_vulnerabilities). 

So get the signature for the message

```
d131dd02c5e6eec4 693d9a0698aff95c 2fcab58712467eab 4004583eb8fb7f89
55ad340609f4b302 83e488832571415a 085125e8f7cdc99f d91dbdf280373c5b
d8823e3156348f5b ae6dacd436c919c6 dd53e2b487da03fd 02396306d248cda0
e99f33420f577ee8 ce54b67080a80d1e c69821bcb6a88393 96f9652b6ff72a70
```

and then get the signature for 

```
d131dd02c5e6eec4 693d9a0698aff95c 2fcab50712467eab 4004583eb8fb7f89
55ad340609f4b302 83e4888325f1415a 085125e8f7cdc99f d91dbd7280373c5b
d8823e3156348f5b ae6dacd436c919c6 dd53e23487da03fd 02396306d248cda0
e99f33420f577ee8 ce54b67080280d1e c69821bcb6a88393 96f965ab6ff72a70
```

and validate the the nonce are the same.

The output of the server should be

```
Encrypted flag: 248005ebc638b16a0208f6c7949f1c68a147f906aa2e749985cdde5e51d230f87af2d19ec0ce1ddfb8808585dd54257bc86d456d4ca1cc8920667e792ad5c4f1
iv: d39a60befaeb2cb45ce8d2181371a387



Enter your message in hex: d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70

Message: d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70
r: 0x557a787642ece2fe307b7de417d7d3c7bfe92313020a58e49771be515c4cadc
s: 0x8d1c17fb248fb8b0af29d64365fae1b495c4eb6340ce027f9f3625564a945cda



Enter your message in hex: d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70

Message: d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70
r: 0x557a787642ece2fe307b7de417d7d3c7bfe92313020a58e49771be515c4cadc
s: 0xda91bba782f6e63aadd53f74bd989f194664a8273d431d4e104b55e01d355296
```

##### Recovering private key 

I just used the relevant code from  [bytemare/ecdsa-keyrec](https://github.com/bytemare/ecdsa-keyrec)


```python
def decryptFlag(secret_exponent, iv, flag):
    key = md5(long_to_bytes(secret_exponent)).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(flag)

order = generator_256.order()

ciphertext = bytes.fromhex('248005ebc638b16a0208f6c7949f1c68a147f906aa2e749985cdde5e51d230f87af2d19ec0ce1ddfb8808585dd54257bc86d456d4ca1cc8920667e792ad5c4f1')
iv = bytes.fromhex('d39a60befaeb2cb45ce8d2181371a387')
m1 = bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70')
r1 = 0x557a787642ece2fe307b7de417d7d3c7bfe92313020a58e49771be515c4cadc
s1 = 0x8d1c17fb248fb8b0af29d64365fae1b495c4eb6340ce027f9f3625564a945cda
m2 = bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70')
r2 = 0x557a787642ece2fe307b7de417d7d3c7bfe92313020a58e49771be515c4cadc
s2 = 0xda91bba782f6e63aadd53f74bd989f194664a8273d431d4e104b55e01d355296

# Validate the the nonce are the same for two different signatures
assert r1 == r2
assert s1 != s2

h1 = bytes_to_long(m1)
h2 = bytes_to_long(m2)


r = r1

r_inv = inverse_mod(r, order)
h = (h1 - h2) % order

for k_try in (s1 - s2,
              s1 + s2,
              -s1 - s2,
              -s1 + s2):

    k = (h * inverse_mod(k_try, order)) % order
    secexp = (((((s1 * k) % order) - h1) % order) * r_inv) % order
    print(decryptFlag(secexp, iv, ciphertext))

# b'HTB{r3u53d_n0nc35?n4h-w3_g0t_d3t3rm1n15t1c-n0nc3s!}\r\r\r\r\r\r\r\r\r\r\r\r\r'
```