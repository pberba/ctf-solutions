# BSides Dehli CTF 2018: RSA Reloaded (Crypto 200)

__Tags:__ `crypto`, `rsa`, `brute-force`  
__Total Points:__ 200

## Problem Statement

### encrypt.py
The implementation of `encrypt.py` is short enough for us to fully show here.

```python
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
import gmpy2

p=getPrime(1024)
q=getPrime(1024)

N1=p*q
e=65537L

flag=open('flag.txt').read()
f1=bytes_to_long(flag[:len(flag)/2])
f2=bytes_to_long(flag[len(flag)/2:])

if p>q:
	x=p%q
else:
	x=q%p

r=gmpy2.next_prime(x+f1)
s=gmpy2.next_prime(r)

for i in range(50):
	s=gmpy2.next_prime(s)

N2=r*s

enc_f1=pow(f2,e,N1)
enc_f2=pow(f1,e,N2)

pub_key = RSA.construct((int(N1), e))
pub_key2 = RSA.construct((int(N2), e))
open("publickey1.pem","w").write(pub_key.exportKey("PEM"))
open("publickey2.pem","w").write(pub_key2.exportKey("PEM"))

file1 = open("ciphertext1.txt", 'w')
file2 = open("ciphertext2.txt", 'w')
file1.write(str(enc_f1))
file2.write(str(enc_f2))

```

## Solution

From the code we can approximate the differences of `p` and `q` used for `N`. And with the different `d` where `q = p + d` we can easily derive `p` and `q` from `N`.


### Decrypting ciphertext2

`ciphertext2` is encrypted using `r` and `s` in the code.

We look at how `r` and `s` is generated.

```python
r=gmpy2.next_prime(x+f1)
s=gmpy2.next_prime(r)

for i in range(50):
	s=gmpy2.next_prime(s)
N2=r*s
```

This can be summarized to
1. `r` is some random prime number
2. `s` is the 51st prime number after `r`

Note that primes are occur frequently so the gaps between primes are expected to be relatively small, even between for large primes.

Since the difference between `d = s - r` is small we simply use brute force to guess the value of `d`. Deriving `s` and `r` from `N2` is simply solving for `s*(s+d) = N2`.

```python
def factor(N, init=1, dx=1):
	_d = init
	while True:
		_s = gmpy2.isqrt(N + (_d/2)**2) + _d/2
		_r = _s - _d
		if _s *_r == N:
			return _s, _r
		_d += dx
```

And with that we can decrypt `ciphertext2`

```python
def decrypt(p, q, e, ct):
	n = p*q
	phi = (p-1)*(q-1)
	d = inverse(e, phi)
	return pow(ct, d, n)


with open('publickey2.pem') as f:
	key2 = RSA.importKey(f)
with open('ciphertext2.txt') as f:
	ct2 = int(f.read().strip())

p, q = factor(key2.n)
f1 = decrypt(p, q, key2.e, ct2)
```

### Decrypting ciphertext1

Recall that `r=gmpy2.next_prime(x+f1)` where `x=abs(p-q)`

```
abs(p-q) + f1 < r
abs(p-q) < r - f1
```

And we just approach this similarly and use brute force to get the value of `abs(p-q)`.


```python
with open('publickey1.pem') as f:
	key1 = RSA.importKey(f)
with open('ciphertext1.txt') as f:
	ct1 = int(f.read().strip())

p, q = factor(key1.n, init=min(p, q) - f1, dx=-1)
f2 = decrypt(p, q, key1.e, ct1)
print(long_to_bytes(f1) + long_to_bytes(f2))
```

To get the flag `flag{F3rm@t_&_s0me_t1nk3r1ng_can_d0_w0nd3rs!!!!}`

## Full Implementation

```python
import gmpy2
from Crypto.Util.number import *
from Crypto.PublicKey import RSA

def factor(N, init=1, dx=1):
	_d = init
	while True:
		_s = gmpy2.isqrt(N + (_d/2)**2) + _d/2
		_r = _s - _d
		if _s *_r == N:
			return _s, _r
		_d += dx


def decrypt(p, q, e, ct):
	n = p*q
	phi = (p-1)*(q-1)
	d = inverse(e, phi)
	return pow(ct, d, n)



with open('publickey2.pem') as f:
	key2 = RSA.importKey(f)
with open('ciphertext2.txt') as f:
	ct2 = int(f.read().strip())

p, q = factor(key2.n)
f1 = decrypt(p, q, key2.e, ct2)

with open('publickey1.pem') as f:
	key1 = RSA.importKey(f)
with open('ciphertext1.txt') as f:
	ct1 = int(f.read().strip())


p, q = factor(key1.n, init=min(p, q) - f1, dx=-1)
f2 = decrypt(p, q, key1.e, ct1)
print(long_to_bytes(f1) + long_to_bytes(f2))
```
