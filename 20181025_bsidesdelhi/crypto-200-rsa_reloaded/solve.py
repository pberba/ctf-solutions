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
