# Tokyo Western 2018: Revolutional Secure Angou (Solved After)

__Tags:__ `crypto`, `crypto-rsa`, `solved-after`

## Disclaimer
I did not solve this during the CTf. Solved after the CTF after reading [P4's write up](https://github.com/p4-team/ctf/tree/master/2018-09-01-tokyowesterns/crypto_rsa).

This is written as my reference in the future.

## Problem Statement

We are given a zip file containing an encrypted flag, an RSA public key, and a ruby script.

```ruby
require 'openssl'

e = 65537
while true
  p = OpenSSL::BN.generate_prime(1024, false)
  q = OpenSSL::BN.new(e).mod_inverse(p)
  next unless q.prime?
  key = OpenSSL::PKey::RSA.new
  key.set_key(p.to_i * q.to_i, e, nil)
  File.write('publickey.pem', key.to_pem)
  File.binwrite('flag.encrypted', key.public_encrypt(File.binread('flag')))
  break
end
```

## Solution

We first express the relationship between `p`, `q` and `e` based on the code.

```
q   = e^1 mod p        # q = OpenSSL::BN.new(e).mod_inverse(p)
eq  = 1 mod p         
eq  = kp + 1           # For some k
eqp = kp^2 + p  
en  = kp^2 + p         # Since n = qp
```

We know that `q < p`, therefore
```
pq < p^2
n  < p^2
```

Based on this we can find the bounds of `k`, since

`en  = kp^2 + p` and `n < p^2` __implies__ `e > k`

Since `e = 65537`, this is small enough to brute force. We solve for p `kp^2 + p - en = 0 for some k < 65537`, and we can do this by using the quadratic formula as we iterate through `k`.

I had some problems with decrypting the flag, since I'm not that experienced with _RSA_ on python. However, I was able to solve my problems reading through the [P4's write up](https://github.com/p4-team/ctf/tree/master/2018-09-01-tokyowesterns/crypto_rsa). And I refactored my code to use their `crypto-common` module and `gmpy2` which made the computation much faster.

```python
from crypto_commons.rsa.rsa_commons import modinv, rsa_printable
from Crypto.PublicKey import RSA
import gmpy2
public_key = RSA.importKey(open('publickey.pem', 'r').read())

def find_solution(a, b, c):
    temp = b**2 - 4*a*c
    p_candidate = gmpy2.isqrt(temp)
    if p_candidate**2 != temp:
        raise ValueError('No Solution')
    if (p_candidate-b) % (2*a) != 0:
        raise ValueError('No Solution')
    return (p_candidate-b)//(2*a)


n = public_key.n
e = public_key.e
ne = n*e

for k in range(1, e+1):
    try:
        p = find_solution(k, 1, -ne)
        break
    except ValueError:
        continue

q = n//p
d = modinv(e, (p-1)*(q-1))

with open('flag.encrypted', 'rb') as flag:
    cipher = int(flag.read().hex(), 16)

# Wrong way to decrypt
# print(bytes.fromhex(hex(pow(cipher, d, n))[2:-1]))
print(str(rsa_printable(cipher, d, n)))
```
