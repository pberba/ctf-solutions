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
