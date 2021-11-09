from Crypto.Util.number import getPrime, bytes_to_long
from math import gcd

flag = open("flag.txt").read().strip().encode()

p = getPrime(1024)
q = getPrime(1024)
n = p * q
e1 = 0x10001
e2 = 0x13369

print(e1, e2)


assert gcd(p-1,e1) == 1 and gcd(q-1, e1) == 1 and gcd(p-1,e2) == 1 and gcd(q-1, e2) == 1

phi = (p-1) * (q-1)
d1 = pow(e1, -1, phi)
print(f"""Retrieved agent data:
n = {n}
e = {e1}
d = {d1}""")


ct = pow(bytes_to_long(flag), e2, n)
print(f"""Spy messages: 
e = {e2}
ct = {ct}""")