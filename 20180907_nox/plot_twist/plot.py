from __future__ import print_function
from pwn import *
# from .MTRecover import MT19937Recover

r = remote('chal.noxale.com', 5115)
r.recvline()

to_send = '0'*16
bits = []
for i in range(625):
	r.send(to_send)

for i in range(625):
	key = r.recvuntil('key:\n').split()[4]
	bits.append(int(key))

mtb = MT19937Recover()
rand = mtb.go(bits)
to_send = str(rand.getrandbits(32)).rjust(16, '0')

r.send(to_send)
print(r.recv())
