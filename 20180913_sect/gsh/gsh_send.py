from pwn import *
import binascii
import random

with open('answer.txt') as f:
	to_send = binascii.unhexlify(f.read().strip())

r = remote('crypto.sect.ctf.rocks', 3333)
r.send(to_send[:-16] + '\n')
r.send(to_send[-16:] + '\n')
r.send('ls\n')
r.send('cat invoice.xls\n')
print(r.recvuntil('}'))
