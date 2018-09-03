from __future__ import print_function
from pwn import *
import random

choices = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

alphabet = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 
  'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
  'W', 'X', 'Y', 'Z', 
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 
  'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
  'v', 'w', 'x', 'y', 'z']

mapping = { ch:val for val, ch in enumerate(alphabet)}

def base59encode(msg):
	n = int(msg.encode('hex'), 16)
	ret = []
	while n > 0:
		ret.append(alphabet[n%59])
		n /= 59
	return ''.join(reversed(ret))

def base59decode(s):
	ret = 0
	for e in s:
		ret = ret*59 + mapping[e]
	return hex(ret)[2:].decode('hex')

space = set()
msgs = []
expected = []

while len(space) < 59:
	msg = ''.join([random.choice(choices) for _ in range(40)])
	encoded = base59encode(msg)
	expected.append(encoded)
	space.update(set(encoded))
	msgs.append(msg)


r = remote('crypto.chal.ctf.westerns.tokyo', 14791)
flag = r.recvline()[len('encrypted flag: '):].strip()
r.recvuntil('message: ')

actual = []
for msg in msgs:
	r.send(msg + '\n')
	cipher = r.recvuntil('message: ')
	cipher = cipher[len('ciphertext: '):-len('message: ')].strip()
	actual.append(cipher)

substitution = {}
for exp, act in zip(expected, actual):
	for l, r in zip(exp, act):
		substitution[r] = l

decrypted_flag = ''.join(substitution[e] for e in flag)
print(base59decode(decrypted_flag))