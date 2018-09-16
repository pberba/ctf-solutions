from pwn import *
import binascii
import random


labels = []
hashes = []

key = int('6374ef84e1382b0b2913b81d3c73ba00', 0x10)

for _ in range(3):
	r = []
	test = []
	for i in range(50):
		b = bytearray([random.getrandbits(8) for _ in range(16)])
		labels.append(binascii.hexlify(b))
		_r = remote('crypto.sect.ctf.rocks', 3333)
		_r.send('\n')
		_r.send(b)
		_r.send('\n\n')
		r.append(_r)

		_r = remote('crypto.sect.ctf.rocks', 3333)
		_r.send('\n')
		_r.send(b+b)
		_r.send('\n\n')
		test.append(_r)

	for i in range(50):
		_r = r[i]
		res = _r.recvuntil('/etc/shadow.')
		h = hex(int(res.split()[-3].split(':')[-1], 0x10)^key).lstrip('0x').rstrip('L')
		_r.close()
		_r = test[i]
		res = _r.recvuntil('/etc/shadow.')
		test_h = int(res.split()[-3].split(':')[-1], 0x10)
		_r.close()
		if test_h != key:
			print("!")
			h = None
		hashes.append(h)

with open('samples.txt', 'w') as f:
	for (b, h) in zip(labels, hashes):
		if h is None:
			continue
		f.write('{},{}\n'.format(b, h))
