import md5
from pwn import *
import binascii

def hash(s):
	m = md5.new()
	m.update(s)
	return m.hexdigest()[:5]

def capthca(desired):
	curr = 0
	while True:
		ret = hash(str(curr))
		if ret == desired:
			return str(curr)
			break
		curr += 1

r = remote('199.247.6.180',  16003)

# # CAPTCHA!!!
# # Give a string X such that md5(X).hexdigest()[:5]=7be7c.
desired = r.recvuntil('.\n')[-7:-2]
r.sendline(capthca(desired))

# Ok, you can continue, go on!
# The key will be the same for the encryption and all decryptions during this session!
# Here's the encrypted flag: 0aa68eb0bd03595d!
# Here's the partial decription oracle!

# Provide a 8-byte string you want to decrypt as hex input:
# (the string has to have at least half of the bits different from the ciphertext)
# $ dddddddddddddddd
# The decryption of dddddddddddddddd is eee303655851e6ad.



prompt = r.recvuntil('oracle!')
ct_flag = binascii.unhexlify(prompt.split('flag: ')[1].split('!')[0])

def decrypt(x):
	r.sendline(binascii.hexlify(x))
	res = r.recvuntil('.\n')
	return binascii.unhexlify(res.split('is ')[1].split('.')[0])

b = chr(255)*8
# test_ct = chr(0)*8
# ct_1 = decrypt(test_ct)
# ct_2 = decrypt(xor(test_ct, b))
# xr = xor(ct_1, ct_2)

xr = '\xaa'*8
pt_flipped_flag = decrypt(xor(ct_flag, b))

print 'X-MAS{%s}' % xor(pt_flipped_flag, xr)

# https://github.com/RobinDavid/pydes/blob/master/pydes.py
