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

PI_1 = [40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25]

PI = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

def permut(block, table):
    return [block[x-1] for x in table]

def p(text):
    b = string_to_bit_array(text)
    t = permut(b, PI)
    return bit_array_to_string(t)

def p_inv(text):
    b = string_to_bit_array(text)
    t = permut(b, PI_1)
    return bit_array_to_string(t)

def string_to_bit_array(text):
    array = list()
    for char in text:
        binval = binvalue(char, 8)
        array.extend([int(x) for x in list(binval)])
    return array

def bit_array_to_string(array):
    res = ''.join([chr(int(y,2)) for y in [''.join([str(x) for x in bytes]) for bytes in  nsplit(array,8)]])
    return res

def binvalue(val, bitsize):
    binval = bin(val)[2:] if isinstance(val, int) else bin(ord(val))[2:]
    if len(binval) > bitsize:
        raise "sadadsadasdasdasdasdasdasdwwwddwdqwdwdadasdsadasdade2"
    while len(binval) < bitsize:
        binval = "0"+binval
    return binval

def nsplit(s, n):
    return [s[k:k+n] for k in xrange(0, len(s), n)]


alphabet = '0123456789abcdef'
r = remote('199.247.6.180',  16004, level='error')
# # CAPTCHA!!!
# # Give a string X such that md5(X).hexdigest()[:5]=7be7c.
desired = r.recvuntil('.\n')[-7:-2]
r.sendline(capthca(desired))

res = r.recvuntil('encryption oracle!')
flag = binascii.unhexlify(res.split('flag: ')[1].split('!')[0])

def encrypt(text):
		r.sendline(binascii.hexlify(text))
		r.recvuntil('The encryption of ')
		r.recvuntil(' is ')
		return binascii.unhexlify(r.recvuntil('.')[:-1])



pt = [None for _ in range(len(flag)*2)]

for a in alphabet:
	for b in alphabet:
		print(a, b)
		c = a*8 + b*8
		c = binascii.unhexlify(c)
		text_p = p_inv(c)

		ct = encrypt(text_p)
		ct_p = binascii.hexlify(p(ct))

		for block in range(len(flag)/8):
			desired_ct = binascii.hexlify(p(flag[block*8:(block+1)*8]))
			for i in range(8):
				if ct_p[i] == desired_ct[i] and ct_p[i + 8] == desired_ct[i + 8]:
					pt[block*16 + i] = a
					pt[block*16+ i+8] = b

out = binascii.unhexlify(''.join(pt))
print(''.join([p_inv(b) for b in nsplit(out, 8)]))


# X-MAS{If_y0u_r3m0ve_th3_av4l4nch3_3ff3c7_th3n_4_bl0ckc1ph3r_1s_vuln3r4ble_t0_st4tis7ic4l_an4lys1s!!!!!!}

# Ok, you can continue, go on!
# The key will be the same for all the encryptions during this session!
# You can do at most 512 encryptions every session.
# Here's the encrypted flag: 58dc34b5be01b198196df8bc8107f46b54fd7d61b727d14b255cff803a47632c966ea0151b88d5cee9e9169bba23dd7a1648c796b40ee3526cf23d8f214b7e39f6e805913c22986eecd81fa815220535d8f81682b214fa5fdde43c883e31232eec60e908fd4aebf7!
# Here's the encryption oracle!

# Provide a string you want to encrypt as hex input:
# (the string has to be 8 bytes long)
# $
