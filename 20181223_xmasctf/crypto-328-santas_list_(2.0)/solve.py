from pwn import *
from Crypto.Util.number import *

r = remote('199.247.6.180', 16002)
flag = int(r.recvuntil('Exit\n').split('Galf - ')[1].split()[0], 16)

def encrypt(m):
	r.sendline("1")
	r.sendline(long_to_bytes(m))
	reply = r.recvuntil('Exit\n')
	return int(reply.split('Encrypted: ')[1].split()[0])

def decrypt(ct):
	r.sendline("2")
	r.sendline(str(ct))
	reply = r.recvuntil('Exit\n')
	return int(reply.split('Decrypted: ')[1].split()[0])

e = 65537
def get_resid(i):
	return i**e - encrypt(i)

def get_n():
	curr = get_resid(bytes_to_long('a'))
	for i in [bytes_to_long('b'), bytes_to_long('c')]:
		curr = GCD(curr, get_resid(i))
	return curr

n = get_n()
m = flag*(n-1) % n
pt = decrypt(m)
print(long_to_bytes((pt*(n-1))%n))
