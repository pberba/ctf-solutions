from pwn import *
from Crypto.Util.number import *

r = remote('199.247.6.180', 16000)

# Hello to the most amazing Christmas event. The X^n-Mas!
# You can send at most 50 requests to the server.
# The modulo is 1705110751. Good luck!
# Enter a integer:

prompt = r.recvuntil('Good luck!')
mod = int(prompt.split(' is ')[1].split('.')[0])
print(mod)
def get_result(x):
	r.recvuntil('integer:')
	r.sendline(str(x))
	r.recvuntil(':')
	ret = int(r.recvuntil('\n').strip())
	return ret

output = []
for i in range(50):
	res = get_result(i)
	output.append((i, res))

with open('solve.out', 'w') as f:
	for i, res in output:
		f.write('{} {}\n'.format(i, res))
