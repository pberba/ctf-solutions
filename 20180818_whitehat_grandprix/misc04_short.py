from pwn import *

def mod_pow(n, e, mod):
	if e == 0:
		return 1
	ret = mod_pow(n, e/2, mod)
	ret = (ret*ret) % mod
	if e % 2 == 1:
		ret *= n
	return ret % mod


def mod_find_cycle(n, mod):
	curr = (n**2)%mod
	count = 2
	while curr != (n%mod):
		curr = (curr*n)%mod
		count+=1
	return count-1

r = remote('misc04.grandprix.whitehatvn.com', 1337)
message = r.recvuntil('face?\n')
prompt = message.split('\n')[5:]

while True:
	face_index = int(prompt[0].split(': ')[1])
	faces = []

	for e in prompt[2:]:
		if e.startswith('So'):
			break
		parts = e.split()
		face = parts[0]
		lip = int(parts[1])
		nose = int(parts[2])
		eyes = int(parts[3])
		forehead = int(parts[4])

		lip_nose = mod_pow(lip, nose, face_index)
		cycle_length = mod_find_cycle(lip_nose, face_index)
		eyes_forehead = mod_pow(eyes, forehead, cycle_length)
		value = mod_pow(lip_nose, eyes_forehead, face_index)
		faces.append((value, face))

	faces.sort()
	r.send(faces[-1][1] + '\n')
	r.recvline()
	r.send('{}\n'.format(faces[-1][0]))
	stage = r.recvline()
	if 'Stage' not in stage:
		print(stage)
		break
	prompt = r.recvuntil('face?\n').split('\n')
