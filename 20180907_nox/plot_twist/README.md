# noxCTF 2018: Plot Twist

__Tags:__ `crypto`, `crypto-random`  
__Total Solvers:__ 56  
__Total Points:__ 543

## Problem Statement

Can you get the flag from the flawlessly written server?

`nc chal.noxale.com 5115`

See `server.py`

## Solution

### Quick Explanation

We exploit the pseudo random number generator used, which is the __Mersenne Twister__. We are then able to predict the next key used and get the flag.

### Full Solution

I have omitted the parts of `server.py` that are not really necessary.

```python
import random

class ThreadedServer(object):
	def getKey(self, r):
		return str(r.getrandbits(32)).rjust(16, '0')

	def listenToClient(self, client, address):
		client_flag = self.flag
		r = random.Random()
		key = self.getKey(r)
		client_flag = self.encrypt(key, client_flag)
		while True:
			try:
				client.send('Please insert the decryption key:\n')
				key_guess = client.recv(16)
				if key_guess == key:
					client.send('Correct! Your flag is: ' + self.decrypt(key, client_flag) + '\n')
				else:
					client.send('Wrong! The key was: ' + key + '\n')
					client_flag = self.decrypt(key, client_flag)
					key = self.getKey(r)
					client_flag = self.encrypt(key, client_flag)
```

We get two insights:

1. A single instance of `random.Random()` is used per connection
2. Bits generated are eventually leaked to us

The [documentation](https://docs.python.org/2/library/random.html) of python's `random` module states:

> Python uses the Mersenne Twister as the core generator... However, being completely deterministic, it is not suitable for all purposes, and is completely unsuitable for cryptographic purposes.

We use eboda's [MTRecover](https://github.com/eboda/mersenne-twister-recover/blob/master/MTRecover.py) to do this, and we get the flag.

```
Correct! Your flag is: noxCTF{41w4ys_us3_cryp70_s3cur3d_PRNGs}
```

## Implementation

```python
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
```
