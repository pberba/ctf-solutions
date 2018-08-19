# WhiteHat GrandPrix 2018: Misc04

## Problem Statement

`nc misc04.grandprix.whitehatvn.com 1337`

__Hint__: After get the message "It's a friendly point", you should send the friendly point value.

Here is the prompt:

```
                   Wellcom to Friendly face challenge
According to experts, the formula for measuring the friendliness of a face is
    (lip point**nose point)**(eyes point**forehead point) mod Face_index
                              Now play!
------------------------------Stage 1--------------------------------------
Face_index: 7897184
Face           Lip point      Nose point     Eyes point     Forehead point
:-)            475020320      847953080      880256045      579217726      
(';')          428011459      639570885      173423050      299150823
...     
(=^..^=)       937474753      344758946      966767343      782968811      
So, what is the most friendly face?
```

## Solution

The solution that will be discussed would be the "semi-naive" approach in solving this problem. It doesn't necessarily solve the problem well sometimes but it is _good enough_ to get the flag.

### Explanation ("Quick" Approach)

If we try to compute the _friendliness_ of the `:-)` face, we would have to evaluate:
```python
((475020320**847953080)**(880256045**579217726)) mod 7897184
```

So a useful concept here is to use `mod_pow` which is really just [binary exponentiation](https://cp-algorithms.com/algebra/binary-exp.html).

```python
def mod_pow(n, e, mod):
	if e == 0:
		return 1
	ret = mod_pow(n, e/2, mod)
	ret = (ret*ret) % mod
	if e % 2 == 1:
		ret *= n
	return ret % mod
```

With `mod_pow`, we can quickly evaluate `(475020320**847953080) mod 7897184` which is `2954392`. Now we are left with:

```python
(2954392**(880256045**579217726)) mod 789718
```

 It is __incorrect__ to assume that we can simply get `(880256045**579217726) mod 789718` and substitute that value in the equation. Instead we have to find the period of `2954392^r mod 789718`. When we evaluate the following:
 * `2954392^1 mod 789718`
 * `2954392^2 mod 789718`
 * `2954392^3 mod 789718`
 * `2954392^4 mod 789718`
 * ...

We will find an exponent `r` such that `2954392^r == 2954392 mod 789718`. The easiest way to do this is to just evaluate `r=1`, `r=2`, ... until we find the period, which is `r-1 = 46452`.

```python
def mod_find_cycle(n, mod):
	curr = (n**2)%mod
	count = 2
	while curr != n:
		curr = (curr*n)%mod
		count+=1
	return count-1
```

Using this period, we can now find `(475020320**847953080) mod (46452))`, which is `5632`. And now we can simply have to evaluate:

```python
(2954392**(5632)) mod 789718
```

This is `230232`.

So in summary, given the functions defined above:
```python
lip_nose = mod_pow(lip, nose, face_index)
cycle_length = mod_find_cycle(lip_nose, face_index)
eyes_forehead = mod_pow(eyes, forehead, cycle_length)
value = mod_pow(lip_nose, eyes_forehead, face_index)
```

### Full Solution
```python
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

```

Perhaps the hardest part of the problem is that without the _hint_, you'd have to guess that you'd have to send the value after giving the face.
