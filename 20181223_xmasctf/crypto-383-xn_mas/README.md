# X-MAS CTF 2018: X^n-mas (Crypto 383)

__Tags:__ `gaussian elimination`  
__Total Points:__ 383  
__Toal Solvers:__ 51


## Problem Statement

```
Hello to the most amazing Christmas event. The X^n-Mas!
You can send at most 50 requests to the server.
The modulo is 1705110751. Good luck!
Enter a integer:
```

The modulo is different for each run.

## Solution

Since there are at most 50 requests, it is a reasonable assumption that the degree of the polynomial is at most 49.

But to illustrate the solution, let us say we only have a quadratic polynomial

```
f(x) = a + bx + cx^2
```

The if we evaluate `f(x1)` we get,

```
f(x1)  = a + b*(x1) + c*(x1^2)
```

We can evaluate `f(.)` several times to get a system of linear equations, and solve for the coefficients.

```
f(0)  = 2
f(1)  = 39
f(2) = 99
```
then

```
2  = a +  0b +    0c
39 = a + 39b + 1521c
99 = a + 99b + 9802c
```

This can be solved this using gaussian elimination, and we extend this to polynomial degree 49, and the coefficients of the polynomial represent the flag `X-MAS{W3_w1sh_you_4_m3rry_Christmas}`


## Implementation

### Fetching Results

```python
from pwn import *

r = remote('199.247.6.180', 16000)

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
```

### Solving for the flag

```python
# sagemath
mod = 3524587069
m = [[] for _ in range(50)]
y = []
with open('files/mod_3524587069.txt') as f:
	for idx, line in enumerate(f.readlines()):
		i, res = line.split()
		for e in range(50):
			m[idx].append(pow(int(i), e, mod))
		y.append(int(res))

y = vector(y)
M = Matrix(Integers(mod), m)
solution = M.solve_right(y)
print(''.join([chr(e) for e in reversed(solution)]))
```
