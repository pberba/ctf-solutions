# SECT CTF 2018: gsh

__Tags:__ `crypto`, `aes`, `linear algebra`  
__Total Solvers:__ 8  
__Total Points:__ 314

## Problem Statement

About last night...

`nc crypto.sect.ctf.rocks 3333`

```
Submitted 2 months ago by [deleted] to /r/infoleaks

I tried to login... was able to get a shell, but as a restricted user.
It seems horrendously badly configured. Which is what I would've expected.
Fortunately, I found a source code from an old unencrypted backup drive...
this one's particularly interesting...

    class AESHash(object):

        def __init__(self, key):
            self.bs = 16
            self.key = hashlib.sha256(key.encode()).digest()

        def _pkcs7pad(self, s, blksize=16):
            missing = abs(len(s) - (len(s) / blksize + 1) * blksize)
            return s + (chr(missing) * missing)

        def digest(self, user, password):
            cipher = AES.new(self.key, AES.MODE_ECB)
            q = 0
            data = self._pkcs7pad(user + password)
            for i in xrange(0, len(data), self.bs):
                block = data[i:i + self.bs]
                q ^= int(cipher.encrypt(block).encode("hex"), 0x10)
            return q

Their authentication mechanism uses some weird keyed AES-based MAC -- I've
never seen anything like it before. I'd say it's insecure, but I don't know
how to exploit it. Also, it's written in Python. Really?

Since the HMAC combines credentials in the following way... it's kind of
moot to give it a try. I've learnt from one-oh-one that h(message | key) is
secure... I think.  Motherf... I'll give up; it's late and I need to go to
sleep... over and out. For now.


-- JD


The revolution will not be televised.
```

When you connect to the service in the original problem, you be asked to provide a username and password, or create a new user.

If you create a new user, you will get the following prompt:

`IO error: cannot write testuser:57ef36c6071b024df40fd6e5f47857d8 to /etc/shadow.`

We get a shell, and you can get the hash of the __admin__ account.

```
$ cat /etc/shadow
admin:8f643bbafa959617b12b591f3145e5c0
```


## Solution

This problem is about finding input that will provide a __hash collision__ with the hash of the admin account.

### Analyzing the hash

We analyze the hash function and we see that the input is made up of _blocks of 16 bytes_ that is processed with AES.

```python
def digest(self, user, password):
    cipher = AES.new(self.key, AES.MODE_ECB)
    q = 0
    data = self._pkcs7pad(user + password)
    for i in xrange(0, len(data), self.bs):
        block = data[i:i + self.bs]
        q ^= int(cipher.encrypt(block).encode("hex"), 0x10)
    return q
```

And from the prompt we note that:

>  I've learnt from one-oh-one that h(message | key) is
secure... I think

Now it is important not three facts here:
1. The mode used in AES is __ECB__
2. The blocks are just __XOR'ed__ with each other
3. The key is appended in the message before hashing. H(message | key)

This gives us with several nice properties. Since the AES is in ECB mode, then the order of the blocks do not really matter and we are sure that a particular block will have a unique hash value.

```python
a = '0'*16 # bytes per block
b = '1'*16

a_hash  = get_hash(a)
b_hash  = get_hash(b)
ab_hash = get_hash(a+b)
ba_hash = get_hash(b+a)

assert ab_hash == ba_hash
assert (a_hash ^ b_hash) == ab_hash  # This will fail ... why?
```

The last statement will fail because the _key_ is appended to the message before each hashing.

```python
get_hash(a)   == H(a) ^ H(key)
get_hash(b)   == H(b) ^ H(key)
get_hash(a+b) == H(a) ^ H(b) ^ H(key)
```

So to simplify things, __we first get the hash of the key__.

```python
get_hash(a+a) == H(a) ^ H(a) ^ H(key)
get_hash(a+a) == (H(a) ^ H(a)) ^ H(key)
get_hash(a+a) == H(key)
```

And now we can get the actual hashes and reliably determine the resultant hash of whatever input we want.

```Python
key_hash  = get_hash(a+a)
a_hash    = get_hash(a) ^ key_hash
b_hash    = get_hash(b) ^ key_hash
ab_hash   = get_hash(a+b) ^ key_hash

assert (a_hash ^ b_hash) == ab_hash
```

### Finding a collision

Our main goal would be given several inputs which we know the corresponding hash, find a combination of these input that will result to our desired hash.

```python
h1 = H(x1) # get_hash(x1) ^ key_value
h2 = H(x2)
h3 = H(x3)
...
```
Find some subset of h's such that
```python
h1 + h2 + ... + hn == (0x57ef36c6071b024df40fd6e5f47857d8^key_value) # Admin Hash
```
Such that
```python
get_hash(x1+x2+...+xn) == 0x57ef36c6071b024df40fd6e5f47857d8
```

We represent this problem in a system of linear equation in the GF(2).

For example

```
x1 = 101
x2 = 001
x3 = 110

desired = 010
```

The last bit is a result of x1 to x3...

```
0 = 1*x1 + 1*x2 + 0*x3
1 = 0*x1 + 0*x2 + 1*x3
0 = 1*x1 + 0*x2 + 1*x3
```

And we can represent this as a matrix

```
[ 1 1 0 ]   [ x1 ]   [ 0 ]
[ 0 0 1 ] x [ x2 ] = [ 1 ]
[ 1 0 1 ]   [ x3 ]   [ 0 ]
```

So finding a collision is:  

1. Generate 128 payload-hash pairs
2. Use the 128 hashes to construct a 128x128 matrix
3. Solve for the linear combination that results to the desired hash in GF(2)

### Getting the flag

Submit the corresponding payload to the solution from the previous step and then get the flag
`SECT{...1_w4s_ly1ng_0f_c0urse_LuLz}`

## Implementation

### Solving for the hash collision
```Python
def get_bits(n):
	ret = []
	for i in range(128):
		ret.append(n%2)
		n = n >> 1
	return ret

labels = []
m = [[] for _ in range(128)]

with open('samples.txt') as f:
	samples = f.readlines()
	for line in samples:
		b, h = line.split(',')
		h_val = int(h, 0x10)
		for idx, v in enumerate(get_bits(h_val)):
			m[idx].append(v)
		labels.append(b)

desired = 'ec10d43e1badbd1c9838e1020d365fc0' # admin_hash ^ key_hash
M = Matrix(Integers(2), m)
y = vector(get_bits(int(desired, 0x10)))
solution = M.solve_right(y)
ans = []
for idx, v in enumerate(solution):
	if v != 1:
		continue
	ans.append(labels[idx])

print(''.join(ans))
```
