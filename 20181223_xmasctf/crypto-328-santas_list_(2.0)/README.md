# X-MAS CTF 2018: Santa's List (2.0) (Crypto 328)

__Tags:__ `rsa`, `textbook-rsa`  
__Total Points:__ 328  
__Toal Solvers:__ 63


## Problem Statement

The solution for _Santa's List_ and _Santa's List 2.0_ are the same.

The problem gives you an encrypted flag, and then gives you the ability to encrypt and decrypt.

```python
rsa = RSA.generate(1024)
flag_encrypted = pow(bytes_to_long(FLAG.encode()), rsa.e, rsa.n)
```

## Encrypted and Decryption

Notice you cannot decrypt anything that has a plaintext which is a multiple of anything that has been encrypted previously by the server (including the flag itself). Instead of giving the plaintext, `Ho, ho, no...` is printed

```python
used = [bytes_to_long(FLAG.encode())]
...
for i in range(5):
    if choice == '1':
        m = bytes_to_long(input('\nPlaintext > ').strip().encode())
        used.append(m)
        print('\nEncrypted: ' + str(encrypt(m)))
    elif choice == '2':
        c = int(input('\nCiphertext > ').strip())
        if c == flag_encrypted:
            print('Ho, ho, no...')
        else:
            m = decrypt(c)
            for no in used:
                if m % no == 0:
                    print('Ho, ho, no...')
                    break
            else:
                print('\nDecrypted: ' + str(m))
```

## Solution

Notice that the flag is encrypted using _textbook-rsa_, which means that the plaintext is malleable. To illustrate the general idea, let us first solve a simpler version of this problem.

### Simpler version of the problem

If the problem given was the following,

```python
for i in range(5):
    if choice == '1':
        m = bytes_to_long(input('\nPlaintext > ').strip().encode())
        print('\nEncrypted: ' + str(encrypt(m)))
    elif choice == '2':
        c = int(input('\nCiphertext > ').strip())
        if c == flag_encrypted:
            print('Ho, ho, no...')
        else:
            print('\nDecrypted: ' + str(m))
```

Since the ciphertext is malleable, then we can mutate the ciphertext in a way that is predictable to us.

```
ct_flag     = encrypt(flag)  = flag^e     mod n
ct_two      = encrypt(2)     = 2^e        mod n
ct_not_flag = ct_flag*ct_two = (flag*2)^e mod n
```

Therefore, `decrypted(ct_not_flag) = flag*2`

But this problem _does not allow_ this. So we have to look for a way to manipulate the ciphertext.

### Solving the current version

Let's say we have the public key `(n, e)`, then we can bypass the `Ho, ho, no...`

```
ct_flag     = encrypt(flag)  = flag^e     mod n
ct_neg      = encrypt(-1)    = -1^e       mod n = -1 mod n
ct_not_flag = ct_flag*ct_neg = (flag*-1)^e mod n
```

Which means that `decrypted(ct_not_flag) = flag*-1 mod n`, and we can easily recover the flag from that.

```python
e = 65537
n = get_n()
m = flag*(n-1) % n
pt = decrypt(m)
print(long_to_bytes((pt*(n-1))%n))
```

But this requires us to be able to get `n` and `e`.

### Getting the public key

Getting `e` is easy because the default value is `e = 65537` and we are left to find `n`.

It's easy to show that for some `m`, then `m**65537 - encrypt(m)` is a multiple of `n`, and for some cases,
```
n = gcd(m1**65537 - encrypt(m1), m2**65537 - encrypt(m2))
```

You can get the GCD of several residuals to make it more likely that you have gotten `n`.

We implement this using,  

```python
e = 65537
def get_resid(i):
	return i**e - encrypt(i)

def get_n():
	curr = get_resid(bytes_to_long('a'))
	for i in [bytes_to_long('b'), bytes_to_long('c')]:
		curr = GCD(curr, get_resid(i))
	return curr
```

This gives us the flag `X-MAS{n4ugh7y_dd0s_pr073c710n_1sn7_h4rd_r1gh7?}`

### Full Implementation

```python
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
```
