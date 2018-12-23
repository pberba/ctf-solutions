# X-MAS CTF 2018: Hanukkah (Crypto 50)

__Tags:__ `rsa`, `crt`  
__Total Points:__ 50  
__Total Solvers:__ 148  

## Problem Statement

We are given the ciphertext and the public key used as well as the implementation of the encryption.

```
ct = 66888784942083126019153811303159234927089875142104191133776750131159613684832139811204509826271372659492496969532819836891353636503721323922652625216288408158698171649305982910480306402937468863367546112783793370786163668258764837887181566893024918981141432949849964495587061024927468880779183895047695332465
pubkey = 577080346122592746450960451960811644036616146551114466727848435471345510503600476295033089858879506008659314011731832530327234404538741244932419600335200164601269385608667547863884257092161720382751699219503255979447796158029804610763137212345011761551677964560842758022253563721669200186956359020683979540809
```

### Encryption
The encryption implementation is in `Hanukkah.py`, here are the main parts:

```python
def genKey(k):
	while True:
		r=getrandbits(k)
		while(r%2):
			r=getrandbits(k)

		p =  3 * r**2 +  2 * r + 7331
		q = 17 * r**2 + 18 * r + 1339
		n = p * q

		if(isPrime(p) and isPrime(q)):
			return (p,q) , n

def encrypt(m,pubkey):
	c=m**2 % pubkey
	return c
```



## Solution

First, we have to decompose `n` into `p` and `q`. To solve this we simply solve for `r` when `pubkey` is given,

```python
pubkey = p*q
pubkey = (3 * r**2 +  2 * r + 7331)*(17 * r**2 + 18 * r + 1339)
```

We do this using `sagemath`,

```python
r = var('r')
p =  3 * r**2 +  2 * r + 7331
q = 17 * r**2 + 18 * r + 1339
n = 577080346122592746450960451960811644036616146551114466727848435471345510503600476295033089858879506008659314011731832530327234404538741244932419600335200164601269385608667547863884257092161720382751699219503255979447796158029804610763137212345011761551677964560842758022253563721669200186956359020683979540809
print(solve([p*q == n], r))
```

This gives us several answers but we are only concerned with the whole answer, and with `r` we can recover `p` and `q`

```python
r = 57998468644974352708871490365213079390068504521588799445473981772354729547806
p =  3 * r**2 +  2 * r + 7331
q = 17 * r**2 + 18 * r + 1339
```

With `p` and `q` we can get the `sqrt(ct) mod n`

```python
ct = 66888784942083126019153811303159234927089875142104191133776750131159613684832139811204509826271372659492496969532819836891353636503721323922652625216288408158698171649305982910480306402937468863367546112783793370786163668258764837887181566893024918981141432949849964495587061024927468880779183895047695332465L

ct_sqrt_p = int(Mod(ct,p).sqrt())
ct_sqrt_q = int(Mod(ct,q).sqrt())

pt = crt(-ct_sqrt_p, -ct_sqrt_q, p, q)
assert pt**2 % n == ct

from Crypto.Util.number import *
print(long_to_bytes(pt))
```

Note that here that all of the following are valid solutions but only one would result to a readable plaintext.
```python
pt = crt(ct_sqrt_p, ct_sqrt_q, p, q)
pt = crt(-ct_sqrt_p, ct_sqrt_q, p, q)
pt = crt(ct_sqrt_p, -ct_sqrt_q, p, q)
pt = crt(-ct_sqrt_p, -ct_sqrt_q, p, q)
```

This gives us the flag `X-MAS{H4nukk4h_Rabb1_and_Rab1n_l0ok_4nd_s0und_v3ry_much_alik3_H4nukk4h}`
