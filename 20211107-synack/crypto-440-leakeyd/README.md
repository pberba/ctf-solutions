
#### leaky (440 points, 44 solves)

##### Problem

You are given the following source code

```python
from Crypto.Util.number import getPrime, bytes_to_long
from math import gcd

flag = open("flag.txt").read().strip().encode()

p = getPrime(1024)
q = getPrime(1024)
n = p * q
e1 = 0x10001
e2 = 0x13369

print(e1, e2)


assert gcd(p-1,e1) == 1 and gcd(q-1, e1) == 1 and gcd(p-1,e2) == 1 and gcd(q-1, e2) == 1

phi = (p-1) * (q-1)
d1 = pow(e1, -1, phi)
print(f"""Retrieved agent data:
n = {n}
e = {e1}
d = {d1}""")


ct = pow(bytes_to_long(flag), e2, n)
print(f"""Spy messages: 
e = {e2}
ct = {ct}""")
```

And the output of this message. 

```
Retrieved agent data:
n = 13382530295713917123015356265347321094256226566257623545889573061147938007171086142592829334764528434702825531635566369283255332692678671260069812638573184350572810970644394853227367978599113205187410151008372135364394060295976954722797560959041525038250922497629995447141186387045145641624575553004116393538045115640382007521177506372844356599515221123769808759792921557288910541261662071330605482964244218808384883839567178211155363863011452476524600201011039875767940325127282609196357565459539854467622590648672354346990722180911082058098493886116049202007545709584770864598362673608862923836981014279206273097017
e = 65537
d = 11569455444932772576648367415079245594982518040054082958680004127416877055866142769229969703359760929755598958930190874633423572023464427060332872186341753191857337442586174582207855332582641194737450361411604871225045984226459287130693565601375936121842940123452710408534497128602222588204605057938374149336484991344046184969452360503325068483025278799356513681880021469192847751113510298088839230617951595758843109007278029595681232283778797485901135862107038739149351060518772094867682593519162349240597142862357240797932956424470777291496596508787661226345849862222655652073745922761860271975329314656555016312713
Spy messages:
e = 78697
ct = 4461852328415864419743101452420387961651156933673863713694420947402421429869721670364426655092362407263142072234174378248471219392117855386367222894744130407609532370830178750575600387702022233241268782964579737764081573978397550577590335855096601816184948403341545535505335757184765869011562485472974997984468216491217981788679749360213892759733091674873206632032015518889157979003123181968736952658371579666643477038906444823824649861271863876401740198790710014620615022343576676868923683803704170440327497263852960257492740456717562069360762813846260931117680928543379201453514283942164106220549947266176556883803
```
##### Solution

For this, we have two RSA keys, `K1` and `K2` that have a common modulo `N`. We are given the private key of `K1` through the value of `d1` 

```python
d1 = pow(e1, -1, phi) # private key of K1 
```

It is important to realize that if you have the value of `e1`, `d1`, and `N`, it is enough to help you factorize `N` into `p` and `q`.  Of course, with `p` and `q`, finding the private key of `K2` (which also uses the same `N`, `p` and `q`) should be trivial.

If you do not know how to do this, you would need to google something like "RSA Prime Factorization with Private Key" which leads you to a [stackexchange forum post](https://math.stackexchange.com/questions/634862/rsa-prime-factorization-for-known-public-and-private-key). 


##### Review of RSA

Recall these three fundamental equations from RSA


```
N = pq  	             (1)
(p-1)(q-1) = phi	     (2)  
d1 =  e1^(-1)   mod phi  (3) 
```


We express `(3)` as equality with some integer `k`

```
d1 * e1 = 1      mod phi
d1 * e1 - 1 =   k*phi
(d1 * e1 - 1)/phi   =   k   (4)
```


How do we find `k` if `phi` is unknown? Well we know that since `p` and `q` are large, then


```
(p-1)(q-1) \approx p * q
phi \approx N
```
Therefore we can approximate k from `(4)` using `N`, which we know,

```
(d1 * e1 - 1)/N   approx   k  
```
Since `phi < N` then `K`, and if `N` is large enough, then K is most probably `ceil(d_1 * e_1 - 1 / N)`.


In python, we can find this using

```python
k = (e1*d1) // n + 1
assert (e1 * d1 - 1) % k == 0 # To check that we are correct
```


Now that we have `K`, `N`, `e1` and `e2`, we have a system of two equations with only two unknowns, `p` and `q`.


```
N = pq
d1 * e1 - 1 =   k * (p-1) * (q-1)
```

Two equations and two unknowns? This is high school algebra.

Here are some of my scratch notes from this
```python
# First we find (p+q)
e1*d1 = (p-1)*(q-1) * k + 1
(e1 * d1 - 1) / k = (p-1)*(q-1)
(e1 * d1 - 1) / k = p*q - q - p + 1
(e1 * d1 - 1) / k = N - q - p + 1
(e1 * d1 - 1) / k - 1 - N  = - q - p
p + q = N + 1 - (e1 * d1 - 1) / k  = X

# Then we use isolate `p and substitute it in N = pq
p = X - q
n = q * (X - q)
0 = X*q - q*q - n
q*q - X*q + n = 0

# Quadratic equation
```
The python code to compute this is

```python
X = n + 1 - (e1*d1 - 1) // k
a = 1
b = X
c = n
p = -(-b + gmpy2.isqrt(b**2 - 4*a*c)) // (2*a)
q = n // p

# Always sense check values 
assert n % p == 0
assert (p*q) == n 
assert isPrime(p) 
assert isPrime(q)
```

With `p` and `q` you should be able to find the private key of `k2` and decrypt the flag.

##### Full Solution

```python
import gmpy2
from math import gcd

from Crypto.Util.number import isPrime, long_to_bytes, inverse

n = 13382530...
e1 = 65537
d1 = 115694...
e2 = 78697
ct = 4461852...

# Step 0 find k
k = (e1*d1) // n + 1
assert (e1 * d1 - 1) % k == 0

# Step 1 find p and q
X = n + 1 - (e1*d1 - 1) // k
a = 1
b = X
c = n
p = -(-b + gmpy2.isqrt(b**2 - 4*a*c)) // (2*a)
q = n // p


assert n % p == 0
assert (p*q) == n 
assert isPrime(p) 
assert isPrime(q)

# Step 2 decrypt flag
phi = (p-1)*(q-1)
pt = pow(ct, d2, n)
print(long_to_bytes(pt))


# HTB{tw4s_4-b3d_1d34_t0_us3-th4t_m0dulu5_4g41n-w45nt_1t...}
```