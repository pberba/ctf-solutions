# SECT CTF 2018: Matry0ska1

__Tags:__ `crypto`, `DLP`  
__Total Solvers:__ 56  
__Total Points:__ 51

## Problem Statement

 Discrete logarithms are hard...

`nc crypto.sect.ctf.rocks 4444`

```
$ nc crypto.sect.ctf.rocks 4444
    _   
  (("))  --- Gimme exponent pl0x
  /   \
 ( (@) )
 \__(__/


p = 122488473105892538559311426995019720049507640328167439356838797108079051563759027212419257414247
g = 2
g^x = 45511628738793634419255680339818484784808546407927908118456437631905223202407320167681187413557
:
```

## Solution

### Quick Explanation

This is a DLP problem where the modulo N is fully factorizable.

Fairly new to `SageMath` so I thought I needed to do some things manually. After solving the problem, I revisited it then realized that you can simply use `SageMath`'s  `discrete_log` function and will the most of the stuff that will be discussed in the full solution for you.

```python
p = 122488473105892538559311426995019720049507640328167439356838797108079051563759027212419257414247
g = 2
h = 41265478705979402454324352217321371405801956976004231887598587967923553448391717998290661984177

R = IntegerModRing(p)
x = discrete_log(R(h), R(g))

print(x)
```

### Long Solution


I got the full factorization from [factordb](http://factordb.com/index.php?query=122488473105892538559311426995019720049507640328167439356838797108079051563759027212419257414247)

Solving for
```
h = g^x mod N
N = p1 * p2 * p3 * p4...
```

Then the following is also true
```
h = g^x = g^x1 mod p1
h = g^x = g^x2 mod p2
h = g^x = g^x3 mod p3
h = g^x = g^x4 mod p4
...
```

This is easier to solve. We then know from [Fermat's Little Theorem](https://en.wikipedia.org/wiki/Fermat%27s_little_theorem) that the following is also true
```
x = x1 mod p1-1
x = x2 mod p2-1
x = x3 mod p3-1
...
```

And this is solvable using the [Chinese Remainder Theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem).

Input this and you will get the flag: `SECT{Ru$$ian_D0LLZ_h0lDs_TH3_S3cR3T}`

## Implementation


```python
_p = 122488473105892538559311426995019720049507640328167439356838797108079051563759027212419257414247
g = 2
_h = 41265478705979402454324352217321371405801956976004231887598587967923553448391717998290661984177

p_factors = [6971096459, 261841354058939, 9293011496905768559, 336286207038529046808347, 21472883178031195225853317139]

def dlog(p):
	g = 2
	h = _h % p
	R = IntegerModRing(p)
	x = discrete_log(R(h), R(g))
	return x

X = []
MOD = []

for p in p_factors:
    x = dlog(p)
    assert pow(g, x, p) == _h%p
    X.append(x)
    MOD.append(p-1)

x = crt(X, MOD)
assert pow(g, x, _p) == _h
print(x)
```
