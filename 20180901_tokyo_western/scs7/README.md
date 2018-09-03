
# Tokyo Western 2018: scs7

__Tags:__ `warmup`, `crypto`

## Problem Statement

`nc crypto.chal.ctf.westerns.tokyo 14791`

Note: You can encrypt up to 100 messages "per once connection".

This is the prompt
```
$ nc crypto.chal.ctf.westerns.tokyo 14791
encrypted flag: o5juBWPt4mS7aLkkqHe9CkWaUwzQKTqPPFpLusanyh3b3ZUTrE59EjAby0nq3E6k
You can encrypt up to 100 messages.
message:
```

Sample Input/Ouput
```
message: aaaa
ciphertext: vyCU1b
message: aaab
ciphertext: vyCU1H
message: a
ciphertext: 4R
message:
```

## Solution

If you want to know the gist of the solution, just look at the quick explanation. The rest of the writeup would simply be my approach in solving this problem. If you need code snippets for some of the parts, it'll be in the end of the writeup.

### Quick Explanation

 The encryption used is a mix of a special encoding and substitution cipher using the following steps:
 1. m1 = base59encode(m)
 2. m2 = substitution_encryption(m1, secret_mapping)


 So to decrypt you first have to figure out the mapping used for the substitution cipher and then just reverse the process.

 1. m1 = substitution_decrypt(m2, secret_mapping)
 2. flag = base59decode(m1)

### Full Explanation

Based on some trial and errors, we can see gain insight from the input and output.
```
message: aaaa
ciphertext: vyCU1b
message: aaab
ciphertext: vyCU1H
message: a
ciphertext: 4R
message:
```

#### It's an encoding

Observe the differences between `aaaa` and `aaab`.

```
aaaa => vyCU1b
aaab => vyCU1H
```

This is a clue that this is either a shift cipher, substitution cipher, or simply some encoding. One clue that can it is an encoding if that _"close"_ characters result to _"close"_ output. Here is an example below, where we see `a`, `b`, and `c` result to ciphertexts all starting with `g`.

```
message: a
ciphertext: gA
message: b
ciphertext: gX
message: c
ciphertext: g1
```

#### It's base59

We enumerate all printable ASCII characters to see if this behavior holds true or if this is a coincidence.

```
message: 0
ciphertext: m
message: 1
ciphertext: z
2message:
ciphertext: 1
3message:
ciphertext: q
message: 4
ciphertext: F

...

message: 9
ciphertext: Z
message: :
ciphertext: 3
message: ;
ciphertext: uG
message: <
ciphertext: uu

...

message: A
ciphertext: uN
message: B
ciphertext: uR
message: C
ciphertext: u7
message: D
ciphertext: uS

```

So here it is clear that it is indeed some encoding. And we observe that it is notable that __starting `;`, the ciphertext is 2 digits__.

| character | value |
| --------- | ----- |
| `:`       | 58    |
| `;`       | 59    |
| `<`       | 60    |

Since `;` is 59, then this is a clue that this is in base59, since this would be `10` in base59. This is further supported by `<`, value 60, which should be `11` in base59.

We see the mapping

| character | value | base59 | ciphertext |
| --------- | ----- | ------ | ---------- |
| `;`       | 59    | 10     | uG         |
| `<`       | 60    | 11     | uu         |


So this leads us to believe that this is __base59 encoding + substitution cipher__.  

#### Finding out the substitution

However, we see that in each run, the substitution is different.
```
message: 9
ciphertext: k
message: :
ciphertext: z
message: ;
ciphertext: AU
message: <
ciphertext: AA
```

To do this, we generate a lot of ciphertext and since we know what the plaintext _(base59 of our message)_ should be, we can figure out what the mapping is.

```
encrypted flag: ZwkbWBK6s1Juy2PPamHctPBy4hCDe5aKKEg2boyQ0UXdXz453nwcnkRd0SQaXnFP

You can encrypt up to 100 messages.
message:
OMPrEcUtniP3tKswwMLLnhCRYbIAMkS7vxycrccg
ciphertext: sjyzwT6TUwUVUZ8Xs0e7jerDy8QQR3jRdcPVedAf5dxrUMqWXkfKq8E
message: vdBPbo7JqcrsQzU8ZzwvdvKOCxFK6wh9LL6ezeYX
ciphertext: xEeEDmYjuLUobQiTnP2NkoV3m8cTJWdKsh4EDd4EgkQNuyWqfWFZYKi
message: Q09UcgkIzd9Nt0BWXrX6wFc1kTrVhJACY0EmJeXc
ciphertext: s1WeVJdKJvGpVvQWZqExHJn61LTj3KiKuDAMP0eKdRpZuQwwJm2nJcW
message: 3QFMcEPpXitmaL05OcTrE0dIBajyAtujbccupUJl
ciphertext: sqnbSkc8K3L50UDGDrHiQsCMpCpPnAgFBbrTmxYX1p8kasngcYJ7VGE
message: NXY3IDTj6eKWvUVTMBLnE0XyjTnh70BtwSK8rXeC
ciphertext: sWfLryrSXGxo3MTBMTqzA3PmmtyR8GvzRTsH7ZBxKYwM6E09mFoer5x
```

And from this information, we know enough to get the flag.

`TWCTF{67ced5346146c105075443add26fd7efd72763dd}`

### Implementation Details

#### Base59

To get the characters used in base59, generate a lot of random ciphertexts, and look at all the unique characters used.

```python
alphabet = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K',
  'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
  'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
  'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
  'v', 'w', 'x', 'y', 'z']

mapping = { ch:val for val, ch in enumerate(alphabet)}
```

##### Encoding

```python
def base59encode(msg):
	n = int(msg.encode('hex'), 16)
	ret = []
	while n > 0:
		ret.append(alphabet[n%59])
		n /= 59
	return ''.join(reversed(ret))
```

##### Decoding

```python
def base59decode(s):
	ret = 0
	for e in s:
		ret = ret*59 + mapping[e]
	return hex(ret)[2:].decode('hex')
```

##### Generate messages and expected encodings
```python
space = set()
msgs = []
expected = []

while len(space) < 59:
	msg = ''.join([random.choice(choices) for _ in range(40)])
	encoded = base59encode(msg)
	expected.append(encoded)
	space.update(set(encoded))
	msgs.append(msg)

```

#### Getting the substitution mapping

Assuming you have generated a lot of ciphertexts and you have the expected encodings.

```python
substitution = {}
for exp, act in zip(expected, actual):
	for l, r in zip(exp, act):
		substitution[r] = l
```

#### Decryption

```python
decrypted_flag = ''.join(substitution[e] for e in flag)
print(base59decode(decrypted_flag))
```
