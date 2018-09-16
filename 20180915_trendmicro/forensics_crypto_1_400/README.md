# Trendmicro 2018: Forensics Crypto 400

__Tags:__ `crypto`, `xor`  
__Total Points:__ 400

## Problem Statement

Cryptography is an important part of modern-day computer security. If encryption is broken, then there is no security in the world that will keep you safe! From bitcoin to banking, strong cryptography keeps data safe and protected from prying eyes on the network. Though encryption standards have gotten stronger over time, they weren't always so protective. Did you know that some cryptography algorithms can be broken by hand? Certain implementations of the Feistel cipher (a class of block ciphers which includes DES) fall into this unfortunate category.

The encryption algorithm for a Feistel cipher is as follows:

Feistel ciphers are a class of block ciphers with parameters n (half the block length), h (the number of rounds), and l (the key size). Then M = {0,1}2n (the plaintext space), C = {0,1}2n (the ciphertext space), and K = {0,1}l (the key space). A key scheduling algorithm determines subkeys k1,k2,⋯,kh from a key k. Each subkey ki determines a function fi {0,1}n ? {0,1}n.

Encryption takes h rounds:

Plaintext is: m = (m0,m1), where (m0,m1) ? {0,1}n

Round 1: (m0,m1) ? (m1,m2) where m2 = m0 XOR f1(m1 )

Round 2: (m1,m2) ? (m2,m3) where m3 = m1 XOR f2(m2 )

.........

Round h: (mh-1,mh) ? (mh,mh+1) where mh+1 = mh-1 XOR fh(mh )

The ciphertext is c = (mh,mh+1).

For this problem, the function f is defined as: fi (x) = x XOR ki
The Challenge:

You've been hired to help intercept the communications of the Malicious Advanced Threat group (MAT). Your team has gained one plaintext/ciphertext pair, and they need you to use it to decrypt an important message just received from MAT. Fortunately, MAT was not very careful about the encryption they used! You've decided that the encryption falls under the category of a Feistel cipher (described above). Note that n = 144 and l = 288. You are not given h, the number of rounds of the cipher, but given poor choice of encryption implemented here you're guessing it's low.

Your plan of attack is to find the key using the plaintext/ciphertext pair you already have and then use that key to decrypt the secret message you've gained. Good luck!

(Note that the secret message will be in binary when you decrypt it. You may want to translate that to an ASCII string to make the decrypted message human-readable.)
Download the file

### Plaintext-Ciphertext Pair
```
Plaintext: 010000010110111000100000011000010111000001110000011011000110010100100000011000010110111001100100001000000110000101101110001000000110111101110010011000010110111001100111011001010010000001110111011001010110111001110100001000000111010001101111001000000101010001110010011001010110111001100100

Ciphertext: 000100100011000101110101001101100110001100110001001110100011110101100000011110010010111000110011001110000000110100100101011111000011000000100001010000100110011100100001011000000111001101110100011011100110000000100000011011010110001001100100001011010110111001100110001010110110110101110001
```

### Secret message
```
Secret Message:
000000110000111001011100001000000001100100101100000100100111111000001001000001100000001100001001000100100010011101001010011000010111100100100010010101110100010001000010010101010100010101111111010001000110000001101001011111110111100001100101011000010010001001001011011000100111001001101011
```

## Solution

So to be able to quickly see the relationship between the plaintext and the ciphertext, we simulate the encryption.

```python
m0 = set(['m0'])
m1 = set(['m1'])

for i in range(10):
	temp = (m0 ^ m1) | set(['k{}'.format(i)])
	m0 = m1
	m1 = temp
	print(i, m1)
```

And we get the following output

```
0 {'m0', 'm1', 'k0'}
1 {'k1', 'm0', 'k0'}
2 {'k2', 'k1', 'm1'}
3 {'k3', 'm1', 'k0', 'k2', 'm0'}
4 {'k3', 'k4', 'k0', 'k1', 'm0'}
5 {'k5', 'm1', 'k4', 'k2', 'k1'}
6 {'k5', 'm1', 'k3', 'k0', 'k6', 'k2', 'm0'}
7 {'k3', 'k4', 'k6', 'k0', 'k1', 'm0', 'k7'}
8 {'k5', 'm1', 'k4', 'k8', 'k2', 'k1', 'k7'}
9 {'m1', 'k6', 'k8', 'k0', 'k2', 'm0', 'k3', 'k5', 'k9'}
```

So in this case, our cipher text will just be

```
c0 = m1 ^ (k5 ^ k4 ^ k8 ^ k2 ^ k1 ^ k7)
c1 = m0 ^ m1 ^ (k6 ^ k8 ^ k0 ^ k2 ^ k3 ^ k5 ^ k9)

Let
final_key0 = (k5 ^ k4 ^ k8 ^ k2 ^ k1 ^ k7)
final_key1 = (k6 ^ k8 ^ k0 ^ k2 ^ k3 ^ k5 ^ k9)

c0 = m1 ^ final_key0
c1 = m0 ^ m1 ^ final_key1
```

So that means we can easily get the final_keys from the plaintext and Ciphertext
```
final_key0 = c0 ^ m1
final_key1 = c1 ^ m1 ^ m0
```

And we can use this final_keys to get the flag from the secret key

```
secret_0 = flag_1 ^ final_key0
secret_1 = flag_0 ^ flag_1 ^ final_key1

flag_1 = secret_0 ^ final_key0
flag_0 = secret_key ^ final_key1 ^ flag_1
```

Although this is only true if you have `H = 10`. Depending on what H, the the relationship between the plaintext, ciphertext and final_keys changes slightly. There are actually 3 forms which you can try all 3 to get the flag.

```
secret_0 = flag_1 ^ final_key0
secret_1 = flag_0 ^ flag_1 ^ final_key^1

secret_0 = flag_0 ^ final_key0
secret_1 = flag_1 ^ final_key^1

secret_0 = flag_0 ^ flag_1 ^ final_key0
secret_1 = flag_0 ^ final_key^1
```

And eventually you'll get the flag `# TMCTF{Feistel-Cipher-Flag-TMCTF2018}`

## Implementations

```python
from  crypto_commons.generic import long_to_bytes
n = 144

p_str = '010000010110111000100000011000010111000001110000011011000110010100100000011000010110111001100100001000000110000101101110001000000110111101110010011000010110111001100111011001010010000001110111011001010110111001110100001000000111010001101111001000000101010001110010011001010110111001100100'
c_str = '000100100011000101110101001101100110001100110001001110100011110101100000011110010010111000110011001110000000110100100101011111000011000000100001010000100110011100100001011000000111001101110100011011100110000000100000011011010110001001100100001011010110111001100110001010110110110101110001'
p_m0 = int(p_str[:n], 2)
p_m1 = int(p_str[n:], 2)
p = [p_m0, p_m1]

c_m0 = int(c_str[:n], 2)
c_m1 = int(c_str[n:], 2)

s_str = '000000110000111001011100001000000001100100101100000100100111111000001001000001100000001100001001000100100010011101001010011000010111100100100010010101110100010001000010010101010100010101111111010001000110000001101001011111110111100001100101011000010010001001001011011000100111001001101011'

s_m0 = int(s_str[:n], 2)
s_m1 = int(s_str[n:], 2)


def decrypt(m0, m1):
	k0 = c_m0
	for e in m0:
		k0 ^= p[e]

	k1 = c_m1
	for e in m1:
		k1 ^= p[e]

	d_m0 = s_m0^k0
	d_m1 = s_m1^k1

	if len(m0) == 2:
		d_m0 ^= d_m1
	if len(m1) == 2:
		d_m1 ^= d_m0


	print(long_to_bytes(d_m0), long_to_bytes(d_m1))

decrypt([0,1],[0])
decrypt([0],[1])
decrypt([1],[0,1])

# TMCTF{Feistel-Cipher-Flag-TMCTF2018}
```
