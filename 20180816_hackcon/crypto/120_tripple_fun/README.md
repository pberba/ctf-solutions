# HackCon2018: Crypto 120 - Tripple FUN

## Problem Statement

You thought DES wasn't safe? How about thrice the fun? Is that safe enough for ya? Eh?

Break this ciphertext  
__Ciphertext:__

```
|\xb3Wm\x83\rE7h\xe3\xc0\xf1^Y\xf0\x8d\xa6I\x92\x9b\xa5\xbc\xdc\xca\x9d\xcd\xe9a0\xa3\x00\xf2\x13\x16]|\xae\xd8\x84\x88
```
### File

__Source Code:__ `trippleFUN.py`

## Solution

### Explanation

If we look at the code found in `trippleFUN.py`, we see how the flag was encrypted.

```python
...
print(str(calendar.timegm(time.gmtime())))
if __name__ == '__main__':
	IV = str(calendar.timegm(time.gmtime()))[-8:]
	message= "######  redacted  ######"
	d = des()
	r = d.encrypt(IV,d.encrypt(IV,d.encrypt(IV,message)))
	print ("Ciphered: %r" % r)

```

Notice that the key used the encrypted is based on the current timestamp of the system during encrypted, which is _not random_. This reduces our search space to the time range which we think the flag was encrypted, and since _DES_ is a symmetric encryption algorithm, if we know the key used to encrypt, we also know the key to decrypt.

Thankfully the code provided also has an option to decrypt although there is not explicit function for it. We look at the `des.encrypt()` function to see how to decrypt.

```python
...
ENCRYPT=1
DECRYPT=0
class des():
    ...
    def encrypt(self, key, text, padding=False):
        return self.run(key, text, ENCRYPT, padding)
...
```

### Full solution

```python
import calendar
import time

from trippleFUN import des, DECRYPT

d = des()
def decrypt(key, text):
	return d.run(key, text, DECRYPT)

curr_IV = calendar.timegm(time.gmtime())

message= "|\xb3Wm\x83\rE7h\xe3\xc0\xf1^Y\xf0\x8d\xa6I\x92\x9b\xa5\xbc\xdc\xca\x9d\xcd\xe9a0\xa3\x00\xf2\x13\x16]|\xae\xd8\x84\x88"
while True:
	curr_IV -= 1
	IV = str(curr_IV)[-8:]
	plain = decrypt(IV,decrypt(IV,decrypt(IV,message)))
	if 'd4rk' in plain:
		print(plain)
		break
```


### Output

```raw
d4rk{0h_lol_t1m3_i5_n0t_A_g00d_s33d}c0de
```

## Answer

```
d4rk{0h_lol_t1m3_i5_n0t_A_g00d_s33d}c0de
```

----------------------------------------------------------

## Other Notes

I guess another (more cumbersome) way to attack this is to analyze the implementation of the encryption itself. Although I didn't look at the implementation of encryption, I don't think it is DES or, at least, a proper implementation of DES.  

Here are some other valid keys to decrypt the flag which shows that it's not good encryption.

```
34555973
34555972
34555963
34555962
34555873
34555872
34555863
34555862
34554973
34554972
34554963
34554962
34554873
34554872
34554863
34554862
```

And also...

```
35554973
35544973
35454973
35444973
34554973
34544973
```
