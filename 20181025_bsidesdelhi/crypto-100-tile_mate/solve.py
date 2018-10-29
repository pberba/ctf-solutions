import binascii
from itertools import cycle
from hashlib import sha384

alphabet = 'abcdefghijklmnopqrstuvwxyz1234567890_{}!'

def xor(msg, key):
	return ''.join(chr(ord(m)^ord(k)) for m, k in zip(msg, cycle(key)))

def encrypt(ch):
	return sha384(ch).digest()[(ord(ch)+7)%48]

def subs_enc(msg):
	return ''.join(map(encrypt, msg))

decrypt_dict = {encrypt(e): e for e in alphabet}
def decrypt(ch):
 	return decrypt_dict.get(ch, '?')

def subs_dec(msg):
	return map(decrypt, msg)

with open('ci.pher.text') as file:
	ct = binascii.unhexlify(file.read().strip())

known = 'flag{'
known_enc = subs_enc(known)
key = xor(known_enc, ct)
ct = xor(ct, key)
print(''.join(subs_dec(ct)))
