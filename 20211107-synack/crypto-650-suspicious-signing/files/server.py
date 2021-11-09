from hashlib import md5
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from ecdsa import ellipticcurve
from ecdsa.ecdsa import curve_256, generator_256, Public_key, Private_key
from random import randint
from os import urandom

flag = open("flag.txt").read().strip().encode()
G = generator_256
order = G.order()

def genKey():
    d = randint(1,order-1)
    pubkey = Public_key(G, d*G)
    privkey = Private_key(pubkey, d)
    return pubkey, privkey
    
def ecdsa_sign(msg, privkey):
    hsh = md5(msg).digest()
    nonce = md5(hsh + long_to_bytes(privkey.secret_multiplier)).digest() * 2
    sig = privkey.sign(bytes_to_long(msg), bytes_to_long(nonce))
    return msg, sig.r, sig.s

def encryptFlag(privkey, flag):
    key = md5(long_to_bytes(privkey.secret_multiplier)).digest()
    iv = urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(flag, 16))
    return ciphertext, iv
    
pubkey, privkey = genKey()
ct, iv = encryptFlag(privkey, flag)
print(f"""Encrypted flag: {ct.hex()}
iv: {iv.hex()}""")
while True:
    msg = input("Enter your message in hex: ")
    try:
        msg = bytes.fromhex(msg)
        m, r, s = ecdsa_sign(msg, privkey)
        print(f"""Message: {m.hex()}
r: {hex(r)}
s: {hex(s)}""")
    except:
      print("An error occured when trying to sign your message.")
