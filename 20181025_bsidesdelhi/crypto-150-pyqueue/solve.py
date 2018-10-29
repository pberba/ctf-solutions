from Crypto.Cipher import AES
from Crypto.Util.number import *
from crypto_commons.generic import is_printable


def unpad(msg):
    padding = ord(msg[-1])
    if padding > 16:
        return msg
    return msg[:-padding]

def brute_force(key, ct):
    for i in range(256):
        temp_key = chr(i) + key[:-1] # Guess the first byte of the key
        cipher = AES.new(temp_key, AES.MODE_ECB)
        plain = unpad(cipher.decrypt(long_to_bytes(ct)))
        if is_printable(plain) and plain:
            return temp_key, plain
    return key, None


with open('ci.pher.text', 'r') as f:
    mac, ct = f.read().strip().split(':')

mac = int(mac)
ct = [int(ct[i:i+2*AES.block_size], 16) for i in range(0, len(ct), 2*AES.block_size)]
ct_mac = reduce(lambda x, y: x^y, ct)
key = long_to_bytes(mac ^ ct_mac)

flag = ''
for e in reversed(ct):
    key, pt = brute_force(key, e)
    flag = pt + flag

print flag
