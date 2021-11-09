from Crypto.Cipher import AES
import random
import time
import base64
from Crypto.Util.number import bytes_to_long, long_to_bytes

BIT_SIZE = 256
BYTE_SIZE = 32

def pad(payload, block_size=BYTE_SIZE):
    length = block_size - (len(payload) % block_size)
    return payload + chr(length) * length

def keygen():
    random.seed(BYTE_SIZE)
    h = random.getrandbits(BIT_SIZE)
    print(h)	
    for i in range(BIT_SIZE):
        random.seed(time.time())
        h = h ^ random.getrandbits(2*BIT_SIZE//BYTE_SIZE)
        print(h)
    return h


random.seed(BYTE_SIZE)
key = random.getrandbits(BIT_SIZE)

key_low = key - (key % (1<<16))
key_high = key_low + (1<<16)



ct = {}
for day in [52, 53, 54, 55]:
    for s1 in ['Insecure', 'Secure']:
        for s2 in ['Insecure', 'Secure']:
            for s3 in ['Insecure', 'Secure']:
                for s4 in ['Insecure', 'Secure']:
                    for prefix in ['', '\n']:
                       for suffix in ['', '\n']: 
                        msg = f"""\
{prefix}Report Day {day}:
    Mainframe: {s1}
    Main Control Unit: {s2}
    Internal Network: {s3}
    Cryptographic Protocols: {s4}
    {suffix}"""
                        msg = pad(msg).encode()
                        for k1 in range(key_low, key_high):
                            cipher = AES.new(long_to_bytes(k1), mode=AES.MODE_ECB)
                            _ct = cipher.encrypt(msg)
                            ct[_ct] = k1



with open('files/packet_6.txt.enc') as f:
    msg_ct = base64.b64decode(f.read())

for k2 in range(key_low, key_high):
    cipher = AES.new(long_to_bytes(k2), mode=AES.MODE_ECB)
    _ct = cipher.decrypt(msg_ct)
    if _ct in ct:
        print(ct[_ct], k2)
        k1 = ct[_ct]
        k2 = k2
        break

k1, k2 = 27534775351079738483622454743638381042593424795345717535038924797978770229648, 27534775351079738483622454743638381042593424795345717535038924797978770265131


with open('files/flag.txt.enc') as f:
    ciphertext = base64.b64decode(f.read())

p1 = AES.new(long_to_bytes(k2), mode=AES.MODE_ECB).decrypt(ciphertext)
p2 = AES.new(long_to_bytes(k1), mode=AES.MODE_ECB).decrypt(p1)

print(p2)

# HTB{_B4D_EncryPt!on_M1tM_4tt4ck_}