from pwn import *
from struct import unpack, pack
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from server import *

aes = AES.new(get_random_bytes(16), AES.MODE_ECB)
flag = 'flag_is{this_is_the_flag}'


def decryption_oracle(p, c):
	return p == tsb_decrypt(aes, c)

def get_flag(p, c):
	if p != tsb_decrypt(aes, c) or p != 'gimme_flag':
		raise Exception('What...')
	return tsb_encrypt(aes, flag)

def get_payload(iv_byte, block):
    iv = pack('<I', iv_byte)[0].rjust(16, '\x00')
    return (iv + xor(block, iv) + iv)

def decrypt(block):
    last_byte = 0
    for i in range(256):
        if not decryption_oracle('', get_payload(i, block)):
            last_byte ^= i

    curr = ''
    for i in range(15, 0, -1):
        for c in range(256):
            if decryption_oracle(curr + chr(c), get_payload(last_byte^i, block)):
                curr += chr(c)
                break
    return curr + chr(last_byte)


block = b'\x00'*(16)
curr = decrypt(block)
desired = 'gimme_flag'.ljust(15, ' ') + chr(6)
iv = xor(curr, desired)
payload = (iv + xor(iv, block) + iv)
flag = get_flag('gimme_flag', payload)


def __decrypt(msg):
    iv, msg = msg[:16], msg[16:]
    prev_pt = iv
    prev_ct = iv
    pt = ''
    for block in split_by(msg, 16):
        pt_block = xor(block, prev_ct)
        pt_block = decrypt(pt_block)
        pt_block = xor(pt_block, prev_pt)
        pt += pt_block
        prev_pt = pt_block
        prev_ct = block
    pt, mac = pt[:-16], pt[-16:]
    if mac != iv:
        raise CryptoError()
    return unpad(pt)

print(__decrypt(flag))
