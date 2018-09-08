from paddingoracle import BadPaddingException, PaddingOracle
from pwn import *

r = remote('chal.noxale.com', 3141)

with open('Encrypted.txt', 'rb') as f:
    data = f.read()

iv = data[:16]
cipher = data[16:]

class PadBuster(PaddingOracle):
    def __init__(self, **kwargs):
        super(PadBuster, self).__init__(**kwargs)

    def oracle(self, data, **kwargs):
        r.send(bytes(48))
        r.send(iv+data)
        if r.recv(1) == '0':
            raise BadPaddingException

padbuster = PadBuster()
value = padbuster.decrypt(cipher, block_size=16, iv=iv)
print('Decrypted: %r' % (value))

# noxCTF{0n3_p4d_2_f4r}
