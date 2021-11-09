from hashlib import md5
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from ecdsa import ellipticcurve
from ecdsa.ecdsa import curve_256, generator_256, Public_key, Private_key
from random import randint
from os import urandom

from ecdsa.numbertheory import inverse_mod



def decryptFlag(secret_exponent, iv, flag):
    key = md5(long_to_bytes(secret_exponent)).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(flag)

order = generator_256.order()

# using output from `solution_output.txt`
ciphertext = bytes.fromhex('248005ebc638b16a0208f6c7949f1c68a147f906aa2e749985cdde5e51d230f87af2d19ec0ce1ddfb8808585dd54257bc86d456d4ca1cc8920667e792ad5c4f1')
iv = bytes.fromhex('d39a60befaeb2cb45ce8d2181371a387')
m1 = bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70')
r1 = 0x557a787642ece2fe307b7de417d7d3c7bfe92313020a58e49771be515c4cadc
s1 = 0x8d1c17fb248fb8b0af29d64365fae1b495c4eb6340ce027f9f3625564a945cda
m2 = bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70')
r2 = 0x557a787642ece2fe307b7de417d7d3c7bfe92313020a58e49771be515c4cadc
s2 = 0xda91bba782f6e63aadd53f74bd989f194664a8273d431d4e104b55e01d355296


assert r1 == r2
assert s1 != s2

h1 = bytes_to_long(m1)
h2 = bytes_to_long(m2)


r = r1

# Precomputed values for minor optimisation
r_inv = inverse_mod(r, order)
h = (h1 - h2) % order

#
# Signature is still valid whether s or -s mod curve_order (or n)
# s*k-h
# Try different possible values for "random" k until hit
for k_try in (s1 - s2,
              s1 + s2,
              -s1 - s2,
              -s1 + s2):

    # Retrieving actual k
    k = (h * inverse_mod(k_try, order)) % order


    # Secret exponent
    secexp = (((((s1 * k) % order) - h1) % order) * r_inv) % order
    print(decryptFlag(secexp, iv, ciphertext))



# b'HTB{r3u53d_n0nc35?n4h-w3_g0t_d3t3rm1n15t1c-n0nc3s!}\r\r\r\r\r\r\r\r\r\r\r\r\r'
