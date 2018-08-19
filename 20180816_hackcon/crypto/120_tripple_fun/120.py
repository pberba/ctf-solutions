import calendar
import time

from trippleFUN import des, DECRYPT

d = des()
def decrypt(key, text):
	return d.run(key, text, DECRYPT)

# Friday, August 17, 2018 12:00:00 AM
curr_IV = 1534464000

message= "|\xb3Wm\x83\rE7h\xe3\xc0\xf1^Y\xf0\x8d\xa6I\x92\x9b\xa5\xbc\xdc\xca\x9d\xcd\xe9a0\xa3\x00\xf2\x13\x16]|\xae\xd8\x84\x88"
while True:
	curr_IV -= 1
	IV = str(curr_IV)[-8:]

	plain = decrypt(IV,decrypt(IV,decrypt(IV,message)))
	if 'd4rk' in plain:
		print(plain)
		break
