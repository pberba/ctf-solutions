import binascii
from server import read_hex, hashtag

def write_file(file_name, data):
    with open(file_name, 'wb') as f:
        f.write(binascii.unhexlify(hex(data)[2:-1]))

desired = '75f2f2b893d1e9fb76163d279ac465f3b3eaf31f0c5abd91648717f43ec6'
desired_value = int(desired, 16)

def fix_hex(file):
    old_file_data = read_hex(file) + 'f'*120
    new_file_name = 'fixed_{}'.format(file)
    write_file(new_file_name, int(old_file_data, 16))

    curr_hash = int(hashtag(new_file_name), 16)
    fix = desired_value ^ curr_hash
    while hashtag(new_file_name) != desired:
        file_data = int(old_file_data, 16) ^ fix
        write_file(new_file_name, file_data)
        fix = fix<<4

fix_hex('ls.jpg')
fix_hex('flag.jpg')
