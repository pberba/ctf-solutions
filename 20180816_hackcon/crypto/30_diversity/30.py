with open('30.txt') as message:
	codes = message.readline().split()

ans = [int('0{}'.format(e), 0) if e[0] != 'd' else int(e[1:]) for e in codes]
ans = [chr(e) for e in ans]
print(''.join(ans))
