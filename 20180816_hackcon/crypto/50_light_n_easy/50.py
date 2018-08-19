pattern = [
	[-1, 0, 0, 0,-1,-1,-1,-1],
	[ 5,-1,-1,-1, 1,-1,-1,-1],
	[ 5,-1,-1,-1, 1,-1,-1,-1],
	[ 5,-1,-1,-1, 1,-1,-1,-1],
	[-1, 6, 6, 6,-1,-1,-1,-1],
	[ 4,-1,-1,-1, 2,-1,-1,-1],
	[ 4,-1,-1,-1, 2,-1,-1,-1],
	[ 4,-1,-1,-1, 2,-1,-1,-1],
	[-1, 3, 3, 3,-1,-1, 7,-1]
]

ans = ['' for _ in range(len(pattern))]

with open('50.txt') as f:
	codes = f.readline().strip().split('-')

for e in codes:
	for line in range(len(pattern)):
		for idx in pattern[line]:
			if idx == -1 or e[idx] == '0':
				ans[line] += ' '
			else:
				ans[line] += 'X'

	# Uncomment to prettify
	if e == '00000000':
		print('\n'.join(ans))
		ans = ['' for _ in range(len(pattern))]


print('\n'.join(ans))
