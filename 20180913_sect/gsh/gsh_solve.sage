def get_bits(n):
	ret = []
	for i in range(128):
		ret.append(n%2)
		n = n >> 1
	return ret

labels = []
m = [[] for _ in range(128)]

with open('samples.txt') as f:
	samples = f.readlines()
	for line in samples:
		b, h = line.split(',')
		h_val = int(h, 0x10)
		for idx, v in enumerate(get_bits(h_val)):
			m[idx].append(v)
		labels.append(b)

desired = 'ec10d43e1badbd1c9838e1020d365fc0' # admin_hash ^ key_hash
M = Matrix(Integers(2), m)
y = vector(get_bits(int(desired, 0x10)))
solution = M.solve_right(y)
ans = []
for idx, v in enumerate(solution):
	if v != 1:
		continue
	ans.append(labels[idx])

print(''.join(ans))
