mod = 3524587069
m = [[] for _ in range(50)]
y = []
with open('files/mod_3524587069.txt') as f:
	for idx, line in enumerate(f.readlines()):
		i, res = line.split()
		for e in range(50):
			m[idx].append(pow(int(i), e, mod))
		y.append(int(res))

y = vector(y)
M = Matrix(Integers(mod), m)
solution = M.solve_right(y)
print(''.join([chr(e) for e in reversed(solution)]))
