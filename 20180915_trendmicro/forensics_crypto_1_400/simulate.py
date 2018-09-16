m0 = set(['m0'])
m1 = set(['m1'])

m = set(['m0', 'm1'])

for i in range(10):
	temp = (m0 ^ m1) | set(['k{}'.format(i)])
	m0 = m1
	m1 = temp
	print(i, m1&m)
