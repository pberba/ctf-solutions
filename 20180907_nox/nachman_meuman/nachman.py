def get_answer(code):
	answer_line = None
	for e in code.split('\n'):
		if 'ANSWER' in e:
			answer_line = e
			break

	answer_line = answer_line.replace('[', '\n')
	answer_line = answer_line.replace(']', '\n')

	l = []
	for e in answer_line.split('\n'):
		try:
			l.append(int(e))
		except Exception:
			pass
	return l

def find_answer(code, ans):
	return ''.join(code[i] for i in ans)


with open('whereistheANSWER') as f:
	code = f.read()


while 'nox' not in code:
	ans = get_answer(code)
	code = find_answer(code, ans)
	print(code)
	print('-------------------------')
