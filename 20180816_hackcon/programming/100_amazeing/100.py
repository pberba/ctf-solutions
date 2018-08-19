from Queue import Queue
from pwn import *
from scipy import misc

dx = [0, 1, 0, -1]
dy = [1, 0, -1, 0]
cmd = ['S', 'D', 'W', 'A']

def fetch_image(r):
	image_delimiter = 'INVALID\n'
	image = ''
	try:
		# image = r.recvuntil(image_delimiter)
		while image_delimiter not in image:
			image += r.recv()
	except:
		print(image)
		return

	while image[1] != 'P':
		image = image[1:]

	with open('100.png', 'wb') as f:
		f.write(image)

def solve():
	maze = misc.imread('100.png')

	width, height, _ = maze.shape

	cell_width = 10
	width /= cell_width
	height /= cell_width
	bitmap = [[1 if (maze[x*cell_width][y*cell_width][0] == 0) else 0 for x in range(width)] for y in range(height)]

	flag = {}
	prev_move = {}
	prev_move[(0,0)] = -1

	q = Queue()
	q.put((0, 0))

	while(not q.empty()):
		x, y = q.get()
		for d in range(4):
			_x = x + dx[d]
			_y = y + dy[d]
			if min(_x, _y) < 0 or _x >= width or _y >= height:
				continue
			if _x == width-1 and _y == height-1:
				flag[(_x, _y)] = d
			if bitmap[_x][_y]:
				continue
			if (_x, _y) in flag:
				continue
			flag[(_x, _y)] = d
			q.put((_x, _y))

	ans = []
	x = width-1
	y = height-1
	if (x,y) not in flag:
		return 'INVALID'
	else:
		while(max(x, y) > 0):
			d = flag[(x,y)]
			ans.append(cmd[d])
			x -= dx[d]
			y -= dy[d]
		ans.reverse()
		return ''.join(ans)


r = remote('139.59.30.165', 9300)
r.recvuntil('Enter)\n')
r.send('\n')

while True:
	fetch_image(r)
	r.send('{}\n'.format(solve()))
	res = r.recvline()

r.close()
