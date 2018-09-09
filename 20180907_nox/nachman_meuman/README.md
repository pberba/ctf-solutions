# noxCTF 2018: Nachman Meuman

__Tags:__ `misc`, `stego`  
__Total Solvers:__ 8  
__Total Points:__ 993

## Problem Statement

We are given a link and a file

https://en.wikipedia.org/wiki/Na_Nach_Nachma_Nachman_Meuman

### whereistheANSWER
```html
// SPDX-License-Identifier: GPL-2.0
/*
 * device_cgroup.c - device cgroup subsystem
 *
 * Copyright 2007 IBM Corp
 */

#include <linux/device_cgroup.h>
#include <linux/cgroup.h>
#include <linux/ctype.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>

static DEFINE_MUTEX(devcgroup_mutex);

enum devcg_behavior {
	DEVCG_DEFAULT_NONE,
	DEVCG_DEFAULT_ALLOW,
	DEVCG_DEFAULT_DENY,
};

/*
 * exception list locking rules:
 * hold devcgroup_mutex for update/read.
 * hold rcu_read_lock() for read.
 */

struct dev_exception_item {
	u32 majorZ, minorQ;
	short type;
	short access;
	struct list_head list;
	struct rcu_head rcu;
};
...
```


## Solution

We look at the file `whereistheANSWER` and after a quick look we will see a very long line starting with `ANSWER`

```
...

int __devcgroup_check_permission(short type, u32 major, u32 minor,
				 short access)
{
	struct dev_cgroup *dev_cgroup;
	bool rc;

	rcu_read_lock();
	dev_cgroup = task_devcgroup(current);
	if (dev_cgroup->behavior == DEVCG_DEFAULT_ALLOW)
		/* Can't match any of the exceptions, even partially */
		rc = !match_exception_partial(&dev_cgroup->exceptions,
					      type, major, minor, access);
	else
		/* Need to match completely one exception to be allowed */
		rc = match_exception(&dev_cgroup->exceptions, type, major,
				     minor, access);
	rcu_read_unlock();

	if (!rc)
		return -EPERM;

	return 0;
ANSWER = [0][37][2][8][244][25][50][11][2][10][244][54][244][10][9][20][78][2][513][11][78][2][20][78][54][11][35][2][37][35][2][37][2][90][52][54][78][25][9][50][97][20][2][379][90][395][2][32][34][5090][103][2][5145][244][13][52][12][2][431][33][2][5][52][12][11][12][22][11][123][17][2][128][5145][244][13][52][12][3144][1401][133][32][10][5171][33][10][52][82][150][33][2][431][123][123][2][1418][9][50][97][20][13][2][1418][11][13][11][25][44][11][17][33][35][2][37][2][90][52][54][78][25][9][50][97][20][2][379][90][395][2][32][34][5090][635][2][1418][11][17][2][4783][244][20][440][2][16][12][10][33][2][431][123][123][2][1418][9][50][97][20][13][2][1418][11][13][11][25][44][11][17][33][35][2][37][2][461][25][9][20][20][11][12][2][76][78][2][5][244][44][9][17][2][4783][52][1295][11][123][123][13][2][379][17][97][52][1295][11][123][123][13][3144][25][11][17][97][244][20][33][10][52][82][395][35][2][37][35]...
}
```

At first I thought the numbers here referred to individual characters in the wikipedia page given in the link above, which really led to nowhere. I then thought that the they might then refer to characters in the actual `whereistheANSWER` file.

This gives us another source code with a similar `ANSWER` line.

```
/* Large capacity key type
 *
 * Copyright (C) 2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2013 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "big_key: "fmt
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/file.h>
#include <linux/shmem_fs.h>
#include <linux/err.h>

...

ANSWER = [0][1][26][2][1][2][2][323][377][58][2][377][7][9][257][5][14][15][16][743][1134][56][40][4][56][9][7][69][2][3][14][56][257][79][2][43][377][1134][3][14][56][257][79][45][2][54][7][9][257][5][14][15][16][2][86][34][69][257][68][7][26][2][1][26][2][1][2][2][224][40][14][54][2][66][14][68][7][2][9][34][56][15][4][14][56][54][2][15][40][7][2][377][1134][3][14][56][257][79][2][2423][372][94][2201][2][40][34][34][18][2][66][257][56][9][15][14][34][56][2][14][86][11][68][7][86][7][56][15][4][15][14][34][56][54][59][26][2][1][26][2][1][2][2][58][257][15][40][34][5][54][506][2][2][377][7][5][6][7][2][137][4][68][68][16][56][2][71][54][7][5][6][7][40][77][257][54][59][14][179][86][59][9][34][86][87][26][2][1][854][2][2][2][2][2][2][224][5][7][56][15][2][52][4][7][6][7][5][2][71][2378][4][7][6][7][5][15][77][257][54][59][14][179][86][59][9][34][86][87][26][2][1][26][2][1][2][2][324][11][69][4]
late_initcall(big_key_init);
```

We do this recursively until we get the flag.

`noxCTF{B00kC1pher1sAw3s0m3}`

## Implementation

```python
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
```
