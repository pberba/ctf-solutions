# HackCon2018: Crypto 50 - Light N' Easy

## Problem Statement

My DIM-WIT no good half-brother gave me this binary text. Lead the way and help me show him who the B055 is.  

Note: enclose the flag in d4rk{}c0de before submitting.

```
01001110-00100000-00111010-00001100-11011110-00011110-00000000-01100000-00101010-01111010-00100000-11110110-00111010-00000000-11111110-00001100-00111000-11011110-00000000-10111100-00001010-11011110-11011110-00101010-00000000-01110110-11011110-00001100-00001100-00111010-01010110-00000000-11111100-00001010-11111010-00101010-11110110-11011110-00000000-11101110-11011110-01111011-00000000-10001110-00001100-11111010-11110110-00000000-00100000-10110110-00000000-00011101-10011111-01111011-10110111-11111110-00001010-00100000-00101010-11110111-01111000-00111010-01100111-10001100-00111011-10101010-11011110
```
### Hint
![hint](hint.jpg)

## Solution

### Explanation

This is an encoding of the 7-segment display.

![7-segment-display](https://www.electronics-tutorials.ws/wp-content/uploads/2013/10/segment4.gif)

And we simply have to map the bits to the display. So I wrote a little script to interpret each code to an ASCII 7-segment display.

### Full solution

```python
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
	# if e == '00000000':
		# print('\n'.join(ans))
		# ans = ['' for _ in range(len(pattern))]


print('\n'.join(ans))
```

### Output

```raw
                                 XXX                    
X   X                   X       X   X   X               
X   X                   X       X   X   X               
X   X                   X       X   X   X               
 XXX             XXX             XXX     XXX            
X           X   X   X   X       X       X               
X           X   X   X   X       X       X               
X           X   X   X   X       X       X               
                 XXX             XXX     XXX            

                                 XXX                    
    X               X           X   X                   
    X               X           X   X                   
    X               X           X   X                   
         XXX     XXX             XXX     XXX            
    X   X   X   X   X       X       X   X   X           
    X   X   X   X   X       X       X   X   X           
    X   X   X   X   X       X       X   X   X           
                 XXX             XXX     XXX            

 XXX                     XXX            
X   X   X               X   X           
X   X   X               X   X           
X   X   X               X   X           
 XXX                     XXX            
X   X   X       X   X   X               
X   X   X       X   X   X               
X   X   X       X   X   X               
 XXX             XXX     XXX            

 XXX             XXX     XXX                    
X               X   X   X   X                   
X               X   X   X   X                   
X               X   X   X   X                   
         XXX     XXX     XXX     XXX            
X   X   X       X       X       X   X           
X   X   X       X       X       X   X           
X   X   X       X       X       X   X           
 XXX             XXX     XXX                    

         XXX                                            
X   X   X   X   X       X               X   X           
X   X   X   X   X       X               X   X           
X   X   X   X   X       X               X   X           
 XXX     XXX                     XXX     XXX            
    X   X       X       X       X   X                   
    X   X       X       X       X   X                   
    X   X       X       X       X   X                   
 XXX     XXX                     XXX     XXX            

 XXX             XXX             XXX     XXX            
X   X               X           X   X   X   X           
X   X               X           X   X   X   X           
X   X               X           X   X   X   X           
         XXX     XXX     XXX     XXX     XXX            
X   X   X       X   X   X   X       X   X               
X   X   X       X   X   X   X       X   X               
X   X   X       X   X   X   X       X   X               
 XXX             XXX             XXX     XXX            

 XXX     XXX                    
X   X   X   X       X           
X   X   X   X       X           
X   X   X   X       X           
 XXX     XXX     XXX            
X   X   X       X   X           
X   X   X       X   X           
X   X   X       X   X           
         XXX     XXX  X         

 XXX             XXX     XXX            
X       X           X   X   X           
X       X           X   X   X           
X       X           X   X   X           
 XXX             XXX     XXX            
X       X       X   X       X           
X       X       X   X       X           
X       X       X   X       X           
                 XXX     XXX            

         XXX            
        X               
        X               
        X               
         XXX            
    X       X           
    X       X           
    X       X           
         XXX            

         XXX             XXX     XXX                             XXX                             XXX             XXX     XXX    
X       X           X   X       X   X                           X   X       X           X   X   X                       X   X   
X       X           X   X       X   X                           X   X       X           X   X   X                       X   X   
X       X           X   X       X   X                           X   X       X           X   X   X                       X   X   
         XXX     XXX     XXX     XXX     XXX             XXX     XXX             XXX     XXX             XXX     XXX     XXX    
X       X       X   X       X   X   X   X           X   X   X       X   X   X   X   X       X   X       X   X   X   X   X       
X       X       X   X       X   X   X   X           X   X   X       X   X   X   X   X       X   X       X   X   X   X   X       
X       X       X   X       X   X   X   X           X   X   X       X   X   X   X   X       X   X       X   X   X   X   X       
 XXX  X  XXX  X  XXX  X  XXX  X  XXX                             XXX  X  XXX     XXX          X          XXX  X          XXX    
```

## Answer

```
d4rk{L.E.d.s.Bring.Joy.To.me}c0de
```
