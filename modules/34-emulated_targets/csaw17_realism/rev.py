# This script is from a solution here: https://github.com/DMArens/CTF-Writeups/blob/master/2017/CSAWQuals/reverse/realistic.py
# I basically just added comments to it

# One thing about this script, it uses z3, which uses special data types so it can solve things. As a result, we have to do some special things such as write our own absolute value function instead of using pythons built in functions.

# First import the needed libraries
from pprint import pprint
from z3 import *
import struct

# Establish the values which our input will be checked against after each of the 8 iterations
resultZ = [ (0x02df, 0x028f), (0x0290, 0x025d), (0x0209, 0x0221), (0x027b, 0x0278), (0x01f9, 0x0233), (0x025e, 0x0291), (0x0229, 0x0255), (0x0211, 0x0270) ]

# Establish the first value for the xmm5 register, which is the first 16 bytes of the elf
xmm5Z = [ [0xb8, 0x13, 0x00, 0xcd, 0x10, 0x0f, 0x20, 0xc0, 0x83, 0xe0, 0xfb, 0x83, 0xc8, 0x02, 0x0f, 0x22], ]

# Establish the solver
z = Solver()

# Establish the value `0` as a z3 integer, for later use
zero = IntVal(0)

# Establish a special absolute value function for z3 values
def abz(x):
	return If( x >= 0, x, -x)

# This function does the `psadbw` (sum of absolute differences) instruction at 0x7c96
def psadbw(xmm5, xmm2):
	x = Sum([abz(x0 - x1) for x0, x1 in zip(xmm5[:8], xmm2[:8])])
	y = Sum([abz(y0 - y1) for y0, y1 in zip(xmm5[8:], xmm2[8:])])
	return x, y

# Now we will append the values in resultZ to xmm5Z. The reason for this being while xmm5Z contains the initial value that it should have, it's value carries over to each iteration. And if we passed the check, it's starting value at each iteration after the first, should be the value that we needed to get to pass the previous check.
for i in resultZ[:-1]:
	xmm5Z.append(list(map(ord, struct.pack('<Q', i[0]) + struct.pack('<Q', i[1]))))

# Now we will establush the values that z3 has control over, which is our input. We will also add a check that each byte has to be within the Ascii range, so we can type it in. We make sure to have the string `flag` in each of the characters names so we can parse them out later
inp = [Int('flag{:02}'.format(i)) for i in range(16)]
for i in inp:
	z.add(i > 30, i < 127)

# Now we will move establish z3 data types with the previously established values in xmm5Z and resultZ. This is so we can use them with z3
xmm5z = [ [IntVal(x) for x in row] for row in xmm5Z]
results = [ [IntVal(x) for x in row] for row in resultZ]

# Now here where we run the algorithm in the loop (btw when I say registers below, I don't mean the actual ones on our computer, just the data values we use to simulate the algorithm)
for i in range(8):
	# First we set the xmm5 register to it's correct value
	xmm5 = xmm5z[i]
	# We set the xmm2 register to be out input
	xmm2 = list(inp)
	# Zero out the corresponding bytes from the andps instruction at 0x7c96
	xmm2[i] = zero
	xmm2[i + 8] = zero
	x,y = psadbw(xmm5, xmm2)
	z.add(x == results[i][0])
	z.add(y == results[i][1])

# Check if it z3 can solve the problem
if z.check() == sat:
	print "z3 can solve it"
elif z.check() == unsat:
	print "The condition isn't satisified, I would recommend crying."
	exit(0)

# Model the solution (it makes z3 come up with a solution), and then filter out the flag and convert it ASCII

model = z.model()
# Create a list to store the various inputs which meet the criteria
solutions = []

# Search for our flag values that we made on line 37, and append them to solutions
for i in model.decls():
	if 'flag' in i.name():
		solutions.append((int(i.name()[4:]), chr(model[i].as_long())))

# Sort out all of the various solutions, then join them together for the needed input
solutions = sorted(solutions, key=lambda x: x[0])
solutions = [x[1] for x in solutions]
flag = ''.join(solutions)

# Next we need to essentially undo the `pshfud` instruction which occurs at `0x7c86`, that way when we give the flag and it applies the instruction, it will have the string needed to pass the eight checks
flag = flag[12:] + flag[8:12] + flag[:8]
print "flag{}".format(flag)


