from z3 import *

# Designate the desired output
desiredOutput = [0x69, 0x72, 0x62, 0x75, 0x67, 0x7a, 0x76, 0x31, 0x76, 0x5e, 0x78, 0x31, 0x74, 0x5e, 0x6a, 0x6f, 0x31, 0x76, 0x5e, 0x65, 0x35, 0x5e, 0x76, 0x40, 0x32, 0x5e, 0x39, 0x69, 0x33, 0x63, 0x40, 0x31, 0x33, 0x38, 0x7c]


# Designate the input z3 will have control of
inp = []
for i in xrange(0x23):
	byte = BitVec("%s" % i, 8)
	inp.append(byte)

z = Solver()

for i in xrange(0x23):
	z.add((inp[i] ^ 1) == desiredOutput[i])


#Check if z3 can solve it, and if it can print out the solution
if z.check() == sat:
#	print z
	print "Condition is satisfied, would still recommend crying: " + str(z.check())
	solution = z.model()
	flag = ""
	for i in range(0, 0x23):
		flag += chr(int(str(solution[inp[i]])))
	print flag

#Check if z3 can't solve it
elif z.check() == unsat:
	print "Condition is not satisfied, would recommend crying: " + str(z.check())