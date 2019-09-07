#Import z3
from z3 import *

#Designate the input z3 will have control of
inp = []
for i in xrange(25):
	b = BitVec("%s" % i, 8)
	inp.append(b)
#Store the input from z3 in the matrix
h, l = 5, 5;
mat = [[0 for x in range(l)] for y in range(h)]
mat[0][0] = inp[0]
mat[0][2] = inp[7]
mat[0][4] = inp[14]
mat[1][1] = inp[21]
mat[1][3] = inp[3]
mat[2][0] = inp[10]
mat[2][2] = inp[17]
mat[2][4] = inp[24]
mat[3][1] = inp[6]
mat[3][3] = inp[13]
mat[4][0] = inp[20]
mat[4][2] = inp[2]
mat[4][4] = inp[9]
mat[0][1] = inp[16]
mat[0][3] = inp[23]
mat[1][0] = inp[5]
mat[1][2] = inp[12]
mat[1][4] = inp[19]
mat[2][1] = inp[1]
mat[2][3] = inp[8]
mat[3][0] = inp[15]
mat[3][2] = inp[22]
mat[3][4] = inp[4]
mat[4][1] = inp[11]
mat[4][3] = inp[18]
#print mat

#Perform the 19 math operations with the matrix
auth = [0]*19
auth[0] = mat[0][0] + mat[4][4]
auth[1] = mat[2][1] + mat[0][2]
auth[2] = mat[4][2] + mat[4][1]
auth[3] = mat[1][3] + mat[3][1]
auth[4] = mat[3][4] + mat[1][2]
auth[5] = mat[1][0] + mat[2][3]
auth[6] = mat[2][4] + mat[2][0]
auth[7] = mat[3][3] + mat[3][2] + mat[0][3]
auth[8] = mat[0][4] + mat[4][0] + mat[0][1]
auth[9] = mat[3][3] + mat[2][0]
auth[10] = mat[4][0] + mat[1][2]
auth[11] = mat[0][4] + mat[4][1]
auth[12] = mat[0][3] + mat[0][2]
auth[13] = mat[3][0] + mat[2][0]
auth[14] = mat[1][4] + mat[1][2]
auth[15] = mat[4][3] + mat[2][3]
auth[16] = mat[2][2] + mat[0][2]
auth[17] = mat[1][1] + mat[4][1]	
#print auth

#Create the solver, and the desired output
z = Solver()
enc = [0x8b, 0xce, 0xb0, 0x89, 0x7b, 0xb0, 0xb0, 0xee, 0xbf, 0x92, 0x65, 0x9d, 0x9a, 0x99, 0x99, 0x94, 0xad, 0xe4]

#Create the z3 constraints for what the output should be:
#equal to it's corresponding enc value
#an ascii character to make it easier to input into the program
for i in xrange(len(enc)):
#	print enc[i]
	z.add(auth[i] == enc[i])
for i in xrange(25):
	z.add(inp[i] > 32)
	z.add(inp[i] < 127)

#Check if z3 can solve it, and if it can print out the solution
if z.check() == sat:
#	print z
	print "Condition is satisfied, would still recommend crying: " + str(z.check())
	solution = z.model()
	flag = ""
	for i in inp:
		flag += chr(int(str(solution[i])))
	print "solution is: " + flag

#Check if z3 can't solve it
if z.check() == unsat:
	print "Condition is not satisfied, would recommend crying: " + str(z.check())