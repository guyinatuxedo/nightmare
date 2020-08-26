#Import z3
from z3 import *

#Establish the hex array of what the end result should be before the binary not
alt_flag = [42, 234, 194, 42, 98, 222, 142, 14, 94, 150, 206, 158, 34, 118, 70, 182, 70, 246, 94, 236, 108, 246, 230, 54, 30, 14, 94, 154, 38, 214, 190]

#Establish the solving function
def solve(alt_flag):    
    #Establish the solver
    zolv = Solver()

    #Establish the array which will hold all of the integers which we will input
    inp = []
    for i in range(0, len(alt_flag)):
        b = BitVec("%d" % i, 16)
        inp.append(b)

    #Run the same text altering function as enc_func
    for i in range(0, len(alt_flag)):
        x = (2 * (inp[i] & 0x55)) | ((inp[i] >> 1) & 0x55)
        y = (4 * (x & 0x33)) | ((x >> 2) & 0x33)
        z = (16 * y) | ( y >> 4)
        #We need to and it by 0xff, that way we only get the last 8 bits
        z = z & 0xff
        #Add the condition to z3 that we need to end value to be equal to it's corresponding alt_flag value
        zolv.add( z == alt_flag[i])

    #Check if the problem is solvable by z3
    if zolv.check() == sat:
        print "The condition is satisfied, would still recommend crying: " + str(zolv.check())
        #The problem is solvable, model it and print the solution
        solution = zolv.model()
        flag = ""
        for i in range(0, len(alt_flag)):
            flag += chr(int(str(solution[inp[i]])))
        print flag

    #The problem is not solvable by z3    
    if zolv.check() == unsat:
        print "The condition is not satisfied, would recommend crying: " + str(zolv.check())


solve(alt_flag)
