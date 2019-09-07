#First import the z3 library
from z3 import *

#Import the two hex strings which we will be xoring
xor1 = [ 0x70, 0x30, 0x53, 0xA1, 0xD3, 0x70, 0x3F, 0x64, 0xB3, 0x16, 0xE4, 0x04, 0x5F, 0x3A, 0xEE, 0x42, 0xB1, 0xA1, 0x37, 0x15, 0x6E, 0x88, 0x2A, 0xAB]
xor2 = [ 0x20, 0xAC, 0x7A, 0x25, 0xD7, 0x9C, 0xC2, 0x1D, 0x58, 0xD0, 0x13, 0x25, 0x96, 0x6A, 0xDC, 0x7E, 0x2E, 0xB4, 0xB4, 0x10, 0xCB, 0x1D, 0xC2, 0x66]


def decrypt(inp, z):
    #Define the encryption algorithm constraints
    y = BitVecVal(0, 8)
    for i in xrange(24):
        x = RotateLeft(inp[i], 3)
        y = RotateRight(y, 2)
        x = x + y
        x = x ^ xor1[i]
        y = x
        x = RotateLeft(x, 4)
        x = x ^ xor2[i]
        z.add(x == 0) 

    #Check if the conditions are satisfiable, if it is model it and get the password
    if z.check() == sat:
        print "The condition is: " + str(z.check())
        solve = z.model()
        cred = ""
        #Sort out the data, and print the passord
        for i in xrange(24):
            cred = cred + chr(int(str(solve[inp[i]])))
        print cred
    else:
        #Something failed and the condition isn't satisifiable, I would recogmend crying
        print "The condition is: " + str(z.check())


#Establish the solver, and the input array
z = Solver()
inp = []

#We need to add an 8 bit vector for every character in our password
for i in xrange(24):
    b = BitVec("%d" % i, 8)
    inp.append(b)

#Now pass the list, and the solver to the decrypt function
decrypt(inp, z)



