#This script is based off of the writeup from: https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2016/BKPCTF/reversing/unholy

#Import libraries
from z3 import *
import xtea
from struct import *

def solvePython():
    z = Solver()

    #Establish the input that z3 has control over
    X=[[BitVec(0,32), BitVec(1,32), BitVec(2,32)], [BitVec(3,32), BitVec(4,32), BitVec(5,32)], [BitVec(6,32), BitVec(7,32), BitVec(8,32)]]
    
    #Establish the other necessary constants
    Y = [[383212,38297,8201833],[382494 ,348234985,3492834886],[3842947 ,984328,38423942839]]
    n=[5034563854941868,252734795015555591,55088063485350767967,-2770438152229037,142904135684288795,-33469734302639376803,-3633507310795117,195138776204250759,-34639402662163370450]
    y=[[0,0,0],[0,0,0],[0,0,0]]
    
    #A=[0,0,0,0,0,0,0,0,0]

    #Pass the z3 input through the input altering algorithm
    for i in range(len(X)):
        for j in range(len(Y[0])):
            for k in range(len(Y)):
                y[i][j]+=X[i][k]*Y[k][j]
    c=0

    for r in y:
        for x in r:
            #Add the condition for it to pass the check
            #if x!=n[c]:
            z.add(x == n[c])
            c=c+1

    #Check to see if the z3 conditions are possible to solve
    if z.check() == sat:
        print "The condition is satisfiable, would still recommend crying: " + str(z.check())
        #Solve it, store it in matrix, then return
        solution = z.model()
        matrix = [[0, 0, 0], [0, 0, 0], [0, 0, 0]]
        for i0 in xrange(len(matrix)):
            for i1 in xrange(len(matrix)):
                matrix[i0][i1] = solution[X[i0][i1]].as_long()
        return matrix
    else:
        print "The condition is not satisfiable, would recommend crying alot: " + str(z.check())
 
def xteaDecrypt(matrix):
    #Establish the key
    key = "tahwiogsnognereh"

    #Take the imported matrix, convert it into a string
    enc_data = ''
    for i0 in xrange(3):
        for i1 in xrange(3):
            #Unpack the matrix entries as four byte Integers in Big Endian
            enc_data += pack('>I', matrix[i0][i1])

    #Because of the check prior to python code running in the shared library we know the last value before decryption should be this
    enc_data += pack('>I', 0x4de3f9fd)

    #Establish the key, and mode for xtea
    enc = xtea.new(key, mode=xtea.MODE_ECB)

    #Decrypt the encrypted data
    decrypted = enc.decrypt(enc_data)
    
    #We have to reformat the decrypted data
    data = ''
    for i in range(0, len(decrypted), 4):
        data += decrypted[i:i+4][::-1]

    #We check to ensure that the last four characters match the four that are appended prior to encryption
    if data[len(data) - 4:len(data)] == " Ssa":
        return data

#Run the code
matrix = solvePython()
flag = xteaDecrypt(matrix)
print "The flag is: " + flag