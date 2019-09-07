# Bkp 2016 unholy

The purpose of this challenge is to leak the flag.

This writeup is based off of this other writeup: `https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2016/BKPCTF/reversing/unholy`

We are given a tar file. Let's see what's inside of it:
```
$    cd unholy
$    ls
main.rb  unholy.so
$    file unholy.so
unholy.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=bd427479f69b029eec5923ccffb1e6dc76a7743e, not stripped
$    cat main.rb
require_relative 'unholy'
include UnHoly
python_hi
puts ruby_hi
puts "Programming Skills: PRIMARILY RUBY AND PYTHON BUT I CAN USE ANY TYPE OF GEM TO CONTROL ANY TYPE OF SNAKE"
puts "give me your flag"
flag = gets.chomp!
arr = flag.unpack("V*")
is_key_correct? arr
```

So we can see here, we have a ruby file and an x64 shared library. The ruby script appears to simply scan in input, and then passed it to the shared library to be checked. Let's take a look at the shared library to see how it checks the input. First we see that `Init_unholy` we see

```
void Init_unholy(void)

{
  UnHoly = rb_define_module("UnHoly");
  rb_define_method(UnHoly,"python_hi",method_python_hi,0);
  rb_define_method(UnHoly,"ruby_hi",method_ruby_hi,0);
  rb_define_method(UnHoly,"is_key_correct?",method_check_key,1);
  return;
}
```

In `method_check_key`, we see this code block:

```
    i = 0;
    do {                // Returns the int element of the ruby array passed as an argument
      uVar3 = rb_ary_entry(puParm2);
      if ((uVar3 & 1) == 0) {   // Convert the nth element into an int
        matrixInt = rb_num2int();
      }
      else {
        matrixInt = rb_fix2int();
      }
      *(undefined4 *)((long)auStack5072 + i * 4) = matrixInt;  // Store the nth element in the matrix
      i = i + 1;
    } while (i != 9);
    x = 0x61735320;       // Append a 4 byte hex string as the final item in the matrix
```

This chunk of code appears to take the values passed to it, and stores the first 8 values as integers in the matrix `matrix`. For the last value `x` it sets it equal to the hex string `0x61735320`.  So this organizes our input into a matrix.

```
      uVar1 = 0;
      uVar5 = uVar3 & 0xffffffff;
      uVar3 = uVar3 >> 0x20;
      do {
        iVar2 = (int)uVar3;
        uVar7 = *(int *)((long)&matrix + (ulong)(uVar1 & 3) * 4) + uVar1;
        uVar1 = uVar1 + 0x9e3779b9;
        uVar4 = (int)uVar5 + (((uint)(uVar3 >> 5) ^ iVar2 << 4) + iVar2 ^ uVar7);
        uVar5 = (ulong)uVar4;
        uVar7 = iVar2 + ((uVar4 >> 5 ^ uVar4 * 0x10) + uVar4 ^
                        *(int *)((long)&matrix + (ulong)(uVar1 >> 0xb & 3) * 4) + uVar1);
        uVar3 = (ulong)uVar7;
      } while (uVar1 != 0xc6ef3720);
```

Looking at this section of the code, we see that this performs various binary operations using the matrix which was made in the previous code block. Now we could reverse this, or if we googled the hard coded hex string `0x9E3779B9`we see results for the encryption algorithms TEA and XTEA. Looking at the source code for XTEA encryption (https://en.wikipedia.org/wiki/XTEA) it looks rather similar to the code above:

This sample code is from `https://en.wikipedia.org/wiki/XTEA`:
```
void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
}
```

Looking at these two, we can tell that we are dealing with an XTEA encryption algorithm (operating in ECB Mode). Luckily for us we can decrypt it, provided we have the key and what the encrypted data is. In an earlier piece of the code we can see the key:

```
  key[0] = 0x74616877;
  key[1] = 0x696f6773;
  key[2] = 0x6e6f676e;
  key[3] = 0x65726568;
```

Here we can see the four pieces of the key, each a four byte hex string that when you convert it to ascii spells `whatisgoingonhere`. Now  the only thing left is to figure out what the encrypted data is, and this is where python comes into the mix. Ghidra's decompilation didn't quite catch this so we will have to look at the disassembly for this:

```
        00100c89 48 8d 0d        LEA        RCX,[s_exec_"""\nimport_struct\ne=range_00100d   = "exec \"\"\"\\nimport struct\\
                 27 01 00 00
        00100c90 ba 88 13        MOV        EDX,0x1388
                 00 00
        00100c95 be 01 00        MOV        ESI,0x1
                 00 00
        00100c9a 48 89 df        MOV        RDI,RBX
        00100c9d 50              PUSH       RAX
        00100c9e 8b 44 24 44     MOV        EAX,dword ptr [RSP + local_13b4]
        00100ca2 50              PUSH       RAX
        00100ca3 8b 44 24 48     MOV        EAX,dword ptr [RSP + local_13b8]
        00100ca7 50              PUSH       RAX
        00100ca8 8b 44 24 4c     MOV        EAX,dword ptr [RSP + local_13bc]
        00100cac 50              PUSH       RAX
        00100cad 8b 44 24 50     MOV        EAX,dword ptr [RSP + local_13c0]
        00100cb1 50              PUSH       RAX
        00100cb2 8b 44 24 54     MOV        EAX,dword ptr [RSP + local_13c4]
        00100cb6 50              PUSH       RAX
        00100cb7 8b 44 24 58     MOV        EAX,dword ptr [RSP + local_13c8]
        00100cbb 50              PUSH       RAX
        00100cbc 44 8b 4c        MOV        R9D,dword ptr [RSP + stacker+0x4]
                 24 5c
        00100cc1 31 c0           XOR        EAX,EAX
        00100cc3 44 8b 44        MOV        R8D,dword ptr [RSP + stacker]
                 24 58
```

This essentially writes python code to `stacker`, then runs it. Looking at the python code that it runs, we can see how the encrypted data is verified:

```python
#Import libraries
import struct
import sys

#Establish alliases
e=range
I=len
F=sys.exit

#This is the matrix which stores the output of the XTEA encryption in here
X=[[%d,%d,%d],[%d,%d,%d],[%d,%d,%d]]

#This is a matrix which stores static values which will be multiplied against the values of the matrix X, and then stored in the matrix Y
Y = [[383212,38297,8201833],[382494 ,348234985,3492834886],[3842947 ,984328,38423942839]]

#This is what our input will be checked against
n=[5034563854941868,252734795015555591,55088063485350767967,-2770438152229037,142904135684288795,-33469734302639376803,-3633507310795117,195138776204250759,-34639402662163370450]

#This is a matrix which will store the output of the operations with matrices X and Y, then checked against the values of n
y=[[0,0,0],[0,0,0],[0,0,0]]

#This is never actually used
A=[0,0,0,0,0,0,0,0,0]

#This section of code multiplies together the values of matrices X and Y, and then stores them in the matrix y
for i in e(I(X)):
 for j in e(I(Y[0])):
  for k in e(I(Y)):
   y[i][j]+=X[i][k]*Y[k][j]

#Establish and set the index for n equal to 0 for the next part
c=0

#This section of code checks to see if the values in the matrix y are equal to the values in n. If they aren't, it exits the program
for r in y:
 for x in r:
 #Check to see if we have the desired input
  if x!=n[c]:
   print "dang...\"
   F(47)
  c=c+1
  print ":)\"
```

Here we can see that the output from the XTEA function is multiplied against static values stored in the Y matrix, then compared against the values in the n array. With this we can use Z3 to figure out what values we need in order to pass those checks, and then using the key from earlier decrypt those values using the XTEA python library to find what the correct input is:

```
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
```

and when we run it:

```
$ python rev.py 
The condition is satisfiable, would still recommend crying: sat
The flag is: BKPCTF{hmmm _why did i even do this} Ssa
```

Just like that, we captured the flag!


