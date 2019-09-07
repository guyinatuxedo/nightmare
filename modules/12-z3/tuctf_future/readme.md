# future

Full disclosure, the solution I found and talk about in here is an unintended solution (got the intended flag after showing my solution to an admin).

Let's take a look at the binary:

```
$    file future
future: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=d6e528233c162804c1b358c2e15be38eb717c98a, not stripped
$    ./future
What's the flag: TUCTF{heres_a_flag}
Try harder.
```

So it is a 32 bit binary, and when we run it it prompts us for the flag. Luckily for this one we're given the source code. Let's take a look at it:

```
$    cat future.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void genMatrix(char mat[5][5], char str[]) {
    for (int i = 0; i < 25; i++) {
        int m = (i * 2) % 25;
        int f = (i * 7) % 25;
        mat[m/5][m%5] = str[f];
    }
}

void genAuthString(char mat[5][5], char auth[]) {
    auth[0] = mat[0][0] + mat[4][4];
    auth[1] = mat[2][1] + mat[0][2];
    auth[2] = mat[4][2] + mat[4][1];
    auth[3] = mat[1][3] + mat[3][1];
    auth[4] = mat[3][4] + mat[1][2];
    auth[5] = mat[1][0] + mat[2][3];
    auth[6] = mat[2][4] + mat[2][0];
    auth[7] = mat[3][3] + mat[3][2] + mat[0][3];
    auth[8] = mat[0][4] + mat[4][0] + mat[0][1];
    auth[9] = mat[3][3] + mat[2][0];
    auth[10] = mat[4][0] + mat[1][2];
    auth[11] = mat[0][4] + mat[4][1];
    auth[12] = mat[0][3] + mat[0][2];
    auth[13] = mat[3][0] + mat[2][0];
    auth[14] = mat[1][4] + mat[1][2];
    auth[15] = mat[4][3] + mat[2][3];
    auth[16] = mat[2][2] + mat[0][2];
    auth[17] = mat[1][1] + mat[4][1];
}

int main() {
    char flag[26];
    printf("What's the flag: ");
    scanf("%25s", flag);
    flag[25] = 0;

    if (strlen(flag) != 25) {
        puts("Try harder.");
        return 0;
    }


    // Setup matrix
    char mat[5][5];// Matrix for a jumbled string
    genMatrix(mat, flag);
    // Generate auth string
    char auth[19]; // The auth string they generate
    auth[18] = 0; // null byte
    genAuthString(mat, auth);    
    char pass[19] = "\x8b\xce\xb0\x89\x7b\xb0\xb0\xee\xbf\x92\x65\x9d\x9a\x99\x99\x94\xad\xe4\x00";
    
    // Check the input
    if (!strcmp(pass, auth)) {
        puts("Yup thats the flag!");
    } else {
        puts("Nope. Try again.");
    }
    
    return 0;
}
```

So looking at the source code, we can tell what the program does. It scans in up to 25 bytes of input, checks to make sure that it scanned in 25 bytes. Then it creates a 5 by 5 matrix, and stores the 25 bytes in the matrix in a slightly obscure way. Then it takes the matrix and performs 19 different additions using 2-3 different matrix values for each iteration. It then compares the output of that to a predefined answer `pass`. If they are the same, then you have the flag.

So first we need to figure out how our input is stored in the matrix. For that, python can help. There are three different values we need to worry about in the `genMatrix` function `f`,  `m/5`, and `m%5`:

```
>>> for i in xrange(25):
...     print ((i * 2) % 25) / 5
...
0
0
0
1
1
2
2
2
3
3
4
4
4
0
0
1
1
1
2
2
3
3
3
4
4
>>> for i in xrange(25):
...     print ((i * 2) % 25) % 5
...
0
2
4
1
3
0
2
4
1
3
0
2
4
1
3
0
2
4
1
3
0
2
4
1
3
>>> for i in xrange(25):
...     print ((i * 7) % 25)
...
0
7
14
21
3
10
17
24
6
13
20
2
9
16
23
5
12
19
1
8
15
22
4
11
18
```

Putting it all together, we find that this is how our input is stored in the5 by 5 matrix:

```
matrix[0][0] = input[0]
matrix[0][2] = input[7]
matrix[0][4] = input[14]
matrix[1][1] = input[21]
matrix[1][3] = input[3]
matrix[2][0] = input[10]
matrix[2][2] = input[17]
matrix[2][4] = input[24]
matrix[3][1] = input[6]
matrix[3][3] = input[13]
matrix[4][0] = input[20]
matrix[4][2] = input[2]
matrix[4][4] = input[9]
matrix[0][1] = input[16]
matrix[0][3] = input[23]
matrix[1][0] = input[5]
matrix[1][2] = input[12]
matrix[1][4] = input[19]
matrix[2][1] = input[1]
matrix[2][3] = input[8]
matrix[3][0] = input[15]
matrix[3][2] = input[22]
matrix[3][4] = input[4]
matrix[4][1] = input[11]
matrix[4][3] = input[18]
```

The mathematical operations done with the matrix is made clear in the source code. So now that we know how our input is scanned in, stored in the matrix, the algorithm the data is ran through, and the desired output it's compared against. We can just write a bit of python code which will use Microsoft's z3 theorem solver to figure out the input we need to get an output. You can check the source code of the script for more details on how Z3 works (tl;dr we specify the inputs we have control over, the algorithm it gets run through, and the constraints such as what we want the end result to be):

```
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
#    print enc[i]
    z.add(auth[i] == enc[i])
for i in xrange(25):
    z.add(inp[i] > 32)
    z.add(inp[i] < 127)

#Check if z3 can solve it, and if it can print out the solution
if z.check() == sat:
#    print z
    print "Condition is satisfied, would still recommend crying: " + str(z.check())
    solution = z.model()
    flag = ""
    for i in inp:
        flag += chr(int(str(solution[i])))
    print "solution is: " + flag

#Check if z3 can't solve it
if z.check() == unsat:
    print "Condition is not satisfied, would recommend crying: " + str(z.check())
```

When we run it:

```
$    python reverent.py
Condition is satisfied, would still recommend crying: sat
solution is: KgBIVp@g@@9n%Y/`PFTt@vb3w
$    ./future
What's the flag: KgBIVp@g@@9n%Y/`PFTt@vb3w
Yup thats the flag!
```

After talking to an admin about my solution, he gave me the real flag which is `TUCTF{5y573m5_0f_4_d0wn!}`. Just like that, we captured the flag using an unintended solution!