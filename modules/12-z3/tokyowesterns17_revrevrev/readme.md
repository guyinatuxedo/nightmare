# Tokyowesterns rev_rev_rev

Let's take a look at the binary:

```
$    file rev_rev_rev-a0b0d214b4aeb9b5dd24ffc971bd391494b9f82e2e60b4afc20e9465f336089f
rev_rev_rev-a0b0d214b4aeb9b5dd24ffc971bd391494b9f82e2e60b4afc20e9465f336089f: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=e33eb178391bae637823f4645d63d63eac3a8d07, stripped
$    ./rev_rev_rev-a0b0d214b4aeb9b5dd24ffc971bd391494b9f82e2e60b4afc20e9465f336089f
Rev! Rev! Rev!
Your input: gimme that flag
Invalid!
```

So we are dealing with a `32` bit program that when we run it, it asks for input (and told us it was invalud). My guess is that this program takes input, alters it, and compares it against a string. Looking through the list of functions (or checking the X-References to strings) we find the `FUN_080485ab` function which looks like where the code we are interested in is:

```
undefined4 FUN_080485ab(void)

{
  char *bytesRead;
  int check;
  int in_GS_OFFSET;
  char input [33];
  int stackCanary;
 
  stackCanary = *(int *)(in_GS_OFFSET + 0x14);
  puts("Rev! Rev! Rev!");
  printf("Your input: ");
  bytesRead = fgets(input,0x21,stdin);
  if (bytesRead == (char *)0x0) {
    puts("Input Error.");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  op0(input);
  op1(input);
  op2(input);
  op3(input);
  check = strcmp(input,PTR_DAT_0804a038);
  if (check == 0) {
    puts("Correct!");
  }
  else {
    puts("Invalid!");
  }
  if (stackCanary != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

So we can see this function starts off bys scanning in `0x21` bytes into `input`. If the `fgets` call scans in no bytes, it exits with an error message. Then it runs `input` through 4 different functions (`op0-op3`). Then it compares our data against `PTR_DAT_0804a038` using `strcmp`, and if it is equivalent then we pass the challenge. We can check what the value of `PTR_DAT_0804a038` via clicking on it and checking it's value. What is happening here is it is scanning in input, altering it with the ops functions, then checking it against `PTR_DAT_0804a038`:

```
                             DAT_08048870                                    XREF[2]:     FUN_080485ab:08048668(*),
                                                                                          0804a038(*)  
        08048870 41              ??         41h    A
        08048871 29              ??         29h    )
        08048872 d9              ??         D9h
        08048873 65              ??         65h    e
        08048874 a1              ??         A1h
        08048875 f1              ??         F1h
        08048876 e1              ??         E1h
        08048877 c9              ??         C9h
        08048878 19              ??         19h
        08048879 09              ??         09h
        0804887a 93              ??         93h
        0804887b 13              ??         13h
        0804887c a1              ??         A1h
        0804887d 09              ??         09h
        0804887e b9              ??         B9h
        0804887f 49              ??         49h    I
        08048880 b9              ??         B9h
        08048881 89              ??         89h
        08048882 dd              ??         DDh
        08048883 61              ??         61h    a
        08048884 31              ??         31h    1
        08048885 69              ??         69h    i
        08048886 a1              ??         A1h
        08048887 f1              ??         F1h
        08048888 71              ??         71h    q
        08048889 21              ??         21h    !
        0804888a 9d              ??         9Dh
        0804888b d5              ??         D5h
        0804888c 3d              ??         3Dh    =
        0804888d 15              ??         15h
        0804888e d5              ??         D5h
        0804888f 00              ??         00h
```

So first we take a look at the `op0` function and we see this:

```
void op0(char *input)

{
  char *newLinePos;
 
  newLinePos = strchr(input,10);
  *newLinePos = '\0';
  return;
}
```

Looking at this function, we can see that it first looks for the character `0xa`, which is a newline character. Then it set's that equal to `0x0`. So essentially it replaces the newline character with a null byte. Let's take a look at `op1`:

```
void op1(char *input)

{
  size_t len;
  char *beg;
  char *end;
  char holder;
 
  beg = input;
  len = strlen(input);
  end = input + (len - 1);
  while (beg < end) {
    holder = *beg;
    *beg = *end;
    *end = holder;
    beg = beg + 1;
    end = end + -1;
  }
  return;
}
```

This code essentially takes our input (which has had the newline character stripped) and just reverses it. For instance, if we gave the program `1234`, it would reverse it to `4321`. Now let's look at `op2`.

```
void op2(byte *input)

{
  byte x;
  byte y;
  byte *inputCpy;
 
  inputCpy = input;
  while (*inputCpy != 0) {
    x = (char)*inputCpy >> 1 & 0x55U | (*inputCpy & 0x55) * '\x02';
    y = (char)x >> 2 & 0x33U | (byte)(((int)(char)x & 0x33U) << 2);
    *inputCpy = y >> 4 | (byte)((int)(char)y << 4);
    inputCpy = inputCpy + 1;
  }
  return;
}
```

This function alters the input, by performing various binary operations on our input (and in one case, multiplying it). We can see that it is a for loop that will run once per each character of our input. It will take the hex value of each character of our input and alter it, however it will only take the first 8 bits worth of data (so the least significant bit). This code effectively translates to the following python since this might be a bit easier to understand. Also shifting a value to the right by `2` is the same as multiplying it by `4`:

```
def enc(input):
    output = ""
    for c in input:
        c = ord(c)
        x = (2 * (c & 0x55)) | ((c >> 1) & 0x55)
        print "x is: " + hex(x)
        y = (4 * (x & 0x33)) | ((x >> 2) & 0x33)
        print "y is: " + hex(y)
        z = (16 * y) | ( y >> 4)
        print "z is: " + hex(z)
        output = hex(z).replace("0x", "")[-2:] + output
    return output
```

With all of that, let's take a look at the final function our input is ran through `op3`:

```
void op3(byte *input)

{
  byte *inputCpy;
 
  inputCpy = input;
  while (*inputCpy != 0) {
    *inputCpy = ~*inputCpy;
    inputCpy = inputCpy + 1;
  }
  return;
}
```

So like the previous function, this runs a loop that iterates for each character of the input. However this time it alters each character by performing a binary not (which it's operator in c is `~`). Essentially it takes the binary value of the character, and converts the zeros to ones and ones to zeros. For instance:

```
0:    0x30:    00110000
NOT 0:         11001111 = 0xcf
```

it essentially performs the same function as this python script:

```
def not_inp(inp):
    output = 0x0
    result = ""
    string = bin(inp).replace("0b", "")
    print "Binary string is: " + string
    for s in string:
        if s == "0":
            result += "1"
        if s == "1":
            result += "0"
    print "Binary inverse is: " + result
    output = int(result, 2)
    return output
```

So we understand what the four functions do. We could have also figured out what some of the functions do by using gdb, and looking at the value of `input_buf` changes (it's how I figured out what the first two functions did). Set the breakpoints before each of the four functions is called, and the final strcmp:

```
gdb-peda$ b *0x0804862b
Breakpoint 1 at 0x804862b
gdb-peda$ b *0x0804863a
Breakpoint 2 at 0x804863a
gdb-peda$ b *0x08048649
Breakpoint 3 at 0x8048649
gdb-peda$ b *0x08048658
Breakpoint 4 at 0x8048658
gdb-peda$ b *0x0804866d
Breakpoint 5 at 0x804866d
gdb-peda$ r
Starting program: /Hackery/west/rev/rev_rev_rev-a0b0d214b4aeb9b5dd24ffc971bd391494b9f82e2e60b4afc20e9465f336089f
Rev! Rev! Rev!
Your input: tux

```

Before `op0` is called:
```
Breakpoint 1, 0x0804862b in ?? ()
gdb-peda$ x/s $eax
0xffffd07b:    "tux\n"
gdb-peda$ c
Continuing.
```

After `op0`, before `op1`:
```
Breakpoint 2, 0x0804863a in ?? ()
gdb-peda$ x/s $eax
0xffffd07b:    "tux"
gdb-peda$ c
Continuing.
```

After `op1`, before `op2`:

```
Breakpoint 3, 0x08048649 in ?? ()
gdb-peda$ x/s $eax
0xffffd07b:    "xut"
gdb-peda$ c
Continuing.
```

After `op2`, before `op3`:
```
Breakpoint 4, 0x08048658 in ?? ()
gdb-peda$ x/x $eax
0xffffd07b:    0x1e
gdb-peda$ x/w $eax
0xffffd07b:    0x002eae1e
gdb-peda$ x/s $eax
0xffffd07b:    "\036\256."
gdb-peda$ c
Continuing.
```

After `op3`, before `strcmp`:
```
Breakpoint 5, 0x0804866d in ?? ()
gdb-peda$ x/x $eax
0xffffd07b:    0xe1
gdb-peda$ x/w $eax
0xffffd07b:    0x00d151e1
```

So we can see the text altered as it is passed through the function. Now that we know what happens to the text, we just need to know what it needs to be after all of it. When we see what value `desired_output` holds, we see this:

```
.rodata:08048870 desired_output_storage db  41h ; A      ; DATA XREF: .data:desired_outputo
.rodata:08048871                 db  29h ; )
.rodata:08048872                 db 0D9h ; +
.rodata:08048873                 db  65h ; e
.rodata:08048874                 db 0A1h ; í
.rodata:08048875                 db 0F1h ; ±
.rodata:08048876                 db 0E1h ; ß
.rodata:08048877                 db 0C9h ; +
.rodata:08048878                 db  19h
.rodata:08048879                 db    9
.rodata:0804887A                 db  93h ; ô
.rodata:0804887B                 db  13h
.rodata:0804887C                 db 0A1h ; í
.rodata:0804887D                 db    9
.rodata:0804887E                 db 0B9h ; ¦
.rodata:0804887F                 db  49h ; I
.rodata:08048880                 db 0B9h ; ¦
.rodata:08048881                 db  89h ; ë
.rodata:08048882                 db 0DDh ; ¦
.rodata:08048883                 db  61h ; a
.rodata:08048884                 db  31h ; 1
.rodata:08048885                 db  69h ; i
.rodata:08048886                 db 0A1h ; í
.rodata:08048887                 db 0F1h ; ±
.rodata:08048888                 db  71h ; q
.rodata:08048889                 db  21h ; !
.rodata:0804888A                 db  9Dh ; ¥
.rodata:0804888B                 db 0D5h ; +
.rodata:0804888C                 db  3Dh ; =
.rodata:0804888D                 db  15h
.rodata:0804888E                 db 0D5h ; +
.rodata:0804888F                 db    0
```

So we can see that it is equal to a hex string starting with `0x41` and ending with `0x0`. So now that we know what it needs to be equal to we can use the solver z3. Essentially once we define what happens to the input, z3 will tell us what input we need to meet the desired output.

 I made two scripts, one to undo the binary not, and one to figure out the input needed to get the desired output out of `enc_func`. Also to account for `op1` (function that reverses our input) I just inputted the hex string backwards. Now for the script to undo the binary not:
 
```
#Establish the flag after the binary not
flag = [ 0xd5, 0x15, 0x3d, 0xd5, 0x9d, 0x21, 0x71, 0xf1, 0xa1, 0x69, 0x31, 0x61, 0xdd, 0x89, 0xb9, 0x49, 0xb9, 0x09, 0xa1, 0x13, 0x93, 0x09, 0x19, 0xc9, 0xe1, 0xf1, 0xa1, 0x65, 0xd9, 0x29, 0x41]

#Establish the function to execute the binary not
def not_inp(inp):
    output = 0x0
    result = ""
    string = bin(inp).replace("0b", "")
    #Check if there are less than 8 bits, and if so add zeroes to the front to get 8 bits
    if len(string) < 8:
        diff = 8 - len(string)
        string = diff*"0" + string
    print "Binary string is:  " + string
    
    #Swap the ones with zeroes, and vice versa
    for s in string:
        if s == "0":
            result += "1"
        if s == "1":
            result += "0"
    print "Binary inverse is: " + result
    
    #Convert the binary string to an int, and return it
    output = int(result, 2)
    return output

#Establish the array which will hold the output
out = []
#Iterate through each character of the flag, and undo the binary not
for i in flag:
    x = not_inp(i)
    out.append(x)
    print hex(x)

#Print the flag before the binary not
print "alt_flag = " + str(out)
```

when we run the script, we see that the hex string before the binary not happens is equal to this:

```
alt_flag = [42, 234, 194, 42, 98, 222, 142, 14, 94, 150, 206, 158, 34, 118, 70, 182, 70, 246, 94, 236, 108, 246, 230, 54, 30, 14, 94, 154, 38, 214, 190]
```

With this info, we can just use z3 to figure out the input needed for `enc_func` to output that. Z3 is a theorem solver by Microsoft (you can find install instructions here https://github.com/Z3Prover/z3). Z3 will allow us to essentially declare the input it has control over, specify the algorithm that it goes through, and then specify what you want the output to be (and any additional constraints you want to have). Then you can check if Z3 can solve it, and if it can it will solve it and print a solution. Checkout the code for more details:

```
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
```

Let's try it!

```
$ python reverent.py
The condition is satisfied, would still recommend crying: sat
TWCTF{qpzisyDnbmboz76oglxpzYdk}
$ ./rev_rev_rev
Rev! Rev! Rev!
Your input: TWCTF{qpzisyDnbmboz76oglxpzYdk}
Correct!
```

Just like that, we reversed the challenge!