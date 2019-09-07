# REcon movfuscation

One thing, this wasn't a ctf challenge but a challenge released as part of a talk from an REcon talk. Let's take a look at the binary:

```
$    file movfuscated1
movfuscated1: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, stripped
$    ./movfuscated1
M/o/Vfuscator 2.0a // domas // @xoreaxeaxeax
Enter the key: 15935728
Nope.
```

So we can see it is a `32` bit binary, that is a crackme. Also as the name suggests, it has been obfuscated using Movfuscated (which obfuscates the code by using a lot of `mov` instructions in the binary). Looking at the assembly code for this binary, we can see that it is going to be a pain:

```
$    objdump -D movfuscated1 -M intel | less

.    .    .

 80482fd:       a1 c0 5d 1d 08          mov    eax,ds:0x81d5dc0
 8048302:       ba 04 00 00 00          mov    edx,0x4
 8048307:       a3 90 5c 0d 08          mov    ds:0x80d5c90,eax
 804830c:       89 15 94 5c 0d 08       mov    DWORD PTR ds:0x80d5c94,edx
 8048312:       b8 00 00 00 00          mov    eax,0x0
 8048317:       bb 00 00 00 00          mov    ebx,0x0
 804831c:       b9 00 00 00 00          mov    ecx,0x0
 8048321:       ba 00 00 00 00          mov    edx,0x0
 8048326:       c7 05 9c 5c 0d 08 00    mov    DWORD PTR ds:0x80d5c9c,0x0
 804832d:       00 00 00
 8048330:       a0 90 5c 0d 08          mov    al,ds:0x80d5c90
 8048335:       8a 1d 94 5c 0d 08       mov    bl,BYTE PTR ds:0x80d5c94
 804833b:       8a 0d 9c 5c 0d 08       mov    cl,BYTE PTR ds:0x80d5c9c
 8048341:       8a 94 18 d0 3b 06 08    mov    dl,BYTE PTR [eax+ebx*1+0x8063bd0]
 8048348:       8a b4 18 e0 3d 06 08    mov    dh,BYTE PTR [eax+ebx*1+0x8063de0]
 804834f:       8a 84 0a d0 3b 06 08    mov    al,BYTE PTR [edx+ecx*1+0x8063bd0]
 8048356:       a2 98 5c 0d 08          mov    ds:0x80d5c98,al
 804835b:       8a 84 0a e0 3d 06 08    mov    al,BYTE PTR [edx+ecx*1+0x8063de0]
 8048362:       a2 9c 5c 0d 08          mov    ds:0x80d5c9c,al
 8048367:       a0 91 5c 0d 08          mov    al,ds:0x80d5c91
```

However we don't need to reverse this binary necessarily. With a lot of different crackmes, they will essentially check the input a single character at a time. If it passes a check it will move on to the next check, and if it doesn't it just immediately exits. Thing is if we have a correct character and it goes on to the next check, that should execute more instructions than if we were to input any other incorrect character. If our assumption is correct, then we can just brute force it one character at a time, and see what character has the most instructions executed when we input it (and select that to be the correct character). Proceeding that we add it to the flag and move on to the next character until we have the flag.

For this we can use the performance analyzer perf to count the number of instructions ran (we can also count other events such as the cpu-clock or branches). Here are some examples

Count the number of instructions:
```
$    perf stat -e instructions ./movfuscated1
M/o/Vfuscator 2.0a // domas // @xoreaxeaxeax
Enter the key: 15935728
Nope.

 Performance counter stats for './movfuscated1':

           804,200      instructions                                                

       2.940768967 seconds time elapsed
```

We can also format the output of perf to make it easier to parse:

```
$    perf stat -x : -e instructions ./movfuscated1
M/o/Vfuscator 2.0a // domas // @xoreaxeaxeax
Enter the key: 15935728
Nope.
803653::instructions:857080:100.00::::
```

Also we can specify what privilege level we want to view the events (so count the number of instructions that run at the user level :u or the kernel level :k, or the user level k):

```
$    sudo perf stat -x : -e instructions:u ./movfuscated1
M/o/Vfuscator 2.0a // domas // @xoreaxeaxeax
Enter the key: 15935728
Nope.
261507::instructions:u:790421:100.00::::
```

We will want to use u, since the instructions we want to count are being ran with user level privileges.

So we can see that the number of instructions is the first thing it gives us with this form of output. Now with this, we can write a python program based off of the earlier mentioned writeup which will simply iterate through all printable characters for each slot, choose the character which has the most instructions ran, and move on to the next character. Also one thing I originally learned how to do this from: https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html

```
# Import the libraries
from subprocess import *
import string
import sys

# Establish the command to count the number of instructions, pipe output of command to /dev/null
command = "perf stat -x : -e instructions:u " + sys.argv[1] + " 1>/dev/null"

# Establish the empty flag
flag = ''


while True:
    # Reset the highest instruction value and corresponding character
    ins_count = 0
    count_chr = ''
    # Iterate Through all printable characters
    for i in string.printable:
        # Start a new process for the new character
        target = Popen(command, stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
        # Give the program the new input to test, and grab the store the output of perf-stat in target_output
        target_output, _ = target.communicate(input='%s\n'%(flag + i))
        # Filter out the instruction count
        instructions = int(target_output.split(':')[0])
        # Check if the new character has the highest instruction count, and if so record the instruction count and corresponding character
        if instructions > ins_count:
            count_chr = i
            ins_count = instructions
    # Add the character with the highest instruction count to flag, print it, and restart
    flag += count_chr
    print flag
```

When we run it (also if you don't have the config set to run the instruction counting with perf as an unprivileged user, you will need to run this with sudo):
```
$    python rev.py ./movfuscated1
{
{R
{Re
{ReC
{ReCo
{ReCoN
{ReCoN2
{ReCoN20
{ReCoN201
{ReCoN2016
{ReCoN2016}
{ReCoN2016}d
{ReCoN2016}dn
$    ./movfuscated1
M/o/Vfuscator 2.0a // domas // @xoreaxeaxeax
Enter the key: {ReCoN2016}
YES!
```

Our script couldn't tell when the key ended, but it was obvious from the text. With that we solved the crackme!