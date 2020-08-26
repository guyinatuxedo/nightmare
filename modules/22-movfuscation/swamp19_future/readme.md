# future_fun

Let's take a look at the binary we are given:

```
$    file future_fun
future_fun: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, not stripped
$    ./future_fun
Give the key, if you think you are worthy.

15935728
```

### Reversing

So we are dealing with a 32 bit crackme here. When we take a look at the assembly code, something becomes very apparent:

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined main()
             undefined         AL:1           <RETURN>
                             main                                            XREF[1]:     Entry Point(*)  
        0805036a a1 88 d2        MOV        EAX,[target]
                 3f 08
        0805036f ba 6a 03        MOV        EDX,0x8805036a
                 05 88
        08050374 a3 10 d1        MOV        [alu_x],EAX
                 1f 08
        08050379 89 15 14        MOV        dword ptr [alu_y],EDX
                 d1 1f 08
        0805037f b8 00 00        MOV        EAX,0x0
                 00 00
        08050384 b9 00 00        MOV        ECX,0x0
                 00 00
        08050389 ba 00 00        MOV        EDX,0x0
                 00 00
        0805038e a0 10 d1        MOV        AL,[alu_x]
                 1f 08
        08050393 8b 0c 85        MOV        ECX,dword ptr [alu_eq + EAX*0x4]                 = 24h    $
                 20 77 05 08
        0805039a 8a 15 14        MOV        DL,byte ptr [alu_y]
                 d1 1f 08
        080503a0 8a 14 11        MOV        DL,byte ptr [ECX + EDX*0x1]
        080503a3 89 15 00        MOV        dword ptr [b0],EDX
                 d1 1f 08
        080503a9 a0 11 d1        MOV        AL,[DAT_081fd111]
                 1f 08
        080503ae 8b 0c 85        MOV        ECX,dword ptr [alu_eq + EAX*0x4]                 = 24h    $
                 20 77 05 08
```

This code has been obfuscated using movfuscator (https://github.com/xoreaxeaxeax/movfuscator). Obfuscating a binary essentially means changing something about it to make it harder to reverse, or understand how it works. Movfuscator is a compiler that obfuscates code by basically only uses the `mov` instruction. As such reversing this become really fun.

Starting off I used demovfuscator on it (you can find it here https://github.com/kirschju/demovfuscator). It can do a couple of things. The first is it can create a graph roughly showing the code flow of the binary. The second is it can generate an elf that replaces some of the `mov` instructions with other instructions that are typically used, which makes it a bit easier to reverse. To set it up, you can either compile it from source code (source found on the github, however there are several dependencies you will need) or just use a precompiled binary. Also you will need to install keystone, which you can find documentation about that here: https://github.com/keystone-engine/keystone


To use it to generate a graph of the code flow execution:
```
$    ./demov -g graph.dot -o patched future_fun
```

Now since the file `graph.dot` is essentially a text file containing information on a graph, we will have to use `dot` to actually draw it for us:

```
$    cat graph.dot | dot -Tpng > graph.png
```

In this case I didn't find the graph to be too helpful. However the patched binary it gave us helped me out alot. Mainly because it patched certain `call` instructions back in which helped finding out where it branched.

Now looking over the list of functions this binary has, `check_input` sounds like the most important function. Using the patched binary, we can just search for the call function to `check_input` and see that it is at `0x08051986`:

```
gef➤  b *0x8051986
Breakpoint 1 at 0x8051986
gef➤  r
Starting program: /home/guyinatuxedo/demovfuscator/patched
Give the key, if you think you are worthy.

flag{15935728}

.    .    .

────────────────────────────────────────────────────────────────────────────── stack ────
0x085fd220│+0x0000: 0x00000071 ("q"?)     ← $esp
0x085fd224│+0x0004: 0x00000066 ("f"?)
0x085fd228│+0x0008: <stack+2097032> sbb eax, 0x66000000
0x085fd22c│+0x000c: "flag{15935728}"
0x085fd230│+0x0010: "{15935728}"
0x085fd234│+0x0014: "35728}"
0x085fd238│+0x0018: 0x000a7d38 ("8}"?)
0x085fd23c│+0x001c: <stack+2097052> add BYTE PTR [eax], al
──────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8051978 <main+5646>      mov    eax, DWORD PTR [eax*4+0x83fd270]
    0x805197f <main+5653>      mov    esp, DWORD PTR ds:0x83fd250
    0x8051985 <main+5659>      pop    eax
 →  0x8051986 <main+5660>      call   0x804896e <check_element+474>
   ↳   0x804896e <check_element+474> mov    eax, ds:0x83fd254
       0x8048973 <check_element+479> mov    ds:0x81fd230, eax
       0x8048978 <check_element+484> mov    eax, 0x83fd250
       0x804897d <check_element+489> mov    edx, 0x1
       0x8048982 <check_element+494> nop    
       0x8048983 <check_element+495> mov    ds:0x83fd294, eax
──────────────────────────────────────────────────────────────── arguments (guessed) ────
check_element+474 (
)
──────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "patched", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8051986 → main()
─────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

So we can see that it takes the two characters as an argument `q` and `f`, which one of them we gave as part of input. Turns out the first couple of characters are `flag{` (since it follows the standard flag format). We see that it is checking the characters of our input one by one, and if a character isn't correct then the program exits and stops checking characters. In addition to that we can see with the first couple of characters that we got, the string that our input is being compared to (after it is ran through some algorithm) is `qshr�r77kj{o8yr<jq7}j�;8{pyr�` (29 characters long).

Now instead of going through and statically reversing this, we can just use a side channel attack using Perf.

### Perf

Perf is a performance analyzer for linux, that can tell you a lot of information on processes that run. We will use it (specifically perf stat) to do instruction counting. Essentially we will count the number of instructions that the binary has ran to help determine if we gave it a correct character. If we gave it a correct character, then it should run through the `chekc_element` function again and thus have a higher instruction count than all other characters we tried. However there are some things happening in the background that can affect this count, so it's not always 100% accurate. However what we can do is check the sequence of characters that it gives us via seeing how many checks it passes with gdb, and add the correct characters to the input. If it starts spitting out wrong characters then we will just restart the script which brute forces it. Essentially we will be using Perf to perform a side channel attack on the binary (which is an attack that we execute by monitoring the actions of a target).

Before you run perf, you may need to install this first:
```
$    sudo apt-get install linux-tools-generic
```

Also you will probably need to edit the file `/proc/sys/kernel/perf_event_paranoid`, if you want to run perf without sudo privileges.

Let's take a look at how perf runs:

```
$    perf stat -x : -e instructions:u ./future_fun
Give the key, if you think you are worthy.

15935728
0::instructions:u:5201320:100.00
```

Here we can see that it executed `5201320` instructions. Let's break down the command:

```
perf stat         Specify that we are using perf stat
-x                 Specify that we want out output in CSV format
-e                 Specify that we are going to be monitoring events
instructions:u     Specify that we are going to be monitoring userland instruction events
./future_fun    Process that we will be anaylyzing
```

Now we can just throw together a little script to do the brute forcing. This script I got from one of my other writeups that is based off of https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html:
```
#Import the libraries
from subprocess import *
import string
import sys

#Establish the command to count the number of instructions
command = "perf stat -x : -e instructions:u " + sys.argv[1] + " 1>/dev/null"
flag = 'flag{'
while True:
    ins_count = 0
    count_chr = ''
    for i in (string.lowercase + string.digits):
        target = Popen(command, stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
        target_output, _ = target.communicate(input='%s\n'%(flag + i))
        instructions = int(target_output.split(':')[4])
        #print hex(instructions)
        if instructions > ins_count:
            count_chr = i
            ins_count = instructions
    flag += count_chr
    print flag
```

when we run it:
```
$    python rev.py ./future_fun
flag{g
flag{g0
flag{g00
flag{g00d
flag{g00dn
flag{g00dnj
```

In this case, it gave us the valid letters `g00d` before selecting an incorrect character. However we can just append those characters to our input and start over (and we can check what characters are valid by setting a breakpoint in gdb for `0x08051986` in the patched binary, and seeing what character is the last one to run through the loop). After a little bit, we get the full flag `flag{g00d_th1ng5_f0r_w41ting}`.

```
$    ./future_fun
Give the key, if you think you are worthy.

flag{g00d_th1ng5_f0r_w41ting}
Good job!
```


