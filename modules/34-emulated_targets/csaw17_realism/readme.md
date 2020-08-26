# Csaw 17 Reversing 400 Realism

This writeup is based off of: `https://github.com/DMArens/CTF-Writeups/blob/master/2017/CSAWQuals/reverse/realism-400.md`

Let's take a look at what we have:

```
$    file main.bin
main.bin: DOS/MBR boot sector
```

So we are given a boot record. We are also given the command `qemu-system-i386 -drive format=raw,file=main.bin`, which when we run it displays a screen which prompts us for the flag. Also I wouldn't recommend doing this challenge on Ubuntu 19.04.

## MBR

x86 Real Mode 16

A couple of things about Master Boot Records that are extremely helpful to know going forward. They are always loaded into memory at the address `0x7c00`. So in gdb, we can just look at the assembly code by examining the memory starting at `0x7c00`. Secondly the code for this program is a sixteen bit assembly, in the `i8086` architecture. You will have to load it as an `x86` processor of size `16` in Ghidra. The third thing, in Ghidra when you load in the binary code will start at the address `0x0`. If you want, you can reload the binary to start at the address `0x7c00`, because that is what the address `0x0` will correlate to when it runs. For instance the address `0x1dc` in Ghidra would translate to the address `0x7ddc` when it runs (I use both address types interchangeably)

## Dynamic Analysis

When reversing this, using gdb to analyze the program as it is running is very helpful. Luckily for us, qemu has built in gdb support with the `-gdb` flag. Here is the command you need to run if you want to run the program with a listener on port `1234` (ip is localhost) for gdb:

```
$    qemu-system-i386 -drive format=raw,file=main.bin -gdb tcp::1234
```

and if you want to connect to the listener on localhost on port `1234` (before that we will set the architecture to `i8086`, so we can view the instructions properly):

```
gef➤  set architecture i8086
warning: A handler for the OS ABI "GNU/Linux" is not built into this configuration
of GDB.  Attempting to continue with the default i8086 settings.

The target architecture is assumed to be i8086
gef➤  target remote localhost:1234
Remote debugging using localhost:1234
warning: No executable has been specified and target does not support
determining executable automatically.  Try using the "file" command.
0x0000b601 in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
[!] Command 'context' failed to execute properly, reason: 'NoneType' object has no attribute 'all_registers'
gef➤  i r
eax            0x0                 0x0
ecx            0xb5e5              0xb5e5
edx            0x0                 0x0
ebx            0xdc80              0xdc80
esp            0x6efa              0x6efa
ebp            0x1234              0x1234
esi            0xfbb8              0xfbb8
edi            0x0                 0x0
eip            0xb601              0xb601
eflags         0x246               [ PF ZF IF ]
cs             0xf000              0xf000
ss             0x0                 0x0
ds             0x0                 0x0
es             0xdc80              0xdc80
fs             0x0                 0x0
gs             0x0                 0x0
```

Now that we have attached the process to gdb, let's see if the instructions begin where we would expect them to at `0x7c00`:

```
gef➤  x/4g 0x7c00
0x7c00: 0xc0200f10cd0013b8  0x220f02c883fbe083
0x7c10: 0x0f06000de0200fc0  0x000a126606c7e022
```

When we check the instructions / opcodes in Ghidra:
```
                             //
                             // ram
                             // fileOffset=0, length=512
                             // ram: 0000:0000-0000:01ff
                             //
             assume DF = 0x0  (Default)
       0000:0000 b8 13 00        MOV        AX,0x13
       0000:0003 cd 10           INT        0x10
       0000:0005 0f 20 c0        MOV        EAX,CR0
       0000:0008 83 e0 fb        AND        AX,0xfffb
       0000:000b 83 c8 02        OR         AX,0x2
       0000:000e 0f 22 c0        MOV        CR0,EAX
       0000:0011 0f 20 e0        MOV        EAX,CR4
       0000:0014 0d 00 06        OR         AX,0x600
       0000:0017 0f 22 e0        MOV        CR4,EAX
       0000:001a c7 06 66        MOV        word ptr [0x1266],0xa
                 12 0a 00
       0000:0020 bb 00 00        MOV        BX,0x0
```

So we can see here the same opcodes that we see at the start of the program (so we know that we know where the start of the code segment in memory is). Now the next step of reversing this is to identify the segment of code where the actual check happens. The elf is only `512` bytes long, so there isn't a lot of code to parse through. However, this is my first time reversing this type of architecture, and thus I am very lost.

So what I decided to do to figure out which code segments are responsible for the check, is set breakpoints at the start of various sub functions (in IDA they are titled something like `loc_8E`)

```
0x7c00

0x7c23

0x7c33

0x7c38

0x7c58

0x7c8e

0x7cdf

0x7d0d

0x7d31
```

When I ran the program normally, it just encountered the breakpoints at `0x7c58`, `0x7d0d`, `0x7c33` and `0x7c38` (in that order). So those four code segments are probably used in handling input and the display. However when we enter in `20` characters and trigger a check, we encounter a breakpoint at `0x7cdf`. So we know that `0x7cdf` is a part of the check. That code path `LAB_0000_00df or 0x7cdf` is called in two different places, at `0x7d55` and `0x7cd1`. When we run the program again, and set breakpoints for `0x7d55` and `0x7cd1` we see that the one that we hit which actually leads to the check is `0x7d55`. This is apart of the subroutine `LAB_0000_014d`, which starts at `0x7d4d`. This is also called at two different places at `0x7c78` and `0x7cba`. When we do the same trial by running the program again with setting a breakpoint at `0x7c78` and `0x7cba` to see where the call actually happens, we see that it is called at `0x7c78`.

The actual instruction at `0x7c78` is a `jnz` instruction for the previous `cmp` instruction at `0x7c6f`. Specifically this is the instruction:

```
       0000:006f 66 81 3e        CMP        dword ptr [0x1234],0x67616c66
                 34 12 66
                 6c 61 67
```

So it is comparing something against the string `flag` (it's displayed backwards in hex, because of least endian). It is probably checking to see if the input we gave it starts with `flag`. When we try running the code again with input that starts with `flag{` and ends in `}`, we see something interesting happen. It passes the check at `0x7c6f` and doesn't execute the jump at `0x7c78`. It just continues execution into `LAB_0000_008e` where it enters into a for loop. However when it is in the for loop, we don't get the error message that we're wrong and we should feel bad.

So with this new discovery, I'm pretty sure what though the check happened at `0x7cdf` isn't actually a part of the check, it's the part of the program that happens after the check if we're wrong at tells us we're bad and should feel bad. The actual check begins at `0x7c66`, where it just sees how many characters of input we've given it. If it is less than or equal to `0x13` (`19`) it just jumps to `0x7d0d` and continues with the loop. However when it reaches `20` characters of input (the amount that we need to enter to trigger the check) it skips the jump and starts actually checking the input at `0x6f` with seeing if the first four characters are `flag`, then continues into the actual check in `LAB_0000_008e` at `0x7c8e`.

## The Check

So now that we know where the check occurs, we can start reversing it. Below is the code that is relevant to the check:

```
       0000:0066 80 3e c8        CMP        byte ptr [0x7dc8],0x13
                 7d 13
       0000:006b 0f 8e 9e 00     JLE        LAB_0000_010d
       0000:006f 66 81 3e        CMP        dword ptr [0x1234],0x67616c66
                 34 12 66
                 6c 61 67
       0000:0078 0f 85 d1 00     JNZ        LAB_0000_014d
       0000:007c 0f 28 06        MOVAPS     XMM0,xmmword ptr [0x1238]
                 38 12
       0000:0081 0f 28 2e        MOVAPS     XMM5,xmmword ptr [0x7c00]
                 00 7c
       0000:0086 66 0f 70        PSHUFD     XMM0,XMM0,0x1e
                 c0 1e
       0000:008b be 08 00        MOV        SI,0x8
                             LAB_0000_008e                                   XREF[1]:     0000:00c1(j)  
       0000:008e 0f 28 d0        MOVAPS     XMM2,XMM0
       0000:0091 0f 54 94        ANDPS      XMM2,xmmword ptr [SI + 0x7d90]
                 90 7d
       0000:0096 66 0f f6 ea     PSADBW     XMM5,XMM2
       0000:009a 0f 29 2e        MOVAPS     xmmword ptr [0x1268],XMM5
                 68 12
       0000:009f 8b 3e 68 12     MOV        DI,word ptr [0x1268]
       0000:00a3 66 c1 e7 10     SHL        EDI,0x10
       0000:00a7 8b 3e 70 12     MOV        DI,word ptr [0x1270]
       0000:00ab 89 f2           MOV        DX,SI
       0000:00ad 4a              DEC        DX
       0000:00ae 01 d2           ADD        DX,DX
       0000:00b0 01 d2           ADD        DX,DX
       0000:00b2 66 67 3b        CMP        EDI,dword ptr [0x7da8 + EDX]
                 ba a8 7d
                 00 00
       0000:00ba 0f 85 8f 00     JNZ        LAB_0000_014d
       0000:00be 4e              DEC        SI
       0000:00bf 85 f6           TEST       SI,SI
       0000:00c1 75 cb           JNZ        LAB_0000_008e
       0000:00c3 c6 06 78        MOV        byte ptr [0x1278],0xa
                 12 0a
       0000:00c8 8b 1e 66 12     MOV        BX,word ptr [0x1266]
       0000:00cc bf 70 7d        MOV        DI,0x7d70
       0000:00cf 85 db           TEST       BX,BX
       0000:00d1 74 0c           JZ         LAB_0000_00df
       0000:00d3 ff 0e 66 12     DEC        word ptr [0x1266]
       0000:00d7 31 c9           XOR        CX,CX
       0000:00d9 ba 14 00        MOV        DX,0x14
       0000:00dc e9 59 ff        JMP        LAB_0000_0038
```

The code between `0x66 ` - `0x78` was discussed above (it just checks the length to see if a check is needed, and if the string starts with `flag`). Proceeding that we see the following code:

```
       0000:007c 0f 28 06        MOVAPS     XMM0,xmmword ptr [0x1238]
                 38 12
       0000:0081 0f 28 2e        MOVAPS     XMM5,xmmword ptr [0x7c00]
                 00 7c
```

Both of these commands are just moving data in memory into the `xmm0` and `xmm5` registers. The instruction at `0x7c` is moving the `16` bytes of our input into the `xmm0` register, which we can see with gdb (depicted below). The instruction at `0x81` is loading the first `16` bytes of the program (since the code for the program starts at `0x7c00`, since it is a MBR, check it with gdb if you want) into the `xmm5` register. These registers are used later:

```
Breakpoint 1, 0x00007c7c in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
[!] Command 'context' failed to execute properly, reason: 'NoneType' object has no attribute 'all_registers'
gef➤  x/x $ds+0x1238
0x1238: 0x7430677b
gef➤  x/s $ds+0x1238
0x1238: "{g0ttem_b0yzzz{___"
```

and on the next line of assembly code, we have this:

```
       0000:0086 66 0f 70        PSHUFD     XMM0,XMM0,0x1e
                 c0 1e
```

This instruction essentially just rearranges our input. It inserts the contents of argument two (the `xmm0` register) into the first argument (also the `xmm0` register) at the position of the third argument `0x1e`. We can see how it rearranges it in gdb (below the input string it is dealing with is `0123456789abcdef`):

before `pshufd`:
```
Breakpoint 2, 0x00007c86 in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
[!] Command 'context' failed to execute properly, reason: 'NoneType' object has no attribute 'all_registers'
gef➤  p $xmm0
$1 = {
  v4_float = {5.5904729e+31, 1.71062063e+19, 3.23465809e+35, 1.81209302e+19},
  v2_double = {4.8112799576068541e+151, 8.9947639173637913e+151},
  v16_int8 = {0x7b, 0x67, 0x30, 0x74, 0x74, 0x65, 0x6d, 0x5f, 0x62, 0x30, 0x79, 0x7a, 0x7a, 0x7a, 0x7b, 0x5f},
  v8_int16 = {0x677b, 0x7430, 0x6574, 0x5f6d, 0x3062, 0x7a79, 0x7a7a, 0x5f7b},
  v4_int32 = {0x7430677b, 0x5f6d6574, 0x7a793062, 0x5f7b7a7a},
  v2_int64 = {0x5f6d65747430677b, 0x5f7b7a7a7a793062},
  uint128 = 0x5f7b7a7a7a7930625f6d65747430677b
}
```

after `pshufd`:
```
Breakpoint 3, 0x00007c8b in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
[!] Command 'context' failed to execute properly, reason: 'NoneType' object has no attribute 'all_registers'
gef➤  p $xmm0
$2 = {
  v4_float = {3.23465809e+35, 1.81209302e+19, 1.71062063e+19, 5.5904729e+31},
  v2_double = {8.9947639173637913e+151, 4.6979905997386182e+251},
  v16_int8 = {0x62, 0x30, 0x79, 0x7a, 0x7a, 0x7a, 0x7b, 0x5f, 0x74, 0x65, 0x6d, 0x5f, 0x7b, 0x67, 0x30, 0x74},
  v8_int16 = {0x3062, 0x7a79, 0x7a7a, 0x5f7b, 0x6574, 0x5f6d, 0x677b, 0x7430},
  v4_int32 = {0x7a793062, 0x5f7b7a7a, 0x5f6d6574, 0x7430677b},
  v2_int64 = {0x5f7b7a7a7a793062, 0x7430677b5f6d6574},
  uint128 = 0x7430677b5f6d65745f7b7a7a7a793062
}
```

The exact order that this instance of `pshufd` shuffles our input is this:
```
0.) last eight bytes first
1.) second group of four bytes
2.) first group of four bytes
```
next we have this line of assembly:

```
       0000:008b be 08 00        MOV        SI,0x8
```

This just moves the value `8` into the `si` register. This is going to be used for an iteration count for the loop we are about to enter (starts at `0x8e`) which will run `8` times.

## The loop portion of the check

Now we enter the loop. The first line just moves the contents of the `xmm0` register into the `xmm2` register:

```
                             LAB_0000_008e                                   XREF[1]:     0000:00c1(j)  
       0000:008e 0f 28 d0        MOVAPS     XMM2,XMM0
```

The next line of code ands together the `xmm2` register with the values stored at `si+0x7d90`, and stores the output in the `xmm2` register. The value at `si+0x7d90` is two `0xffffffffffffff00` segments. The end result is the eight and sixteen bytes of `xmm2` are set to `0x00`.

```
       0000:0091 0f 54 94        ANDPS      XMM2,xmmword ptr [SI + 0x7d90]
                 90 7d
```

next we have the `psadbw` instruction:

```
       0000:0096 66 0f f6 ea     PSADBW     XMM5,XMM2
```

this instruction computes the absolute sum of differences between the `xmm5` and `xmm2` registers, and stores it in the `xmm5` register. So essentially what it does is it subtracts each byte of the `xmm2` register, from each byte of the `xmm5` register. It then takes the absolute values of the differences, and adds them together. Also it does two additions, one for the first eight bytes and the second eight bytes. For an example, here we can see the `xmm2` and `xmm5` registers before and after the `psadbw` instruction (this time the input string is `{g0ttem_b0yzzz{_`):

before:
```
Breakpoint 5, 0x00007c96 in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
[!] Command 'context' failed to execute properly, reason: 'NoneType' object has no attribute 'all_registers'
gef➤  p $xmm2
$3 = {
  v4_float = {3.23463868e+35, 1.81209302e+19, 1.71060788e+19, 5.5904729e+31},
  v2_double = {8.9947639173636774e+151, 4.6979905997385002e+251},
  v16_int8 = {0x0, 0x30, 0x79, 0x7a, 0x7a, 0x7a, 0x7b, 0x5f, 0x0, 0x65, 0x6d, 0x5f, 0x7b, 0x67, 0x30, 0x74},
  v8_int16 = {0x3000, 0x7a79, 0x7a7a, 0x5f7b, 0x6500, 0x5f6d, 0x677b, 0x7430},
  v4_int32 = {0x7a793000, 0x5f7b7a7a, 0x5f6d6500, 0x7430677b},
  v2_int64 = {0x5f7b7a7a7a793000, 0x7430677b5f6d6500},
  uint128 = 0x7430677b5f6d65005f7b7a7a7a793000
}
gef➤  p $xmm5
$4 = {
  v4_float = {-134298496, -2.50091934, -1.48039995e-36, 1.93815862e-18},
  v2_double = {-8.0294250547975565, 1.241726856953559e-144},
  v16_int8 = {0xb8, 0x13, 0x0, 0xcd, 0x10, 0xf, 0x20, 0xc0, 0x83, 0xe0, 0xfb, 0x83, 0xc8, 0x2, 0xf, 0x22},
  v8_int16 = {0x13b8, 0xcd00, 0xf10, 0xc020, 0xe083, 0x83fb, 0x2c8, 0x220f},
  v4_int32 = {0xcd0013b8, 0xc0200f10, 0x83fbe083, 0x220f02c8},
  v2_int64 = {0xc0200f10cd0013b8, 0x220f02c883fbe083},
  uint128 = 0x220f02c883fbe083c0200f10cd0013b8
```

after:
```
gef➤  p $xmm5
$5 = {
  v4_float = {1.14626214e-42, 0, 1.01594139e-42, 0},
  v2_double = {4.0414569829813967e-321, 3.5819759323490374e-321},
  v16_int8 = {0x32, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xd5, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  v8_int16 = {0x332, 0x0, 0x0, 0x0, 0x2d5, 0x0, 0x0, 0x0},
  v4_int32 = {0x332, 0x0, 0x2d5, 0x0},
  v2_int64 = {0x332, 0x2d5},
  uint128 = 0x00000000000002d50000000000000332
}
```

and here are the calculations that happened:

```
0xb8 - 0x0 = 184
0x30 - 0x13 = 29
0x79 - 0x0 = 121
0xcd - 0x7a = 83
0x7a - 0x10 = 106
0x7a - 0xf = 107
0x7b - 0x20 = 91
0xc0 - 0x5f = 97
hex(184 + 29 + 121 + 83 + 106 + 107 + 91 + 97) = 0x332

0x83 - 0x0 = 131
0xe0 - 0x65 = 123
0xfb - 0x6d = 142
0x83 - 0x5f = 36
0xc8 - 0x7b = 77
0x67 - 0x2 = 101
0x30 - 0xf = 33
0x74 - 0x22 = 82
hex(131 + 123 + 142 + 36 + 77+ 101 + 33 + 82) = 0x2d5
```

Proceeding that we have the rest of the check:

```
       0000:009a 0f 29 2e        MOVAPS     xmmword ptr [0x1268],XMM5
                 68 12
       0000:009f 8b 3e 68 12     MOV        DI,word ptr [0x1268]
       0000:00a3 66 c1 e7 10     SHL        EDI,0x10
       0000:00a7 8b 3e 70 12     MOV        DI,word ptr [0x1270]
       0000:00ab 89 f2           MOV        DX,SI
       0000:00ad 4a              DEC        DX
       0000:00ae 01 d2           ADD        DX,DX
       0000:00b0 01 d2           ADD        DX,DX
       0000:00b2 66 67 3b        CMP        EDI,dword ptr [0x7da8 + EDX]
                 ba a8 7d
                 00 00
       0000:00ba 0f 85 8f 00     JNZ        LAB_0000_014d
```

Essentially what this section of code does, it takes the two values obtained from the previous `psadbw` instruction, arranges them in the `edi` register (`0x313` first then `0x2d5`) and compares it against a value stored in memory. If the check is successful, the loop continues for another iteration where it repeats the loop. The loop will run for eight times, and if we pass all of the checks, we have the correct flag. To find the values that we need to be equal to to pass this check, we can use gdb, and then just jump to the next iteration to see the next value (btw the check happens at `0x7cb2`, our input is in the `edi` register and the value we are comparing it against is in `edx+0x7da8`):

```
Breakpoint 1, 0x00007cb2 in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────── registers ────
[!] Command 'context' failed to execute properly, reason: 'NoneType' object has no attribute 'all_registers'
gef➤  x/x $edx+0x7da8
0x7dc4: 0x02df028f
gef➤  j *0x7cbe
Continuing at 0x7cbe.
Python Exception <class 'AttributeError'> 'NoneType' object has no attribute 'all_registers':

Breakpoint 1, 0x00007cb2 in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────── registers ────
[!] Command 'context' failed to execute properly, reason: 'NoneType' object has no attribute 'all_registers'
gef➤  x/x $edx+0x7da8
0x7dc0: 0x0290025d
```

and you can continue to do that until you have all eight values.

## z3

Now that we have reversed the algorithm that our input is sent through, and we know the end value it is being compared to, we can use z3 to figure out what the flag is. Below is my z3 script I wrote to find the flag:

```
# This script is from a solution here: https://github.com/DMArens/CTF-Writeups/blob/master/2017/CSAWQuals/reverse/realistic.py

# One thing about this script, it uses z3, which uses special data types so it can solve things. As a result, we have to do some special things such as write our own absolute value function instead of using pythons built in functions.

# First import the needed libraries
from pprint import pprint
from z3 import *
import struct

# Establish the values which our input will be checked against after each of the 8 iterations
resultZ = [ (0x02df, 0x028f), (0x0290, 0x025d), (0x0209, 0x0221), (0x027b, 0x0278), (0x01f9, 0x0233), (0x025e, 0x0291), (0x0229, 0x0255), (0x0211, 0x0270) ]

# Establish the first value for the xmm5 register, which is the first 16 bytes of the elf
xmm5Z = [ [0xb8, 0x13, 0x00, 0xcd, 0x10, 0x0f, 0x20, 0xc0, 0x83, 0xe0, 0xfb, 0x83, 0xc8, 0x02, 0x0f, 0x22], ]

# Establish the solver
z = Solver()

# Establish the value `0` as a z3 integer, for later use
zero = IntVal(0)

# Establish a special absolute value function for z3 values
def abz(x):
    return If( x >= 0, x, -x)

# This function does the `psadbw` (sum of absolute differences) instruction at 0x7c96
def psadbw(xmm5, xmm2):
    x = Sum([abz(x0 - x1) for x0, x1 in zip(xmm5[:8], xmm2[:8])])
    y = Sum([abz(y0 - y1) for y0, y1 in zip(xmm5[8:], xmm2[8:])])
    return x, y

# Now we will append the values in resultZ to xmm5Z. The reason for this being while xmm5Z contains the initial value that it should have, it's value carries over to each iteration. And if we passed the check, it's starting value at each iteration after the first, should be the value that we needed to get to pass the previous check.
for i in resultZ[:-1]:
    xmm5Z.append(list(map(ord, struct.pack('<Q', i[0]) + struct.pack('<Q', i[1]))))

# Now we will establush the values that z3 has control over, which is our input. We will also add a check that each byte has to be within the Ascii range, so we can type it in. We make sure to have the string `flag` in each of the characters names so we can parse them out later
inp = [Int('flag{:02}'.format(i)) for i in range(16)]
for i in inp:
    z.add(i > 30, i < 127)

# Now we will move establish z3 data types with the previously established values in xmm5Z and resultZ. This is so we can use them with z3
xmm5z = [ [IntVal(x) for x in row] for row in xmm5Z]
results = [ [IntVal(x) for x in row] for row in resultZ]

# Now here where we run the algorithm in the loop (btw when I say registers below, I don't mean the actual ones on our computer, just the data values we use to simulate the algorithm)
for i in range(8):
    # First we set the xmm5 register to it's correct value
    xmm5 = xmm5z[i]
    # We set the xmm2 register to be out input
    xmm2 = list(inp)
    # Zero out the corresponding bytes from the andps instruction at 0x7c96
    xmm2[i] = zero
    xmm2[i + 8] = zero
    x,y = psadbw(xmm5, xmm2)
    z.add(x == results[i][0])
    z.add(y == results[i][1])

# Check if it z3 can solve the problem
if z.check() == sat:
    print "z3 can solve it"
elif z.check() == unsat:
    print "The condition isn't satisified, I would recommend crying."
    exit(0)

# Model the solution (it makes z3 come up with a solution), and then filter out the flag and convert it ASCII

model = z.model()
# Create a list to store the various inputs which meet the criteria
solutions = []

# Search for our flag values that we made on line 37, and append them to solutions
for i in model.decls():
    if 'flag' in i.name():
        solutions.append((int(i.name()[4:]), chr(model[i].as_long())))

# Sort out all of the various solutions, then join them together for the needed input
solutions = sorted(solutions, key=lambda x: x[0])
solutions = [x[1] for x in solutions]
flag = ''.join(solutions)

# Next we need to essentially undo the `pshfud` instruction which occurs at `0x7c86`, that way when we give the flag and it applies the instruction, it will have the string needed to pass the eight checks
flag = flag[12:] + flag[8:12] + flag[:8]
print "flag{}".format(flag)
```

and when we run it:
```
$    python rev.py 
z3 can solve it
flag{4r3alz_m0d3_y0}
```

Just like that, we captured the flag!
