# h3 h3machine1

Let's take a look at the disassembly for the binary file we are given for this challenge:

```
$    ./h3disasm challenge1.h3i
0001: 12040000 push 0000
0002: 41040800 jz 0008
0003: 12044281 push 8142
0004: 37041000 lshift 0010
0005: 1204c0a9 push a9c0
0006: 31000000 or
0007: 50040080 setf 8000
0008: 00000000 halt
```

So we can see here, the assembly code for this program consists of just 8 instructions. The second address we can see a jz instruction, which should jump to the address `0008`, which just runs the halt instruction, thus ending the program. Because of this, we will never be able to execute the instructions between `0003` and `0007`. Looking at the instructions between the addresses `0003` to `0007` we see that it pushes values onto the stack, and runs several different binary operations on it. It is probably generating the flag. Since we have the wonderful documentation, we know a lot regarding the assembly, we can simply patch the code to jump to the instruction `0003` instead of `0008`, thus running the segment of code that we should be missing. To patch it, we will need a hex editor. For this you can use bless:

```
$    sudo apt-get install bless
```

This is the program before we patch it:

```
00000000: 00 00 00 00 12 04 00 00 41 04 08 00 12 04 42 81  ........A.....B.
00000010: 37 04 10 00 12 04 c0 a9 31 00 00 00 50 04 00 80  7.......1...P...
00000020: 00 00 00 00                                      ....
```

This is the program after we patch it:

```
00000000: 00 00 00 00 12 04 00 00 41 04 03 00 12 04 42 81  ........A.....B.
00000010: 37 04 10 00 12 04 c0 a9 31 00 00 00 50 04 00 80  7.......1...P...
00000020: 00 00 00 00                                      ....
```
As you can see, we only had to change one byte (the argument to the jz instruction). Let's try to run the patched version now (I used the `--trace` option so it printed all of the instructions, and the stack contents):

```
$    ./h3emu --trace challenge1-patched.h3i
0001: push 0000
0002: jz 0003
0003: push 8142
0004: lshift 0010
0005: push a9c0
0006: or
0007: setf 8000
0008: halt
Stack:
ffff: 00000000
fffe: flag{8142a9c0}

Registers:
IP: 0009
SP: fffe
Flags:   F
```

When we run the patched version, we can see that the rest of the code does run. Even more so, we can see that the flag is loaded onto the stack for us. Just like that, we captured the flag.
