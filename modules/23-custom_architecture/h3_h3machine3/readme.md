# h3 h3machine3

For this challenge, let's look at the assembly code:

```
$    ./h3disasm challenge3.h3i
0001: 12010000 push +0000
0002: 12040400 push 0004
0003: 11000000 swap
0004: 12010100 push +0001
0005: 32000000 not
0006: 1204ff00 push 00ff
0007: 30000000 and
0008: 33000000 xor
0009: 38040800 rotate 0008
000a: 11000000 swap
000b: 21040100 sub 0001
000c: 41040e00 jz 000e
000d: 40040300 jmp 0003
000e: 11000000 swap
000f: 21021600 sub $0016
0010: 41041200 jz 0012
0011: 40041500 jmp 0015
0012: 10000000 drop
0013: 10000000 drop
0014: 50040080 setf 8000
0015: 00000000 halt
0016: 5b6d517c
```

So this program only has 16 instructions. However we can see what appears to be a for loop here:

```
0002: 12040400 push 0004
0003: 11000000 swap
0004: 12010100 push +0001
0005: 32000000 not
0006: 1204ff00 push 00ff
0007: 30000000 and
0008: 33000000 xor
0009: 38040800 rotate 0008
000a: 11000000 swap
000b: 21040100 sub 0001
000c: 41040e00 jz 000e
000d: 40040300 jmp 0003
```

Here what is happening is it is pushing the value `0004` onto the stack, running the binary operation not on it to give us `fffb`, then anding it with `00ff` to give us `00fb`. Proceeding that xors that with our input, so effectively xoring the least significant byte of our input with `fb`. Then it shifts our input to the right by `0x8` bits (or one byte). Proceeding that it decrements the iteration count by one, and if it is not equal to zero it will rerun the loop. Let's see how many times it runs:

```
$    ./h3emu --trace challenge3.h3i 00000000
0001: push +0000
0002: push 0004
0003: swap
0004: push +0001
0005: not
0006: push 00ff
0007: and
0008: xor
0009: rotate 0008
000a: swap
000b: sub 0001
000c: jz 000e
000d: jmp 0003
0003: swap
0004: push +0001
0005: not
0006: push 00ff
0007: and
0008: xor
0009: rotate 0008
000a: swap
000b: sub 0001
000c: jz 000e
000d: jmp 0003
0003: swap
0004: push +0001
0005: not
0006: push 00ff
0007: and
0008: xor
0009: rotate 0008
000a: swap
000b: sub 0001
000c: jz 000e
000d: jmp 0003
0003: swap
0004: push +0001
0005: not
0006: push 00ff
0007: and
0008: xor
0009: rotate 0008
000a: swap
000b: sub 0001
000c: jz 000e
000e: swap
000f: sub $0016
0010: jz 0012
0011: jmp 0015
0015: halt
Stack:
ffff: 00000000
fffe: 00000000
fffd: 82ac8fa0

Registers:
IP: 0016
SP: fffd
Flags:   
```

So here we can see that the loop is ran 4 times. So effectively it just xors each byte of our input (with our input being a hex string). One thing to notice is that the byte it xors our input by is incremented by one each time the loop is run. So our least significant byte is xored by `0xfb`, or second least significant byte is xored by `0xfc`, our third by `0xfd`, and our fourth by `0xfe`.

Continuing after that process, let's look at what happens when the loop finishes:

```
000e: 11000000 swap
000f: 21021600 sub $0016
0010: 41041200 jz 0012
0011: 40041500 jmp 0015
0012: 10000000 drop
0013: 10000000 drop
0014: 50040080 setf 8000
0015: 00000000 halt
0016: 5b6d517c
```

So looking here, we can essentially see that it is subtracting the result of the previous loop by `0x7c516d5b` (remember we are dealing with a least-endian architecture here) is equal to zero. So effectively in order to solve this challenge, we just have to find out what hex string will output `0x7c516d5b` from the previous loop. Since we have what the output should be, and what it is being xored by, we can just xor the two together to get the input:

```
>>> hex(0x5b ^ 0xfb)
'0xa0'
>>> hex(0x6d ^ 0xfc)
'0x91'
>>> hex(0x51 ^ 0xfd)
'0xac'
>>> hex(0x7c ^ 0xfe)
'0x82'
```

and when we put it all toghether:

```
$	./h3emu --trace challenge3.h3i 82ac91a0
0001: push +0000
0002: push 0004
0003: swap
0004: push +0001
0005: not
0006: push 00ff
0007: and
0008: xor
0009: rotate 0008
000a: swap
000b: sub 0001
000c: jz 000e
000d: jmp 0003
0003: swap
0004: push +0001
0005: not
0006: push 00ff
0007: and
0008: xor
0009: rotate 0008
000a: swap
000b: sub 0001
000c: jz 000e
000d: jmp 0003
0003: swap
0004: push +0001
0005: not
0006: push 00ff
0007: and
0008: xor
0009: rotate 0008
000a: swap
000b: sub 0001
000c: jz 000e
000d: jmp 0003
0003: swap
0004: push +0001
0005: not
0006: push 00ff
0007: and
0008: xor
0009: rotate 0008
000a: swap
000b: sub 0001
000c: jz 000e
000e: swap
000f: sub $0016
0010: jz 0012
0012: drop
0013: drop
0014: setf 8000
0015: halt
Stack:
ffff: flag{82ac91a0}

Registers:
IP: 0016
SP: ffff
Flags: Z F
```

Just like that we captured the flag!