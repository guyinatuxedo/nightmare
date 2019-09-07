# h3 h3machine2

For this part, I found it helpful to patch in halts into the code (just change the opcode for the instruction you want to break out to the opcode of halt which is 00)

Let's take a look at the assembly code for this challenge:

```
$    ./h3disasm challenge2.h3i
0001: 12040000 push 0000
0002: 60041400 call 0014
0003: 41040500 jz 0005
0004: 00000000 halt
0005: 10000000 drop
0006: 60042400 call 0024
0007: 41040900 jz 0009
0008: 00000000 halt
0009: 10000000 drop
000a: 60043400 call 0034
000b: 41040d00 jz 000d
000c: 00000000 halt
000d: 10000000 drop
000e: 60044400 call 0044
000f: 41041100 jz 0011
0010: 00000000 halt
0011: 10000000 drop
0012: 50040080 setf 8000
0013: 00000000 halt
0014: 11000000 swap
0015: 12040c10 push 100c
0016: 37041000 lshift 0010
0017: 1204852b push 2b85
0018: 31000000 or
0019: 21000000 sub
001a: 41041c00 jz 001c
001b: 61000000 ret
001c: 10000000 drop
001d: 12040c10 push 100c
001e: 37041000 lshift 0010
001f: 1204852b push 2b85
0020: 31000000 or
0021: 33000000 xor
0022: 12040000 push 0000
0023: 61000000 ret
0024: 11000000 swap
0025: 12040187 push 8701
0026: 37041000 lshift 0010
0027: 12049803 push 0398
0028: 31000000 or
0029: 21000000 sub
002a: 41042c00 jz 002c
002b: 61000000 ret
002c: 10000000 drop
002d: 12040187 push 8701
002e: 37041000 lshift 0010
002f: 12049803 push 0398
0030: 31000000 or
0031: 33000000 xor
0032: 12040000 push 0000
0033: 61000000 ret
0034: 11000000 swap
0035: 12040918 push 1809
0036: 37041000 lshift 0010
0037: 1204d9f0 push f0d9
0038: 31000000 or
0039: 21000000 sub
003a: 41043c00 jz 003c
003b: 61000000 ret
003c: 10000000 drop
003d: 12040918 push 1809
003e: 37041000 lshift 0010
003f: 1204d9f0 push f0d9
0040: 31000000 or
0041: 33000000 xor
0042: 12040000 push 0000
0043: 61000000 ret
0044: 11000000 swap
0045: 1204f5ab push abf5
0046: 37041000 lshift 0010
0047: 1204e7ed push ede7
0048: 31000000 or
0049: 21000000 sub
004a: 41044c00 jz 004c
004b: 61000000 ret
004c: 10000000 drop
004d: 1204f5ab push abf5
004e: 37041000 lshift 0010
004f: 1204e7ed push ede7
0050: 31000000 or
0051: 33000000 xor
0052: 12040000 push 0000
0053: 61000000 ret
```

First off the bat, we can see that there are 53 instructions (a lot more than the previous challenge). Before we start going through the assembly, let's run it:

```
$    ./h3emu --trace challenge2.h3i
0001: push 0000
0002: call 0014
0014: swap
Stack:

Registers:
IP: 0015
SP: 0000
Flags: Z  
Stack underflow!
$    ./h3emu --trace challenge2.h3i 15935728
0001: push 0000
0002: call 0014
0014: swap
0015: push 100c
0016: lshift 0010
0017: push 2b85
0018: or
0019: sub
001a: jz 001c
001b: ret
0003: jz 0005
0004: halt
Stack:
ffff: 00000000
fffe: 05872ba3

Registers:
IP: 0005
SP: fffe
Flags:    
```

So we can see that the program requires input. We can also see that our input that we entered doesn't appear to be on the stack, so after it scans it in it probably alters it.

At the start of the program, we can see that it calls the address 14. Let's see what that does:

```
0014: 11000000 swap
0015: 12040c10 push 100c
0016: 37041000 lshift 0010
0017: 1204852b push 2b85
0018: 31000000 or
0019: 21000000 sub
001a: 41041c00 jz 001c
```

So we can see that it pushes the hex value `0x100c`, shifts it over to the right by two bytes (so it is now 0x100c0000), then pushes `0x2b85` onto the stack. Proceeding that it ors the two hex strings together, leaving us with `0x100c2b85`, then runs the sub instruction with our input and that hex string. If the output is zero, it will jump to the address `001c`, so we probably need to give it the input `100c2b85` (with our input being a hex string) in order to pass this check (btw the program interprets our input as hex characters, not asci):

```
$    ./h3emu --trace challenge2.h3i 100c2b85
0001: push 0000
0002: call 0014
0014: swap
0015: push 100c
0016: lshift 0010
0017: push 2b85
0018: or
0019: sub
001a: jz 001c
001c: drop
001d: push 100c
001e: lshift 0010
001f: push 2b85
0020: or
0021: xor
0022: push 0000
0023: ret
0003: jz 0005
0005: drop
0006: call 0024
0024: swap
Stack:

Registers:
IP: 0025
SP: 0000
Flags: Z  
Stack underflow!
```

So we can see that we passed the check. Proceeding that, it says that there is another Stack underflow, so we need to give it more input:

```
$    ./h3emu --trace challenge2.h3i 15935728 100c2b85
0001: push 0000
0002: call 0014
0014: swap
0015: push 100c
0016: lshift 0010
0017: push 2b85
0018: or
0019: sub
001a: jz 001c
001c: drop
001d: push 100c
001e: lshift 0010
001f: push 2b85
0020: or
0021: xor
0022: push 0000
0023: ret
0003: jz 0005
0005: drop
0006: call 0024
0024: swap
0025: push 8701
0026: lshift 0010
0027: push 0398
0028: or
0029: sub
002a: jz 002c
002b: ret
0007: jz 0009
0008: halt
Stack:
ffff: 100c2b85
fffe: 8e925390

Registers:
IP: 0009
SP: fffe
Flags:  C
```

So we can see with the new input, that there is a new check. This new check is seeing if our second input is equal to the hex string `87010398`. Let's see what happens when we pass it that hex string for the second input:

```
$    ./h3emu --trace challenge2.h3i 87010398 100c2b85
0001: push 0000
0002: call 0014
0014: swap
0015: push 100c
0016: lshift 0010
0017: push 2b85
0018: or
0019: sub
001a: jz 001c
001c: drop
001d: push 100c
001e: lshift 0010
001f: push 2b85
0020: or
0021: xor
0022: push 0000
0023: ret
0003: jz 0005
0005: drop
0006: call 0024
0024: swap
0025: push 8701
0026: lshift 0010
0027: push 0398
0028: or
0029: sub
002a: jz 002c
002c: drop
002d: push 8701
002e: lshift 0010
002f: push 0398
0030: or
0031: xor
0032: push 0000
0033: ret
0007: jz 0009
0009: drop
000a: call 0034
0034: swap
Stack:

Registers:
IP: 0035
SP: 0000
Flags: Z  
Stack underflow!
```

So we can see that we passed the check, and it expects more input. So for the first two checks, it just sees if our input is equal to a certain hex string. Let's see how far we can get by essentially replacing the same process of sending it the hex string that it looks for:

```
$    ./h3emu --trace challenge2.h3i 15935728 87010398 100c2b85
0001: push 0000
0002: call 0014
0014: swap
0015: push 100c
0016: lshift 0010
0017: push 2b85
0018: or
0019: sub
001a: jz 001c
001c: drop
001d: push 100c
001e: lshift 0010
001f: push 2b85
0020: or
0021: xor
0022: push 0000
0023: ret
0003: jz 0005
0005: drop
0006: call 0024
0024: swap
0025: push 8701
0026: lshift 0010
0027: push 0398
0028: or
0029: sub
002a: jz 002c
002c: drop
002d: push 8701
002e: lshift 0010
002f: push 0398
0030: or
0031: xor
0032: push 0000
0033: ret
0007: jz 0009
0009: drop
000a: call 0034
0034: swap
0035: push 1809
0036: lshift 0010
0037: push f0d9
0038: or
0039: sub
003a: jz 003c
003b: ret
000b: jz 000d
000c: halt
Stack:
ffff: 970d281d
fffe: fd89664f

Registers:
IP: 000d
SP: fffe
Flags:  C
```
```
$    ./h3emu --trace challenge2.h3i 1809f0d9 87010398 100c2b85
0001: push 0000
0002: call 0014
0014: swap
0015: push 100c
0016: lshift 0010
0017: push 2b85
0018: or
0019: sub
001a: jz 001c
001c: drop
001d: push 100c
001e: lshift 0010
001f: push 2b85
0020: or
0021: xor
0022: push 0000
0023: ret
0003: jz 0005
0005: drop
0006: call 0024
0024: swap
0025: push 8701
0026: lshift 0010
0027: push 0398
0028: or
0029: sub
002a: jz 002c
002c: drop
002d: push 8701
002e: lshift 0010
002f: push 0398
0030: or
0031: xor
0032: push 0000
0033: ret
0007: jz 0009
0009: drop
000a: call 0034
0034: swap
0035: push 1809
0036: lshift 0010
0037: push f0d9
0038: or
0039: sub
003a: jz 003c
003c: drop
003d: push 1809
003e: lshift 0010
003f: push f0d9
0040: or
0041: xor
0042: push 0000
0043: ret
000b: jz 000d
000d: drop
000e: call 0044
0044: swap
Stack:

Registers:
IP: 0045
SP: 0000
Flags: Z  
Stack underflow!
```
```
$    ./h3emu --trace challenge2.h3i 15935728 1809f0d9 87010398 100c2b85
0001: push 0000
0002: call 0014
0014: swap
0015: push 100c
0016: lshift 0010
0017: push 2b85
0018: or
0019: sub
001a: jz 001c
001c: drop
001d: push 100c
001e: lshift 0010
001f: push 2b85
0020: or
0021: xor
0022: push 0000
0023: ret
0003: jz 0005
0005: drop
0006: call 0024
0024: swap
0025: push 8701
0026: lshift 0010
0027: push 0398
0028: or
0029: sub
002a: jz 002c
002c: drop
002d: push 8701
002e: lshift 0010
002f: push 0398
0030: or
0031: xor
0032: push 0000
0033: ret
0007: jz 0009
0009: drop
000a: call 0034
0034: swap
0035: push 1809
0036: lshift 0010
0037: push f0d9
0038: or
0039: sub
003a: jz 003c
003c: drop
003d: push 1809
003e: lshift 0010
003f: push f0d9
0040: or
0041: xor
0042: push 0000
0043: ret
000b: jz 000d
000d: drop
000e: call 0044
0044: swap
0045: push abf5
0046: lshift 0010
0047: push ede7
0048: or
0049: sub
004a: jz 004c
004b: ret
000f: jz 0011
0010: halt
Stack:
ffff: 8f04d8c4
fffe: 699d6941

Registers:
IP: 0011
SP: fffe
Flags:  C
```
```
./h3emu --trace challenge2.h3i abf5ede7 1809f0d9 87010398 100c2b85
0001: push 0000
0002: call 0014
0014: swap
0015: push 100c
0016: lshift 0010
0017: push 2b85
0018: or
0019: sub
001a: jz 001c
001c: drop
001d: push 100c
001e: lshift 0010
001f: push 2b85
0020: or
0021: xor
0022: push 0000
0023: ret
0003: jz 0005
0005: drop
0006: call 0024
0024: swap
0025: push 8701
0026: lshift 0010
0027: push 0398
0028: or
0029: sub
002a: jz 002c
002c: drop
002d: push 8701
002e: lshift 0010
002f: push 0398
0030: or
0031: xor
0032: push 0000
0033: ret
0007: jz 0009
0009: drop
000a: call 0034
0034: swap
0035: push 1809
0036: lshift 0010
0037: push f0d9
0038: or
0039: sub
003a: jz 003c
003c: drop
003d: push 1809
003e: lshift 0010
003f: push f0d9
0040: or
0041: xor
0042: push 0000
0043: ret
000b: jz 000d
000d: drop
000e: call 0044
0044: swap
0045: push abf5
0046: lshift 0010
0047: push ede7
0048: or
0049: sub
004a: jz 004c
004c: drop
004d: push abf5
004e: lshift 0010
004f: push ede7
0050: or
0051: xor
0052: push 0000
0053: ret
000f: jz 0011
0011: drop
0012: setf 8000
0013: halt
Stack:
ffff: flag{24f13523}

Registers:
IP: 0014
SP: ffff
Flags: Z F
```

Just like that, we captured the flag.