# CSAW 2015 Hackingtime

This writeups is based off of this writeup:
```
http://bruce30262.logdown.com/posts/301384--csaw-ctf-2015-hacking-time
```

Let's take a look at the binary the gave us:

```
$    file HackingTime.nes
HackingTime.nes: iNES ROM dump, 2x16k PRG, 1x8k CHR, [Vert.]
```

So we are give an NES ROM image. This means we are going to need an NES ROM/Debugger. I used the Windows version of FCEUX which you can get here:
```
http://www.fceux.com/web/download.html
```

Now when we launch the ROM with the debugger, we are presented with a little story, then tasked with figuring out a password (`f` is basically `A`). Let's just select the password `0123456789ABCDEFGHIJKM` (don't check it) and see what the memory looks like with Debug>Hex Editor:

```
000000: 4A 91 00 40 00 30 31 32 33 34 35 36 37 38 39 41
000010: 42 43 44 45 45 46 47 48 49 4A 4B 4C 4D 00 00 00
000020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000030: 00 00 00 00 00 00 4D 00 00 BB 97 C0 00 17 23 1C
```

So we can see that our password is stored in hex starting at 0x5 with `0x30` and goes all the way to 0x1C with `4D`. We can also see that it has a null byte before and after the string. So our string in total is 24 characters, and even if we leave it blank it still has the hex value 0x20 so it's just a space character. So we can assume that the password is 24 characters long. Let's give it the password and see how the memory changes:

```
000000: 4A 91 00 40 00 30 31 32 33 34 35 36 37 38 39 41
000010: 42 43 44 45 45 46 47 48 49 4A 4B 4C 4D 00 3F FF
000020: A2 F0 65 AC 26 9F DF CF 35 CF 3F 45 5C 98 E9 3B
000030: CF 32 80 ED 32 0E 4D 00 00 BB 97 C0 00 17 23 1C
```

So we can see that the memory has changed, starting at 0x1E, directly after the null byte after our password, we see 24 bytes of data has been written, the same length as our password. So it looks like the password algorithm reads the password from memory here, runs it through an algorithm, and then stores the output in memory starting at 0x1E. We can find the code for the algorithm by setting a read breakpoint at 0x5 or at any part of the password. To set a read breakpoint, just right click and set the breakpoint. Then just reenter the password, and we can see the 6502 assembly code for the password algorithm:

```
 00:82F1:A0 00     LDY #$00
 00:82F3:A9 00     LDA #$00
 00:82F5:85 3B     STA $003B = #$00
>00:82F7:B9 05 00  LDA $0005,Y @ $0005 = #$30
 00:82FA:AA        TAX
 00:82FB:2A        ROL
 00:82FC:8A        TXA
 00:82FD:2A        ROL
 00:82FE:AA        TAX
 00:82FF:2A        ROL
 00:8300:8A        TXA
 00:8301:2A        ROL
 00:8302:AA        TAX
 00:8303:2A        ROL
 00:8304:8A        TXA
 00:8305:2A        ROL
 00:8306:48        PHA
 00:8307:A5 3B     LDA $003B = #$00
 00:8309:AA        TAX
 00:830A:6A        ROR
 00:830B:8A        TXA
 00:830C:6A        ROR
 00:830D:AA        TAX
 00:830E:6A        ROR
 00:830F:8A        TXA
 00:8310:6A        ROR
 00:8311:85 3B     STA $003B = #$00
 00:8313:68        PLA
 00:8314:18        CLC
 00:8315:65 3B     ADC $003B = #$00
 00:8317:59 5E 95  EOR $955E,Y @ $955E = #$70
 00:831A:85 3B     STA $003B = #$00
 00:831C:AA        TAX
 00:831D:2A        ROL
 00:831E:8A        TXA
 00:831F:2A        ROL
 00:8320:AA        TAX
 00:8321:2A        ROL
 00:8322:8A        TXA
 00:8323:2A        ROL
 00:8324:AA        TAX
 00:8325:2A        ROL
 00:8326:8A        TXA
 00:8327:2A        ROL
 00:8328:AA        TAX
 00:8329:2A        ROL
 00:832A:8A        TXA
 00:832B:2A        ROL
 00:832C:59 76 95  EOR $9576,Y @ $9576 = #$20
 00:832F:99 1E 00  STA $001E,Y @ $001E = #$00
 00:8332:C8        INY
 00:8333:C0 18     CPY #$18
 00:8335:D0 C0     BNE $82F7
 00:8337:A0 00     LDY #$00
 00:8339:B9 1E 00  LDA $001E,Y @ $001E = #$00
 00:833C:D0 08     BNE $8346
 00:833E:C8        INY
 00:833F:C0 18     CPY #$18
 00:8341:D0 F6     BNE $8339
 00:8343:A9 01     LDA #$01
 00:8345:60        RTS -----------------------------------------
```

Let's break this up into pieces to reverse. To help with this, I've set execute breakpoints at the memory address `8307`, `8311`, `8317`, `831A`, `832C`, and `832F`.

```
 00:82F1:A0 00     LDY #$00
 00:82F3:A9 00     LDA #$00
 00:82F5:85 3B     STA $003B = #$00
```

This code just loads the accumulator and y registers with the value `0x0`, and then also stores the same value in the memory location 0x3B, which we can see with the hex editor is that value (it's stored a few bytes over from the password output), which we will be using later. So effectively this converts into the following Python code:
```
i = 0
y = 0
```

```
 00:82F7:B9 05 00  LDA $0005,Y @ $0005 = #$30
 00:82FA:AA        TAX
 00:82FB:2A        ROL
 00:82FC:8A        TXA
 00:82FD:2A        ROL
 00:82FE:AA        TAX
 00:82FF:2A        ROL
 00:8300:8A        TXA
 00:8301:2A        ROL
 00:8302:AA        TAX
 00:8303:2A        ROL
 00:8304:8A        TXA
 00:8305:2A        ROL
 00:8306:48        PHA
```

So we can see here that it loads the password character from memory into the accumulator register, then rotates it by to the left. Let's check it by hand:

```
0x30:    00110000

Shifted by 1 to the left
0x60:    01100000

Shifted by 2 to the left
0xc0:    11000000

Shifted by 3 to the left
0x81:    10000001
```

As we can see, the value we got by doing it by hand is the same that is currently in the accumulator register, so we should be correct. Lastly we see that there is a `PHA` instruction, which pushes whatever is in the Accumulator register to the stack, since we need to clear the accumulator register for other operations however still hold the value 0x81. So this assembly code converts to the following python code:

```
x = RotateLeft(inp[i], 3)
```

```
 00:8307:A5 3B     LDA $003B = #$00
 00:8309:AA        TAX
 00:830A:6A        ROR
 00:830B:8A        TXA
 00:830C:6A        ROR
 00:830D:AA        TAX
 00:830E:6A        ROR
 00:830F:8A        TXA
 00:8310:6A        ROR
>00:8311:85 3B     STA $003B = #$00
```

Here we can see that the value of whatever is stored at 0x3B is being loaded into the accumulator register, shifted to the right twice, then written to 0x3B. We know that the value stored at 0x3B is zero, and zero shifted to the right or left however many times is still zero, so the value of the accumulator register should be 0 (which it is). This assembly code converts into the following python code:
```
y = BitVecVal(0, 8)
y = BitVecVal(0, 8)
```

```
 00:8313:68        PLA
 00:8314:18        CLC
 00:8315:65 3B     ADC $003B = #$00
```

Here we can see that it pulls the 0x81 function back from the stack and into the accumulator register, then adds the value of 0x3B to it, and stores the output in the accumulator register. Since the value at 0x3B is zero, the accumulator remains at the value of 0x81. So this translates into the following python code:

```
x = x + y
```

```
 00:8317:59 5E 95  EOR $955E,Y @ $955E = #$70
 00:831A:85 3B     STA $003B = #$00
```

Here we can see it xors the accumulator register with the value stored in memory at 0x955E, which we can see from the hex editor is this

```
70 30 53 A1 D3 70 3F 64 B3 16 E4 04 5F 3A EE 42 B1 A1 37 15 6E 88 2A AB
```

So we can see that just like our password this has 24 bytes. In addition to that we can see that it is xoring our first character (well where it is in the encryption process) with the first character of the hex string, so it should xor our second character with the second bit, third with the third, etc. Let's do the xor by hand:

```
0x81:    10000001    
0x70:    01110000

Xor:    11110001 = 0xF1
```

so when we did the xor, we see that we got the value 0xF1, which is the same as the value stored in the accumulator register, so that checks out. Lastly we see that it writes the value of the accumulator to 0x3B, so this assembly code converts to the following python code:

```
xor1 = "703053A1D3703F64B316E4045F3AEE42B1A137156E882AAB".decode("hex")
x = x ^ xor1[i]
y = x
```

```
 00:831C:AA        TAX
 00:831D:2A        ROL
 00:831E:8A        TXA
 00:831F:2A        ROL
 00:8320:AA        TAX
 00:8321:2A        ROL
 00:8322:8A        TXA
 00:8323:2A        ROL
 00:8324:AA        TAX
 00:8325:2A        ROL
 00:8326:8A        TXA
 00:8327:2A        ROL
 00:8328:AA        TAX
 00:8329:2A        ROL
 00:832A:8A        TXA
 00:832B:2A        ROL
```

So we can see again that it is shifting the accumulator register over to the left, this time by 4. At the start of this operation, the accumulator register is equal to 0xF1, so let's work this out by hand and check it:

```
0xF1:    11110001

Shifted 1 to the left
0xE3:    11100011

Shifted 2 to the left
0xC7:    11000111

Shifted 3 to the left
0x8F:    10001111

Shifted 4 to the left
0x1F:    00011111
```

So at the end, we should have the value 0x1F in the accumulator register which we do. So this assembly code converts to the following python code:

```
x = RotateLeft(x, 4)
```

```
 00:832C:59 76 95  EOR $9576,Y @ $9576 = #$20
>00:832F:99 1E 00  STA $001E,Y @ $001E = #$00
```

Here we see another `EOR` instruction which xors the accumulator register with the value stored at 9576:

```
20 AC 7A 25 D7 9C C2 1D 58 D0 13 25 96 6A DC 7E 2E B4 B4 10 CB 1D C2 66
```

We can also see that it xors the bytes in the same order as the previous xor, so the first character by 0x20, second by 0xAC, third by 0x7A. After that we see that it writes the value stored in the accumulator register to the memory address 0x1E, which we can see is the next byte after the null terminator that ends out password, which is where we would expect the output of the function to go to (based upon our previous findings). So this converts to the following python code:

```
xor2 = "20AC7A25D79CC21D58D01325966ADC7E2EB4B410CB1DC266".decode("hex")
x = x ^ xor2[i]
```

```
 00:8332:C8        INY
 00:8333:C0 18     CPY #$18
 00:8335:D0 C0     BNE $82F7
 00:8337:A0 00     LDY #$00
 00:8339:B9 1E 00  LDA $001E,Y @ $001F = #$FF
 00:833C:D0 08     BNE $8346
 00:833E:C8        INY
 00:833F:C0 18     CPY #$18
 00:8341:D0 F6     BNE $8339
 00:8343:A9 01     LDA #$01
```

I didn't set a breakpoint after this, however, we don't need to to see what it is doing. First it increments the `Y` register by one, then checks to see if it is equal to 0x18 (which is the same length as our password). If it isn't then it jumps back to the start of this function and runs the encryption algorithm. After that it will load a zero into the Y register, load the value of the output of the encryption algorithm (this case stored at 0x1E) and compare them. If not it will branch to a function at 0x8346 which essentially just fails us (if we go there, we fail the password check). If it doesn't fail, then it simply loop through checking the output for each character of the password. So essentially this checks to see if the output of the encryption algorithm is zero for all of the characters, and does the work of a for loop which converts to the following python code:
```
for i in xrange(24):
    if x[i] != 0:
        break
```

So we know how the encryption algorithm works, and what output we need. Now we can just use z3 solver, which is a theorem prover designed by Microsoft to find the input needed to get the output we need (24 zeros). Quick Z3 solver intro, you can give it a formula, it will tell you if it can be solved, and some values to solve it:

```
$    python
Python 2.7.13 (default, Jan 19 2017, 14:48:08)
[GCC 6.3.0 20170118] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from z3 import *
>>> x = Int('x')
>>> y = Int('y')
>>> z = Solver()
>>> z.add(x > y, y < 5)
>>> z.check()
sat
>>> z.model()
[y = 4, x = 5]
```

As we can see, we established two integers and a solver, added a constraint to the solver, checked the solver to ensure that it is satisfiable, then modeled it to see what values will actually satisfy it. keep in mind since the registers is 6502 assembly can only have 8 bits, we have to treat them as only capable of 8 bits in our python. Now we can use this tool in the same manner to find what input will give us 24 zeroes, with having the encryption algorithm be the constraints. here is the python code for it:

```
#First import the z3 library
from z3 import *

#Import the two hex strings which we will be xoring
xor1 = [ 0x70, 0x30, 0x53, 0xA1, 0xD3, 0x70, 0x3F, 0x64, 0xB3, 0x16, 0xE4, 0x04, 0x5F, 0x3A, 0xEE, 0x42, 0xB1, 0xA1, 0x37, 0x15, 0x6E, 0x88, 0x2A, 0xAB]
xor2 = [ 0x20, 0xAC, 0x7A, 0x25, 0xD7, 0x9C, 0xC2, 0x1D, 0x58, 0xD0, 0x13, 0x25, 0x96, 0x6A, 0xDC, 0x7E, 0x2E, 0xB4, 0xB4, 0x10, 0xCB, 0x1D, 0xC2, 0x66]


def decrypt(inp, z):
    #Define the encryption algorithm constraints
    y = BitVecVal(0, 8)
    for i in xrange(24):
        x = RotateLeft(inp[i], 3)
        y = RotateRight(y, 2)
        x = x + y
        x = x ^ xor1[i]
        y = x
        x = RotateLeft(x, 4)
        x = x ^ xor2[i]
        z.add(x == 0)

    #Check if the conditions are satisfiable, if it is model it and get the password
    if z.check() == sat:
        print "The condition is: " + str(z.check())
        solve = z.model()
        cred = ""
        #Sort out the data, and print the passord
        for i in xrange(24):
            cred = cred + chr(int(str(solve[inp[i]])))
        print cred
    else:
        #Something failed and the condition isn't satisifiable, I would recogmend crying
        print "The condition is: " + str(z.check())


#Establish the solver, and the input array
z = Solver()
inp = []

#We need to add an 8 bit vector for every character in our password
for i in xrange(24):
    b = BitVec("%d" % i, 8)
    inp.append(b)

#Now pass the list, and the solver to the decrypt function
decrypt(inp, z)
```

and when we run it:

```
$    python rev.py
The condition is: sat
NOHACK4UXWRATHOFKFUHRERX
```

So we get the string `NOHACK4UXWRATHOFKFUHRERX` which happens to be the password, and also the flag for this challenge. Just like that we solved this challenge!