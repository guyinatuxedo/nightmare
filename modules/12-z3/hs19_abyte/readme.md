# hsctf 2019 A-Byte

Let's take a look at the binary:

```
$	file a-byte 
a-byte: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=88fe0ee8aed1a070d6555c7e9866e364a40f686c, stripped
$	./a-byte 159
u do not know da wae
```

So we can see that we are dealing with a `64` bit function, that takes in data by passing arguments to the program. Looking through the functions, we find `FUN_0010073a` which appears to hold most of the code that is relevant to us.

```
undefined8 FUN_0010073a(int argc,long argv)

{
  long lVar1;
  int iVar2;
  undefined8 uVar3;
  size_t inputLen;
  long in_FS_OFFSET;
  int i;
  char desiredOutput;
  char *inputPtr;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  if (argc == 2) {
    inputPtr = *(char **)(argv + 8);
    inputLen = strlen(inputPtr);
    if ((int)inputLen == 0x23) {
      i = 0;
      while (i < 0x23) {
        inputPtr[(long)i] = inputPtr[(long)i] ^ 1;
        i = i + 1;
      }
      desiredOutput = 'i';
      iVar2 = strcmp(&desiredOutput,inputPtr);
      if (iVar2 == 0) {
        puts("Oof, ur too good");
        uVar3 = 0;
        goto LAB_00100891;
      }
    }
  }
  puts("u do not know da wae");
  uVar3 = 0xffffffff;
LAB_00100891:
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar3;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

So we can see that it only wants a single argument in addition to the program name (argc has to be two). Then it checks to see if our input that we gave it via and argument is `0x23` bytes long. If so it will then go through and set all of the bytes equal to the byte xored by 1. It then checks to see if our input is equal to `desiredOutput`, and if it is it looks like we solved the challenge. Looking at the decompiled code, it looks like `desiredOutput` is set equal to just the character `i`. The decompilation got that wrong, and looking at the assembly code shows us what it is actually set equal to:

```
        001007d5 c6 45 d0 69     MOV        byte ptr [RBP + desiredOutput],0x69
        001007d9 c6 45 d1 72     MOV        byte ptr [RBP + local_37],0x72
        001007dd c6 45 d2 62     MOV        byte ptr [RBP + local_36],0x62
        001007e1 c6 45 d3 75     MOV        byte ptr [RBP + local_35],0x75
        001007e5 c6 45 d4 67     MOV        byte ptr [RBP + local_34],0x67
        001007e9 c6 45 d5 7a     MOV        byte ptr [RBP + local_33],0x7a
        001007ed c6 45 d6 76     MOV        byte ptr [RBP + local_32],0x76
        001007f1 c6 45 d7 31     MOV        byte ptr [RBP + local_31],0x31
        001007f5 c6 45 d8 76     MOV        byte ptr [RBP + local_30],0x76
        001007f9 c6 45 d9 5e     MOV        byte ptr [RBP + local_2f],0x5e
        001007fd c6 45 da 78     MOV        byte ptr [RBP + local_2e],0x78
        00100801 c6 45 db 31     MOV        byte ptr [RBP + local_2d],0x31
        00100805 c6 45 dc 74     MOV        byte ptr [RBP + local_2c],0x74
        00100809 c6 45 dd 5e     MOV        byte ptr [RBP + local_2b],0x5e
        0010080d c6 45 de 6a     MOV        byte ptr [RBP + local_2a],0x6a
        00100811 c6 45 df 6f     MOV        byte ptr [RBP + local_29],0x6f
        00100815 c6 45 e0 31     MOV        byte ptr [RBP + local_28],0x31
        00100819 c6 45 e1 76     MOV        byte ptr [RBP + local_27],0x76
        0010081d c6 45 e2 5e     MOV        byte ptr [RBP + local_26],0x5e
        00100821 c6 45 e3 65     MOV        byte ptr [RBP + local_25],0x65
        00100825 c6 45 e4 35     MOV        byte ptr [RBP + local_24],0x35
        00100829 c6 45 e5 5e     MOV        byte ptr [RBP + local_23],0x5e
        0010082d c6 45 e6 76     MOV        byte ptr [RBP + local_22],0x76
        00100831 c6 45 e7 40     MOV        byte ptr [RBP + local_21],0x40
        00100835 c6 45 e8 32     MOV        byte ptr [RBP + local_20],0x32
        00100839 c6 45 e9 5e     MOV        byte ptr [RBP + local_1f],0x5e
        0010083d c6 45 ea 39     MOV        byte ptr [RBP + local_1e],0x39
        00100841 c6 45 eb 69     MOV        byte ptr [RBP + local_1d],0x69
        00100845 c6 45 ec 33     MOV        byte ptr [RBP + local_1c],0x33
        00100849 c6 45 ed 63     MOV        byte ptr [RBP + local_1b],0x63
        0010084d c6 45 ee 40     MOV        byte ptr [RBP + local_1a],0x40
        00100851 c6 45 ef 31     MOV        byte ptr [RBP + local_19],0x31
        00100855 c6 45 f0 33     MOV        byte ptr [RBP + local_18],0x33
        00100859 c6 45 f1 38     MOV        byte ptr [RBP + local_17],0x38
        0010085d c6 45 f2 7c     MOV        byte ptr [RBP + local_16],0x7c
        00100861 c6 45 f3 00     MOV        byte ptr [RBP + local_15],0x0
```

So we can see that we are dealing with a char array on the stack, that it moves in input one byte at a time. We can see that the amount of bytes it moves in is `35` (excluding the null byte terminator at the end), the same amount for the length of the data we pass in as an argument. So we know what input we control, we know the algorithm that it is passed through, and we know what the end result will need to be. This is everything we need to make a simple Z3 script to find the solution for us:

```
from z3 import *

# Designate the desired output
desiredOutput = [0x69, 0x72, 0x62, 0x75, 0x67, 0x7a, 0x76, 0x31, 0x76, 0x5e, 0x78, 0x31, 0x74, 0x5e, 0x6a, 0x6f, 0x31, 0x76, 0x5e, 0x65, 0x35, 0x5e, 0x76, 0x40, 0x32, 0x5e, 0x39, 0x69, 0x33, 0x63, 0x40, 0x31, 0x33, 0x38, 0x7c]


# Designate the input z3 will have control of
inp = []
for i in xrange(0x23):
	byte = BitVec("%s" % i, 8)
	inp.append(byte)

z = Solver()

for i in xrange(0x23):
	z.add((inp[i] ^ 1) == desiredOutput[i])


#Check if z3 can solve it, and if it can print out the solution
if z.check() == sat:
#	print z
	print "Condition is satisfied, would still recommend crying: " + str(z.check())
	solution = z.model()
	flag = ""
	for i in range(0, 0x23):
		flag += chr(int(str(solution[inp[i]])))
	print flag

#Check if z3 can't solve it
elif z.check() == unsat:
	print "Condition is not satisfied, would recommend crying: " + str(z.check())
```

When we run it:

```
$	python reverent.py 
Condition is satisfied, would still recommend crying: sat
hsctf{w0w_y0u_kn0w_d4_wA3_8h2bA029}
$	./a-byte hsctf{w0w_y0u_kn0w_d4_wA3_8h2bA029}
Oof, ur too good
```

Just like that, we solved the challenge!