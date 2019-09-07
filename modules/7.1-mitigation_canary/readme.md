# Stack Canary

The Stack Canary is another mitigation designed to protect against things like stack based buffer overflows. The general idea is, a random value is placed at the bottom of the stack frame, which is below the stack variables where we actually have input. If had a buffer overflow to overwrite the saved return address, this value on the stack would be overwritten. Then before the return address is executed, it checks to see if that value is the same one it set. If it isn't then it knows that there is a memory corruption bug happening and terminates the program. Also the name comes from the use of canaries in a mine. If the canary stops singing, get out before you die from gas poisoning.

To understand this better, let's look at a binary compiled with a stack canary:

```
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000401132 <+0>:    push   rbp
   0x0000000000401133 <+1>:    mov    rbp,rsp
   0x0000000000401136 <+4>:    sub    rsp,0x20
   0x000000000040113a <+8>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000401143 <+17>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000000401147 <+21>:    xor    eax,eax
   0x0000000000401149 <+23>:    mov    rdx,QWORD PTR [rip+0x2ef0]        # 0x404040 <stdin@@GLIBC_2.2.5>
   0x0000000000401150 <+30>:    lea    rax,[rbp-0x12]
   0x0000000000401154 <+34>:    mov    esi,0x9
   0x0000000000401159 <+39>:    mov    rdi,rax
   0x000000000040115c <+42>:    call   0x401040 <fgets@plt>
   0x0000000000401161 <+47>:    mov    DWORD PTR [rbp-0x18],0x5
   0x0000000000401168 <+54>:    nop
   0x0000000000401169 <+55>:    mov    rax,QWORD PTR [rbp-0x8]
   0x000000000040116d <+59>:    xor    rax,QWORD PTR fs:0x28
   0x0000000000401176 <+68>:    je     0x40117d <main+75>
   0x0000000000401178 <+70>:    call   0x401030 <__stack_chk_fail@plt>
   0x000000000040117d <+75>:    leave  
   0x000000000040117e <+76>:    ret    
End of assembler dump.
```


Now let's look at a binary compiled from the same source code, but without a stack canary:

```
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000401122 <+0>:    push   rbp
   0x0000000000401123 <+1>:    mov    rbp,rsp
   0x0000000000401126 <+4>:    sub    rsp,0x10
   0x000000000040112a <+8>:    mov    rdx,QWORD PTR [rip+0x2eff]        # 0x404030 <stdin@@GLIBC_2.2.5>
   0x0000000000401131 <+15>:    lea    rax,[rbp-0xe]
   0x0000000000401135 <+19>:    mov    esi,0x9
   0x000000000040113a <+24>:    mov    rdi,rax
   0x000000000040113d <+27>:    call   0x401030 <fgets@plt>
   0x0000000000401142 <+32>:    mov    DWORD PTR [rbp-0x4],0x5
   0x0000000000401149 <+39>:    nop
   0x000000000040114a <+40>:    leave  
   0x000000000040114b <+41>:    ret    
End of assembler dump.
```

We can see a few differences between the code, like when it checks the stack canary:

```
   0x0000000000401169 <+55>:    mov    rax,QWORD PTR [rbp-0x8]
   0x000000000040116d <+59>:    xor    rax,QWORD PTR fs:0x28
   0x0000000000401176 <+68>:    je     0x40117d <main+75>
   0x0000000000401178 <+70>:    call   0x401030 <__stack_chk_fail@plt>
```

Let's actually take a look at the stack canary in memory:

```
Breakpoint 1, 0x0000000000401168 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdfde  →  0x7fffffffe0d0000a
$rbx   : 0x0               
$rcx   : 0xfbad2288        
$rdx   : 0x00007fffffffdfde  →  0x7fffffffe0d0000a
$rsp   : 0x00007fffffffdfd0  →  0x0000000000401180  →  <__libc_csu_init+0> push r15
$rbp   : 0x00007fffffffdff0  →  0x0000000000401180  →  <__libc_csu_init+0> push r15
$rsi   : 0x00007ffff7fb2590  →  0x0000000000000000
$rdi   : 0x0               
$rip   : 0x0000000000401168  →  <main+54> nop
$r8    : 0x00007ffff7fb2580  →  0x0000000000000000
$r9    : 0x00007ffff7fb7500  →  0x00007ffff7fb7500  →  [loop detected]
$r10   : 0x00007ffff7fafca0  →  0x0000000000405660  →  0x0000000000000000
$r11   : 0x246             
$r12   : 0x0000000000401050  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffe0d0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfd0│+0x0000: 0x0000000000401180  →  <__libc_csu_init+0> push r15 ← $rsp
0x00007fffffffdfd8│+0x0008: 0x000a000000000005
0x00007fffffffdfe0│+0x0010: 0x00007fffffffe0d0  →  0x0000000000000001
0x00007fffffffdfe8│+0x0018: 0x92105577ff879300
0x00007fffffffdff0│+0x0020: 0x0000000000401180  →  <__libc_csu_init+0> push r15 ← $rbp
0x00007fffffffdff8│+0x0028: 0x00007ffff7df1b6b  →  <__libc_start_main+235> mov edi, eax
0x00007fffffffe000│+0x0030: 0x0000000000000000
0x00007fffffffe008│+0x0038: 0x00007fffffffe0d8  →  0x00007fffffffe3f7  →  "/tmp/tryc"
─────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401159 <main+39>        mov    rdi, rax
     0x40115c <main+42>        call   0x401040 <fgets@plt>
     0x401161 <main+47>        mov    DWORD PTR [rbp-0x18], 0x5
 →   0x401168 <main+54>        nop    
     0x401169 <main+55>        mov    rax, QWORD PTR [rbp-0x8]
     0x40116d <main+59>        xor    rax, QWORD PTR fs:0x28
     0x401176 <main+68>        je     0x40117d <main+75>
     0x401178 <main+70>        call   0x401030 <__stack_chk_fail@plt>
     0x40117d <main+75>        leave  
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tryc", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x401168 → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  x/g $rbp-0x8
0x7fffffffdfe8:    0x92105577ff879300
```

Here we can see is the stack canary. We can tell that it is the stack canary from several different things. Firstly it is the value being used when it is doing the stack canary check. Also it is around the spot on the stack it should be. Also it matches the pattern of a stack canary. While they are random they do fit a general pattern.

For `x64` elfs, the pattern is an `0x8` byte qword, where the first seven bytes are random and the last byte is a null byte.

For `x86` elfs, the pattern is a `0x4` byte dword, where the first three bytes are random and the last byte is a null byte.

Let's change the value of the canary and see what happens!

```
gef➤  x/g $rbp-0x8
0x7fffffffdfe8:    0x92105577ff879300
gef➤  set *0x7fffffffdfe8 = 0x0
gef➤  x/g $rbp-0x8
0x7fffffffdfe8:    0x9210557700000000
gef➤  c
Continuing.
*** stack smashing detected ***: <unknown> terminated
```

As we can see, it saw that the value of the canary changed and it terminated the process.

So what's the bypass? If we need to overwrite the stack canary, then we just overwrite it with itself. For instance:

```
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401159 <main+39>        mov    rdi, rax
     0x40115c <main+42>        call   0x401040 <fgets@plt>
     0x401161 <main+47>        mov    DWORD PTR [rbp-0x18], 0x5
 →   0x401168 <main+54>        nop    
     0x401169 <main+55>        mov    rax, QWORD PTR [rbp-0x8]
     0x40116d <main+59>        xor    rax, QWORD PTR fs:0x28
     0x401176 <main+68>        je     0x40117d <main+75>
     0x401178 <main+70>        call   0x401030 <__stack_chk_fail@plt>
     0x40117d <main+75>        leave  
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tryc", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x401168 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/g $rbp-0x8
0x7fffffffdfe8:    0x62c8c8d34092fd00
gef➤  set *0x7fffffffdfe8 = 0x4092fd00
gef➤  x/g $rbp-0x8
0x7fffffffdfe8:    0x62c8c8d34092fd00
gef➤  c
Continuing.
[Inferior 1 (process 7134) exited normally]
```

Here we just wrote the value of the canary to itself, and it passed the check. Of course this requires us to know the value of the stack canary. This can be accomplished via leaking the canary (which we will see later). Also in some cases you might be able to do something like brute forcing that value.