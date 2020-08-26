# aslr/pie intro

With exploiting binaries, there are various mitigations that you will face that will make it harder to exploit. Defeating them is usually just one step for actually gainning control over a program (assuming that the mitigation stands in your way). Since it is just something that stands in your way, and since for the modules I like to cover a new type of bug / exploitation technique, I didn't make a module dedicated to each of the mitigations you will see. However you still do see them (or some combination of the,) nearly everywhere through this project. So the purpose of these is to give you a brief explanation as to what they are.

So what is address space randomization (aslr)? Processes have memory. All of the memory addresses to each byte. Aslr randomization that in certain memory region such as the stack and the heap. This keeps us from knowing what the memory addresses are for certain regions of memory.

For instance, let's take a look at the address of this one stack variable, one iteration of running this binary:

```
Breakpoint 1, 0x0000000000401161 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffabfee6fe  →  0x7fffabfee7f0000a
$rbx   : 0x0               
$rcx   : 0xfbad2088        
$rdx   : 0x00007fffabfee6fe  →  0x7fffabfee7f0000a
$rsp   : 0x00007fffabfee6f0  →  0x0000000000401180  →  <__libc_csu_init+0> push r15
$rbp   : 0x00007fffabfee710  →  0x0000000000401180  →  <__libc_csu_init+0> push r15
$rsi   : 0x00007f4512ce4590  →  0x0000000000000000
$rdi   : 0x0               
$rip   : 0x0000000000401161  →  <main+47> mov DWORD PTR [rbp-0x18], 0x5
$r8    : 0x0000000001100010  →  0x0000000000000000
$r9    : 0x63              
$r10   : 0x00007f4512ce1ca0  →  0x0000000001101260  →  0x0000000000000000
$r11   : 0x246             
$r12   : 0x0000000000401050  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffabfee7f0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────── stack ────
0x00007fffabfee6f0│+0x0000: 0x0000000000401180  →  <__libc_csu_init+0> push r15 ← $rsp
0x00007fffabfee6f8│+0x0008: 0x000a000000401050
0x00007fffabfee700│+0x0010: 0x00007fffabfee7f0  →  0x0000000000000001
0x00007fffabfee708│+0x0018: 0x29e19ee33cdef200
0x00007fffabfee710│+0x0020: 0x0000000000401180  →  <__libc_csu_init+0> push r15 ← $rbp
0x00007fffabfee718│+0x0028: 0x00007f4512b23b6b  →  <__libc_start_main+235> mov edi, eax
0x00007fffabfee720│+0x0030: 0x0000000000000000
0x00007fffabfee728│+0x0038: 0x00007fffabfee7f8  →  0x00007fffabfef410  →  0x4e47007972742f2e ("./try"?)
─────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401154 <main+34>        mov    esi, 0x9
     0x401159 <main+39>        mov    rdi, rax
     0x40115c <main+42>        call   0x401040 <fgets@plt>
 →   0x401161 <main+47>        mov    DWORD PTR [rbp-0x18], 0x5
     0x401168 <main+54>        nop    
     0x401169 <main+55>        mov    rax, QWORD PTR [rbp-0x8]
     0x40116d <main+59>        xor    rax, QWORD PTR fs:0x28
     0x401176 <main+68>        je     0x40117d <main+75>
     0x401178 <main+70>        call   0x401030 <__stack_chk_fail@plt>
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "try", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x401161 → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  x/g $rbp-0x18
0x7fffabfee6f8:    0xa000000401050
```   

We can see that for this iteration, the variable at `rbp-0x18` has the address `0x7fffabfee6f8`. Let's see what the address is on another iteration of running the binary:

```
Breakpoint 1, 0x0000000000401161 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007ffcdc7caf6e  →  0x7ffcdc7cb060000a
$rbx   : 0x0               
$rcx   : 0xfbad2088        
$rdx   : 0x00007ffcdc7caf6e  →  0x7ffcdc7cb060000a
$rsp   : 0x00007ffcdc7caf60  →  0x0000000000401180  →  <__libc_csu_init+0> push r15
$rbp   : 0x00007ffcdc7caf80  →  0x0000000000401180  →  <__libc_csu_init+0> push r15
$rsi   : 0x00007ff338fda590  →  0x0000000000000000
$rdi   : 0x0               
$rip   : 0x0000000000401161  →  <main+47> mov DWORD PTR [rbp-0x18], 0x5
$r8    : 0x00000000023b9010  →  0x0000000000000000
$r9    : 0x63              
$r10   : 0x00007ff338fd7ca0  →  0x00000000023ba260  →  0x0000000000000000
$r11   : 0x246             
$r12   : 0x0000000000401050  →  <_start+0> xor ebp, ebp
$r13   : 0x00007ffcdc7cb060  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────── stack ────
0x00007ffcdc7caf60│+0x0000: 0x0000000000401180  →  <__libc_csu_init+0> push r15 ← $rsp
0x00007ffcdc7caf68│+0x0008: 0x000a000000401050
0x00007ffcdc7caf70│+0x0010: 0x00007ffcdc7cb060  →  0x0000000000000001
0x00007ffcdc7caf78│+0x0018: 0x7065c5c264020400
0x00007ffcdc7caf80│+0x0020: 0x0000000000401180  →  <__libc_csu_init+0> push r15 ← $rbp
0x00007ffcdc7caf88│+0x0028: 0x00007ff338e19b6b  →  <__libc_start_main+235> mov edi, eax
0x00007ffcdc7caf90│+0x0030: 0x0000000000000000
0x00007ffcdc7caf98│+0x0038: 0x00007ffcdc7cb068  →  0x00007ffcdc7cb410  →  0x4e47007972742f2e ("./try"?)
─────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401154 <main+34>        mov    esi, 0x9
     0x401159 <main+39>        mov    rdi, rax
     0x40115c <main+42>        call   0x401040 <fgets@plt>
 →   0x401161 <main+47>        mov    DWORD PTR [rbp-0x18], 0x5
     0x401168 <main+54>        nop    
     0x401169 <main+55>        mov    rax, QWORD PTR [rbp-0x8]
     0x40116d <main+59>        xor    rax, QWORD PTR fs:0x28
     0x401176 <main+68>        je     0x40117d <main+75>
     0x401178 <main+70>        call   0x401030 <__stack_chk_fail@plt>
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "try", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x401161 → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  x/g $rbp-0x18
0x7ffcdc7caf68:    0xa000000401050
```

This time we can see that the address is `0x7ffcdc7caf68`, so it has changed. Also one quick note, when you run a binary straight up in gdb, it can disable aslr in certain memory regions. The reason why aslr works here is I spawned the process, then attached it using pwntools.

Now know the addresses of various things in memory regions like the heap, stack, and libc (libc is where standard functions like `fgets` and `puts` live) can be extremely helpful if not necessary while attacking some targets. So what is the bypass to this mitigation?

The bypass is we leak an address from a memory region that we want to know what it's address space is. For this it might help to take a look at the memory mappings of a process with `vmmap`:

```
gef➤  vmmap
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-- /tmp/try
0x0000000000401000 0x0000000000402000 0x0000000000001000 r-x /tmp/try
0x0000000000402000 0x0000000000403000 0x0000000000002000 r-- /tmp/try
0x0000000000403000 0x0000000000404000 0x0000000000002000 r-- /tmp/try
0x0000000000404000 0x0000000000405000 0x0000000000003000 rw- /tmp/try
0x00000000023b9000 0x00000000023da000 0x0000000000000000 rw- [heap]
0x00007ff338df3000 0x00007ff338e18000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ff338e18000 0x00007ff338f8b000 0x0000000000025000 r-x /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ff338f8b000 0x00007ff338fd4000 0x0000000000198000 r-- /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ff338fd4000 0x00007ff338fd7000 0x00000000001e0000 r-- /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ff338fd7000 0x00007ff338fda000 0x00000000001e3000 rw- /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ff338fda000 0x00007ff338fe0000 0x0000000000000000 rw-
0x00007ff338ff6000 0x00007ff338ff7000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ff338ff7000 0x00007ff339018000 0x0000000000001000 r-x /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ff339018000 0x00007ff339020000 0x0000000000022000 r-- /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ff339020000 0x00007ff339021000 0x0000000000029000 r-- /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ff339021000 0x00007ff339022000 0x000000000002a000 rw- /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ff339022000 0x00007ff339023000 0x0000000000000000 rw-
0x00007ffcdc7ab000 0x00007ffcdc7cc000 0x0000000000000000 rw- [stack]
0x00007ffcdc7d3000 0x00007ffcdc7d6000 0x0000000000000000 r-- [vvar]
0x00007ffcdc7d6000 0x00007ffcdc7d7000 0x0000000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
```

So here we can see various memory regions such as the `heap`, the `stack`, `libc`, and more. Thing is while the addresses in a memory space will change, the offset between the addresses themselves will not change. So if we leak a single address from a memory region that we know what is, we can just add the offset to whatever address we want to know. We can find this offset in gdb, since the offsets between two different memory addresses in the same memory region don't change. There are lots of different ways we can get an infoleak that you will see throughout this project. Also if we get an infoleak for let's say the `libc` region of memory, that is only good for the `libc` region of memory. We can't use that `libc` infoleak to figure out the address space for things like the `heap` or the `stack` (or vice versa).

## pie

Position Independent Executable (pie) is another binary mitigation extremely similar to aslr. It is basically aslr but for the actual binary's code / memory regions. For instance, let's take a look at a binary that is compiled without `pie`:

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
=> 0x0000000000401161 <+47>:    mov    DWORD PTR [rbp-0x18],0x5
   0x0000000000401168 <+54>:    nop
   0x0000000000401169 <+55>:    mov    rax,QWORD PTR [rbp-0x8]
   0x000000000040116d <+59>:    xor    rax,QWORD PTR fs:0x28
   0x0000000000401176 <+68>:    je     0x40117d <main+75>
   0x0000000000401178 <+70>:    call   0x401030 <__stack_chk_fail@plt>
   0x000000000040117d <+75>:    leave  
   0x000000000040117e <+76>:    ret    
End of assembler dump.
```

We can see here that all of the instruction addresses are fixed. The address `0x401132` will always point to the first instruction of the `main` function. We can even set a break point for it, and view it as an instruction:

```
gef➤  b *0x401132
Breakpoint 2 at 0x401132
gef➤  r
Starting program: /tmp/try

Breakpoint 2, 0x0000000000401132 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000000000401132  →  <main+0> push rbp
$rbx   : 0x0               
$rcx   : 0x0000000000401180  →  <__libc_csu_init+0> push r15
$rdx   : 0x00007fffffffe0e8  →  0x00007fffffffe3ff  →  "SHELL=/bin/bash"
$rsp   : 0x00007fffffffdff8  →  0x00007ffff7df1b6b  →  0x480002084ee8c789
$rbp   : 0x0000000000401180  →  <__libc_csu_init+0> push r15
$rsi   : 0x00007fffffffe0d8  →  0x00007fffffffe3f6  →  "/tmp/try"
$rdi   : 0x1               
$rip   : 0x0000000000401132  →  <main+0> push rbp
$r8    : 0x00007ffff7fb1a40  →  0x0000000000000000
$r9    : 0x00007ffff7fb1a40  →  0x0000000000000000
$r10   : 0x7               
$r11   : 0x2               
$r12   : 0x0000000000401050  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffe0d0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdff8│+0x0000: 0x00007ffff7df1b6b  →  0x480002084ee8c789     ← $rsp
0x00007fffffffe000│+0x0008: 0x0000000000000000
0x00007fffffffe008│+0x0010: 0x00007fffffffe0d8  →  0x00007fffffffe3f6  →  "/tmp/try"
0x00007fffffffe010│+0x0018: 0x0000000100040000
0x00007fffffffe018│+0x0020: 0x0000000000401132  →  <main+0> push rbp
0x00007fffffffe020│+0x0028: 0x0000000000000000
0x00007fffffffe028│+0x0030: 0x6f71579249248831
0x00007fffffffe030│+0x0038: 0x0000000000401050  →  <_start+0> xor ebp, ebp
─────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401121 <__do_global_dtors_aux+33> data16 nop WORD PTR cs:[rax+rax*1+0x0]
     0x40112c <__do_global_dtors_aux+44> nop    DWORD PTR [rax+0x0]
     0x401130 <frame_dummy+0>  jmp    0x4010c0 <register_tm_clones>
 →   0x401132 <main+0>         push   rbp
     0x401133 <main+1>         mov    rbp, rsp
     0x401136 <main+4>         sub    rsp, 0x20
     0x40113a <main+8>         mov    rax, QWORD PTR fs:0x28
     0x401143 <main+17>        mov    QWORD PTR [rbp-0x8], rax
     0x401147 <main+21>        xor    eax, eax
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "try", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x401132 → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  x/i 0x401132
=> 0x401132 <main>:    push   rbp
```

With pie, everything in the "binary's" memory regions is compiled to have an offset versus a fixed address. Each time the binary is run, the binary generates a random number known as a base. Then the address of everything becomes the base plus the offset. For this to make more since let's first look at the memory mapping:

```
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-- /tmp/try
0x0000000000401000 0x0000000000402000 0x0000000000001000 r-x /tmp/try
0x0000000000402000 0x0000000000403000 0x0000000000002000 r-- /tmp/try
0x0000000000403000 0x0000000000404000 0x0000000000002000 r-- /tmp/try
0x0000000000404000 0x0000000000405000 0x0000000000003000 rw- /tmp/try
0x00007ffff7dcb000 0x00007ffff7df0000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ffff7df0000 0x00007ffff7f63000 0x0000000000025000 r-x /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ffff7f63000 0x00007ffff7fac000 0x0000000000198000 r-- /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ffff7fac000 0x00007ffff7faf000 0x00000000001e0000 r-- /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ffff7faf000 0x00007ffff7fb2000 0x00000000001e3000 rw- /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ffff7fb2000 0x00007ffff7fb8000 0x0000000000000000 rw-
0x00007ffff7fce000 0x00007ffff7fd1000 0x0000000000000000 r-- [vvar]
0x00007ffff7fd1000 0x00007ffff7fd2000 0x0000000000000000 r-x [vdso]
0x00007ffff7fd2000 0x00007ffff7fd3000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ffff7fd3000 0x00007ffff7ff4000 0x0000000000001000 r-x /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ffff7ff4000 0x00007ffff7ffc000 0x0000000000022000 r-- /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ffff7ffc000 0x00007ffff7ffd000 0x0000000000029000 r-- /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ffff7ffd000 0x00007ffff7ffe000 0x000000000002a000 rw- /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw-
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
```

When I say "binary's" memory regions I mean these regions specifically:

```
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-- /tmp/try
0x0000000000401000 0x0000000000402000 0x0000000000001000 r-x /tmp/try
0x0000000000402000 0x0000000000403000 0x0000000000002000 r-- /tmp/try
0x0000000000403000 0x0000000000404000 0x0000000000002000 r-- /tmp/try
0x0000000000404000 0x0000000000405000 0x0000000000003000 rw- /tmp/try
```

Now let's see what the main function looks like when we compile it with pie:

```
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001145 <+0>:    push   rbp
   0x0000000000001146 <+1>:    mov    rbp,rsp
   0x0000000000001149 <+4>:    sub    rsp,0x20
   0x000000000000114d <+8>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000001156 <+17>:    mov    QWORD PTR [rbp-0x8],rax
   0x000000000000115a <+21>:    xor    eax,eax
   0x000000000000115c <+23>:    mov    rdx,QWORD PTR [rip+0x2ead]        # 0x4010 <stdin@@GLIBC_2.2.5>
   0x0000000000001163 <+30>:    lea    rax,[rbp-0x12]
   0x0000000000001167 <+34>:    mov    esi,0x9
   0x000000000000116c <+39>:    mov    rdi,rax
   0x000000000000116f <+42>:    call   0x1040 <fgets@plt>
   0x0000000000001174 <+47>:    mov    DWORD PTR [rbp-0x18],0x5
   0x000000000000117b <+54>:    nop
   0x000000000000117c <+55>:    mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000001180 <+59>:    xor    rax,QWORD PTR fs:0x28
   0x0000000000001189 <+68>:    je     0x1190 <main+75>
   0x000000000000118b <+70>:    call   0x1030 <__stack_chk_fail@plt>
   0x0000000000001190 <+75>:    leave  
   0x0000000000001191 <+76>:    ret    
End of assembler dump.
```

As you can see, all of the instructions are now addressed to an offset versus a fixed address. Every time that the binary runs each of those instructions will have a different address. Let's see this in action.

Run 0:
```
gef➤  vmmap
Start              End                Offset             Perm Path
0x000055ce0fb38000 0x000055ce0fb39000 0x0000000000000000 r-- /tmp/try
0x000055ce0fb39000 0x000055ce0fb3a000 0x0000000000001000 r-x /tmp/try
0x000055ce0fb3a000 0x000055ce0fb3b000 0x0000000000002000 r-- /tmp/try
0x000055ce0fb3b000 0x000055ce0fb3c000 0x0000000000002000 r-- /tmp/try
0x000055ce0fb3c000 0x000055ce0fb3d000 0x0000000000003000 rw- /tmp/try
0x000055ce0fb5a000 0x000055ce0fb7b000 0x0000000000000000 rw- [heap]
0x00007fb90e941000 0x00007fb90e966000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007fb90e966000 0x00007fb90ead9000 0x0000000000025000 r-x /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007fb90ead9000 0x00007fb90eb22000 0x0000000000198000 r-- /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007fb90eb22000 0x00007fb90eb25000 0x00000000001e0000 r-- /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007fb90eb25000 0x00007fb90eb28000 0x00000000001e3000 rw- /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007fb90eb28000 0x00007fb90eb2e000 0x0000000000000000 rw-
0x00007fb90eb44000 0x00007fb90eb45000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007fb90eb45000 0x00007fb90eb66000 0x0000000000001000 r-x /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007fb90eb66000 0x00007fb90eb6e000 0x0000000000022000 r-- /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007fb90eb6e000 0x00007fb90eb6f000 0x0000000000029000 r-- /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007fb90eb6f000 0x00007fb90eb70000 0x000000000002a000 rw- /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007fb90eb70000 0x00007fb90eb71000 0x0000000000000000 rw-
0x00007fff45acc000 0x00007fff45aed000 0x0000000000000000 rw- [stack]
0x00007fff45b19000 0x00007fff45b1c000 0x0000000000000000 r-- [vvar]
0x00007fff45b1c000 0x00007fff45b1d000 0x0000000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
```

Run 1:
```
gef➤  vmmap
Start              End                Offset             Perm Path
0x000055c5ba9e8000 0x000055c5ba9e9000 0x0000000000000000 r-- /tmp/try
0x000055c5ba9e9000 0x000055c5ba9ea000 0x0000000000001000 r-x /tmp/try
0x000055c5ba9ea000 0x000055c5ba9eb000 0x0000000000002000 r-- /tmp/try
0x000055c5ba9eb000 0x000055c5ba9ec000 0x0000000000002000 r-- /tmp/try
0x000055c5ba9ec000 0x000055c5ba9ed000 0x0000000000003000 rw- /tmp/try
0x000055c5bc62a000 0x000055c5bc64b000 0x0000000000000000 rw- [heap]
0x00007ff808662000 0x00007ff808687000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ff808687000 0x00007ff8087fa000 0x0000000000025000 r-x /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ff8087fa000 0x00007ff808843000 0x0000000000198000 r-- /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ff808843000 0x00007ff808846000 0x00000000001e0000 r-- /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ff808846000 0x00007ff808849000 0x00000000001e3000 rw- /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ff808849000 0x00007ff80884f000 0x0000000000000000 rw-
0x00007ff808865000 0x00007ff808866000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ff808866000 0x00007ff808887000 0x0000000000001000 r-x /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ff808887000 0x00007ff80888f000 0x0000000000022000 r-- /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ff80888f000 0x00007ff808890000 0x0000000000029000 r-- /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ff808890000 0x00007ff808891000 0x000000000002a000 rw- /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ff808891000 0x00007ff808892000 0x0000000000000000 rw-
0x00007fff2ad6a000 0x00007fff2ad8b000 0x0000000000000000 rw- [stack]
0x00007fff2adc6000 0x00007fff2adc9000 0x0000000000000000 r-- [vvar]
0x00007fff2adc9000 0x00007fff2adca000 0x0000000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
```

As we can see, pie has changed the memory addresses for the binary's memory spaces.

Also one thing, pie can make it a bit annoying to set breakpoints. Luckily gef has a cool feature to help with this.

```
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001145 <+0>:    push   rbp
   0x0000000000001146 <+1>:    mov    rbp,rsp
   0x0000000000001149 <+4>:    sub    rsp,0x20
   0x000000000000114d <+8>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000001156 <+17>:    mov    QWORD PTR [rbp-0x8],rax
   0x000000000000115a <+21>:    xor    eax,eax
   0x000000000000115c <+23>:    mov    rdx,QWORD PTR [rip+0x2ead]        # 0x4010 <stdin@@GLIBC_2.2.5>
   0x0000000000001163 <+30>:    lea    rax,[rbp-0x12]
   0x0000000000001167 <+34>:    mov    esi,0x9
   0x000000000000116c <+39>:    mov    rdi,rax
   0x000000000000116f <+42>:    call   0x1040 <fgets@plt>
   0x0000000000001174 <+47>:    mov    DWORD PTR [rbp-0x18],0x5
   0x000000000000117b <+54>:    nop
   0x000000000000117c <+55>:    mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000001180 <+59>:    xor    rax,QWORD PTR fs:0x28
   0x0000000000001189 <+68>:    je     0x1190 <main+75>
   0x000000000000118b <+70>:    call   0x1030 <__stack_chk_fail@plt>
   0x0000000000001190 <+75>:    leave  
   0x0000000000001191 <+76>:    ret    
End of assembler dump.
```

Let's say we wanted to break at `0x116f`. We can't set a breakpoint for that offset directly. However we can still set a breakpoint for it:

```
gef➤  pie b *0x116f
gef➤  pie run
Stopped due to shared library event (no libraries added or removed)

Breakpoint 1, 0x000055555555516f in main ()
[+] base address 0x555555554000
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdfde  →  0x7fffffffe0d00000
$rbx   : 0x0               
$rcx   : 0x00005555555551a0  →  <__libc_csu_init+0> push r15
$rdx   : 0x00007ffff7fafa00  →  0x00000000fbad2088
$rsp   : 0x00007fffffffdfd0  →  0x00005555555551a0  →  <__libc_csu_init+0> push r15
$rbp   : 0x00007fffffffdff0  →  0x00005555555551a0  →  <__libc_csu_init+0> push r15
$rsi   : 0x9               
$rdi   : 0x00007fffffffdfde  →  0x7fffffffe0d00000
$rip   : 0x000055555555516f  →  <main+42> call 0x555555555040 <fgets@plt>
$r8    : 0x00007ffff7fb1a40  →  0x0000000000000000
$r9    : 0x00007ffff7fb1a40  →  0x0000000000000000
$r10   : 0x7               
$r11   : 0x2               
$r12   : 0x0000555555555060  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffe0d0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfd0│+0x0000: 0x00005555555551a0  →  <__libc_csu_init+0> push r15 ← $rsp
0x00007fffffffdfd8│+0x0008: 0x0000555555555060  →  <_start+0> xor ebp, ebp
0x00007fffffffdfe0│+0x0010: 0x00007fffffffe0d0  →  0x0000000000000001
0x00007fffffffdfe8│+0x0018: 0xdb3c67cc21531d00
0x00007fffffffdff0│+0x0020: 0x00005555555551a0  →  <__libc_csu_init+0> push r15 ← $rbp
0x00007fffffffdff8│+0x0028: 0x00007ffff7df1b6b  →  <__libc_start_main+235> mov edi, eax
0x00007fffffffe000│+0x0030: 0x0000000000000000
0x00007fffffffe008│+0x0038: 0x00007fffffffe0d8  →  0x00007fffffffe3f9  →  "/tmp/try"
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555163 <main+30>        lea    rax, [rbp-0x12]
   0x555555555167 <main+34>        mov    esi, 0x9
   0x55555555516c <main+39>        mov    rdi, rax
 → 0x55555555516f <main+42>        call   0x555555555040 <fgets@plt>
   ↳  0x555555555040 <fgets@plt+0>    jmp    QWORD PTR [rip+0x2f8a]        # 0x555555557fd0 <fgets@got.plt>
      0x555555555046 <fgets@plt+6>    push   0x1
      0x55555555504b <fgets@plt+11>   jmp    0x555555555020
      0x555555555050 <__cxa_finalize@plt+0> jmp    QWORD PTR [rip+0x2fa2]        # 0x555555557ff8
      0x555555555056 <__cxa_finalize@plt+6> xchg   ax, ax
      0x555555555058                  add    BYTE PTR [rax], al
─────────────────────────────────────────────────────── arguments (guessed) ────
fgets@plt (
   $rdi = 0x00007fffffffdfde → 0x7fffffffe0d00000,
   $rsi = 0x0000000000000009,
   $rdx = 0x00007ffff7fafa00 → 0x00000000fbad2088
)
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "try", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555516f → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  
```

As you see using the `pie b` and `pie run` commands, we were able to set a breakpoint for an offset.

So as to how to defeat pie and know the address of this memory region, you defeat it the same way you would defeat aslr. You leak a single address from the memory region. Then since the offsets stay the same every time, you can figure out the address of anything in that memory region.