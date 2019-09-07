# gdb-gef

So throughout this project, we will be using a lot of different tools. The purpose of this module is to show you some of the basics of three of those tools. We will start with gdb-gef.

First off, gdb is a debugger (specifically the gnu debugger). Gef is an a gdb wrapper, designed  to give us some extended features (https://github.com/hugsy/gef). To install it, you can find the instructions on the github page. it's super simple.

A debugger is software that allows us to perform various types of analysis of a process as it's running, and alter it in a variety of different ways.

Now you can tell if you have it installed by just looking at gdb. For instance this is the look of gdb if you have gef installed:

```
$ gdb
GNU gdb (Ubuntu 8.2.91.20190405-0ubuntu3) 8.2.91.20190405-git
Copyright (C) 2019 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
GEF for linux ready, type `gef' to start, `gef config' to configure
75 commands loaded for GDB 8.2.91.20190405-git using Python engine 3.7
[*] 5 commands could not be loaded, run `gef missing` to know why.
gef➤  
```

If you don't have it installed this is what vanilla gdb looks like:

```
$    gdb
GNU gdb (Ubuntu 8.2.91.20190405-0ubuntu3) 8.2.91.20190405-git
Copyright (C) 2019 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
(gdb)
```

## Running

To run the binary `titan` in gdb:

```
gdb ./titan
GNU gdb (Ubuntu 8.2.91.20190405-0ubuntu3) 8.2.91.20190405-git
Copyright (C) 2019 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
GEF for linux ready, type `gef' to start, `gef config' to configure
75 commands loaded for GDB 8.2.91.20190405-git using Python engine 3.7
[*] 5 commands could not be loaded, run `gef missing` to know why.
Reading symbols from ./titan...
(No debugging symbols found in ./titan)
gef➤  r
Starting program: /tmp/titan
hi
```

If you are running a process in gdb, and wish to drop to the debugger console, you can do so by pressing `Cotrol + C`:

```
gef➤  r
Starting program: /tmp/titan
hi
^C
Program received signal SIGINT, Interrupt.
0x00007ffff7ed6f81 in __GI___libc_read (fd=0x0, buf=0x555555559670, nbytes=0x400) at ../sysdeps/unix/sysv/linux/read.c:26
26    ../sysdeps/unix/sysv/linux/read.c: No such file or directory.
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00007ffff7faea00  →  0x00000000fbad2288
$rcx   : 0x00007ffff7ed6f81  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x400             
$rsp   : 0x00007fffffffdef8  →  0x00007ffff7e59e50  →  <_IO_file_underflow+336> test rax, rax
$rbp   : 0xd68             
$rsi   : 0x0000555555559670  →  0x0000000000000000
$rdi   : 0x0               
$rip   : 0x00007ffff7ed6f81  →  0x5777fffff0003d48 ("H="?)
$r8    : 0x00007ffff7fb1580  →  0x0000000000000000
$r9    : 0x00007ffff7fb6500  →  0x00007ffff7fb6500  →  [loop detected]
$r10   : 0x00007ffff7faeca0  →  0x0000555555559a70  →  0x0000000000000000
$r11   : 0x246             
$r12   : 0x00007ffff7faf960  →  0x0000000000000000
$r13   : 0x00007ffff7fb0560  →  0x0000000000000000
$r14   : 0x00007ffff7faf848  →  0x00007ffff7faf760  →  0x00000000fbad2a84
$r15   : 0x00007ffff7fb0560  →  0x0000000000000000
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdef8│+0x0000: 0x00007ffff7e59e50  →  <_IO_file_underflow+336> test rax, rax     ← $rsp
0x00007fffffffdf00│+0x0008: 0x00007ffff7faf960  →  0x0000000000000000
0x00007fffffffdf08│+0x0010: 0x00007ffff7faea00  →  0x00000000fbad2288
0x00007fffffffdf10│+0x0018: 0x00007ffff7fb0560  →  0x0000000000000000
0x00007fffffffdf18│+0x0020: 0x000000000000000a
0x00007fffffffdf20│+0x0028: 0x0000000000000000
0x00007fffffffdf28│+0x0030: 0x0000000000000008
0x00007fffffffdf30│+0x0038: 0x00007ffff7faea00  →  0x00000000fbad2288
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7ed6f75 <read+5>         or     eax, 0x85008b00
   0x7ffff7ed6f7a <read+10>        shl    BYTE PTR [rbp+0x13], 0x31
   0x7ffff7ed6f7e <read+14>        ror    BYTE PTR [rdi], 0x5
 → 0x7ffff7ed6f81 <read+17>        cmp    rax, 0xfffffffffffff000
   0x7ffff7ed6f87 <read+23>        ja     0x7ffff7ed6fe0 <__GI___libc_read+112>
   0x7ffff7ed6f89 <read+25>        ret    
   0x7ffff7ed6f8a <read+26>        nop    WORD PTR [rax+rax*1+0x0]
   0x7ffff7ed6f90 <read+32>        push   r12
   0x7ffff7ed6f92 <read+34>        mov    r12, rdx
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "titan", stopped, reason: SIGINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7ed6f81 → __GI___libc_read(fd=0x0, buf=0x555555559670, nbytes=0x400)
[#1] 0x7ffff7e59e50 → _IO_new_file_underflow(fp=0x7ffff7faea00 <_IO_2_1_stdin_>)
[#2] 0x7ffff7e5b182 → __GI__IO_default_uflow(fp=0x7ffff7faea00 <_IO_2_1_stdin_>)
[#3] 0x7ffff7e4d1fa → __GI__IO_getline_info(fp=0x7ffff7faea00 <_IO_2_1_stdin_>, buf=0x7fffffffdfee "", n=0x8, delim=0xa, extract_delim=0x1, eof=0x0)
[#4] 0x7ffff7e4d2e8 → __GI__IO_getline(fp=0x7ffff7faea00 <_IO_2_1_stdin_>, buf=0x7fffffffdfee "", n=<optimized out>, delim=0xa, extract_delim=0x1)
[#5] 0x7ffff7e4c1ab → _IO_fgets(buf=0x7fffffffdfee "", n=<optimized out>, fp=0x7ffff7faea00 <_IO_2_1_stdin_>)
[#6] 0x555555555190 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

## Breakpoints

Let's take a look at the main function:

```
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000401142 <+0>:    push   rbp
   0x0000000000401143 <+1>:    mov    rbp,rsp
   0x0000000000401146 <+4>:    sub    rsp,0x20
   0x000000000040114a <+8>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000401153 <+17>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000000401157 <+21>:    xor    eax,eax
   0x0000000000401159 <+23>:    lea    rdi,[rip+0xea4]        # 0x402004
   0x0000000000401160 <+30>:    call   0x401030 <puts@plt>
   0x0000000000401165 <+35>:    mov    rdx,QWORD PTR [rip+0x2ed4]        # 0x404040 <stdin@@GLIBC_2.2.5>
   0x000000000040116c <+42>:    lea    rax,[rbp-0x12]
   0x0000000000401170 <+46>:    mov    esi,0x9
   0x0000000000401175 <+51>:    mov    rdi,rax
   0x0000000000401178 <+54>:    call   0x401050 <fgets@plt>
   0x000000000040117d <+59>:    nop
   0x000000000040117e <+60>:    mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000401182 <+64>:    xor    rax,QWORD PTR fs:0x28
   0x000000000040118b <+73>:    je     0x401192 <main+80>
   0x000000000040118d <+75>:    call   0x401040 <__stack_chk_fail@plt>
   0x0000000000401192 <+80>:    leave  
   0x0000000000401193 <+81>:    ret    
End of assembler dump.
```

Let's say we wanted to break on the call to `puts`. We can do this by setting a breakpoint for that instruction.

Like this:
```
gef➤  b *main+30
Breakpoint 1 at 0x401160
```

Or like this:
```
gef➤  b *0x401160
Note: breakpoint 1 also set at pc 0x401160.
Breakpoint 2 at 0x401160
```

When we run the binary and it tries to execute that instruction, the process will pause and drop us into the debugger console:

```
gef➤  r
Starting program: /tmp/titan

Breakpoint 1, 0x0000000000401160 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x00000000004011a0  →  <__libc_csu_init+0> push r15
$rdx   : 0x00007fffffffe0f8  →  0x00007fffffffe412  →  "SHELL=/bin/bash"
$rsp   : 0x00007fffffffdfe0  →  0x00000000004011a0  →  <__libc_csu_init+0> push r15
$rbp   : 0x00007fffffffe000  →  0x00000000004011a0  →  <__libc_csu_init+0> push r15
$rsi   : 0x00007fffffffe0e8  →  0x00007fffffffe407  →  "/tmp/titan"
$rdi   : 0x0000000000402004  →  0x3b031b0100006968 ("hi"?)
$rip   : 0x0000000000401160  →  <main+30> call 0x401030 <puts@plt>
$r8    : 0x00007ffff7fb0a40  →  0x0000000000000000
$r9    : 0x00007ffff7fb0a40  →  0x0000000000000000
$r10   : 0x1               
$r11   : 0x206             
$r12   : 0x0000000000401060  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffe0e0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfe0│+0x0000: 0x00000000004011a0  →  <__libc_csu_init+0> push r15     ← $rsp
0x00007fffffffdfe8│+0x0008: 0x0000000000401060  →  <_start+0> xor ebp, ebp
0x00007fffffffdff0│+0x0010: 0x00007fffffffe0e0  →  0x0000000000000001
0x00007fffffffdff8│+0x0018: 0x42586df821034f00
0x00007fffffffe000│+0x0020: 0x00000000004011a0  →  <__libc_csu_init+0> push r15     ← $rbp
0x00007fffffffe008│+0x0028: 0x00007ffff7df0b6b  →  <__libc_start_main+235> mov edi, eax
0x00007fffffffe010│+0x0030: 0x00007ffff7fab4d8  →  0x00007ffff7df0450  →  <init_cacheinfo+0> push r15
0x00007fffffffe018│+0x0038: 0x00007fffffffe0e8  →  0x00007fffffffe407  →  "/tmp/titan"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401153 <main+17>        mov    QWORD PTR [rbp-0x8], rax
     0x401157 <main+21>        xor    eax, eax
     0x401159 <main+23>        lea    rdi, [rip+0xea4]        # 0x402004
 →   0x401160 <main+30>        call   0x401030 <puts@plt>
   ↳    0x401030 <puts@plt+0>     jmp    QWORD PTR [rip+0x2fe2]        # 0x404018 <puts@got.plt>
        0x401036 <puts@plt+6>     push   0x0
        0x40103b <puts@plt+11>    jmp    0x401020
        0x401040 <__stack_chk_fail@plt+0> jmp    QWORD PTR [rip+0x2fda]        # 0x404020 <__stack_chk_fail@got.plt>
        0x401046 <__stack_chk_fail@plt+6> push   0x1
        0x40104b <__stack_chk_fail@plt+11> jmp    0x401020
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
puts@plt (
   $rdi = 0x0000000000402004 → 0x3b031b0100006968 ("hi"?),
   $rsi = 0x00007fffffffe0e8 → 0x00007fffffffe407 → "/tmp/titan",
   $rdx = 0x00007fffffffe0f8 → 0x00007fffffffe412 → "SHELL=/bin/bash"
)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "titan", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x401160 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

In the debugger console is where we can actually use the debugger to provide various types of analysis, and change things about the binary. For now let's keep looking at breakpoints. To show all breakpoints:

```
gef➤  info breakpoints
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x0000000000401160 <main+30>
    breakpoint already hit 1 time
2       breakpoint     keep y   0x0000000000401170 <main+46>
```

To delete a breakpoint Num `2`:

```
gef➤  delete 2
```

We can also set breakpoints for functions like `puts`:

```
gef➤  b *puts
Breakpoint 1 at 0x401030
gef➤  r
Starting program: /tmp/titan

Breakpoint 1, __GI__IO_puts (str=0x402004 "hi") at ioputs.c:35
35    ioputs.c: No such file or directory.
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x00000000004011a0  →  <__libc_csu_init+0> push r15
$rdx   : 0x00007fffffffe0f8  →  0x00007fffffffe412  →  "SHELL=/bin/bash"
$rsp   : 0x00007fffffffdfd8  →  0x0000000000401165  →  <main+35> mov rdx, QWORD PTR [rip+0x2ed4]        # 0x404040 <stdin@@GLIBC_2.2.5>
$rbp   : 0x00007fffffffe000  →  0x00000000004011a0  →  <__libc_csu_init+0> push r15
$rsi   : 0x00007fffffffe0e8  →  0x00007fffffffe407  →  "/tmp/titan"
$rdi   : 0x0000000000402004  →  0x3b031b0100006968 ("hi"?)
$rip   : 0x00007ffff7e4dcc0  →  <puts+0> push r14
$r8    : 0x00007ffff7fb0a40  →  0x0000000000000000
$r9    : 0x00007ffff7fb0a40  →  0x0000000000000000
$r10   : 0x3               
$r11   : 0x00007ffff7e4dcc0  →  <puts+0> push r14
$r12   : 0x0000000000401060  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffe0e0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfd8│+0x0000: 0x0000000000401165  →  <main+35> mov rdx, QWORD PTR [rip+0x2ed4]        # 0x404040 <stdin@@GLIBC_2.2.5>     ← $rsp
0x00007fffffffdfe0│+0x0008: 0x00000000004011a0  →  <__libc_csu_init+0> push r15
0x00007fffffffdfe8│+0x0010: 0x0000000000401060  →  <_start+0> xor ebp, ebp
0x00007fffffffdff0│+0x0018: 0x00007fffffffe0e0  →  0x0000000000000001
0x00007fffffffdff8│+0x0020: 0xf2a5b1c2e2ab0300
0x00007fffffffe000│+0x0028: 0x00000000004011a0  →  <__libc_csu_init+0> push r15     ← $rbp
0x00007fffffffe008│+0x0030: 0x00007ffff7df0b6b  →  <__libc_start_main+235> mov edi, eax
0x00007fffffffe010│+0x0038: 0x00007ffff7fab4d8  →  0x00007ffff7df0450  →  <init_cacheinfo+0> push r15
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7e4dcb1 <popen+145>      ret    
   0x7ffff7e4dcb2                  nop    WORD PTR cs:[rax+rax*1+0x0]
   0x7ffff7e4dcbc                  nop    DWORD PTR [rax+0x0]
 → 0x7ffff7e4dcc0 <puts+0>         push   r14
   0x7ffff7e4dcc2 <puts+2>         push   r13
   0x7ffff7e4dcc4 <puts+4>         mov    r13, rdi
   0x7ffff7e4dcc7 <puts+7>         push   r12
   0x7ffff7e4dcc9 <puts+9>         push   rbp
   0x7ffff7e4dcca <puts+10>        push   rbx
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "titan", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7e4dcc0 → __GI__IO_puts(str=0x402004 "hi")
[#1] 0x401165 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

## Viewing Things

So one thing that gdb is really useful for is viewing the values of different things. Once we are dropped into a debugger while the process is viewing, let's view the contents of the `rdi` register:

```
Breakpoint 1, 0x0000000000401160 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x00000000004011a0  →  <__libc_csu_init+0> push r15
$rdx   : 0x00007fffffffe0f8  →  0x00007fffffffe412  →  "SHELL=/bin/bash"
$rsp   : 0x00007fffffffdfe0  →  0x00000000004011a0  →  <__libc_csu_init+0> push r15
$rbp   : 0x00007fffffffe000  →  0x00000000004011a0  →  <__libc_csu_init+0> push r15
$rsi   : 0x00007fffffffe0e8  →  0x00007fffffffe407  →  "/tmp/titan"
$rdi   : 0x0000000000402004  →  0x3b031b0100006968 ("hi"?)
$rip   : 0x0000000000401160  →  <main+30> call 0x401030 <puts@plt>
$r8    : 0x00007ffff7fb0a40  →  0x0000000000000000
$r9    : 0x00007ffff7fb0a40  →  0x0000000000000000
$r10   : 0x1               
$r11   : 0x206             
$r12   : 0x0000000000401060  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffe0e0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfe0│+0x0000: 0x00000000004011a0  →  <__libc_csu_init+0> push r15     ← $rsp
0x00007fffffffdfe8│+0x0008: 0x0000000000401060  →  <_start+0> xor ebp, ebp
0x00007fffffffdff0│+0x0010: 0x00007fffffffe0e0  →  0x0000000000000001
0x00007fffffffdff8│+0x0018: 0x0a17c82ca27b0d00
0x00007fffffffe000│+0x0020: 0x00000000004011a0  →  <__libc_csu_init+0> push r15     ← $rbp
0x00007fffffffe008│+0x0028: 0x00007ffff7df0b6b  →  <__libc_start_main+235> mov edi, eax
0x00007fffffffe010│+0x0030: 0x00007ffff7fab4d8  →  0x00007ffff7df0450  →  <init_cacheinfo+0> push r15
0x00007fffffffe018│+0x0038: 0x00007fffffffe0e8  →  0x00007fffffffe407  →  "/tmp/titan"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401153 <main+17>        mov    QWORD PTR [rbp-0x8], rax
     0x401157 <main+21>        xor    eax, eax
     0x401159 <main+23>        lea    rdi, [rip+0xea4]        # 0x402004
 →   0x401160 <main+30>        call   0x401030 <puts@plt>
   ↳    0x401030 <puts@plt+0>     jmp    QWORD PTR [rip+0x2fe2]        # 0x404018 <puts@got.plt>
        0x401036 <puts@plt+6>     push   0x0
        0x40103b <puts@plt+11>    jmp    0x401020
        0x401040 <__stack_chk_fail@plt+0> jmp    QWORD PTR [rip+0x2fda]        # 0x404020 <__stack_chk_fail@got.plt>
        0x401046 <__stack_chk_fail@plt+6> push   0x1
        0x40104b <__stack_chk_fail@plt+11> jmp    0x401020
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
puts@plt (
   $rdi = 0x0000000000402004 → 0x3b031b0100006968 ("hi"?),
   $rsi = 0x00007fffffffe0e8 → 0x00007fffffffe407 → "/tmp/titan",
   $rdx = 0x00007fffffffe0f8 → 0x00007fffffffe412 → "SHELL=/bin/bash"
)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "titan", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x401160 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rdi
$1 = 0x402004
```

So we can see that the register `rdi` holds the value `0x402004`, which is a pointer. Let's see what it points to:

```
gef➤  x/g 0x402004
0x402004:    0x3b031b0100006968
gef➤  x/s 0x402004
0x402004:    "hi"
```

So we can see that it points to the string `hi`, which will be printed by `puts` (since `puts` takes a single argument which is a char pointer). One thing in gdb when you examine things with `x`, you can specify what you want to examine it as. Possible things include as a string `x/s`, as a qword `x/g`, or as a dword `x/w`.

let's view the contents of all of the registers:

```
gef➤  info registers
rax            0x0                 0x0
rbx            0x0                 0x0
rcx            0x4011a0            0x4011a0
rdx            0x7fffffffe0f8      0x7fffffffe0f8
rsi            0x7fffffffe0e8      0x7fffffffe0e8
rdi            0x402004            0x402004
rbp            0x7fffffffe000      0x7fffffffe000
rsp            0x7fffffffdfe0      0x7fffffffdfe0
r8             0x7ffff7fb0a40      0x7ffff7fb0a40
r9             0x7ffff7fb0a40      0x7ffff7fb0a40
r10            0x1                 0x1
r11            0x206               0x206
r12            0x401060            0x401060
r13            0x7fffffffe0e0      0x7fffffffe0e0
r14            0x0                 0x0
r15            0x0                 0x0
rip            0x401160            0x401160 <main+30>
eflags         0x246               [ PF ZF IF ]
cs             0x33                0x33
ss             0x2b                0x2b
ds             0x0                 0x0
es             0x0                 0x0
fs             0x0                 0x0
gs             0x0                 0x0
```

Now let's view the stack frame:

```
gef➤  info frame
Stack level 0, frame at 0x7fffffffe010:
 rip = 0x401160 in main; saved rip = 0x7ffff7df0b6b
 Arglist at 0x7fffffffe000, args:
 Locals at 0x7fffffffe000, Previous frame's sp is 0x7fffffffe010
 Saved registers:
  rbp at 0x7fffffffe000, rip at 0x7fffffffe008
```

Now let's view the disassembly for the main function:

```
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000401142 <+0>:    push   rbp
   0x0000000000401143 <+1>:    mov    rbp,rsp
   0x0000000000401146 <+4>:    sub    rsp,0x20
   0x000000000040114a <+8>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000401153 <+17>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000000401157 <+21>:    xor    eax,eax
   0x0000000000401159 <+23>:    lea    rdi,[rip+0xea4]        # 0x402004
=> 0x0000000000401160 <+30>:    call   0x401030 <puts@plt>
   0x0000000000401165 <+35>:    mov    rdx,QWORD PTR [rip+0x2ed4]        # 0x404040 <stdin@@GLIBC_2.2.5>
   0x000000000040116c <+42>:    lea    rax,[rbp-0x12]
   0x0000000000401170 <+46>:    mov    esi,0x9
   0x0000000000401175 <+51>:    mov    rdi,rax
   0x0000000000401178 <+54>:    call   0x401050 <fgets@plt>
   0x000000000040117d <+59>:    nop
   0x000000000040117e <+60>:    mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000401182 <+64>:    xor    rax,QWORD PTR fs:0x28
   0x000000000040118b <+73>:    je     0x401192 <main+80>
   0x000000000040118d <+75>:    call   0x401040 <__stack_chk_fail@plt>
   0x0000000000401192 <+80>:    leave  
   0x0000000000401193 <+81>:    ret    
End of assembler dump.
```

## Changing Values

Let's say we wanted to change the contents of the `rdi` register:

```
gef➤  p $rdi
$2 = 0x402004
gef➤  set $rdi = 0x0
gef➤  p $rdi
$3 = 0x0
```

Now let's say we wanted to change the value stored at the memory address `0x402004` to `0xfacade`:

```
gef➤  x/g 0x402004
0x402004:    0x3b031b0100006968
gef➤  set *0x402004 = 0xfacade
gef➤  x/g 0x402004
0x402004:    0x3b031b0100facade
```

Let's say we wanted to jump directly to an instruction like `0x40117d`, and skip all instructions in between:

```
gef➤  j *0x40117d
Continuing at 0x40117d.
```