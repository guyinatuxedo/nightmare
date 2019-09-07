# nx

Nx is short-hand for Non-Executable stack. What this means is that the stack region of memory is not executable. So if there is perfectly valid code there, you can't execute it due to it's permissions.

For more on this, let's take a look at the memory mappings for a binary that was compiled without this mitigation:

Here it is with `NX` enabled:

```
gef➤  vmmap
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-- /tmp/tryc
0x0000000000401000 0x0000000000402000 0x0000000000001000 r-x /tmp/tryc
0x0000000000402000 0x0000000000403000 0x0000000000002000 r-- /tmp/tryc
0x0000000000403000 0x0000000000404000 0x0000000000002000 r-- /tmp/tryc
0x0000000000404000 0x0000000000405000 0x0000000000003000 rw- /tmp/tryc
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

Here is is with `NX` disabled:

```
gef➤  vmmap
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000403000 0x0000000000000000 r-x /tmp/try
0x0000000000403000 0x0000000000404000 0x0000000000002000 r-x /tmp/try
0x0000000000404000 0x0000000000405000 0x0000000000003000 rwx /tmp/try
0x00007ffff7dcb000 0x00007ffff7fac000 0x0000000000000000 r-x /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ffff7fac000 0x00007ffff7faf000 0x00000000001e0000 r-x /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ffff7faf000 0x00007ffff7fb2000 0x00000000001e3000 rwx /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ffff7fb2000 0x00007ffff7fb8000 0x0000000000000000 rwx
0x00007ffff7fce000 0x00007ffff7fd1000 0x0000000000000000 r-- [vvar]
0x00007ffff7fd1000 0x00007ffff7fd2000 0x0000000000000000 r-x [vdso]
0x00007ffff7fd2000 0x00007ffff7ffc000 0x0000000000000000 r-x /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ffff7ffc000 0x00007ffff7ffd000 0x0000000000029000 r-x /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ffff7ffd000 0x00007ffff7ffe000 0x000000000002a000 rwx /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rwx
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rwx [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
```

So we can see that for when `NX` is enabled, the stack has the memory permissions `rw`. When `NX` hasn't been enabled, the stack has the memory permissions `rwx`. So when `NX` is enabled we can read and write to it, however when `NX` isn't enabled we can read / write / and execute code. Let's see what happens when we try to jump to somewhere in the stack (essentially executing data in the stack as code) while `NX` is enabled:

```
gef➤  j *0x00007ffffffde000
Continuing at 0x7ffffffde000.

Program received signal SIGSEGV, Segmentation fault.
0x00007ffffffde000 in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00007ffff7fafa00  →  0x00000000fbad2288
$rcx   : 0x00007ffff7ed7f81  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x400             
$rsp   : 0x00007fffffffdee8  →  0x00007ffff7e5ae50  →  <_IO_file_underflow+336> test rax, rax
$rbp   : 0xd68             
$rsi   : 0x0000555555559260  →  0x0000000000000000
$rdi   : 0x0               
$rip   : 0x00007ffffffde000  →  0x0000000000000000
$r8    : 0x00007ffff7fb2580  →  0x0000000000000000
$r9    : 0x00007ffff7fb7500  →  0x00007ffff7fb7500  →  [loop detected]
$r10   : 0x00007ffff7fafca0  →  0x0000555555559660  →  0x0000000000000000
$r11   : 0x246             
$r12   : 0x00007ffff7fb0960  →  0x0000000000000000
$r13   : 0x00007ffff7fb1560  →  0x0000000000000000
$r14   : 0x00007ffff7fb0848  →  0x00007ffff7fb0760  →  0x00000000fbad2084
$r15   : 0x00007ffff7fafa00  →  0x00000000fbad2288
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdee8│+0x0000: 0x00007ffff7e5ae50  →  <_IO_file_underflow+336> test rax, rax     ← $rsp
0x00007fffffffdef0│+0x0008: 0x00007ffff7f7a447  →  "__vdso_getcpu"
0x00007fffffffdef8│+0x0010: 0x00007ffff7fafa00  →  0x00000000fbad2288
0x00007fffffffdf00│+0x0018: 0x00007ffff7fb1560  →  0x0000000000000000
0x00007fffffffdf08│+0x0020: 0x000000000000000a
0x00007fffffffdf10│+0x0028: 0x0000000000000000
0x00007fffffffdf18│+0x0030: 0x0000000000000008
0x00007fffffffdf20│+0x0038: 0x00007ffff7fafa00  →  0x00000000fbad2288
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffffffddffa                  add    BYTE PTR [rax], al
   0x7ffffffddffc                  add    BYTE PTR [rax], al
   0x7ffffffddffe                  add    BYTE PTR [rax], al
 → 0x7ffffffde000                  add    BYTE PTR [rax], al
   0x7ffffffde002                  add    BYTE PTR [rax], al
   0x7ffffffde004                  add    BYTE PTR [rax], al
   0x7ffffffde006                  add    BYTE PTR [rax], al
   0x7ffffffde008                  add    BYTE PTR [rax], al
   0x7ffffffde00a                  add    BYTE PTR [rax], al
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tryc", stopped, reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffffffde000 → add BYTE PTR [rax], al
[#1] 0x7ffff7e5ae50 → _IO_new_file_underflow(fp=0x7ffff7fafa00 <_IO_2_1_stdin_>)
[#2] 0x7ffff7e5c182 → __GI__IO_default_uflow(fp=0x7ffff7fafa00 <_IO_2_1_stdin_>)
[#3] 0x7ffff7e4e1fa → __GI__IO_getline_info(fp=0x7ffff7fafa00 <_IO_2_1_stdin_>, buf=0x7fffffffdfde "", n=0x8, delim=0xa, extract_delim=0x1, eof=0x0)
[#4] 0x7ffff7e4e2e8 → __GI__IO_getline(fp=0x7ffff7fafa00 <_IO_2_1_stdin_>, buf=0x7fffffffdfde "", n=<optimized out>, delim=0xa, extract_delim=0x1)
[#5] 0x7ffff7e4d1ab → _IO_fgets(buf=0x7fffffffdfde "", n=<optimized out>, fp=0x7ffff7fafa00 <_IO_2_1_stdin_>)
[#6] 0x555555555174 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

We see here that as soon as we tried to execute code in the stack with `NX` enabled, we got a `SIGSEV`. This is because we tried to execute memory that was not executable.

So what's the bypass? THe typical bypass I use is to not execute code from the stack. Looking at the memory regions with `NX` enabled, we see that the `pie` and `libc` memory regions have some executable memory spaces where instructions are stored. We can leverage those to actually execute code through things like rop, even though in a lot of instances we can't write to those memory regions since the memory permissions are `rx`.